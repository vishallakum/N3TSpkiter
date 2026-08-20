import socket
import ssl
import re
import os
import subprocess
import platform
import time
from core.utils import get_common_service_name, load_json_file


class ServiceProber:
    def __init__(self, config, results):
        self.config = config
        self.results = results

    def probe_all_open_ports(self):
        target = self.config.resolved_ip or self.config.target
        for port in sorted(self.results.open_ports):
            info = self._probe_port(target, port)
            self.results.add_service_info(port, info["service"], info["banner"],
                                           info["version"], info["confidence"])

    def _probe_port(self, target, port):
        info = {"service": get_common_service_name(port), "banner": "", "version": "", "confidence": "low"}
        for probe_func in [self._ssl_check, self._null_probe, self._http_probe, self._specific_probe]:
            result = probe_func(target, port)
            if result:
                info.update(result)
                if info["confidence"] == "high":
                    return info
        return info

    def _ssl_check(self, target, port):
        if port not in [443, 465, 636, 993, 995, 8443, 8883]:
            return None
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target, port), timeout=3) as raw:
                with ctx.wrap_socket(raw, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    ver = ssock.version()
                    cipher = ssock.cipher()
                    cn = ""
                    if cert:
                        subj = dict(x[0] for x in cert.get("subject", []))
                        cn = subj.get("commonName", "")
                    svc_map = {443:"https",465:"smtps",636:"ldaps",993:"imaps",995:"pop3s",8443:"https-alt"}
                    return {
                        "service": svc_map.get(port, "ssl"),
                        "banner": f"TLS/{ver} CN={cn}",
                        "version": f"{ver} {cipher[0] if cipher else ''}",
                        "confidence": "high"
                    }
        except Exception:
            return None

    def _null_probe(self, target, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            try:
                data = s.recv(1024).decode(errors="ignore").strip()
                s.close()
                if data:
                    parsed = self._parse_banner(data, port)
                    return {"banner": data, "confidence": "high",
                            "service": parsed.get("service", get_common_service_name(port)),
                            "version": parsed.get("version", data[:100])}
            except socket.timeout:
                s.close()
        except Exception:
            pass
        return None

    def _http_probe(self, target, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            req = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: N3TSpkiter/4.0\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode())
            resp = b""
            while True:
                try:
                    c = s.recv(4096)
                    if not c:
                        break
                    resp += c
                    if len(resp) > 8192:
                        break
                except Exception:
                    break
            s.close()
            if resp:
                d = resp.decode(errors="ignore")
                if "HTTP/" in d:
                    r = {"service": "https" if port in [443, 8443] else "http",
                         "banner": d.split("\r\n")[0], "version": "", "confidence": "high"}
                    m = re.search(r"Server:\s*(.+?)[\r\n]", d, re.IGNORECASE)
                    if m:
                        r["version"] = m.group(1).strip()
                    return r
        except Exception:
            pass
        return None

    def _specific_probe(self, target, port):
        probes = {
            21: self._ftp, 22: self._ssh, 25: self._smtp, 53: self._dns_p,
            110: self._pop3, 143: self._imap, 161: self._snmp,
            3306: self._mysql, 3389: self._rdp, 5432: self._pgsql,
            6379: self._redis, 27017: self._mongo, 445: self._smb
        }
        if port in probes:
            return probes[port](target, port)
        return None

    def _ftp(self, t, p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((t, p))
            b = s.recv(1024).decode(errors="ignore").strip()
            s.close()
            if b:
                return {"service":"ftp","banner":b,"version":b[:80],"confidence":"high"}
        except Exception:
            pass
        return None

    def _ssh(self, t, p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((t, p))
            b = s.recv(1024).decode(errors="ignore").strip()
            s.close()
            if "SSH" in b:
                return {"service":"ssh","banner":b,"version":b,"confidence":"high"}
        except Exception:
            pass
        return None

    def _smtp(self, t, p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((t, p))
            b = s.recv(1024).decode(errors="ignore").strip()
            s.close()
            if b.startswith("220") or "SMTP" in b.upper():
                return {"service":"smtp","banner":b,"version":b,"confidence":"high"}
        except Exception:
            pass
        return None

    def _pop3(self, t, p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((t, p))
            b = s.recv(1024).decode(errors="ignore").strip()
            s.close()
            if "+OK" in b:
                return {"service":"pop3","banner":b,"version":b,"confidence":"high"}
        except Exception:
            pass
        return None

    def _imap(self, t, p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((t, p))
            b = s.recv(1024).decode(errors="ignore").strip()
            s.close()
            if "IMAP" in b.upper() or "OK" in b:
                return {"service":"imap","banner":b,"version":b,"confidence":"high"}
        except Exception:
            pass
        return None

    def _mysql(self, t, p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((t, p))
            d = s.recv(1024)
            s.close()
            if d and len(d) > 5:
                ve = d.find(b"\x00", 5)
                if ve > 5:
                    v = d[5:ve].decode(errors="ignore")
                    return {"service":"mysql","banner":f"MySQL {v}","version":v,"confidence":"high"}
        except Exception:
            pass
        return None

    def _pgsql(self, t, p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((t, p))
            s.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
            d = s.recv(1024)
            s.close()
            if d and d[0:1] in (b"N", b"E"):
                return {"service":"postgresql","banner":"PostgreSQL","version":"","confidence":"high"}
        except Exception:
            pass
        return None

    def _rdp(self, t, p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((t, p))
            s.sendall(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00")
            d = s.recv(1024)
            s.close()
            if d and d[0:2] == b"\x03\x00":
                return {"service":"rdp","banner":"Microsoft RDP","version":"RDP","confidence":"high"}
        except Exception:
            pass
        return None

    def _redis(self, t, p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((t, p))
            s.sendall(b"INFO\r\n")
            d = s.recv(4096).decode(errors="ignore")
            s.close()
            if "redis_version" in d:
                m = re.search(r"redis_version:([\d.]+)", d)
                v = m.group(1) if m else ""
                return {"service":"redis","banner":f"Redis {v}","version":v,"confidence":"high"}
        except Exception:
            pass
        return None

    def _mongo(self, t, p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((t, p))
            s.close()
            return {"service":"mongodb","banner":"MongoDB","version":"","confidence":"medium"}
        except Exception:
            pass
        return None

    def _smb(self, t, p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((t, p))
            s.close()
            return {"service":"microsoft-ds","banner":"SMB/CIFS","version":"","confidence":"medium"}
        except Exception:
            pass
        return None

    def _dns_p(self, t, p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03", (t, p))
            d, _ = s.recvfrom(512)
            s.close()
            if d:
                return {"service":"dns","banner":"DNS Server","version":"","confidence":"high"}
        except Exception:
            pass
        return None

    def _snmp(self, t, p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", (t, p))
            d, _ = s.recvfrom(1024)
            s.close()
            if d:
                return {"service":"snmp","banner":"SNMP","version":"SNMPv1/v2c","confidence":"high"}
        except Exception:
            pass
        return None

    def _parse_banner(self, banner, port):
        patterns = [
            (r"SSH-([\d.]+)-(.*)", "ssh"), (r"220.*FTP", "ftp"),
            (r"220.*SMTP", "smtp"), (r"HTTP/", "http"),
            (r"\+OK", "pop3"), (r"IMAP", "imap"),
            (r"MySQL", "mysql"), (r"redis", "redis"),
        ]
        for p, svc in patterns:
            if re.search(p, banner, re.IGNORECASE):
                return {"service": svc, "version": banner[:100]}
        return {}


class OSDetector:
    def __init__(self, config, results):
        self.config = config
        self.results = results

    def detect(self):
        target = self.config.resolved_ip or self.config.target
        guesses = []
        for method in [self._ttl, self._banner, self._ports, self._tcp_fp]:
            r = method(target)
            if isinstance(r, list):
                guesses.extend(r)
            elif r:
                guesses.append(r)
        for g in guesses:
            self.results.add_os_guess(g["os"], g["confidence"], g["reason"])
        return guesses

    def _ttl(self, target):
        try:
            p = "-n" if platform.system().lower() == "windows" else "-c"
            r = subprocess.run(["ping", p, "1", target], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=5)
            m = re.search(r"ttl[=:](\d+)", r.stdout.decode(errors="ignore"), re.IGNORECASE)
            if m:
                ttl = int(m.group(1))
                if ttl <= 64:
                    return {"os": "Linux/Unix/macOS", "confidence": "medium", "reason": f"TTL={ttl}"}
                elif ttl <= 128:
                    return {"os": "Windows", "confidence": "medium", "reason": f"TTL={ttl}"}
                else:
                    return {"os": "Network Device", "confidence": "low", "reason": f"TTL={ttl}"}
        except Exception:
            pass
        return None

    def _banner(self, target):
        guesses = []
        indicators = {"ubuntu":"Ubuntu","debian":"Debian","centos":"CentOS",
                       "windows":"Windows","microsoft":"Windows","iis":"Windows (IIS)",
                       "apache":"Linux (Apache)","nginx":"Linux (Nginx)",
                       "freebsd":"FreeBSD","macos":"macOS","darwin":"macOS"}
        for port, svc in self.results.service_info.items():
            text = f"{svc.get('banner','')} {svc.get('version','')}".lower()
            for k, v in indicators.items():
                if k in text:
                    guesses.append({"os": v, "confidence": "medium",
                                    "reason": f"Banner on {port} contains '{k}'"})
                    break
        return guesses

    def _ports(self, target):
        op = set(self.results.open_ports)
        if {135, 139, 445, 3389} & op:
            return {"os": "Windows", "confidence": "medium",
                    "reason": f"Windows ports: {sorted({135,139,445,3389} & op)}"}
        if 22 in op:
            return {"os": "Linux/Unix", "confidence": "low", "reason": "SSH open"}
        return None

    def _tcp_fp(self, target):
        port = None
        for p in [80, 443, 22, 8080]:
            if p in self.results.open_ports:
                port = p
                break
        if not port and self.results.open_ports:
            port = self.results.open_ports[0]
        if not port:
            return None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            start = time.time()
            r = s.connect_ex((target, port))
            rtt = round((time.time() - start) * 1000, 1)
            if r != 0:
                s.close()
                return None
            try:
                mss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
            except Exception:
                mss = 0
            s.close()
            scores = {"Linux": 0, "Windows": 0, "macOS": 0}
            reasons = [f"RTT={rtt}ms"]
            if mss == 1460:
                scores["Linux"] += 2
                reasons.append(f"MSS={mss}")
            elif mss in [1380, 1360]:
                scores["Windows"] += 2
                reasons.append(f"MSS={mss}")
            best = max(scores, key=scores.get)
            return {"os": best, "confidence": "low",
                    "reason": f"TCP Fingerprint: {'; '.join(reasons)}"}
        except Exception:
            return None
