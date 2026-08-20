"""
N3TSpkiter v4.0 - Web & DNS Reconnaissance Module
Features: DNS Enum, Subdomain Enum, Directory Enum, HTTP/HTTPS Enum,
          SSL/TLS Enum, FTP/SMTP Enum, SSH/SMB Enum, DB Enum,
          MAC Detection, HTTP Headers, Tech Detection, VHost Enum,
          Certificate Info, Vulnerability Scan, CVE Detection
"""

import socket
import ssl
import re
import json
import time
import struct
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed


class WebRecon:
    def __init__(self, config, results):
        self.config = config
        self.results = results

    # ========== DNS Enumeration ==========
    def dns_enum(self, domain=None):
        target = domain or self.config.target
        records = {}
        try:
            records["A"] = socket.gethostbyname(target)
        except Exception:
            pass
        try:
            all_info = socket.getaddrinfo(target, None)
            records["ALL_IPS"] = list(set([i[4][0] for i in all_info]))
        except Exception:
            pass
        try:
            hostname, aliases, ips = socket.gethostbyaddr(records.get("A", target))
            records["PTR"] = hostname
            if aliases:
                records["ALIASES"] = aliases
        except Exception:
            pass
        try:
            import subprocess
            for rtype in ["MX", "NS", "TXT", "CNAME", "SOA", "AAAA"]:
                try:
                    r = subprocess.run(["dig", "+short", rtype, target],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                    out = r.stdout.decode(errors="ignore").strip()
                    if out:
                        records[rtype] = out.split("\n")
                except Exception:
                    pass
        except Exception:
            pass
        self.results.dns_records = records
        return records

    # ========== Subdomain Enumeration ==========
    def subdomain_enum(self, domain=None):
        target = domain or self.config.target
        common_subs = [
            "www","mail","ftp","admin","blog","dev","test","staging",
            "api","app","cdn","cloud","cpanel","dashboard","db","demo",
            "dns","docs","email","files","forum","git","help","host",
            "imap","info","intranet","jenkins","jira","ldap","login",
            "m","manage","media","monitor","mx","mysql","nas","news",
            "ns1","ns2","office","ops","panel","pop","portal","proxy",
            "rdp","remote","server","shop","smtp","sql","ssh","ssl",
            "stage","static","store","support","svn","vpn","web",
            "webmail","wiki","www2","beta","alpha","backup","old","new"
        ]
        found = []
        def check_sub(sub):
            try:
                full = f"{sub}.{target}"
                ip = socket.gethostbyname(full)
                return (full, ip)
            except Exception:
                return None
        with ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(check_sub, s): s for s in common_subs}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    found.append(r)
        self.results.subdomains = found
        return found

    # ========== Directory Enumeration ==========
    def dir_enum(self, target=None):
        host = target or self.config.target
        ip = self.config.resolved_ip or host
        common_dirs = [
            "/","/admin","/login","/dashboard","/api","/wp-admin",
            "/wp-login.php","/administrator","/phpmyadmin","/cpanel",
            "/webmail","/robots.txt","/.git","/sitemap.xml","/.env",
            "/config","/backup","/test","/old","/new","/staging",
            "/dev","/docs","/help","/info","/status","/health",
            "/server-status","/server-info","/.htaccess","/.well-known",
            "/favicon.ico","/wp-content","/uploads","/images","/css",
            "/js","/static","/media","/files","/download","/assets"
        ]
        found = []
        def check_dir(path):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                port = 443 if 443 in self.results.open_ports else 80
                sock.connect((ip, port))
                req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: N3TSpkiter/4.0\r\nConnection: close\r\n\r\n"
                sock.sendall(req.encode())
                resp = sock.recv(1024).decode(errors="ignore")
                sock.close()
                if resp:
                    status_match = re.search(r"HTTP/\d\.\d (\d+)", resp)
                    if status_match:
                        code = int(status_match.group(1))
                        if code < 400:
                            return (path, code)
                return None
            except Exception:
                return None
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(check_dir, d): d for d in common_dirs}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    found.append(r)
        self.results.directories = found
        return found

    # ========== HTTP Header Analysis ==========
    def http_headers(self, target=None):
        host = target or self.config.target
        ip = self.config.resolved_ip or host
        headers = {}
        for port in [80, 443, 8080, 8443]:
            if port not in self.results.open_ports and self.results.open_ports:
                continue
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, port))
                if port in [443, 8443]:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: N3TSpkiter/4.0\r\nConnection: close\r\n\r\n"
                sock.sendall(req.encode())
                resp = sock.recv(4096).decode(errors="ignore")
                sock.close()
                for line in resp.split("\r\n"):
                    if ":" in line and not line.startswith("HTTP"):
                        key, val = line.split(":", 1)
                        headers[key.strip()] = val.strip()
                break
            except Exception:
                continue
        self.results.http_headers = headers
        return headers

    # ========== Technology Detection ==========
    def tech_detect(self, target=None):
        host = target or self.config.target
        ip = self.config.resolved_ip or host
        techs = []
        headers = self.results.http_headers or {}
        server = headers.get("Server", "").lower()
        powered = headers.get("X-Powered-By", "").lower()
        tech_map = {
            "apache": "Apache HTTP Server",
            "nginx": "Nginx",
            "iis": "Microsoft IIS",
            "lighttpd": "Lighttpd",
            "cloudflare": "Cloudflare CDN",
            "php": "PHP",
            "asp.net": "ASP.NET",
            "express": "Node.js Express",
            "django": "Django",
            "flask": "Flask",
            "ruby": "Ruby on Rails",
            "tomcat": "Apache Tomcat",
            "jetty": "Jetty",
            "gunicorn": "Gunicorn",
            "openresty": "OpenResty",
            "varnish": "Varnish Cache",
        }
        combined = f"{server} {powered}"
        for key, name in tech_map.items():
            if key in combined:
                techs.append(name)
        # Check response body
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            port = 443 if 443 in self.results.open_ports else 80
            sock.connect((ip, port))
            if port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: N3TSpkiter/4.0\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode())
            body = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    body += chunk
                    if len(body) > 16384:
                        break
                except Exception:
                    break
            sock.close()
            body_str = body.decode(errors="ignore").lower()
            body_techs = {
                "wordpress": "WordPress",
                "wp-content": "WordPress",
                "joomla": "Joomla",
                "drupal": "Drupal",
                "magento": "Magento",
                "shopify": "Shopify",
                "react": "React.js",
                "angular": "Angular",
                "vue.js": "Vue.js",
                "jquery": "jQuery",
                "bootstrap": "Bootstrap",
                "laravel": "Laravel",
                "next.js": "Next.js",
            }
            for key, name in body_techs.items():
                if key in body_str and name not in techs:
                    techs.append(name)
        except Exception:
            pass
        self.results.technologies = techs
        return techs

    # ========== Virtual Host Enumeration ==========
    def vhost_enum(self, target=None):
        host = target or self.config.target
        ip = self.config.resolved_ip or host
        common_vhosts = [
            f"www.{host}", f"admin.{host}", f"mail.{host}",
            f"dev.{host}", f"staging.{host}", f"api.{host}",
            f"test.{host}", f"beta.{host}", f"portal.{host}",
            f"app.{host}", f"shop.{host}", f"blog.{host}",
        ]
        found = []
        default_resp = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, 80))
            req = f"GET / HTTP/1.1\r\nHost: invalid.invalid\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode())
            default_resp = sock.recv(512).decode(errors="ignore")
            sock.close()
        except Exception:
            pass
        def check_vhost(vhost):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, 80))
                req = f"GET / HTTP/1.1\r\nHost: {vhost}\r\nConnection: close\r\n\r\n"
                sock.sendall(req.encode())
                resp = sock.recv(512).decode(errors="ignore")
                sock.close()
                if resp and resp != default_resp:
                    status = re.search(r"HTTP/\d\.\d (\d+)", resp)
                    if status:
                        code = int(status.group(1))
                        if code < 400:
                            return (vhost, code)
                return None
            except Exception:
                return None
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(check_vhost, v): v for v in common_vhosts}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    found.append(r)
        self.results.vhosts = found
        return found

    # ========== SSL/TLS Certificate Info ==========
    def cert_info(self, target=None):
        host = target or self.config.target
        ip = self.config.resolved_ip or host
        info = {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, 443), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", []))
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        info["common_name"] = subject.get("commonName", "")
                        info["organization"] = subject.get("organizationName", "")
                        info["issuer"] = issuer.get("organizationName", "")
                        info["issuer_cn"] = issuer.get("commonName", "")
                        info["not_before"] = cert.get("notBefore", "")
                        info["not_after"] = cert.get("notAfter", "")
                        info["serial"] = cert.get("serialNumber", "")
                        sans = cert.get("subjectAltName", [])
                        info["san"] = [s[1] for s in sans]
                    info["tls_version"] = version
                    info["cipher"] = cipher[0] if cipher else ""
                    info["cipher_bits"] = cipher[2] if cipher and len(cipher) > 2 else ""
        except Exception as e:
            info["error"] = str(e)[:50]
        self.results.cert_info = info
        return info

    # ========== Vulnerability Scanning ==========
    def vuln_scan(self, target=None):
        host = target or self.config.target
        ip = self.config.resolved_ip or host
        vulns = []
        headers = self.results.http_headers or {}
        security_headers = {
            "X-Frame-Options": "Missing X-Frame-Options (Clickjacking risk)",
            "X-Content-Type-Options": "Missing X-Content-Type-Options (MIME sniffing)",
            "X-XSS-Protection": "Missing X-XSS-Protection",
            "Strict-Transport-Security": "Missing HSTS (SSL stripping risk)",
            "Content-Security-Policy": "Missing CSP (XSS risk)",
            "Referrer-Policy": "Missing Referrer-Policy",
            "Permissions-Policy": "Missing Permissions-Policy",
        }
        for header, desc in security_headers.items():
            if header not in headers:
                vulns.append({"type": "missing_header", "severity": "medium",
                              "description": desc, "header": header})
        if "Server" in headers:
            server = headers["Server"]
            ver = re.search(r"[\d.]+", server)
            if ver:
                vulns.append({"type": "info_disclosure", "severity": "low",
                              "description": f"Server version exposed: {server}"})
        if "X-Powered-By" in headers:
            vulns.append({"type": "info_disclosure", "severity": "low",
                          "description": f"Technology exposed: {headers['X-Powered-By']}"})
        # Check common vulns
        for port in self.results.open_ports:
            svc = self.results.service_info.get(port, {})
            service = svc.get("service", "")
            version = svc.get("version", "")
            if "ftp" in service and "anonymous" in svc.get("banner", "").lower():
                vulns.append({"type": "anon_ftp", "severity": "high",
                              "description": f"Anonymous FTP on port {port}"})
            if port == 23:
                vulns.append({"type": "telnet", "severity": "high",
                              "description": "Telnet (unencrypted) open"})
            if port in [161, 162]:
                vulns.append({"type": "snmp", "severity": "medium",
                              "description": f"SNMP open on port {port}"})
        self.results.vulnerabilities = vulns
        return vulns

    # ========== CVE Detection ==========
    def cve_detect(self):
        cves = []
        for port, svc in self.results.service_info.items():
            service = svc.get("service", "").lower()
            version = svc.get("version", "").lower()
            banner = svc.get("banner", "").lower()
            combined = f"{service} {version} {banner}"
            cve_patterns = {
                "openssh_7": [("CVE-2018-15473", "OpenSSH < 7.7 User Enumeration", "medium")],
                "openssh_6": [("CVE-2016-0777", "OpenSSH < 7.1p2 Info Leak", "high")],
                "apache/2.4.49": [("CVE-2021-41773", "Apache 2.4.49 Path Traversal", "critical")],
                "apache/2.4.50": [("CVE-2021-42013", "Apache 2.4.50 RCE", "critical")],
                "vsftpd 2.3.4": [("CVE-2011-2523", "vsftpd 2.3.4 Backdoor", "critical")],
                "proftpd 1.3.3": [("CVE-2011-4130", "ProFTPD Memory Corruption", "high")],
                "mysql 5.": [("CVE-2012-2122", "MySQL Auth Bypass", "high")],
                "iis/6": [("CVE-2017-7269", "IIS 6.0 Buffer Overflow", "critical")],
                "iis/7": [("CVE-2010-3972", "IIS 7.5 FTP DoS", "medium")],
                "nginx/1.4": [("CVE-2013-4547", "Nginx < 1.4.4 URI Bypass", "high")],
                "phpmyadmin": [("CVE-2018-12613", "phpMyAdmin LFI", "high")],
                "tomcat/7": [("CVE-2017-12617", "Tomcat RCE via PUT", "critical")],
                "redis": [("CVE-2015-4335", "Redis Lua Sandbox Escape", "critical")],
                "mongodb": [("CVE-2019-2390", "MongoDB Unauthenticated Access", "high")],
                "elasticsearch": [("CVE-2015-1427", "Elasticsearch RCE", "critical")],
            }
            for pattern, cve_list in cve_patterns.items():
                if pattern in combined:
                    for cve_id, desc, severity in cve_list:
                        cves.append({"cve": cve_id, "description": desc,
                                     "severity": severity, "port": port,
                                     "service": service})
        self.results.cve_list = cves
        return cves

    # ========== MAC Address Detection ==========
    def mac_detect(self, target=None):
        ip = self.config.resolved_ip or self.config.target
        mac = None
        try:
            r = subprocess.run(["arp", "-n", ip], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=5)
            out = r.stdout.decode(errors="ignore")
            mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", out)
            if mac_match:
                mac = mac_match.group(0)
        except Exception:
            pass
        self.results.mac_address = mac
        return mac

    # ========== Network Distance / RTT ==========
    def network_distance(self, target=None):
        ip = self.config.resolved_ip or self.config.target
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            for port in [80, 443, 22]:
                try:
                    r = sock.connect_ex((ip, port))
                    if r == 0:
                        break
                except Exception:
                    continue
            rtt = round((time.time() - start) * 1000, 2)
            sock.close()
            # Estimate hops from TTL
            try:
                p = "-n" if platform.system().lower() == "windows" else "-c"
                result = subprocess.run(["ping", p, "1", ip],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                ttl_match = re.search(r"ttl[=:](\d+)", result.stdout.decode(errors="ignore"), re.IGNORECASE)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    if ttl <= 64:
                        hops = 64 - ttl
                    elif ttl <= 128:
                        hops = 128 - ttl
                    else:
                        hops = 255 - ttl
                else:
                    hops = None
            except Exception:
                hops = None
            self.results.network_distance = {"rtt_ms": rtt, "estimated_hops": hops}
            return self.results.network_distance
        except Exception:
            return None
