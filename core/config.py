import socket
import ipaddress
import os


class Config:
    def __init__(self):
        self.target = None
        self.resolved_ip = None
        self.is_ipv6 = False
        self.ports = []
        self.excluded_ports = []
        self.timeout = 1.0
        self.threads = 100
        self.scan_type = "tcp-connect"
        self.intensity = 3
        self.verbose = False
        self.skip_ping = False
        self.scan_delay = 0.0
        self.max_retries = 1
        self.fragment = False
        self.mtu_size = 0
        self.decoy_ips = []
        self.spoof_source_ip = None
        self.spoof_source_port = None
        self.spoof_mac = None
        self.data_length = 0
        self.bad_checksum = False
        self.ttl_value = 0
        self.sequential = False
        self.min_rate = 0
        self.max_rate = 0
        self.debug_mode = False
        self.custom_flags = 0x02
        self.aggressive = False

    def set_target(self, target):
        target = target.strip()
        try:
            addr = ipaddress.ip_address(target)
            self.target = target
            self.resolved_ip = target
            self.is_ipv6 = isinstance(addr, ipaddress.IPv6Address)
            return True, f"Target set: {target}"
        except ValueError:
            pass
        try:
            network = ipaddress.ip_network(target, strict=False)
            self.target = target
            self.resolved_ip = str(network)
            self.is_ipv6 = network.version == 6
            return True, f"Target network: {target}"
        except ValueError:
            pass
        if "-" in target and "/" not in target:
            try:
                base, end_part = target.rsplit(".", 1)
                if "-" in end_part:
                    start, end = end_part.split("-")
                    start_ip = f"{base}.{start}"
                    ipaddress.ip_address(start_ip)
                    self.target = target
                    self.resolved_ip = start_ip
                    return True, f"Target range: {target}"
            except Exception:
                pass
        try:
            ip = socket.gethostbyname(target)
            self.target = target
            self.resolved_ip = ip
            self.is_ipv6 = False
            return True, f"Target: {target} ({ip})"
        except socket.gaierror:
            pass
        return False, f"Cannot resolve: {target}"

    def set_ports(self, port_input):
        ports = set()
        port_input = port_input.strip().lower()
        presets = {
            "top100": self._top_100_ports(),
            "top1000": self._top_1000_ports(),
            "all": list(range(1, 65536)),
            "common": [21,22,23,25,53,80,110,111,135,139,143,443,445,
                       993,995,1723,3306,3389,5900,8080,8443]
        }
        if port_input in presets:
            self.ports = presets[port_input]
            self._apply_exclusions()
            return True, f"Ports: {port_input} ({len(self.ports)})"
        try:
            parts = port_input.split(",")
            for part in parts:
                part = part.strip()
                if "-" in part:
                    s, e = part.split("-", 1)
                    s, e = int(s), int(e)
                    if s > e:
                        s, e = e, s
                    for p in range(s, e + 1):
                        if 1 <= p <= 65535:
                            ports.add(p)
                else:
                    p = int(part)
                    if 1 <= p <= 65535:
                        ports.add(p)
            self.ports = sorted(list(ports))
            self._apply_exclusions()
            return True, f"Ports: {len(self.ports)}"
        except Exception:
            return False, "Invalid port format"

    def set_excluded_ports(self, port_input):
        try:
            ports = set()
            for part in port_input.split(","):
                part = part.strip()
                if "-" in part:
                    s, e = part.split("-", 1)
                    for p in range(int(s), int(e) + 1):
                        ports.add(p)
                else:
                    ports.add(int(part))
            self.excluded_ports = sorted(list(ports))
            self._apply_exclusions()
            return True, f"Excluded: {len(self.excluded_ports)}"
        except Exception:
            return False, "Invalid format"

    def _apply_exclusions(self):
        if self.excluded_ports and self.ports:
            self.ports = [p for p in self.ports if p not in self.excluded_ports]

    def set_timeout(self, v):
        try:
            t = float(v)
            if 0.1 <= t <= 30:
                self.timeout = t
                return True, f"Timeout: {t}s"
            return False, "0.1-30"
        except ValueError:
            return False, "Invalid"

    def set_threads(self, v):
        try:
            t = int(v)
            if 1 <= t <= 500:
                self.threads = t
                return True, f"Threads: {t}"
            return False, "1-500"
        except ValueError:
            return False, "Invalid"

    def set_intensity(self, v):
        try:
            i = int(v)
            if 1 <= i <= 5:
                self.intensity = i
                m = {1:(3.0,10),2:(2.0,50),3:(1.0,100),4:(0.5,200),5:(0.3,300)}
                self.timeout, self.threads = m[i]
                return True, f"Intensity: {i} (t={self.timeout}s, th={self.threads})"
            return False, "1-5"
        except ValueError:
            return False, "Invalid"

    def set_skip_ping(self, v):
        self.skip_ping = v.lower() in ("on","true","yes","1")
        return True, f"Skip ping: {'ON' if self.skip_ping else 'OFF'}"

    def set_scan_delay(self, v):
        try:
            d = float(v)
            if 0 <= d <= 60:
                self.scan_delay = d
                return True, f"Delay: {d}s"
            return False, "0-60"
        except ValueError:
            return False, "Invalid"

    def set_max_retries(self, v):
        try:
            r = int(v)
            if 0 <= r <= 10:
                self.max_retries = r
                return True, f"Retries: {r}"
            return False, "0-10"
        except ValueError:
            return False, "Invalid"

    def set_fragment(self, v):
        self.fragment = v.lower() in ("on","true","yes","1")
        return True, f"Fragment: {'ON' if self.fragment else 'OFF'}"

    def set_mtu(self, v):
        try:
            m = int(v)
            if m > 0 and m % 8 == 0:
                self.mtu_size = m
                self.fragment = True
                return True, f"MTU: {m}"
            return False, "Must be multiple of 8"
        except ValueError:
            return False, "Invalid"

    def set_decoys(self, v):
        import random
        ips = []
        for ip in v.split(","):
            ip = ip.strip()
            if ip == "RND":
                ips.append(f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}")
            elif ip == "ME":
                ips.append("ME")
            else:
                try:
                    ipaddress.ip_address(ip)
                    ips.append(ip)
                except ValueError:
                    pass
        self.decoy_ips = ips
        return True, f"Decoys: {len(ips)}"

    def set_spoof_ip(self, v):
        try:
            ipaddress.ip_address(v.strip())
            self.spoof_source_ip = v.strip()
            return True, f"Spoof IP: {v}"
        except ValueError:
            return False, "Invalid IP"

    def set_spoof_port(self, v):
        try:
            p = int(v)
            if 1 <= p <= 65535:
                self.spoof_source_port = p
                return True, f"Spoof port: {p}"
            return False, "1-65535"
        except ValueError:
            return False, "Invalid"

    def set_spoof_mac(self, v):
        import re, random
        v = v.strip()
        if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", v):
            self.spoof_mac = v
            return True, f"MAC: {v}"
        elif v.upper() == "RND":
            mac = ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])
            self.spoof_mac = mac
            return True, f"MAC: {mac}"
        return False, "Invalid MAC"

    def set_data_length(self, v):
        try:
            d = int(v)
            if 0 <= d <= 1400:
                self.data_length = d
                return True, f"Data padding: {d}B"
            return False, "0-1400"
        except ValueError:
            return False, "Invalid"

    def set_bad_checksum(self, v):
        self.bad_checksum = v.lower() in ("on","true","yes","1")
        return True, f"Bad checksum: {'ON' if self.bad_checksum else 'OFF'}"

    def set_ttl(self, v):
        try:
            t = int(v)
            if 1 <= t <= 255:
                self.ttl_value = t
                return True, f"TTL: {t}"
            return False, "1-255"
        except ValueError:
            return False, "Invalid"

    def set_min_rate(self, v):
        try:
            r = int(v)
            self.min_rate = max(0, r)
            return True, f"Min rate: {r}"
        except ValueError:
            return False, "Invalid"

    def set_max_rate(self, v):
        try:
            r = int(v)
            self.max_rate = max(0, r)
            return True, f"Max rate: {r}"
        except ValueError:
            return False, "Invalid"

    def load_target_file(self, filepath):
        try:
            if not os.path.exists(filepath.strip()):
                return False, "File not found", []
            targets = []
            with open(filepath.strip(), "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
            return True, f"Loaded {len(targets)} targets", targets
        except Exception as e:
            return False, str(e), []

    def _top_100_ports(self):
        return [7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,
                119,135,139,143,144,179,199,389,427,443,444,445,465,513,
                514,515,543,544,548,554,587,631,646,873,990,993,995,1025,
                1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,
                2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,
                5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,
                6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,
                9100,9999,10000,32768,49152,49153,49154,49155,49156]

    def _top_1000_ports(self):
        base = self._top_100_ports()
        extended = list(range(1, 1024))
        return sorted(list(set(base + extended)))[:1000]

    def get_summary(self):
        lines = []
        lines.append(f"  Target       : {self.target or 'Not set'}")
        if self.resolved_ip and self.resolved_ip != self.target:
            lines.append(f"  Resolved     : {self.resolved_ip}")
        lines.append(f"  Ports        : {len(self.ports)}" if self.ports else "  Ports        : Not set")
        lines.append(f"  Scan Type    : {self.scan_type}")
        lines.append(f"  Intensity    : {self.intensity}")
        lines.append(f"  Timeout      : {self.timeout}s")
        lines.append(f"  Threads      : {self.threads}")
        if self.fragment:
            lines.append(f"  Fragment     : ON")
        if self.decoy_ips:
            lines.append(f"  Decoys       : {len(self.decoy_ips)}")
        if self.ttl_value:
            lines.append(f"  TTL          : {self.ttl_value}")
        if self.debug_mode:
            lines.append(f"  Debug        : ON")
        return "\n".join(lines)

    def reset(self):
        self.__init__()
