import socket
import time
import subprocess
import platform


class HostChecker:
    def __init__(self, config):
        self.config = config

    def check_all(self):
        results = {
            "dns_resolve": self._dns(),
            "ping": self._ping(),
            "tcp_ping": self._tcp_ping(),
            "reverse_dns": self._rdns(),
            "latency": self._latency()
        }
        results["overall"] = "up" if any([
            results["dns_resolve"]["success"],
            results["ping"]["success"],
            results["tcp_ping"]["success"]
        ]) else "down"
        return results

    def _dns(self):
        try:
            ip = socket.gethostbyname(self.config.target)
            try:
                all_ips = list(set([i[4][0] for i in socket.getaddrinfo(self.config.target, None)]))
            except Exception:
                all_ips = [ip]
            return {"success": True, "ip": ip, "all_ips": all_ips}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _rdns(self):
        try:
            ip = self.config.resolved_ip or self.config.target
            hostname, _, _ = socket.gethostbyaddr(ip)
            return {"success": True, "hostname": hostname}
        except Exception:
            return {"success": False, "hostname": None}

    def _ping(self):
        try:
            t = self.config.resolved_ip or self.config.target
            p = "-n" if platform.system().lower() == "windows" else "-c"
            w = "-w" if platform.system().lower() == "windows" else "-W"
            r = subprocess.run(["ping", p, "1", w, "2", t],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            return {"success": r.returncode == 0, "method": "ICMP"}
        except Exception:
            return {"success": False, "method": "ICMP"}

    def _tcp_ping(self):
        t = self.config.resolved_ip or self.config.target
        for port in [80, 443, 22, 21, 25, 8080]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                if s.connect_ex((t, port)) == 0:
                    s.close()
                    return {"success": True, "method": "TCP", "port": port}
                s.close()
            except Exception:
                continue
        return {"success": False, "method": "TCP"}

    def _latency(self):
        t = self.config.resolved_ip or self.config.target
        for port in [80, 443, 22]:
            try:
                start = time.time()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                if s.connect_ex((t, port)) == 0:
                    lat = round((time.time() - start) * 1000, 2)
                    s.close()
                    return lat
                s.close()
            except Exception:
                continue
        return None
