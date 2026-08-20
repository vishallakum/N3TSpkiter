import time
import json
import os

RESUME_FILE = "/tmp/n3tspkiter_resume.json"


class ScanResults:
    def __init__(self):
        self.reset()

    def reset(self):
        self.start_time = None
        self.end_time = None
        self.host_status = None
        self.host_latency = None
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.port_details = {}
        self.service_info = {}
        self.os_guess = []
        self.traceroute_hops = []
        self.scan_type_used = None
        self.dns_records = {}
        self.subdomains = []
        self.directories = []
        self.http_headers = {}
        self.technologies = []
        self.vhosts = []
        self.cert_info = {}
        self.vulnerabilities = []
        self.cve_list = []
        self.mac_address = None
        self.network_distance = None
        self.nse_results = {}

    def start_timer(self):
        self.start_time = time.time()

    def stop_timer(self):
        self.end_time = time.time()

    def get_duration(self):
        if self.start_time and self.end_time:
            return round(self.end_time - self.start_time, 2)
        return 0

    def add_port_result(self, port, state, reason="", protocol="tcp"):
        self.port_details[f"{protocol}/{port}"] = {
            "port": port, "state": state, "reason": reason, "protocol": protocol
        }
        if state == "open" and port not in self.open_ports:
            self.open_ports.append(port)
        elif state == "closed" and port not in self.closed_ports:
            self.closed_ports.append(port)
        elif "filtered" in state and port not in self.filtered_ports:
            self.filtered_ports.append(port)

    def add_service_info(self, port, service, banner="", version="", confidence="low"):
        self.service_info[port] = {
            "service": service, "banner": banner,
            "version": version, "confidence": confidence
        }

    def add_os_guess(self, os_name, confidence, reason):
        self.os_guess.append({"os": os_name, "confidence": confidence, "reason": reason})

    def get_summary_dict(self):
        return {
            "duration": self.get_duration(),
            "host_status": self.host_status,
            "open_ports": sorted(self.open_ports),
            "closed_count": len(self.closed_ports),
            "filtered_count": len(self.filtered_ports),
            "services": self.service_info,
            "os_detection": self.os_guess,
            "vulnerabilities": self.vulnerabilities,
            "cve_list": self.cve_list,
            "technologies": self.technologies,
            "subdomains": self.subdomains,
            "http_headers": self.http_headers,
            "cert_info": self.cert_info
        }

    def to_json(self):
        return json.dumps(self.get_summary_dict(), indent=2, default=str)

    def save_progress(self, config):
        try:
            data = {
                "target": config.target,
                "resolved_ip": config.resolved_ip,
                "open_ports": list(self.open_ports),
                "closed_ports": list(self.closed_ports),
                "filtered_ports": list(self.filtered_ports),
                "port_details": dict(self.port_details),
                "host_status": str(self.host_status),
                "scan_type": str(self.scan_type_used),
                "ports_remaining": [p for p in config.ports
                                    if p not in self.open_ports
                                    and p not in self.closed_ports
                                    and p not in self.filtered_ports]
            }
            with open(RESUME_FILE, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    @staticmethod
    def load_progress():
        if not os.path.exists(RESUME_FILE):
            return None
        try:
            with open(RESUME_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return None

    @staticmethod
    def clear_progress():
        if os.path.exists(RESUME_FILE):
            os.remove(RESUME_FILE)
