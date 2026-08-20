import os
import json
import time
import xml.etree.ElementTree as ET
from xml.dom import minidom
from core.utils import get_common_service_name


class Reporter:
    def __init__(self, config, results):
        self.config = config
        self.results = results
        self.report_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
        os.makedirs(self.report_dir, exist_ok=True)

    def generate_text(self):
        l = ["="*60, "  N3TSpkiter v4.0 Scan Report", "="*60]
        l.append(f"  Target    : {self.config.target}")
        if self.config.resolved_ip != self.config.target:
            l.append(f"  IP        : {self.config.resolved_ip}")
        l.append(f"  Scan      : {self.results.scan_type_used}")
        l.append(f"  Duration  : {self.results.get_duration()}s")
        l.append(f"  Status    : {self.results.host_status}")
        l.append("")
        l.append(f"  {'PORT':<10}{'STATE':<12}{'SERVICE':<15}{'VERSION'}")
        l.append(f"  {'-'*60}")
        for p in sorted(self.results.open_ports):
            s = self.results.service_info.get(p, {})
            svc = s.get("service", get_common_service_name(p))
            ver = s.get("version", "")[:30]
            l.append(f"  {p:<10}{'open':<12}{svc:<15}{ver}")
        l.append(f"\n  Open:{len(self.results.open_ports)} Closed:{len(self.results.closed_ports)} Filtered:{len(self.results.filtered_ports)}")
        if self.results.os_guess:
            l.append("\n  OS DETECTION")
            for g in self.results.os_guess:
                l.append(f"  {g['os']} ({g['confidence']}) - {g['reason']}")
        if self.results.vulnerabilities:
            l.append("\n  VULNERABILITIES")
            for v in self.results.vulnerabilities:
                l.append(f"  [{v['severity'].upper()}] {v['description']}")
        if self.results.cve_list:
            l.append("\n  CVE DETECTIONS")
            for c in self.results.cve_list:
                l.append(f"  [{c['severity'].upper()}] {c['cve']} - {c['description']}")
        if self.results.technologies:
            l.append(f"\n  TECHNOLOGIES: {', '.join(self.results.technologies)}")
        if self.results.subdomains:
            l.append(f"\n  SUBDOMAINS ({len(self.results.subdomains)}):")
            for sd, ip in self.results.subdomains[:20]:
                l.append(f"    {sd} -> {ip}")
        l.append(f"\n  Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        l.append("="*60)
        return "\n".join(l)

    def generate_json(self):
        return json.dumps({
            "tool": "N3TSpkiter", "version": "4.0",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.config.target,
            "resolved_ip": self.config.resolved_ip,
            "results": self.results.get_summary_dict()
        }, indent=2, default=str)

    def generate_html(self):
        h = f"""<!DOCTYPE html><html><head><title>N3TSpkiter - {self.config.target}</title>
<style>body{{font-family:monospace;background:#1a1a2e;color:#eee;padding:20px}}
h1{{color:#0ff}}h2{{color:#0ff}}table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #333;padding:8px;text-align:left}}th{{background:#16213e;color:#0ff}}
.open{{color:#0f0}}.high{{color:#f00}}.medium{{color:#fa0}}.low{{color:#0f0}}</style></head>
<body><h1>N3TSpkiter Report</h1><p>Target: {self.config.target} | IP: {self.config.resolved_ip}</p>
<p>Duration: {self.results.get_duration()}s | Date: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<h2>Ports</h2><table><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>"""
        for p in sorted(self.results.open_ports):
            s = self.results.service_info.get(p, {})
            h += f'<tr><td>{p}</td><td class="open">open</td><td>{s.get("service","")}</td><td>{s.get("version","")[:50]}</td></tr>'
        h += "</table>"
        if self.results.vulnerabilities:
            h += "<h2>Vulnerabilities</h2><ul>"
            for v in self.results.vulnerabilities:
                h += f'<li class="{v["severity"]}">[{v["severity"].upper()}] {v["description"]}</li>'
            h += "</ul>"
        if self.results.cve_list:
            h += "<h2>CVE Detections</h2><ul>"
            for c in self.results.cve_list:
                h += f'<li class="{c["severity"]}">[{c["severity"].upper()}] {c["cve"]} - {c["description"]}</li>'
            h += "</ul>"
        h += "</body></html>"
        return h

    def generate_xml(self):
        root = ET.Element("n3tspkiter", version="4.0", timestamp=time.strftime("%Y-%m-%d %H:%M:%S"))
        si = ET.SubElement(root, "scaninfo")
        ET.SubElement(si, "target").text = str(self.config.target)
        ET.SubElement(si, "ip").text = str(self.config.resolved_ip)
        ports = ET.SubElement(root, "ports")
        for p in sorted(self.results.open_ports):
            s = self.results.service_info.get(p, {})
            pe = ET.SubElement(ports, "port", number=str(p), state="open")
            ET.SubElement(pe, "service").text = s.get("service", "")
            ET.SubElement(pe, "version").text = s.get("version", "")
        return minidom.parseString(ET.tostring(root, encoding="unicode")).toprettyxml(indent="  ")

    def generate_markdown(self):
        l = [f"# N3TSpkiter Report\n", f"**Target:** {self.config.target}\n",
             f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
             "## Ports\n", "| Port | State | Service | Version |", "|------|-------|---------|---------|"]
        for p in sorted(self.results.open_ports):
            s = self.results.service_info.get(p, {})
            l.append(f"| {p} | open | {s.get('service','')} | {s.get('version','')[:40]} |")
        return "\n".join(l)

    def generate_grep(self):
        ports = ",".join([f"{p}/open/tcp//{self.results.service_info.get(p,{}).get('service','')}"
                          for p in sorted(self.results.open_ports)])
        return f"Host: {self.config.resolved_ip} ({self.config.target})\tPorts: {ports}\tStatus: {self.results.host_status}"

    def save_report(self, fmt="text"):
        ts = time.strftime("%Y%m%d_%H%M%S")
        safe = self.config.target.replace(".", "_").replace("/", "_")
        gens = {"text":(self.generate_text,"txt"),"json":(self.generate_json,"json"),
                "markdown":(self.generate_markdown,"md"),"html":(self.generate_html,"html"),
                "xml":(self.generate_xml,"xml"),"grep":(self.generate_grep,"gnmap")}
        if fmt not in gens:
            return False, f"Unknown: {fmt}"
        gen, ext = gens[fmt]
        path = os.path.join(self.report_dir, f"n3tspkiter_{safe}_{ts}.{ext}")
        with open(path, "w") as f:
            f.write(gen())
        return True, path
