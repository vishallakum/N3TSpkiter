import cmd
import os
import sys
import time
import socket
import subprocess
import platform
import ipaddress
import re

from core.config import Config
from core.results import ScanResults
from core.scanner import PortScanner
from core.probe import ServiceProber, OSDetector
from core.hostcheck import HostChecker
from core.reporter import Reporter
from core.recon import WebRecon
from core.utils import Colors, colored, success, error, info, warning, banner, clear_screen, get_common_service_name


class N3TSpkiterShell(cmd.Cmd):
    intro = banner() + "\n  Type 'help' for commands.\n"

    def __init__(self):
        super().__init__()
        self.config = Config()
        self.results = ScanResults()
        self._update_prompt()

    def _update_prompt(self):
        if self.config.target:
            t = self.config.target[:20]
            self.prompt = f"{Colors.BOLD}{Colors.CYAN}N3TSpkiter{Colors.RESET}({Colors.GREEN}{t}{Colors.RESET})> "
        else:
            self.prompt = f"{Colors.BOLD}{Colors.CYAN}N3TSpkiter{Colors.RESET}> "

    def _pr(self, ok, msg):
        print(success(msg) if ok else error(msg))

    # ========== SET ==========
    def do_set(self, arg):
        """Set configuration. Type 'help set' for options."""
        parts = arg.split(maxsplit=1)
        if len(parts) < 2:
            print(error("Usage: set <option> <value>"))
            return
        k, v = parts[0].lower().strip(), parts[1].strip()
        simple = {
            "target": lambda: (self.config.set_target(v), self._update_prompt()),
            "ports": lambda: (self.config.set_ports(v), None),
            "timeout": lambda: (self.config.set_timeout(v), None),
            "threads": lambda: (self.config.set_threads(v), None),
            "intensity": lambda: (self.config.set_intensity(v), None),
            "skip-ping": lambda: (self.config.set_skip_ping(v), None),
            "scan-delay": lambda: (self.config.set_scan_delay(v), None),
            "max-retries": lambda: (self.config.set_max_retries(v), None),
            "exclude-ports": lambda: (self.config.set_excluded_ports(v), None),
            "fragment": lambda: (self.config.set_fragment(v), None),
            "mtu": lambda: (self.config.set_mtu(v), None),
            "decoys": lambda: (self.config.set_decoys(v), None),
            "spoof-ip": lambda: (self.config.set_spoof_ip(v), None),
            "spoof-port": lambda: (self.config.set_spoof_port(v), None),
            "spoof-mac": lambda: (self.config.set_spoof_mac(v), None),
            "data-length": lambda: (self.config.set_data_length(v), None),
            "bad-checksum": lambda: (self.config.set_bad_checksum(v), None),
            "ttl": lambda: (self.config.set_ttl(v), None),
            "min-rate": lambda: (self.config.set_min_rate(v), None),
            "max-rate": lambda: (self.config.set_max_rate(v), None),
        }
        if k == "scan-type":
            valid = ["tcp-connect","udp","window","syn","fin","xmas","null","ack","maimon","custom"]
            if v.lower() in valid:
                self.config.scan_type = v.lower()
                print(success(f"Scan type: {v}"))
                if v.lower() in ["syn","fin","xmas","null","ack","maimon","custom"]:
                    if os.geteuid() != 0:
                        print(warning("Needs root/sudo"))
                    else:
                        print(info("Root detected. Ready."))
            else:
                print(error(f"Invalid. Use: {', '.join(valid)}"))
            return
        if k == "scanflags":
            try:
                self.config.custom_flags = int(v, 0)
                self.config.scan_type = "custom"
                print(success(f"Custom flags: 0x{self.config.custom_flags:02x}"))
            except ValueError:
                print(error("Invalid hex"))
            return
        if k == "verbose":
            self.config.verbose = v.lower() in ("on","true","yes","1")
            print(success(f"Verbose: {'ON' if self.config.verbose else 'OFF'}"))
            return
        if k == "debug":
            self.config.debug_mode = v.lower() in ("on","true","yes","1")
            print(success(f"Debug: {'ON' if self.config.debug_mode else 'OFF'}"))
            return
        if k in simple:
            r = simple[k]()
            if r and r[0]:
                self._pr(*r[0])
        else:
            print(error(f"Unknown: {k}"))

    # ========== SHOW ==========
    def do_show(self, arg):
        """Show info: config|results|ports|services|os|vulns|cves|techs|subs|headers|cert|all"""
        a = arg.strip().lower()
        if a == "config":
            print(f"\n{Colors.CYAN}[Config]{Colors.RESET}\n{self.config.get_summary()}\n")
        elif a == "results":
            self._show_results()
        elif a == "ports":
            self._show_ports(False)
        elif a == "ports open":
            self._show_ports(True)
        elif a == "services":
            self._show_services()
        elif a == "os":
            self._show_os()
        elif a == "vulns":
            self._show_vulns()
        elif a == "cves":
            self._show_cves()
        elif a == "techs":
            self._show_techs()
        elif a == "subs":
            self._show_subs()
        elif a == "headers":
            self._show_headers()
        elif a == "cert":
            self._show_cert()
        elif a == "dirs":
            self._show_dirs()
        elif a == "all":
            for f in [self._show_results, lambda: self._show_ports(False),
                      self._show_services, self._show_os, self._show_vulns,
                      self._show_cves, self._show_techs, self._show_subs,
                      self._show_headers, self._show_cert, self._show_dirs]:
                f()
        else:
            print(error("show <config|results|ports|services|os|vulns|cves|techs|subs|headers|cert|dirs|all>"))

    def _show_results(self):
        print()
        print(f"  {'='*50}")
        print(f"  SCAN RESULTS")
        print(f"  {'='*50}")
        print(f"  Host Status  : {self.results.host_status or 'Not checked'}")
        if self.results.host_latency:
            print(f"  Latency      : {self.results.host_latency}ms")
        print(f"  Scan Type    : {self.results.scan_type_used or 'None'}")
        print(f"  Duration     : {self.results.get_duration()}s")
        print(f"  {'-'*50}")
        print(f"  Open         : {len(self.results.open_ports)}")
        print(f"  Closed       : {len(self.results.closed_ports)}")
        print(f"  Filtered     : {len(self.results.filtered_ports)}")
        if self.results.open_ports:
            print(f"  {'-'*50}")
            print(f"  Open Ports   : {sorted(self.results.open_ports)}")
        print(f"  {'='*50}")
        print()
    def _show_ports(self, open_only):
        if not self.results.port_details:
            print(info("No data. Run scan."))
            return
        print(f"\n{Colors.CYAN}[Ports]{Colors.RESET}")
        print(f"  {'PORT':<8}{'PROTO':<6}{'STATE':<14}{'SERVICE':<15}{'REASON'}")
        print(f"  {'-'*60}")
        for k in sorted(self.results.port_details, key=lambda x: int(x.split("/")[1])):
            d = self.results.port_details[k]
            if open_only and d["state"] != "open":
                continue
            st = d["state"]
            c = Colors.GREEN if st == "open" else Colors.YELLOW if "filter" in st else Colors.RED
            if st in ("open","filtered","open|filtered","unfiltered"):
                print(f"  {d['port']:<8}{d['protocol']:<6}{colored(st,c):<23}{get_common_service_name(d['port']):<15}{d['reason'][:30]}")
        print()

    def _show_services(self):
        if not self.results.service_info:
            print(info("No services. Run 'probe'."))
            return
        print()
        print(f"  {'='*75}")
        print(f"  SERVICE DETECTION RESULTS")
        print(f"  {'='*75}")
        print(f"  {'PORT':<10}{'SERVICE':<18}{'VERSION':<30}{'CONFIDENCE'}")
        print(f"  {'-'*75}")
        for p in sorted(self.results.service_info):
            s = self.results.service_info[p]
            svc = s.get('service', 'unknown')
            ver = s.get('version', 'N/A')[:28]
            conf = s.get('confidence', 'low')
            print(f"  {p:<10}{svc:<18}{ver:<30}{conf}")
        print(f"  {'='*75}")
        print()
    def _show_os(self):
        if not self.results.os_guess:
            print(info("No OS data. Run 'os-detect'."))
            return
        print()
        print(f"  {'='*70}")
        print(f"  OS DETECTION RESULTS")
        print(f"  {'='*70}")
        print(f"  {'#':<5}{'OS':<25}{'CONFIDENCE':<15}{'REASON'}")
        print(f"  {'-'*70}")
        for i, g in enumerate(self.results.os_guess, 1):
            print(f"  {i:<5}{g['os'][:22]:<25}{g['confidence']:<15}{g['reason'][:30]}")
        print(f"  {'='*70}")
        if self.results.os_guess:
            print(f"  Best Guess: {self.results.os_guess[0]['os']}")
        print()
    def _show_vulns(self):
        if not self.results.vulnerabilities:
            print(info("No vulns. Run 'vulnscan'."))
            return
        print()
        print(f"  {'='*65}")
        print(f"  VULNERABILITY SCAN RESULTS")
        print(f"  {'='*65}")
        print(f"  {'SEVERITY':<12}{'TYPE':<20}{'DESCRIPTION'}")
        print(f"  {'-'*65}")
        for v in self.results.vulnerabilities:
            sev = v['severity'].upper()
            vtype = v.get('type', 'unknown')[:18]
            desc = v['description'][:35]
            print(f"  {sev:<12}{vtype:<20}{desc}")
        print(f"  {'='*65}")
        print(f"  Total: {len(self.results.vulnerabilities)} issue(s) found")
        print()
    def _show_cves(self):
        if not self.results.cve_list:
            print(info("No CVEs. Run 'cvedetect'."))
            return
        print()
        print(f"  {'='*75}")
        print(f"  CVE DETECTION RESULTS")
        print(f"  {'='*75}")
        print(f"  {'CVE ID':<20}{'SEVERITY':<12}{'PORT':<8}{'DESCRIPTION'}")
        print(f"  {'-'*75}")
        for c in self.results.cve_list:
            cve = c['cve']
            sev = c['severity'].upper()
            port = str(c.get('port', ''))
            desc = c['description'][:35]
            print(f"  {cve:<20}{sev:<12}{port:<8}{desc}")
        print(f"  {'='*75}")
        print(f"  Total: {len(self.results.cve_list)} CVE(s) found")
        print()
    def _show_techs(self):
        if not self.results.technologies:
            print(info("No techs. Run 'techdetect'."))
            return
        print(f"\n{Colors.CYAN}[Technologies]{Colors.RESET}")
        for t in self.results.technologies:
            print(f"  {Colors.GREEN}●{Colors.RESET} {t}")
        print()

    def _show_subs(self):
        if not self.results.subdomains:
            print(info("No subs. Run 'subenum'."))
            return
        print(f"\n{Colors.CYAN}[Subdomains] ({len(self.results.subdomains)}){Colors.RESET}")
        for sd, ip in self.results.subdomains:
            print(f"  {Colors.GREEN}●{Colors.RESET} {sd} -> {ip}")
        print()

    def _show_headers(self):
        if not self.results.http_headers:
            print(info("No headers. Run 'headers'."))
            return
        print(f"\n{Colors.CYAN}[HTTP Headers]{Colors.RESET}")
        for k, v in self.results.http_headers.items():
            print(f"  {Colors.BOLD}{k}{Colors.RESET}: {v}")
        print()

    def _show_cert(self):
        if not self.results.cert_info:
            print(info("No cert. Run 'certinfo'."))
            return
        print(f"\n{Colors.CYAN}[Certificate]{Colors.RESET}")
        for k, v in self.results.cert_info.items():
            if isinstance(v, list):
                print(f"  {k}: {', '.join(v[:5])}")
            else:
                print(f"  {k}: {v}")
        print()

    def _show_dirs(self):
        if not self.results.directories:
            print(info("No dirs. Run 'direnum'."))
            return
        print(f"\n{Colors.CYAN}[Directories]{Colors.RESET}")
        for path, code in self.results.directories:
            print(f"  {Colors.GREEN}[{code}]{Colors.RESET} {path}")
        print()

    # ========== SCANNING ==========
    def do_hostcheck(self, arg):
        """Host discovery."""
        if not self.config.target:
            print(error("Set target first"))
            return
        if self.config.skip_ping:
            print(info("Skip ping ON."))
            self.results.host_status = "up"
            return
        print(info(f"Checking: {self.config.target}"))
        r = HostChecker(self.config).check_all()
        if r["dns_resolve"]["success"]:
            print(success(f"DNS: {r['dns_resolve']['ip']}"))
        if r["reverse_dns"]["success"]:
            print(success(f"rDNS: {r['reverse_dns']['hostname']}"))
        print(success("Ping: UP") if r["ping"]["success"] else warning("Ping: No response"))
        if r["tcp_ping"]["success"]:
            print(success(f"TCP: port {r['tcp_ping'].get('port','?')}"))
        if r["latency"]:
            print(info(f"Latency: {r['latency']}ms"))
            self.results.host_latency = r["latency"]
        self.results.host_status = r["overall"]
    def do_hostcheck(self, arg):
        """Host discovery."""
        if not self.config.target:
            print(error("Set target first"))
            return
        if self.config.skip_ping:
            print(info("Skip ping ON."))
            self.results.host_status = "up"
            return
        print(info(f"Checking host: {self.config.target}"))
        print()
        r = HostChecker(self.config).check_all()
        print(f"  {'CHECK':<20}{'STATUS':<12}{'DETAIL'}")
        print(f"  {'-'*55}")
        if r["dns_resolve"]["success"]:
            print(f"  {'DNS Resolve':<20}{'OK':<12}{r['dns_resolve']['ip']}")
        else:
            print(f"  {'DNS Resolve':<20}{'FAIL':<12}{r['dns_resolve'].get('error','')[:30]}")
        if r["reverse_dns"]["success"]:
            print(f"  {'Reverse DNS':<20}{'OK':<12}{r['reverse_dns']['hostname']}")
        else:
            print(f"  {'Reverse DNS':<20}{'N/A':<12}")
        if r["ping"]["success"]:
            print(f"  {'ICMP Ping':<20}{'UP':<12}Host responds")
        else:
            print(f"  {'ICMP Ping':<20}{'DOWN':<12}No response")
        if r["tcp_ping"]["success"]:
            print(f"  {'TCP Ping':<20}{'UP':<12}Port {r['tcp_ping'].get('port','?')} open")
        else:
            print(f"  {'TCP Ping':<20}{'DOWN':<12}No ports responded")
        if r["latency"]:
            print(f"  {'Latency':<20}{'':<12}{r['latency']}ms")
            self.results.host_latency = r["latency"]
        print(f"  {'-'*55}")
        self.results.host_status = r["overall"]
        print(f"  Host Status: {r['overall'].upper()}")
        print()

    def do_portscan(self, arg):
        """Port scan."""
        if not self.config.target:
            print(error("Set target"))
            return
        if not self.config.ports:
            print(error("Set ports"))
            return
        self.results.reset()
        self.results.host_status = "up"
        sc = PortScanner(self.config, self.results)
        def cb(p, s):
            svc = get_common_service_name(p)
            c = Colors.GREEN if s == "open" else Colors.YELLOW
            print(f"  {colored(f'[{s.upper()}]',c)} {p} ({svc})")
        sc.set_progress_callback(cb)
        st = self.config.scan_type
        print(info(f"{st} scan on {self.config.target} ({len(self.config.ports)} ports)"))
        m = {"tcp-connect":sc.tcp_connect_scan,"udp":sc.udp_scan,"window":sc.window_scan,
             "syn":sc.syn_scan,"fin":sc.fin_scan,"xmas":sc.xmas_scan,"null":sc.null_scan,
             "ack":sc.ack_scan,"maimon":sc.maimon_scan}
        fn = (lambda: sc.custom_scan(self.config.custom_flags)) if st == "custom" else m.get(st, sc.tcp_connect_scan)
        try:
            fn()
        except KeyboardInterrupt:
            print(warning("Interrupted"))
        try:
            self.results.save_progress(self.config)
        except Exception:
            pass
        if not self.results.end_time:
            self.results.stop_timer()
        duration = self.results.get_duration()
        op = len(self.results.open_ports)
        cl = len(self.results.closed_ports)
        fl = len(self.results.filtered_ports)
        print()
        print(f"  Scan Complete in {duration}s")
        print(f"  {'='*50}")
        print(f"  Open: {op}  |  Closed: {cl}  |  Filtered: {fl}")
        print(f"  {'='*50}")
        if self.results.open_ports:
            print()
            print(f"  {'PORT':<10}{'STATE':<12}{'SERVICE'}")
            print(f"  {'-'*35}")
            for p in sorted(self.results.open_ports):
                svc = get_common_service_name(p)
                print(f"  {p:<10}{'open':<12}{svc}")
        print()

    def do_probe(self, arg):
        """Service/version detection."""
        if not self.results.open_ports:
            print(error("No open ports. Run 'portscan'"))
            return
        print(info(f"Probing {len(self.results.open_ports)} ports..."))
        ServiceProber(self.config, self.results).probe_all_open_ports()
        print()
        print(f"  {'PORT':<10}{'SERVICE':<18}{'VERSION':<35}{'CONFIDENCE'}")
        print(f"  {'-'*75}")
        for p in sorted(self.results.service_info):
            s = self.results.service_info[p]
            svc = s.get('service', 'unknown')
            ver = s.get('version', '')[:32]
            conf = s.get('confidence', 'low')
            print(f"  {p:<10}{svc:<18}{ver:<35}{conf}")
        print()
        print(f"  Probe Complete. {len(self.results.service_info)} service(s) identified.")
        print()
    def do_os_detect(self, arg):
        """OS detection."""
        if not self.config.target:
            print(error("Set target"))
            return
        print(info("OS detection..."))
        gs = OSDetector(self.config, self.results).detect()
        if gs:
            print()
            print(f"  {'#':<5}{'OS':<25}{'CONFIDENCE':<15}{'REASON'}")
            print(f"  {'-'*70}")
            for i, g in enumerate(gs, 1):
                os_name = g['os'][:22]
                conf = g['confidence']
                reason = g['reason'][:35]
                print(f"  {i:<5}{os_name:<25}{conf:<15}{reason}")
            print()
            best = gs[0]
            print(f"  Best Guess: {best['os']} ({best['confidence']})")
        else:
            print(info("No OS detected. Run scan+probe first."))
        print()
    def default(self, line):
        if line.strip().startswith("os-detect"):
            return self.do_os_detect("")
        print(error(f"Unknown: {line}. Type 'help'."))

    # ========== RECON ==========
    def do_dnsenum(self, arg):
        """DNS enumeration."""
        if not self.config.target:
            print(error("Set target"))
            return
        print(info(f"DNS enum: {self.config.target}"))
        r = WebRecon(self.config, self.results).dns_enum()
        for k, v in r.items():
            print(f"  {Colors.BOLD}{k}{Colors.RESET}: {v}")
        print()

    def do_subenum(self, arg):
        """Subdomain enumeration."""
        if not self.config.target:
            print(error("Set target"))
            return
        print(info(f"Subdomain enum: {self.config.target}"))
        r = WebRecon(self.config, self.results).subdomain_enum()
        print(success(f"Found {len(r)} subdomains:"))
        for sd, ip in r:
            print(f"  {Colors.GREEN}●{Colors.RESET} {sd} -> {ip}")
        print()

    def do_direnum(self, arg):
        """Directory enumeration."""
        if not self.config.target:
            print(error("Set target"))
            return
        print(info(f"Dir enum: {self.config.target}"))
        r = WebRecon(self.config, self.results).dir_enum()
        print(success(f"Found {len(r)} paths:"))
        for path, code in r:
            print(f"  {Colors.GREEN}[{code}]{Colors.RESET} {path}")
        print()

    def do_headers(self, arg):
        """HTTP header analysis."""
        if not self.config.target:
            print(error("Set target"))
            return
        print(info("HTTP headers..."))
        r = WebRecon(self.config, self.results).http_headers()
        for k, v in r.items():
            print(f"  {Colors.BOLD}{k}{Colors.RESET}: {v}")
        print()

    def do_techdetect(self, arg):
        """Technology detection."""
        if not self.config.target:
            print(error("Set target"))
            return
        print(info("Tech detection..."))
        if not self.results.http_headers:
            WebRecon(self.config, self.results).http_headers()
        r = WebRecon(self.config, self.results).tech_detect()
        print(success(f"Found {len(r)} technologies:"))
        for t in r:
            print(f"  {Colors.GREEN}●{Colors.RESET} {t}")
        print()

    def do_vhostenum(self, arg):
        """Virtual host enumeration."""
        if not self.config.target:
            print(error("Set target"))
            return
        print(info("VHost enum..."))
        r = WebRecon(self.config, self.results).vhost_enum()
        print(success(f"Found {len(r)} vhosts:"))
        for vh, code in r:
            print(f"  {Colors.GREEN}[{code}]{Colors.RESET} {vh}")
        print()

    def do_certinfo(self, arg):
        """SSL/TLS certificate info."""
        if not self.config.target:
            print(error("Set target"))
            return
        print(info("Certificate info..."))
        r = WebRecon(self.config, self.results).cert_info()
        for k, v in r.items():
            if isinstance(v, list):
                print(f"  {k}: {', '.join(v[:5])}")
            else:
                print(f"  {k}: {v}")
        print()

    def do_vulnscan(self, arg):
        """Vulnerability scanning."""
        if not self.config.target:
            print(error("Set target"))
            return
        print(info("Vulnerability scan..."))
        if not self.results.http_headers:
            WebRecon(self.config, self.results).http_headers()
        r = WebRecon(self.config, self.results).vuln_scan()
        print(success(f"Found {len(r)} issues:"))
        for v in r:
            c = Colors.RED if v["severity"] in ["high", "critical"] else Colors.YELLOW
            sev = colored(f"[{v['severity'].upper()}]", c)
            print(f"  {sev} {v['description']}")
        print()

    def do_cvedetect(self, arg):
        """CVE detection."""
        if not self.results.service_info:
            print(error("Run 'probe' first"))
            return
        print(info("CVE detection..."))
        r = WebRecon(self.config, self.results).cve_detect()
        if r:
            print(success(f"Found {len(r)} CVEs:"))
            for item in r:
                cl = Colors.RED if item["severity"] in ["high", "critical"] else Colors.YELLOW
                sev = colored(f"[{item['severity'].upper()}]", cl)
                print(f"  {sev} {item['cve']} - {item['description']}")
        else:
            print(info("No known CVEs found."))
        print()

    def do_macdetect(self, arg):
        """MAC address detection."""
        if not self.config.target:
            print(error("Set target"))
            return
        mac = WebRecon(self.config, self.results).mac_detect()
        print(success(f"MAC: {mac}") if mac else info("MAC not found (remote host)"))

    def do_netdist(self, arg):
        """Network distance/RTT."""
        if not self.config.target:
            print(error("Set target"))
            return
        r = WebRecon(self.config, self.results).network_distance()
        if r:
            print(success(f"RTT: {r['rtt_ms']}ms | Hops: {r['estimated_hops']}"))
        else:
            print(warning("Could not measure"))

    # ========== UTILITIES ==========
    def do_traceroute(self, arg):
        """Traceroute."""
        if not self.config.target:
            print(error("Set target"))
            return
        t = self.config.resolved_ip or self.config.target
        print(info(f"Traceroute to {t}..."))
        try:
            cmd = ["traceroute","-n","-w","2","-q","1",t] if platform.system().lower() != "windows" else ["tracert","-d",t]
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            print(r.stdout.decode(errors="ignore"))
        except Exception as e:
            print(error(str(e)))

    def do_sweep(self, arg):
        """Ping sweep. Usage: sweep 192.168.1.0/24"""
        cidr = arg.strip() or (self.config.target if self.config.target and "/" in self.config.target else "")
        if not cidr:
            print(error("Usage: sweep <cidr>"))
            return
        print(info(f"Sweeping {cidr}..."))
        live = PortScanner(self.config, self.results).ping_sweep(cidr)
        print(success(f"Found {len(live)} hosts:"))
        for h in live:
            print(f"  {Colors.GREEN}●{Colors.RESET} {h}")

    def do_dns(self, arg):
        """DNS lookup."""
        t = arg.strip() or self.config.target
        if not t:
            print(error("Usage: dns <domain>"))
            return
        try:
            ip = socket.gethostbyname(t)
            print(success(f"A: {ip}"))
            try:
                h, _, _ = socket.gethostbyaddr(ip)
                print(info(f"rDNS: {h}"))
            except Exception:
                pass
        except Exception:
            print(error("Cannot resolve"))

    def do_whois(self, arg):
        """WHOIS lookup."""
        t = arg.strip() or self.config.target
        if not t:
            print(error("Usage: whois <target>"))
            return
        try:
            r = subprocess.run(["whois", t], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            print(r.stdout.decode(errors="ignore")[:3000])
        except Exception as e:
            print(error(str(e)))

    def do_fullscan(self, arg):
        """Complete auto recon (all 52 features)."""
        if not self.config.target:
            print(error("Set target"))
            return
        if not self.config.ports:
            self.config.set_ports("top100")
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*50}")
        print(f"  N3TSpkiter Full Reconnaissance")
        print(f"{'='*50}{Colors.RESET}\n")
        steps = [
            ("Host Discovery", self.do_hostcheck),
            ("Port Scanning", self.do_portscan),
            ("Service Detection", self.do_probe),
            ("OS Detection", self.do_os_detect),
            ("DNS Enumeration", self.do_dnsenum),
            ("Subdomain Enumeration", self.do_subenum),
            ("HTTP Headers", self.do_headers),
            ("Technology Detection", self.do_techdetect),
            ("Certificate Info", self.do_certinfo),
            ("Directory Enumeration", self.do_direnum),
            ("Vulnerability Scan", self.do_vulnscan),
            ("CVE Detection", self.do_cvedetect),
            ("MAC Detection", self.do_macdetect),
            ("Network Distance", self.do_netdist),
        ]
        for i, (name, func) in enumerate(steps, 1):
            print(f"{Colors.YELLOW}[{i}/{len(steps)}] {name}{Colors.RESET}")
            try:
                func("")
            except Exception as e:
                print(warning(f"Skipped: {str(e)[:50]}"))
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*50}{Colors.RESET}")
        print(success("Full scan complete!"))
        print(info("'show all' for results | 'save all' for reports"))
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*50}{Colors.RESET}\n")

    def do_aggressive(self, arg):
        """Aggressive scan (like nmap -A)."""
        self.config.aggressive = True
        if not self.config.ports:
            self.config.set_ports("top1000")
        self.config.set_intensity("4")
        self.do_fullscan("")

    def do_scanlist(self, arg):
        """Scan from file."""
        if not arg.strip():
            print(error("Usage: scanlist <file>"))
            return
        ok, msg, targets = self.config.load_target_file(arg)
        if not ok:
            print(error(msg))
            return
        print(success(msg))
        if not self.config.ports:
            self.config.set_ports("top100")
        for i, t in enumerate(targets, 1):
            print(f"\n{Colors.YELLOW}[{i}/{len(targets)}] {t}{Colors.RESET}")
            ok, m = self.config.set_target(t)
            if not ok:
                print(error(f"Skip: {m}"))
                continue
            self._update_prompt()
            self.results.reset()
            self.do_fullscan("")
            self.do_save("all")

    def do_resume(self, arg):
        """Resume scan."""
        data = ScanResults.load_progress()
        if not data:
            print(error("No saved scan"))
            return
        print(info(f"Resuming: {data['target']}"))
        self.config.set_target(data["target"])
        self.config.ports = data.get("ports_remaining", [])
        self.results.open_ports = data.get("open_ports", [])
        self._update_prompt()
        self.do_portscan("")
        ScanResults.clear_progress()

    # ========== REPORTS ==========
    def do_save(self, arg):
        """Save report: text|json|markdown|html|xml|grep|all"""
        if not self.results.host_status and not self.results.open_ports:
            print(error("No results"))
            return
        fmt = arg.strip().lower() or "text"
        rp = Reporter(self.config, self.results)
        if fmt == "all":
            for f in ["text","json","markdown","html","xml","grep"]:
                ok, r = rp.save_report(f)
                print(success(f"Saved: {r}") if ok else error(r))
        else:
            ok, r = rp.save_report(fmt)
            print(success(f"Saved: {r}") if ok else error(r))

    def do_report(self, arg):
        """Display report: text|json|markdown|xml"""
        if not self.results.host_status and not self.results.open_ports:
            print(error("No results"))
            return
        rp = Reporter(self.config, self.results)
        fmt = arg.strip().lower() or "text"
        gens = {"text":rp.generate_text,"json":rp.generate_json,"markdown":rp.generate_markdown,"xml":rp.generate_xml}
        if fmt in gens:
            print(gens[fmt]())
        else:
            print(error("Use: text|json|markdown|xml"))

    # ========== UTILITY ==========
    def do_reset(self, arg):
        self.config.reset()
        self.results.reset()
        self._update_prompt()
        print(success("Reset done"))

    def do_clear(self, arg):
        clear_screen()

    def do_banner(self, arg):
        print(banner())

    def do_status(self, arg):
        print(f"\n{Colors.CYAN}[Status]{Colors.RESET}")
        print(f"  Target    : {self.config.target or 'Not set'}")
        print(f"  Ports     : {len(self.config.ports)}")
        print(f"  Open      : {len(self.results.open_ports)}")
        print(f"  Services  : {len(self.results.service_info)}")
        print(f"  Vulns     : {len(self.results.vulnerabilities)}")
        print(f"  CVEs      : {len(self.results.cve_list)}")
        print(f"  Subs      : {len(self.results.subdomains)}")
        print(f"  Techs     : {len(self.results.technologies)}")
        print()

    def do_exit(self, arg):
        print(f"\n{Colors.CYAN}Exiting N3TSpkiter.{Colors.RESET}\n")
        return True

    def do_quit(self, arg):
        return self.do_exit(arg)

    def do_EOF(self, arg):
        return self.do_exit(arg)

    def do_help(self, arg):
        """Quick help - main commands."""
        if arg:
            super().do_help(arg)
            return
        print(f"\n{Colors.BOLD}{Colors.CYAN}N3TSpkiter Commands{Colors.RESET}")
        print(f"  Type 'fullhelp' for detailed help\n")
        cats = {
            "Core Scanning": [
                ("set target <ip/domain>", "Set scan target"),
                ("set ports <range/preset>", "Set ports (top100/top1000/common/all)"),
                ("set scan-type <type>", "tcp-connect/udp/syn/fin/xmas/null/ack/window"),
                ("set intensity <1-5>", "Scan speed"),
                ("hostcheck", "Host discovery (DNS+Ping+TCP)"),
                ("portscan", "Port scan"),
                ("probe", "Service & version detection"),
                ("os-detect", "OS detection"),
                ("traceroute", "Network traceroute"),
                ("sweep <cidr>", "Network ping sweep"),
            ],
            "Web & DNS Recon": [
                ("dnsenum", "DNS enumeration (A,MX,NS,TXT,SOA)"),
                ("subenum", "Subdomain enumeration"),
                ("direnum", "Directory enumeration"),
                ("headers", "HTTP header analysis"),
                ("certinfo", "SSL/TLS certificate info"),
                ("techdetect", "Technology detection"),
                ("vhostenum", "Virtual host enumeration"),
            ],
            "Service & Network": [
                ("probe", "SSH/FTP/SMTP/SMB/DB enumeration"),
                ("macdetect", "MAC address detection"),
                ("netdist", "Network distance/RTT"),
            ],
            "Vulnerability & CVE": [
                ("vulnscan", "Vulnerability scanning"),
                ("cvedetect", "CVE detection & mapping"),
                ("aggressive", "Aggressive scan"),
                ("fullscan", "Complete auto recon"),
            ],
            "Firewall Evasion": [
                ("set fragment/mtu/decoys/ttl", "Firewall evasion"),
                ("set spoof-ip/spoof-port/spoof-mac", "Spoofing"),
                ("set bad-checksum/data-length", "IDS testing"),
            ],
            "Results & Reports": [
                ("show results/ports/services/os", "View scan data"),
                ("show vulns/cves/techs/subs", "View recon data"),
                ("show headers/cert/dirs/all", "View web data"),
                ("save text/json/html/xml/all", "Export reports"),
                ("report text/json", "View report in terminal"),
                ("scanlist <file>", "Multi-target scan"),
                ("resume", "Resume interrupted scan"),
            ],
            "Utilities": [
                ("dns <domain>", "DNS lookup"),
                ("whois <target>", "WHOIS lookup"),
                ("status", "Quick status"),
                ("banner", "Show banner"),
                ("clear", "Clear screen"),
                ("reset", "Reset all"),
                ("exit", "Exit tool"),
            ],
        }
        for cat, cmds in cats.items():
            print(f"  {Colors.YELLOW}{cat}{Colors.RESET}")
            for c, d in cmds:
                print(f"    {Colors.GREEN}{c:<42}{Colors.RESET}{d}")
            print()

    def do_fullhelp(self, arg):
        """Full help - all commands with details."""
        print(f"\n{Colors.BOLD}{Colors.CYAN}N3TSpkiter - All Commands{Colors.RESET}\n")
        cats = {
            "Target & Config": [
                ("set target <ip/domain/cidr>", "Set scan target"),
                ("set ports <range/preset>", "Set ports (top100/top1000/common/all/22,80,443/1-1000)"),
                ("set intensity <1-5>", "Scan speed (1=slow 5=fast)"),
                ("set timeout <seconds>", "Connection timeout"),
                ("set threads <number>", "Parallel threads"),
                ("set scan-delay <seconds>", "Delay between retries"),
                ("set max-retries <number>", "Max retry attempts"),
                ("set exclude-ports <ports>", "Exclude ports from scan"),
                ("set skip-ping on/off", "Skip host discovery"),
                ("set verbose on/off", "Verbose output"),
                ("set debug on/off", "Debug output"),
                ("show config", "Show current settings"),
            ],
            "Core Scanning": [
                ("hostcheck", "Host discovery (DNS+Ping+TCP)"),
                ("portscan", "Port scan (uses set scan-type)"),
                ("probe", "Service & version detection"),
                ("os-detect", "OS detection (TTL+Banner+TCP)"),
                ("traceroute", "Network traceroute"),
                ("sweep <cidr>", "Network ping sweep"),
            ],
            "Scan Types": [
                ("set scan-type tcp-connect", "TCP full connect scan"),
                ("set scan-type udp", "UDP scan"),
                ("set scan-type syn", "SYN stealth scan (root)"),
                ("set scan-type fin", "FIN scan (root)"),
                ("set scan-type xmas", "XMAS scan (root)"),
                ("set scan-type null", "NULL scan (root)"),
                ("set scan-type ack", "ACK scan - firewall detect (root)"),
                ("set scan-type maimon", "Maimon scan (root)"),
                ("set scan-type window", "Window scan"),
                ("set scanflags <hex>", "Custom TCP flags (root)"),
            ],
            "Firewall Evasion": [
                ("set fragment on/off", "Packet fragmentation"),
                ("set mtu <size>", "Custom MTU (multiple of 8)"),
                ("set decoys RND,RND,ME,RND", "Decoy scan"),
                ("set spoof-ip <ip>", "Source IP spoofing"),
                ("set spoof-port <port>", "Source port spoofing"),
                ("set spoof-mac RND/<mac>", "MAC address spoofing"),
                ("set data-length <bytes>", "Packet padding"),
                ("set bad-checksum on/off", "Bad checksum (IDS test)"),
                ("set ttl <1-255>", "Custom TTL value"),
                ("set min-rate <packets>", "Min packet rate"),
                ("set max-rate <packets>", "Max packet rate"),
            ],
            "Web & DNS Recon": [
                ("dnsenum", "DNS enumeration (A,MX,NS,TXT,SOA)"),
                ("subenum", "Subdomain enumeration"),
                ("direnum", "Directory enumeration"),
                ("headers", "HTTP header analysis"),
                ("certinfo", "SSL/TLS certificate info"),
                ("techdetect", "Technology detection"),
                ("vhostenum", "Virtual host enumeration"),
            ],
            "Service Enumeration": [
                ("probe", "SSH/FTP/SMTP/SMB/DB enumeration"),
                ("macdetect", "MAC address detection"),
                ("netdist", "Network distance & RTT"),
            ],
            "Vulnerability & CVE": [
                ("vulnscan", "Vulnerability scanning"),
                ("cvedetect", "CVE detection & mapping"),
                ("aggressive", "Aggressive scan (all features)"),
                ("fullscan", "Complete auto recon"),
            ],
            "Results & Reports": [
                ("show results", "Scan result summary"),
                ("show ports", "All port details"),
                ("show ports open", "Open ports only"),
                ("show services", "Service details"),
                ("show os", "OS detection results"),
                ("show vulns", "Vulnerability results"),
                ("show cves", "CVE detection results"),
                ("show techs", "Detected technologies"),
                ("show subs", "Found subdomains"),
                ("show headers", "HTTP headers"),
                ("show cert", "Certificate info"),
                ("show dirs", "Found directories"),
                ("show all", "Show everything"),
                ("save text/json/html/xml/markdown/grep/all", "Export reports"),
                ("report text/json/xml/markdown", "View report in terminal"),
                ("scanlist <file>", "Scan targets from file"),
                ("resume", "Resume interrupted scan"),
            ],
            "Utilities": [
                ("dns <domain>", "DNS lookup"),
                ("whois <target>", "WHOIS lookup"),
                ("status", "Quick status overview"),
                ("banner", "Show tool banner"),
                ("clear", "Clear screen"),
                ("reset", "Reset all settings"),
                ("exit / quit", "Exit tool"),
            ],
        }
        for cat, cmds in cats.items():
            print(f"  {Colors.YELLOW}{cat}{Colors.RESET}")
            for c, d in cmds:
                print(f"    {Colors.GREEN}{c:<45}{Colors.RESET}{d}")
            print()

    def emptyline(self):
        pass
