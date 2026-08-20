import socket
import struct
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class PortScanner:
    def __init__(self, config, results):
        self.config = config
        self.results = results
        self.lock = threading.Lock()
        self.scanned = 0
        self.total = 0
        self.scanning = False
        self.progress_callback = None

    def set_progress_callback(self, cb):
        self.progress_callback = cb

    def tcp_connect_scan(self):
        self._run_scan("TCP Connect", self._tcp_connect_port)

    def udp_scan(self):
        self._run_scan("UDP", self._udp_scan_port, max_threads=50)

    def window_scan(self):
        self._run_scan("Window", self._tcp_connect_port)

    def syn_scan(self):
        self._raw_scan_all(0x02, "SYN Stealth", "syn")

    def fin_scan(self):
        self._raw_scan_all(0x01, "FIN", "fin")

    def xmas_scan(self):
        self._raw_scan_all(0x29, "XMAS", "xmas")

    def null_scan(self):
        self._raw_scan_all(0x00, "NULL", "null")

    def ack_scan(self):
        self._raw_scan_all(0x10, "ACK", "ack")

    def maimon_scan(self):
        self._raw_scan_all(0x11, "Maimon", "maimon")

    def custom_scan(self, flags):
        self._raw_scan_all(flags, f"Custom(0x{flags:02x})", "custom")

    def _run_scan(self, name, scan_func, max_threads=None):
        target = self.config.resolved_ip or self.config.target
        ports = sorted(self.config.ports) if self.config.sequential else self.config.ports
        self.total = len(ports)
        self.scanned = 0
        self.scanning = True
        self.results.scan_type_used = name
        self.results.start_timer()
        threads = max_threads or self.config.threads
        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(scan_func, target, p): p for p in ports}
                try:
                    for f in as_completed(futures):
                        try:
                            f.result(timeout=self.config.timeout + 3)
                        except Exception:
                            pass
                        with self.lock:
                            self.scanned += 1
                        if self.config.max_rate > 0:
                            time.sleep(1.0 / self.config.max_rate)
                except KeyboardInterrupt:
                    print("\n\033[93m[!] Interrupted.\033[0m")
                    ex.shutdown(wait=False, cancel_futures=True)
        except KeyboardInterrupt:
            pass
        self.results.stop_timer()
        self.results.open_ports.sort()
        self.scanning = False

    def _tcp_connect_port(self, target, port):
        family = socket.AF_INET6 if self.config.is_ipv6 else socket.AF_INET
        attempts = self.config.max_retries + 1
        state, reason = "filtered", "No response"
        for attempt in range(attempts):
            if self.config.scan_delay > 0 and attempt > 0:
                time.sleep(self.config.scan_delay)
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            if self.config.ttl_value > 0:
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, self.config.ttl_value)
                except Exception:
                    pass
            try:
                r = sock.connect_ex((target, port))
                if r == 0:
                    state, reason = "open", "SYN-ACK received"
                    break
                else:
                    state, reason = "closed", f"errno:{r}"
            except socket.timeout:
                state, reason = "filtered", "Timeout"
            except ConnectionRefusedError:
                state, reason = "closed", "RST"
                break
            except OSError as e:
                state, reason = "filtered", str(e)[:30]
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        with self.lock:
            self.results.add_port_result(port, state, reason=reason, protocol="tcp")
        if state == "open" and self.progress_callback:
            self.progress_callback(port, "open")
        if self.config.debug_mode:
            print(f"    \033[2m[DBG] {port}/tcp={state} ({reason})\033[0m")

    def _udp_scan_port(self, target, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.config.timeout * 2)
        try:
            sock.sendto(b"\x00" * max(1, self.config.data_length), (target, port))
            try:
                data, _ = sock.recvfrom(1024)
                with self.lock:
                    self.results.add_port_result(port, "open", reason="UDP response", protocol="udp")
                if self.progress_callback:
                    self.progress_callback(port, "open")
            except socket.timeout:
                with self.lock:
                    self.results.add_port_result(port, "open|filtered", reason="No response", protocol="udp")
        except ConnectionRefusedError:
            with self.lock:
                self.results.add_port_result(port, "closed", reason="ICMP unreachable", protocol="udp")
        except Exception as e:
            with self.lock:
                self.results.add_port_result(port, "filtered", reason=str(e)[:30], protocol="udp")
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _checksum(self, data):
        if len(data) % 2:
            data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return ~s & 0xffff

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _build_ip_header(self, src, dst, payload_len):
        ttl = self.config.ttl_value if self.config.ttl_value > 0 else 64
        flags_offset = 0x2000 if self.config.fragment else 0
        h = struct.pack("!BBHHHBBH4s4s",
                        0x45, 0, 20 + payload_len, random.randint(1, 65535),
                        flags_offset, ttl, socket.IPPROTO_TCP, 0,
                        socket.inet_aton(src), socket.inet_aton(dst))
        ck = self._checksum(h)
        return h[:10] + struct.pack("!H", ck) + h[12:]

    def _build_tcp_packet(self, src, dst, dport, flags):
        sport = self.config.spoof_source_port or random.randint(1024, 65535)
        seq = random.randint(0, 0xFFFFFFFF)
        pad = b"\x00" * self.config.data_length
        h = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags,
                        socket.htons(8192), 0, 0)
        psh = struct.pack("!4s4sBBH", socket.inet_aton(src), socket.inet_aton(dst),
                          0, socket.IPPROTO_TCP, len(h) + len(pad))
        ck = random.randint(1, 65535) if self.config.bad_checksum else self._checksum(psh + h + pad)
        h = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags,
                        socket.htons(8192), ck, 0)
        return h + pad

    def _check_root(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.close()
            return True
        except Exception:
            return False

    def _raw_scan_all(self, flags, name, stype):
        if not self._check_root():
            print(f"\033[91m[-] {name} requires root/sudo.\033[0m")
            return
        target = self.config.resolved_ip or self.config.target
        src = self.config.spoof_source_ip or self._get_local_ip()
        ports = sorted(self.config.ports) if self.config.sequential else self.config.ports
        self.total = len(ports)
        self.scanned = 0
        self.scanning = True
        self.results.scan_type_used = name
        self.results.start_timer()
        ev = []
        if self.config.fragment: ev.append("Fragment")
        if self.config.decoy_ips: ev.append(f"Decoys({len(self.config.decoy_ips)})")
        if self.config.spoof_source_ip: ev.append(f"SpoofIP")
        if self.config.spoof_source_port: ev.append(f"SpoofPort({self.config.spoof_source_port})")
        if self.config.bad_checksum: ev.append("BadSum")
        if self.config.ttl_value: ev.append(f"TTL({self.config.ttl_value})")
        if ev:
            print(f"  \033[93m[Evasion] {', '.join(ev)}\033[0m")
        try:
            with ThreadPoolExecutor(max_workers=self.config.threads) as ex:
                futures = {ex.submit(self._raw_port, src, target, p, flags, stype): p for p in ports}
                try:
                    for f in as_completed(futures):
                        try:
                            f.result(timeout=self.config.timeout + 3)
                        except Exception:
                            pass
                        with self.lock:
                            self.scanned += 1
                except KeyboardInterrupt:
                    print(f"\n\033[93m[!] {name} interrupted.\033[0m")
                    ex.shutdown(wait=False, cancel_futures=True)
        except KeyboardInterrupt:
            pass
        self.results.stop_timer()
        self.scanning = False

    def _raw_port(self, src, dst, port, flags, stype):
        ss = rs = None
        try:
            rs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            rs.settimeout(self.config.timeout + 1)
            ss = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            ss.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            if self.config.decoy_ips:
                for d in self.config.decoy_ips:
                    if d == "ME":
                        continue
                    try:
                        tcp = self._build_tcp_packet(d, dst, port, flags)
                        ip = self._build_ip_header(d, dst, len(tcp))
                        ss.sendto(ip + tcp, (dst, 0))
                    except Exception:
                        pass
                    time.sleep(0.01)
            tcp = self._build_tcp_packet(src, dst, port, flags)
            ip = self._build_ip_header(src, dst, len(tcp))
            pkt = ip + tcp
            if self.config.fragment and self.config.mtu_size > 0:
                frags = self._fragment(pkt, self.config.mtu_size)
                for fr in frags:
                    ss.sendto(fr, (dst, 0))
            else:
                ss.sendto(pkt, (dst, 0))
            if self.config.debug_mode:
                print(f"    \033[2m[DBG] Sent {stype} -> {dst}:{port} flags=0x{flags:02x}\033[0m")
            start = time.time()
            while time.time() - start < (self.config.timeout + 1):
                try:
                    data = rs.recv(4096)
                    if not data or len(data) < 40:
                        continue
                    ihl = (data[0] & 0x0F) * 4
                    if len(data) < ihl + 20:
                        continue
                    sp = struct.unpack("!H", data[ihl:ihl + 2])[0]
                    if sp != port:
                        continue
                    tf = data[ihl + 13]
                    if self.config.debug_mode:
                        print(f"    \033[2m[DBG] Response {dst}:{port} flags=0x{tf:02x}\033[0m")
                    self._analyze(port, tf, stype)
                    return
                except socket.timeout:
                    break
                except Exception:
                    break
            self._no_response(port, stype)
        except Exception as e:
            with self.lock:
                self.results.add_port_result(port, "filtered", reason=str(e)[:40], protocol="tcp")
        finally:
            for s in [ss, rs]:
                try:
                    if s:
                        s.close()
                except Exception:
                    pass

    def _analyze(self, port, tf, stype):
        if stype == "syn":
            if tf & 0x12:
                with self.lock:
                    self.results.add_port_result(port, "open", reason="SYN-ACK", protocol="tcp")
                if self.progress_callback:
                    self.progress_callback(port, "open")
            elif tf & 0x04:
                with self.lock:
                    self.results.add_port_result(port, "closed", reason="RST", protocol="tcp")
        elif stype == "ack":
            if tf & 0x04:
                with self.lock:
                    self.results.add_port_result(port, "unfiltered", reason="RST", protocol="tcp")
            else:
                with self.lock:
                    self.results.add_port_result(port, "filtered", reason="No RST", protocol="tcp")
        else:
            if tf & 0x04:
                with self.lock:
                    self.results.add_port_result(port, "closed", reason="RST", protocol="tcp")
            else:
                with self.lock:
                    self.results.add_port_result(port, "open|filtered", reason="No RST", protocol="tcp")

    def _no_response(self, port, stype):
        if stype == "syn":
            with self.lock:
                self.results.add_port_result(port, "filtered", reason="No response", protocol="tcp")
        elif stype == "ack":
            with self.lock:
                self.results.add_port_result(port, "filtered", reason="No response", protocol="tcp")
        else:
            with self.lock:
                self.results.add_port_result(port, "open|filtered", reason="No response", protocol="tcp")
            if self.progress_callback:
                self.progress_callback(port, "open|filtered")

    def _fragment(self, pkt, mtu):
        iph = pkt[:20]
        payload = pkt[20:]
        frags = []
        fs = max(8, mtu - 20)
        off = 0
        while off < len(payload):
            chunk = payload[off:off + fs]
            mf = 1 if (off + fs) < len(payload) else 0
            fo = (mf << 13) | (off // 8)
            fh = bytearray(iph)
            struct.pack_into("!H", fh, 6, fo)
            struct.pack_into("!H", fh, 2, 20 + len(chunk))
            fh[10] = fh[11] = 0
            ck = self._checksum(bytes(fh))
            struct.pack_into("!H", fh, 10, ck)
            frags.append(bytes(fh) + chunk)
            off += fs
        return frags

    def ping_sweep(self, cidr):
        import ipaddress, subprocess, platform
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return []
        live = []
        p = "-n" if platform.system().lower() == "windows" else "-c"
        def ping(ip):
            try:
                r = subprocess.run(["ping", p, "1", "-W", "1", str(ip)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
                return str(ip) if r.returncode == 0 else None
            except Exception:
                return None
        try:
            with ThreadPoolExecutor(max_workers=50) as ex:
                for f in as_completed({ex.submit(ping, ip): ip for ip in net.hosts()}):
                    r = f.result()
                    if r:
                        live.append(r)
        except KeyboardInterrupt:
            pass
        return sorted(live, key=lambda x: ipaddress.ip_address(x))

    def get_progress(self):
        return round((self.scanned / self.total) * 100, 1) if self.total else 0
