#!/usr/bin/env python3
"""
Termux network scanner + authorized load generator.
Use only on hosts you own or have explicit permission to test.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

try:
    import urllib.request
except ImportError:
    urllib = None  # type: ignore

CLR_RED = "\033[1;31m"
CLR_GREEN = "\033[1;32m"
CLR_YELLOW = "\033[1;33m"
CLR_CYAN = "\033[1;36m"
CLR_MAGENTA = "\033[1;35m"
CLR_WHITE = "\033[1;37m"
CLR_RESET = "\033[0m"

BANNER = f"""
{CLR_RED}╔══════════════════════════════════════════════════════════╗
║   TERMUX NET STRESS / LOAD TOOL  v3  (authorized use)    ║
╚══════════════════════════════════════════════════════════╝{CLR_RESET}
"""

LOAD_PRESETS: dict[str, dict[str, object]] = {
    "1": {"name": "Lite UDP", "threads": 25, "duration": 10, "size": 512, "mode": "udp"},
    "2": {"name": "Web storm", "threads": 60, "duration": 20, "size": 1024, "mode": "http"},
    "3": {"name": "TCP hammer", "threads": 100, "duration": 30, "size": 2048, "mode": "tcp-hold"},
    "4": {"name": "POST flood", "threads": 80, "duration": 25, "size": 4096, "mode": "http-post"},
}

MAX_THREADS = 512
MAX_DURATION = 3600
MAX_PACKET = 65507

PORT_SERVICE: dict[int, str] = {
    22: "SSH",
    80: "Web",
    443: "HTTPS",
    445: "SMB",
    554: "Camera/RTSP",
    8009: "Cast",
    8080: "Web-alt",
    8443: "HTTPS-alt",
}

# Common MAC OUI prefixes (vendor hint on LAN)
OUI_VENDORS: dict[str, str] = {
    "00:17:88": "Philips Hue",
    "18:b4:30": "Google/Nest",
    "28:6c:07": "Xiaomi",
    "3c:28:6d": "Google",
    "44:65:0d": "Amazon",
    "50:dc:ec": "Apple",
    "58:41:20": "Huawei",
    "5c:ea:1d": "Microsoft",
    "68:ff:7b": "TP-Link",
    "84:0d:8e": "Espressif",
    "a4:77:33": "Google",
    "ac:bc:32": "Apple",
    "b0:be:76": "Samsung",
    "bc:92:6b": "Apple",
    "c0:17:4d": "Samsung",
    "d8:1c:79": "Amazon",
    "dc:a6:32": "Raspberry Pi",
    "e0:91:53": "Xiaomi",
    "f0:18:98": "Apple",
    "f4:f5:d8": "Google",
    "fc:ec:da": "Ubiquiti",
}


@dataclass
class RunStats:
    ok: int = 0
    fail: int = 0
    bytes_out: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add_ok(self, nbytes: int) -> None:
        with self.lock:
            self.ok += 1
            self.bytes_out += nbytes

    def add_fail(self) -> None:
        with self.lock:
            self.fail += 1

    def snapshot(self) -> tuple[int, int, int]:
        with self.lock:
            return self.ok, self.fail, self.bytes_out


def supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text: str, code: str) -> str:
    if not supports_color():
        return text
    return f"{code}{text}{CLR_RESET}"


def parse_target(raw: str) -> tuple[str, int, str, bool]:
    """Returns host, port, path, use_tls from URL or host:port."""
    raw = raw.strip()
    if "://" not in raw:
        if "/" in raw:
            raw = "http://" + raw
        elif ":" in raw and raw.rsplit(":", 1)[-1].isdigit():
            host, port_s = raw.rsplit(":", 1)
            return host, int(port_s), "/", False
        return raw, 80, "/", False

    parsed = urllib.parse.urlparse(raw)
    host = parsed.hostname or "127.0.0.1"
    use_tls = parsed.scheme == "https"
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return host, port, path, use_tls


def is_loopback_or_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except (socket.gaierror, ValueError):
        return False


def require_authorization(host: str, skip: bool) -> None:
    if skip or is_loopback_or_private(host):
        return
    print(c("\n[!] Target is not private/loopback.", CLR_YELLOW))
    print("    Load testing third-party systems without permission is illegal.")
    typed = input(c("    Type exactly: I HAVE PERMISSION\n> ", CLR_WHITE)).strip()
    if typed != "I HAVE PERMISSION":
        print(c("[x] Aborted.", CLR_RED))
        sys.exit(1)


class NetworkTester:
    def __init__(self) -> None:
        self.stop = threading.Event()
        self.stats = RunStats()
        self.scan_notice = ""

    def get_primary_local_ip(self) -> Optional[str]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("1.1.1.1", 80))
                return s.getsockname()[0]
        except OSError:
            return None

    def get_default_gateway(self) -> Optional[str]:
        try:
            out = subprocess.check_output(
                ["ip", "route", "show", "default"],
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            for line in out.decode("utf-8", errors="replace").splitlines():
                parts = line.split()
                if "via" in parts:
                    idx = parts.index("via")
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
        except (subprocess.SubprocessError, FileNotFoundError, ValueError):
            pass
        for prop in ("dhcp.wlan0.gateway", "dhcp.eth0.gateway", "dhcp.wlan1.gateway"):
            try:
                out = subprocess.check_output(
                    ["getprop", prop],
                    stderr=subprocess.DEVNULL,
                    timeout=2,
                )
                gw = out.decode("utf-8", errors="replace").strip()
                if gw and gw != "0.0.0.0":
                    return gw
            except (subprocess.SubprocessError, FileNotFoundError):
                continue
        return None

    def get_arp_table(self) -> dict[str, str]:
        table: dict[str, str] = {}
        try:
            with open("/proc/net/arp", encoding="utf-8", errors="replace") as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    ip, mac = parts[0], parts[3].upper()
                    if mac != "00:00:00:00:00:00":
                        table[ip] = mac
        except OSError:
            pass
        return table

    def resolve_hostname(self, ip: str) -> Optional[str]:
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(socket.gethostbyaddr, ip)
                name, _, _ = fut.result(timeout=1.2)
            short = name.rstrip(".").split(".")[0]
            if short and short != ip:
                return short
        except Exception:
            pass
        return None

    def vendor_from_mac(self, mac: str) -> Optional[str]:
        norm = mac.upper().replace("-", ":")
        prefix = norm[:8]
        return OUI_VENDORS.get(prefix)

    def label_for_host(
        self,
        ip: str,
        port: Optional[int] = None,
        role: Optional[str] = None,
        arp: Optional[dict[str, str]] = None,
    ) -> str:
        arp = arp if arp is not None else self.get_arp_table()
        bits: list[str] = []
        if role:
            bits.append(role)
        host = self.resolve_hostname(ip)
        if host:
            bits.append(host)
        mac = arp.get(ip)
        if mac:
            vendor = self.vendor_from_mac(mac)
            if vendor and (not host or vendor.lower() not in host.lower()):
                bits.append(vendor)
        if port is not None:
            svc = PORT_SERVICE.get(port, f"port {port}")
            bits.append(svc)
        title = " / ".join(bits) if bits else "Unknown device"
        return f"{title} ({ip})"

    def format_services(self, ports: list[int]) -> str:
        if not ports:
            return "-"
        labels = [f"{p}({PORT_SERVICE.get(p, '?')})" for p in ports[:5]]
        extra = f" +{len(ports) - 5}" if len(ports) > 5 else ""
        return ",".join(labels) + extra

    def http_server_hint(self, ip: str, port: int = 80, timeout: float = 1.2) -> Optional[str]:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                req = f"GET / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode("ascii"))
                data = s.recv(2048).decode("latin-1", errors="replace")
            for line in data.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()[:32]
            lower = data.lower()
            if "<title>" in lower:
                start = lower.index("<title>") + 7
                end = lower.find("</title>", start)
                if end > start:
                    return data[start:end].strip()[:32]
        except OSError:
            pass
        return None

    def tcp_latency_ms(self, ip: str, port: int, timeout: float = 1.0) -> Optional[float]:
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return (time.perf_counter() - start) * 1000.0
        except OSError:
            return None

    def make_host_entry(
        self,
        ip: str,
        *,
        open_ports: Optional[list[int]] = None,
        role: Optional[str] = None,
        trust: str = "LIVE",
        rssi: int = -48,
        arp: Optional[dict[str, str]] = None,
    ) -> dict:
        arp = arp if arp is not None else self.get_arp_table()
        ports = sorted(set(open_ports or []))
        pick = ports[0] if ports else None
        name = self.label_for_host(ip, pick, role=role, arp=arp)
        if ports and pick in (80, 8080, 8000):
            hint = self.http_server_hint(ip, pick)
            if hint:
                name = f"{name.split(' (')[0]} [{hint}] ({ip})"
        mac = arp.get(ip, "")
        lat = self.tcp_latency_ms(ip, pick) if pick else None
        return {
            "ssid": name,
            "bssid": ip,
            "rssi": rssi,
            "frequency": 0,
            "ports": ports,
            "mac": mac,
            "trust": trust,
            "latency_ms": lat,
        }

    def suggest_port_for_mode(self, ports: list[int], mode: str) -> int:
        if not ports:
            return 443 if mode.startswith("http") else 80
        if mode in ("http", "http-post"):
            for p in (80, 8080, 8000, 443, 8443):
                if p in ports:
                    return p
        if mode == "udp":
            for p in (53, 443, 80):
                if p in ports:
                    return p
        return ports[0]

    def get_ip_neigh_neighbors(self) -> list[dict]:
        neighbors: list[dict] = []
        try:
            out = subprocess.check_output(
                ["ip", "neigh", "show"],
                stderr=subprocess.DEVNULL,
                timeout=4,
            )
            for line in out.decode("utf-8", errors="replace").splitlines():
                parts = line.split()
                if not parts:
                    continue
                ip = parts[0]
                state = parts[-1] if parts else ""
                if state not in ("REACHABLE", "STALE", "DELAY", "PROBE"):
                    continue
                try:
                    if not ipaddress.ip_address(ip).is_private:
                        continue
                except ValueError:
                    continue
                neighbors.append(
                    {
                        "ssid": self.label_for_host(ip),
                        "bssid": ip,
                        "rssi": -52,
                        "frequency": 0,
                    }
                )
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return neighbors

    def _probe_open_ports(self, ip: str, ports: tuple[int, ...], timeout: float) -> list[int]:
        open_ports: list[int] = []
        for port in ports:
            try:
                with socket.create_connection((ip, port), timeout=timeout):
                    open_ports.append(port)
            except OSError:
                continue
        return open_ports

    def scan_lan_hosts(self, local_ip: str, timeout: float = 0.35) -> list[dict]:
        """Find active hosts on the same /24 WiFi LAN (open TCP port probe)."""
        try:
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        except ValueError:
            return []
        hosts = [str(h) for h in network.hosts() if str(h) != local_ip]
        ports = (80, 443, 8080, 8443, 22, 445, 554, 8009, 53, 62078)
        ip_ports: dict[str, list[int]] = {}
        done = 0
        total = len(hosts)
        with ThreadPoolExecutor(max_workers=48) as pool:
            futures = {pool.submit(self._probe_open_ports, ip, ports, timeout): ip for ip in hosts}
            for fut in as_completed(futures):
                ip = futures[fut]
                done += 1
                if done % 16 == 0 or done == total:
                    pct = int(done * 100 / max(total, 1))
                    sys.stdout.write(f"\r[*] LAN scan progress: {pct}% ({done}/{total})   ")
                    sys.stdout.flush()
                try:
                    open_ports = fut.result()
                except Exception:
                    continue
                if open_ports:
                    ip_ports[ip] = open_ports
        if total:
            sys.stdout.write("\n")
            sys.stdout.flush()

        arp = self.get_arp_table()
        gateway = self.get_default_gateway()
        found: list[dict] = []
        for ip, open_ports in ip_ports.items():
            role = "Router" if gateway and ip == gateway else None
            found.append(
                self.make_host_entry(
                    ip,
                    open_ports=open_ports,
                    role=role,
                    trust="LIVE",
                    arp=arp,
                )
            )
        return found

    def get_proc_arp_neighbors(self) -> list[dict]:
        neighbors: list[dict] = []
        try:
            with open("/proc/net/arp", encoding="utf-8", errors="replace") as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) < 4 or parts[3] == "00:00:00:00:00:00":
                        continue
                    ip = parts[0]
                    try:
                        if not ipaddress.ip_address(ip).is_private:
                            continue
                    except ValueError:
                        continue
                    neighbors.append(
                        {
                            "ssid": self.label_for_host(ip),
                            "bssid": ip,
                            "rssi": -58,
                            "frequency": 0,
                        }
                    )
        except OSError:
            pass
        return neighbors

    def get_connected_wifi_termux(self) -> Optional[dict]:
        try:
            out = subprocess.check_output(
                ["termux-wifi-connectioninfo"],
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            data = json.loads(out.decode("utf-8"))
            ssid = data.get("ssid") or "<WiFi>"
            ip = data.get("ip") or self.get_primary_local_ip()
            if not ip:
                return None
            return {
                "ssid": f"Connected: {ssid}",
                "bssid": ip,
                "rssi": int(data.get("rssi", -45)),
                "frequency": int(data.get("frequency") or 0),
            }
        except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError, TypeError, ValueError):
            return None

    def build_lan_entries(self) -> list[dict]:
        entries: list[dict] = []
        seen: set[str] = set()
        local_ip = self.get_primary_local_ip()
        gateway = self.get_default_gateway()
        if local_ip:
            entries.append(
                {
                    "ssid": f"This phone ({local_ip})",
                    "bssid": local_ip,
                    "rssi": -35,
                    "frequency": 0,
                    "trust": "LOCAL",
                    "ports": [],
                    "mac": self.get_arp_table().get(local_ip, ""),
                }
            )
            seen.add(local_ip)
        arp = self.get_arp_table()
        if gateway and gateway not in seen:
            entries.append(
                self.make_host_entry(gateway, role="Router", trust="ROUTE", rssi=-42, arp=arp)
            )
            seen.add(gateway)
        for item in self.get_proc_arp_neighbors():
            if item["bssid"] not in seen:
                entries.append(item)
                seen.add(item["bssid"])
        for item in self.get_ip_neigh_neighbors():
            if item["bssid"] not in seen:
                entries.append(item)
                seen.add(item["bssid"])
        return entries

    def _merge_network_lists(self, *lists: list[dict]) -> list[dict]:
        by_ip: dict[str, dict] = {}
        for lst in lists:
            for net in lst:
                ip = net.get("bssid", "")
                if not ip:
                    continue
                if ip not in by_ip:
                    by_ip[ip] = dict(net)
                    continue
                cur = by_ip[ip]
                cur_ports = set(cur.get("ports") or [])
                cur_ports.update(net.get("ports") or [])
                cur["ports"] = sorted(cur_ports)
                if net.get("trust") == "LIVE":
                    cur["trust"] = "LIVE"
                if len(str(net.get("ssid", ""))) > len(str(cur.get("ssid", ""))):
                    cur["ssid"] = net["ssid"]
                if net.get("latency_ms") is not None:
                    cur["latency_ms"] = net["latency_ms"]
                if net.get("mac"):
                    cur["mac"] = net["mac"]
        return list(by_ip.values())

    def get_wifi_scan_termux(self) -> list[dict]:
        notes: list[str] = []
        wifi_scan: list[dict] = []
        try:
            out = subprocess.check_output(
                ["termux-wifi-scaninfo"],
                stderr=subprocess.DEVNULL,
                timeout=8,
            )
            for item in json.loads(out.decode("utf-8")):
                bssid = item.get("bssid", "")
                if bssid and ":" in bssid and bssid.count(".") != 3:
                    display_ip = bssid
                else:
                    display_ip = item.get("ip") or bssid or "?"
                mac = item.get("bssid", "")
                ssid = item.get("ssid", "<HIDDEN>")
                wifi_scan.append(
                    {
                        "ssid": f"WiFi AP: {ssid}",
                        "bssid": mac if mac else display_ip,
                        "rssi": item.get("rssi", -100),
                        "frequency": item.get("frequency", 0),
                    }
                )
            notes.append("WiFi scan OK (termux-api)")
        except FileNotFoundError:
            notes.append("termux-wifi-scaninfo missing → pkg install termux-api + Termux:API app")
        except (subprocess.SubprocessError, json.JSONDecodeError):
            notes.append("WiFi scan failed → enable Location for Termux + Termux:API")

        connected = self.get_connected_wifi_termux()
        if connected:
            notes.append("connected WiFi OK")
        lan = self.build_lan_entries()
        local_ip = self.get_primary_local_ip()
        if local_ip:
            print(
                c(
                    "\n[*] Deep LAN scan (same WiFi). ~20-40 sec...\n",
                    CLR_CYAN,
                )
            )
            t0 = time.perf_counter()
            lan = self._merge_network_lists(lan, self.scan_lan_hosts(local_ip))
            notes.append(f"scan {time.perf_counter() - t0:.0f}s")
            if len(lan) > 1:
                notes.append("LAN active hosts scanned")
        if lan:
            notes.append("LAN IP/gateway detected")

        networks = self._merge_network_lists(
            ([connected] if connected else []),
            lan,
            wifi_scan,
        )

        if not networks:
            notes.append("no LAN data — showing examples only")
            networks = [
                {"ssid": "(example) localhost", "bssid": "127.0.0.1", "rssi": -30, "frequency": 0},
                {"ssid": "(example) gateway", "bssid": "192.168.1.1", "rssi": -42, "frequency": 0},
            ]

        self.scan_notice = " | ".join(notes)
        return networks

    def display_networks(self, networks: list[dict]) -> list[dict]:
        sorted_nets = sorted(networks, key=lambda x: x["rssi"], reverse=True)
        live = sum(1 for n in sorted_nets if n.get("trust") == "LIVE")
        print(
            c(
                f"\n[+] Targets: {len(sorted_nets)} total | {live} LIVE (TCP confirmed)\n",
                CLR_CYAN,
            )
        )
        print(c("LIVE=port open now | ROUTE=router guess | LOCAL=this phone\n", CLR_WHITE))
        hdr = f"{'#':<3} {'HOST':<22} {'IP':<15} {'OK':<5} {'ms':<5} {'PORTS'}"
        print(c(hdr, CLR_YELLOW))
        print("-" * 78)
        for idx, net in enumerate(sorted_nets):
            ip = net["bssid"]
            if not all(p.isdigit() or p == "." for p in ip.split(".")):
                ip = "?"
            trust = str(net.get("trust", "?"))[:5]
            if trust == "LIVE":
                trust = c("LIVE", CLR_GREEN)
            lat = net.get("latency_ms")
            lat_s = f"{lat:.0f}" if isinstance(lat, (int, float)) else "-"
            name = net.get("ssid", "?").split(" (")[0][:22]
            ports = self.format_services(net.get("ports") or [])
            tag = c("*", CLR_GREEN) if idx == 0 else " "
            print(f"{idx + 1:<3} {name:<22} {ip:<15} {trust:<5} {lat_s:<5} {ports} {tag}")
            mac = net.get("mac")
            if mac:
                print(c(f"    MAC {mac}", CLR_WHITE))
        return sorted_nets

    def ping_check(self, host: str, timeout: float = 2.0) -> Optional[float]:
        """TCP connect latency to :80 as lightweight reachability (Termux often lacks ping)."""
        start = time.perf_counter()
        try:
            with socket.create_connection((host, 80), timeout=timeout):
                return (time.perf_counter() - start) * 1000.0
        except OSError:
            for port in (443, 8080, 53):
                try:
                    with socket.create_connection((host, port), timeout=timeout):
                        return (time.perf_counter() - start) * 1000.0
                except OSError:
                    continue
        return None

    def _worker_udp(self, host: str, port: int, payload: bytes) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        addr = (host, port)
        while not self.stop.is_set():
            try:
                n = sock.sendto(payload, addr)
                self.stats.add_ok(n)
            except OSError:
                self.stats.add_fail()

    def _worker_tcp_burst(self, host: str, port: int, payload: bytes) -> None:
        while not self.stop.is_set():
            try:
                with socket.create_connection((host, port), timeout=1.0) as s:
                    s.sendall(payload)
                    self.stats.add_ok(len(payload))
            except OSError:
                self.stats.add_fail()

    def _worker_tcp_hold(self, host: str, port: int, payload: bytes) -> None:
        while not self.stop.is_set():
            s: Optional[socket.socket] = None
            try:
                s = socket.create_connection((host, port), timeout=2.0)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                while not self.stop.is_set():
                    s.sendall(payload)
                    self.stats.add_ok(len(payload))
            except OSError:
                self.stats.add_fail()
            finally:
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    def _worker_http(
        self,
        host: str,
        port: int,
        path: str,
        use_tls: bool,
        method: str,
        body: bytes,
    ) -> None:
        ctx = ssl.create_default_context() if use_tls else None
        while not self.stop.is_set():
            try:
                raw = socket.create_connection((host, port), timeout=3.0)
                if use_tls and ctx:
                    sock = ctx.wrap_socket(raw, server_hostname=host)
                else:
                    sock = raw
                req = (
                    f"{method} {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Connection: close\r\n"
                    f"User-Agent: TermuxNetTester/2\r\n"
                )
                if body and method == "POST":
                    req += f"Content-Length: {len(body)}\r\nContent-Type: application/octet-stream\r\n"
                req += "\r\n"
                blob = req.encode("ascii") + (body if method == "POST" else b"")
                sock.sendall(blob)
                self.stats.add_ok(len(blob))
                try:
                    sock.recv(4096)
                except OSError:
                    pass
                sock.close()
            except OSError:
                self.stats.add_fail()

    def _stats_loop(self, start: float, duration: int) -> None:
        last_ok, last_bytes, last_t = 0, 0, start
        while not self.stop.wait(0.5):
            now = time.perf_counter()
            ok, fail, nbytes = self.stats.snapshot()
            dt = max(now - last_t, 1e-6)
            rps = (ok - last_ok) / dt
            mbps = ((nbytes - last_bytes) * 8) / dt / 1_000_000
            elapsed = int(now - start)
            rem = max(0, duration - elapsed)
            line = (
                f"\r{c('[*]', CLR_GREEN)} ok={ok} fail={fail} "
                f"~{rps:.0f}/s {mbps:.2f} Mbit/s "
                f"elapsed={elapsed}s left={rem}s   "
            )
            sys.stdout.write(line)
            sys.stdout.flush()
            last_ok, last_bytes, last_t = ok, nbytes, now
            if elapsed >= duration:
                break

    def launch(
        self,
        host: str,
        port: int,
        threads: int,
        duration: int,
        packet_size: int,
        mode: str,
        path: str = "/",
        use_tls: bool = False,
        http_method: str = "GET",
    ) -> None:
        threads = max(1, min(threads, MAX_THREADS))
        duration = max(1, min(duration, MAX_DURATION))
        packet_size = max(64, min(packet_size, MAX_PACKET))
        payload = os.urandom(packet_size)

        workers: dict[str, Callable[[], None]] = {
            "udp": lambda: self._worker_udp(host, port, payload),
            "tcp": lambda: self._worker_tcp_burst(host, port, payload),
            "tcp-hold": lambda: self._worker_tcp_hold(host, port, payload),
            "http": lambda: self._worker_http(host, port, path, use_tls, http_method, b""),
            "http-post": lambda: self._worker_http(host, port, path, use_tls, "POST", payload),
        }
        if mode not in workers:
            print(c(f"Unknown mode: {mode}", CLR_RED))
            sys.exit(1)

        lat = self.ping_check(host)
        if lat is not None:
            print(c(f"[+] Reachability ~{lat:.0f} ms (TCP probe)", CLR_GREEN))
        else:
            print(c("[!] Target did not answer common TCP ports; test may show high fail rate.", CLR_YELLOW))

        print(c("\n[*] Starting load run", CLR_MAGENTA))
        print(f"    host={host} port={port} mode={mode} threads={threads} duration={duration}s payload={packet_size}B")
        if mode.startswith("http"):
            print(f"    path={path} tls={use_tls}")

        self.stop.clear()
        self.stats = RunStats()
        pool: list[threading.Thread] = []
        worker_fn = workers[mode]

        start = time.perf_counter()
        monitor = threading.Thread(target=self._stats_loop, args=(start, duration), daemon=True)
        monitor.start()

        for _ in range(threads):
            t = threading.Thread(target=worker_fn, daemon=True)
            t.start()
            pool.append(t)

        try:
            while time.perf_counter() - start < duration:
                time.sleep(0.2)
        except KeyboardInterrupt:
            print(c("\n[!] Interrupted.", CLR_RED))

        self.stop.set()
        monitor.join(timeout=1.0)
        for t in pool:
            t.join(timeout=0.3)

        ok, fail, nbytes = self.stats.snapshot()
        total = ok + fail
        print(
            c(
                f"\n\n[✓] Done. success={ok} fail={fail} "
                f"rate={(ok / max(total, 1)) * 100:.1f}% bytes≈{nbytes / 1024:.1f} KiB\n",
                CLR_GREEN,
            )
        )


def interactive_main(tester: NetworkTester) -> None:
    print(c("[1] Scanning Wi‑Fi / LAN...", CLR_CYAN))
    nets = tester.get_wifi_scan_termux()
    sorted_nets = tester.display_networks(nets)
    if tester.scan_notice:
        print(c(f"[*] {tester.scan_notice}", CLR_YELLOW))
    print(
        c(
            "\n[i] IP-k LIVE jelzésnél biztosak (TCP válasz). ROUTE = router, de port nem ellenőrzött.",
            CLR_WHITE,
        )
    )

    print(c("\n=== Target ===", CLR_YELLOW))
    choice = input("Index / IP / URL [2]: ").strip() or "2"
    sel: Optional[dict] = None
    if choice.isdigit() and 1 <= int(choice) <= len(sorted_nets):
        sel = sorted_nets[int(choice) - 1]
        raw = sel["bssid"]
        if not all(p.isdigit() or p == "." for p in raw.split(".")):
            raw = input(f"IP for '{sel['ssid']}': ").strip() or "127.0.0.1"
    else:
        raw = choice

    host, port, path, use_tls = parse_target(raw)

    print(c("\nPresets: 1=Lite UDP | 2=Web | 3=TCP hold | 4=POST | Enter=manual", CLR_MAGENTA))
    preset_in = input("Preset: ").strip()
    threads, duration, packet_size, mode = 100, 30, 1024, "udp"
    if preset_in in LOAD_PRESETS:
        p = LOAD_PRESETS[preset_in]
        threads = int(p["threads"])
        duration = int(p["duration"])
        packet_size = int(p["size"])
        mode = str(p["mode"])
        print(c(f"→ {p['name']}: {mode}, {threads} thr, {duration}s", CLR_GREEN))
    else:
        print(c("\nModes: udp | tcp | tcp-hold | http | http-post", CLR_CYAN))
        mode = input("Mode [http]: ").strip().lower() or "http"
        t_in = input("Threads [60]: ").strip()
        threads = int(t_in) if t_in.isdigit() else 60
        d_in = input("Duration seconds [20]: ").strip()
        duration = int(d_in) if d_in.isdigit() else 20
        s_in = input("Payload bytes [1024]: ").strip()
        packet_size = int(s_in) if s_in.isdigit() else 1024

    if sel and sel.get("ports"):
        port = tester.suggest_port_for_mode(sel["ports"], mode)
        print(c(f"[+] Auto port from scan: {port} (open: {sel['ports']})", CLR_GREEN))
    elif "://" not in choice and ":" not in choice:
        p_in = input(f"Port [{port}]: ").strip()
        if p_in.isdigit():
            port = int(p_in)

    if mode.startswith("http") and port in (443, 8443):
        use_tls = True
    if mode.startswith("http") and path == "/" and "://" in choice:
        _, port, path, use_tls = parse_target(choice)

    require_authorization(host, skip=False)
    tester.launch(host, port, threads, duration, packet_size, mode, path, use_tls)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Termux load generator (authorized targets only)")
    p.add_argument("-t", "--target", help="host, host:port, or http(s):// URL")
    p.add_argument("-m", "--mode", default="udp", choices=["udp", "tcp", "tcp-hold", "http", "http-post"])
    p.add_argument("-T", "--threads", type=int, default=100)
    p.add_argument("-d", "--duration", type=int, default=30)
    p.add_argument("-s", "--size", type=int, default=1024, help="UDP/TCP payload or POST body size")
    p.add_argument("-p", "--port", type=int, help="Override port when target is plain IP/host")
    p.add_argument("--skip-auth", action="store_true", help="Skip permission prompt (still your responsibility)")
    p.add_argument("-i", "--interactive", action="store_true", help="Wi‑Fi scan + menu")
    return p


def main() -> None:
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()
    tester = NetworkTester()

    if args.interactive or not args.target:
        interactive_main(tester)
        return

    host, port, path, use_tls = parse_target(args.target)
    if args.port is not None:
        port = args.port

    require_authorization(host, skip=args.skip_auth)
    tester.launch(
        host=host,
        port=port,
        threads=args.threads,
        duration=args.duration,
        packet_size=args.size,
        mode=args.mode,
        path=path,
        use_tls=use_tls,
    )


if __name__ == "__main__":
    main()
