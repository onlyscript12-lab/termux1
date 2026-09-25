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
║     TERMUX NET STRESS / LOAD TOOL  v2  (authorized use)  ║
╚══════════════════════════════════════════════════════════╝{CLR_RESET}
"""

MAX_THREADS = 512
MAX_DURATION = 3600
MAX_PACKET = 65507


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

    def get_wifi_scan_termux(self) -> list[dict]:
        networks: list[dict] = []
        try:
            out = subprocess.check_output(
                ["termux-wifi-scaninfo"],
                stderr=subprocess.DEVNULL,
                timeout=8,
            )
            for item in json.loads(out.decode("utf-8")):
                networks.append(
                    {
                        "ssid": item.get("ssid", "<HIDDEN>"),
                        "bssid": item.get("bssid", "00:00:00:00:00:00"),
                        "rssi": item.get("rssi", -100),
                        "frequency": item.get("frequency", 0),
                    }
                )
        except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError):
            networks = self.get_fallback_network_info()
        return networks

    def get_fallback_network_info(self) -> list[dict]:
        networks: list[dict] = []
        try:
            arp_out = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL, timeout=5)
            for line in arp_out.decode("utf-8", errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[1].strip("()")
                    mac = parts[3]
                    networks.append(
                        {
                            "ssid": f"Host ({ip})",
                            "bssid": ip,
                            "rssi": -50,
                            "frequency": 2412,
                        }
                    )
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        if not networks:
            networks.extend(
                [
                    {"ssid": "Localhost", "bssid": "127.0.0.1", "rssi": -30, "frequency": 0},
                    {"ssid": "Typical gateway", "bssid": "192.168.1.1", "rssi": -42, "frequency": 5000},
                    {"ssid": "LAN example", "bssid": "192.168.1.100", "rssi": -55, "frequency": 2437},
                ]
            )
        return networks

    def display_networks(self, networks: list[dict]) -> list[dict]:
        sorted_nets = sorted(networks, key=lambda x: x["rssi"], reverse=True)
        print(c("\n[+] Detected networks (strongest first):\n", CLR_CYAN))
        hdr = f"{'#':<4} {'SSID / HOST':<28} {'IP / BSSID':<18} {'dBm':<8} {'RANGE'}"
        print(c(hdr, CLR_YELLOW))
        print("-" * 78)
        for idx, net in enumerate(sorted_nets):
            rssi = net["rssi"]
            if rssi > -60:
                prox = c("CLOSE", CLR_GREEN)
            elif rssi > -75:
                prox = c("MID", CLR_YELLOW)
            else:
                prox = c("FAR", CLR_RED)
            tag = c(" *", CLR_GREEN) if idx == 0 else ""
            ip = net["bssid"]
            if not all(p.isdigit() or p == "." for p in ip.split(".")):
                ip = net.get("ssid", ip)
            print(f"{idx + 1:<4} {net['ssid'][:28]:<28} {ip:<18} {rssi:<8} {prox}{tag}")
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
    nets = tester.display_networks(tester.get_wifi_scan_termux())

    print(c("\n=== Target ===", CLR_YELLOW))
    choice = input("Index from list, host, or URL [127.0.0.1]: ").strip() or "127.0.0.1"
    if choice.isdigit() and 1 <= int(choice) <= len(nets):
        sel = nets[int(choice) - 1]
        raw = sel["bssid"]
        if not all(p.isdigit() or p == "." for p in raw.split(".")):
            raw = input(f"IP for '{sel['ssid']}': ").strip() or "127.0.0.1"
    else:
        raw = choice

    host, port, path, use_tls = parse_target(raw)
    if "://" not in choice and ":" not in choice:
        p_in = input(f"Port [{port}]: ").strip()
        if p_in.isdigit():
            port = int(p_in)

    print(c("\nModes: udp | tcp | tcp-hold | http | http-post", CLR_CYAN))
    mode = input("Mode [udp]: ").strip().lower() or "udp"
    if mode.startswith("http") and path == "/" and "://" in choice:
        _, port, path, use_tls = parse_target(choice)

    t_in = input("Threads [100]: ").strip()
    threads = int(t_in) if t_in.isdigit() else 100
    d_in = input("Duration seconds [30]: ").strip()
    duration = int(d_in) if d_in.isdigit() else 30
    s_in = input("Payload bytes [1024]: ").strip()
    packet_size = int(s_in) if s_in.isdigit() else 1024

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
