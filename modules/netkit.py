# -*- coding: utf-8 -*-
"""
MEOW-SEC :: NETKIT — Network Utilities
  · Ping sweep (ICMP / TCP)
  · Banner grabber (port → service version)
  · HTTP request builder (custom headers, methods, body)
  · IP / CIDR calculator
  · Traceroute (hops via TTL)
  · HTTP response viewer
"""
import socket, os, re, time, json, struct
import concurrent.futures
from datetime import datetime

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN, CAT_FOUND
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.syntax import Syntax
from rich import box

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── PING SWEEP ──────────────────────────────────────────────

def tcp_ping(host: str, port: int = 80, timeout: float = 1.0) -> dict:
    """Ping TCP : tente une connexion sur un port rapide"""
    start = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        res = s.connect_ex((host, port))
        s.close()
        latency = round((time.time() - start) * 1000)
        return {"host": host, "alive": res == 0, "latency": latency}
    except Exception:
        return {"host": host, "alive": False, "latency": 0}

def icmp_ping(host: str, timeout: float = 1.0) -> dict:
    """ICMP ping via os.system (Windows compatible)"""
    import subprocess
    start = time.time()
    try:
        cmd = ["ping", "-n", "1", "-w", "500", host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        alive = result.returncode == 0
        latency = round((time.time() - start) * 1000)
        return {"host": host, "alive": alive, "latency": latency}
    except Exception:
        return {"host": host, "alive": False, "latency": 0}

def expand_cidr(cidr: str) -> list:
    """Expande un CIDR en liste d'IPs — jusqu'à /16 (65534 hosts)"""
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        n = net.num_addresses
        if n > 65536:
            warn(f"Network too large ({n:,} hosts). Use /16 or smaller.")
            return []
        if n > 256:
            warn(f"Large range: {n-2:,} hosts. This may take a while.")
        return [str(ip) for ip in net.hosts()]
    except ValueError as e:
        err(f"Invalid CIDR: {e}"); return []

def ping_sweep(targets: list, workers: int = 50) -> list:
    """Ping en parallèle une liste d'hôtes"""
    alive = []
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn, TimeElapsedColumn

    with Progress(
        SpinnerColumn(style=G1),
        TextColumn(f"[{G1}]Ping sweep"),
        BarColumn(bar_width=35, style=G2, complete_style=G1),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console
    ) as prog:
        task = prog.add_task("", total=len(targets))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(tcp_ping, h, 80): h for h in targets}
            for fut in concurrent.futures.as_completed(futures):
                prog.advance(task)
                r = fut.result()
                if r["alive"]:
                    alive.append(r)
                    prog.log(f"  [{G1}]●[/]  [{CY}]{r['host']:<18}[/]  [{DM}]{r['latency']}ms[/]")
    return alive

# ─── BANNER GRABBER ──────────────────────────────────────────

BANNER_PROBES = {
    21:   b"",
    22:   b"SSH-2.0-MEOW\r\n",
    23:   b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18",
    25:   b"EHLO meow.sec\r\n",
    80:   b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    110:  b"",
    143:  b"",
    443:  b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    3306: b"",
    5432: b"",
    6379: b"*1\r\n$4\r\nPING\r\n",
    27017:b"",
    9200: b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
}

def grab_banner(host: str, port: int, timeout: float = 3.0) -> str:
    probe = BANNER_PROBES.get(port, b"")
    if b"{host}" in probe:
        probe = probe.replace(b"{host}", host.encode())
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if probe:
            s.send(probe)
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner.split("\n")[0][:120]
    except Exception:
        return ""

def multi_banner(host: str, ports: list) -> list:
    results = []
    for port in ports:
        banner = grab_banner(host, port)
        if banner:
            results.append({"port": port, "banner": banner})
            find(f"Port [{CY}]{port}[/] → [{G1}]{banner[:80]}[/]")
    return results

# ─── HTTP REQUEST BUILDER ────────────────────────────────────

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]

def http_request_builder():
    """Constructeur de requête HTTP custom"""
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] HTTP REQUEST BUILDER ", style=G2))

    if not HAS_REQUESTS:
        err("requests not available."); return

    url = Prompt.ask(f"  [{G1}]◈ URL[/]").strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Method
    for i, m in enumerate(HTTP_METHODS, 1):
        console.print(f"  [{G1}][{i}][/] {m}")
    method_idx = IntPrompt.ask(f"  [{G1}]◈ Method[/]", default=1) - 1
    method = HTTP_METHODS[method_idx % len(HTTP_METHODS)]

    # Headers
    headers = {
        "User-Agent": "MEOW-SEC/1.0",
        "Accept":     "*/*",
    }
    console.print(f"\n  [{G2}]Default headers: {list(headers.keys())}[/]")
    while Confirm.ask(f"  [{G1}]◈ Add custom header?[/]", default=False):
        k = Prompt.ask(f"    [{CY}]Header name[/]")
        v = Prompt.ask(f"    [{CY}]Header value[/]")
        headers[k] = v

    # Body
    body = None
    if method in ("POST", "PUT", "PATCH"):
        if Confirm.ask(f"  [{G1}]◈ Add request body?[/]", default=True):
            body = Prompt.ask(f"  [{G1}]◈ Body[/]")
            ct = Prompt.ask(f"  [{G1}]◈ Content-Type[/]",
                            default="application/x-www-form-urlencoded")
            headers["Content-Type"] = ct

    # Follow redirects
    follow = Confirm.ask(f"  [{G1}]◈ Follow redirects?[/]", default=True)

    console.print()
    info(f"Sending {method} → [{CY}]{url}[/]")

    try:
        r = requests.request(method, url, headers=headers, data=body,
                             allow_redirects=follow, verify=False, timeout=15)

        # Response display
        status_color = G1 if r.status_code < 400 else (OR if r.status_code < 500 else RD)
        console.print(f"\n  Status: [{status_color}]{r.status_code} {r.reason}[/]")
        console.print(f"  Time:   [{CY}]{r.elapsed.total_seconds()*1000:.0f}ms[/]")
        console.print(f"  Size:   [{G1}]{len(r.content)} bytes[/]")
        console.print(f"  URL:    [{DM}]{r.url}[/]")

        # Headers
        console.print()
        t = Table(title=f"[{G1}]Response Headers[/]",
                  box=box.SIMPLE, border_style=G2, header_style=CY)
        t.add_column("Header", style=CY, width=30)
        t.add_column("Value",  style=G1)
        for k, v in r.headers.items():
            t.add_row(k, v[:80])
        console.print(t)

        # Body preview
        console.print()
        body_preview = r.text[:2000]
        ct = r.headers.get("Content-Type", "")
        if "json" in ct:
            try:
                body_preview = json.dumps(r.json(), indent=2)[:2000]
                console.print(Panel(Syntax(body_preview, "json", theme="monokai"),
                                    title=f"[{G1}]Response Body (JSON)", border_style=G2))
            except Exception:
                console.print(Panel(body_preview, title=f"[{G1}]Response Body",
                                    border_style=G2))
        elif "html" in ct:
            console.print(Panel(Syntax(body_preview, "html", theme="monokai"),
                                title=f"[{G1}]Response Body (HTML)", border_style=G2))
        else:
            console.print(Panel(Text(body_preview, style=G1),
                                title=f"[{G1}]Response Body", border_style=G2))

    except Exception as e:
        err(f"Request failed: {e}")

# ─── IP CALCULATOR ───────────────────────────────────────────

def ip_calc(cidr_or_ip: str):
    import ipaddress
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] IP / CIDR CALCULATOR ", style=G2))
    try:
        if "/" in cidr_or_ip:
            net = ipaddress.ip_network(cidr_or_ip, strict=False)
            rows = [
                ("Network",       str(net.network_address)),
                ("Broadcast",     str(net.broadcast_address)),
                ("Netmask",       str(net.netmask)),
                ("Wildcard",      str(net.hostmask)),
                ("Prefix length", str(net.prefixlen)),
                ("Num hosts",     str(net.num_addresses - 2)),
                ("First host",    str(list(net.hosts())[0]) if net.num_addresses > 2 else "N/A"),
                ("Last host",     str(list(net.hosts())[-1]) if net.num_addresses > 2 else "N/A"),
                ("IP version",    f"IPv{net.version}"),
                ("Is private",    "YES" if net.is_private else "no"),
            ]
        else:
            addr = ipaddress.ip_address(cidr_or_ip)
            rows = [
                ("Address",       str(addr)),
                ("IP version",    f"IPv{addr.version}"),
                ("Is private",    "YES" if addr.is_private else "no"),
                ("Is loopback",   "YES" if addr.is_loopback else "no"),
                ("Is multicast",  "YES" if addr.is_multicast else "no"),
                ("Is global",     "YES" if addr.is_global else "no"),
                ("Compressed",    addr.compressed),
                ("Packed hex",    addr.packed.hex()),
            ]
        print_result_table(f"IP Info :: {cidr_or_ip}", ["Property", "Value"], rows)
    except ValueError as e:
        err(f"Invalid IP/CIDR: {e}")

# ─── TRACEROUTE (TCP) ────────────────────────────────────────

def tcp_traceroute(host: str, port: int = 80, max_hops: int = 20):
    """TCP traceroute (works without raw sockets on Windows)"""
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] TRACEROUTE → {host}:{port} ", style=G2))
    info("Tracing route (TCP SYN method)...")
    console.print()

    try:
        dest_ip = socket.gethostbyname(host)
        info(f"Resolved: [{CY}]{host}[/] → [{G1}]{dest_ip}[/]")
    except Exception:
        err(f"Cannot resolve: {host}"); return

    rows = []
    for ttl in range(1, max_hops + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            s.settimeout(1.5)
            start = time.time()
            try:
                s.connect((dest_ip, port))
                hop_ip = dest_ip
                latency = round((time.time() - start) * 1000)
                s.close()
                try:
                    hop_name = socket.gethostbyaddr(hop_ip)[0]
                except Exception:
                    hop_name = ""
                rows.append((str(ttl), hop_ip, hop_name[:40], f"{latency}ms"))
                console.print(f"  [{CY}]{ttl:2}[/]  [{G1}]{hop_ip:<18}[/]  [{DM}]{hop_name[:35]:<35}[/]  [{OR}]{latency}ms[/]")
                break  # Destination reached
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                latency = round((time.time() - start) * 1000)
                hop_ip = "*"
                rows.append((str(ttl), hop_ip, "", f"{latency}ms"))
                console.print(f"  [{CY}]{ttl:2}[/]  [{DM}]*               [/]  [{DM}]timeout[/]  [{DM}]{latency}ms[/]")
        except Exception:
            rows.append((str(ttl), "*", "", "timeout"))
        finally:
            try: s.close()
            except Exception: pass

    console.print()
    print_result_table(f"Traceroute :: {host}", ["Hop", "IP", "Hostname", "RTT"], rows)

# ─── MAIN NETKIT ─────────────────────────────────────────────

def run():
    show_module_banner("netkit")
    cat_talk(CAT_SCAN, "NETKIT network tools loaded...", OR)
    console.print()

    while True:
        console.print(f"  [{G1}][1][/] Ping sweep         (TCP or ICMP over a range)")
        console.print(f"  [{G1}][2][/] Banner grabber     (grab service version strings)")
        console.print(f"  [{G1}][3][/] HTTP request builder (custom method/headers/body)")
        console.print(f"  [{G1}][4][/] IP / CIDR calculator")
        console.print(f"  [{G1}][5][/] TCP traceroute")
        console.print(f"  [{G1}][0][/] Back")
        console.print()
        choice = ask_choice("NETKIT", "0")
        if choice == "0": break
        elif choice == "1": _ping_menu()
        elif choice == "2": _banner_menu()
        elif choice == "3": http_request_builder()
        elif choice == "4":
            cidr = Prompt.ask(f"  [{G1}]◈ IP or CIDR[/]").strip()
            if cidr: ip_calc(cidr)
        elif choice == "5":
            host = Prompt.ask(f"  [{G1}]◈ Target host[/]").strip()
            port = IntPrompt.ask(f"  [{G1}]◈ Port[/]", default=80)
            if host: tcp_traceroute(host, port)
        console.print()

def _ping_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] PING SWEEP ", style=G2))
    console.print(f"  [{G1}][1][/] Single host")
    console.print(f"  [{G1}][2][/] IP range (e.g. 192.168.1.1-50)")
    console.print(f"  [{G1}][3][/] CIDR block (e.g. 192.168.1.0/24)")
    mode = ask_choice("", "1")

    targets = []
    if mode == "1":
        h = Prompt.ask(f"  [{G1}]◈ Host[/]").strip()
        if h: targets = [h]
    elif mode == "2":
        rng = Prompt.ask(f"  [{G1}]◈ Range (e.g. 192.168.1.1-50)[/]").strip()
        targets = _parse_range(rng)
    elif mode == "3":
        cidr = Prompt.ask(f"  [{G1}]◈ CIDR[/]").strip()
        targets = expand_cidr(cidr)

    if not targets: return
    info(f"Sweeping [{G1}]{len(targets)}[/] hosts...")
    alive = ping_sweep(targets)
    console.print()
    if alive:
        rows = [(r["host"], f"{r['latency']}ms") for r in alive]
        print_result_table(f"Alive hosts ({len(alive)}/{len(targets)})",
                           ["Host", "Latency"], rows)
    else:
        warn("No hosts responded.")

def _banner_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] BANNER GRABBER ", style=G2))
    host = Prompt.ask(f"  [{G1}]◈ Target host/IP[/]").strip()
    if not host: return

    ports_str = Prompt.ask(f"  [{G1}]◈ Ports (e.g. 22,80,443,3306)[/]",
                           default="21,22,25,80,110,143,443,3306,5432,6379,9200").strip()
    ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]

    info(f"Grabbing banners from [{G1}]{len(ports)}[/] ports on [{CY}]{host}[/]...")
    multi_banner(host, ports)

def _parse_range(rng: str) -> list:
    """Parse 192.168.1.1-50 → list of IPs"""
    try:
        m = re.match(r"(\d+\.\d+\.\d+\.)(\d+)-(\d+)", rng)
        if m:
            base, start, end = m.group(1), int(m.group(2)), int(m.group(3))
            return [f"{base}{i}" for i in range(start, end+1)]
    except Exception:
        pass
    return []

def _banner():
    logo = Text(r"""
 ███╗   ██╗███████╗████████╗██╗  ██╗██╗████████╗
 ████╗  ██║██╔════╝╚══██╔══╝██║ ██╔╝██║╚══██╔══╝
 ██╔██╗ ██║█████╗     ██║   █████╔╝ ██║   ██║
 ██║╚██╗██║██╔══╝     ██║   ██╔═██╗ ██║   ██║
 ██║ ╚████║███████╗   ██║   ██║  ██╗██║   ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝   ╚═╝
  [PING SWEEP · BANNER GRAB · HTTP FORGE · TRACEROUTE]""", style=f"bold {G1}")
    console.print(Panel(Align(logo, align="center"), border_style=RD, padding=(0,1)))
