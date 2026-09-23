# -*- coding: utf-8 -*-
"""
MEOW-SEC :: CLAW — Port & Service Scanner
Inspired by nmap — built from scratch with sockets
"""
import socket
import concurrent.futures
import time
from core.ui import console, ok, err, info, warn, find, boot_progress, print_result_table, show_module_banner, ask_target, ask_choice, G1, G2, CY, OR, RD, DM
from core.cats import CAT_SCAN, CAT_FOUND, cat_talk
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.prompt import Prompt

# ─── COMMON PORTS ────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP",       22: "SSH",       23: "Telnet",    25: "SMTP",
    53: "DNS",       80: "HTTP",      110: "POP3",     111: "RPC",
    135: "MSRPC",    139: "NetBIOS",  143: "IMAP",     443: "HTTPS",
    445: "SMB",      993: "IMAPS",    995: "POP3S",    1433: "MSSQL",
    1521: "Oracle",  2375: "Docker",  3306: "MySQL",   3389: "RDP",
    4444: "Meterpreter", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    7001: "WebLogic",8080: "HTTP-Alt",8443: "HTTPS-Alt",8888: "Jupyter",
    9200: "Elasticsearch", 27017: "MongoDB", 6000: "X11", 5601: "Kibana",
}

TOP_100_PORTS = list(COMMON_PORTS.keys()) + [
    20, 24, 26, 70, 79, 88, 106, 113, 119, 135, 144, 179, 194, 220, 389,
    427, 443, 444, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646,
    873, 990, 992, 994, 1080, 1194, 1723, 2049, 2181, 4000, 4001, 4002,
    4100, 5000, 5001, 5002, 5060, 5061, 8000, 8001, 8008, 8009, 8010, 8081,
    8090, 8180, 9000, 9090, 9300, 10000, 49152
]
TOP_100_PORTS = sorted(set(TOP_100_PORTS))

# ─── SCANNER ─────────────────────────────────────────────────

def scan_port(host: str, port: int, timeout: float = 0.8) -> dict:
    """Tente une connexion TCP sur un port"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        banner = ""
        if result == 0:
            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(256).decode(errors="ignore").split("\n")[0].strip()
            except Exception:
                pass
        s.close()
        return {
            "port":    port,
            "state":   "OPEN" if result == 0 else "CLOSED",
            "service": COMMON_PORTS.get(port, "unknown"),
            "banner":  banner[:60] if banner else "",
        }
    except Exception:
        return {"port": port, "state": "ERROR", "service": "", "banner": ""}

def resolve_host(host: str) -> str | None:
    """Résout le hostname en IP"""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None

def grab_service_version(host: str, port: int) -> str:
    """Tente de récupérer la bannière / version d'un service"""
    probes = {
        22:  b"SSH-2.0-MEOW\r\n",
        25:  b"EHLO meow.sec\r\n",
        21:  b"USER anonymous\r\n",
        80:  b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n",
        443: b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n",
    }
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect((host, port))
        probe = probes.get(port, b"\r\n")
        s.send(probe)
        data = s.recv(512).decode(errors="ignore").strip()
        s.close()
        return data.split("\n")[0][:80]
    except Exception:
        return ""

# ─── MAIN CLAW ───────────────────────────────────────────────

def run(target: str = None):
    show_module_banner("claw")
    cat_talk(CAT_SCAN, "CLAW port scanner online — let's see what's open...", OR)
    console.print()

    if not target:
        target = ask_target("Target host / IP")
    if not target:
        err("No target provided."); return

    # Mode
    console.print(f"  [{G1}][1][/] Quick scan  (top 30 ports)")
    console.print(f"  [{G1}][2][/] Full scan   (top 100 ports)")
    console.print(f"  [{G1}][3][/] Custom range")
    mode = ask_choice("Mode", "1")

    if mode == "1":
        ports = list(COMMON_PORTS.keys())[:30]
    elif mode == "2":
        ports = TOP_100_PORTS
    elif mode == "3":
        raw = Prompt.ask(f"  [{G1}]◈ Port range (e.g. 1-1024 or 80,443,8080)[/]")
        ports = _parse_ports(raw)
    else:
        ports = list(COMMON_PORTS.keys())[:30]

    # Résolution
    ip = resolve_host(target)
    if not ip:
        err(f"Cannot resolve: {target}"); return

    info(f"Target resolved: [bold {CY}]{target}[/] → [{G1}]{ip}[/]")
    info(f"Scanning [bold]{len(ports)}[/] ports with [bold {G1}]CLAW[/]...")
    console.print()

    boot_progress([
        "Initializing socket engine...",
        f"Resolving {target}...",
        "Building port queue...",
        "Launching thread pool...",
        "Scanning...",
    ])

    open_ports = []
    all_results = []
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=150) as pool:
        futures = {pool.submit(scan_port, ip, p): p for p in ports}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            all_results.append(res)
            if res["state"] == "OPEN":
                open_ports.append(res)
                find(f"Port [{CY}]{res['port']}/{res['service']}[/] → [bold {G1}]OPEN[/]  {res['banner']}")
            done += 1

    elapsed = time.time() - start
    console.print()

    # Grab versions pour les ports ouverts
    if open_ports:
        info("Grabbing service banners...")
        for p in open_ports:
            ver = grab_service_version(ip, p["port"])
            if ver:
                p["banner"] = ver[:60]

    # Résultats
    if open_ports:
        cat_talk(CAT_FOUND, f"{len(open_ports)} open port(s) found!", G1)
        rows = [(p["port"], p["service"], "OPEN", p["banner"]) for p in open_ports]
        print_result_table(
            f"CLAW RESULTS :: {target} ({ip})",
            ["PORT", "SERVICE", "STATE", "BANNER"],
            rows, color_col=2
        )
    else:
        warn("No open ports found.")

    info(f"Scan completed in [{G1}]{elapsed:.2f}s[/]  |  [{CY}]{len(open_ports)}/{len(ports)}[/] ports open")

    # Sauvegarde
    _save_results(target, ip, open_ports)

# ─── UTILS ───────────────────────────────────────────────────

def _parse_ports(raw: str) -> list:
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports += list(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def _save_results(target: str, ip: str, ports: list):
    import os, json
    from datetime import datetime
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out_dir, exist_ok=True)
    fname = os.path.join(out_dir, f"claw_{target.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    data = {"target": target, "ip": ip, "timestamp": datetime.now().isoformat(), "results": ports}
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
