# -*- coding: utf-8 -*-
"""
MEOW-SEC :: Proxy Manager
Download → Validate → Rotate
"""
import os, json, time, random, threading, re
import concurrent.futures
from datetime import datetime
from typing import Optional

from core.ui import console, ok, err, info, warn, find, G1, G2, CY, OR, RD, DM
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn, TimeElapsedColumn

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

PROXY_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "proxies.json")

# ─── SOURCES PUBLIQUES GRATUITES ─────────────────────────────
PROXY_SOURCES = [
    # ── ProxyScrape API (mis à jour toutes les 10 min) ────────
    ("https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all", "plain"),
    ("https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&timeout=3000&country=all&anonymity=elite", "plain"),
    ("https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks5&timeout=5000&country=all", "plain"),
    # ── GeoNode API (filtre uptime >= 70%) ────────────────────
    ("https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&filterUpTime=70&protocols=http", "geonode"),
    ("https://proxylist.geonode.com/api/proxy-list?limit=500&page=2&sort_by=lastChecked&sort_type=desc&filterUpTime=70&protocols=http", "geonode"),
    ("https://proxylist.geonode.com/api/proxy-list?limit=500&page=3&sort_by=lastChecked&sort_type=desc&filterUpTime=70&protocols=http", "geonode"),
    ("https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=speed&sort_type=asc&filterUpTime=80&protocols=https", "geonode"),
    # ── GitHub listes maintenues quotidiennement ──────────────
    ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt", "plain"),
    ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks4.txt", "socks4"),
    ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks5.txt", "socks5"),
    ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "plain"),
    ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt", "socks4"),
    ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "socks5"),
    ("https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks4&timeout=5000&country=all", "socks4"),
    ("https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt", "plain"),
    ("https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt", "plain"),
    ("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt", "plain"),
    ("https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt", "plain"),
    ("https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt", "plain"),
    ("https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", "plain"),
    ("https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt", "plain"),
    ("https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt", "plain"),
    ("https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt", "plain"),
    ("https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt", "plain"),
    ("https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt", "plain"),
    ("https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt", "plain"),
    ("https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/http.txt", "plain"),
    ("https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt", "plain"),
    ("https://raw.githubusercontent.com/im-razvan/proxy_list/main/http.txt", "plain"),
    ("https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt", "plain"),
    ("https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt", "plain"),
    ("https://raw.githubusercontent.com/HyperBeats/proxy-list/main/http.txt", "plain"),
    # ── dstat.st (protégé DiamWall — fonctionne si cookie passé manuellement) ─
    ("https://dstat.st/tools/http",  "dstat"),
    ("https://dstat.st/tools/socks4","dstat"),
    ("https://dstat.st/tools/socks5","dstat"),
]

# Fichiers locaux optionnels (télécharger manuellement depuis dstat.st puis placer ici)
_DSTAT_LOCAL_FILES = [
    (os.path.join(os.path.dirname(__file__), "..", "data", "dstat_http.txt"),   "plain"),
    (os.path.join(os.path.dirname(__file__), "..", "data", "dstat_socks4.txt"), "socks4"),
    (os.path.join(os.path.dirname(__file__), "..", "data", "dstat_socks5.txt"), "socks5"),
]

# URLs de test pour validation — on accepte si au moins une répond
_TEST_URLS = [
    "http://www.google.com",
    "http://httpbin.org/ip",
    "http://ip-api.com/json",
]

class ProxyManager:
    """
    Gestionnaire de proxies: télécharge, valide, conserve et fait tourner les bons.
    Usage:
        pm = ProxyManager()
        pm.refresh()          # télécharge + valide
        proxy = pm.get()      # donne un proxy aléatoire
        pm.mark_bad(proxy)    # marque comme mauvais
    """

    def __init__(self, test_url: str = "http://www.google.com", timeout: int = 6):
        self.test_url   = test_url
        self.timeout    = timeout
        self.good: list  = []
        self.bad: set    = set()
        self._lock       = threading.Lock()
        self._load()

    # ── TÉLÉCHARGEMENT ────────────────────────────────────────

    def download(self, max_per_source: int = 500) -> list:
        """Télécharge les listes depuis les sources publiques"""
        raw = set()
        info(f"Downloading proxies from [{G1}]{len(PROXY_SOURCES)}[/] sources...")

        for url, fmt in PROXY_SOURCES:
            try:
                hdrs = {"User-Agent": "MEOW-SEC/1.5"}
                if "dstat.st" in url:
                    hdrs = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                        "Accept": "text/plain,text/html,*/*",
                        "Referer": "https://dstat.st/",
                    }
                r = requests.get(url, timeout=12, headers=hdrs)
                if r.status_code == 200:
                    if fmt == "geonode":
                        try:
                            data = r.json().get("data", [])
                            proxies_parsed = [f"{p['ip']}:{p['port']}" for p in data if p.get('ip') and p.get('port')]
                            sample = proxies_parsed[:max_per_source]
                        except Exception:
                            sample = []
                    elif fmt == "dstat":
                        # dstat.st utilise DiamWall — on tente avec headers navigateur
                        # Si ça marche, c'est du plain text IP:PORT
                        if r.status_code == 200 and ":" in r.text:
                            lines = [l.strip() for l in r.text.splitlines()
                                     if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}$", l.strip())]
                            sample = lines[:max_per_source]
                        else:
                            sample = []
                    elif fmt in ("socks4", "socks5"):
                        # Préfixer les proxies avec le bon scheme
                        lines = [l.strip() for l in r.text.splitlines() if ":" in l and l.strip() and not l.strip().startswith("#")]
                        sample = [f"{fmt}://{l}" if not l.startswith(fmt) else l for l in lines[:max_per_source]]
                    else:
                        lines = [l.strip() for l in r.text.splitlines() if ":" in l and l.strip() and not l.strip().startswith("#")]
                        sample = lines[:max_per_source]
                    raw.update(sample)
                    ok(f"  [{CY}]{len(sample)}[/] proxies from {url[:50]}...")
                else:
                    warn(f"  Source returned {r.status_code}: {url[:50]}...")
            except Exception as e:
                warn(f"  Failed: {url[:40]}... ({e})")

        # ── Fichiers locaux dstat.st (téléchargés manuellement) ──
        for fpath, fmt in _DSTAT_LOCAL_FILES:
            if os.path.exists(fpath):
                try:
                    with open(fpath, encoding="utf-8", errors="ignore") as f:
                        lines = [l.strip() for l in f if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}$", l.strip())]
                    sample = []
                    for l in lines[:max_per_source]:
                        if fmt in ("socks4", "socks5"):
                            sample.append(f"{fmt}://{l}")
                        else:
                            sample.append(l)
                    raw.update(sample)
                    ok(f"  [{CY}]{len(sample)}[/] proxies from local file {os.path.basename(fpath)}")
                except Exception as e:
                    warn(f"  Local file error {fpath}: {e}")

        proxies = list(raw)
        info(f"Total raw proxies: [{G1}]{len(proxies)}[/]")
        return proxies

    # ── VALIDATION ───────────────────────────────────────────

    def validate(self, proxies: list, workers: int = 100) -> list:
        """Teste les proxies en parallèle, garde les bons"""
        good = []
        total = len(proxies)
        info(f"Validating [{G1}]{total}[/] proxies (workers={workers})...")
        console.print()

        with Progress(
            SpinnerColumn(style=G1),
            TextColumn(f"[{G1}]Testing proxies"),
            BarColumn(bar_width=38, style=G2, complete_style=G1),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("", total=total)

            def test_one(proxy_str: str) -> Optional[dict]:
                if proxy_str.startswith("socks5://") or proxy_str.startswith("socks4://"):
                    proxy_dict = {"http": proxy_str, "https": proxy_str}
                else:
                    proxy_dict = {"http": f"http://{proxy_str}", "https": f"http://{proxy_str}"}
                # Essaie plusieurs URLs de test — accepte dès la première qui répond
                for test_url in _TEST_URLS:
                    try:
                        start = time.time()
                        r = requests.get(test_url, proxies=proxy_dict,
                                         timeout=self.timeout, verify=False,
                                         allow_redirects=True)
                        latency = round((time.time() - start) * 1000)
                        if r.status_code < 500:
                            return {"proxy": proxy_str, "latency_ms": latency,
                                    "validated": datetime.now().isoformat()}
                    except Exception:
                        continue
                return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(test_one, p): p for p in proxies}
                for fut in concurrent.futures.as_completed(futures):
                    progress.advance(task)
                    result = fut.result()
                    if result:
                        good.append(result)

        good.sort(key=lambda x: x["latency_ms"])
        find(f"{len(good)} working proxies found (from {total} tested)")
        return good

    # ── REFRESH (download + validate) ────────────────────────

    def refresh(self, workers: int = 100):
        raw = self.download()
        if not raw:
            err("No proxies downloaded."); return
        self.good = self.validate(raw, workers=workers)
        self._save()
        info(f"Proxy pool: [{G1}]{len(self.good)}[/] working proxies saved.")

    # ── ROTATION ─────────────────────────────────────────────

    def get(self) -> Optional[str]:
        """Retourne un proxy du top 30% le plus rapide (trié par latence)"""
        with self._lock:
            available = [p for p in self.good if p["proxy"] not in self.bad]
            if not available:
                return None
            # Prioriser les plus rapides — top 30% min 10 proxies
            top_n = max(10, len(available) // 3)
            pool = available[:top_n]
            return random.choice(pool)["proxy"]

    def get_dict(self) -> Optional[dict]:
        """Retourne un proxy dict compatible requests (http, socks4, socks5)"""
        proxy = self.get()
        if not proxy:
            return None
        if proxy.startswith("socks5://") or proxy.startswith("socks4://"):
            return {"http": proxy, "https": proxy}
        return {"http": f"http://{proxy}", "https": f"http://{proxy}"}

    def mark_bad(self, proxy: str):
        """Marque un proxy comme mauvais"""
        with self._lock:
            self.bad.add(proxy)

    def rotate(self) -> Optional[str]:
        """Donne le prochain proxy (round-robin sur les bons)"""
        return self.get()

    def stats(self) -> dict:
        return {
            "total":     len(self.good),
            "bad":       len(self.bad),
            "available": len([p for p in self.good if p["proxy"] not in self.bad]),
            "fastest":   self.good[0]["proxy"] if self.good else None,
            "avg_latency": round(sum(p["latency_ms"] for p in self.good) / len(self.good)) if self.good else 0,
        }

    # ── PERSISTANCE ─────────────────────────────────────────

    def _save(self):
        os.makedirs(os.path.dirname(PROXY_FILE), exist_ok=True)
        with open(PROXY_FILE, "w", encoding="utf-8") as f:
            json.dump(self.good, f, indent=2)

    def _load(self):
        if os.path.exists(PROXY_FILE):
            try:
                with open(PROXY_FILE, encoding="utf-8") as f:
                    self.good = json.load(f)
                info(f"Loaded [{G1}]{len(self.good)}[/] cached proxies from disk.")
            except Exception:
                self.good = []

    def requests_get(self, url: str, **kwargs) -> Optional[object]:
        """GET via proxy rotatif avec fallback automatique"""
        proxy = self.get_dict()
        if proxy:
            kwargs.setdefault("proxies", proxy)
        kwargs.setdefault("timeout", 10)
        kwargs.setdefault("verify", False)
        try:
            r = requests.get(url, **kwargs)
            return r
        except Exception:
            if proxy:
                self.mark_bad(list(proxy.values())[0].replace("http://", ""))
            return None


# Singleton global
_manager = None

def get_manager() -> ProxyManager:
    global _manager
    if _manager is None:
        _manager = ProxyManager()
    return _manager

def px() -> Optional[dict]:
    """Retourne un proxy dict rotatif ou None — usage: requests.get(url, proxies=px())"""
    return get_manager().get_dict()

def rget(url: str, **kwargs):
    """requests.get avec proxy rotatif automatique"""
    return get_manager().requests_get(url, **kwargs)
