# -*- coding: utf-8 -*-
"""
MEOW-SEC :: Proxy Manager
Download → Validate → Rotate
"""
import os, json, time, random, threading
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
    # Format: (url, parser_fn_name)
    ("https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all", "plain"),
    ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", "plain"),
    ("https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", "plain"),
    ("https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt", "plain"),
    ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "plain"),
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

    def __init__(self, test_url: str = "http://httpbin.org/ip", timeout: int = 6):
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
                r = requests.get(url, timeout=10,
                                 headers={"User-Agent": "MEOW-SEC/1.0"})
                if r.status_code == 200:
                    lines = [l.strip() for l in r.text.splitlines() if ":" in l and l.strip()]
                    sample = lines[:max_per_source]
                    raw.update(sample)
                    ok(f"  [{CY}]{len(sample)}[/] proxies from {url[:50]}...")
                else:
                    warn(f"  Source returned {r.status_code}: {url[:50]}...")
            except Exception as e:
                warn(f"  Failed: {url[:40]}... ({e})")

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
                try:
                    proxy_dict = {"http": f"http://{proxy_str}", "https": f"http://{proxy_str}"}
                    start = time.time()
                    r = requests.get(self.test_url, proxies=proxy_dict,
                                     timeout=self.timeout, verify=False)
                    latency = round((time.time() - start) * 1000)
                    if r.status_code == 200:
                        return {"proxy": proxy_str, "latency_ms": latency,
                                "validated": datetime.now().isoformat()}
                except Exception:
                    pass
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
        """Retourne un proxy aléatoire parmi les bons"""
        with self._lock:
            available = [p["proxy"] for p in self.good if p["proxy"] not in self.bad]
            if not available:
                return None
            return random.choice(available)

    def get_dict(self) -> Optional[dict]:
        """Retourne un proxy dict compatible requests"""
        proxy = self.get()
        if not proxy:
            return None
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
