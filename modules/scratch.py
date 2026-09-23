# -*- coding: utf-8 -*-
"""
MEOW-SEC :: SCRATCH — Directory & File Brute Force
Inspired by gobuster / dirb — built from scratch
"""
import os, json, time
import concurrent.futures
from datetime import datetime
from urllib.parse import urljoin

from core.ui import console, ok, err, info, warn, find, boot_progress, print_result_table, show_module_banner, ask_target, ask_choice, G1, G2, CY, OR, RD, DM
from core.cats import CAT_SCAN, cat_talk
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn, TimeElapsedColumn

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request, ssl
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

# ─── WORDLISTS INTÉGRÉES ─────────────────────────────────────

WORDLIST_COMMON = [
    "admin", "login", "wp-admin", "administrator", "dashboard", "panel",
    "cpanel", "phpmyadmin", "wp-login.php", "config", "backup",
    "test", "dev", "staging", "api", "api/v1", "api/v2", "graphql",
    "uploads", "upload", "files", "images", "static", "assets",
    "robots.txt", "sitemap.xml", ".git", ".env", ".htaccess",
    "phpinfo.php", "info.php", "install", "setup", "old", "new",
    "tmp", "temp", "log", "logs", "debug", "error",
    "user", "users", "account", "accounts", "profile", "register",
    "signup", "signin", "logout", "auth", "oauth", "sso",
    "download", "downloads", "export", "import", "search",
    "includes", "include", "lib", "libs", "vendor", "node_modules",
    "js", "css", "img", "media", "public", "private",
    "secret", "secrets", "keys", "certs", "ssl",
    "wp-content", "wp-includes", "wp-json",
    "server-status", "server-info",
    "db", "database", "mysql", "sqlite", "data",
    "swagger", "swagger.json", "openapi.json", "swagger-ui",
    "health", "status", "ping", "metrics", "actuator",
    "console", "shell", "cmd", "exec",
    "flag", "flags", "ctf",
]

WORDLIST_EXTENSIONS = [
    ".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".cgi",
    ".bak", ".old", ".backup", ".zip", ".tar", ".gz", ".sql",
    ".txt", ".log", ".xml", ".json", ".yaml", ".yml", ".conf",
    ".config", ".ini", ".env",
]

WORDLIST_FULL = WORDLIST_COMMON + [
    w + ext for w in ["index", "main", "app", "web", "site", "home",
                       "config", "settings", "admin", "user", "login"]
    for ext in WORDLIST_EXTENSIONS[:8]
]

STATUS_COLORS = {
    200: G1,   201: G1,   204: G1,
    301: CY,   302: CY,   307: CY,   308: CY,
    401: OR,   403: OR,
    500: RD,   503: RD,
}

# ─── HTTP ────────────────────────────────────────────────────

def _check(url: str, timeout: float = 6.0) -> dict:
    try:
        if HAS_REQUESTS:
            r = requests.get(url, timeout=timeout, allow_redirects=False,
                             verify=False, proxies=_px(),
                             headers={"User-Agent": "MEOW-SCRATCH/1.0"})
            return {"url": url, "status": r.status_code,
                    "size": len(r.content), "ok": True,
                    "location": r.headers.get("Location", ""),
                    "body_hash": hash(r.content[:512])}
        else:
            import urllib.request, ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "MEOW-SCRATCH/1.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx, encoding="utf-8") as resp:
                body = resp.read(4096)
                return {"url": url, "status": resp.status,
                        "size": len(body), "ok": True, "location": "",
                        "body_hash": hash(body[:512])}
    except Exception:
        return {"url": url, "status": 0, "size": 0, "ok": False, "body_hash": 0}

# ─── SOFT 404 BASELINE ───────────────────────────────────────

def _get_baseline(target: str) -> dict | None:
    """
    Envoie une requête vers un chemin aléatoire pour détecter les soft 404.
    Si le serveur répond 200 à un chemin inexistant, on enregistre le pattern
    (taille ± 5%, body hash) pour filtrer les faux positifs.
    """
    import random, string
    rand_path = "/" + "".join(random.choices(string.ascii_lowercase, k=16))
    result = _check(target + rand_path)
    if result["status"] == 200:
        return {
            "status":    200,
            "size":      result["size"],
            "body_hash": result["body_hash"],
            "soft404":   True,
        }
    return {"soft404": False}

def _is_false_positive(result: dict, baseline: dict) -> bool:
    """Retourne True si le résultat correspond au pattern soft 404 (faux positif)"""
    if not baseline.get("soft404"):
        return False
    # Même hash de body = copie exacte de la 404 custom
    if result.get("body_hash") == baseline.get("body_hash"):
        return True
    # Taille trop proche de la baseline (±8%) = probablement la même page
    bl_size = baseline.get("size", 0)
    r_size  = result.get("size", 0)
    if bl_size > 0 and r_size > 0:
        ratio = abs(r_size - bl_size) / bl_size
        if ratio < 0.08:
            return True
    return False

def _normalise(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")

# ─── MAIN SCRATCH ────────────────────────────────────────────

def run(target: str = None):
    show_module_banner("scratch")
    cat_talk(CAT_SCAN, "SCRATCH brute-forcer ready — clawing through paths...", OR)
    console.print()

    if not target:
        target = ask_target("Target URL (e.g. https://example.com)")
    if not target:
        err("No target."); return

    target = _normalise(target)
    info(f"Target: [{CY}]{target}[/]")
    console.print()

    # Wordlist
    console.print(f"  [{G1}][1][/] Common paths  ({len(WORDLIST_COMMON)} words)")
    console.print(f"  [{G1}][2][/] Full list     ({len(WORDLIST_FULL)} words)")
    console.print(f"  [{G1}][3][/] Custom file")
    mode = ask_choice("Wordlist", "1")

    if mode == "1":
        words = WORDLIST_COMMON
    elif mode == "2":
        words = WORDLIST_FULL
    elif mode == "3":
        path = Prompt.ask(f"  [{G1}]◈ Wordlist path[/]").strip()
        if not os.path.exists(path):
            err(f"File not found: {path}"); return
        with open(path, encoding="utf-8") as f:
            words = [l.strip() for l in f if l.strip()]
    else:
        words = WORDLIST_COMMON

    # Threads
    threads = int(Prompt.ask(f"  [{G1}]◈ Threads[/]", default="30"))
    threads = max(1, min(threads, 100))

    # Extensions à tester en plus
    extra_ext = Prompt.ask(f"  [{G1}]◈ Extra extensions (e.g. .php,.bak) or ENTER to skip[/]", default="")
    ext_list = [e.strip() for e in extra_ext.split(",") if e.strip()] if extra_ext else []

    # Build URL list
    urls = []
    for w in words:
        urls.append(f"{target}/{w}")
        for ext in ext_list:
            if not w.endswith(ext):
                urls.append(f"{target}/{w}{ext}")

    info(f"Testing [{G1}]{len(urls)}[/] paths  |  threads=[{CY}]{threads}[/]")

    # Détection soft 404 (faux positifs)
    info("Detecting custom 404 page (baseline check)...")
    baseline = _get_baseline(target)
    if baseline.get("soft404"):
        warn(f"Soft 404 detected! Server returns 200 for random paths "
             f"(size≈{baseline['size']}B) — filtering false positives automatically.")
    else:
        ok("Standard 404 detected — no soft 404.")
    console.print()

    found = []
    done  = 0
    total = len(urls)

    with Progress(
        SpinnerColumn(style=G1),
        TextColumn(f"[{G1}]SCRATCH"),
        BarColumn(bar_width=40, style=G2, complete_style=G1),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Brute forcing...", total=total)

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_check, url): url for url in urls}
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                progress.advance(task)
                if res["ok"] and res["status"] not in (404, 410, 400) \
                        and not _is_false_positive(res, baseline):
                    s = res["status"]
                    col = STATUS_COLORS.get(s, WH if False else G1)
                    note = res.get("location", "")[:40]
                    found.append((res["url"].replace(target, ""), str(s), _severity(s), note))
                    progress.log(
                        f"  [{col}][{s}][/]  {res['url'].replace(target,'')}  "
                        + (f"[{DM}]→ {note}[/]" if note else "")
                    )

    console.print()

    if found:
        print_result_table(
            f"SCRATCH RESULTS :: {target}",
            ["PATH", "STATUS", "SEVERITY", "REDIRECT"],
            found, color_col=2
        )
    else:
        info("Nothing found.")

    _save(target, found)

def _severity(status: int) -> str:
    if status == 200:   return "FOUND"
    if status in (301, 302, 307, 308): return "REDIRECT"
    if status == 401:   return "AUTH"
    if status == 403:   return "FORBIDDEN"
    if status >= 500:   return "ERROR"
    return "INFO"

def _save(target, found):
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out_dir, exist_ok=True)
    slug = target.replace("://", "_").replace("/", "_").replace(".", "_")
    fname = os.path.join(out_dir, f"scratch_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "found": found}, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
