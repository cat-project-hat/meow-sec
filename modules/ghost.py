# -*- coding: utf-8 -*-
"""
MEOW-SEC :: GHOST — Username Generator + Multi-Platform Existence Checker
OSINT tool inspired by Sherlock / WhatsMyName — built from scratch
"""
import re, os, json, time, random
import concurrent.futures
from datetime import datetime

from core.ui import (
                     console, show_module_banner, ok, err, info,
                     warn, find, ask_choice, print_result_table, G1,
                     G2, CY, OR, RD, DM)
from core.cats import CAT_SCAN, CAT_FOUND, cat_talk
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn, TimeElapsedColumn
from rich import box

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── PLATFORMS DATABASE ──────────────────────────────────────
# Format: name → (url_template, exists_indicator, check_type)
# check_type: "status_200" | "body_contains" | "body_not_contains" | "status_not_404"
PLATFORMS = {
    # Dev / Tech
    "GitHub":         ("https://github.com/{}", 200, "status_200"),
    "GitLab":         ("https://gitlab.com/{}", 200, "status_200"),
    "HackerNews":     ("https://news.ycombinator.com/user?id={}", 200, "status_200"),
    "Replit":         ("https://replit.com/@{}", 200, "status_200"),
    "Codepen":        ("https://codepen.io/{}", 200, "status_200"),
    "Stack Overflow": ("https://stackoverflow.com/users/{}",    200, "status_200"),
    "PyPI":           ("https://pypi.org/user/{}/",             200, "status_200"),
    "npm":            ("https://www.npmjs.com/~{}",             200, "status_200"),
    "Docker Hub":     ("https://hub.docker.com/u/{}",           200, "status_200"),
    # Social
    "Reddit":         ("https://www.reddit.com/user/{}",        200, "status_200"),
    "Twitter/X":      ("https://x.com/{}",                      200, "status_200"),
    "Instagram":      ("https://www.instagram.com/{}/",         200, "status_200"),
    "TikTok":         ("https://www.tiktok.com/@{}",            200, "status_200"),
    "Pinterest":      ("https://www.pinterest.com/{}/",         200, "status_200"),
    "Tumblr":         ("https://{}.tumblr.com",                  200, "status_200"),
    "Medium":         ("https://medium.com/@{}",                200, "status_200"),
    "Twitch":         ("https://www.twitch.tv/{}",              200, "status_200"),
    "YouTube":        ("https://www.youtube.com/@{}",           200, "status_200"),
    "Dailymotion":    ("https://www.dailymotion.com/{}",        200, "status_200"),
    # Gaming
    "Steam":          ("https://steamcommunity.com/id/{}",      200, "status_200"),
    "Roblox":         ("https://www.roblox.com/user.aspx?username={}", 200, "body_not_contains"),
    "Chess.com":      ("https://www.chess.com/member/{}",       200, "status_200"),
    "Speedrun.com":   ("https://www.speedrun.com/user/{}",      200, "status_200"),
    # Hacker / CTF / Sec
    "HackTheBox":     ("https://app.hackthebox.com/users/profile/{}", 200, "status_200"),
    "TryHackMe":      ("https://tryhackme.com/p/{}",            200, "status_200"),
    "CTFtime":        ("https://ctftime.org/user/{}",           200, "status_200"),
    # Creative
    "DeviantArt":     ("https://www.deviantart.com/{}",         200, "status_200"),
    "Behance":        ("https://www.behance.net/{}",            200, "status_200"),
    "Dribbble":       ("https://dribbble.com/{}",               200, "status_200"),
    "SoundCloud":     ("https://soundcloud.com/{}",             200, "status_200"),
    # Misc
    "Pastebin":       ("https://pastebin.com/u/{}",             200, "status_200"),
    "Keybase":        ("https://keybase.io/{}",                 200, "status_200"),
    "About.me":       ("https://about.me/{}",                   200, "status_200"),
    "Gravatar":       ("https://en.gravatar.com/{}",            200, "status_200"),
    "Fiverr":         ("https://www.fiverr.com/{}",             200, "status_200"),
}

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
]

# ─── USERNAME GENERATOR ──────────────────────────────────────

L33T_MAP = {"a":"4","e":"3","i":"1","o":"0","s":"5","t":"7","g":"9","b":"8"}

def leet(word: str) -> str:
    return "".join(L33T_MAP.get(c.lower(), c) for c in word)

def generate_usernames(name: str, extra: str = "") -> list:
    """Génère des variantes de username depuis un nom"""
    name  = name.strip().lower()
    extra = extra.strip().lower()

    # Splits
    parts = re.split(r"[\s._\-]+", name)
    first = parts[0] if parts else name
    last  = parts[-1] if len(parts) > 1 else ""
    init  = first[0] if first else ""

    base_combos = list({
        name,
        name.replace(" ", ""),
        name.replace(" ", "_"),
        name.replace(" ", "."),
        name.replace(" ", "-"),
        first,
        last,
        f"{first}{last}",
        f"{first}.{last}",
        f"{first}_{last}",
        f"{last}{first}",
        f"{init}{last}",
        f"{first}{init}",
    })
    base_combos = [b for b in base_combos if len(b) >= 2]

    # Variantes
    variants = []
    suffixes = ["", "1", "2", "3", "99", "123", "x", "0", "_x", "_hk", "_sec",
                "_dev", "_pro", "2024", "2025", "_cat", "_meow", "xd"]
    prefixes = ["", "the", "x", "0x", "real", "its", "i_am_", "_"]

    for base in base_combos:
        for suf in suffixes:
            variants.append(base + suf)
        for pre in prefixes:
            variants.append(pre + base)

    # L33t
    for base in base_combos[:5]:
        variants.append(leet(base))
        variants.append(leet(base) + "1337")

    # Extra keyword
    if extra:
        for base in base_combos[:4]:
            variants += [f"{base}_{extra}", f"{extra}_{base}", f"{base}{extra}"]

    # Nettoyage : unique, pas trop court, pas trop long
    seen = set()
    result = []
    for v in variants:
        v = re.sub(r"[^a-z0-9_.\-]", "", v)
        if len(v) >= 3 and v not in seen:
            seen.add(v)
            result.append(v)

    return sorted(result)

# ─── CHECKER ─────────────────────────────────────────────────

def check_username(username: str, platform: str, url_tmpl: str,
                   expected_status: int, check_type: str,
                   proxy: dict = None, timeout: int = 8) -> dict:
    url = url_tmpl.format(username)
    try:
        headers = {"User-Agent": random.choice(UA_LIST)}
        kwargs  = {"timeout": timeout, "verify": False,
                   "allow_redirects": True, "headers": headers}
        if proxy:
            kwargs["proxies"] = proxy

        r = requests.get(url, **kwargs, timeout=10)

        if check_type == "status_200":
            exists = r.status_code == 200
        elif check_type == "status_not_404":
            exists = r.status_code not in (404, 410, 400)
        elif check_type == "body_contains":
            exists = r.status_code == 200 and username.lower() in r.text.lower()
        elif check_type == "body_not_contains":
            exists = r.status_code == 200 and "Page Not Found" not in r.text
        else:
            exists = r.status_code == 200

        return {"platform": platform, "username": username,
                "url": url, "status": r.status_code,
                "exists": exists, "error": None}
    except Exception as e:
        return {"platform": platform, "username": username,
                "url": url, "status": 0,
                "exists": False, "error": str(e)[:60]}

# ─── MAIN GHOST ──────────────────────────────────────────────

def run():
    show_module_banner("ghost")
    cat_talk(CAT_SCAN, "GHOST username intel active — checking platforms...", OR)
    console.print()

    console.print(f"  [{G1}][1][/] Check a single username across all platforms")
    console.print(f"  [{G1}][2][/] Generate usernames from a name + check")
    console.print(f"  [{G1}][3][/] Generate only (no check)")
    console.print(f"  [{G1}][0][/] Back")
    console.print()

    choice = ask_choice("GHOST", "0")

    if choice == "0":
        return
    elif choice == "1":
        username = Prompt.ask(f"  [{G1}]◈ Username to check[/]").strip()
        if username:
            _check_one(username)
    elif choice == "2":
        name = Prompt.ask(f"  [{G1}]◈ Full name or word[/]").strip()
        extra = Prompt.ask(f"  [{G1}]◈ Extra keyword (optional)[/]", default="").strip()
        if name:
            usernames = generate_usernames(name, extra)
            info(f"Generated [{G1}]{len(usernames)}[/] username variants")
            _pick_and_check(usernames)
    elif choice == "3":
        name = Prompt.ask(f"  [{G1}]◈ Full name or word[/]").strip()
        extra = Prompt.ask(f"  [{G1}]◈ Extra keyword (optional)[/]", default="").strip()
        if name:
            usernames = generate_usernames(name, extra)
            _show_generated(usernames)

def _check_one(username: str):
    """Vérifie un username sur toutes les plateformes"""
    # Proxy optionnel
    proxy = _ask_proxy()

    workers = int(Prompt.ask(f"  [{G1}]◈ Threads[/]", default="20"))
    platforms_sel = _ask_platforms()

    info(f"Checking [{CY}]{username}[/] on [{G1}]{len(platforms_sel)}[/] platforms...")
    console.print()

    results = _run_checks([(username, name, tmpl, st, ct)
                           for name, (tmpl, st, ct) in platforms_sel.items()],
                          workers=workers, proxy=proxy)

    _display_results(results, username)

def _pick_and_check(usernames: list):
    """Montre les usernames générés et laisse l'utilisateur en choisir"""
    _show_generated(usernames)
    console.print()

    sel = Prompt.ask(
        f"  [{G1}]◈ Pick username(s) to check (comma-separated or ALL)[/]",
        default="ALL"
    ).strip()

    if sel.upper() == "ALL":
        # Limite à 10 pour éviter des milliers de requêtes
        to_check = usernames[:10]
        warn(f"Checking first [{OR}]{len(to_check)}[/] variants (use single check for a specific one)")
    else:
        to_check = [s.strip() for s in sel.split(",") if s.strip()]

    proxy    = _ask_proxy()
    workers  = int(Prompt.ask(f"  [{G1}]◈ Threads[/]", default="20"))
    platforms_sel = _ask_platforms()

    tasks = [
        (uname, pname, tmpl, st, ct)
        for uname in to_check
        for pname, (tmpl, st, ct) in platforms_sel.items()
    ]

    info(f"Running [{G1}]{len(tasks)}[/] checks...")
    results = _run_checks(tasks, workers=workers, proxy=proxy)
    _display_results(results)

def _run_checks(tasks: list, workers: int = 20, proxy: dict = None) -> list:
    results = []
    with Progress(
        SpinnerColumn(style=G1),
        TextColumn(f"[{G1}]GHOST checking"),
        BarColumn(bar_width=35, style=G2, complete_style=G1),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("", total=len(tasks))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(check_username, uname, pname, tmpl, st, ct, proxy): (uname, pname)
                for uname, pname, tmpl, st, ct in tasks
            }
            for fut in concurrent.futures.as_completed(futures):
                progress.advance(task)
                res = fut.result()
                results.append(res)
                if res["exists"]:
                    progress.log(
                        f"  [{G1}]★[/]  [{CY}]{res['platform']:<18}[/]  "
                        f"[{G1}]{res['username']}[/]  [{DM}]{res['url']}[/]"
                    )
    return results

def _display_results(results: list, username: str = ""):
    found = [r for r in results if r["exists"]]
    not_found = [r for r in results if not r["exists"] and not r["error"]]

    console.print()

    if found:
        cat_talk(CAT_FOUND, f"{len(found)} profile(s) found!", G1)
        rows = [(r["platform"], r["username"], r["url"]) for r in found]
        print_result_table(
            f"GHOST RESULTS{' :: ' + username if username else ''}",
            ["PLATFORM", "USERNAME", "URL"], rows
        )
    else:
        info("No profiles found on checked platforms.")

    # Sauvegarde
    _save(username or "batch", results)

def _show_generated(usernames: list):
    t = Table(
        title=f"[{G1}]GENERATED USERNAMES ({len(usernames)})[/]",
        box=box.SIMPLE, border_style=G2, header_style=CY,
        show_lines=False
    )
    t.add_column("#",        style=DM,  width=5)
    t.add_column("Username", style=G1,  width=25)
    t.add_column("#",        style=DM,  width=5)
    t.add_column("Username", style=CY,  width=25)

    pairs = list(zip(usernames[::2], usernames[1::2]))
    for i, (a, b) in enumerate(pairs):
        idx = i * 2
        t.add_row(str(idx+1), a, str(idx+2), b)
    if len(usernames) % 2:
        t.add_row(str(len(usernames)), usernames[-1], "", "")

    console.print(t)

def _ask_proxy() -> dict | None:
    use_proxy = Prompt.ask(
        f"  [{G1}]◈ Use proxy from pool? (y/n)[/]", default="n"
    ).lower()
    if use_proxy == "y":
        from core.proxy_manager import get_manager
        pm = get_manager()
        p = pm.get_dict()
        if p:
            info(f"Using proxy: [{CY}]{pm.get()}[/]")
            return p
        else:
            warn("No proxies in pool. Running without proxy.")
    return None

def _ask_platforms() -> dict:
    console.print()
    console.print(f"  [{G1}][1][/] All platforms  ({len(PLATFORMS)})")
    console.print(f"  [{G1}][2][/] Hacker / CTF platforms only")
    console.print(f"  [{G1}][3][/] Social media only")
    console.print(f"  [{G1}][4][/] Dev platforms only")
    sel = ask_choice("Platforms", "1")

    if sel == "2":
        hacker = ["HackTheBox", "TryHackMe", "CTFtime", "GitHub", "GitLab",
                  "HackerNews", "Keybase", "Pastebin"]
        return {k: v for k, v in PLATFORMS.items() if k in hacker}
    elif sel == "3":
        social = ["Reddit", "Twitter/X", "Instagram", "TikTok", "Pinterest",
                  "Tumblr", "Medium", "Twitch", "YouTube", "SoundCloud"]
        return {k: v for k, v in PLATFORMS.items() if k in social}
    elif sel == "4":
        dev = ["GitHub", "GitLab", "Replit", "Codepen", "Stack Overflow",
               "PyPI", "npm", "Docker Hub"]
        return {k: v for k, v in PLATFORMS.items() if k in dev}
    else:
        return PLATFORMS

def _save(username, results):
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out_dir, exist_ok=True)
    slug = re.sub(r"[^a-z0-9_]", "_", username.lower())[:30]
    fname = os.path.join(out_dir, f"ghost_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    found = [r for r in results if r["exists"]]
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"username": username, "found": found, "all": results}, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")

def _banner():
    logo = Text(r"""
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
 ██║  ███╗███████║██║   ██║███████╗   ██║
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
  [USERNAME GENERATOR + PLATFORM CHECKER]""", style=f"bold {G1}")
    console.print(Panel(Align(logo, align="center"), border_style=RD, padding=(0,1)))
