# -*- coding: utf-8 -*-
"""
MEOW-SEC :: CATNAP — Subdomain Enumerator
Inspired by sublist3r / amass — built from scratch
"""
import socket, os, json, time
import concurrent.futures
from datetime import datetime

from core.ui import console, ok, err, info, warn, find, print_result_table, show_module_banner, ask_target, ask_choice, G1, G2, CY, OR, RD, DM
from core.cats import CAT_SCAN, cat_talk
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn, TimeElapsedColumn
from rich.prompt import Prompt

# ─── BUILT-IN WORDLIST ───────────────────────────────────────
SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "imap", "vpn", "m", "mobile", "static", "cdn", "img", "images", "news",
    "blog", "dev", "staging", "test", "api", "api2", "app", "admin", "portal",
    "support", "store", "shop", "payment", "secure", "login", "auth",
    "remote", "direct", "server", "mx", "relay", "exchange", "owa",
    "db", "mysql", "sql", "database", "redis", "mongo", "elastic",
    "ci", "jenkins", "gitlab", "github", "jira", "confluence", "wiki",
    "monitor", "grafana", "kibana", "prometheus", "logs",
    "assets", "media", "upload", "uploads", "download", "downloads",
    "beta", "alpha", "v1", "v2", "v3", "old", "new", "backup",
    "demo", "preview", "sandbox", "qa", "uat", "prod", "internal",
    "intranet", "corporate", "private", "vpn2", "sso",
    "chat", "meet", "video", "voice", "live",
    "help", "docs", "documentation", "kb", "forum", "community",
    "status", "health", "ping", "monitor", "uptime",
    "ns3", "ns4", "dns", "dns1", "dns2",
    "smtp1", "smtp2", "pop3", "pop3s", "imaps",
    "git", "svn", "cvs", "repo",
    "cloud", "s3", "storage", "files",
    "phpmyadmin", "cpanel", "plesk", "whm",
    "k8s", "kubernetes", "docker", "registry",
]

# ─── CHECK ───────────────────────────────────────────────────

def resolve_sub(sub: str, domain: str, timeout: float = 1.5) -> dict:
    fqdn = f"{sub}.{domain}"
    try:
        socket.setdefaulttimeout(timeout)
        ips = [addr[4][0] for addr in socket.getaddrinfo(fqdn, None, socket.AF_INET)]
        ips = list(set(ips))
        return {"sub": sub, "fqdn": fqdn, "ips": ips, "found": True}
    except Exception:
        return {"sub": sub, "fqdn": fqdn, "ips": [], "found": False}

def check_http(fqdn: str) -> str:
    """Vérifie si le sous-domaine répond en HTTP"""
    try:
        import requests
        from core.proxy_manager import px as _px
        for scheme in ("https", "http"):
            try:
                r = requests.get(f"{scheme}://{fqdn}", timeout=4,
                                 allow_redirects=False, verify=False, proxies=_px(),
                                 headers={"User-Agent": "MEOW-CATNAP/1.0"})
                return f"{scheme}/{r.status_code}"
            except Exception:
                pass
    except ImportError:
        pass
    return ""

# ─── MAIN CATNAP ─────────────────────────────────────────────

def run(target: str = None):
    show_module_banner("catnap")
    cat_talk(CAT_SCAN, "CATNAP subdomain sniffer active — enumerating...", OR)
    console.print()

    if not target:
        target = ask_target("Target domain (e.g. example.com)")
    if not target:
        err("No target."); return

    import re
    target = re.sub(r"https?://", "", target).split("/")[0].strip()
    info(f"Target domain: [{CY}]{target}[/]")
    console.print()

    console.print(f"  [{G1}][1][/] Quick scan   ({len(SUBDOMAINS[:40])} subdomains)")
    console.print(f"  [{G1}][2][/] Full scan    ({len(SUBDOMAINS)} subdomains)")
    console.print(f"  [{G1}][3][/] Custom file")
    mode = ask_choice("Mode", "1")

    if mode == "1":
        words = SUBDOMAINS[:40]
    elif mode == "2":
        words = SUBDOMAINS
    elif mode == "3":
        path = Prompt.ask(f"  [{G1}]◈ Wordlist path[/]").strip()
        if not os.path.exists(path):
            err(f"File not found: {path}"); return
        with open(path) as f:
            words = [l.strip() for l in f if l.strip()]
    else:
        words = SUBDOMAINS[:40]

    http_check = Prompt.ask(
        f"  [{G1}]◈ Check HTTP on found subdomains? (y/n)[/]",
        default="y"
    ).lower() == "y"

    threads = int(Prompt.ask(f"  [{G1}]◈ Threads[/]", default="50"))

    info(f"Testing [{G1}]{len(words)}[/] subdomains  |  threads=[{CY}]{threads}[/]")
    console.print()

    found = []
    total = len(words)

    with Progress(
        SpinnerColumn(style=G1),
        TextColumn(f"[{G1}]CATNAP"),
        BarColumn(bar_width=40, style=G2, complete_style=G1),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Enumerating...", total=total)

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(resolve_sub, w, target): w for w in words}
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                progress.advance(task)
                if res["found"]:
                    ips_str = ", ".join(res["ips"][:3])
                    http = check_http(res["fqdn"]) if http_check else ""
                    found.append((res["fqdn"], ips_str, http or "-"))
                    progress.log(
                        f"  [{G1}]★[/]  [{CY}]{res['fqdn']:<40}[/]  [{OR}]{ips_str}[/]  [{DM}]{http}[/]"
                    )

    console.print()

    if found:
        print_result_table(
            f"CATNAP RESULTS :: {target}",
            ["SUBDOMAIN", "IP(s)", "HTTP"],
            found
        )
        find(f"{len(found)} subdomain(s) discovered on [{CY}]{target}[/]")
    else:
        info("No subdomains found.")

    _save(target, found)

def _save(target, found):
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out_dir, exist_ok=True)
    slug = target.replace(".", "_")
    fname = os.path.join(out_dir, f"catnap_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w") as f:
        json.dump({"target": target, "found": found}, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
