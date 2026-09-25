# -*- coding: utf-8 -*-
"""
MEOW-SEC :: SUBBRUTE (#67) — Aggressive Subdomain Brute-Forcer
200+ built-in wordlist, smart permutations, wildcard detection, HTTP probing.
For authorized security testing and CTF challenges only.
"""
import os, re, json, socket, time
import concurrent.futures
from datetime import datetime

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_target, ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn, TimeElapsedColumn
from rich.prompt import Prompt

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

# ─── BUILT-IN WORDLIST (200+) ─────────────────────────────────
WORDLIST = [
    # Core
    "www", "mail", "ftp", "smtp", "pop", "imap", "vpn", "remote", "admin",
    "api", "app", "portal", "dashboard", "secure", "login", "auth",
    # Dev / Staging
    "dev", "dev1", "dev2", "staging", "stage", "test", "test1", "test2",
    "beta", "alpha", "sandbox", "preprod", "qa", "uat", "demo", "preview",
    "nightly", "canary", "rc", "release", "feature",
    # CI / DevOps
    "jenkins", "ci", "cd", "pipeline", "teamcity", "bamboo", "travis",
    "gitlab", "github", "bitbucket", "jira", "confluence", "wiki", "redmine",
    "grafana", "kibana", "prometheus", "logstash", "portainer", "rancher",
    "vault", "consul", "nomad", "terraform", "puppet", "ansible", "chef",
    # Cloud / Storage
    "cdn", "static", "assets", "media", "images", "img", "files", "uploads",
    "download", "downloads", "s3", "storage", "backup", "backups", "archive",
    "blob", "cloud", "obj", "bucket",
    # Infra / DB
    "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2",
    "relay", "smtp2", "pop3", "exchange", "owa", "autodiscover",
    "db", "db1", "db2", "database", "mysql", "pgsql", "postgres", "redis",
    "mongo", "mongodb", "elastic", "elasticsearch", "cassandra", "memcache",
    "memcached", "cache", "queue", "broker", "kafka", "rabbitmq", "zookeeper",
    # Auth / IAM
    "sso", "oauth", "oauth2", "saml", "idp", "adfs", "iam", "keycloak",
    "okta", "ldap", "ad", "accounts", "account", "identity",
    # Monitoring / Status
    "status", "health", "ping", "monitor", "monitoring", "uptime", "metrics",
    "alerts", "logs", "logging", "trace", "tracing", "sentry", "datadog",
    "nagios", "zabbix", "pagerduty", "ops",
    # E-commerce / CMS
    "shop", "store", "cart", "checkout", "pay", "payment", "payments",
    "billing", "invoice", "orders", "blog", "cms", "wp", "wordpress",
    "drupal", "magento", "woocommerce",
    # Community / Support
    "forum", "community", "help", "support", "helpdesk", "ticket", "tickets",
    "kb", "docs", "documentation", "doc", "api-docs", "swagger", "openapi",
    "wiki",
    # Mobile / Apps
    "m", "mobile", "app2", "apps", "ios", "android", "pwa",
    # Misc services
    "chat", "meet", "video", "voice", "live", "stream", "webrtc",
    "register", "signup", "verify", "confirm", "activate", "reset",
    "internal", "intranet", "corporate", "private", "extranet",
    "old", "new", "legacy", "v1", "v2", "v3", "v4",
    "prod", "production", "uat", "stg", "int", "ext",
    "proxy", "gateway", "waf", "firewall", "edge",
    "phpmyadmin", "cpanel", "whm", "plesk", "webmin",
    "k8s", "kubernetes", "docker", "registry", "harbor",
    "git", "svn", "repo", "code", "source",
    "vpn2", "openvpn", "wireguard",
    "ftp2", "sftp",
    "smtp1", "mail2", "webmail", "imap2",
    "ns5", "dns3", "resolver",
    "node", "server", "srv", "host", "box",
    "home", "www2", "web", "web1", "web2", "site",
]

# De-duplicate while preserving order
_seen = set()
WORDLIST = [x for x in WORDLIST if not (_seen.add(x) or x in _seen)]  # type: ignore

# ─── DNS HELPERS ──────────────────────────────────────────────

def _resolve(fqdn: str) -> list[str]:
    """Resolve FQDN → list of IPs. Returns [] on failure."""
    try:
        addrs = socket.getaddrinfo(fqdn, None, socket.AF_INET,
                                   socket.SOCK_STREAM, 0, socket.AI_ADDRINFO)
        return list({addr[4][0] for addr in addrs})
    except (socket.gaierror, OSError):
        return []


def _detect_wildcard(domain: str) -> list[str] | None:
    """Returns the wildcard IP(s) if the domain has a DNS wildcard, else None."""
    probe = f"_meow_nonexistent_12345.{domain}"
    ips = _resolve(probe)
    return ips if ips else None


def _check_http(fqdn: str) -> tuple[str, str]:
    """GET http/https for fqdn. Returns (status, title)."""
    if not HAS_REQUESTS:
        return "", ""
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{fqdn}",
                timeout=4, allow_redirects=True, verify=False,
                proxies=_px(),
                headers={"User-Agent": "MEOW-SUBBRUTE/1.0"}
            )
            title = ""
            m = re.search(r"<title[^>]*>([^<]{1,80})", r.text, re.I)
            if m:
                title = m.group(1).strip()
            return f"{scheme}/{r.status_code}", title
        except Exception:
            pass
    return "", ""


# ─── WORKER ───────────────────────────────────────────────────

def _probe_sub(args: tuple) -> dict:
    """Thread worker: resolve + optionally HTTP-check one subdomain."""
    sub, domain, wildcard_ips, do_http = args
    fqdn = f"{sub}.{domain}"
    ips  = _resolve(fqdn)

    if not ips:
        return {"found": False, "fqdn": fqdn, "ips": [], "http": "", "title": ""}

    # Wildcard filtering
    if wildcard_ips:
        if set(ips) == set(wildcard_ips):
            return {"found": False, "fqdn": fqdn, "ips": ips, "http": "", "title": "",
                    "wildcard_filtered": True}

    http, title = ("", "")
    if do_http:
        http, title = _check_http(fqdn)

    return {"found": True, "fqdn": fqdn, "ips": ips, "http": http, "title": title}

# ─── MAIN ─────────────────────────────────────────────────────

def run(target: str = None):
    show_module_banner("subbrute")
    cat_talk(CAT_SCAN, "SUBBRUTE — aggressive subdomain brute-force with wildcard detection...", OR)
    console.print()

    if not target:
        target = ask_target("Target domain (e.g. example.com)")
    if not target:
        err("No target."); return

    target = re.sub(r"https?://", "", target).split("/")[0].strip().lower()
    info(f"Target domain: [{CY}]{target}[/]")
    console.print()

    # ── Scan mode ─────────────────────────────────────────────
    console.print(f"  [{G1}][1][/] Quick scan        (~{min(60, len(WORDLIST))} subdomains, built-in core)")
    console.print(f"  [{G1}][2][/] Full scan         ({len(WORDLIST)} subdomains, built-in list)")
    console.print(f"  [{G1}][3][/] Full + permutations  ({len(WORDLIST)} words + generated permutations)")
    console.print(f"  [{G1}][4][/] Custom file")
    mode = ask_choice("Mode", "2")
    console.print()

    if mode == "1":
        words = WORDLIST[:60]
        do_perms = False
    elif mode == "2":
        words = list(WORDLIST)
        do_perms = False
    elif mode == "3":
        words = list(WORDLIST)
        do_perms = True
    elif mode == "4":
        path = Prompt.ask(f"  [{G1}]◈ Wordlist path[/]").strip()
        if not os.path.exists(path):
            err(f"File not found: {path}"); return
        with open(path, encoding="utf-8", errors="ignore") as f:
            words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        do_perms = False
    else:
        words = list(WORDLIST)
        do_perms = False

    # ── Permutations ──────────────────────────────────────────
    if do_perms:
        base_domain = target.split(".")[0]
        perms = set()
        for w in words[:50]:  # permute only the first 50 words to keep it sane
            perms.add(f"{w}-{base_domain}")
            perms.add(f"{base_domain}-{w}")
        perms -= set(words)
        words = words + sorted(perms)
        info(f"Permutations generated: [{G1}]{len(perms)}[/] additional entries")

    threads = int(Prompt.ask(f"  [{G1}]◈ Threads[/]", default="50").strip())
    do_http = Prompt.ask(
        f"  [{G1}]◈ HTTP probe found subdomains? (y/n)[/]", default="y"
    ).lower() == "y"
    console.print()

    # ── Wildcard detection ────────────────────────────────────
    info("Checking for DNS wildcard...")
    wildcard_ips = _detect_wildcard(target)
    if wildcard_ips:
        warn(f"DNS wildcard detected! IPs: [{OR}]{', '.join(wildcard_ips)}[/]  — filtering false positives")
    else:
        ok("No DNS wildcard detected.")
    console.print()

    info(f"Bruteforcing [{G1}]{len(words)}[/] subdomains  |  threads=[{CY}]{threads}[/]")
    console.print()

    found     = []
    filtered  = 0
    start     = time.time()

    args_list = [(w, target, wildcard_ips, do_http) for w in words]

    with Progress(
        SpinnerColumn(style=G1),
        TextColumn(f"[{G1}]SUBBRUTE"),
        BarColumn(bar_width=38, style=G2, complete_style=G1),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Bruting...", total=len(words))

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_probe_sub, a): a[0] for a in args_list}
            for fut in concurrent.futures.as_completed(futures):
                result = fut.result()
                progress.advance(task)

                if result.get("wildcard_filtered"):
                    filtered += 1
                    continue

                if result["found"]:
                    fqdn   = result["fqdn"]
                    ips    = ", ".join(result["ips"][:3])
                    http   = result.get("http", "")
                    title  = result.get("title", "")[:40]
                    found.append((fqdn, ips, http or "-", title or "-"))
                    progress.log(
                        f"  [{G1}]★[/]  [{CY}]{fqdn:<45}[/]  [{OR}]{ips}[/]"
                        + (f"  [{DM}]{http}[/]" if http else "")
                    )

    elapsed = time.time() - start
    console.print()

    if wildcard_ips and filtered:
        info(f"Wildcard filtered: [{DM}]{filtered}[/] false positive(s) removed")

    if found:
        print_result_table(
            f"SUBBRUTE RESULTS :: {target}",
            ["SUBDOMAIN", "IP(s)", "HTTP", "TITLE"],
            found
        )
        find(f"{len(found)} subdomain(s) discovered on [{CY}]{target}[/] in {elapsed:.1f}s")
    else:
        info(f"No subdomains found in {elapsed:.1f}s.")

    _save(target, found, wildcard_ips)


def _save(domain: str, found: list, wildcard: list | None):
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out_dir, exist_ok=True)
    slug  = domain.replace(".", "_")
    fname = os.path.join(out_dir, f"subbrute_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    payload = {
        "domain":    domain,
        "timestamp": datetime.now().isoformat(),
        "wildcard":  wildcard,
        "count":     len(found),
        "results": [
            {"subdomain": r[0], "ips": r[1], "http": r[2], "title": r[3]}
            for r in found
        ]
    }
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
