# -*- coding: utf-8 -*-
"""
MEOW-SEC :: PURR — HTTP Recon & Header Analyzer
Inspired by nikto / whatweb — built from scratch
"""
import re, json, os, ssl, socket
from datetime import datetime
from urllib.parse import urlparse, urljoin
import urllib.request

from core.ui import console, ok, err, info, warn, find, boot_progress, print_result_table, show_module_banner, ask_target, G1, G2, CY, OR, RD, DM
from core.cats import CAT_RECON, cat_talk
from rich.panel import Panel
from rich.text import Text

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

# ─── SECURITY HEADERS ────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security":        ("HIGH",   "HSTS missing — downgrade attacks possible"),
    "Content-Security-Policy":          ("HIGH",   "No CSP — XSS risk"),
    "X-Frame-Options":                  ("MEDIUM", "Clickjacking possible"),
    "X-Content-Type-Options":           ("MEDIUM", "MIME sniffing possible"),
    "Referrer-Policy":                  ("LOW",    "Referrer leakage"),
    "Permissions-Policy":               ("LOW",    "Browser features uncontrolled"),
    "X-XSS-Protection":                 ("LOW",    "Legacy XSS filter absent"),
    "Cross-Origin-Opener-Policy":       ("LOW",    "COOP not set"),
    "Cross-Origin-Resource-Policy":     ("LOW",    "CORP not set"),
}

INTERESTING_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via", "X-Cache",
    "CF-RAY", "X-Amzn-Trace-Id", "X-Request-Id",
]

JUICY_PATHS = [
    "/.git/HEAD", "/.env", "/wp-login.php", "/admin", "/admin.php",
    "/phpmyadmin", "/phpinfo.php", "/robots.txt", "/sitemap.xml",
    "/.htaccess", "/backup.zip", "/backup.sql", "/web.config",
    "/config.php", "/wp-config.php", "/.DS_Store", "/crossdomain.xml",
    "/security.txt", "/.well-known/security.txt", "/api/v1", "/api/v2",
    "/swagger.json", "/openapi.json", "/graphql", "/.well-known/openid-configuration",
    "/server-status", "/server-info", "/.git/config",
]

# ─── HTTP HELPER ─────────────────────────────────────────────

def _get(url: str, timeout: int = 8) -> dict:
    """Requête GET simple, retourne status + headers + body[:2000]"""
    try:
        if HAS_REQUESTS:
            r = requests.get(url, timeout=timeout, allow_redirects=True,
                             verify=False, proxies=_px(),
                             headers={"User-Agent": "MEOW-SEC/1.0 (security-scanner)"})
            return {"status": r.status_code, "headers": dict(r.headers),
                    "body": r.text[:2000], "url": r.url, "ok": True}
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "MEOW-SEC/1.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(2000).decode(errors="ignore")
                return {"status": resp.status, "headers": dict(resp.headers),
                        "body": body, "url": str(resp.url), "ok": True}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "url": url, "ok": False, "error": str(e)}

def _normalise(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")

# ─── CHECKS ──────────────────────────────────────────────────

def check_headers(base_url: str) -> tuple:
    """Analyse les en-têtes de sécurité"""
    r = _get(base_url)
    if not r["ok"]:
        err(f"Request failed: {r.get('error', '')}"); return [], {}

    findings = []
    h = {k.lower(): v for k, v in r["headers"].items()}

    # Security headers manquants
    for hdr, (sev, desc) in SECURITY_HEADERS.items():
        if hdr.lower() not in h:
            findings.append((hdr, "MISSING", sev, desc))
        else:
            findings.append((hdr, h[hdr.lower()][:50], "OK", "Present"))

    # Headers informatifs
    for hdr in INTERESTING_HEADERS:
        if hdr.lower() in h:
            val = h[hdr.lower()]
            findings.append((hdr, val[:60], "INFO", "Tech disclosure"))
            find(f"Tech header: [{CY}]{hdr}[/] = [{OR}]{val}[/]")

    return findings, r

def check_paths(base_url: str) -> list:
    """Teste les chemins sensibles"""
    import concurrent.futures
    info(f"Probing {len(JUICY_PATHS)} sensitive paths...")

    def _probe(path):
        url = base_url + path
        r = _get(url, timeout=5)
        if r["ok"] and r["status"] not in (404, 403, 410):
            sev = "HIGH" if any(x in path for x in [".env", ".git", "config", "backup", "phpinfo"]) else "MEDIUM"
            return (path, str(r["status"]), sev, url)
        return None

    # Run in parallel but collect results in JUICY_PATHS order
    results_map = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_idx = {executor.submit(_probe, path): i for i, path in enumerate(JUICY_PATHS)}
        for fut in concurrent.futures.as_completed(future_to_idx):
            idx = future_to_idx[fut]
            result = fut.result()
            if result is not None:
                results_map[idx] = result

    found = []
    for i in sorted(results_map):
        entry = results_map[i]
        found.append(entry)
        find(f"[{entry[1]}] [{CY}]{entry[0]}[/]  [{OR}]({entry[2]})[/]")
    return found

def check_ssl(host: str) -> list:
    """Infos SSL/TLS"""
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                proto = ssock.version()

                not_after = cert.get("notAfter", "")
                cn = dict(x[0] for x in cert.get("subject", [])).get("commonName", "N/A")
                findings.append(("Protocol",  proto,       "INFO", ""))
                findings.append(("Cipher",    cipher[0],   "INFO", ""))
                findings.append(("CN",        cn,          "INFO", ""))
                findings.append(("Expires",   not_after,   "INFO", ""))

                if "TLSv1.0" in proto or "TLSv1.1" in proto:
                    findings.append(("TLS Version", proto, "HIGH", "Outdated TLS version"))

                ok(f"SSL/TLS: [{G1}]{proto}[/]  cipher=[{CY}]{cipher[0]}[/]")
    except Exception as e:
        warn(f"SSL check skipped: {e}")
    return findings

def detect_tech(body: str, headers: dict) -> list:
    """Détecte la stack technique"""
    techs = []
    checks = [
        (r"wp-content|wordpress",      "WordPress"),
        (r"drupal",                     "Drupal"),
        (r"joomla",                     "Joomla"),
        (r"laravel",                    "Laravel"),
        (r"django",                     "Django"),
        (r"react",                      "React"),
        (r"vue\.js|vuejs",              "Vue.js"),
        (r"angular",                    "Angular"),
        (r"bootstrap",                  "Bootstrap"),
        (r"jquery",                     "jQuery"),
        (r"x-powered-by.*php",          "PHP"),
        (r"asp\.net",                   "ASP.NET"),
        (r"nginx",                      "Nginx"),
        (r"apache",                     "Apache"),
        (r"cloudflare",                 "Cloudflare"),
    ]
    combined = body.lower() + " ".join(headers.values()).lower()
    for pattern, name in checks:
        if re.search(pattern, combined, re.I):
            techs.append(name)
    return techs

# ─── MAIN PURR ───────────────────────────────────────────────

def run(target: str = None):
    show_module_banner("purr")
    cat_talk(CAT_RECON, "PURR web recon active — sniffing headers...", OR)
    console.print()

    if not target:
        target = ask_target("Target URL (e.g. https://example.com)")
    if not target:
        err("No target."); return

    target = _normalise(target)
    parsed = urlparse(target)
    host   = parsed.netloc

    info(f"Target: [{CY}]{target}[/]")
    console.print()

    boot_progress([
        "Connecting to target...",
        "Fetching HTTP headers...",
        "Analyzing security headers...",
        "Probing sensitive paths...",
        "Checking SSL/TLS...",
        "Detecting tech stack...",
    ])

    console.print()

    # ── HEADERS ──
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] HEADERS ", style=G2))
    hdr_findings, first_resp = check_headers(target)

    if not hdr_findings:
        warn("Could not retrieve headers (timeout or connection error).")
    else:
        missing = [(h, v, s, d) for h, v, s, d in hdr_findings if v == "MISSING"]
        if missing:
            print_result_table("Missing Security Headers",
                ["HEADER", "STATUS", "SEVERITY", "ISSUE"],
                missing, color_col=2)

    # ── TECH STACK ──
    console.print(Rule(f"[{G1}] TECH STACK ", style=G2))
    if first_resp.get("ok"):
        techs = detect_tech(first_resp["body"], first_resp["headers"])
        if techs:
            for t in techs:
                find(f"Detected: [{CY}]{t}[/]")
        else:
            info("No frameworks detected.")
    console.print()

    # ── SSL ──
    if host:
        console.print(Rule(f"[{G1}] SSL / TLS ", style=G2))
        ssl_info = check_ssl(host)
        if ssl_info:
            print_result_table("SSL/TLS Info",
                ["CHECK", "VALUE", "SEVERITY", "NOTE"],
                ssl_info, color_col=2)

    # ── PATHS ──
    console.print(Rule(f"[{G1}] SENSITIVE PATHS ", style=G2))
    path_findings = check_paths(target)
    if path_findings:
        print_result_table("Exposed Paths",
            ["PATH", "STATUS", "SEVERITY", "URL"],
            path_findings, color_col=2)
    else:
        info("No sensitive paths found.")

    # Sauvegarde
    _save(target, hdr_findings, path_findings)

def _save(target, headers, paths):
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out_dir, exist_ok=True)
    slug = target.replace("://", "_").replace("/", "_").replace(".", "_")
    fname = os.path.join(out_dir, f"purr_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "headers": headers, "paths": paths}, f, indent=2, default=str)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
