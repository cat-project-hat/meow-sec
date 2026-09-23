# -*- coding: utf-8 -*-
"""
MEOW-SEC :: CMS — CMS / Framework Fingerprinting
  · WordPress, Drupal, Joomla, Magento, PrestaShop
  · Laravel, Django, Flask, Symfony, Rails, Express
  · Version detection + known CVE hints
  · Plugin/theme enum (WordPress)
  · Exposed config/backup files
"""
import re, os, json, time
from datetime import datetime
from urllib.parse import urljoin

from core.ui import (
                     console, ok, err, info, warn,
                     find, show_module_banner, ask_choice, print_result_table, G1,
                     G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN, CAT_FOUND
from rich.panel   import Panel
from rich.table   import Table
from rich.prompt  import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn, TimeElapsedColumn
from rich         import box
from rich.rule    import Rule

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

# ─── CMS FINGERPRINTS ────────────────────────────────────────

CMS_DB = {
    "WordPress": {
        "paths":   ["/wp-login.php", "/wp-admin/", "/wp-json/wp/v2/",
                    "/wp-content/", "/wp-includes/", "/xmlrpc.php",
                    "/wp-cron.php", "/readme.html"],
        "headers": ["x-powered-by"],
        "body":    ["wp-content", "wp-includes", "wordpress", "wp-json",
                    "/wp-login.php", "wp_head"],
        "version_regex": [
            r'<meta name="generator" content="WordPress ([0-9.]+)"',
            r'"version":"([0-9.]+)"',
        ],
        "color": CY,
        "cve_link": "https://wpscan.com/wordpresses/",
        "plugins_path": "/wp-content/plugins/",
        "extras": [
            ("/wp-json/wp/v2/users",    "User enumeration via REST API"),
            ("/xmlrpc.php",              "XMLRPC enabled (brute force / DoS vector)"),
            ("/?author=1",               "Author enumeration"),
            ("/wp-config.php.bak",       "Config backup exposed"),
        ]
    },
    "Drupal": {
        "paths":   ["/user/login", "/CHANGELOG.txt", "/sites/default/",
                    "/core/CHANGELOG.txt", "/misc/drupal.js", "/modules/"],
        "headers": ["x-drupal-cache", "x-generator"],
        "body":    ["drupal", "sites/default", "drupal.js", "Drupal.settings",
                    "drupal-toolbar"],
        "version_regex": [
            r'Drupal ([0-9]+\.[0-9]+)',
            r'"version":"([0-9.]+)"',
        ],
        "color": OR,
        "cve_link": "https://www.drupal.org/security",
        "extras": [
            ("/CHANGELOG.txt",           "CHANGELOG exposes version"),
            ("/sites/default/files/",    "Files directory listing"),
        ]
    },
    "Joomla": {
        "paths":   ["/administrator/", "/components/", "/modules/",
                    "/language/en-GB/en-GB.xml", "/templates/",
                    "/cache/", "/plugins/", "/configuration.php"],
        "headers": [],
        "body":    ["joomla", "/components/", "/modules/", "Joomla!",
                    "/media/system/js/"],
        "version_regex": [
            r'<generator>Joomla! ([0-9.]+)',
            r'"version":"([0-9.]+)"',
        ],
        "color": RD,
        "cve_link": "https://developer.joomla.org/security-centre.html",
        "extras": [
            ("/administrator/",          "Admin panel exposed"),
            ("/configuration.php.bak",   "Config backup"),
        ]
    },
    "Magento": {
        "paths":   ["/admin", "/index.php/admin/", "/skin/frontend/",
                    "/js/mage/", "/app/etc/local.xml", "/downloader/",
                    "/mage"],
        "headers": ["x-magento-vary", "x-magento-tags"],
        "body":    ["mage/", "Magento", "skin/frontend", "var/cache",
                    "Mage.Cookies"],
        "version_regex": [r'Magento/([0-9.]+)'],
        "color": OR,
        "cve_link": "https://magento.com/security",
        "extras": [
            ("/app/etc/local.xml",       "Config file exposed (credentials!)"),
            ("/downloader/",             "Magento Connect Manager"),
        ]
    },
    "PrestaShop": {
        "paths":   ["/admin/", "/modules/", "/classes/", "/config/",
                    "/themes/", "/img/"],
        "body":    ["prestashop", "presta-shop", "/modules/", "/themes/"],
        "headers": [],
        "version_regex": [r'PrestaShop ([0-9.]+)'],
        "color": CY,
        "cve_link": "https://security.prestashop.com/",
        "extras": []
    },
    "Laravel": {
        "paths":   ["/.env", "/storage/logs/laravel.log", "/public/",
                    "/artisan", "/config/app.php"],
        "headers": ["x-powered-by"],
        "body":    ["laravel", "Illuminate\\", "APP_KEY", "Laravel"],
        "version_regex": [r'"laravel/framework":"([0-9.^~]+)"'],
        "color": RD,
        "cve_link": "https://laravel.com/docs/security",
        "extras": [
            ("/.env",                    "ENV file EXPOSED (DB credentials, APP_KEY!)"),
            ("/storage/logs/laravel.log","Log file exposed (stack traces)"),
        ]
    },
    "Django": {
        "paths":   ["/admin/", "/static/admin/", "/media/"],
        "headers": ["x-frame-options", "x-content-type-options"],
        "body":    ["django", "csrfmiddlewaretoken", "Django", "__admin_media_prefix__"],
        "version_regex": [r'Django ([0-9.]+)'],
        "color": G1,
        "cve_link": "https://docs.djangoproject.com/en/stable/releases/security/",
        "extras": [
            ("/admin/",                  "Django admin panel"),
        ]
    },
    "Flask": {
        "paths":   ["/console", "/_debug_toolbar/"],
        "headers": ["server"],
        "body":    ["Werkzeug", "flask", "jinja2", "Debugger"],
        "version_regex": [r'Werkzeug/([0-9.]+)'],
        "color": DM,
        "cve_link": "https://flask.palletsprojects.com/en/stable/",
        "extras": [
            ("/console",                 "Werkzeug console EXPOSED (RCE!)"),
        ]
    },
    "Symfony": {
        "paths":   ["/_profiler/", "/app.php", "/app_dev.php", "/app_test.php"],
        "headers": ["x-debug-token"],
        "body":    ["symfony", "Symfony", "_profiler", "app_dev.php"],
        "version_regex": [r'Symfony ([0-9.]+)'],
        "color": DM,
        "cve_link": "https://symfony.com/blog/category/security-advisories",
        "extras": [
            ("/app_dev.php",             "Dev mode exposed (debug info)"),
            ("/_profiler/",              "Profiler exposed (internal info)"),
        ]
    },
    "Ruby on Rails": {
        "paths":   ["/rails/info/properties", "/rails/mailers", "/.git/"],
        "headers": ["x-runtime", "x-request-id"],
        "body":    ["rails", "Ruby on Rails", "ActionController"],
        "version_regex": [r'Rails ([0-9.]+)'],
        "color": RD,
        "cve_link": "https://rubyonrails.org/security",
        "extras": []
    },
    "Express (Node.js)": {
        "paths":   ["/api/", "/graphql", "/swagger", "/.env"],
        "headers": ["x-powered-by"],
        "body":    ["express", "Cannot GET", "node"],
        "version_regex": [r'Express/([0-9.]+)'],
        "color": G2,
        "cve_link": "https://github.com/expressjs/express/security",
        "extras": [
            ("/.env",                    "ENV file check"),
        ]
    },
}

# Fichiers sensibles communs à tous les CMS
COMMON_SENSITIVE = [
    ("/.git/HEAD",          "Git repository exposed"),
    ("/.git/config",        "Git config exposed (credentials!)"),
    ("/.svn/entries",       "SVN repository exposed"),
    ("/.DS_Store",          "macOS directory listing"),
    ("/composer.json",      "Composer dependencies exposed"),
    ("/package.json",       "NPM package info"),
    ("/.htpasswd",          "htpasswd file"),
    ("/web.config",         "IIS web.config"),
    ("/phpinfo.php",        "PHPInfo exposed (system info)"),
    ("/info.php",           "PHP info"),
    ("/server-status",      "Apache server-status"),
    ("/server-info",        "Apache server-info"),
    ("/crossdomain.xml",    "Flash cross-domain policy"),
    ("/clientaccesspolicy.xml", "Silverlight cross-domain"),
    ("/.well-known/security.txt", "Security.txt (contact)"),
    ("/SECURITY.md",        "Security policy"),
    ("/README.md",          "README (version hints)"),
    ("/CHANGELOG",          "Changelog (version hints)"),
    ("/LICENSE",            "License file"),
    ("/.travis.yml",        "CI config (infra hints)"),
    ("/.github/workflows/", "GitHub Actions config"),
    ("/docker-compose.yml", "Docker compose exposed"),
    ("/Dockerfile",         "Dockerfile exposed"),
    ("/backup.zip",         "Backup archive"),
    ("/backup.sql",         "SQL backup"),
    ("/db.sql",             "Database dump"),
    ("/dump.sql",           "Database dump"),
]

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
           "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}

# ─── DETECTION ───────────────────────────────────────────────

def _get(url: str, timeout: int = 8) -> dict:
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout,
                         verify=False, allow_redirects=True, proxies=_px())
        return {"status": r.status_code, "body": r.text[:8000],
                "headers": {k.lower(): v.lower() for k, v in r.headers.items()},
                "ok": True}
    except Exception:
        return {"status": 0, "body": "", "headers": {}, "ok": False}

def detect_cms(base_url: str) -> dict:
    base = base_url.rstrip("/")
    results = {}

    # Page principale
    main = _get(base)
    if not main["ok"]:
        return {"error": f"Cannot reach {base}"}

    body_low   = main["body"].lower()
    hdrs       = main["headers"]

    for cms_name, sig in CMS_DB.items():
        score   = 0
        matched = []
        version = None

        # Body signatures
        for b in sig["body"]:
            if b.lower() in body_low:
                score += 10; matched.append(f"body:{b[:20]}")

        # Header signatures
        for h in sig.get("headers", []):
            if h in hdrs:
                score += 8; matched.append(f"header:{h}")

        # Path checks (parallèle limité)
        for path in sig["paths"][:4]:
            r2 = _get(base + path)
            if r2["status"] in (200, 301, 302, 403):
                score += 15
                matched.append(f"path:{path}")
                # Try version extraction
                if not version and r2["ok"]:
                    for pat in sig.get("version_regex", []):
                        m = re.search(pat, r2["body"], re.I)
                        if m:
                            version = m.group(1)

        if score > 0:
            results[cms_name] = {
                "score":   score,
                "matched": matched,
                "version": version,
                "color":   sig["color"],
                "cve":     sig["cve_link"],
                "extras":  sig.get("extras", []),
            }

    return {"cms": results, "base": base,
            "server": hdrs.get("server","?"),
            "x_powered": hdrs.get("x-powered-by",""),
            "tech_hints": _tech_hints(main)}

def _tech_hints(resp: dict) -> list:
    """Détecte le stack technique depuis les headers"""
    hints = []
    hdrs = resp["headers"]
    body = resp["body"].lower()

    checks = {
        "PHP":        ["x-powered-by", "php"],
        "ASP.NET":    ["x-aspnet-version", "x-aspnetmvc-version"],
        "IIS":        [("server", "iis")],
        "Nginx":      [("server", "nginx")],
        "Apache":     [("server", "apache")],
        "Cloudflare": ["cf-ray", "cf-cache-status"],
        "Varnish":    [("via", "varnish")],
    }
    for tech, checks_ in checks.items():
        for c in checks_:
            if isinstance(c, tuple):
                k, v = c
                if v in hdrs.get(k,""):
                    hints.append(tech); break
            else:
                if c in hdrs or c in body:
                    hints.append(tech); break
    return list(set(hints))

# ─── SENSITIVE FILES SCAN ────────────────────────────────────

def scan_sensitive(base_url: str, extra: list = None) -> list:
    base  = base_url.rstrip("/")
    found = []
    paths = COMMON_SENSITIVE + (extra or [])

    with Progress(SpinnerColumn(style=G1),
                  TextColumn(f"[{G1}]Scanning sensitive files"),
                  BarColumn(bar_width=30, style=G2, complete_style=G1),
                  MofNCompleteColumn(), TimeElapsedColumn(),
                  console=console) as prog:
        task = prog.add_task("", total=len(paths))
        for path, desc in paths:
            prog.advance(task)
            r = _get(base + path, timeout=6)
            if r["status"] in (200, 206, 301, 302, 403):
                c = G1 if r["status"] == 200 else OR
                found.append((path, str(r["status"]), desc))
                prog.log(f"  [{c}][{r['status']}][/] {path}  [{DM}]{desc}[/]")
            time.sleep(0.05)

    return found

# ─── WORDPRESS PLUGIN ENUM ───────────────────────────────────

WP_POPULAR_PLUGINS = [
    "akismet","wordfence","woocommerce","elementor","jetpack","yoast-seo",
    "contact-form-7","w3-total-cache","wp-super-cache","mailchimp-for-wp",
    "really-simple-ssl","all-in-one-seo-pack","updraftplus","duplicate-page",
    "advanced-custom-fields","wp-mail-smtp","redirection","wp-rocket",
    "ninja-forms","ultimate-member","buddypress","bbpress","wp-members",
    "login-lockdown","limit-login-attempts","ithemes-security","wordfence",
    "sucuri-scanner","wp-file-manager","file-manager","revslider",
]

def enum_wp_plugins(base_url: str) -> list:
    base  = base_url.rstrip("/")
    found = []
    with Progress(SpinnerColumn(style=G1),
                  TextColumn(f"[{G1}]WP plugin enum"),
                  BarColumn(bar_width=30, style=G2, complete_style=G1),
                  MofNCompleteColumn(), console=console) as prog:
        task = prog.add_task("", total=len(WP_POPULAR_PLUGINS))
        for plugin in WP_POPULAR_PLUGINS:
            prog.advance(task)
            r = _get(f"{base}/wp-content/plugins/{plugin}/", timeout=5)
            if r["status"] in (200, 301, 302, 403):
                # Try to get version from readme
                r2 = _get(f"{base}/wp-content/plugins/{plugin}/readme.txt", timeout=4)
                ver = "?"
                if r2["status"] == 200:
                    m = re.search(r'Stable tag:\s*([0-9.]+)', r2["body"], re.I)
                    if m: ver = m.group(1)
                found.append((plugin, ver, str(r["status"])))
                prog.log(f"  [{G1}][{r['status']}][/] {plugin}  v{ver}")
    return found

# ─── MAIN ────────────────────────────────────────────────────

def run():
    show_module_banner("cms")
    cat_talk(CAT_SCAN, "CMS fingerprinting engine loaded.", OR)
    console.print()

    if not HAS_REQUESTS:
        err("requests library required."); return

    while True:
        console.print(f"  [{G1}][1][/] Detect CMS / framework")
        console.print(f"  [{G1}][2][/] Scan sensitive / exposed files")
        console.print(f"  [{G1}][3][/] WordPress plugin enumeration")
        console.print(f"  [{G1}][4][/] Full scan  (1+2+3)")
        console.print(f"  [{G1}][0][/] Back")
        console.print()
        choice = ask_choice("CMS", "0")

        if choice == "0": break
        url = Prompt.ask(f"  [{G1}]◈ Target URL[/]").strip()
        if not url: continue
        if "://" not in url: url = "https://" + url

        if choice in ("1","4"):
            info("Fingerprinting CMS / framework...")
            data = detect_cms(url)
            _display_cms(data)

        if choice in ("2","4"):
            console.print()
            info("Scanning for sensitive/exposed files...")
            found = scan_sensitive(url)
            if found:
                print_result_table("Sensitive Files", ["Path","Status","Description"], found)
            else:
                ok("No sensitive files found.")

        if choice in ("3","4"):
            # Check si WordPress d'abord
            data = detect_cms(url) if choice == "4" else {}
            if "WordPress" in data.get("cms",{}) or choice == "3":
                console.print()
                info("Enumerating WordPress plugins...")
                plugins = enum_wp_plugins(url)
                if plugins:
                    print_result_table("WP Plugins Found",
                        ["Plugin","Version","Status"], plugins)
                else:
                    info("No common plugins detected.")

        _save_results(url, choice)
        console.print()

def _display_cms(data: dict):
    if "error" in data:
        err(data["error"]); return

    console.print()
    info(f"Server: [{CY}]{data['server']}[/]  "
         f"X-Powered-By: [{OR}]{data.get('x_powered','?')}[/]")
    if data.get("tech_hints"):
        info(f"Tech stack: [{G1}]{', '.join(data['tech_hints'])}[/]")
    console.print()

    cms = data.get("cms",{})
    if not cms:
        warn("No CMS detected."); return

    # Top match
    top_name = max(cms, key=lambda k: cms[k]["score"])
    top = cms[top_name]
    conf = min(top["score"] * 2, 100)

    find(f"CMS detected: [{top['color']}]{top_name}[/]"
         + (f" v{top['version']}" if top.get("version") else "")
         + f"  (confidence: [{G1}]{conf}%[/])")
    info(f"CVE / Security: [{CY}]{top['cve']}[/]")

    # Extras critiques
    for path, note in top.get("extras",[]):
        if any(w in note for w in ("EXPOSED","EXPOSED","RCE","credentials")):
            warn(f"{path}  [{RD}]{note}[/]")
        else:
            info(f"{path}  [{DM}]{note}[/]")

    # Table tous CMS détectés
    if len(cms) > 1:
        console.print()
        t = Table(box=box.SIMPLE, header_style=CY, border_style=G2, show_edge=False)
        t.add_column("CMS",       style=f"bold {G1}", width=20)
        t.add_column("Version",   style=CY, width=10)
        t.add_column("Confidence",style=OR, width=12)
        t.add_column("Evidence",  style=DM)
        for name, d in sorted(cms.items(), key=lambda x: x[1]["score"], reverse=True):
            c = min(d["score"]*2, 100)
            t.add_row(name, d.get("version") or "?", f"{c}%",
                      ", ".join(d["matched"][:3]))
        console.print(t)

def _save_results(url, mode):
    os.makedirs("data", exist_ok=True)
    fname = f"data/cms_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": url, "mode": mode,
                   "timestamp": datetime.now().isoformat()}, f, indent=2)
    ok(f"Saved: {fname}")
