# -*- coding: utf-8 -*-
"""MEOW-SEC :: WPSCAN — WordPress Vulnerability Scanner
Détecte : version, CVEs, plugins vulnérables, user enum, XMLRPC, fichiers sensibles,
REST API leak, directory listing, headers manquants, WP-Cron abuse.
"""
import os, re, json
from datetime import datetime
from urllib.parse import urljoin, urlparse

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN, CAT_FOUND
from rich.panel    import Panel
from rich.table    import Table
from rich.prompt   import Prompt, Confirm
from rich.rule     import Rule
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn
from rich          import box

try:
    import requests as _req
    _req.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

_UA      = "Mozilla/5.0 (compatible; MEOW-WPSCAN/1.0; authorized-test)"
_TIMEOUT = 10

# ─── CVEs CONNUES PAR VERSION WP ─────────────────────────────

_WP_CVES = {
    "6.4":  [("CVE-2023-5561",  "HIGH",   "Unauthenticated blind SSRF via pingback"),
             ("CVE-2023-49752", "MEDIUM",  "XSS via comment author in admin")],
    "6.3":  [("CVE-2023-39999", "MEDIUM",  "Reflected XSS in search results"),
             ("CVE-2023-38000", "HIGH",    "XSS via stored post content")],
    "6.2":  [("CVE-2023-2745",  "MEDIUM",  "Directory traversal in wp_get_font_dir()")],
    "6.1":  [("CVE-2022-43497", "MEDIUM",  "XSS via plugin activation"),
             ("CVE-2022-43500", "MEDIUM",  "XSS in search block")],
    "6.0":  [("CVE-2022-3590",  "MEDIUM",  "Unauthenticated blind SSRF")],
    "5.9":  [("CVE-2022-21663", "MEDIUM",  "Object injection via meta"),
             ("CVE-2022-21661", "HIGH",    "SQL injection via WP_Query")],
    "5.8":  [("CVE-2021-44223", "MEDIUM",  "XSS in block widgets")],
    "5.7":  [("CVE-2021-29447", "HIGH",    "XXE via media upload (wav file)")],
    "5.6":  [("CVE-2021-29450", "MEDIUM",  "SSRF via DNS rebinding"),
             ("CVE-2020-28032", "HIGH",    "Object injection deserialization")],
    "5.5":  [("CVE-2020-28033", "MEDIUM",  "Embed XSS"),
             ("CVE-2020-28034", "MEDIUM",  "XSS via wp_targeted_link_rel()")],
    "5.4":  [("CVE-2020-11026", "MEDIUM",  "XSS via Customizer")],
    "5.3":  [("CVE-2019-20041", "MEDIUM",  "XSS via shortcode comment")],
    "5.2":  [("CVE-2019-17670", "HIGH",    "SSRF via `s` param in admin"),
             ("CVE-2019-16781", "MEDIUM",  "XSS in post author slug")],
    "4.":   [("CVE-2017-14723", "HIGH",    "SQL injection via meta"),
             ("CVE-2019-9787",  "HIGH",    "CSRF leading to XSS in comments")],
}

# ─── PLUGINS VULNÉRABLES COURANTS ────────────────────────────

_VULN_PLUGINS = {
    "contact-form-7":        ("CVE-2020-35489", "CRITICAL", "Unrestricted file upload"),
    "woocommerce":           ("CVE-2023-28121", "CRITICAL", "Auth bypass via user ID header"),
    "elementor":             ("CVE-2023-32243", "CRITICAL", "Priv escalation in role manager"),
    "wp-file-manager":       ("CVE-2020-25213", "CRITICAL", "Unauthenticated RCE via elFinder"),
    "ultimate-member":       ("CVE-2023-3460",  "CRITICAL", "Priv escalation to admin"),
    "wp-super-cache":        ("CVE-2023-2732",  "HIGH",     "Unauthenticated RCE"),
    "wpforms-lite":          ("CVE-2023-2681",  "HIGH",     "Stored XSS"),
    "all-in-one-seo-pack":   ("CVE-2023-0585",  "HIGH",     "Stored XSS in post titles"),
    "advanced-custom-fields":("CVE-2023-30777", "HIGH",     "Reflected XSS"),
    "yoast-seo":             ("CVE-2021-25118", "MEDIUM",   "Stored XSS in meta"),
    "jetpack":               ("CVE-2023-2996",  "MEDIUM",   "Stored XSS in Contact Form"),
    "wordfence":             ("CVE-2021-24876", "MEDIUM",   "Open redirect"),
    "akismet":               ("CVE-2021-24376", "LOW",      "CSRF token leak"),
    "timthumb":              ("CVE-2011-4106",  "CRITICAL", "Remote file inclusion / code exec"),
    "revslider":             ("CVE-2014-9734",  "CRITICAL", "Arbitrary file upload"),
    "gravityforms":          ("CVE-2021-9090",  "HIGH",     "SQL injection in form entries"),
    "duplicator":            ("CVE-2020-11738", "HIGH",     "Unauthenticated arbitrary file read"),
    "wp-db-backup":          ("CVE-2014-9734",  "HIGH",     "Arbitrary file download"),
    "login-lockdown":        ("CVE-2023-4827",  "HIGH",     "SQL injection"),
    "mailchimp-for-wp":      ("CVE-2021-24612", "MEDIUM",   "CSRF + stored XSS"),
}

# ─── THÈMES VULNÉRABLES ──────────────────────────────────────

_VULN_THEMES = {
    "twentytwentythree": ("", "LOW",    "Unpatched XSS on older installs"),
    "divi":              ("CVE-2023-2996","HIGH",  "XSS via customizer"),
    "avada":             ("CVE-2021-24888","HIGH", "CSRF in theme options"),
    "enfold":            ("CVE-2022-1654","MEDIUM","Reflected XSS in search"),
    "newspaper":         ("CVE-2022-0952","HIGH",  "Priv escalation"),
}

# ─── FICHIERS SENSIBLES ──────────────────────────────────────

_SENSITIVE_FILES = [
    ("/wp-config.php",              "WP config (DB creds)",  "CRITICAL"),
    ("/wp-config.php.bak",          "WP config backup",      "CRITICAL"),
    ("/wp-config.php~",             "WP config swap file",   "CRITICAL"),
    ("/wp-config-sample.php",       "Sample config present", "LOW"),
    ("/wp-content/debug.log",       "Debug log exposed",     "HIGH"),
    ("/.htaccess",                  "htaccess exposed",      "MEDIUM"),
    ("/.env",                       ".env exposed",          "CRITICAL"),
    ("/readme.html",                "Readme leaks version",  "LOW"),
    ("/license.txt",                "License leaks version", "LOW"),
    ("/wp-admin/install.php",       "Install script open",   "HIGH"),
    ("/wp-admin/upgrade.php",       "Upgrade script open",   "MEDIUM"),
    ("/wp-cron.php",                "WP-Cron accessible",    "MEDIUM"),
    ("/xmlrpc.php",                 "XML-RPC enabled",       "HIGH"),
    ("/wp-content/uploads/",        "Uploads dir browsable", "MEDIUM"),
    ("/wp-content/backup/",         "Backup dir exposed",    "HIGH"),
    ("/wp-content/backups/",        "Backup dir exposed",    "HIGH"),
    ("/wp-json/wp/v2/users",        "User REST API open",    "HIGH"),
    ("/wp-json/",                   "REST API exposed",      "MEDIUM"),
    ("/wp-includes/wlwmanifest.xml","WLW manifest leak",     "LOW"),
    ("/feed/",                      "RSS feed (version leak)","LOW"),
    ("/sitemap.xml",                "Sitemap exposed",       "INFO"),
    ("/robots.txt",                 "Robots.txt (info leak)","INFO"),
    ("/wp-login.php",               "Login page exposed",    "INFO"),
    ("/wp-content/mu-plugins/",     "Must-use plugins dir",  "MEDIUM"),
    ("/wp-content/uploads/wpforms/","WPForms uploads",       "MEDIUM"),
]

# ─── HEADERS DE SÉCURITÉ ─────────────────────────────────────

_SECURITY_HEADERS = [
    ("X-Frame-Options",                  "Clickjacking protection"),
    ("Content-Security-Policy",          "XSS / injection policy"),
    ("X-Content-Type-Options",           "MIME sniffing protection"),
    ("Strict-Transport-Security",        "HTTPS enforcement"),
    ("Referrer-Policy",                  "Referrer information leakage"),
    ("Permissions-Policy",               "Browser features restriction"),
]

# ─── HELPERS ─────────────────────────────────────────────────

def _get(url, allow_redirect=True):
    try:
        return _req.get(url, verify=False, timeout=_TIMEOUT,
                        allow_redirects=allow_redirect, proxies=_px(),
                        headers={"User-Agent": _UA})
    except Exception:
        return None


def _post(url, data):
    try:
        return _req.post(url, data=data, verify=False, timeout=_TIMEOUT,
                         allow_redirects=True, proxies=_px(),
                         headers={"User-Agent": _UA,
                                  "Content-Type": "application/xml"})
    except Exception:
        return None


def _base(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


# ─── DÉTECTION DE VERSION ─────────────────────────────────────

def _detect_version(base):
    version = None
    sources = []

    r = _get(f"{base}/readme.html")
    if r and r.status_code == 200:
        m = re.search(r"(?:Version|version)\s*:?\s*([0-9]+\.[0-9]+\.?[0-9]*)", r.text)
        if m:
            version = m.group(1); sources.append("readme.html")

    if not version:
        r = _get(base)
        if r:
            m = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', r.text)
            if m:
                version = m.group(1); sources.append("meta generator")

    if not version:
        r = _get(f"{base}/feed/")
        if r and r.status_code == 200:
            m = re.search(r"<generator>https://wordpress\.org/\?v=([0-9.]+)</generator>", r.text)
            if m:
                version = m.group(1); sources.append("RSS feed")

    if not version:
        r = _get(f"{base}/wp-includes/css/buttons.min.css")
        if r and r.status_code == 200:
            m = re.search(r"\?ver=([0-9.]+)", r.url or "")
            if m:
                version = m.group(1); sources.append("static asset ver=")

    return version, sources


# ─── CVE LOOKUP ──────────────────────────────────────────────

def _version_cves(version):
    if not version:
        return []
    cves = []
    for ver_prefix, vuln_list in _WP_CVES.items():
        if version.startswith(ver_prefix):
            cves.extend(vuln_list)
    return cves


# ─── ENUM PLUGINS ────────────────────────────────────────────

def _enum_plugins(base):
    found = []
    console.print(f"  [{DM}]Checking {len(_VULN_PLUGINS)} known vulnerable plugins...[/]")
    for slug, (cve, severity, desc) in _VULN_PLUGINS.items():
        url = f"{base}/wp-content/plugins/{slug}/"
        r = _get(url)
        if r and r.status_code in (200, 403):
            find(f"Plugin [{G1}]{slug}[/] found — [{RD}]{severity}[/] {desc}  [{CY}]{cve}[/]")
            found.append({"slug": slug, "cve": cve, "severity": severity, "desc": desc,
                          "url": url})
        else:
            # Check readme.txt for version
            r2 = _get(f"{base}/wp-content/plugins/{slug}/readme.txt")
            if r2 and r2.status_code == 200:
                m = re.search(r"Stable tag:\s*([0-9.]+)", r2.text)
                ver = m.group(1) if m else "?"
                find(f"Plugin [{G1}]{slug}[/] v{ver} — [{RD}]{severity}[/] {desc}  [{CY}]{cve}[/]")
                found.append({"slug": slug, "cve": cve, "severity": severity,
                              "desc": f"{desc} (v{ver})", "url": url})
    return found


# ─── ENUM THÈMES ─────────────────────────────────────────────

def _enum_themes(base):
    found = []
    for slug, (cve, severity, desc) in _VULN_THEMES.items():
        r = _get(f"{base}/wp-content/themes/{slug}/style.css")
        if r and r.status_code == 200:
            m = re.search(r"Version:\s*([0-9.]+)", r.text)
            ver = m.group(1) if m else "?"
            find(f"Theme [{G1}]{slug}[/] v{ver} — [{OR}]{severity}[/] {desc}")
            found.append({"slug": slug, "cve": cve, "severity": severity,
                          "desc": desc, "ver": ver})
    return found


# ─── USER ENUM ───────────────────────────────────────────────

def _enum_users(base):
    users = []

    # Via REST API
    r = _get(f"{base}/wp-json/wp/v2/users")
    if r and r.status_code == 200:
        try:
            data = r.json()
            for u in (data if isinstance(data, list) else []):
                name = u.get("name", "?")
                slug = u.get("slug", "?")
                find(f"User [{G1}]{name}[/] (slug: {slug}) — via REST API")
                users.append({"name": name, "slug": slug, "method": "REST API"})
        except Exception:
            pass

    # Via author redirect (?author=N)
    if not users:
        for i in range(1, 6):
            r = _get(f"{base}/?author={i}", allow_redirect=False)
            if r and r.status_code in (301, 302):
                loc = r.headers.get("Location", "")
                m = re.search(r"/author/([^/]+)/", loc)
                if m:
                    find(f"User [{G1}]{m.group(1)}[/] — via author redirect ?author={i}")
                    users.append({"name": m.group(1), "id": i, "method": "author enum"})

    return users


# ─── XML-RPC ─────────────────────────────────────────────────

def _test_xmlrpc(base):
    findings = []
    r = _get(f"{base}/xmlrpc.php")
    if not r or r.status_code not in (200, 405):
        return findings

    find(f"XML-RPC accessible — [{RD}]brute force amplification possible[/]")
    findings.append({"type": "xmlrpc-enabled", "severity": "HIGH",
                     "evidence": f"HTTP {r.status_code}"})

    # Test system.listMethods
    xml = """<?xml version="1.0" encoding="utf-8"?>
<methodCall><methodName>system.listMethods</methodName><params/></methodCall>"""
    r2 = _post(f"{base}/xmlrpc.php", xml)
    if r2 and "wp.getUsersBlogs" in (r2.text or ""):
        find(f"XML-RPC listMethods OK — [{RD}]wp.getUsersBlogs available (brute amp)[/]")
        findings.append({"type": "xmlrpc-listmethods", "severity": "HIGH",
                         "evidence": "wp.getUsersBlogs"})

    return findings


# ─── FICHIERS SENSIBLES ──────────────────────────────────────

def _check_sensitive(base):
    findings = []
    for path, desc, severity in _SENSITIVE_FILES:
        url = base + path
        r = _get(url)
        if not r:
            continue
        if r.status_code == 200:
            # Filter false positives for wp-config.php (should redirect/403)
            if "wp-config.php" in path and len(r.text) < 100:
                continue
            sev_c = RD if severity == "CRITICAL" else (OR if severity == "HIGH" else CY)
            find(f"[{sev_c}]{severity}[/] [{G1}]{path}[/] — {desc}")
            findings.append({"path": path, "desc": desc, "severity": severity,
                             "url": url, "status": r.status_code})
        elif r.status_code == 403 and severity == "CRITICAL":
            info(f"  [{DM}]{path} → 403 (exists but blocked)[/]")
            findings.append({"path": path, "desc": f"{desc} (403 — exists)", "severity": "MEDIUM",
                             "url": url, "status": 403})
    return findings


# ─── HEADERS DE SÉCURITÉ ─────────────────────────────────────

def _check_headers(base):
    missing = []
    r = _get(base)
    if not r:
        return missing
    hdrs = {k.lower(): v for k, v in r.headers.items()}
    for hdr, desc in _SECURITY_HEADERS:
        if hdr.lower() not in hdrs:
            warn(f"  Missing header: [{OR}]{hdr}[/]  [{DM}]{desc}[/]")
            missing.append({"header": hdr, "desc": desc})
    return missing


# ─── WP-CRON ABUSE ───────────────────────────────────────────

def _check_wpcron(base):
    r = _get(f"{base}/wp-cron.php")
    if r and r.status_code == 200:
        find(f"WP-Cron public — [{OR}]DoS amplification possible[/]")
        return [{"type": "wpcron-public", "severity": "MEDIUM",
                 "evidence": "wp-cron.php returns 200"}]
    return []


# ─── DIRECTORY LISTING ───────────────────────────────────────

def _check_dirlist(base):
    findings = []
    dirs = ["/wp-content/uploads/", "/wp-content/plugins/", "/wp-content/themes/"]
    for d in dirs:
        r = _get(base + d)
        if r and r.status_code == 200 and ("index of" in r.text.lower() or
                                             "<title>Index of" in r.text):
            find(f"Directory listing [{RD}]ENABLED[/] — [{G1}]{d}[/]")
            findings.append({"type": "directory-listing", "path": d, "severity": "MEDIUM"})
    return findings


# ─── SAVE ────────────────────────────────────────────────────

def _save(target, results):
    os.makedirs("data", exist_ok=True)
    slug = re.sub(r"[^a-zA-Z0-9_-]", "_", target)[:40]
    fname = f"data/wpscan_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "results": results,
                   "timestamp": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{fname}[/]")


# ─── MAIN ────────────────────────────────────────────────────

def run():
    show_module_banner("wpscan")
    cat_talk(CAT_SCAN, "WordPress Vulnerability Scanner — version, plugins, users, XMLRPC, fichiers", RD)
    console.print()
    warn("AUTHORIZED USE ONLY — Unauthorized testing is illegal.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    if not HAS_REQUESTS:
        err("requests library not available. Run: pip install requests"); return

    url = Prompt.ask(f"  [{G1}]◈ Target WordPress URL[/]").strip()
    if not url.startswith("http"):
        url = "https://" + url
    base = _base(url)

    console.print(f"\n  [{G1}][1][/] Full scan  [{DM}](tout)[/]")
    console.print(f"  [{G1}][2][/] Version + CVEs uniquement")
    console.print(f"  [{G1}][3][/] Plugins + thèmes vulnérables")
    console.print(f"  [{G1}][4][/] User enumeration")
    console.print(f"  [{G1}][5][/] Fichiers sensibles + headers")
    mode = ask_choice("Mode", "1")

    info(f"Target: [{CY}]{base}[/]")
    console.print()

    all_results = {"target": base, "version": None, "cves": [],
                   "plugins": [], "themes": [], "users": [],
                   "sensitive": [], "xmlrpc": [], "headers": [],
                   "wpcron": [], "dirlist": []}

    # ── Version + CVEs ──
    if mode in ("1", "2"):
        console.print(Rule(f"[{G1}] VERSION DETECTION", style=G2))
        version, sources = _detect_version(base)
        if version:
            find(f"WordPress version [{G1}]{version}[/]  [{DM}]via: {', '.join(sources)}[/]")
            all_results["version"] = version
            cves = _version_cves(version)
            all_results["cves"] = cves
            if cves:
                for cve_id, sev, desc in cves:
                    sev_c = RD if sev == "CRITICAL" else (OR if sev == "HIGH" else CY)
                    find(f"  [{sev_c}]{sev}[/] [{CY}]{cve_id}[/] — {desc}")
            else:
                ok(f"  No known CVEs for version {version} in database")
        else:
            warn("WordPress version not detected (may be hidden)")

    # ── Plugins ──
    if mode in ("1", "3"):
        console.print(Rule(f"[{G1}] PLUGIN SCAN", style=G2))
        plugins = _enum_plugins(base)
        all_results["plugins"] = plugins
        if not plugins: info(f"  [{DM}]No known vulnerable plugins found[/]")

        # ── Thèmes ──
        console.print(Rule(f"[{G1}] THEME SCAN", style=G2))
        themes = _enum_themes(base)
        all_results["themes"] = themes
        if not themes: info(f"  [{DM}]No known vulnerable themes found[/]")

    # ── Users ──
    if mode in ("1", "4"):
        console.print(Rule(f"[{G1}] USER ENUMERATION", style=G2))
        users = _enum_users(base)
        all_results["users"] = users
        if not users: info(f"  [{DM}]No users enumerated[/]")

    # ── Fichiers sensibles + XMLRPC + Cron + DirList + Headers ──
    if mode in ("1", "5"):
        console.print(Rule(f"[{G1}] SENSITIVE FILES", style=G2))
        sens = _check_sensitive(base)
        all_results["sensitive"] = sens
        if not sens: info(f"  [{DM}]No sensitive files found[/]")

        console.print(Rule(f"[{G1}] XML-RPC", style=G2))
        xmlrpc = _test_xmlrpc(base)
        all_results["xmlrpc"] = xmlrpc
        if not xmlrpc: info(f"  [{DM}]XML-RPC not accessible[/]")

        console.print(Rule(f"[{G1}] WP-CRON + DIRECTORY LISTING", style=G2))
        all_results["wpcron"] = _check_wpcron(base)
        all_results["dirlist"] = _check_dirlist(base)

        console.print(Rule(f"[{G1}] SECURITY HEADERS", style=G2))
        all_results["headers"] = _check_headers(base)
        if not all_results["headers"]: ok("  All security headers present")

    # ── Résumé ──
    console.print()
    total_vulns = (len(all_results["cves"]) + len(all_results["plugins"]) +
                   len(all_results["themes"]) + len(all_results["xmlrpc"]) +
                   len([s for s in all_results["sensitive"]
                        if s.get("severity") in ("CRITICAL", "HIGH")]))

    if total_vulns > 0:
        cat_talk(CAT_FOUND, f"{total_vulns} high-impact WordPress finding(s)!", G1)

    t = Table(title=f"[{G1}]WPScan Summary — {base}[/]",
              box=box.MINIMAL_DOUBLE_HEAD, border_style=G2, header_style=CY)
    t.add_column("Category",  min_width=20)
    t.add_column("Count",     min_width=8)
    t.add_column("Status",    min_width=16)

    def _stat(n, warn_n=1):
        return (f"[{RD}]{n} found[/]" if n >= warn_n else f"[{G2}]clean[/]")

    t.add_row("WP Version",      all_results["version"] or "?",
              f"[{CY}]{len(all_results['cves'])} CVEs[/]" if all_results["version"] else "unknown")
    t.add_row("Vulnerable plugins",   str(len(all_results["plugins"])),  _stat(len(all_results["plugins"])))
    t.add_row("Vulnerable themes",    str(len(all_results["themes"])),   _stat(len(all_results["themes"])))
    t.add_row("Users enumerated",     str(len(all_results["users"])),    _stat(len(all_results["users"])))
    t.add_row("Sensitive files",      str(len(all_results["sensitive"])),_stat(len(all_results["sensitive"])))
    t.add_row("XML-RPC issues",       str(len(all_results["xmlrpc"])),   _stat(len(all_results["xmlrpc"])))
    t.add_row("Missing sec headers",  str(len(all_results["headers"])),  _stat(len(all_results["headers"])))
    console.print(t)

    _save(base, all_results)
