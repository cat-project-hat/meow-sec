# -*- coding: utf-8 -*-
"""
MEOW-SEC :: TAKEOVER — Subdomain Takeover Checker
For authorized security testing and CTF challenges only.
"""
import os, re, json, socket, concurrent.futures, threading
from datetime import datetime

from core.ui import (console, ok, err, info, warn, find, boot_progress,
                     print_result_table, show_module_banner, ask_target,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_RECON, cat_talk
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn, TimeElapsedColumn

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

# ─── FINGERPRINTS ─────────────────────────────────────────────
# (service, cname_pattern, body_fingerprint, severity)
FINGERPRINTS = [
    ("GitHub Pages",     "github.io",          "There isn't a GitHub Pages site here",                "HIGH"),
    ("Heroku",           "herokudns.com",       "No such app",                                         "HIGH"),
    ("Heroku",           ".herokuapp.com",      "No such app",                                         "HIGH"),
    ("Amazon S3",        ".s3.amazonaws.com",   "NoSuchBucket",                                        "HIGH"),
    ("Amazon CloudFront","cloudfront.net",      "Bad Request",                                         "MEDIUM"),
    ("Zendesk",          ".zendesk.com",        "Help Center Closed",                                  "HIGH"),
    ("Shopify",          "myshopify.com",       "Sorry, this shop is currently unavailable",           "HIGH"),
    ("Shopify",          "shops.myshopify.com", "Sorry, this shop is currently unavailable",           "HIGH"),
    ("Fastly",           ".fastly.net",         "Fastly error: unknown domain",                        "HIGH"),
    ("Pantheon",         "pantheonsite.io",     "The gods are wise",                                   "MEDIUM"),
    ("Unbounce",         "unbouncepages.com",   "The requested URL was not found",                     "HIGH"),
    ("HubSpot",          "hubspot.net",         "Domain not configured",                               "HIGH"),
    ("Bitbucket",        "bitbucket.io",        "Repository not found",                                "HIGH"),
    ("Ghost",            "ghost.io",            "The thing you were looking for is no longer here",    "HIGH"),
    ("Netlify",          ".netlify.app",        "Not Found",                                           "MEDIUM"),
    ("Netlify",          "netlify.com",         "Not Found",                                           "MEDIUM"),
    ("Vercel",           "vercel.app",          "The deployment could not be found",                   "HIGH"),
    ("Surge",            "surge.sh",            "project not found",                                   "HIGH"),
    ("Statuspage",       "statuspage.io",       "You are being",                                       "MEDIUM"),
    ("Tumblr",           ".tumblr.com",         "There's nothing here",                                "HIGH"),
    ("WordPress.com",    "wordpress.com",       "Do you want to register",                             "MEDIUM"),
    ("Readme",           "readme.io",           "Project doesnt exist",                                "HIGH"),
    ("Acquia",           "acquia-test.site",    "Web Site Not Configured",                             "MEDIUM"),
    ("Azure",            "azurewebsites.net",   "Error 404 - Web app not found",                       "HIGH"),
    ("Azure",            "cloudapp.net",        "Error 404 - Web app not found",                       "MEDIUM"),
    ("Cargo",            "cargocollective.com", "404 Not Found",                                       "MEDIUM"),
    ("UserVoice",        "uservoice.com",       "This UserVoice subdomain is currently available",     "HIGH"),
    ("Fly.io",           ".fly.dev",            "404 Not Found",                                       "MEDIUM"),
]

def _get_cname(subdomain: str) -> str:
    try:
        return socket.getfqdn(subdomain)
    except Exception:
        return ""

def _fetch(url: str, timeout: int = 8) -> tuple:
    """Returns (status_code, body_text)"""
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         allow_redirects=True, proxies=_px(),
                         headers={"User-Agent": "MEOW-TAKEOVER/1.1 (authorized-test)"})
        return r.status_code, r.text[:4000]
    except requests.exceptions.ConnectionError:
        return 0, "NXDOMAIN"
    except Exception:
        return 0, ""

def _check_subdomain(subdomain: str) -> dict:
    cname = _get_cname(subdomain)
    status, body = _fetch(f"https://{subdomain}")
    if status == 0:
        status, body = _fetch(f"http://{subdomain}")

    result = {
        "subdomain": subdomain,
        "cname":     cname if cname != subdomain else "—",
        "status":    status,
        "vuln":      False,
        "service":   "",
        "sev":       "INFO",
        "note":      "",
    }

    for service, cname_pat, body_fp, sev in FINGERPRINTS:
        cname_match = cname_pat in cname.lower() if cname else False
        body_match  = body_fp.lower() in body.lower() if body else False

        if cname_match and body_match:
            result.update({"vuln": True, "service": service, "sev": sev,
                           "note": f"CNAME → {cname_pat}  +  body fingerprint matched"})
            return result
        elif cname_match and status in (0, 404):
            result.update({"vuln": True, "service": service, "sev": "MEDIUM",
                           "note": f"CNAME → {cname_pat}  (no response — possibly unclaimed)"})
            return result

    if body == "NXDOMAIN":
        result["note"] = "NXDOMAIN — dangling DNS"
        result["sev"]  = "LOW"

    return result

def _get_subdomains_crtsh(domain: str) -> list:
    info("Fetching subdomains from crt.sh...")
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json",
                         timeout=15, verify=False,
                         headers={"User-Agent": "MEOW-TAKEOVER/1.1"})
        if r.status_code == 200:
            data = r.json()
            subs = set()
            for e in data:
                for name in e.get("name_value","").split("\n"):
                    name = name.strip().lstrip("*.")
                    if domain in name:
                        subs.add(name)
            return sorted(subs)
    except Exception as e:
        warn(f"crt.sh error: {e}")
    return []

# ─── MAIN ─────────────────────────────────────────────────────
def run(target: str = None):
    show_module_banner("takeover")
    cat_talk(CAT_RECON, "TAKEOVER scanner — hunting for dangling DNS and unclaimed services...", OR)
    console.print()

    if not target:
        target = ask_target("Target domain (example.com)")
    if not target:
        err("No target."); return

    target = re.sub(r"https?://", "", target).split("/")[0].strip().lstrip("*.")
    info(f"Domain: [{CY}]{target}[/]")
    console.print()

    console.print(f"  [{G1}][1][/] Fetch subdomains from crt.sh then check")
    console.print(f"  [{G1}][2][/] Check a custom list (enter manually)")
    mode = ask_choice("Mode", "1")

    subdomains = []
    if mode == "1":
        subdomains = _get_subdomains_crtsh(target)
        if not subdomains:
            warn("No subdomains found in crt.sh."); return
        info(f"Found [{CY}]{len(subdomains)}[/] subdomains to check")
    else:
        from rich.prompt import Prompt
        raw = Prompt.ask(f"  [{CY}]Subdomains (comma-separated)[/]").strip()
        subdomains = [s.strip() for s in raw.split(",") if s.strip()]

    if not subdomains:
        err("No subdomains to check."); return

    warn("Use ONLY on authorized targets.")
    boot_progress(["Resolving CNAMEs...", "Fingerprinting services...", "Checking takeover signatures..."])
    console.print()

    findings = []
    lock = threading.Lock()

    def check(sub):
        res = _check_subdomain(sub)
        if res["vuln"]:
            with lock:
                findings.append(res)
                find(f"[{res['sev']}] [{CY}]{sub}[/]  →  [{G1}]{res['service']}[/]  {res['note']}")
        return res

    all_results = []
    total = len(subdomains)
    with Progress(SpinnerColumn(style=G1), TextColumn(f"[{G1}]Checking"),
                  BarColumn(bar_width=36, style=G2, complete_style=G1),
                  MofNCompleteColumn(), TimeElapsedColumn(), console=console) as p:
        task = p.add_task("", total=total)
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
            futures = {pool.submit(check, s): s for s in subdomains}
            for fut in concurrent.futures.as_completed(futures):
                p.advance(task)
                all_results.append(fut.result())

    console.print()
    vuln_results = [r for r in all_results if r["vuln"]]

    if vuln_results:
        rows = [(r["subdomain"], r["service"], r["sev"], r["cname"][:30], r["note"][:50])
                for r in vuln_results]
        print_result_table("Potential Takeover Targets",
                           ["SUBDOMAIN", "SERVICE", "SEV", "CNAME", "NOTE"],
                           rows, color_col=2)
    else:
        ok("No subdomain takeover vulnerabilities detected.")

    _save(target, vuln_results)

def _save(target, findings):
    out = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out, exist_ok=True)
    fname = os.path.join(out, f"takeover_{target.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"domain": target, "findings": findings, "time": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
