# -*- coding: utf-8 -*-
"""
MEOW-SEC :: HARVEST — Email Harvester
For authorized security testing and CTF challenges only.
"""
import os, re, json
from datetime import datetime
from urllib.parse import urlparse, quote

from core.ui import (console, ok, err, info, warn, find, boot_progress,
                     print_result_table, show_module_banner, ask_target,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_RECON, cat_talk

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

def _req(url: str, timeout: int = 10):
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         allow_redirects=True, proxies=_px(),
                         headers={"User-Agent": "Mozilla/5.0 (MEOW-HARVEST/1.1)"})
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return ""

def _extract_emails(text: str) -> set:
    return set(EMAIL_RE.findall(text))

# ─── SOURCE: crt.sh ───────────────────────────────────────────
def _from_crtsh(domain: str) -> set:
    info("Querying crt.sh...")
    text = _req(f"https://crt.sh/?q=%25{domain}&output=json")
    emails = _extract_emails(text)
    # Also extract from cert subjects
    try:
        import json as _json
        data = _json.loads(text)
        for entry in data[:100]:
            subj = entry.get("name_value", "") + entry.get("issuer_name", "")
            emails |= _extract_emails(subj)
    except Exception:
        pass
    if emails:
        ok(f"crt.sh → [{G1}]{len(emails)}[/] emails")
    return emails

# ─── SOURCE: Hunter.io (no key, limited) ──────────────────────
def _from_hunter(domain: str) -> set:
    info("Querying Hunter.io (no key)...")
    text = _req(f"https://hunter.io/search/{domain}")
    return _extract_emails(text)

# ─── SOURCE: GitHub search ────────────────────────────────────
def _from_github(domain: str) -> set:
    info("Querying GitHub search...")
    emails = set()
    for q in [f'"{domain}" email', f'site:{domain}']:
        text = _req(f"https://github.com/search?q={quote(q)}&type=code")
        emails |= _extract_emails(text)
    if emails:
        ok(f"GitHub → [{G1}]{len(emails)}[/] emails")
    return emails

# ─── SOURCE: Common pattern generation ────────────────────────
def _generate_patterns(domain: str, names: list) -> set:
    """Génère des patterns d'emails courants pour une liste de noms"""
    generated = set()
    for name in names:
        parts = name.lower().split()
        if len(parts) < 2:
            continue
        fn, ln = parts[0], parts[-1]
        fi = fn[0]
        li = ln[0]
        patterns = [
            f"{fn}@{domain}", f"{ln}@{domain}",
            f"{fn}.{ln}@{domain}", f"{ln}.{fn}@{domain}",
            f"{fi}{ln}@{domain}", f"{fn}{li}@{domain}",
            f"{fi}.{ln}@{domain}", f"{fn}_{ln}@{domain}",
        ]
        generated.update(patterns)
    return generated

# ─── SOURCE: Web scrape target domain ─────────────────────────
def _scrape_site(domain: str) -> set:
    info(f"Scraping https://{domain}...")
    emails = set()
    pages  = [f"https://{domain}", f"https://{domain}/contact",
              f"https://{domain}/about", f"https://{domain}/team",
              f"https://www.{domain}", f"https://{domain}/contact-us"]
    for url in pages:
        text = _req(url)
        found = _extract_emails(text)
        # Filter out common false positives
        found = {e for e in found if not e.endswith((".png", ".jpg", ".gif", ".css", ".js"))}
        emails |= found
    if emails:
        ok(f"Direct scrape → [{G1}]{len(emails)}[/] emails")
    return emails

# ─── SOURCE: Archive.org ──────────────────────────────────────
def _from_archive(domain: str) -> set:
    info("Querying Wayback Machine CDX API...")
    emails = set()
    text = _req(f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original&limit=200&filter=statuscode:200")
    emails |= _extract_emails(text)
    if emails:
        ok(f"Archive.org → [{G1}]{len(emails)}[/] emails")
    return emails

# ─── MAIN ─────────────────────────────────────────────────────
def run(target: str = None):
    show_module_banner("harvest")
    cat_talk(CAT_RECON, "HARVEST mode — collecting email addresses from public sources...", CY)
    console.print()

    if not target:
        target = ask_target("Target domain (example.com)")
    if not target:
        err("No target."); return

    # Normalize domain
    target = re.sub(r"https?://", "", target).split("/")[0].strip()
    if target.startswith("www."):
        target = target[4:]

    info(f"Domain: [{CY}]{target}[/]")
    console.print()

    console.print(f"  [{G1}][1][/] Site scrape only")
    console.print(f"  [{G1}][2][/] OSINT sources (crt.sh + Archive.org + GitHub)")
    console.print(f"  [{G1}][3][/] Full harvest (all sources)")
    console.print(f"  [{G1}][4][/] Pattern generator (enter names manually)")
    mode = ask_choice("Mode", "3")

    boot_progress(["Preparing harvest...", "Connecting to sources...", "Extracting emails..."])
    console.print()

    all_emails = set()

    if mode in ("1", "3"):
        all_emails |= _scrape_site(target)

    if mode in ("2", "3"):
        all_emails |= _from_crtsh(target)
        all_emails |= _from_archive(target)
        all_emails |= _from_github(target)

    if mode == "4":
        from rich.prompt import Prompt
        raw = Prompt.ask(f"  [{CY}]Enter full names separated by commas[/]").strip()
        names = [n.strip() for n in raw.split(",") if n.strip()]
        gen = _generate_patterns(target, names)
        if gen:
            find(f"Generated [{G1}]{len(gen)}[/] email patterns")
            all_emails |= gen

    # Filter to domain only
    domain_emails = {e for e in all_emails if target in e}
    other_emails  = all_emails - domain_emails

    console.print()
    if all_emails:
        rows = sorted([(e, "ON-DOMAIN" if target in e else "other") for e in all_emails],
                      key=lambda x: (x[1] != "ON-DOMAIN", x[0]))
        print_result_table("Harvested Emails",
                           ["EMAIL", "TYPE"],
                           rows[:200])
        find(f"Total: [{G1}]{len(all_emails)}[/] emails  (on-domain: {len(domain_emails)})")
    else:
        warn("No emails found.")

    _save(target, list(all_emails))

def _save(target, emails):
    out = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out, exist_ok=True)
    fname = os.path.join(out, f"harvest_{target.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"domain": target, "emails": emails, "count": len(emails),
                   "time": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
