# -*- coding: utf-8 -*-
"""
MEOW-SEC :: BUCKET — Cloud Storage Bucket Finder
For authorized security testing and CTF challenges only.
"""
import os, re, json, concurrent.futures, threading
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

# ─── BUCKET NAME PATTERNS ─────────────────────────────────────
def _gen_names(base: str) -> list:
    suffixes = [
        "", "-backup", "-bak", "-dev", "-staging", "-prod", "-test",
        "-static", "-assets", "-media", "-files", "-data", "-logs",
        "-public", "-private", "-internal", "-web", "-app", "-cdn",
        "-uploads", "-downloads", "-releases", "-builds", "-artifacts",
        ".backup", ".dev", ".staging", "-2024", "-2025", "-2026",
    ]
    prefixes = ["", "dev-", "prod-", "staging-", "test-", "backup-", "cdn-", "static-", "media-"]

    names = set()
    for suf in suffixes:
        names.add(f"{base}{suf}")
    for pre in prefixes:
        names.add(f"{pre}{base}")
    # Also try domain parts
    parts = base.split(".")
    if len(parts) > 1:
        for p in parts:
            if len(p) > 2:
                names.add(p)
                for suf in suffixes[:8]:
                    names.add(f"{p}{suf}")
    return sorted(names)

# ─── CLOUD PROVIDERS ──────────────────────────────────────────
def _check_s3(name: str) -> dict:
    urls = [
        f"https://{name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{name}",
    ]
    for url in urls:
        try:
            r = requests.get(url, timeout=6, verify=False,
                             headers={"User-Agent": "MEOW-BUCKET/1.1"},
                             allow_redirects=False)
            if r.status_code == 200 and "ListBucketResult" in r.text:
                return {"name": name, "provider": "AWS S3", "url": url,
                        "status": "PUBLIC_READ", "sev": "CRITICAL",
                        "note": "Bucket listing enabled"}
            elif r.status_code == 200:
                return {"name": name, "provider": "AWS S3", "url": url,
                        "status": "EXISTS_200", "sev": "HIGH",
                        "note": "Bucket exists and returns 200"}
            elif r.status_code == 403:
                return {"name": name, "provider": "AWS S3", "url": url,
                        "status": "EXISTS_403", "sev": "INFO",
                        "note": "Bucket exists but access denied"}
            elif r.status_code == 307:
                return {"name": name, "provider": "AWS S3", "url": url,
                        "status": "REDIRECT", "sev": "INFO",
                        "note": f"Redirect to {r.headers.get('Location','')}"}
        except Exception:
            pass
    return {}

def _check_gcs(name: str) -> dict:
    url = f"https://storage.googleapis.com/{name}"
    try:
        r = requests.get(url, timeout=6, verify=False,
                         headers={"User-Agent": "MEOW-BUCKET/1.1"},
                         allow_redirects=False)
        if r.status_code == 200 and "ListBucketResult" in r.text:
            return {"name": name, "provider": "GCS", "url": url,
                    "status": "PUBLIC_READ", "sev": "CRITICAL",
                    "note": "Bucket listing enabled"}
        elif r.status_code == 200:
            return {"name": name, "provider": "GCS", "url": url,
                    "status": "EXISTS_200", "sev": "HIGH",
                    "note": "Bucket accessible"}
        elif r.status_code == 403:
            return {"name": name, "provider": "GCS", "url": url,
                    "status": "EXISTS_403", "sev": "INFO",
                    "note": "Bucket exists, access denied"}
    except Exception:
        pass
    return {}

def _check_azure(name: str) -> dict:
    urls = [
        f"https://{name}.blob.core.windows.net",
        f"https://{name}.blob.core.windows.net/$web",
    ]
    for url in urls:
        try:
            r = requests.get(url, timeout=6, verify=False,
                             headers={"User-Agent": "MEOW-BUCKET/1.1"},
                             allow_redirects=False)
            if r.status_code in (200, 400, 409):
                note = "Container accessible" if r.status_code == 200 else "Account exists"
                sev  = "HIGH" if r.status_code == 200 else "INFO"
                return {"name": name, "provider": "Azure Blob", "url": url,
                        "status": str(r.status_code), "sev": sev, "note": note}
            elif r.status_code == 403:
                return {"name": name, "provider": "Azure Blob", "url": url,
                        "status": "EXISTS_403", "sev": "INFO",
                        "note": "Account exists, access denied"}
        except Exception:
            pass
    return {}

def _check_digitalocean(name: str) -> dict:
    # DO Spaces
    regions = ["nyc3", "sfo3", "ams3", "sgp1", "fra1"]
    for reg in regions[:2]:  # check first 2 regions for speed
        url = f"https://{name}.{reg}.digitaloceanspaces.com"
        try:
            r = requests.get(url, timeout=5, verify=False,
                             headers={"User-Agent": "MEOW-BUCKET/1.1"},
                             allow_redirects=False)
            if r.status_code in (200, 403):
                note = "Space public" if r.status_code == 200 else "Space exists, private"
                return {"name": name, "provider": f"DO Spaces ({reg})", "url": url,
                        "status": str(r.status_code), "sev": "HIGH" if r.status_code == 200 else "INFO",
                        "note": note}
        except Exception:
            pass
    return {}

CHECKERS = [_check_s3, _check_gcs, _check_azure, _check_digitalocean]

# ─── MAIN ─────────────────────────────────────────────────────
def run(target: str = None):
    show_module_banner("bucket")
    cat_talk(CAT_RECON, "BUCKET hunter activated — scanning cloud storage...", CY)
    console.print()

    if not target:
        target = ask_target("Target company name or domain (example.com / acmecorp)")
    if not target:
        err("No target."); return

    # Normalize
    base = re.sub(r"https?://", "", target).split("/")[0].strip()
    if base.endswith(".com") or base.endswith(".org") or base.endswith(".net"):
        base = base.rsplit(".", 1)[0]

    info(f"Base name: [{CY}]{base}[/]")
    console.print()

    console.print(f"  [{G1}][1][/] AWS S3 only")
    console.print(f"  [{G1}][2][/] All providers (S3 + GCS + Azure + DO)")
    console.print(f"  [{G1}][3][/] Quick scan (fewer name variants, all providers)")
    mode = ask_choice("Mode", "2")

    names = _gen_names(base)
    if mode == "3":
        names = names[:20]  # Quick scan

    info(f"Testing [{CY}]{len(names)}[/] bucket name variants...")
    warn("Use ONLY on authorized targets.")
    console.print()

    checkers = [_check_s3] if mode == "1" else CHECKERS

    findings = []
    lock = threading.Lock()

    def check_all(name):
        results = []
        for checker in checkers:
            res = checker(name)
            if res:
                results.append(res)
        return results

    total = len(names)
    with Progress(SpinnerColumn(style=G1), TextColumn(f"[{G1}]Scanning"),
                  BarColumn(bar_width=36, style=G2, complete_style=G1),
                  MofNCompleteColumn(), TimeElapsedColumn(), console=console) as p:
        task = p.add_task("", total=total)
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(check_all, n): n for n in names}
            for fut in concurrent.futures.as_completed(futures):
                p.advance(task)
                for res in fut.result():
                    if res:
                        with lock:
                            findings.append(res)
                            sev_color = RD if res["sev"] == "CRITICAL" else OR if res["sev"] == "HIGH" else CY
                            find(f"[{sev_color}]{res['sev']}[/]  [{res['provider']}]  [{CY}]{res['name']}[/]  {res['note']}")

    console.print()
    if findings:
        # Show only non-INFO first
        vuln = [f for f in findings if f["sev"] not in ("INFO",)]
        info_only = [f for f in findings if f["sev"] == "INFO"]
        show = vuln + info_only[:10]
        rows = [(f["name"], f["provider"], f["sev"], f["status"], f["note"][:45])
                for f in show]
        print_result_table("Cloud Buckets Found",
                           ["NAME", "PROVIDER", "SEV", "STATUS", "NOTE"],
                           rows, color_col=2)
    else:
        ok("No accessible cloud buckets found.")

    _save(base, findings)

def _save(base, findings):
    out = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out, exist_ok=True)
    fname = os.path.join(out, f"bucket_{base.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": base, "findings": findings, "time": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
