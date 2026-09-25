# -*- coding: utf-8 -*-
"""
MEOW-SEC :: HOSTHEADER — Host Header Injection Tester  (#68)
Password Reset Poisoning · VHost Discovery · Ambiguous Host · SSRF
For authorized security testing and CTF challenges only.
"""
import os, json, re
from datetime import datetime
from urllib.parse import urlparse

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

ATTACKER = "attacker.com"

_RESET_HOST_PAYLOADS = [
    ATTACKER,
    f"{ATTACKER}:80",
    f"target.com@{ATTACKER}",
    f"{ATTACKER}#target.com",
    f"{ATTACKER}\r\nX-Forwarded-Host: target.com",
]

_ALT_HEADERS = [
    ("X-Forwarded-Host",   ATTACKER),
    ("X-Forwarded-Server", ATTACKER),
    ("X-Host",             ATTACKER),
    ("X-Original-Host",    ATTACKER),
    ("X-Rewrite-URL",      "/reset?token=meow"),
    ("Forwarded",          f"host={ATTACKER}"),
]

_VHOST_PREFIXES = [
    "admin", "internal", "dev", "staging", "backend",
    "api", "management", "test", "mail", "vpn", "uat",
]

_AMBIGUOUS_TESTS = [
    ("double-host",        lambda host: {"Host": f"{host}\r\nHost: {ATTACKER}"}),
    ("space-separated",    lambda host: {"Host": f"{host} {ATTACKER}"}),
    ("port-at-attacker",   lambda host: {"Host": f"{host}:443@{ATTACKER}"}),
]

_SSRF_HOSTS = [
    "169.254.169.254",           # AWS / Azure metadata
    "metadata.google.internal",  # GCP
    "192.168.1.1",               # LAN gateway
    "localhost",
    "127.0.0.1",
]

UA = "MEOW-HOSTHEADER/1.0 (authorized-test)"


# ─── HELPERS ──────────────────────────────────────────────────

def _get(url, headers=None, timeout=8, method="GET", data=None):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    try:
        fn = requests.post if method == "POST" else requests.get
        r = fn(url, headers=h, data=data, timeout=timeout,
               verify=False, allow_redirects=False, proxies=_px())
        return r
    except Exception as e:
        return None


def _reflects_attacker(r) -> bool:
    if r is None:
        return False
    body = r.text.lower()
    hdrs = " ".join(v.lower() for v in r.headers.values())
    return ATTACKER in body or ATTACKER in hdrs


def _title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip()[:60] if m else ""


# ─── TEST 1 — PASSWORD RESET POISONING ────────────────────────

def _test_reset_poisoning(target: str) -> list:
    info("  [1/4] Password Reset Poisoning...")
    host = urlparse(target).netloc
    findings = []

    # Baseline — no evil header
    baseline = _get(target, method="POST", data={"email": "test@test.com"})
    base_len = len(baseline.content) if baseline else 0
    base_status = baseline.status_code if baseline else 0

    # Host header payloads
    for payload in _RESET_HOST_PAYLOADS:
        r = _get(target, headers={"Host": payload}, method="POST",
                 data={"email": "test@test.com"})
        if r is None:
            continue
        reflected = _reflects_attacker(r)
        size_diff = abs(len(r.content) - base_len) > 50
        if reflected or (r.status_code != base_status and r.status_code not in (0,)):
            sev = "HIGH" if reflected else "MEDIUM"
            note = "attacker.com reflected in response" if reflected else f"status changed {base_status}→{r.status_code}"
            findings.append({
                "vector": "Host-header",
                "payload": payload[:60],
                "status": r.status_code,
                "reflected": reflected,
                "sev": sev,
                "note": note,
            })
            find(f"[RESET POISON][{sev}] Host: [{CY}]{payload[:50]}[/] — {note}")

    # Alternative headers
    for hdr_name, hdr_val in _ALT_HEADERS:
        r = _get(target, headers={hdr_name: hdr_val}, method="POST",
                 data={"email": "test@test.com"})
        if r is None:
            continue
        reflected = _reflects_attacker(r)
        size_diff = abs(len(r.content) - base_len) > 50
        if reflected or size_diff:
            sev = "HIGH" if reflected else "LOW"
            note = "attacker.com reflected" if reflected else f"body size diff {abs(len(r.content)-base_len)}B"
            findings.append({
                "vector": hdr_name,
                "payload": hdr_val,
                "status": r.status_code,
                "reflected": reflected,
                "sev": sev,
                "note": note,
            })
            find(f"[ALT HEADER][{sev}] {hdr_name}: [{CY}]{hdr_val}[/] — {note}")

    if not findings:
        ok("    No password reset poisoning indicators.")
    return findings


# ─── TEST 2 — VIRTUAL HOST DISCOVERY ──────────────────────────

def _test_vhost_discovery(target: str) -> list:
    info("  [2/4] Virtual Host Discovery...")
    parsed = urlparse(target)
    base_host = parsed.netloc.split(":")[0]
    # strip www.
    domain = re.sub(r"^www\.", "", base_host)
    findings = []

    baseline = _get(target)
    base_len = len(baseline.content) if baseline else 0
    base_title = _title(baseline.text) if baseline else ""
    base_status = baseline.status_code if baseline else 0

    for prefix in _VHOST_PREFIXES:
        vhost = f"{prefix}.{domain}"
        r = _get(target, headers={"Host": vhost})
        if r is None:
            continue
        size_diff = abs(len(r.content) - base_len)
        title = _title(r.text)
        different = (
            r.status_code != base_status or
            size_diff > 200 or
            (title and title != base_title)
        )
        if different:
            sev = "MEDIUM"
            note = []
            if r.status_code != base_status:
                note.append(f"status {base_status}→{r.status_code}")
            if size_diff > 200:
                note.append(f"size diff {size_diff}B")
            if title and title != base_title:
                note.append(f"title: '{title}'")
            findings.append({
                "vector": "vhost",
                "payload": vhost,
                "status": r.status_code,
                "reflected": False,
                "sev": sev,
                "note": "; ".join(note),
            })
            find(f"[VHOST][{sev}] Host: [{CY}]{vhost}[/] — {'; '.join(note)}")

    if not findings:
        ok("    No virtual hosts detected.")
    return findings


# ─── TEST 3 — AMBIGUOUS HOST HEADER ───────────────────────────

def _test_ambiguous(target: str) -> list:
    info("  [3/4] Ambiguous Host Header...")
    parsed = urlparse(target)
    host = parsed.netloc
    findings = []

    for test_name, hdr_fn in _AMBIGUOUS_TESTS:
        extra = hdr_fn(host)
        r = _get(target, headers=extra)
        if r is None:
            continue
        reflected = _reflects_attacker(r)
        # also check Location header
        loc = r.headers.get("Location", "")
        loc_hit = ATTACKER in loc
        if reflected or loc_hit:
            sev = "HIGH"
            note = []
            if reflected:
                note.append("attacker.com in body/headers")
            if loc_hit:
                note.append(f"Location: {loc[:60]}")
            findings.append({
                "vector": f"ambiguous/{test_name}",
                "payload": str(extra)[:80],
                "status": r.status_code,
                "reflected": True,
                "sev": sev,
                "note": "; ".join(note),
            })
            find(f"[AMBIGUOUS][{sev}] {test_name} — {'; '.join(note)}")

    if not findings:
        ok("    No ambiguous Host header issues detected.")
    return findings


# ─── TEST 4 — HOST HEADER SSRF ────────────────────────────────

def _test_ssrf(target: str) -> list:
    info("  [4/4] Host Header SSRF...")
    findings = []

    baseline = _get(target)
    base_len = len(baseline.content) if baseline else 0
    base_status = baseline.status_code if baseline else 0

    for ssrf_host in _SSRF_HOSTS:
        r = _get(target, headers={"Host": ssrf_host})
        if r is None:
            continue
        size_diff = abs(len(r.content) - base_len)
        status_diff = r.status_code != base_status
        if status_diff or size_diff > 200:
            sev = "HIGH"
            note = []
            if status_diff:
                note.append(f"status changed {base_status}→{r.status_code}")
            if size_diff > 200:
                note.append(f"body diff {size_diff}B")
            findings.append({
                "vector": "ssrf-host",
                "payload": ssrf_host,
                "status": r.status_code,
                "reflected": False,
                "sev": sev,
                "note": "; ".join(note),
            })
            find(f"[SSRF][{sev}] Host: [{CY}]{ssrf_host}[/] — {'; '.join(note)}")

    if not findings:
        ok("    No Host-header SSRF indicators.")
    return findings


# ─── SAVE ─────────────────────────────────────────────────────

def _save(target: str, findings: list):
    os.makedirs("data", exist_ok=True)
    host = urlparse(target).netloc.replace(".", "_").replace(":", "_")
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"data/hostheader_{host}_{ts}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({
            "target": target,
            "findings": findings,
            "timestamp": datetime.now().isoformat(),
        }, f, indent=2)
    ok(f"Results saved → [{CY}]{fname}[/]")


# ─── MAIN ─────────────────────────────────────────────────────

def run(target: str = None):
    show_module_banner("hostheader")
    cat_talk(CAT_SCAN, "Host header injection tester active...", OR)
    console.print()

    if not HAS_REQUESTS:
        err("requests library not available. Install it: pip install requests")
        return

    if not target:
        target = ask_target("Target URL (https://example.com/reset-password)")
    if not target:
        err("No target."); return
    if not target.startswith("http"):
        target = "https://" + target

    info(f"Target: [{CY}]{target}[/]")
    console.print()

    console.print(f"  [{G1}][1][/] Password Reset Poisoning (Host + Alt headers)")
    console.print(f"  [{G1}][2][/] Virtual Host Discovery")
    console.print(f"  [{G1}][3][/] Ambiguous Host Header")
    console.print(f"  [{G1}][4][/] Host Header SSRF")
    console.print(f"  [{G1}][5][/] Full scan (all tests)")
    mode = ask_choice("Mode", "5")
    console.print()

    all_findings = []

    if mode in ("1", "5"):
        all_findings += _test_reset_poisoning(target)
        console.print()
    if mode in ("2", "5"):
        all_findings += _test_vhost_discovery(target)
        console.print()
    if mode in ("3", "5"):
        all_findings += _test_ambiguous(target)
        console.print()
    if mode in ("4", "5"):
        all_findings += _test_ssrf(target)
        console.print()

    # Summary table
    if all_findings:
        rows = [
            (f["vector"][:22], f["sev"], f["payload"][:38], str(f["status"]), f["note"][:42])
            for f in all_findings
        ]
        print_result_table(
            "Host Header Vulnerabilities",
            ["VECTOR", "SEV", "PAYLOAD", "STATUS", "NOTE"],
            rows,
            color_col=1,
        )
        _sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        worst = max(all_findings, key=lambda x: _sev_map.get(x["sev"], 0))
        warn(f"Highest severity: [{RD}]{worst['sev']}[/]")
    else:
        ok("No Host header vulnerabilities detected.")

    _save(target, all_findings)
