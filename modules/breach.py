# -*- coding: utf-8 -*-
"""MEOW-SEC :: BREACH — Data Breach Checker via Public APIs"""
import os, re, json, hashlib
from datetime import datetime

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN
from rich.panel  import Panel
from rich.table  import Table
from rich.prompt import Prompt, Confirm
from rich.rule   import Rule
from rich        import box

try:
    import requests as _req
    _req.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False


def _save(name, target, results):
    os.makedirs("data", exist_ok=True)
    fname = f"data/{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "results": results,
                   "timestamp": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved: [bold]{fname}[/]")


def _check_password_hibp(password: str) -> dict:
    """k-anonymity: send first 5 chars of SHA1 hash, check suffix in response. FREE."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = _req.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "MEOW-BREACH/1.1", "Add-Padding": "true"},
            timeout=10, verify=True
        )
        if r.status_code != 200:
            return {"found": False, "count": 0, "error": f"API status {r.status_code}"}
        # Format: HASHSUFFIX:COUNT\r\n
        for line in r.text.splitlines():
            parts = line.strip().split(":")
            if len(parts) == 2 and parts[0].upper() == suffix:
                count = int(parts[1])
                return {"found": True, "count": count, "error": ""}
        return {"found": False, "count": 0, "error": ""}
    except Exception as e:
        return {"found": False, "count": 0, "error": str(e)[:60]}


def _check_email_hibp(email: str, api_key: str) -> dict:
    """HIBP v3 email breach check — requires API key."""
    try:
        r = _req.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={
                "hibp-api-key": api_key,
                "User-Agent": "MEOW-BREACH/1.1",
            },
            params={"truncateResponse": "false"},
            timeout=10, verify=True
        )
        if r.status_code == 200:
            breaches = r.json()
            return {"found": True, "count": len(breaches), "breaches": breaches[:10], "error": ""}
        elif r.status_code == 404:
            return {"found": False, "count": 0, "breaches": [], "error": ""}
        elif r.status_code == 401:
            return {"found": False, "count": 0, "breaches": [], "error": "Invalid API key"}
        elif r.status_code == 429:
            return {"found": False, "count": 0, "breaches": [], "error": "Rate limited"}
        else:
            return {"found": False, "count": 0, "breaches": [],
                    "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"found": False, "count": 0, "breaches": [], "error": str(e)[:60]}


def _list_all_breaches() -> list:
    """List all known breaches from HIBP (free, no key)."""
    try:
        r = _req.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            headers={"User-Agent": "MEOW-BREACH/1.1"},
            timeout=15, verify=True
        )
        if r.status_code == 200:
            return r.json()
        return []
    except Exception:
        return []


def _check_email_leakcheck(email: str) -> dict:
    """LeakCheck.io public endpoint (limited free)."""
    try:
        r = _req.get(
            f"https://leakcheck.io/api/public",
            params={"check": email},
            headers={"User-Agent": "MEOW-BREACH/1.1"},
            timeout=10, verify=True
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("success"):
                found = data.get("found", 0) > 0
                return {"found": found, "count": data.get("found", 0),
                        "sources": data.get("sources", [])[:5], "error": ""}
        return {"found": False, "count": 0, "sources": [], "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"found": False, "count": 0, "sources": [], "error": str(e)[:60]}


def run():
    show_module_banner("breach")
    cat_talk(CAT_SCAN, "Data breach checker — HIBP & LeakCheck", CY)
    console.print()
    warn("AUTHORIZED USE ONLY — Check only addresses/passwords you own or have permission to check.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm I have permission to check these credentials[/]", default=False):
        info("Aborted."); return

    if not HAS_REQUESTS:
        err("requests library not available. Install it: pip install requests"); return

    console.print(f"\n  [{G1}][1][/] Password check (k-anonymity, FREE — no account needed)")
    console.print(f"  [{G1}][2][/] Email breach check (HIBP API key required)")
    console.print(f"  [{G1}][3][/] List all known breaches (free)")
    mode = Prompt.ask(f"  [{CY}]◈ Mode[/]", default="1").strip()

    results = []

    if mode == "1":
        password = Prompt.ask(f"  [{G1}]◈ Password to check[/]", password=True).strip()
        if not password:
            err("No password entered."); return
        info("Checking via k-anonymity (only first 5 chars of SHA1 hash sent)...")
        result = _check_password_hibp(password)
        if result["error"]:
            err(f"API error: {result['error']}")
        elif result["found"]:
            find(f"Password PWNED — seen [{RD}]{result['count']:,}[/] times in data breaches!")
            warn("This password should NOT be used. Change it immediately.")
        else:
            ok("Password NOT found in known breaches.")
        results.append({"type": "password", **result})

    elif mode == "2":
        email = Prompt.ask(f"  [{G1}]◈ Email address[/]").strip()
        api_key = Prompt.ask(f"  [{CY}]◈ HIBP API key (get from haveibeenpwned.com)[/]",
                             default="").strip()

        if api_key:
            info(f"Checking {email} via HIBP v3...")
            hibp_result = _check_email_hibp(email, api_key)
            if hibp_result["error"]:
                warn(f"HIBP: {hibp_result['error']}")
            elif hibp_result["found"]:
                find(f"HIBP: [{RD}]{hibp_result['count']}[/] breach(es) for {email}")
                for breach in hibp_result.get("breaches", []):
                    bname = breach.get("Name", "?")
                    bdate = breach.get("BreachDate", "?")
                    bdata = ", ".join(breach.get("DataClasses", [])[:4])
                    info(f"  Breach: [{OR}]{bname}[/] ({bdate}) — {bdata}")
            else:
                ok(f"HIBP: No breaches found for {email}")
            results.append({"type": "email_hibp", "email": email, **hibp_result})
        else:
            warn("No HIBP API key provided — skipping HIBP check")

        # LeakCheck free
        info(f"Checking {email} via LeakCheck.io (free)...")
        lc_result = _check_email_leakcheck(email)
        if lc_result["error"]:
            warn(f"LeakCheck: {lc_result['error']}")
        elif lc_result["found"]:
            find(f"LeakCheck: [{RD}]{lc_result['count']}[/] source(s) for {email}")
            for src in lc_result.get("sources", []):
                info(f"  Source: [{OR}]{src}[/]")
        else:
            ok(f"LeakCheck: No leaks found for {email}")
        results.append({"type": "email_leakcheck", "email": email, **lc_result})

    elif mode == "3":
        domain_filter = Prompt.ask(f"  [{CY}]◈ Filter by domain (optional, leave blank for all)[/]",
                                   default="").strip().lower()
        info("Fetching all HIBP breaches (this may take a moment)...")
        breaches = _list_all_breaches()
        if not breaches:
            err("Failed to fetch breach list."); return

        if domain_filter:
            breaches = [b for b in breaches
                        if domain_filter in b.get("Domain", "").lower()
                        or domain_filter in b.get("Name", "").lower()]

        console.print()
        t = Table(title=f"[{G1}]Breaches ({len(breaches)})[/]", box=box.MINIMAL_DOUBLE_HEAD,
                  border_style=G2, header_style=CY)
        t.add_column("Name",        min_width=20)
        t.add_column("Date",        min_width=12)
        t.add_column("Domain",      min_width=22)
        t.add_column("Accounts",    min_width=12)
        t.add_column("Data types",  min_width=30)

        for b in breaches[:50]:
            name   = b.get("Name", "?")
            date   = b.get("BreachDate", "?")
            domain = b.get("Domain", "?")
            count  = f"{b.get('PwnCount', 0):,}"
            dtypes = ", ".join(b.get("DataClasses", [])[:3])
            t.add_row(name, date, domain, count, dtypes)
        console.print(t)
        if len(breaches) > 50:
            info(f"Showing 50 of {len(breaches)} breaches. Use domain filter to narrow down.")
        results = [{"type": "all_breaches", "total": len(breaches)}]

    _save("breach", "breach_check", results)
