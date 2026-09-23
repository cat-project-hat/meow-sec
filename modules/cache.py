# -*- coding: utf-8 -*-
"""MEOW-SEC :: CACHE — Web Cache Poisoning / Deception Tester"""
import os, re, json
from datetime import datetime
from urllib.parse import urlparse

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


_POISON_TESTS = [
    ("X-Forwarded-Host",    {"X-Forwarded-Host":  "evil.com"}),
    ("X-Forwarded-Scheme",  {"X-Forwarded-Scheme":"nothttps"}),
    ("X-Original-URL",      {"X-Original-URL":    "/admin"}),
    ("X-Rewrite-URL",       {"X-Rewrite-URL":     "/admin"}),
    ("X-Override-URL",      {"X-Override-URL":    "/admin"}),
    ("X-Host",              {"X-Host":            "evil.com"}),
    ("X-Forwarded-Port",    {"X-Forwarded-Port":  "1337"}),
    ("X-HTTP-Method-Override", {"X-HTTP-Method-Override": "DELETE"}),
    ("Host-override",       {"Host":              "evil.com"}),
]

_FAT_GET_HDR = {"Content-Length": "10", "Content-Type": "application/x-www-form-urlencoded"}


def _baseline(url, timeout=8):
    try:
        r = _req.get(url, verify=False, allow_redirects=False, timeout=timeout,
                     headers={"User-Agent": "MEOW-CACHE/1.1"})
        return r.status_code, len(r.content), dict(r.headers)
    except Exception:
        return 0, 0, {}


def _poison_req(url, extra_headers, timeout=8):
    hdrs = {"User-Agent": "MEOW-CACHE/1.1", **extra_headers}
    try:
        r = _req.get(url, verify=False, allow_redirects=False, timeout=timeout, headers=hdrs)
        return r.status_code, len(r.content), dict(r.headers), r.text[:500]
    except Exception as e:
        return 0, 0, {}, ""


def _fat_get(url, timeout=8):
    hdrs = {"User-Agent": "MEOW-CACHE/1.1", **_FAT_GET_HDR}
    try:
        r = _req.request("GET", url, data="test=meow", headers=hdrs,
                         verify=False, allow_redirects=False, timeout=timeout)
        return r.status_code, len(r.content), dict(r.headers)
    except Exception:
        return 0, 0, {}


def _cache_deception_test(url, timeout=8):
    """Append fake static extensions and check if auth-protected path becomes cacheable."""
    suffixes = ["/nonexistent.css", "/robots.txt.jpg", "/style.css", "/app.js"]
    base = url.rstrip("/")
    results = []
    for suf in suffixes:
        test_url = base + suf
        try:
            r = _req.get(test_url, verify=False, allow_redirects=False, timeout=timeout,
                         headers={"User-Agent": "MEOW-CACHE/1.1"})
            cache_headers = {k.lower(): v for k, v in r.headers.items()}
            cacheable = (
                r.status_code == 200 and
                ("max-age" in cache_headers.get("cache-control", "") or
                 "x-cache" in cache_headers or
                 "cf-cache-status" in cache_headers)
            )
            results.append({
                "path": suf, "status": r.status_code,
                "cacheable": cacheable,
                "cache_control": cache_headers.get("cache-control", ""),
                "x_cache": cache_headers.get("x-cache", ""),
            })
        except Exception:
            results.append({"path": suf, "status": 0, "cacheable": False,
                            "cache_control": "", "x_cache": ""})
    return results


def run():
    show_module_banner("cache")
    cat_talk(CAT_SCAN, "Web cache poisoning & deception tester", CY)
    console.print()
    warn("AUTHORIZED USE ONLY — Unauthorized testing is illegal.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    if not HAS_REQUESTS:
        err("requests library not available. Install it: pip install requests"); return

    url = Prompt.ask(f"  [{G1}]◈ Target URL[/]").strip()
    if not url.startswith("http"):
        url = "https://" + url

    info("Fetching baseline response...")
    base_status, base_len, base_hdrs = _baseline(url)
    info(f"Baseline: status={base_status}  body={base_len}B")
    console.print()

    results = []

    # Poison tests
    info("Running cache poisoning header tests...")
    for test_name, extra_headers in _POISON_TESTS:
        status, body_len, hdrs, body = _poison_req(url, extra_headers)
        # Detect reflection of injected header value
        reflected = any(v in body for v in extra_headers.values())
        status_diff  = (status != base_status and status not in (0,))
        size_diff     = abs(body_len - base_len) > 100
        vuln = reflected or status_diff or size_diff
        sev  = "POTENTIAL" if vuln else "SAFE"
        note = []
        if reflected:    note.append("header reflected in body")
        if status_diff:  note.append(f"status changed {base_status}→{status}")
        if size_diff:    note.append(f"body size diff {abs(body_len-base_len)}B")
        results.append({
            "test": test_name, "status": status,
            "body_len": body_len, "severity": sev,
            "note": "; ".join(note) or "no diff"
        })
        if vuln:
            find(f"Cache poison: [{RD}]{test_name}[/] — {'; '.join(note)}")

    # Fat GET test
    status_fg, len_fg, _ = _fat_get(url)
    vuln_fg = abs(len_fg - base_len) > 100
    results.append({
        "test": "Fat GET", "status": status_fg,
        "body_len": len_fg, "severity": "POTENTIAL" if vuln_fg else "SAFE",
        "note": f"body diff {abs(len_fg-base_len)}B" if vuln_fg else "no diff"
    })

    console.print()
    # Cache deception tests
    info("Running cache deception tests...")
    deception = _cache_deception_test(url)
    for d in deception:
        vuln_d = d["cacheable"]
        results.append({
            "test": f"Deception:{d['path']}", "status": d["status"],
            "body_len": 0, "severity": "POTENTIAL" if vuln_d else "SAFE",
            "note": f"cacheable ext — {d['cache_control']}" if vuln_d else "not cached"
        })
        if vuln_d:
            find(f"Cache deception: [{OR}]{d['path']}[/] appears cacheable!")

    # Display table
    console.print()
    t = Table(title=f"[{G1}]Cache Poisoning Results[/]", box=box.MINIMAL_DOUBLE_HEAD,
              border_style=G2, header_style=CY)
    t.add_column("Test",     min_width=28)
    t.add_column("Status",   min_width=7)
    t.add_column("Severity", min_width=10)
    t.add_column("Note",     min_width=35)

    sc_map = {"POTENTIAL": RD, "SAFE": G2}
    for r in results:
        sc = sc_map.get(r["severity"], DM)
        t.add_row(r["test"], str(r["status"]),
                  f"[{sc}]{r['severity']}[/]", r["note"])
    console.print(t)

    potentials = [r for r in results if r["severity"] == "POTENTIAL"]
    if potentials:
        find(f"{len(potentials)} potential cache issue(s) found!")
    else:
        ok("No cache poisoning/deception indicators found.")

    _save("cache", url, results)
