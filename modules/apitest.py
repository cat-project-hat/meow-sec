# -*- coding: utf-8 -*-
"""
MEOW-SEC :: APITEST — REST API Security Tester (module 63)
For authorized security testing and CTF challenges only.
"""
import os, json, time
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_target, ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk
from core.proxy_manager import px as _px

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from rich.rule    import Rule
from rich.prompt  import Prompt

# ─── CONSTANTS ────────────────────────────────────────────────────────────────

_UA = "MEOW-APITEST/1.0 (authorized-security-test)"
_TIMEOUT = 8

_DISCOVERY_PATHS = [
    # Version roots
    "/api/v1/", "/api/v2/", "/api/v3/",
    "/v1/", "/v2/", "/v3/",
    "/api/", "/rest/", "/graphql",
    # Docs
    "/swagger.json", "/openapi.json", "/api-docs",
    "/swagger-ui.html", "/swagger-ui/", "/redoc",
    "/.well-known/", "/.well-known/openid-configuration",
    # Admin / internal
    "/api/admin/", "/api/admin", "/api/internal/",
    "/api/debug/", "/api/health", "/api/status",
    "/api/metrics", "/api/config",
    # Users
    "/api/users", "/api/users/",
    "/api/me", "/api/profile",
    "/api/account", "/api/accounts",
    "/api/v1/users", "/api/v2/users",
    "/api/v1/me",   "/api/v2/me",
]

_MASS_FIELDS = [
    {"role": "admin"},
    {"isAdmin": True},
    {"admin": True},
    {"privilege": "admin"},
    {"is_admin": True},
    {"id": 1},
    {"userId": 1},
    {"accountId": 1},
    {"verified": True},
    {"active": True},
    {"balance": 99999},
    {"credits": 99999},
    {"role": "superuser"},
]

_METHODS_EXTRA = ["HEAD", "OPTIONS", "TRACE", "PATCH", "PUT", "DELETE"]

_AUTH_BYPASS_VARIANTS = [
    ("No Authorization header", None),
    ("Empty Bearer",            "Bearer "),
    ("Bearer null",             "Bearer null"),
    ("Bearer undefined",        "Bearer undefined"),
    ("Bearer 0",                "Bearer 0"),
    ("Bearer false",            "Bearer false"),
    ("Bearer 1",                "Bearer 1"),
    ("Bearer test",             "Bearer test"),
]

_VERBOSE_ERROR_PAYLOADS = [
    ('{"broken": }',                          "application/json"),
    ('{"id": "string-not-int"}',              "application/json"),
    ('{',                                     "application/json"),
    ('<script>x</script>',                    "application/json"),
    ('{"__proto__":{"admin":true}}',          "application/json"),
    ('a=1&b=2',                               "application/x-www-form-urlencoded"),
]

_STACK_HINTS = [
    "traceback", "stack trace", "exception", "at line", "syntax error",
    "undefined method", "nullpointerexception", "java.lang", "django",
    "flask", "rails", "laravel", "express", "spring boot", "file not found",
    "internal server error", "sqlstate", "odbc", "pg::", "mysql",
]

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _headers(token: str = None, content_type: str = "application/json") -> dict:
    h = {"User-Agent": _UA, "Content-Type": content_type, "Accept": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}" if not token.startswith("Bearer ") else token
    return h

def _get(url: str, token: str = None, extra_headers: dict = None) -> requests.Response | None:
    try:
        h = _headers(token)
        if extra_headers:
            h.update(extra_headers)
        return requests.get(url, headers=h, timeout=_TIMEOUT,
                            verify=False, proxies=_px(), allow_redirects=False)
    except Exception:
        return None

def _post(url: str, body: dict, token: str = None, content_type: str = "application/json") -> requests.Response | None:
    try:
        h = _headers(token, content_type)
        data = json.dumps(body) if content_type == "application/json" else body
        return requests.post(url, data=data, headers=h, timeout=_TIMEOUT,
                             verify=False, proxies=_px(), allow_redirects=False)
    except Exception:
        return None

def _request_method(method: str, url: str, token: str = None) -> requests.Response | None:
    try:
        return requests.request(method, url, headers=_headers(token),
                                timeout=_TIMEOUT, verify=False,
                                proxies=_px(), allow_redirects=False)
    except Exception:
        return None

def _normalize_base(url: str) -> str:
    if not url.startswith("http"):
        url = "https://" + url
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def _looks_alive(status: int) -> bool:
    return status in (200, 201, 204, 301, 302, 401, 403, 405)

def _slugify(url: str) -> str:
    return urlparse(url).netloc.replace(".", "_").replace(":", "_")

# ─── 1. ENDPOINT DISCOVERY ────────────────────────────────────────────────────

def _discover_endpoints(base: str, token: str = None) -> list[dict]:
    """Return list of {url, status, server, content_type} for responsive paths."""
    results = []

    def _probe(path):
        url = base.rstrip("/") + path
        r   = _get(url, token)
        if r is None:
            return None
        if _looks_alive(r.status_code):
            return {
                "url":          url,
                "path":         path,
                "status":       r.status_code,
                "server":       r.headers.get("Server", "—"),
                "content_type": r.headers.get("Content-Type", "—")[:40],
                "length":       len(r.content),
            }
        return None

    info(f"  Probing [{len(_DISCOVERY_PATHS)}] paths on [{CY}]{base}[/] ...")
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(_probe, p): p for p in _DISCOVERY_PATHS}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                color = G1 if r["status"] in (200, 201, 204) else OR
                console.print(f"    [{color}]{r['status']}[/]  {r['url']:<55} [{DM}]{r['server']}[/]")
                results.append(r)

    return results

# ─── 2. MASS ASSIGNMENT ───────────────────────────────────────────────────────

def _test_mass_assignment(endpoints: list[dict], token: str = None) -> list[dict]:
    findings = []
    post_targets = [e for e in endpoints if e["status"] in (200, 201, 401, 403)][:5]

    if not post_targets:
        info("  No suitable endpoints for mass assignment test.")
        return findings

    info(f"  Testing mass assignment on [{len(post_targets)}] endpoints...")

    for ep in post_targets:
        url = ep["url"]
        # Build combined payload with all extra fields at once
        payload = {}
        for field_dict in _MASS_FIELDS:
            payload.update(field_dict)

        r = _post(url, payload, token)
        if r is None:
            continue

        if r.status_code in (200, 201):
            try:
                body = r.json()
                body_str = json.dumps(body).lower()
            except Exception:
                body_str = r.text.lower()

            accepted = [k for d in _MASS_FIELDS for k in d
                        if k.lower() in body_str or str(list(d.values())[0]).lower() in body_str]

            if accepted:
                find(f"[MASS-ASSIGN] [{CY}]{url}[/]  accepted: [{G1}]{', '.join(accepted[:6])}[/]")
                findings.append({
                    "type":    "mass_assignment",
                    "url":     url,
                    "status":  r.status_code,
                    "fields":  accepted,
                    "sev":     "HIGH",
                    "note":    f"Server reflected injected fields: {', '.join(accepted[:6])}",
                })
            else:
                info(f"  [{OR}]POST 200[/] but no injected fields reflected → [{DM}]{url}[/]")
        else:
            info(f"  POST {r.status_code} → [{DM}]{url}[/]")

    return findings

# ─── 3. HTTP METHOD TAMPERING ─────────────────────────────────────────────────

def _test_method_tampering(endpoints: list[dict], token: str = None) -> list[dict]:
    findings = []
    if not endpoints:
        return findings

    info(f"  Probing unexpected HTTP methods on [{len(endpoints)}] endpoints...")

    for ep in endpoints[:8]:   # cap to avoid flooding
        url = ep["url"]
        for method in _METHODS_EXTRA:
            r = _request_method(method, url, token)
            if r is None:
                continue
            if r.status_code == 200 and method not in ("HEAD", "OPTIONS"):
                find(f"[METHOD-TAMPER] [{CY}]{method}[/] {url} → [{G1}]200[/]  (unexpected success)")
                findings.append({
                    "type":   "method_tamper",
                    "url":    url,
                    "method": method,
                    "status": r.status_code,
                    "sev":    "MEDIUM",
                    "note":   f"{method} returns 200 — unexpected method accepted",
                })
            elif method == "OPTIONS" and r.status_code in (200, 204):
                allow = r.headers.get("Allow", r.headers.get("Access-Control-Allow-Methods", ""))
                if allow:
                    info(f"  OPTIONS {url} Allow: [{DM}]{allow[:60]}[/]")
                    if any(m in allow.upper() for m in ["TRACE", "DELETE", "PUT"]):
                        find(f"[METHOD-TAMPER] [{CY}]OPTIONS[/] {url} exposes risky methods: [{G1}]{allow[:60]}[/]")
                        findings.append({
                            "type":   "method_tamper",
                            "url":    url,
                            "method": "OPTIONS",
                            "status": r.status_code,
                            "sev":    "LOW",
                            "note":   f"Risky methods advertised: {allow[:60]}",
                        })

    return findings

# ─── 4. AUTH BYPASS ───────────────────────────────────────────────────────────

def _test_auth_bypass(endpoints: list[dict], token: str = None) -> list[dict]:
    findings = []
    targets = [e for e in endpoints if e["status"] in (401, 403)]
    if not targets:
        # fall back to any alive endpoint
        targets = endpoints[:3]
    if not targets:
        info("  No endpoints available for auth bypass test.")
        return findings

    info(f"  Testing auth bypass on [{len(targets[:5])}] protected endpoints...")

    for ep in targets[:5]:
        url = ep["url"]
        baseline_status = ep["status"]

        # --- Token variants ---
        for label, auth_val in _AUTH_BYPASS_VARIANTS:
            try:
                h = {"User-Agent": _UA, "Accept": "application/json"}
                if auth_val is not None:
                    h["Authorization"] = auth_val
                r = requests.get(url, headers=h, timeout=_TIMEOUT,
                                 verify=False, proxies=_px(), allow_redirects=False)
                if r.status_code in (200, 201) and baseline_status in (401, 403):
                    find(f"[AUTH-BYPASS] [{CY}]{label}[/] → [{G1}]{r.status_code}[/] on {url}")
                    findings.append({
                        "type":     "auth_bypass",
                        "url":      url,
                        "method":   label,
                        "status":   r.status_code,
                        "baseline": baseline_status,
                        "sev":      "CRITICAL",
                        "note":     f"Auth bypass via {label}",
                    })
            except Exception:
                pass

        # --- X-Original-URL / X-Rewrite-URL tricks ---
        for hdr_name in ("X-Original-URL", "X-Rewrite-URL", "X-Override-URL"):
            for admin_path in ("/admin", "/api/admin", "/api/internal"):
                try:
                    h = _headers(token)
                    h[hdr_name] = admin_path
                    r = requests.get(url, headers=h, timeout=_TIMEOUT,
                                     verify=False, proxies=_px(), allow_redirects=False)
                    if r.status_code in (200, 201):
                        find(f"[AUTH-BYPASS] [{CY}]{hdr_name}: {admin_path}[/] → [{G1}]{r.status_code}[/] on {url}")
                        findings.append({
                            "type":     "auth_bypass",
                            "url":      url,
                            "method":   f"{hdr_name}: {admin_path}",
                            "status":   r.status_code,
                            "baseline": baseline_status,
                            "sev":      "HIGH",
                            "note":     f"Header override trick: {hdr_name}={admin_path}",
                        })
                except Exception:
                    pass

        # --- Content-Type switch ---
        if token:
            r_json = _post(url, {"test": 1}, token, "application/json")
            r_form = _post(url, "test=1",    token, "application/x-www-form-urlencoded")
            if r_json and r_form:
                if r_json.status_code != r_form.status_code:
                    info(f"  [{OR}]Content-Type difference[/] on {url}: JSON={r_json.status_code} FORM={r_form.status_code}")
                    if r_form.status_code in (200, 201) and r_json.status_code in (400, 403, 422):
                        find(f"[AUTH-BYPASS] Content-Type switch bypassed validation on {url}")
                        findings.append({
                            "type":   "auth_bypass",
                            "url":    url,
                            "method": "Content-Type: form vs json",
                            "status": r_form.status_code,
                            "sev":    "MEDIUM",
                            "note":   "Form content-type bypasses JSON validation",
                        })

    return findings

# ─── 5. RATE LIMITING ─────────────────────────────────────────────────────────

def _test_rate_limit(endpoints: list[dict], token: str = None) -> list[dict]:
    findings = []
    target = next((e for e in endpoints if e["status"] in (200, 201, 401, 403)), None)
    if not target:
        info("  No suitable endpoint for rate limit test.")
        return findings

    url = target["url"]
    info(f"  Sending 20 rapid requests to [{CY}]{url}[/] ...")
    statuses = []
    rate_headers_seen = []

    for i in range(20):
        r = _get(url, token)
        if r is None:
            statuses.append(0)
            continue
        statuses.append(r.status_code)
        for h in ("X-RateLimit-Limit", "X-RateLimit-Remaining",
                  "X-RateLimit-Reset", "Retry-After", "RateLimit-Limit"):
            if h in r.headers and h not in rate_headers_seen:
                rate_headers_seen.append(f"{h}: {r.headers[h]}")

    ok200 = sum(1 for s in statuses if s == 200)
    ok429 = sum(1 for s in statuses if s == 429)

    if ok429 > 0:
        ok(f"  Rate limiting active: [{G1}]{ok429}[/] × 429 responses after {ok200} successes")
    elif not rate_headers_seen and ok200 >= 18:
        find(f"[RATE-LIMIT] [{CY}]{url}[/] — no rate limiting detected ({ok200}/20 requests returned 200)")
        findings.append({
            "type":   "rate_limit",
            "url":    url,
            "status": "absent",
            "sev":    "MEDIUM",
            "note":   f"{ok200}/20 requests succeeded, no 429 and no RateLimit headers",
        })
    else:
        info(f"  Rate limit headers: {', '.join(rate_headers_seen) or '—'}")

    return findings

# ─── 6. API VERSIONING ────────────────────────────────────────────────────────

def _test_api_versioning(endpoints: list[dict], token: str = None) -> list[dict]:
    findings = []
    v2_paths = [e for e in endpoints if "/v2/" in e["url"] or "/v3/" in e["url"]]
    if not v2_paths:
        info("  No v2/v3 endpoints found — skipping version downgrade test.")
        return findings

    info(f"  Checking older API versions for [{len(v2_paths)}] endpoints...")

    for ep in v2_paths:
        for old_ver, new_ver in [("/v2/", "/v1/"), ("/v3/", "/v2/"), ("/v3/", "/v1/"),
                                  ("/api/v2/", "/api/v1/"), ("/api/v3/", "/api/v2/")]:
            if old_ver in ep["url"]:
                old_url = ep["url"].replace(old_ver, new_ver, 1)
                r = _get(old_url, token)
                if r and r.status_code in (200, 201):
                    find(f"[API-VERSION] Older endpoint alive: [{CY}]{old_url}[/] → [{G1}]{r.status_code}[/]")
                    findings.append({
                        "type":    "api_versioning",
                        "url":     old_url,
                        "current": ep["url"],
                        "status":  r.status_code,
                        "sev":     "MEDIUM",
                        "note":    f"Older API version still accessible ({old_ver} → {new_ver})",
                    })

    return findings

# ─── 7. VERBOSE ERRORS ────────────────────────────────────────────────────────

def _test_verbose_errors(endpoints: list[dict], token: str = None) -> list[dict]:
    findings = []
    targets = [e for e in endpoints if e["status"] in (200, 201, 400, 401, 403, 422)][:5]
    if not targets:
        info("  No endpoints for verbose error test.")
        return findings

    info(f"  Sending malformed payloads to [{len(targets)}] endpoints...")

    for ep in targets:
        url = ep["url"]
        for payload, ctype in _VERBOSE_ERROR_PAYLOADS:
            try:
                h = _headers(token, ctype)
                r = requests.post(url, data=payload, headers=h, timeout=_TIMEOUT,
                                  verify=False, proxies=_px(), allow_redirects=False)
                if r.status_code in (500, 502, 503, 400, 422):
                    body_low = r.text.lower()
                    matched = [hint for hint in _STACK_HINTS if hint in body_low]
                    if matched:
                        find(f"[VERBOSE-ERR] [{CY}]{url}[/] [{RD}]{r.status_code}[/] leaks: [{G1}]{', '.join(matched[:4])}[/]")
                        findings.append({
                            "type":    "verbose_error",
                            "url":     url,
                            "status":  r.status_code,
                            "payload": payload[:40],
                            "leaked":  matched[:4],
                            "sev":     "LOW",
                            "note":    f"Stack/framework info in error response: {', '.join(matched[:4])}",
                        })
                        break   # one finding per endpoint is enough
            except Exception:
                pass

    return findings

# ─── SAVE ─────────────────────────────────────────────────────────────────────

def _save(base: str, all_findings: dict):
    out = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out, exist_ok=True)
    slug  = _slugify(base)
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(out, f"apitest_{slug}_{ts}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({
            "target":    base,
            "timestamp": datetime.now().isoformat(),
            "findings":  all_findings,
        }, f, indent=2, default=str)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")

# ─── SUMMARY TABLE ────────────────────────────────────────────────────────────

_SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

def _print_summary(all_findings: list[dict]):
    if not all_findings:
        ok("No vulnerabilities found — API looks clean.")
        return

    rows = []
    for f in sorted(all_findings, key=lambda x: _SEV_ORDER.get(x.get("sev", "INFO"), 0), reverse=True):
        rows.append((
            f.get("type", "—").upper()[:18],
            f.get("sev", "—"),
            f.get("url", "—")[-50:],
            f.get("note", "—")[:60],
        ))

    print_result_table(
        f"API Security Findings  ({len(rows)} issue(s))",
        ["TYPE", "SEV", "URL (tail)", "NOTE"],
        rows,
    )
    worst = max(all_findings, key=lambda x: _SEV_ORDER.get(x.get("sev", "INFO"), 0))
    warn(f"Highest severity: [{RD}]{worst['sev']}[/]  — {worst.get('note','')[:70]}")

# ─── MAIN run() ───────────────────────────────────────────────────────────────

def run(target: str = None):
    show_module_banner("apitest")
    cat_talk(CAT_SCAN, "REST API security sensors online — initialising scan...", OR)
    console.print()

    if not HAS_REQUESTS:
        err("requests library not installed. Run: pip install requests"); return

    if not target:
        target = ask_target("Base API URL (e.g. https://api.example.com)")
    if not target:
        err("No target provided."); return

    base = _normalize_base(target)
    info(f"Base URL  : [{CY}]{base}[/]")

    token = Prompt.ask(
        f"  [{G2}][?][/{G2}]  Bearer token (leave empty to test without auth)",
        default="",
        password=False,
        console=console,
    ).strip() or None

    if token:
        info(f"Token     : [{DM}]{token[:12]}…[/] (provided)")
    else:
        info(f"Token     : [{DM}]none — unauthenticated scan[/]")

    console.print()
    console.print(f"  [{G1}][1][/] Full scan  (all checks)")
    console.print(f"  [{G1}][2][/] Discovery only")
    console.print(f"  [{G1}][3][/] Auth bypass only")
    mode = ask_choice("Mode") or "1"
    console.print()

    all_findings: list[dict] = []
    endpoints:    list[dict] = []

    # ── Discovery (always runs, needed by other tests) ──
    console.print(Rule(f"[{CY}] 1 · Endpoint Discovery ", style=G2))
    endpoints = _discover_endpoints(base, token)
    if endpoints:
        find(f"[{len(endpoints)}] responsive endpoint(s) found")
    else:
        warn("No responsive endpoints found — subsequent tests may be limited")
    console.print()

    if mode in ("1",):
        # ── Mass Assignment ──
        console.print(Rule(f"[{CY}] 2 · Mass Assignment ", style=G2))
        all_findings += _test_mass_assignment(endpoints, token)
        console.print()

        # ── Method Tampering ──
        console.print(Rule(f"[{CY}] 3 · HTTP Method Tampering ", style=G2))
        all_findings += _test_method_tampering(endpoints, token)
        console.print()

        # ── Auth Bypass ──
        console.print(Rule(f"[{CY}] 4 · Auth Bypass ", style=G2))
        all_findings += _test_auth_bypass(endpoints, token)
        console.print()

        # ── Rate Limiting ──
        console.print(Rule(f"[{CY}] 5 · Rate Limiting ", style=G2))
        all_findings += _test_rate_limit(endpoints, token)
        console.print()

        # ── API Versioning ──
        console.print(Rule(f"[{CY}] 6 · API Version Downgrade ", style=G2))
        all_findings += _test_api_versioning(endpoints, token)
        console.print()

        # ── Verbose Errors ──
        console.print(Rule(f"[{CY}] 7 · Verbose Error Leakage ", style=G2))
        all_findings += _test_verbose_errors(endpoints, token)
        console.print()

    elif mode == "3":
        console.print(Rule(f"[{CY}] Auth Bypass ", style=G2))
        all_findings += _test_auth_bypass(endpoints, token)
        console.print()

    # ── Summary ──
    console.print(Rule(f"[{G1}] Results ", style=G2))
    _print_summary(all_findings)
    console.print()

    _save(base, all_findings)
