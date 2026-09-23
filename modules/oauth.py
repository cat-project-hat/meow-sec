# -*- coding: utf-8 -*-
"""MEOW-SEC :: OAUTH — OAuth 2.0 / OIDC Misconfiguration Tester"""
import os, re, json
from datetime import datetime
from urllib.parse import urlparse, urlencode, urljoin

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


_DISCO_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
    "/api/oauth/.well-known/openid-configuration",
    "/.well-known/oauth2/openid-configuration",
]

_CLIENT_SECRET_PATTERNS = [
    r'client_secret["\s]*[:=]["\s]*([A-Za-z0-9_\-]{8,})',
    r'clientSecret["\s]*[:=]["\s]*([A-Za-z0-9_\-]{8,})',
    r'"secret"\s*:\s*"([A-Za-z0-9_\-]{8,})"',
]

_CLIENT_ID_PATTERNS = [
    r'client_id["\s]*[:=]["\s]*["\']([A-Za-z0-9_\-\.]{4,})["\']',
    r'clientId["\s]*[:=]["\s]*["\']([A-Za-z0-9_\-\.]{4,})["\']',
]


def _fetch(url, timeout=10):
    try:
        r = _req.get(url, verify=False, allow_redirects=False, timeout=timeout,
                     headers={"User-Agent": "MEOW-OAUTH/1.1"})
        return r.status_code, r.text, dict(r.headers)
    except Exception as e:
        return 0, "", {}


def _post(url, data, timeout=10):
    try:
        r = _req.post(url, data=data, verify=False, allow_redirects=False, timeout=timeout,
                      headers={"User-Agent": "MEOW-OAUTH/1.1"})
        return r.status_code, r.text
    except Exception:
        return 0, ""


def _get_with_params(url, params, timeout=10):
    try:
        r = _req.get(url, params=params, verify=False, allow_redirects=False, timeout=timeout,
                     headers={"User-Agent": "MEOW-OAUTH/1.1"})
        return r.status_code, r.text, r.headers.get("Location", "")
    except Exception:
        return 0, "", ""


def run():
    show_module_banner("oauth")
    cat_talk(CAT_SCAN, "OAuth 2.0 / OIDC misconfiguration tester", OR)
    console.print()
    warn("AUTHORIZED USE ONLY — Unauthorized testing is illegal.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    if not HAS_REQUESTS:
        err("requests library not available. Install it: pip install requests"); return

    url = Prompt.ask(f"  [{G1}]◈ Target base URL (e.g. https://app.example.com)[/]").strip()
    if not url.startswith("http"):
        url = "https://" + url
    url = url.rstrip("/")

    client_id = Prompt.ask(f"  [{CY}]◈ Client ID (optional, leave blank)[/]", default="").strip()

    results = []

    # Step 1: Discovery
    info("Step 1: OAuth/OIDC discovery endpoints...")
    disco_data = None
    disco_url  = None
    auth_endpoint = None
    token_endpoint = None

    for path in _DISCO_PATHS:
        full = url + path
        status, body, _ = _fetch(full)
        if status == 200:
            ok(f"Discovery found: {full}")
            try:
                disco_data = json.loads(body)
                disco_url  = full
                auth_endpoint  = disco_data.get("authorization_endpoint", "")
                token_endpoint = disco_data.get("token_endpoint", "")
                results.append({"check": "Discovery", "finding": f"Found: {full}",
                                 "severity": "INFO", "detail": body[:200]})
            except Exception:
                pass
            break

    if not disco_data:
        info("No discovery endpoint found — using guessed paths")
        for guess in ["/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
                      "/connect/authorize", "/api/oauth/authorize"]:
            status, _, _ = _fetch(url + guess)
            if status in (200, 302, 400):
                auth_endpoint = url + guess
                ok(f"Auth endpoint guessed: {auth_endpoint}")
                break

    # Step 2: Open redirect in redirect_uri
    if auth_endpoint:
        info(f"Step 2: Testing open redirect in redirect_uri...")
        cid = client_id or "test_client"
        params = {
            "response_type": "code",
            "client_id": cid,
            "redirect_uri": "https://evil.com/callback",
            "scope": "openid",
            "state": "meow_test",
        }
        status, body, location = _get_with_params(auth_endpoint, params)
        vuln_redir = "evil.com" in location
        sev = "HIGH" if vuln_redir else "SAFE"
        note = f"Redirected to {location[:60]}" if vuln_redir else f"status={status}"
        results.append({"check": "Open redirect_uri", "finding": note,
                        "severity": sev, "detail": location})
        if vuln_redir:
            find(f"Open redirect_uri! [{RD}]evil.com accepted[/]")

        # Step 3: State param enforcement
        info("Step 3: State parameter enforcement (CSRF)...")
        no_state_params = {k: v for k, v in params.items() if k != "state"}
        status_ns, body_ns, loc_ns = _get_with_params(auth_endpoint, no_state_params)
        missing_state = status_ns in (200, 302) and "state" not in (body_ns + loc_ns).lower()
        sev_state = "MEDIUM" if missing_state else "SAFE"
        results.append({"check": "State param required", "finding":
                        "No state enforced (CSRF risk)" if missing_state else "State enforced",
                        "severity": sev_state, "detail": f"status={status_ns}"})
        if missing_state:
            find(f"State parameter not enforced — CSRF risk!")

        # Step 4: response_type=token (implicit flow)
        info("Step 4: Implicit flow (response_type=token)...")
        imp_params = {**params, "response_type": "token"}
        status_imp, body_imp, loc_imp = _get_with_params(auth_endpoint, imp_params)
        implicit_ok = status_imp in (200, 302) and "error" not in body_imp.lower()
        sev_imp = "MEDIUM" if implicit_ok else "SAFE"
        results.append({"check": "Implicit flow enabled", "finding":
                        "Implicit flow accepted" if implicit_ok else "Implicit flow rejected",
                        "severity": sev_imp, "detail": f"status={status_imp}"})

        # Step 5: PKCE enforcement
        info("Step 5: PKCE enforcement check...")
        pkce_params = {**params, "response_type": "code", "code_challenge_method": "plain",
                       "code_challenge": "dGVzdA"}
        no_pkce_params = {**params, "response_type": "code"}
        status_pkce, _, _ = _get_with_params(auth_endpoint, pkce_params)
        status_no_pkce, _, _ = _get_with_params(auth_endpoint, no_pkce_params)
        pkce_required = status_pkce in (200, 302) and status_no_pkce not in (200, 302)
        sev_pkce = "SAFE" if pkce_required else "LOW"
        results.append({"check": "PKCE enforcement", "finding":
                        "PKCE required" if pkce_required else "PKCE not required",
                        "severity": sev_pkce, "detail": f"with={status_pkce} without={status_no_pkce}"})

    # Step 6: Client secret in JS
    info("Step 6: Scanning homepage for client_id/client_secret in JS...")
    status_home, body_home, _ = _fetch(url)
    if body_home:
        for pat in _CLIENT_SECRET_PATTERNS:
            m = re.search(pat, body_home, re.IGNORECASE)
            if m:
                find(f"Client secret in page source: [{RD}]{m.group(1)[:30]}[/]")
                results.append({"check": "Client secret in JS", "finding": m.group(1)[:40],
                                 "severity": "HIGH", "detail": pat})
        for pat in _CLIENT_ID_PATTERNS:
            m = re.search(pat, body_home, re.IGNORECASE)
            if m:
                info(f"Client ID found: {m.group(1)[:30]}")
                results.append({"check": "Client ID exposed", "finding": m.group(1)[:30],
                                 "severity": "LOW", "detail": pat})

    # Step 7: Token endpoint GET
    if token_endpoint:
        info("Step 7: Token endpoint allows GET...")
        st_get, _, _ = _fetch(token_endpoint + "?grant_type=client_credentials&client_id=test")
        allows_get = st_get in (200, 400, 401)
        sev_get = "LOW" if allows_get else "SAFE"
        results.append({"check": "Token endpoint GET", "finding":
                        f"Accepts GET (status {st_get})" if allows_get else "POST only",
                        "severity": sev_get, "detail": f"status={st_get}"})

    # Display results
    console.print()
    t = Table(title=f"[{G1}]OAuth Check Results[/]", box=box.MINIMAL_DOUBLE_HEAD,
              border_style=G2, header_style=CY)
    t.add_column("Check",    min_width=26)
    t.add_column("Finding",  min_width=36)
    t.add_column("Severity", min_width=8)

    sev_colors = {"HIGH": RD, "MEDIUM": OR, "LOW": CY, "SAFE": G2, "INFO": DM}
    for r in results:
        sc = sev_colors.get(r["severity"], DM)
        t.add_row(r["check"], r["finding"], f"[{sc}]{r['severity']}[/]")
    console.print(t)

    issues = [r for r in results if r["severity"] not in ("SAFE", "INFO")]
    if issues:
        find(f"{len(issues)} OAuth misconfiguration(s) found!")
    else:
        ok("No OAuth misconfigurations detected.")

    _save("oauth", url, results)
