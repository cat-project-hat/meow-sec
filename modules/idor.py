# -*- coding: utf-8 -*-
"""
MEOW-SEC :: IDOR — Insecure Direct Object Reference Tester
For authorized security testing and CTF challenges only.
"""
import os, re, json, time, uuid, string, random
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_target, ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (authorized-pentest-idor)",
    "Accept": "application/json, text/html, */*",
}

# ─── UTILS ───────────────────────────────────────────────────

def _req(method, url, **kwargs):
    kwargs.setdefault("timeout", 10)
    kwargs.setdefault("verify", False)
    kwargs.setdefault("proxies", _px())
    kwargs.setdefault("allow_redirects", True)
    try:
        return requests.request(method, url, **kwargs)
    except Exception:
        return None

def _gen_ids(ref_id: str) -> list:
    """Generates neighboring/alternative IDs around the reference."""
    variants = []
    # Sequential integers
    try:
        n = int(ref_id)
        for delta in range(-5, 6):
            if delta != 0:
                variants.append(str(n + delta))
        variants += ["0", "1", "2", "9999", "10000", "-1"]
    except ValueError:
        pass

    # UUID swap
    try:
        uuid.UUID(ref_id)
        variants += [str(uuid.uuid4()) for _ in range(3)]
        # Near UUID (flip last char)
        swapped = ref_id[:-1] + ("a" if ref_id[-1] != "a" else "b")
        variants.append(swapped)
    except ValueError:
        pass

    # Common predictable replacements
    variants += ["admin", "0", "1", "null", "undefined", "test", "root"]

    # Remove duplicates while preserving order
    seen = set()
    result = []
    for v in variants:
        if v not in seen and v != ref_id:
            seen.add(v)
            result.append(v)
    return result[:20]

def _compare(baseline, r) -> dict:
    """Compare a response to baseline and return finding info."""
    if r is None:
        return None
    finding = {
        "status": r.status_code,
        "size": len(r.content),
        "diff_size": len(r.content) - len(baseline.content),
        "same_status": r.status_code == baseline.status_code,
    }
    # Different content despite same status → potential IDOR
    if (r.status_code in (200, 201) and
            baseline.status_code in (200, 201) and
            len(r.content) > 50 and
            r.content != baseline.content):
        finding["vuln"] = True
    elif r.status_code in (200, 201) and baseline.status_code in (401, 403, 404):
        finding["vuln"] = True
    else:
        finding["vuln"] = False
    return finding

# ─── TEST 1 — URL path ID swap ────────────────────────────────

def _test_path_idor(url: str, ref_id: str, cookies: dict) -> list:
    console.print(f"\n  [{CY}]→ Path ID swap[/]  [{DM}](ref: {ref_id})[/]")
    baseline = _req("GET", url, headers=_HEADERS, cookies=cookies)
    if baseline is None:
        err("Baseline request failed")
        return []

    findings = []
    ids = _gen_ids(ref_id)
    for test_id in ids:
        test_url = re.sub(
            r'(\b' + re.escape(ref_id) + r'\b)',
            test_id,
            url
        )
        if test_url == url:
            continue
        r = _req("GET", test_url, headers=_HEADERS, cookies=cookies)
        cmp = _compare(baseline, r)
        if cmp and cmp.get("vuln"):
            find(f"IDOR [path] {test_url}  →  HTTP {r.status_code}  ({len(r.content)} bytes)")
            findings.append({
                "type": "path_idor",
                "url": test_url,
                "id": test_id,
                "status": r.status_code,
                "size": len(r.content),
            })
        else:
            status_str = r.status_code if r else "ERR"
            console.print(f"  [{DM}]  {test_id:<20}  →  {status_str}[/]")
    return findings

# ─── TEST 2 — Query param ID swap ────────────────────────────

def _test_param_idor(url: str, param: str, ref_id: str, cookies: dict) -> list:
    console.print(f"\n  [{CY}]→ Query param swap[/]  [{DM}](?{param}={ref_id})[/]")
    baseline = _req("GET", url, headers=_HEADERS, cookies=cookies)
    if baseline is None:
        err("Baseline request failed")
        return []

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = parse_qs(parsed.query)

    findings = []
    for test_id in _gen_ids(ref_id):
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param] = test_id
        test_url = base_url + "?" + urlencode(test_params)
        r = _req("GET", test_url, headers=_HEADERS, cookies=cookies)
        cmp = _compare(baseline, r)
        if cmp and cmp.get("vuln"):
            find(f"IDOR [param] {param}={test_id}  →  HTTP {r.status_code}  ({len(r.content)} bytes)")
            findings.append({
                "type": "param_idor",
                "url": test_url,
                "param": param,
                "id": test_id,
                "status": r.status_code,
                "size": len(r.content),
            })
        else:
            status_str = r.status_code if r else "ERR"
            console.print(f"  [{DM}]  {param}={test_id:<15}  →  {status_str}[/]")
    return findings

# ─── TEST 3 — JSON body IDOR (REST API) ──────────────────────

def _test_json_idor(url: str, field: str, ref_id: str, cookies: dict) -> list:
    console.print(f"\n  [{CY}]→ JSON body field swap[/]  [{DM}]({field}: {ref_id})[/]")
    h = {**_HEADERS, "Content-Type": "application/json"}
    baseline = _req("POST", url, headers=h, cookies=cookies, json={field: ref_id})
    if baseline is None:
        err("Baseline request failed")
        return []

    findings = []
    for test_id in _gen_ids(ref_id):
        r = _req("POST", url, headers=h, cookies=cookies, json={field: test_id})
        cmp = _compare(baseline, r)
        if cmp and cmp.get("vuln"):
            find(f"IDOR [json] {field}={test_id}  →  HTTP {r.status_code}  ({len(r.content)} bytes)")
            findings.append({
                "type": "json_idor",
                "url": url,
                "field": field,
                "id": test_id,
                "status": r.status_code,
                "size": len(r.content),
            })
        else:
            status_str = r.status_code if r else "ERR"
            console.print(f"  [{DM}]  {field}={test_id:<15}  →  {status_str}[/]")
    return findings

# ─── TEST 4 — BOLA (Broken Object Level Auth) REST paths ─────

_BOLA_PATTERNS = [
    "/api/users/{id}",
    "/api/users/{id}/profile",
    "/api/users/{id}/orders",
    "/api/accounts/{id}",
    "/api/orders/{id}",
    "/api/invoices/{id}",
    "/api/documents/{id}",
    "/api/files/{id}",
    "/user/{id}",
    "/profile/{id}",
    "/account/{id}",
    "/order/{id}",
    "/admin/users/{id}",
    "/v1/users/{id}",
    "/v2/users/{id}",
]

def _test_bola(base_url: str, ref_id: str, cookies: dict) -> list:
    console.print(f"\n  [{CY}]→ BOLA REST patterns[/]  [{DM}](id: {ref_id})[/]")
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    findings = []

    for pattern in _BOLA_PATTERNS:
        for test_id in [ref_id] + _gen_ids(ref_id)[:3]:
            path = pattern.replace("{id}", str(test_id))
            full_url = origin + path
            r = _req("GET", full_url, headers=_HEADERS, cookies=cookies)
            if r is None:
                continue
            if r.status_code in (200, 201) and len(r.content) > 20:
                label = "OWN" if test_id == ref_id else f"[bold {RD}]IDOR[/]"
                if test_id != ref_id:
                    find(f"BOLA [{path}]  id={test_id}  →  HTTP {r.status_code}  ({len(r.content)} bytes)")
                    findings.append({
                        "type": "bola",
                        "url": full_url,
                        "id": test_id,
                        "status": r.status_code,
                        "size": len(r.content),
                    })
                else:
                    console.print(f"  [{G2}]  {path}  →  {r.status_code}  (own)[/]")
            elif r.status_code in (403, 401):
                console.print(f"  [{DM}]  {path}  →  {r.status_code}  (protected)[/]")
    return findings

# ─── SAVE ─────────────────────────────────────────────────────

def _save(target: str, findings: list):
    if not findings:
        return
    os.makedirs("data", exist_ok=True)
    fname = f"data/idor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "findings": findings, "ts": datetime.now().isoformat()}, f, indent=2)
    ok(f"Saved → {fname}")

# ─── MAIN ─────────────────────────────────────────────────────

def run():
    show_module_banner("idor")
    if not HAS_REQUESTS:
        err("requests not installed"); return

    console.print(f"\n  [{CY}]IDOR / BOLA Tester[/]  [{DM}]— Insecure Direct Object Reference[/]\n")

    url = ask_target("Target URL (with ID in path or param)")
    if not url:
        return
    if not url.startswith("http"):
        url = "http://" + url

    console.print(f"\n  [{CY}]Mode:[/]")
    console.print(f"  [{G2}][1][/] Path ID swap  (URL contains /resource/123)")
    console.print(f"  [{G2}][2][/] Query param swap  (?id=123&user=456)")
    console.print(f"  [{G2}][3][/] JSON body field  (POST API)")
    console.print(f"  [{G2}][4][/] BOLA — REST pattern discovery")
    console.print(f"  [{G2}][5][/] All tests")

    mode = ask_choice("Mode")
    if mode not in ("1", "2", "3", "4", "5"):
        warn("Invalid mode"); return

    ref_id = ask_choice("Reference ID (your own, e.g. 42 or a UUID)")
    if not ref_id:
        warn("Need a reference ID"); return

    cookie_str = ask_choice("Session cookie (name=value; name2=val2) [Enter to skip]")
    cookies = {}
    if cookie_str and "=" in cookie_str:
        for part in cookie_str.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k.strip()] = v.strip()

    all_findings = []

    if mode in ("1", "5"):
        all_findings += _test_path_idor(url, ref_id, cookies)

    if mode in ("2", "5"):
        param = ask_choice("Param name to test (e.g. id, user_id)")
        if param:
            all_findings += _test_param_idor(url, param, ref_id, cookies)

    if mode in ("3", "5"):
        field = ask_choice("JSON field name (e.g. userId, account_id)")
        if field:
            all_findings += _test_json_idor(url, field, ref_id, cookies)

    if mode in ("4", "5"):
        all_findings += _test_bola(url, ref_id, cookies)

    console.print()
    if all_findings:
        cat_talk(CAT_FOUND, f"{len(all_findings)} IDOR finding(s) detected!", G1)
        rows = [
            [f["type"], f.get("url", url), f.get("id", "?"), str(f.get("status", "?")), str(f.get("size", "?"))]
            for f in all_findings
        ]
        print_result_table(["Type", "URL", "ID", "Status", "Size"], rows)
        _save(url, all_findings)
    else:
        cat_talk(CAT_SCAN, "No IDOR found — may need valid session cookies or different IDs.", DM)
