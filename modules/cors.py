# -*- coding: utf-8 -*-
"""
MEOW-SEC :: CORS — CORS Misconfiguration Tester
For authorized security testing and CTF challenges only.
"""
import os, json
from datetime import datetime
from urllib.parse import urlparse

from core.ui import (console, ok, err, info, warn, find, boot_progress,
                     print_result_table, show_module_banner, ask_target,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

# ─── TEST ORIGINS ─────────────────────────────────────────────
def _build_test_origins(target_url: str) -> list:
    parsed = urlparse(target_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    host   = parsed.netloc.replace("www.", "")
    return [
        f"https://evil.com",
        f"https://attacker.com",
        f"null",
        f"{base}.evil.com",
        f"https://evil{host}",
        f"https://{host}.attacker.com",
        f"https://evil.com%60{base}",
        f"https://not{host}",
        f"http://{host}",          # downgrade
        f"https://sub.{host}",
    ]

def _check_cors(url: str, origin: str, timeout: int = 8) -> dict:
    try:
        r = requests.options(
            url,
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "User-Agent": "MEOW-CORS/1.1 (authorized-test)",
            },
            timeout=timeout, verify=False, proxies=_px(), allow_redirects=False
        )
        acao  = r.headers.get("Access-Control-Allow-Origin", "")
        acac  = r.headers.get("Access-Control-Allow-Credentials", "")
        acam  = r.headers.get("Access-Control-Allow-Methods", "")
        acah  = r.headers.get("Access-Control-Allow-Headers", "")

        vuln  = False
        sev   = "INFO"
        note  = ""

        if acao == "*":
            note = "Wildcard (*) — open CORS"
            sev  = "MEDIUM"
            vuln = True
        elif acao == origin and acao not in ("", None):
            if acac.lower() == "true":
                note = "Origin reflected + credentials=true → CRITICAL"
                sev  = "CRITICAL"
                vuln = True
            else:
                note = "Origin reflected (no credentials)"
                sev  = "LOW"
                vuln = True
        elif acao == "null" and acac.lower() == "true":
            note = "null origin + credentials=true"
            sev  = "HIGH"
            vuln = True

        return {
            "origin": origin,
            "acao":   acao or "—",
            "acac":   acac or "—",
            "vuln":   vuln,
            "sev":    sev,
            "note":   note,
            "status": r.status_code,
        }
    except Exception as e:
        return {"origin": origin, "acao": "—", "acac": "—",
                "vuln": False, "sev": "ERROR", "note": str(e)[:50], "status": 0}

def _check_get_cors(url: str, origin: str, timeout: int = 8) -> dict:
    """GET-based CORS check (some servers don't handle OPTIONS properly)"""
    try:
        r = requests.get(
            url,
            headers={
                "Origin": origin,
                "User-Agent": "MEOW-CORS/1.1 (authorized-test)",
            },
            timeout=timeout, verify=False, proxies=_px(), allow_redirects=False
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        vuln = False
        sev  = "INFO"
        note = ""

        if acao == "*":
            note = "Wildcard (*) on GET"; sev = "MEDIUM"; vuln = True
        elif acao == origin and acao:
            if acac.lower() == "true":
                note = "Origin reflected on GET + credentials=true"; sev = "CRITICAL"; vuln = True
            else:
                note = "Origin reflected on GET"; sev = "LOW"; vuln = True

        return {"origin": origin, "acao": acao or "—", "acac": acac or "—",
                "vuln": vuln, "sev": sev, "note": note, "status": r.status_code}
    except Exception as e:
        return {"origin": origin, "acao": "—", "acac": "—",
                "vuln": False, "sev": "ERROR", "note": str(e)[:50], "status": 0}

# ─── MAIN ─────────────────────────────────────────────────────

def run(target: str = None):
    show_module_banner("cors")
    cat_talk(CAT_SCAN, "CORS sensors active — testing cross-origin policies...", OR)
    console.print()

    if not target:
        target = ask_target("Target URL (https://example.com/api/endpoint)")
    if not target:
        err("No target."); return

    if not target.startswith("http"):
        target = "https://" + target

    info(f"Target: [{CY}]{target}[/]")
    console.print()

    console.print(f"  [{G1}][1][/] OPTIONS preflight test")
    console.print(f"  [{G1}][2][/] GET-based test")
    console.print(f"  [{G1}][3][/] Full test (OPTIONS + GET)")
    mode = ask_choice("Mode", "3")

    boot_progress(["Preparing origins...", "Sending requests...", "Analyzing headers..."])
    console.print()

    origins = _build_test_origins(target)
    findings = []

    for origin in origins:
        if mode in ("1", "3"):
            res = _check_cors(target, origin)
            if res["vuln"]:
                findings.append(res)
                find(f"[VULN][{res['sev']}] Origin [{CY}]{origin}[/] → ACAO: [{G1}]{res['acao']}[/]  ACAC: {res['acac']} — {res['note']}")
            else:
                info(f"  Origin {origin[:45]:<45} → [{DM}]{res['acao'][:30]}[/]")

        if mode in ("2", "3"):
            res2 = _check_get_cors(target, origin)
            if res2["vuln"] and res2 not in findings:
                findings.append(res2)
                find(f"[GET][{res2['sev']}] Origin [{CY}]{origin}[/] → ACAO: [{G1}]{res2['acao']}[/] — {res2['note']}")

    console.print()
    if findings:
        rows = [(f["origin"][:40], f["sev"], f["acao"][:30], f["acac"], f["note"][:50])
                for f in findings]
        print_result_table("CORS Vulnerabilities Found",
                           ["ORIGIN", "SEV", "ACAO", "Credentials", "NOTE"],
                           rows, color_col=1)
        _sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        worst = max(findings, key=lambda x: _sev_map.get(x["sev"], 0))
        warn(f"Highest severity: [{RD}]{worst['sev']}[/]")
    else:
        ok("No CORS misconfigurations detected.")

    _save(target, findings)

def _save(target, findings):
    out = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out, exist_ok=True)
    fname = os.path.join(out, f"cors_{urlparse(target).netloc.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "findings": findings, "time": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
