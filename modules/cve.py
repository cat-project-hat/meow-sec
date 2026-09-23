# -*- coding: utf-8 -*-
"""
MEOW-SEC :: CVE — CVE Lookup & Version Matcher
For authorized security testing and CTF challenges only.
"""
import os, re, json
from datetime import datetime

from core.ui import (console, ok, err, info, warn, find, boot_progress,
                     print_result_table, show_module_banner, ask_target,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk
from rich.prompt import Prompt
from rich.rule import Rule

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

HEADERS = {"User-Agent": "MEOW-CVE/1.1 (security-research)"}

# ─── CVE SOURCES ──────────────────────────────────────────────

def _search_nvd(keyword: str, max_results: int = 10) -> list:
    """NVD REST API (no key needed, rate-limited)"""
    info("Querying NVD database...")
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            headers=HEADERS, timeout=15, verify=False
        )
        if r.status_code == 200:
            data = r.json()
            items = data.get("vulnerabilities", [])
            results = []
            for item in items:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "?")
                descs = cve.get("descriptions", [])
                desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "?")[:200]
                metrics = cve.get("metrics", {})
                score = "?"
                sev   = "?"
                for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                    m_list = metrics.get(key, [])
                    if m_list:
                        cvss = m_list[0].get("cvssData", {})
                        score = cvss.get("baseScore", "?")
                        sev   = cvss.get("baseSeverity", m_list[0].get("baseSeverity","?"))
                        break
                published = cve.get("published", "?")[:10]
                results.append({"id": cve_id, "score": score, "severity": str(sev),
                                 "published": published, "description": desc})
            return results
        elif r.status_code == 503:
            warn("NVD API rate limited — wait 6 seconds and retry")
        else:
            warn(f"NVD returned HTTP {r.status_code}")
    except Exception as e:
        warn(f"NVD error: {e}")
    return []

def _search_cve_circl(keyword: str, max_results: int = 10) -> list:
    """CVE Search by CIRCL.lu — no key needed"""
    info("Querying CIRCL CVE database...")
    try:
        r = requests.get(
            f"https://cve.circl.lu/api/search/{keyword}",
            headers=HEADERS, timeout=10, verify=False
        )
        if r.status_code == 200:
            data = r.json()
            results_raw = data if isinstance(data, list) else data.get("data", [])
            results = []
            for item in results_raw[:max_results]:
                cve_id = item.get("id", item.get("CVE","?"))
                cvss   = str(item.get("cvss", item.get("cvss3", "?")))
                desc   = item.get("summary", "?")[:200]
                published = item.get("Published","?")[:10]
                sev = _score_to_sev(cvss)
                results.append({"id": cve_id, "score": cvss, "severity": sev,
                                 "published": published, "description": desc})
            return results
        else:
            warn(f"CIRCL returned HTTP {r.status_code}")
    except Exception as e:
        warn(f"CIRCL error: {e}")
    return []

def _get_cve_detail(cve_id: str) -> dict:
    """Get details for a specific CVE"""
    info(f"Fetching details for [{CY}]{cve_id}[/]...")
    try:
        r = requests.get(
            f"https://cve.circl.lu/api/cve/{cve_id}",
            headers=HEADERS, timeout=10, verify=False
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}

def _score_to_sev(score) -> str:
    try:
        s = float(score)
        if s >= 9.0:  return "CRITICAL"
        if s >= 7.0:  return "HIGH"
        if s >= 4.0:  return "MEDIUM"
        if s > 0:     return "LOW"
    except (ValueError, TypeError):
        pass
    return "?"

def _scan_target_headers(target: str) -> list:
    """Scan a target URL, detect software versions, search for CVEs"""
    info(f"Scanning [{CY}]{target}[/] for version fingerprints...")
    keywords = []

    # Tech detection via headers + body
    version_patterns = [
        (r"Apache[\s/]([\d.]+)", "Apache"),
        (r"nginx[\s/]([\d.]+)", "nginx"),
        (r"Microsoft-IIS[\s/]([\d.]+)", "IIS"),
        (r"PHP[\s/]([\d.]+)", "PHP"),
        (r"OpenSSL[\s/]([\d.a-z]+)", "OpenSSL"),
        (r"WordPress[\s/]([\d.]+)", "WordPress"),
        (r"Drupal[\s/]([\d.]+)", "Drupal"),
        (r"Joomla[\s/!]([\d.]+)", "Joomla"),
        (r"X-Powered-By: (.*)", "powered_by"),
        (r"Server: (.*)", "server_header"),
        (r"Liferay[\s/]([\d.]+)", "Liferay"),
        (r"Tomcat[\s/]([\d.]+)", "Tomcat"),
        (r"JBoss[\s/]([\d.]+)", "JBoss"),
    ]

    try:
        r = requests.get(target, headers={"User-Agent": "MEOW-CVE/1.1"},
                         timeout=10, verify=False, allow_redirects=True,
                         proxies=_px())
        all_text = "\n".join(f"{k}: {v}" for k,v in r.headers.items()) + "\n" + r.text[:5000]

        for pattern, tech in version_patterns:
            m = re.search(pattern, all_text, re.I)
            if m:
                version_str = m.group(1).strip() if m.lastindex else ""
                keywords.append(f"{tech} {version_str}".strip())
                find(f"Detected: [{CY}]{tech}[/]  version: [{G1}]{version_str}[/]")
    except Exception as e:
        err(f"Scan error: {e}")

    return keywords

# ─── MAIN ─────────────────────────────────────────────────────
def run(target: str = None):
    show_module_banner("cve")
    cat_talk(CAT_SCAN, "CVE module — matching software versions to known vulnerabilities...", OR)
    console.print()

    console.print(f"  [{G1}][1][/] Search CVE by keyword (software name + version)")
    console.print(f"  [{G1}][2][/] Get details for a specific CVE ID")
    console.print(f"  [{G1}][3][/] Auto-scan a target URL for version fingerprints")
    mode = ask_choice("Mode", "1")

    all_results = []

    if mode == "1":
        kw = Prompt.ask(f"  [{CY}]Keyword (e.g. 'Apache 2.4.49', 'OpenSSL 1.1.1', 'WordPress 5.8')[/]").strip()
        if not kw:
            err("No keyword."); return
        boot_progress(["Querying CVE databases...", "Fetching NVD...", "Fetching CIRCL..."])
        console.print()
        results = _search_nvd(kw) or _search_cve_circl(kw)
        all_results = results

    elif mode == "2":
        cve_id = Prompt.ask(f"  [{CY}]CVE ID (e.g. CVE-2021-44228)[/]").strip().upper()
        if not cve_id.startswith("CVE-"):
            err("Invalid CVE ID format."); return
        boot_progress(["Fetching CVE details..."])
        console.print()
        detail = _get_cve_detail(cve_id)
        if detail:
            console.print(Rule(f"[{G1}] {cve_id} ", style=G2))
            rows = [
                ("Summary",    detail.get("summary","?")[:100]),
                ("CVSS Score", str(detail.get("cvss", detail.get("cvss3","?")))),
                ("Severity",   _score_to_sev(detail.get("cvss", detail.get("cvss3","0")))),
                ("Published",  str(detail.get("Published","?"))[:10]),
                ("Modified",   str(detail.get("Modified","?"))[:10]),
                ("CWE",        str(detail.get("cwe","?"))),
            ]
            print_result_table(cve_id, ["FIELD", "VALUE"], rows)
            refs = detail.get("references", [])[:5]
            if refs:
                info("References:")
                for ref in refs:
                    console.print(f"  [{CY}]{ref}[/]")
        else:
            warn(f"No details found for {cve_id}")
        return

    elif mode == "3":
        if not target:
            target = ask_target("Target URL (https://example.com)")
        if not target:
            err("No target."); return
        if not target.startswith("http"):
            target = "https://" + target
        boot_progress(["Scanning target...", "Fingerprinting versions...", "Querying CVEs..."])
        console.print()
        keywords = _scan_target_headers(target)
        if not keywords:
            warn("No software versions detected.")
            return
        for kw in keywords:
            info(f"Searching CVEs for: [{CY}]{kw}[/]")
            results = _search_nvd(kw, max_results=5) or _search_cve_circl(kw, max_results=5)
            for r in results:
                r["keyword"] = kw
            all_results += results

    if all_results:
        # Sort by severity
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "?": 0}
        all_results.sort(key=lambda x: sev_order.get(x.get("severity","?"), 0), reverse=True)
        rows = [(r["id"], r.get("score","?"), r.get("severity","?"),
                 r.get("published","?")[:10], r["description"][:60])
                for r in all_results[:30]]
        print_result_table("CVE Results", ["CVE ID", "SCORE", "SEV", "DATE", "DESCRIPTION"],
                           rows, color_col=2)
        critical = [r for r in all_results if r.get("severity") in ("CRITICAL","HIGH")]
        if critical:
            find(f"{len(critical)} HIGH/CRITICAL CVEs found!")
    else:
        ok("No CVEs found for this search.")

    _save(all_results)

def _save(results):
    out = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out, exist_ok=True)
    fname = os.path.join(out, f"cve_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"results": results, "time": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
