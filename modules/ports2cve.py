# -*- coding: utf-8 -*-
"""
MEOW-SEC :: PORTS2CVE (#66) — Port Scan → CVE Correlator
Correlates CLAW scan results with HIGH/CRITICAL CVEs via NVD & CIRCL.lu.
For authorized security testing and CTF challenges only.
"""
import os, re, json, time, glob
from datetime import datetime

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_target, ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk
from rich.prompt import Prompt
from rich.rule import Rule

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

HEADERS = {"User-Agent": "MEOW-PORTS2CVE/1.0 (security-research)"}

# ─── PORT → PRODUCT FALLBACK MAP ──────────────────────────────
PORT_PRODUCT = {
    21:    "vsftpd",
    22:    "openssh",
    23:    "telnet",
    25:    "sendmail",
    53:    "bind",
    80:    "apache",
    110:   "dovecot",
    143:   "dovecot",
    443:   "apache",
    445:   "samba",
    3306:  "mysql",
    3389:  "freerdp",
    5432:  "postgresql",
    5900:  "libvncserver",
    6379:  "redis",
    8080:  "tomcat",
    8443:  "tomcat",
    8888:  "jupyter",
    9200:  "elasticsearch",
    27017: "mongodb",
}

# ─── BANNER PARSING ───────────────────────────────────────────

BANNER_PATTERNS = [
    (r"Apache[/ ]([\d.]+)",           "apache"),
    (r"nginx[/ ]([\d.]+)",            "nginx"),
    (r"OpenSSH[_ ]([\d.p]+)",         "openssh"),
    (r"Microsoft-IIS[/ ]([\d.]+)",    "iis"),
    (r"vsftpd[/ ]([\d.]+)",           "vsftpd"),
    (r"ProFTPD[/ ]([\d.]+)",          "proftpd"),
    (r"MySQL[/ ]([\d.]+)",            "mysql"),
    (r"MariaDB[/ ]([\d.]+)",          "mariadb"),
    (r"PostgreSQL[/ ]([\d.]+)",       "postgresql"),
    (r"Redis[/ ]([\d.]+)",            "redis"),
    (r"MongoDB[/ ]([\d.]+)",          "mongodb"),
    (r"Tomcat[/ ]([\d.]+)",           "tomcat"),
    (r"PHP[/ ]([\d.]+)",              "php"),
    (r"OpenSSL[/ ]([\da-z.]+)",       "openssl"),
    (r"Samba[/ ]([\d.]+)",            "samba"),
    (r"Exim[/ ]([\d.]+)",             "exim"),
    (r"Postfix[/ ]([\d.]+)",          "postfix"),
    (r"Sendmail[/ ]([\d.]+)",         "sendmail"),
    (r"Dovecot[/ ]([\d.]+)",          "dovecot"),
    (r"([\d.]+)",                     None),   # version-only fallback
]

def parse_banner(banner: str, port: int) -> tuple[str, str]:
    """Returns (product, version) parsed from banner string."""
    if not banner:
        product = PORT_PRODUCT.get(port, "")
        return product, ""

    for pattern, product_name in BANNER_PATTERNS[:-1]:
        m = re.search(pattern, banner, re.I)
        if m:
            version = m.group(1).strip()
            return product_name, version

    # Try to detect product from port if banner is vague
    product = PORT_PRODUCT.get(port, "")
    version_m = re.search(r"([\d]+\.[\d.]+)", banner)
    version = version_m.group(1) if version_m else ""
    return product, version

# ─── CVE FETCHING ─────────────────────────────────────────────

def _score_to_sev(score) -> str:
    try:
        s = float(score)
        if s >= 9.0: return "CRITICAL"
        if s >= 7.0: return "HIGH"
        if s >= 4.0: return "MEDIUM"
        if s > 0:    return "LOW"
    except (ValueError, TypeError):
        pass
    return "?"


def _search_nvd(product: str, version: str = "") -> list:
    """Query NVD API v2 for HIGH/CRITICAL CVEs. Rate-limited: 100 req/min without key."""
    keyword = f"{product} {version}".strip()
    if not keyword:
        return []
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": 10},
            headers=HEADERS, timeout=15, verify=False
        )
        if r.status_code == 200:
            items = r.json().get("vulnerabilities", [])
            results = []
            for item in items:
                cve   = item.get("cve", {})
                cid   = cve.get("id", "?")
                descs = cve.get("descriptions", [])
                desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "?")[:120]
                metrics = cve.get("metrics", {})
                score, sev = "?", "?"
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    m_list = metrics.get(key, [])
                    if m_list:
                        cvss = m_list[0].get("cvssData", {})
                        score = cvss.get("baseScore", "?")
                        sev   = cvss.get("baseSeverity", m_list[0].get("baseSeverity", "?"))
                        break
                # Only keep HIGH / CRITICAL
                try:
                    if float(score) < 7.0:
                        continue
                except (ValueError, TypeError):
                    continue
                results.append({
                    "id": cid, "score": score, "severity": str(sev).upper(),
                    "description": desc, "source": "NVD"
                })
            return results
        elif r.status_code == 503:
            warn("NVD rate limited — skipping")
    except Exception as e:
        warn(f"NVD error: {e}")
    return []


def _search_circl(product: str) -> list:
    """Query CIRCL.lu CVE Search API for HIGH/CRITICAL CVEs."""
    if not product:
        return []
    try:
        # CIRCL endpoint: /api/search/{vendor}/{product} or /api/search/{product}
        r = requests.get(
            f"https://cve.circl.lu/api/search/{product}",
            headers=HEADERS, timeout=10, verify=False
        )
        if r.status_code == 200:
            data  = r.json()
            items = data if isinstance(data, list) else data.get("data", [])
            results = []
            for item in items[:15]:
                cid   = item.get("id", item.get("CVE", "?"))
                score = str(item.get("cvss", item.get("cvss3", "?")))
                desc  = item.get("summary", "?")[:120]
                sev   = _score_to_sev(score)
                try:
                    if float(score) < 7.0:
                        continue
                except (ValueError, TypeError):
                    continue
                results.append({
                    "id": cid, "score": score, "severity": sev,
                    "description": desc, "source": "CIRCL"
                })
            return results
    except Exception as e:
        warn(f"CIRCL error: {e}")
    return []


def _fetch_cves(product: str, version: str) -> list:
    """Fetch from NVD then CIRCL, deduplicate, return HIGH/CRITICAL only."""
    nvd_results    = _search_nvd(product, version)
    time.sleep(0.6)  # NVD rate-limit: 100 req/min without API key
    circl_results  = _search_circl(product)

    seen = set()
    merged = []
    for cve in nvd_results + circl_results:
        cid = cve["id"]
        if cid not in seen:
            seen.add(cid)
            merged.append(cve)

    merged.sort(key=lambda x: float(x["score"]) if isinstance(x["score"], (int, float)) or
                (isinstance(x["score"], str) and x["score"] != "?") else 0, reverse=True)
    return merged

# ─── CLAW FILE LOADER ─────────────────────────────────────────

def _list_claw_files() -> list:
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    return sorted(glob.glob(os.path.join(data_dir, "claw_*.json")), reverse=True)


def _load_claw_file(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _pick_claw_file() -> dict | None:
    files = _list_claw_files()
    if not files:
        warn("No CLAW result files found in data/")
        return None

    console.print(f"\n  [{G1}]Available CLAW scans:[/]")
    for i, fp in enumerate(files[:10], 1):
        console.print(f"  [{G1}][{i}][/] [{CY}]{os.path.basename(fp)}[/]")

    choice = Prompt.ask(f"  [{G1}]◈ Select file number[/]", default="1").strip()
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(files):
            return _load_claw_file(files[idx])
    except ValueError:
        pass
    err("Invalid selection.")
    return None

# ─── MAIN ─────────────────────────────────────────────────────

def run(target: str = None):
    show_module_banner("ports2cve")
    cat_talk(CAT_SCAN, "PORTS2CVE — correlating port scan results with known CVEs...", OR)
    console.print()

    if not HAS_REQUESTS:
        err("requests library not installed. Run: pip install requests"); return

    console.print(f"  [{G1}][1][/] Load CLAW JSON scan file  (data/claw_*.json)")
    console.print(f"  [{G1}][2][/] Enter ports/services manually")
    mode = ask_choice("Mode") or "1"
    console.print()

    ports_data = []  # list of {"port": N, "service": "...", "banner": "..."}
    scan_target = target or "unknown"

    if mode == "1":
        claw = _pick_claw_file()
        if not claw:
            return
        scan_target  = claw.get("target", "unknown")
        raw_results  = claw.get("results", [])
        ports_data   = [p for p in raw_results if p.get("state") == "OPEN"]
        if not ports_data:
            warn("No OPEN ports found in this CLAW file.")
            return
        info(f"Loaded [{G1}]{len(ports_data)}[/] open port(s) from CLAW scan of [{CY}]{scan_target}[/]")

    elif mode == "2":
        if not target:
            scan_target = ask_target("Target name / IP (for filename)")
        console.print(f"  [{DM}]Enter one port per line. Format:  port service banner")
        console.print(f"  [{DM}]Example:  80 http Apache/2.4.49")
        console.print(f"  [{DM}]Leave blank to finish.[/]")
        while True:
            line = Prompt.ask(f"  [{G1}]◈ Port entry[/]", default="").strip()
            if not line:
                break
            parts = line.split(None, 2)
            try:
                port    = int(parts[0])
                service = parts[1] if len(parts) > 1 else ""
                banner  = parts[2] if len(parts) > 2 else ""
                ports_data.append({"port": port, "service": service, "banner": banner, "state": "OPEN"})
            except (ValueError, IndexError):
                warn("Invalid format — skipping line")

    if not ports_data:
        err("No port data to process."); return

    console.print()
    info(f"Searching CVEs for [{G1}]{len(ports_data)}[/] port(s) — this may take a moment...")
    console.print()

    all_findings = []  # list of (port, service, product, version, cve_id, score, severity, desc)
    port_summary = {}  # port → list of CVEs

    for entry in ports_data:
        port    = entry.get("port", 0)
        service = entry.get("service", "")
        banner  = entry.get("banner", "")

        product, version = parse_banner(banner, port)

        if not product:
            info(f"Port [{CY}]{port}[/] — no product identified, skipping")
            continue

        info(f"Port [{CY}]{port}[/]  [{DM}]{service}[/]  →  searching [{G1}]{product} {version}[/]")

        cves = _fetch_cves(product, version)

        if cves:
            find(f"Port {port}/{service}  [{G1}]{product} {version}[/]  →  [{RD}]{len(cves)} HIGH/CRITICAL CVE(s)[/]")
        else:
            info(f"Port {port}/{service}  [{G1}]{product} {version}[/]  →  no HIGH/CRITICAL CVEs found")

        port_summary[port] = {
            "service": service, "product": product,
            "version": version, "banner": banner, "cves": cves
        }

        for cve in cves:
            sev   = cve.get("severity", "?")
            score = cve.get("score", "?")
            color = RD if sev == "CRITICAL" else OR
            all_findings.append((
                str(port), service or "-", f"{product} {version}".strip(),
                f"[{color}]{cve['id']}[/{color}]",
                f"[{color}]{score}[/{color}]",
                f"[{color}]{sev}[/{color}]",
                cve["description"][:55]
            ))

    console.print()

    if all_findings:
        print_result_table(
            f"PORTS2CVE :: {scan_target}",
            ["PORT", "SERVICE", "PRODUCT+VER", "CVE ID", "CVSS", "SEV", "DESCRIPTION"],
            all_findings
        )
        total_crit = sum(1 for f in all_findings if "CRITICAL" in f[5])
        total_high = sum(1 for f in all_findings if "HIGH" in f[5])
        find(f"{len(all_findings)} CVE(s) found — [{RD}]{total_crit} CRITICAL[/] / [{OR}]{total_high} HIGH[/]")
    else:
        ok("No HIGH/CRITICAL CVEs found for scanned ports.")

    _save(scan_target, port_summary)


def _save(target: str, data: dict):
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out_dir, exist_ok=True)
    slug  = re.sub(r"[^a-zA-Z0-9_-]", "_", target)[:40]
    fname = os.path.join(out_dir, f"ports2cve_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "timestamp": datetime.now().isoformat(), "results": data}, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
