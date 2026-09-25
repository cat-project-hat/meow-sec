# -*- coding: utf-8 -*-
"""
MEOW-SEC :: EMAILSEC — Email Security Checker (SPF / DKIM / DMARC / Spoofing)
For authorized security testing and CTF challenges only.
"""
import os, json, re, socket, time
import concurrent.futures
from datetime import datetime

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_target, ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# DNS-over-HTTPS (no dnspython dependency)
_DOH_URL = "https://cloudflare-dns.com/dns-query"
_HEADERS_DOH = {"Accept": "application/dns-json"}

# ─── DNS-over-HTTPS resolver ──────────────────────────────────

def _doh(name: str, rtype: str) -> list:
    if not HAS_REQUESTS:
        return []
    try:
        r = requests.get(_DOH_URL, params={"name": name, "type": rtype},
                         headers=_HEADERS_DOH, timeout=8, verify=False)
        data = r.json()
        return [a["data"] for a in data.get("Answer", []) if a.get("type") is not None]
    except Exception:
        return []

def _txt_records(domain: str) -> list:
    return _doh(domain, "TXT")

def _mx_records(domain: str) -> list:
    return _doh(domain, "MX")

def _a_record(domain: str) -> str:
    results = _doh(domain, "A")
    return results[0] if results else ""

# ─── SPF ──────────────────────────────────────────────────────

def _check_spf(domain: str) -> dict:
    txts = _txt_records(domain)
    spf = None
    for t in txts:
        t_clean = t.strip('"').strip()
        if t_clean.lower().startswith("v=spf1"):
            spf = t_clean
            break

    if not spf:
        return {"found": False, "record": None, "issues": ["No SPF record found — domain can be spoofed"],
                "severity": "HIGH"}

    issues = []
    severity = "OK"

    if "+all" in spf.lower():
        issues.append("SPF ends with +all — ANYONE can send email for this domain!")
        severity = "CRITICAL"
    elif "~all" in spf.lower():
        issues.append("SPF ends with ~all (SoftFail) — spoofed emails may be delivered")
        severity = "MEDIUM"
    elif "?all" in spf.lower():
        issues.append("SPF ends with ?all (Neutral) — no protection")
        severity = "MEDIUM"
    elif "-all" in spf.lower():
        pass  # Good
    else:
        issues.append("SPF has no 'all' mechanism — incomplete policy")
        severity = "LOW"

    # Too many DNS lookups (>10 limit)
    lookup_terms = re.findall(r'\b(include|a|mx|ptr|exists):', spf, re.I)
    if len(lookup_terms) > 10:
        issues.append(f"SPF has {len(lookup_terms)} DNS lookups (limit is 10) — PermError likely")
        if severity == "OK":
            severity = "LOW"

    # ptr mechanism is deprecated
    if "ptr" in spf.lower():
        issues.append("SPF uses 'ptr' mechanism — deprecated (slow and unreliable)")

    return {"found": True, "record": spf, "issues": issues, "severity": severity}

# ─── DKIM ─────────────────────────────────────────────────────

_COMMON_SELECTORS = [
    "default", "google", "mail", "smtp", "email", "dkim", "k1",
    "k2", "s1", "s2", "key1", "key2", "selector1", "selector2",
    "mimecast", "proofpoint", "mailchimp", "sendgrid", "ses",
    "everlytickey1", "cm", "zoho", "mailgun",
]

def _check_dkim(domain: str, selectors: list = None) -> dict:
    if selectors is None:
        selectors = _COMMON_SELECTORS

    def _check_selector(sel):
        name = f"{sel}._domainkey.{domain}"
        records = _txt_records(name)
        for r in records:
            if "v=DKIM1" in r or "p=" in r:
                return {"selector": sel, "record": r.strip('"')}
        return None

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_check_selector, sel): sel for sel in selectors}
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            if result is not None:
                found.append(result)

    issues = []
    severity = "OK"

    if not found:
        issues.append(f"No DKIM records found for {len(selectors)} common selectors — email authenticity unverifiable")
        severity = "MEDIUM"

    for entry in found:
        rec = entry["record"]
        # Short key or test mode
        match = re.search(r"p=([A-Za-z0-9+/=]+)", rec)
        if match:
            key_b64 = match.group(1)
            # Empty key = revoked
            if not key_b64.strip():
                issues.append(f"Selector [{entry['selector']}] has empty p= — DKIM key revoked")
                severity = "MEDIUM"
            elif len(key_b64) < 200:
                issues.append(f"Selector [{entry['selector']}] key is short ({len(key_b64)} chars) — may be 512-bit (weak)")
                if severity == "OK":
                    severity = "LOW"
        if "t=y" in rec:
            issues.append(f"Selector [{entry['selector']}] has t=y — test mode, not enforced")
            if severity == "OK":
                severity = "LOW"

    return {"found": bool(found), "selectors": found, "issues": issues, "severity": severity}

# ─── DMARC ────────────────────────────────────────────────────

def _check_dmarc(domain: str) -> dict:
    records = _txt_records(f"_dmarc.{domain}")
    dmarc = None
    for r in records:
        r_clean = r.strip('"')
        if r_clean.lower().startswith("v=dmarc1"):
            dmarc = r_clean
            break

    if not dmarc:
        return {"found": False, "record": None,
                "issues": ["No DMARC record — spoofed emails bypass policy enforcement"],
                "severity": "HIGH"}

    issues = []
    severity = "OK"

    # Policy
    match_p = re.search(r"\bp=(\w+)", dmarc, re.I)
    policy = match_p.group(1).lower() if match_p else "none"
    if policy == "none":
        issues.append("DMARC p=none — monitoring only, no enforcement (spoofing still possible)")
        severity = "HIGH"
    elif policy == "quarantine":
        issues.append("DMARC p=quarantine — spoofed emails go to spam (partial protection)")
        severity = "LOW"
    # p=reject is ideal

    # Subdomain policy
    match_sp = re.search(r"\bsp=(\w+)", dmarc, re.I)
    if not match_sp:
        issues.append("No sp= subdomain policy — subdomains inherit p= (may be none)")
        if severity == "OK":
            severity = "LOW"
    elif match_sp.group(1).lower() == "none":
        issues.append("sp=none — subdomains have no DMARC enforcement")

    # Reporting
    if "rua=" not in dmarc.lower():
        issues.append("No rua= aggregate report URI — no visibility into spoofing attempts")

    # Percentage
    match_pct = re.search(r"\bpct=(\d+)", dmarc, re.I)
    if match_pct:
        pct = int(match_pct.group(1))
        if pct < 100:
            issues.append(f"pct={pct} — policy only applied to {pct}% of emails")
            if severity == "OK":
                severity = "LOW"

    return {"found": True, "record": dmarc, "policy": policy, "issues": issues, "severity": severity}

# ─── BIMI ─────────────────────────────────────────────────────

def _check_bimi(domain: str) -> dict:
    """Check BIMI TXT record at default._bimi.{domain}"""
    records = _doh(f"default._bimi.{domain}", "TXT")
    for r in records:
        r_clean = r.strip('"')
        if "v=BIMI1" in r_clean or r_clean.lower().startswith("v=bimi1"):
            l_tag = re.search(r'\bl=([^\s;]+)', r_clean, re.I)
            a_tag = re.search(r'\ba=([^\s;]+)', r_clean, re.I)
            return {
                "found": True,
                "record": r_clean,
                "logo_url": l_tag.group(1) if l_tag else "",
                "vmc_url":  a_tag.group(1) if a_tag else "",
            }
    return {"found": False}

# ─── MX ───────────────────────────────────────────────────────

def _check_mx(domain: str) -> dict:
    mx_records = _mx_records(domain)
    if not mx_records:
        return {"found": False, "records": [], "issues": ["No MX records — domain cannot receive email"]}

    records = []
    for mx in mx_records:
        priority, host = mx.split(" ", 1) if " " in mx else ("?", mx)
        records.append({"priority": priority, "host": host.rstrip(".")})

    return {"found": True, "records": records, "issues": []}

# ─── SPOOF SIMULATION ─────────────────────────────────────────

def _spoof_score(spf: dict, dkim: dict, dmarc: dict) -> tuple:
    """Returns (score 0-10, verdict) where 10 = trivially spoofable."""
    score = 0
    reasons = []

    if not spf["found"]:
        score += 4
        reasons.append("No SPF")
    elif "+all" in (spf.get("record") or ""):
        score += 4
        reasons.append("SPF +all")
    elif "~all" in (spf.get("record") or "") or "?all" in (spf.get("record") or ""):
        score += 2
        reasons.append("SPF softfail/neutral")

    if not dkim["found"]:
        score += 2
        reasons.append("No DKIM")

    if not dmarc["found"]:
        score += 4
        reasons.append("No DMARC")
    elif dmarc.get("policy") == "none":
        score += 3
        reasons.append("DMARC p=none")
    elif dmarc.get("policy") == "quarantine":
        score += 1
        reasons.append("DMARC quarantine")

    score = min(score, 10)
    if score >= 7:
        verdict = f"[bold {RD}]HIGHLY SPOOFABLE[/]"
    elif score >= 4:
        verdict = f"[{OR}]MODERATELY SPOOFABLE[/]"
    elif score >= 1:
        verdict = f"[{CY}]PARTIALLY PROTECTED[/]"
    else:
        verdict = f"[{G1}]WELL PROTECTED[/]"

    return score, verdict, reasons

# ─── SAVE ─────────────────────────────────────────────────────

def _save(domain: str, report: dict):
    os.makedirs("data", exist_ok=True)
    fname = f"data/emailsec_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    ok(f"Saved → {fname}")

# ─── MAIN ─────────────────────────────────────────────────────

def run():
    show_module_banner("emailsec")
    if not HAS_REQUESTS:
        err("requests not installed"); return

    console.print(f"\n  [{CY}]Email Security Checker[/]  [{DM}]— SPF / DKIM / DMARC / spoof score[/]\n")

    domain_raw = ask_target("Target domain (e.g. example.com or user@example.com)")
    if not domain_raw:
        return

    # Extract domain from email if needed
    domain = domain_raw.strip().lower()
    if "@" in domain:
        domain = domain.split("@")[-1]
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc or domain
    domain = domain.rstrip("/")

    extra_selectors_raw = ask_choice("Extra DKIM selectors (comma-separated) [Enter to skip]")
    extra_selectors = []
    if extra_selectors_raw:
        extra_selectors = [s.strip() for s in extra_selectors_raw.split(",") if s.strip()]

    info(f"Checking email security for: {domain}")
    console.print()

    # ── SPF ──
    console.print(f"  [{CY}]→ SPF[/]")
    spf = _check_spf(domain)
    if spf["found"]:
        color = G1 if spf["severity"] == "OK" else (RD if spf["severity"] in ("CRITICAL", "HIGH") else OR)
        ok(f"SPF found  [{color}]{spf['severity']}[/{color}]")
        console.print(f"  [{DM}]{spf['record']}[/]")
    else:
        err("No SPF record")
    for issue in spf["issues"]:
        find(issue) if "CRITICAL" in issue or "HIGH" in issue else warn(issue)

    console.print()

    # ── DKIM ──
    console.print(f"  [{CY}]→ DKIM[/]")
    dkim = _check_dkim(domain, _COMMON_SELECTORS + extra_selectors)
    if dkim["found"]:
        ok(f"DKIM found: {len(dkim['selectors'])} selector(s)")
        for entry in dkim["selectors"]:
            rec = entry['record']
            info(f"  selector={entry['selector']}  →  {rec[:80]}{'...' if len(rec) > 80 else ''}")
    else:
        err("No DKIM selectors found")
    for issue in dkim["issues"]:
        warn(issue)

    console.print()

    # ── DMARC ──
    console.print(f"  [{CY}]→ DMARC[/]")
    dmarc = _check_dmarc(domain)
    if dmarc["found"]:
        policy_color = G1 if dmarc.get("policy") == "reject" else (OR if dmarc.get("policy") == "quarantine" else RD)
        ok(f"DMARC found  policy=[{policy_color}]{dmarc.get('policy', '?').upper()}[/{policy_color}]")
        console.print(f"  [{DM}]{dmarc['record']}[/]")
    else:
        err("No DMARC record")
    for issue in dmarc["issues"]:
        find(issue) if "HIGH" in spf["severity"] or not dmarc["found"] else warn(issue)

    console.print()

    # ── MX ──
    console.print(f"  [{CY}]→ MX Records[/]")
    mx = _check_mx(domain)
    if mx["found"]:
        ok(f"{len(mx['records'])} MX record(s)")
        for rec in mx["records"]:
            info(f"  priority={rec['priority']}  host={rec['host']}")
    else:
        err("No MX records")

    console.print()

    # ── BIMI ──
    console.print(f"  [{CY}]→ BIMI (Brand Indicators for Message Identification)[/]")
    bimi = _check_bimi(domain)
    if bimi["found"]:
        if bimi.get("vmc_url"):
            ok(f"BIMI found with VMC (Verified Mark Certificate) — high email posture")
            info(f"  Logo : {bimi['logo_url'][:80]}")
            info(f"  VMC  : {bimi['vmc_url'][:80]}")
        else:
            ok(f"BIMI record found (no VMC)")
            if bimi.get("logo_url"):
                info(f"  Logo : {bimi['logo_url'][:80]}")
        console.print(f"  [{DM}]{bimi['record'][:80]}[/]")
    else:
        info("No BIMI record (optional — not penalizing)")

    console.print()

    # ── Spoof score ──
    score, verdict, reasons = _spoof_score(spf, dkim, dmarc)
    console.print(f"  [{CY}]─── Spoof Risk Score ───[/]")
    console.print(f"\n  Score: [{RD if score >= 7 else OR if score >= 4 else G1}]{score}/10[/]  {verdict}")
    if reasons:
        console.print(f"  Reasons: [{DM}]{' · '.join(reasons)}[/]")

    if score >= 7:
        find(f"Domain [{domain}] is HIGHLY SPOOFABLE — attacker can send email as @{domain}")
    elif score >= 4:
        warn(f"Domain [{domain}] has partial email protection — spoofing may succeed")
    else:
        ok(f"Domain [{domain}] is reasonably protected against spoofing")

    console.print()

    # ── Summary table ──
    rows = [
        ["SPF",   "✓" if spf["found"] else "✗",
         spf.get("record", "—")[:60] if spf.get("record") else "—",
         spf["severity"]],
        ["DKIM",  "✓" if dkim["found"] else "✗",
         f"{len(dkim['selectors'])} selector(s)" if dkim["found"] else "none found",
         dkim["severity"]],
        ["DMARC", "✓" if dmarc["found"] else "✗",
         dmarc.get("record", "—")[:60] if dmarc.get("record") else "—",
         dmarc["severity"]],
        ["MX",    "✓" if mx["found"] else "✗",
         ", ".join(r["host"] for r in mx["records"][:3]),
         "OK" if mx["found"] else "WARN"],
        ["BIMI",  "✓" if bimi["found"] else "—",
         (("VMC+" if bimi.get("vmc_url") else "") + bimi.get("record", "not configured")[:40]) if bimi["found"] else "not configured",
         ("OK+VMC" if bimi.get("vmc_url") else "OK") if bimi["found"] else "INFO"],
    ]
    print_result_table("Email Security Summary", ["Check", "Found", "Record", "Severity"], rows)

    report = {
        "domain": domain,
        "spoof_score": score,
        "verdict": str(verdict),
        "spf": spf,
        "dkim": {**dkim, "selectors": dkim["selectors"]},
        "dmarc": dmarc,
        "mx": mx,
        "bimi": bimi,
        "ts": datetime.now().isoformat(),
    }
    _save(domain, report)
