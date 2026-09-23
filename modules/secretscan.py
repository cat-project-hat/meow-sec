# -*- coding: utf-8 -*-
"""MEOW-SEC :: SECRETSCAN — Secret / Credential Scanner in HTTP Responses"""
import os, re, json
from datetime import datetime
from urllib.parse import urlparse, urljoin

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN
from rich.panel  import Panel
from rich.table  import Table
from rich.prompt import Prompt, Confirm, IntPrompt
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


_PATTERNS = [
    ("AWS Access Key",         r"AKIA[0-9A-Z]{16}",                                          "HIGH"),
    ("AWS Secret Key",         r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",                 "HIGH"),
    ("GitHub Token",           r"gh[pousr]_[A-Za-z0-9]{36,}",                                "HIGH"),
    ("Google API Key",         r"AIza[0-9A-Za-z\-_]{35}",                                    "HIGH"),
    ("JWT",                    r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*", "MEDIUM"),
    ("Private Key Header",     r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",           "HIGH"),
    ("Database URL",           r"(mysql|postgresql|mongodb|redis)://[^@\s]+@[^\s]+",          "HIGH"),
    ("Basic Auth in URL",      r"://[^:]+:[^@]+@[^/\s]+",                                    "HIGH"),
    ("Slack Token",            r"xox[baprs]-[0-9a-zA-Z]{10,48}",                             "HIGH"),
    ("Stripe Live Key",        r"sk_live_[0-9a-zA-Z]{24,}",                                  "HIGH"),
    ("Twilio SID",             r"AC[0-9a-fA-F]{32}",                                         "HIGH"),
    ("Password in JSON",       r'"password"\s*:\s*"[^"]{4,}"',                               "HIGH"),
    ("Secret/Token in JSON",   r'"(secret|token|api_key|apikey|auth_token)"\s*:\s*"[^"]{8,}"',"MEDIUM"),
    ("SendGrid Key",           r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}",             "HIGH"),
    ("Mailgun Key",            r"key-[0-9a-zA-Z]{32}",                                       "MEDIUM"),
]


def _scan_text(text: str, source_url: str) -> list:
    findings = []
    for name, pattern, sev in _PATTERNS:
        matches = re.finditer(pattern, text)
        for m in matches:
            val = m.group(0)[:40]
            findings.append({
                "url": source_url, "pattern": name,
                "value": val, "severity": sev
            })
    return findings


def _fetch_page(url, timeout=10):
    try:
        r = _req.get(url, verify=False, allow_redirects=True, timeout=timeout,
                     headers={"User-Agent": "MEOW-SECRETSCAN/1.1"})
        return r.text, r.status_code
    except Exception as e:
        return "", 0


def _crawl(base_url, max_pages=50, max_depth=2):
    """Simple BFS crawler, returns list of URLs visited."""
    from collections import deque
    visited = set()
    queue = deque([(base_url, 0)])
    pages = []

    parsed_base = urlparse(base_url)
    base_netloc = parsed_base.netloc

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        text, status = _fetch_page(url)
        if status == 200 and text:
            pages.append((url, text))
            if depth < max_depth:
                # Extract links
                hrefs = re.findall(r'href=["\']([^"\']+)["\']', text)
                for href in hrefs:
                    if href.startswith("http"):
                        abs_url = href
                    elif href.startswith("/"):
                        abs_url = f"{parsed_base.scheme}://{base_netloc}{href}"
                    else:
                        abs_url = urljoin(url, href)
                    parsed_link = urlparse(abs_url)
                    if parsed_link.netloc == base_netloc and abs_url not in visited:
                        queue.append((abs_url, depth + 1))
    return pages


def run():
    show_module_banner("secretscan")
    cat_talk(CAT_SCAN, "Secret & credential scanner in HTTP responses", OR)
    console.print()
    warn("AUTHORIZED USE ONLY — Unauthorized testing is illegal.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    if not HAS_REQUESTS:
        err("requests library not available. Install it: pip install requests"); return

    url = Prompt.ask(f"  [{G1}]◈ Target URL[/]").strip()
    if not url.startswith("http"):
        url = "https://" + url

    console.print(f"  [{G1}][1][/] Single URL scan")
    console.print(f"  [{G1}][2][/] Crawl mode (depth 2, max 50 pages)")
    mode = Prompt.ask(f"  [{CY}]◈ Mode[/]", default="1").strip()

    all_findings = []

    if mode == "2":
        info("Crawling... this may take a while")
        pages = _crawl(url)
        info(f"Crawled {len(pages)} page(s)")
        for page_url, text in pages:
            findings = _scan_text(text, page_url)
            if findings:
                find(f"{len(findings)} secret(s) in {page_url}")
            all_findings.extend(findings)
    else:
        text, status = _fetch_page(url)
        if status == 0:
            err(f"Failed to fetch {url}"); return
        all_findings = _scan_text(text, url)

    console.print()
    if not all_findings:
        ok("No secrets found in responses.")
    else:
        t = Table(title=f"[{G1}]Secrets Found ({len(all_findings)})[/]",
                  box=box.MINIMAL_DOUBLE_HEAD, border_style=G2, header_style=CY)
        t.add_column("URL",      min_width=30)
        t.add_column("Pattern",  min_width=20)
        t.add_column("Value",    min_width=30)
        t.add_column("Severity", min_width=8)

        sev_colors = {"HIGH": RD, "MEDIUM": OR}
        for f in all_findings:
            sc = sev_colors.get(f["severity"], DM)
            t.add_row(f["url"][:40], f["pattern"],
                      f["value"], f"[{sc}]{f['severity']}[/]")
        console.print(t)

        highs = sum(1 for f in all_findings if f["severity"] == "HIGH")
        find(f"{len(all_findings)} secret(s) found — {highs} HIGH severity!")

    _save("secretscan", url, all_findings)
