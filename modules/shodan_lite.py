# -*- coding: utf-8 -*-
"""MEOW-SEC :: SHODAN — Shodan-Lite IP Recon (no API key required)"""
import os, re, json, socket
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

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


def _lookup_ip(ip: str, timeout=8) -> dict:
    """Query internetdb.shodan.io for a single IP."""
    try:
        r = _req.get(f"https://internetdb.shodan.io/{ip}",
                     headers={"User-Agent": "MEOW-SHODAN/1.1"},
                     timeout=timeout, verify=True)
        if r.status_code == 200:
            data = r.json()
            data["ip"] = ip
            return data
        elif r.status_code == 404:
            return {"ip": ip, "ports": [], "cpes": [], "hostnames": [],
                    "tags": [], "vulns": [], "error": "no data"}
        else:
            return {"ip": ip, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"ip": ip, "error": str(e)[:60]}


def _resolve_domain(domain: str) -> list:
    """Resolve domain to IPs."""
    try:
        info_list = socket.getaddrinfo(domain, None)
        ips = list({r[4][0] for r in info_list})
        return ips
    except Exception:
        return []


def _cidr_to_ips(cidr: str) -> list:
    """Expand CIDR to list of IPs (up to /24 = 256)."""
    try:
        import ipaddress
        net = ipaddress.ip_network(cidr, strict=False)
        if net.num_addresses > 256:
            warn(f"CIDR too large ({net.num_addresses} IPs) — limiting to /24 (256)")
            net = ipaddress.ip_network(f"{str(net.network_address)}/24", strict=False)
        return [str(ip) for ip in net.hosts()]
    except Exception as e:
        err(f"Invalid CIDR: {e}")
        return []


def _crt_sh_lookup(domain: str, timeout=10) -> list:
    """Certificate transparency lookup via crt.sh."""
    try:
        r = _req.get(f"https://crt.sh/?q={domain}&output=json",
                     headers={"User-Agent": "MEOW-SHODAN/1.1"},
                     timeout=timeout, verify=True)
        if r.status_code == 200:
            certs = r.json()
            names = set()
            for c in certs:
                name_val = c.get("name_value", "")
                for n in name_val.split("\n"):
                    n = n.strip()
                    if n and not n.startswith("*"):
                        names.add(n)
            return list(names)[:30]
    except Exception:
        pass
    return []


def _display_ip(data: dict):
    """Display a single IP result."""
    ip = data.get("ip", "?")
    ports   = data.get("ports", [])
    cpes    = data.get("cpes", [])
    hostnames = data.get("hostnames", [])
    tags    = data.get("tags", [])
    vulns   = data.get("vulns", [])
    error   = data.get("error", "")

    if error and not ports:
        info(f"[{ip}] {error}")
        return

    has_vulns = len(vulns) > 0
    sev_color = RD if has_vulns else (OR if tags else G1)

    console.print(f"\n  [{sev_color}]◈ {ip}[/]")
    if ports:
        console.print(f"    [{CY}]Ports:[/] {', '.join(str(p) for p in ports)}")
    if hostnames:
        console.print(f"    [{G1}]Hostnames:[/] {', '.join(hostnames[:5])}")
    if cpes:
        console.print(f"    [{CY}]CPEs:[/] {', '.join(cpes[:3])}")
    if tags:
        console.print(f"    [{OR}]Tags:[/] {', '.join(tags)}")
    if vulns:
        find(f"CVEs on {ip}: [{RD}]{', '.join(vulns[:5])}[/]")


def run():
    show_module_banner("shodan")
    cat_talk(CAT_SCAN, "Shodan-Lite recon — no API key (internetdb.shodan.io)", G1)
    console.print()
    warn("AUTHORIZED USE ONLY — Unauthorized testing is illegal.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    if not HAS_REQUESTS:
        err("requests library not available. Install it: pip install requests"); return

    console.print(f"\n  [{G1}][1][/] Single IP lookup")
    console.print(f"  [{G1}][2][/] CIDR range scan (up to /24)")
    console.print(f"  [{G1}][3][/] Domain to IP + lookup")
    mode = Prompt.ask(f"  [{CY}]◈ Mode[/]", default="1").strip()

    all_results = []

    if mode == "1":
        ip = Prompt.ask(f"  [{G1}]◈ IP address[/]").strip()
        info(f"Looking up {ip}...")
        data = _lookup_ip(ip)
        _display_ip(data)
        all_results.append(data)

    elif mode == "2":
        cidr = Prompt.ask(f"  [{G1}]◈ CIDR range (e.g. 192.168.1.0/24)[/]").strip()
        ips  = _cidr_to_ips(cidr)
        if not ips:
            return
        threads = min(20, len(ips))
        info(f"Scanning {len(ips)} IPs with {threads} threads...")
        console.print()

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(_lookup_ip, ip): ip for ip in ips}
            done = 0
            for future in as_completed(futures):
                done += 1
                data = future.result()
                all_results.append(data)
                if data.get("ports") or data.get("vulns"):
                    _display_ip(data)
                if done % 20 == 0:
                    info(f"Progress: {done}/{len(ips)}")

        # Summary table
        console.print()
        found_ips = [d for d in all_results if d.get("ports")]
        if found_ips:
            t = Table(title=f"[{G1}]CIDR Scan Summary ({len(found_ips)} active IPs)[/]",
                      box=box.MINIMAL_DOUBLE_HEAD, border_style=G2, header_style=CY)
            t.add_column("IP",         min_width=16)
            t.add_column("Ports",      min_width=24)
            t.add_column("CVEs",       min_width=8)
            t.add_column("Tags",       min_width=16)
            t.add_column("Hostnames",  min_width=24)
            for d in found_ips[:40]:
                vuln_count = len(d.get("vulns", []))
                sc = RD if vuln_count > 0 else G1
                t.add_row(
                    f"[{sc}]{d['ip']}[/]",
                    ", ".join(str(p) for p in d.get("ports", [])[:6]),
                    f"[{RD}]{vuln_count}[/]" if vuln_count else "0",
                    ", ".join(d.get("tags", [])[:3]),
                    ", ".join(d.get("hostnames", [])[:2])
                )
            console.print(t)
        else:
            ok("No active IPs found in range.")

    elif mode == "3":
        domain = Prompt.ask(f"  [{G1}]◈ Domain name[/]").strip()
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        info(f"Resolving {domain}...")
        ips = _resolve_domain(domain)
        if not ips:
            err(f"Could not resolve {domain}"); return
        info(f"Resolved to: {', '.join(ips)}")

        for ip in ips:
            info(f"Looking up {ip}...")
            data = _lookup_ip(ip)
            _display_ip(data)
            all_results.append(data)

        # crt.sh cert transparency
        info(f"\nQuerying crt.sh certificate transparency for {domain}...")
        subdomains = _crt_sh_lookup(domain)
        if subdomains:
            find(f"crt.sh: {len(subdomains)} subdomain(s) via CT")
            t2 = Table(title=f"[{G1}]CT Subdomains[/]", box=box.SIMPLE,
                       border_style=G2, header_style=CY)
            t2.add_column("Subdomain", min_width=40)
            for s in subdomains[:20]:
                t2.add_row(s)
            console.print(t2)
        else:
            info("No CT subdomains found.")
        all_results.append({"crt_sh": subdomains})

    active = len([d for d in all_results if isinstance(d, dict) and d.get("ports")])
    if active:
        find(f"{active} active IP(s) with open ports found.")

    _save("shodan", "shodan_lite_scan", all_results)
