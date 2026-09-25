# -*- coding: utf-8 -*-
"""
MEOW-SEC :: IPLOOKUP — IP / Domain Intelligence Lookup
For authorized security research only.
"""
import os, json, re, socket, ipaddress, concurrent.futures
from datetime import datetime
from urllib.parse import urlparse

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_target, ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

_UA = "MEOW-SEC/1.4 (authorized-research)"

# ─── HELPERS ──────────────────────────────────────────────────

def _req(url: str, **kwargs) -> dict:
    kwargs.setdefault("timeout", 8)
    kwargs.setdefault("verify", False)
    kwargs.setdefault("headers", {"User-Agent": _UA})
    try:
        r = requests.get(url, **kwargs)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}

def _clean_target(raw: str) -> str:
    """Extract IP or hostname from URL/domain string."""
    raw = raw.strip()
    if raw.startswith("http"):
        raw = urlparse(raw).netloc or raw
    return raw.split(":")[0].split("/")[0]

def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def _resolve(host: str) -> list:
    try:
        results = socket.getaddrinfo(host, None)
        return list({r[4][0] for r in results})
    except Exception:
        return []

# ─── PROVIDERS ────────────────────────────────────────────────

def _ip_api(ip: str) -> dict:
    """ip-api.com — free, no key, rich data."""
    d = _req(f"http://ip-api.com/json/{ip}?fields=66846719")
    if d.get("status") == "success":
        return {
            "provider": "ip-api.com",
            "ip":        d.get("query",""),
            "country":   d.get("country","?"),
            "country_code": d.get("countryCode","?"),
            "region":    d.get("regionName","?"),
            "city":      d.get("city","?"),
            "zip":       d.get("zip","?"),
            "lat":       d.get("lat","?"),
            "lon":       d.get("lon","?"),
            "timezone":  d.get("timezone","?"),
            "isp":       d.get("isp","?"),
            "org":       d.get("org","?"),
            "as":        d.get("as","?"),
            "asname":    d.get("asname","?"),
            "reverse":   d.get("reverse","?"),
            "mobile":    d.get("mobile", False),
            "proxy":     d.get("proxy", False),
            "hosting":   d.get("hosting", False),
        }
    return {}

def _ipinfo(ip: str) -> dict:
    """ipinfo.io — free tier, 50k req/month."""
    d = _req(f"https://ipinfo.io/{ip}/json")
    if d.get("ip"):
        return {
            "provider": "ipinfo.io",
            "ip":       d.get("ip",""),
            "hostname": d.get("hostname","?"),
            "city":     d.get("city","?"),
            "region":   d.get("region","?"),
            "country":  d.get("country","?"),
            "org":      d.get("org","?"),
            "postal":   d.get("postal","?"),
            "timezone": d.get("timezone","?"),
            "loc":      d.get("loc","?"),
        }
    return {}

def _shodan_lite(ip: str) -> dict:
    """Shodan InternetDB — free, no key."""
    d = _req(f"https://internetdb.shodan.io/{ip}")
    if d:
        return {
            "provider":   "shodan-internetdb",
            "ip":         d.get("ip",""),
            "ports":      d.get("ports", []),
            "cpes":       d.get("cpes", []),
            "hostnames":  d.get("hostnames", []),
            "tags":       d.get("tags", []),
            "vulns":      d.get("vulns", []),
        }
    return {}

def _abuseipdb(ip: str) -> dict:
    """AbuseIPDB check without API key — public confidence only via web scrape fallback."""
    # No-key endpoint
    d = _req(f"https://api.abuseipdb.com/api/v2/check",
             headers={"Key": "", "Accept": "application/json"},
             params={"ipAddress": ip, "maxAgeInDays": 90})
    if d.get("data"):
        data = d["data"]
        return {
            "provider":       "abuseipdb",
            "abuse_score":    data.get("abuseConfidenceScore", 0),
            "total_reports":  data.get("totalReports", 0),
            "country":        data.get("countryCode","?"),
            "isp":            data.get("isp","?"),
            "domain":         data.get("domain","?"),
            "is_tor":         data.get("isTor", False),
            "is_whitelist":   data.get("isWhitelisted", False),
        }
    return {}

def _bgp_tools(ip: str) -> dict:
    """bgp.tools — ASN / route / prefix info."""
    d = _req(f"https://bgp.tools/prefix/{ip}.json")
    if d:
        return {
            "provider": "bgp.tools",
            "asn":       d.get("asn","?"),
            "as_name":   d.get("as_name","?"),
            "prefix":    d.get("prefix","?"),
            "country":   d.get("country","?"),
            "rir":       d.get("rir","?"),
        }
    return {}

def _reverse_dns(ip: str) -> list:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return [host]
    except Exception:
        return []

def _whois_rdap(ip: str) -> dict:
    """RDAP whois via ARIN/RIPE/APNIC."""
    d = _req(f"https://rdap.arin.net/registry/ip/{ip}")
    if not d:
        d = _req(f"https://rdap.db.ripe.net/ip/{ip}")
    if d:
        name  = d.get("name","?")
        hdl   = d.get("handle","?")
        country = d.get("country", "")
        entities = d.get("entities",[])
        org = ""
        for e in entities:
            if "registrant" in e.get("roles",[]) or "technical" in e.get("roles",[]):
                try:
                    org = e["vcardArray"][1][1][3]
                except (IndexError, KeyError, TypeError):
                    org = ""
                break
        return {"provider":"rdap", "name": name, "handle": hdl, "country": country, "org": org}
    return {}

def _greynoise(ip: str) -> dict:
    """GreyNoise community API — no key required."""
    d = _req(f"https://api.greynoise.io/v3/community/{ip}")
    if d and d.get("ip"):
        return {
            "provider": "greynoise",
            "noise":     d.get("noise", False),      # True = internet scanner connu
            "riot":      d.get("riot", False),        # True = service légitime connu (Google, Cloudflare...)
            "classification": d.get("classification", "unknown"),  # benign/malicious/unknown
            "name":      d.get("name", ""),           # nom de l'organisation
            "link":      d.get("link", ""),
        }
    return {}

# ─── BATCH CIDR ───────────────────────────────────────────────

def _scan_cidr(cidr: str, workers: int = 50) -> list:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        err(f"Invalid CIDR: {e}"); return []

    hosts = list(net.hosts())
    if len(hosts) > 256:
        warn(f"Limiting to 256 IPs (CIDR has {len(hosts)})")
        hosts = hosts[:256]

    results = []
    def probe(ip):
        d = _ip_api(str(ip))
        if d:
            return d
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for i, result in enumerate(ex.map(probe, hosts)):
            if result:
                results.append(result)
                console.print(f"  [{G2}]{result['ip']:<18}[/]  {result.get('country_code','?'):<4}  "
                               f"{result.get('isp','?')[:40]}")
    return results

# ─── DISPLAY ──────────────────────────────────────────────────

def _print_geo(d: dict):
    if not d:
        return
    p = d.get("provider","")
    console.print(f"\n  [{CY}]── GeoIP ({p}) ──[/]")
    ok(f"  IP:       {d.get('ip','?')}")
    info(f"  Country:  {d.get('country','?')} ({d.get('country_code','?')})")
    info(f"  Region:   {d.get('region', d.get('regionName','?'))}")
    info(f"  City:     {d.get('city','?')}  ZIP: {d.get('zip', d.get('postal','?'))}")
    info(f"  Coords:   {d.get('lat','?')},{d.get('lon','?')}")
    info(f"  Timezone: {d.get('timezone','?')}")
    info(f"  ISP:      {d.get('isp','?')}")
    info(f"  Org:      {d.get('org','?')}")
    info(f"  AS:       {d.get('as', d.get('asn','?'))}  ({d.get('asname', d.get('as_name','?'))})")
    if d.get("mobile"):  warn("  Mobile connection")
    if d.get("proxy"):   warn("  Proxy / VPN detected")
    if d.get("hosting"): warn("  Hosting / datacenter IP")

def _print_shodan(d: dict):
    if not d:
        return
    console.print(f"\n  [{CY}]── Shodan InternetDB ──[/]")
    ports = d.get("ports",[])
    vulns = d.get("vulns",[])
    tags  = d.get("tags",[])
    if ports:   ok(f"  Open ports:   {ports}")
    if tags:    warn(f"  Tags:         {tags}")
    if d.get("cpes"): info(f"  CPEs:         {d.get('cpes',[][:3])}")
    if vulns:
        for v in vulns[:10]:
            find(f"  VULN: {v}")

def _print_abuse(d: dict):
    if not d:
        return
    console.print(f"\n  [{CY}]── AbuseIPDB ──[/]")
    score = d.get("abuse_score", 0)
    color = RD if score > 50 else OR if score > 10 else G1
    console.print(f"  Abuse score:  [{color}]{score}/100[/{color}]  ({d.get('total_reports',0)} reports)")
    if d.get("is_tor"): warn("  Tor exit node")
    if d.get("is_whitelist"): ok("  Whitelisted")

def _print_greynoise(d: dict):
    if not d: return
    console.print(f"\n  [{CY}]── GreyNoise ──[/]")
    if d.get("riot"):
        ok(f"  RIOT: {d.get('name','')} — known legitimate service")
    elif d.get("noise"):
        cls = d.get("classification","unknown")
        color = RD if cls == "malicious" else OR if cls == "unknown" else G1
        warn(f"  Noise: [{color}]{cls}[/] — {d.get('name','internet scanner')}")
    else:
        info(f"  Not seen in GreyNoise mass-scan data")

# ─── SAVE ─────────────────────────────────────────────────────

def _save(target: str, data: dict):
    os.makedirs("data", exist_ok=True)
    fname = f"data/iplookup_{target.replace('/','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    ok(f"Saved → {fname}")

# ─── MAIN ─────────────────────────────────────────────────────

def run():
    show_module_banner("iplookup")
    if not HAS_REQUESTS:
        err("requests not installed"); return

    console.print(f"\n  [{CY}]IP / Domain Intelligence Lookup[/]")
    console.print(f"  [{DM}]GeoIP · ASN · Shodan · AbuseIPDB · RDAP WHOIS · reverse DNS · CIDR scan[/]\n")

    console.print(f"  [{CY}]Mode:[/]")
    console.print(f"  [{G2}][1][/] Single IP or domain — full lookup")
    console.print(f"  [{G2}][2][/] CIDR range scan (up to /24)")
    console.print(f"  [{G2}][3][/] Bulk lookup from file (one IP/domain per line)")

    mode = ask_choice("Mode") or "1"

    if mode == "1":
        raw = ask_target("IP address or domain")
        if not raw:
            return
        target = _clean_target(raw)

        ip = target
        if not _is_ip(target):
            info(f"Resolving {target}...")
            ips = _resolve(target)
            if not ips:
                err(f"Cannot resolve {target}"); return
            ip = ips[0]
            info(f"Resolved: {ips}")

        console.print(f"\n  [{G1}]Target: {ip}[/]\n")

        all_data = {"target": target, "ip": ip}

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as _pool:
            _f_geo  = _pool.submit(_ip_api, ip)
            _f_geo2 = _pool.submit(_ipinfo, ip)
            _f_shod = _pool.submit(_shodan_lite, ip)
            _f_rdap = _pool.submit(_whois_rdap, ip)
            _f_rdns = _pool.submit(_reverse_dns, ip)
            _f_gn   = _pool.submit(_greynoise, ip)
            geo  = _f_geo.result()
            geo2 = _f_geo2.result()
            shod = _f_shod.result()
            rdap = _f_rdap.result()
            rdns = _f_rdns.result()
            gn   = _f_gn.result()
        abuse = _abuseipdb(ip)

        _print_geo(geo or geo2)
        _print_shodan(shod)
        _print_abuse(abuse)
        _print_greynoise(gn)

        if rdns:
            console.print(f"\n  [{CY}]── Reverse DNS ──[/]")
            info(f"  PTR: {rdns}")

        if rdap:
            console.print(f"\n  [{CY}]── RDAP WHOIS ──[/]")
            info(f"  Name: {rdap.get('name','?')}  Handle: {rdap.get('handle','?')}")

        # Maps link
        lat = (geo or geo2 or {}).get("lat") or (geo2 or {}).get("loc","").split(",")[0]
        lon = (geo or geo2 or {}).get("lon") or ((geo2 or {}).get("loc","").split(",")[1] if "," in (geo2 or {}).get("loc","") else "")
        if lat and lon:
            console.print(f"\n  [{DM}]Maps: https://maps.google.com/maps?q={lat},{lon}[/]")

        all_data.update({"geo": geo, "shodan": shod, "abuse": abuse, "rdap": rdap, "rdns": rdns, "greynoise": gn})
        _save(target, all_data)

    elif mode == "2":
        cidr = ask_target("CIDR range (e.g. 192.168.1.0/24)")
        if not cidr:
            return
        console.print(f"\n  [{G1}]Scanning {cidr}...[/]\n")
        results = _scan_cidr(cidr)
        if results:
            cat_talk(CAT_FOUND, f"{len(results)} hosts found in {cidr}")
            _save(cidr, {"cidr": cidr, "hosts": results})
        else:
            cat_talk(CAT_SCAN, "No hosts responded.")

    elif mode == "3":
        fpath = ask_target("File path (one IP or domain per line)")
        if not fpath or not os.path.isfile(fpath):
            err("File not found"); return
        with open(fpath) as f:
            targets = [l.strip() for l in f if l.strip()]
        info(f"Loaded {len(targets)} targets")
        all_results = []
        for t in targets[:100]:
            ip = t if _is_ip(t) else (_resolve(t) or [None])[0]
            if not ip:
                warn(f"Cannot resolve {t}"); continue
            geo = _ip_api(ip)
            if geo:
                console.print(f"  [{G2}]{ip:<18}[/]  {geo.get('country_code','?'):<4}  {geo.get('isp','?')[:40]}")
                all_results.append(geo)
        _save(fpath, {"targets": all_results})
