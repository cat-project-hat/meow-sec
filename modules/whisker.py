# -*- coding: utf-8 -*-
"""
MEOW-SEC :: WHISKER — DNS / WHOIS / IP OSINT
Inspired by recon-ng / fierce — built from scratch
"""
import socket, json, os, re, time
from datetime import datetime

from core.ui import console, ok, err, info, warn, find, boot_progress, print_result_table, show_module_banner, ask_target, ask_choice, G1, G2, CY, OR, RD, DM
from core.cats import CAT_RECON, cat_talk
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── DNS RECORD TYPES ────────────────────────────────────────
DNS_TYPES = {
    "A":     1,
    "NS":    2,
    "CNAME": 5,
    "MX":    15,
    "TXT":   16,
    "AAAA":  28,
}

# ─── IP GEOLOCATION via ip-api.com (free, no key needed) ─────
def geoip(ip: str) -> dict:
    if not HAS_REQUESTS:
        return {}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}

# ─── DNS LOOKUP ──────────────────────────────────────────────
def dns_lookup(host: str) -> dict:
    results = {}

    # A record
    try:
        ips = socket.getaddrinfo(host, None, socket.AF_INET)
        results["A"] = list({addr[4][0] for addr in ips})
    except Exception:
        results["A"] = []

    # AAAA
    try:
        ips6 = socket.getaddrinfo(host, None, socket.AF_INET6)
        results["AAAA"] = list({addr[4][0] for addr in ips6})
    except Exception:
        results["AAAA"] = []

    # MX (via socket workaround or dnspython if available)
    results["MX"] = _dns_query(host, "MX")
    results["NS"] = _dns_query(host, "NS")
    results["TXT"] = _dns_query(host, "TXT")

    # Reverse DNS
    rev_ips = []
    for ip in results.get("A", []):
        try:
            host_rev = socket.gethostbyaddr(ip)[0]
            rev_ips.append(f"{ip} → {host_rev}")
        except Exception:
            rev_ips.append(ip)
    results["PTR"] = rev_ips

    return results

def _dns_query(host: str, qtype: str) -> list:
    """DNS query via Google DoH (DNS-over-HTTPS) — pas besoin de dnspython"""
    if not HAS_REQUESTS:
        return []
    try:
        r = requests.get(
            "https://dns.google/resolve",
            params={"name": host, "type": qtype},
            timeout=5,
            headers={"Accept": "application/dns-json"}
        )
        if r.status_code == 200:
            data = r.json()
            answers = data.get("Answer", [])
            return [a["data"] for a in answers]
    except Exception:
        pass
    return []

# ─── WHOIS (via whois.iana.org ou whois API) ─────────────────
def whois_lookup(domain: str) -> dict:
    """WHOIS via whois.iana.org raw socket"""
    result = {"raw": "", "registrar": "", "created": "", "expires": "", "nameservers": []}
    try:
        # Tente whois.iana.org pour obtenir le bon serveur
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect(("whois.iana.org", 43))
        s.send((domain.split(".")[-1] + "\r\n").encode())
        refer = s.recv(4096).decode(errors="ignore")
        s.close()

        # Cherche le serveur whois référent
        whois_server = None
        for line in refer.split("\n"):
            if line.lower().startswith("whois:"):
                whois_server = line.split(":", 1)[1].strip()
                break

        if whois_server:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect((whois_server, 43))
            s.send((domain + "\r\n").encode())
            raw = ""
            while True:
                chunk = s.recv(4096).decode(errors="ignore")
                if not chunk: break
                raw += chunk
            s.close()
            result["raw"] = raw[:3000]
            result["registrar"]   = _extract(raw, r"Registrar:\s*(.+)")
            result["created"]     = _extract(raw, r"Creation Date:\s*(.+)")
            result["expires"]     = _extract(raw, r"Expiry Date:\s*(.+)|Registry Expiry Date:\s*(.+)")
            nss = re.findall(r"Name Server:\s*(.+)", raw, re.I)
            result["nameservers"] = [n.strip().lower() for n in nss][:8]

    except Exception as e:
        result["error"] = str(e)

    return result

def _extract(text: str, pattern: str) -> str:
    m = re.search(pattern, text, re.I)
    if m:
        val = next((g for g in m.groups() if g), "")
        return val.strip()[:80]
    return ""

# ─── IP INFO ─────────────────────────────────────────────────
def ip_info(ip: str) -> dict:
    geo = geoip(ip)
    result = {}
    if geo and geo.get("status") == "success":
        result = {
            "ip":       ip,
            "country":  f"{geo.get('country','')} ({geo.get('countryCode','')})",
            "region":   geo.get("regionName", ""),
            "city":     geo.get("city", ""),
            "ISP":      geo.get("isp", ""),
            "org":      geo.get("org", ""),
            "AS":       geo.get("as", ""),
            "timezone": geo.get("timezone", ""),
            "hosting":  "YES" if geo.get("hosting") else "no",
            "proxy":    "YES" if geo.get("proxy") else "no",
        }
    return result

# ─── MAIN WHISKER ────────────────────────────────────────────

def run(target: str = None):
    show_module_banner("whisker")
    cat_talk(CAT_RECON, "WHISKER OSINT sensors active — sniffing the network...", OR)
    console.print()

    if not target:
        target = ask_target("Target domain or IP")
    if not target:
        err("No target."); return

    # Nettoyage
    target = re.sub(r"https?://", "", target).split("/")[0].strip()
    info(f"Target: [{CY}]{target}[/]")
    console.print()

    # Mode
    console.print(f"  [{G1}][1][/] Full recon   (DNS + WHOIS + GeoIP)")
    console.print(f"  [{G1}][2][/] DNS only")
    console.print(f"  [{G1}][3][/] WHOIS only")
    console.print(f"  [{G1}][4][/] GeoIP only")
    console.print(f"  [{G1}][5][/] Zone transfer (AXFR)")
    console.print(f"  [{G1}][6][/] Certificate Transparency (crt.sh subdomains)")
    console.print(f"  [{G1}][7][/] Full recon + AXFR + crt.sh")
    mode = ask_choice("Mode", "1")

    boot_progress([
        "Wiring whiskers...",
        "DNS resolution...",
        "WHOIS query...",
        "GeoIP lookup...",
        "Correlating data...",
    ])

    console.print()
    from rich.rule import Rule

    is_ip = _is_ip(target)

    # ── DNS ──
    if mode in ("1", "2") and not is_ip:
        console.print(Rule(f"[{G1}] DNS RECORDS ", style=G2))
        dns = dns_lookup(target)
        rows = []
        for rtype, values in dns.items():
            for v in (values if isinstance(values, list) else [values]):
                rows.append((rtype, v))
                if rtype in ("A",):
                    find(f"[{CY}]{rtype}[/]  →  [{G1}]{v}[/]")
                else:
                    info(f"[{CY}]{rtype}[/]  →  {v}")
        if rows:
            print_result_table("DNS Records", ["TYPE", "VALUE"], rows)

    # ── IP info (pour chaque A record) ──
    ips_to_check = []
    if is_ip:
        ips_to_check = [target]
    elif mode in ("1", "2"):
        ips_to_check = dns.get("A", [])

    if mode in ("1", "4") and ips_to_check:
        console.print(Rule(f"[{G1}] GEO / IP INFO ", style=G2))
        for ip in ips_to_check[:3]:
            info(f"GeoIP for [{CY}]{ip}[/]...")
            geo = ip_info(ip)
            if geo:
                rows = list(geo.items())
                print_result_table(f"IP Info :: {ip}",
                    ["FIELD", "VALUE"], rows)
                if geo.get("proxy") == "YES" or geo.get("hosting") == "YES":
                    warn(f"[{ip}] → Proxy/VPN/Hosting detected!")

    # ── WHOIS ──
    if mode in ("1", "3") and not is_ip:
        console.print(Rule(f"[{G1}] WHOIS ", style=G2))
        info(f"WHOIS query for [{CY}]{target}[/]...")
        w = whois_lookup(target)
        if "error" not in w:
            rows = [
                ("Registrar",    w.get("registrar", "N/A")),
                ("Created",      w.get("created",   "N/A")),
                ("Expires",      w.get("expires",   "N/A")),
                ("Nameservers",  ", ".join(w.get("nameservers", []))),
            ]
            print_result_table("WHOIS Summary", ["FIELD", "VALUE"], rows)

            if w.get("raw"):
                from rich.syntax import Syntax
                console.print(Panel(
                    w["raw"][:800],
                    title=f"[{G1}]WHOIS RAW (truncated)",
                    border_style=G2
                ))
        else:
            warn(f"WHOIS failed: {w.get('error')}")

    # ── ZONE TRANSFER ──
    if mode in ("5", "7") and not is_ip:
        from rich.rule import Rule
        console.print(Rule(f"[{RD}] ZONE TRANSFER (AXFR) ", style=G2))
        warn("Zone transfer testing — use only on authorized targets")
        zr = zone_transfer(target)
        if zr.get("vulnerable"):
            find(f"[{RD}]VULNERABLE[/] — zone transfer succeeded on {len(zr['records'])} nameserver(s)")
            for rec in zr["records"]:
                find(f"  NS: [{CY}]{rec['ns']}[/]  ({rec['ns_ip']})  —  {rec['raw_bytes']} bytes")
        else:
            ok("Zone transfer refused — target appears safe")

    # ── CERT TRANSPARENCY ──
    if mode in ("6", "7") and not is_ip:
        from rich.rule import Rule
        console.print(Rule(f"[{CY}] CERTIFICATE TRANSPARENCY ", style=G2))
        info(f"Querying crt.sh for [{CY}]{target}[/]...")
        subs = crt_sh_lookup(target)
        if subs:
            find(f"Found [{G1}]{len(subs)}[/] subdomains in CT logs")
            rows = [(s["subdomain"], s["not_after"], s["issuer"][:40]) for s in subs[:60]]
            print_result_table(f"CT Subdomains :: {target}",
                               ["Subdomain", "Expiry", "Issuer"], rows)
        else:
            warn("No results from crt.sh.")

    # Sauvegarde
    _save(target, mode)

# ─── ZONE TRANSFER (AXFR) ────────────────────────────────────

def zone_transfer(domain: str) -> dict:
    """Tente un transfert de zone AXFR sur chaque nameserver du domaine"""
    results = {"domain": domain, "nameservers": [], "records": [], "vulnerable": False}
    ns_list = _dns_query(domain, "NS")
    if not ns_list:
        return {**results, "error": "No NS records found"}
    results["nameservers"] = ns_list

    for ns in ns_list:
        ns_ip = None
        try:
            ns_ip = socket.gethostbyname(ns.rstrip("."))
        except Exception:
            continue
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(6)
            sock.connect((ns_ip, 53))
            # Build AXFR query (RFC 1035)
            qname = b""
            for part in domain.split("."):
                qname += bytes([len(part)]) + part.encode()
            qname += b"\x00"
            query = (
                b"\x00\x01"   # txid
                b"\x00\x00"   # flags: standard query
                b"\x00\x01"   # QDCOUNT=1
                b"\x00\x00"   # ANCOUNT
                b"\x00\x00"   # NSCOUNT
                b"\x00\x00"   # ARCOUNT
                + qname
                + b"\x00\xfc" # QTYPE=AXFR (252)
                + b"\x00\x01" # QCLASS=IN
            )
            length = len(query).to_bytes(2, "big")
            sock.sendall(length + query)
            data = b""
            sock.settimeout(8)
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            sock.close()
            if len(data) > 20:
                results["vulnerable"] = True
                results["records"].append({
                    "ns": ns, "ns_ip": ns_ip,
                    "raw_bytes": len(data),
                    "note": "AXFR returned data — zone transfer possible"
                })
                find(f"AXFR SUCCESS on [{CY}]{ns}[/] ({ns_ip}) — {len(data)} bytes returned")
            else:
                info(f"  [{DM}]AXFR refused by {ns} ({ns_ip})[/]")
        except Exception as e:
            info(f"  [{DM}]AXFR error on {ns}: {e}[/]")
    return results

# ─── CERTIFICATE TRANSPARENCY (crt.sh) ───────────────────────

def crt_sh_lookup(domain: str) -> list:
    """Sous-domaines via crt.sh — sans clé API"""
    if not HAS_REQUESTS:
        err("requests not installed"); return []
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (MEOW-SEC/1.1)"}
        )
        if r.status_code != 200:
            warn(f"crt.sh returned HTTP {r.status_code}"); return []
        entries = r.json()
        seen = set()
        subs = []
        for e in entries[:200]:
            for name in e.get("name_value","").split("\n"):
                name = name.strip().lstrip("*.")
                if name and name not in seen and domain in name:
                    seen.add(name)
                    subs.append({
                        "subdomain": name,
                        "issuer":    e.get("issuer_name","?")[:50],
                        "not_after": e.get("not_after","?")[:10],
                        "id":        e.get("id",""),
                    })
        return subs
    except Exception as e:
        err(f"crt.sh error: {e}"); return []

def _is_ip(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))

def _save(target, mode):
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out_dir, exist_ok=True)
    fname = os.path.join(out_dir, f"whisker_{target.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w") as f:
        json.dump({"target": target, "mode": mode, "time": datetime.now().isoformat()}, f)
    ok(f"Scan logged → [{CY}]{os.path.basename(fname)}[/]")
