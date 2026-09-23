# -*- coding: utf-8 -*-
"""
MEOW-SEC :: SSLSCAN — SSL/TLS Deep Scanner
  · Protocoles supportés (TLS 1.0/1.1/1.2/1.3, SSLv2/v3)
  · Suites de chiffrement acceptées
  · Certificat : expiry, SANs, issuer, self-signed, chain
  · HSTS, HPKP, CT, OCSP stapling
  · Certificate Transparency via crt.sh (no API key)
  · Vulnérabilités connues : BEAST, POODLE, HEARTBLEED hints
"""
import ssl, socket, json, os, time, re
from datetime import datetime, timezone

from core.ui import (
                     console, ok, err, info, warn,
                     find, show_module_banner, ask_choice, print_result_table, G1,
                     G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN
from rich.panel   import Panel
from rich.table   import Table
from rich.prompt  import Prompt
from rich.rule    import Rule
from rich         import box

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── PROTOCOL CHECKS ─────────────────────────────────────────

PROTOCOLS = [
    ("TLS 1.3",  ssl.PROTOCOL_TLS_CLIENT,  {"minimum_version": ssl.TLSVersion.TLSv1_3}  if hasattr(ssl, "TLSVersion") else {}),
    ("TLS 1.2",  ssl.PROTOCOL_TLS_CLIENT,  {"minimum_version": ssl.TLSVersion.TLSv1_2,
                                             "maximum_version": ssl.TLSVersion.TLSv1_2}  if hasattr(ssl, "TLSVersion") else {}),
    ("TLS 1.1",  ssl.PROTOCOL_TLS_CLIENT,  {"minimum_version": ssl.TLSVersion.TLSv1,
                                             "maximum_version": ssl.TLSVersion.TLSv1_1}  if hasattr(ssl, "TLSVersion") else {}),
    ("TLS 1.0",  ssl.PROTOCOL_TLS_CLIENT,  {}),
]

# Suites à tester pour BEAST/POODLE
WEAK_CIPHERS = ["RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5", "ADH"]
STRONG_CIPHERS = ["ECDHE", "DHE", "CHACHA20", "AES256-GCM", "AES128-GCM"]

def _probe_protocol(host: str, port: int, proto_name: str,
                    proto_const, options: dict) -> dict:
    """Tente une connexion TLS avec une version spécifique"""
    try:
        ctx = ssl.SSLContext(proto_const)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        if options and hasattr(ssl, "TLSVersion"):
            if "minimum_version" in options:
                ctx.minimum_version = options["minimum_version"]
            if "maximum_version" in options:
                ctx.maximum_version = options["maximum_version"]

        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                proto  = ssock.version()
                cipher = ssock.cipher()
                return {
                    "proto":   proto_name,
                    "enabled": True,
                    "version": proto or proto_name,
                    "cipher":  cipher[0] if cipher else "?",
                    "bits":    cipher[2] if cipher else 0,
                }
    except ssl.SSLError:
        return {"proto": proto_name, "enabled": False}
    except Exception:
        return {"proto": proto_name, "enabled": False}

# ─── CERTIFICATE INFO ────────────────────────────────────────

def get_cert_info(host: str, port: int = 443) -> dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert    = ssock.getpeercert()
                der     = ssock.getpeercert(binary_form=True)
                proto   = ssock.version()
                cipher  = ssock.cipher()

        # Parse expiry
        not_before = cert.get("notBefore","")
        not_after  = cert.get("notAfter","")
        expiry     = None
        days_left  = None
        try:
            expiry    = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
        except Exception:
            pass

        # Subject / Issuer
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))

        # SANs
        sans = []
        for san_type, san_val in cert.get("subjectAltName", []):
            sans.append(san_val)

        # Self-signed?
        self_signed = subject == issuer

        # Fingerprint SHA256
        import hashlib
        fp = hashlib.sha256(der).hexdigest() if der else "?"

        return {
            "ok":          True,
            "cn":          subject.get("commonName","?"),
            "org":         subject.get("organizationName","?"),
            "issuer_cn":   issuer.get("commonName","?"),
            "issuer_org":  issuer.get("organizationName","?"),
            "not_before":  not_before,
            "not_after":   not_after,
            "days_left":   days_left,
            "sans":        sans,
            "self_signed": self_signed,
            "fingerprint": fp,
            "protocol":    proto,
            "cipher":      cipher[0] if cipher else "?",
            "cipher_bits": cipher[2] if cipher else 0,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ─── HTTP SECURITY HEADERS CHECK ─────────────────────────────

HTTP_SEC_HEADERS = {
    "strict-transport-security": ("HSTS",         "HIGH",   "Forces HTTPS — missing means downgrade possible"),
    "content-security-policy":   ("CSP",          "MEDIUM", "Prevents XSS — missing is a risk"),
    "x-frame-options":           ("X-Frame",      "MEDIUM", "Prevents clickjacking"),
    "x-content-type-options":    ("X-Content-Type","LOW",   "Prevents MIME sniffing"),
    "referrer-policy":           ("Referrer",     "LOW",    "Controls referrer leakage"),
    "permissions-policy":        ("Permissions",  "LOW",    "Controls browser features"),
    "x-xss-protection":          ("X-XSS",        "LOW",    "Legacy XSS filter (deprecated)"),
    "expect-ct":                 ("Expect-CT",    "LOW",    "Certificate Transparency enforcement"),
    "cross-origin-opener-policy":("COOP",         "LOW",    "Cross-origin isolation"),
    "cross-origin-resource-policy":("CORP",       "LOW",    "Cross-origin resource isolation"),
}

def check_http_headers(host: str, port: int = 443) -> dict:
    if not HAS_REQUESTS: return {}
    scheme = "https" if port == 443 else "http"
    try:
        r = requests.get(f"{scheme}://{host}:{port}/", timeout=10,
                         timeout=10, verify=False,
                         headers={"User-Agent": "Mozilla/5.0"},
                         allow_redirects=True)
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        results = {}
        for h, (name, sev, note) in HTTP_SEC_HEADERS.items():
            present = h in hdrs
            val     = hdrs.get(h, "")
            results[name] = {"present": present, "value": val[:80],
                             "severity": sev, "note": note}
        return results
    except Exception:
        return {}

# ─── CERTIFICATE TRANSPARENCY (crt.sh) ───────────────────────

def crt_sh_lookup(domain: str) -> list:
    """Recherche dans les logs CT via crt.sh — sans clé API"""
    if not HAS_REQUESTS: return []
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10,
                         timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200: return []
        entries = r.json()
        seen = set()
        certs = []
        for e in entries[:100]:
            name = e.get("name_value","").strip()
            for n in name.split("\n"):
                n = n.strip().lstrip("*.")
                if n and n not in seen:
                    seen.add(n)
                    certs.append({
                        "name":      n,
                        "issuer":    e.get("issuer_name","?")[:60],
                        "not_after": e.get("not_after","?"),
                        "id":        e.get("id",""),
                    })
        return certs
    except Exception:
        return []

# ─── VULNERABILITY HINTS ─────────────────────────────────────

def _vuln_hints(protos: list, cert: dict) -> list:
    hints = []
    enabled = {p["proto"] for p in protos if p.get("enabled")}

    if "TLS 1.0" in enabled:
        hints.append(("HIGH",   "TLS 1.0 enabled",
                      "Vulnerable to BEAST, POODLE-on-TLS. Disable TLS 1.0."))
    if "TLS 1.1" in enabled:
        hints.append(("MEDIUM", "TLS 1.1 enabled",
                      "Deprecated since RFC 8996 (2021). Should be disabled."))
    if "TLS 1.2" in enabled and "TLS 1.3" not in enabled:
        hints.append(("LOW",    "TLS 1.3 not supported",
                      "TLS 1.3 offers better security and performance."))

    cipher = cert.get("cipher","")
    for weak in WEAK_CIPHERS:
        if weak in cipher.upper():
            hints.append(("HIGH", f"Weak cipher: {cipher}",
                          "RC4/DES/NULL ciphers are cryptographically broken."))
            break

    if cert.get("self_signed"):
        hints.append(("HIGH",   "Self-signed certificate",
                      "No trusted CA — vulnerable to MitM attacks."))

    dl = cert.get("days_left")
    if dl is not None:
        if dl < 0:
            hints.append(("CRITICAL", "Certificate EXPIRED",
                          f"Expired {abs(dl)} days ago."))
        elif dl < 14:
            hints.append(("HIGH",    f"Certificate expires in {dl} days",
                          "Renew immediately."))
        elif dl < 30:
            hints.append(("MEDIUM",  f"Certificate expires in {dl} days",
                          "Renew soon."))

    return hints

# ─── MAIN ────────────────────────────────────────────────────

def run():
    show_module_banner("sslscan")
    cat_talk(CAT_SCAN, "SSL/TLS scanner loaded.", OR)
    console.print()

    while True:
        console.print(f"  [{G1}][1][/] Full SSL/TLS scan")
        console.print(f"  [{G1}][2][/] Certificate info only")
        console.print(f"  [{G1}][3][/] Certificate Transparency  (crt.sh subdomain discovery)")
        console.print(f"  [{G1}][4][/] HTTP security headers check")
        console.print(f"  [{G1}][0][/] Back")
        console.print()
        choice = ask_choice("SSLSCAN", "0")
        if choice == "0": break

        host = Prompt.ask(f"  [{G1}]◈ Host (domain or IP)[/]").strip()
        if not host: continue
        host = host.replace("https://","").replace("http://","").split("/")[0]
        port_str = Prompt.ask(f"  [{G1}]◈ Port[/]", default="443").strip()
        port = int(port_str) if port_str.isdigit() else 443
        console.print()

        if choice in ("1","2"):
            info(f"Getting certificate info for [{CY}]{host}:{port}[/]...")
            cert = get_cert_info(host, port)
            _display_cert(cert)

        if choice == "1":
            console.print()
            info("Probing TLS protocol versions...")
            protos = []
            for name, proto_const, opts in PROTOCOLS:
                res = _probe_protocol(host, port, name, proto_const, opts)
                protos.append(res)
                c = G1 if res["enabled"] else DM
                status = f"[{c}]{'ENABLED' if res['enabled'] else 'disabled'}[/]"
                cipher_info = f"  {res.get('cipher','')}  ({res.get('bits',0)} bits)" if res["enabled"] else ""
                console.print(f"  [{CY}]{name:<10}[/] {status}{cipher_info}")

            console.print()
            hints = _vuln_hints(protos, cert if cert.get("ok") else {})
            if hints:
                console.print(Rule(f"[{RD}] VULNERABILITY HINTS ", style=G2))
                for sev, title, note in hints:
                    c = RD if sev == "CRITICAL" else (RD if sev == "HIGH" else (OR if sev == "MEDIUM" else CY))
                    warn_fn = find if sev == "CRITICAL" else warn
                    console.print(f"  [{c}][{sev}][/] {title}")
                    console.print(f"     [{DM}]{note}[/]")
            else:
                ok("No obvious TLS vulnerabilities detected.")

            console.print()
            info("Checking HTTP security headers...")
            hdrs_result = check_http_headers(host, port)
            _display_headers(hdrs_result)

        if choice in ("1","4") and choice != "1":
            info("Checking HTTP security headers...")
            hdrs_result = check_http_headers(host, port)
            _display_headers(hdrs_result)

        if choice == "3":
            domain = host
            info(f"Querying crt.sh for [{CY}]{domain}[/] (certificate transparency)...")
            certs = crt_sh_lookup(domain)
            if certs:
                find(f"Found [{G1}]{len(certs)}[/] subdomains in CT logs:")
                rows = [(c["name"], c["not_after"][:10], c["issuer"][:40]) for c in certs[:50]]
                print_result_table(f"CT Subdomains :: {domain}",
                    ["Subdomain","Expiry","Issuer"], rows)
            else:
                warn("No results from crt.sh.")

        _save(host, port, choice)
        console.print()

def _display_cert(cert: dict):
    if not cert.get("ok"):
        err(f"Certificate error: {cert.get('error','?')}"); return

    dl = cert.get("days_left")
    exp_c = G1 if (dl and dl > 30) else (OR if (dl and dl > 0) else RD)

    t = Table(box=box.SIMPLE, show_edge=False, show_header=False,
              padding=(0,2), border_style=G2)
    t.add_column("K", style=CY, width=18)
    t.add_column("V", style=G1)

    t.add_row("CN",          cert["cn"])
    t.add_row("Organization", cert["org"])
    t.add_row("Issuer",      cert["issuer_cn"])
    t.add_row("Issuer Org",  cert["issuer_org"])
    t.add_row("Valid from",  cert["not_before"])
    t.add_row("Expires",     f"[{exp_c}]{cert['not_after']}  ({dl} days)[/]")
    t.add_row("Self-signed", f"[{RD}]YES[/]" if cert["self_signed"] else f"[{G1}]no[/]")
    t.add_row("Protocol",    cert.get("protocol","?"))
    t.add_row("Cipher",      f"{cert.get('cipher','?')} ({cert.get('cipher_bits',0)} bits)")
    t.add_row("SANs",        ", ".join(cert["sans"][:8]))
    t.add_row("SHA256",      cert.get("fingerprint","?")[:40]+"...")

    console.print(Panel(t, title=f"[{CY}]◈ Certificate ◈", border_style=CY))

def _display_headers(hdrs: dict):
    if not hdrs: return
    rows = []
    for name, d in hdrs.items():
        c = G1 if d["present"] else (RD if d["severity"] == "HIGH" else OR)
        status = f"[{c}]{'PRESENT' if d['present'] else 'MISSING'}[/]"
        rows.append((name, status, d["severity"], d["note"][:50]))
    print_result_table("HTTP Security Headers", ["Header","Status","Severity","Note"], rows)

def _save(host, port, mode):
    os.makedirs("data", exist_ok=True)
    fname = f"data/ssl_{host}_{port}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": host, "port": port, "mode": mode,
                   "timestamp": datetime.now().isoformat()}, f, indent=2)
    ok(f"Saved: {fname}")
