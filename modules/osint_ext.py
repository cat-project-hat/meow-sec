# -*- coding: utf-8 -*-
"""
MEOW-SEC :: OSINT+ — Extended OSINT Extensions
  · Email breach check (HaveIBeenPwned public API)
  · Email OSINT (MX, format validation, provider info)
  · Google Dork builder
  · IP reputation (AbuseIPDB public lookup)
  · Phone number analysis (region, carrier via pattern)
  · Pastebin / pastesearch
  · Shodan alternatives (Censys, Fofa, etc.)
"""
import re, os, json, time
from datetime import datetime

from core.ui import (console, ok, err, info, warn, find,
                     ask_choice, print_result_table,
                     G1, G2, CY, OR, RD, DM)
from core.cats import CAT_RECON, CAT_FOUND, cat_talk
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich import box

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── BANNER ──────────────────────────────────────────────────

def _banner():
    logo = Text(r"""
  ██████╗ ███████╗██╗███╗  ██╗████████╗ ██╗
 ██╔═══██╗██╔════╝██║████╗ ██║╚══██╔══╝ ╚█╗
 ██║   ██║███████╗██║██╔██╗██║   ██║    ██╔╝
 ██║   ██║╚════██║██║██║╚████║   ██║    ╚██╗
 ╚██████╔╝███████║██║██║ ╚███║   ██║     ╚█╝
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚══╝   ╚═╝
     [EXTENDED OSINT TOOLKIT]""", style=f"bold {G1}")
    console.print(Panel(Align(logo, align="center"), border_style=RD, padding=(0,1)))

# ─── EMAIL OSINT ─────────────────────────────────────────────

EMAIL_PROVIDERS = {
    "gmail.com":     ("Google",     "commercial"),
    "yahoo.com":     ("Yahoo",      "commercial"),
    "outlook.com":   ("Microsoft",  "commercial"),
    "hotmail.com":   ("Microsoft",  "commercial"),
    "protonmail.com":("ProtonMail", "private/encrypted"),
    "proton.me":     ("ProtonMail", "private/encrypted"),
    "tutanota.com":  ("Tutanota",   "private/encrypted"),
    "pm.me":         ("ProtonMail", "private/encrypted"),
    "cock.li":       ("Cock.li",    "anonymous"),
    "guerrillamail.com": ("GuerrillaMail", "disposable"),
    "mailinator.com": ("Mailinator","disposable"),
    "tempmail.com":  ("TempMail",   "disposable"),
    "10minutemail.com": ("10min",   "disposable"),
    "yopmail.com":   ("YOPmail",    "disposable"),
}

def email_osint(email: str):
    """Analyse d'une adresse email"""
    console.print()
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] EMAIL OSINT :: {email} ", style=G2))

    if "@" not in email:
        err("Invalid email format."); return

    local, domain = email.rsplit("@", 1)

    # Infos de base
    rows = [
        ("Local part",     local),
        ("Domain",         domain),
        ("Format valid",   "YES" if re.match(r"^[a-zA-Z0-9._%+\-]+$", local) else "NO"),
    ]

    # Provider
    if domain.lower() in EMAIL_PROVIDERS:
        provider, ptype = EMAIL_PROVIDERS[domain.lower()]
        rows.append(("Provider",   provider))
        rows.append(("Type",       ptype))
        if ptype == "disposable":
            warn(f"Disposable email provider detected: [{OR}]{provider}[/]")
        elif ptype == "private/encrypted":
            warn(f"Privacy-focused provider: [{CY}]{provider}[/]")

    print_result_table("Email Analysis", ["Field", "Value"], rows)

    # MX lookup
    info("Checking MX records...")
    mx = _dns_mx(domain)
    if mx:
        mx_rows = [(f"MX {i+1}", m) for i, m in enumerate(mx)]
        print_result_table("MX Records", ["Type", "Server"], mx_rows)

    # HIBP check
    _hibp_check(email)

def _dns_mx(domain: str) -> list:
    """MX lookup via Google DoH"""
    if not HAS_REQUESTS:
        return []
    try:
        r = requests.get("https://dns.google/resolve",
                         params={"name": domain, "type": "MX"},
                         timeout=5, headers={"Accept": "application/dns-json"})
        if r.status_code == 200:
            answers = r.json().get("Answer", [])
            return [a["data"].split(" ", 1)[-1].strip(".") for a in answers]
    except Exception:
        pass
    return []

def _hibp_check(email: str):
    """HaveIBeenPwned — API v3 (sans clé pour la version basique)"""
    info("Checking HaveIBeenPwned...")
    if not HAS_REQUESTS:
        warn("requests not available."); return
    try:
        # HIBP v3 requiert une clé API pour les emails maintenant.
        # On utilise l'endpoint public pour les passwords (k-anonymity)
        # et on informe l'utilisateur pour les breaches email.
        warn(f"[{OR}]HIBP email breach check requires an API key.[/]")
        info(f"Check manually: [bold {CY}]https://haveibeenpwned.com/account/{email}[/]")
        info(f"Free API key:   [{CY}]https://haveibeenpwned.com/API/Key[/]")
    except Exception as e:
        err(f"HIBP check failed: {e}")

# ─── PASSWORD HASH CHECK (k-anonymity) ───────────────────────

def check_password_pwned(password: str):
    """Vérifie si un hash de mot de passe est dans les bases HIBP (k-anonymity)"""
    import hashlib
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    if not HAS_REQUESTS:
        err("requests not available."); return

    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}",
                         timeout=8, headers={"User-Agent": "MEOW-SEC/1.0"})
        if r.status_code == 200:
            lines = r.text.splitlines()
            for line in lines:
                h, count = line.split(":")
                if h == suffix:
                    warn(f"Password found in [{RD}]{count}[/] breach(es)!")
                    return int(count)
            ok("Password NOT found in known breaches.")
            return 0
        else:
            err(f"HIBP API returned {r.status_code}")
    except Exception as e:
        err(f"Error: {e}")
    return -1

# ─── GOOGLE DORK BUILDER ─────────────────────────────────────

DORK_TEMPLATES = {
    "Login pages":         'site:{target} inurl:login OR inurl:signin OR inurl:admin',
    "Config files":        'site:{target} ext:conf OR ext:config OR ext:yaml OR ext:yml OR ext:env',
    "Database files":      'site:{target} ext:sql OR ext:db OR ext:sqlite',
    "Backup files":        'site:{target} ext:bak OR ext:backup OR ext:old OR ext:zip',
    "Git exposed":         'site:{target} inurl:.git',
    "PHP info":            'site:{target} inurl:phpinfo.php OR inurl:info.php',
    "Log files":           'site:{target} ext:log',
    "Password files":      'site:{target} inurl:password OR inurl:passwd OR inurl:credentials',
    "API keys":            'site:{target} "api_key" OR "apikey" OR "api-key" OR "secret_key"',
    "AWS keys":            'site:{target} "AKIA" OR "aws_access_key" OR "aws_secret"',
    "JWT tokens":          'site:{target} "eyJ" ext:json OR ext:txt OR ext:log',
    "Cameras":             'inurl:/view/view.shtml site:{target}',
    "Directory listing":   'site:{target} intitle:"Index of /"',
    "Error messages":      'site:{target} "mysql_fetch_array" OR "SQL syntax" OR "Warning: mysql"',
    "Open redirects":      'site:{target} inurl:redirect= OR inurl:url= OR inurl:goto=',
    "Subdomains":          'site:*.{target} -www',
    "PDF documents":       'site:{target} ext:pdf',
    "Word docs":           'site:{target} ext:doc OR ext:docx',
    "Excel sheets":        'site:{target} ext:xls OR ext:xlsx',
    "GitHub code":         'site:github.com "{target}"',
    "Pastebin leaks":      'site:pastebin.com "{target}"',
    "LinkedIn employees":  'site:linkedin.com "{target}" employees',
    "Shodan":              f'hostname:{{target}}',
}

def dork_builder(target: str = None):
    """Construit et affiche des Google Dorks pour une cible"""
    if not target:
        target = Prompt.ask(f"  [{G1}]◈ Target domain[/]").strip()
    if not target:
        return

    target = re.sub(r"https?://", "", target).rstrip("/")

    t = Table(
        title=f"[{G1}]GOOGLE DORKS :: {target}[/]",
        box=box.SIMPLE, border_style=G2, header_style=CY,
        show_lines=True
    )
    t.add_column("#",     style=DM, width=4)
    t.add_column("Name",  style=CY, width=22)
    t.add_column("Dork",  style=G1)

    for i, (name, tmpl) in enumerate(DORK_TEMPLATES.items(), 1):
        dork = tmpl.replace("{target}", target)
        t.add_row(str(i), name, dork)

    console.print(t)
    console.print()

    # Export option
    export = Prompt.ask(f"  [{G1}]◈ Export dorks to file? (y/n)[/]", default="y")
    if export.lower() == "y":
        _save_dorks(target)

def _save_dorks(target: str):
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out_dir, exist_ok=True)
    slug = target.replace(".", "_")
    fname = os.path.join(out_dir, f"dorks_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(fname, "w") as f:
        f.write(f"# MEOW-SEC Google Dorks for: {target}\n")
        f.write(f"# Generated: {datetime.now()}\n\n")
        for name, tmpl in DORK_TEMPLATES.items():
            dork = tmpl.replace("{target}", target)
            f.write(f"# {name}\n{dork}\n\n")
    ok(f"Dorks saved → [{CY}]{os.path.basename(fname)}[/]")

# ─── IP REPUTATION ───────────────────────────────────────────

def ip_reputation(ip: str):
    """Vérifie la réputation d'une IP via des sources publiques"""
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] IP REPUTATION :: {ip} ", style=G2))

    checks = []

    # AbuseIPDB (public check sans clé)
    if HAS_REQUESTS:
        info("Checking threat intelligence feeds...")

        # VirusTotal public (sans clé API)
        info(f"Check on VirusTotal: [{CY}]https://www.virustotal.com/gui/ip-address/{ip}[/]")
        info(f"Check on AbuseIPDB:  [{CY}]https://www.abuseipdb.com/check/{ip}[/]")
        info(f"Check on Shodan:     [{CY}]https://www.shodan.io/host/{ip}[/]")
        info(f"Check on Censys:     [{CY}]https://search.censys.io/hosts/{ip}[/]")

        # Tor exit node check (public list)
        try:
            r = requests.get("https://check.torproject.org/torbulkexitlist",
                             timeout=8, headers={"User-Agent": "MEOW-SEC/1.0"})
            if r.status_code == 200 and ip in r.text:
                warn(f"[{RD}]IP {ip} is a TOR EXIT NODE![/]")
                checks.append(("Tor Exit Node", "YES", "HIGH"))
            else:
                ok(f"Not a known Tor exit node.")
                checks.append(("Tor Exit Node", "NO", "INFO"))
        except Exception:
            checks.append(("Tor Exit Node", "CHECK FAILED", "N/A"))

        # Bogon / reserved range check
        if _is_bogon(ip):
            warn(f"IP {ip} is a BOGON/private range address!")
            checks.append(("Bogon/Private", "YES", "MEDIUM"))
        else:
            checks.append(("Bogon/Private", "NO", "INFO"))

        if checks:
            print_result_table(f"IP Reputation :: {ip}",
                ["CHECK", "RESULT", "SEVERITY"], checks, color_col=2)

def _is_bogon(ip: str) -> bool:
    """Vérifie si l'IP est dans une plage privée/réservée"""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        return False

# ─── PHONE OSINT ─────────────────────────────────────────────

COUNTRY_CODES = {
    "+1":   ("USA/Canada",  "NANP"),
    "+33":  ("France",      "Orange/SFR/Bouygues"),
    "+44":  ("UK",          "BT/Vodafone/O2"),
    "+49":  ("Germany",     "Deutsche Telekom/Vodafone"),
    "+7":   ("Russia/KZ",   "MTS/Beeline"),
    "+86":  ("China",       "China Mobile/Unicom"),
    "+81":  ("Japan",       "NTT/SoftBank"),
    "+91":  ("India",       "Jio/Airtel/Vi"),
    "+55":  ("Brazil",      "Claro/Vivo/TIM"),
    "+61":  ("Australia",   "Telstra/Optus"),
    "+34":  ("Spain",       "Movistar/Vodafone"),
    "+39":  ("Italy",       "TIM/Vodafone"),
    "+31":  ("Netherlands", "KPN/T-Mobile"),
    "+32":  ("Belgium",     "Proximus/Base"),
    "+41":  ("Switzerland", "Swisscom"),
    "+46":  ("Sweden",      "Telia/Tre"),
    "+47":  ("Norway",      "Telenor"),
    "+45":  ("Denmark",     "TDC/Telenor"),
    "+358": ("Finland",     "Elisa/Telia"),
    "+351": ("Portugal",    "NOS/MEO"),
    "+420": ("Czech Rep",   "T-Mobile/O2"),
    "+48":  ("Poland",      "Orange/Play"),
    "+380": ("Ukraine",     "Kyivstar/Vodafone"),
    "+90":  ("Turkey",      "Turkcell/Vodafone"),
    "+966": ("Saudi Arabia","STC/Mobily"),
    "+971": ("UAE",         "Etisalat/du"),
    "+20":  ("Egypt",       "Vodafone/Orange"),
    "+27":  ("South Africa","MTN/Vodacom"),
    "+82":  ("South Korea", "SK/KT/LGU+"),
    "+62":  ("Indonesia",   "Telkomsel"),
    "+52":  ("Mexico",      "Telcel/Movistar"),
    "+54":  ("Argentina",   "Claro/Personal"),
    "+57":  ("Colombia",    "Claro/Movistar"),
}

def phone_osint(phone: str):
    """Analyse d'un numéro de téléphone"""
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] PHONE OSINT ", style=G2))

    # Normalisation
    phone = re.sub(r"[\s\-\(\).]", "", phone)
    if not phone.startswith("+"):
        warn("Number should start with country code, e.g. +33612345678")

    rows = [("Raw input", phone)]

    # Détection du pays
    matched_cc = None
    matched_cc_len = 0
    for cc, (country, carriers) in COUNTRY_CODES.items():
        if phone.startswith(cc) and len(cc) > matched_cc_len:
            matched_cc = (cc, country, carriers)
            matched_cc_len = len(cc)

    if matched_cc:
        cc, country, carriers = matched_cc
        national = phone[len(cc):]
        rows += [
            ("Country code",    cc),
            ("Country",         country),
            ("National number", national),
            ("Possible carriers", carriers),
            ("Number length",   str(len(national))),
        ]
        find(f"Country: [{CY}]{country}[/]  carriers: [{OR}]{carriers}[/]")
    else:
        warn("Unknown country code.")
        rows.append(("Country code", "UNKNOWN"))

    print_result_table("Phone Analysis", ["Field", "Value"], rows)

    # Liens de vérification manuelle
    info("Manual OSINT links:")
    info(f"  NumLookup: [{CY}]https://www.numlookup.com/?number={phone}[/]")
    info(f"  PhoneInfoga: [{CY}]https://phoneinfoga.crvx.fr/[/]")
    info(f"  Truecaller: [{CY}]https://www.truecaller.com/search/{phone}[/]")

# ─── PASTEBIN SEARCH ─────────────────────────────────────────

def paste_search(query: str):
    """Recherche dans les pastes publics"""
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] PASTE SEARCH :: {query} ", style=G2))

    info("Paste search engines:")
    info(f"  Pastebin:    [{CY}]https://pastebin.com/search?q={query.replace(' ','+')}[/]")
    info(f"  PasteBin.pl: [{CY}]https://pastebin.pl/search?q={query.replace(' ','+')}[/]")
    info(f"  GitHub:      [{CY}]https://github.com/search?q={query.replace(' ','+')}+password&type=code[/]")
    info(f"  Psbdmp:      [{CY}]https://psbdmp.ws/search/{query.replace(' ','+')}[/]")
    info(f"  Dumpster:    [{CY}]https://www.dumpsterdiving.no/search?query={query.replace(' ','+')}[/]")

    if HAS_REQUESTS:
        # Psbdmp a une API publique
        try:
            r = requests.get(f"https://psbdmp.ws/api/search/{query}",
                             timeout=10, headers={"User-Agent": "MEOW-SEC/1.0"})
            if r.status_code == 200:
                data = r.json()
                results = data.get("data", [])
                if results:
                    find(f"{len(results)} paste(s) found on psbdmp!")
                    rows = [(p.get("id",""), p.get("title","")[:50], p.get("time","")) for p in results[:10]]
                    print_result_table("Paste Results (psbdmp)", ["ID","Title","Date"], rows)
                else:
                    info("No results on psbdmp.")
        except Exception as e:
            warn(f"psbdmp API error: {e}")

# ─── CENSYS / SHODAN ALTERNATIVE ─────────────────────────────

def search_engines_osint(target: str):
    """Liens vers les moteurs de recherche OSINT pour une cible"""
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] SEARCH ENGINES :: {target} ", style=G2))

    links = [
        ("Shodan",      f"https://www.shodan.io/search?query={target}"),
        ("Censys",      f"https://search.censys.io/search?resource=hosts&q={target}"),
        ("Fofa",        f"https://fofa.info/result?qbase64={_b64(f'host={target}')}"),
        ("BinaryEdge",  f"https://app.binaryedge.io/services/query?query={target}"),
        ("ZoomEye",     f"https://www.zoomeye.org/searchResult?q={target}"),
        ("GreyNoise",   f"https://viz.greynoise.io/ip/{target}"),
        ("Spyse",       f"https://spyse.com/target/domain/{target}"),
        ("SecurityTrails", f"https://securitytrails.com/domain/{target}/dns"),
        ("Robtex",      f"https://www.robtex.com/dns-lookup/{target}"),
        ("DNSDumpster", f"https://dnsdumpster.com/ (search: {target})"),
        ("Netcraft",    f"https://searchdns.netcraft.com/?restriction=site+contains&host={target}"),
        ("WaybackMachine", f"https://web.archive.org/web/*/{target}"),
        ("crt.sh",      f"https://crt.sh/?q={target}"),
        ("ViewDNS",     f"https://viewdns.info/reverseip/?host={target}&t=1"),
        ("IPVoid",      f"https://www.ipvoid.com/ip-blacklist-check/ (check: {target})"),
        ("MXToolbox",   f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{target}"),
    ]

    t = Table(
        title=f"[{G1}]OSINT ENGINES :: {target}[/]",
        box=box.SIMPLE, border_style=G2, header_style=CY
    )
    t.add_column("Engine", style=CY, width=20)
    t.add_column("Link",   style=G1)
    for name, link in links:
        t.add_row(name, link)
    console.print(t)

def _b64(s: str) -> str:
    import base64
    return base64.b64encode(s.encode()).decode()

# ─── MAIN OSINT+ ─────────────────────────────────────────────

def run():
    show_module_banner("osint")
    cat_talk(CAT_RECON, "OSINT+ extended sensors online...", OR)
    console.print()

    while True:
        console.print(f"  [{G1}][1][/] Email OSINT           (analysis + MX + breach links)")
        console.print(f"  [{G1}][2][/] Password breach check (HIBP k-anonymity — no plain password sent)")
        console.print(f"  [{G1}][3][/] Google Dork builder")
        console.print(f"  [{G1}][4][/] IP reputation check")
        console.print(f"  [{G1}][5][/] Phone number OSINT")
        console.print(f"  [{G1}][6][/] Paste search (breach data)")
        console.print(f"  [{G1}][7][/] Search engines OSINT links")
        console.print(f"  [{G1}][0][/] Back")
        console.print()

        choice = ask_choice("OSINT+", "0")

        if choice == "0":
            break
        elif choice == "1":
            email = Prompt.ask(f"  [{G1}]◈ Email address[/]").strip()
            if email: email_osint(email)
        elif choice == "2":
            pw = Prompt.ask(f"  [{G1}]◈ Password to check[/]").strip()
            if pw:
                info("Checking via SHA1 k-anonymity (first 5 chars of hash only — password stays private)")
                check_password_pwned(pw)
        elif choice == "3":
            target = Prompt.ask(f"  [{G1}]◈ Target domain[/]").strip()
            if target: dork_builder(target)
        elif choice == "4":
            ip = Prompt.ask(f"  [{G1}]◈ IP address[/]").strip()
            if ip: ip_reputation(ip)
        elif choice == "5":
            phone = Prompt.ask(f"  [{G1}]◈ Phone number (e.g. +33612345678)[/]").strip()
            if phone: phone_osint(phone)
        elif choice == "6":
            query = Prompt.ask(f"  [{G1}]◈ Search query (email, domain, username...)[/]").strip()
            if query: paste_search(query)
        elif choice == "7":
            target = Prompt.ask(f"  [{G1}]◈ Target (domain or IP)[/]").strip()
            if target: search_engines_osint(target)
        else:
            warn("Invalid option.")
        console.print()
