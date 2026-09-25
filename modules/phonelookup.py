# -*- coding: utf-8 -*-
"""
MEOW-SEC :: PHONELOOKUP — Phone Number Intelligence
For authorized OSINT and security research only.
"""
import os, json, re
from datetime import datetime

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_target, ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

_UA = "MEOW-SEC/1.4 (authorized-osint)"

# ─── COUNTRY PREFIX TABLE ────────────────────────────────────

_COUNTRY_CODES = {
    "1":   ("US/CA", "North America",         ["AT&T","Verizon","T-Mobile","Rogers","Bell"]),
    "7":   ("RU/KZ", "Russia/Kazakhstan",     ["MTS","Beeline","Megafon"]),
    "20":  ("EG",    "Egypt",                 ["Vodafone Egypt","Orange Egypt"]),
    "27":  ("ZA",    "South Africa",          ["Vodacom","MTN","Cell C"]),
    "30":  ("GR",    "Greece",                ["Cosmote","Vodafone GR"]),
    "31":  ("NL",    "Netherlands",           ["KPN","Vodafone NL","T-Mobile NL"]),
    "32":  ("BE",    "Belgium",               ["Proximus","Base","Orange BE"]),
    "33":  ("FR",    "France",                ["Orange","SFR","Bouygues","Free"]),
    "34":  ("ES",    "Spain",                 ["Movistar","Vodafone ES","Orange ES"]),
    "36":  ("HU",    "Hungary",               ["Magyar Telekom","Vodafone HU"]),
    "39":  ("IT",    "Italy",                 ["TIM","Vodafone IT","WindTre"]),
    "40":  ("RO",    "Romania",               ["Orange RO","Vodafone RO","Digi"]),
    "41":  ("CH",    "Switzerland",           ["Swisscom","Sunrise","Salt"]),
    "43":  ("AT",    "Austria",               ["A1","Magenta","Drei"]),
    "44":  ("GB",    "United Kingdom",        ["EE","O2","Vodafone UK","Three"]),
    "45":  ("DK",    "Denmark",               ["TDC","Telenor DK","Telia DK"]),
    "46":  ("SE",    "Sweden",                ["Telia","Tele2","Telenor SE"]),
    "47":  ("NO",    "Norway",                ["Telenor NO","Telia NO"]),
    "48":  ("PL",    "Poland",                ["Orange PL","T-Mobile PL","Play","Plus"]),
    "49":  ("DE",    "Germany",               ["Deutsche Telekom","Vodafone DE","O2 DE"]),
    "51":  ("PE",    "Peru",                  ["Claro","Movistar PE"]),
    "52":  ("MX",    "Mexico",                ["Telcel","AT&T MX","Movistar MX"]),
    "54":  ("AR",    "Argentina",             ["Claro AR","Personal","Movistar AR"]),
    "55":  ("BR",    "Brazil",                ["Vivo","Claro BR","TIM BR","Oi"]),
    "56":  ("CL",    "Chile",                 ["Entel","Movistar CL","Claro CL"]),
    "57":  ("CO",    "Colombia",              ["Claro CO","Movistar CO"]),
    "58":  ("VE",    "Venezuela",             ["Movistar VE","Digitel"]),
    "60":  ("MY",    "Malaysia",              ["Maxis","Celcom","Digi MY"]),
    "61":  ("AU",    "Australia",             ["Telstra","Optus","Vodafone AU"]),
    "62":  ("ID",    "Indonesia",             ["Telkomsel","Indosat","XL Axiata"]),
    "63":  ("PH",    "Philippines",           ["Globe","Smart","DITO"]),
    "64":  ("NZ",    "New Zealand",           ["Spark","Vodafone NZ","2degrees"]),
    "65":  ("SG",    "Singapore",             ["Singtel","StarHub","M1"]),
    "66":  ("TH",    "Thailand",              ["AIS","DTAC","True Move"]),
    "81":  ("JP",    "Japan",                 ["NTT Docomo","SoftBank","au"]),
    "82":  ("KR",    "South Korea",           ["SK Telecom","KT","LG U+"]),
    "84":  ("VN",    "Vietnam",               ["Viettel","MobiFone","Vinaphone"]),
    "86":  ("CN",    "China",                 ["China Mobile","China Unicom","China Telecom"]),
    "90":  ("TR",    "Turkey",                ["Turkcell","Vodafone TR","Türk Telekom"]),
    "91":  ("IN",    "India",                 ["Reliance Jio","Airtel","Vi","BSNL"]),
    "92":  ("PK",    "Pakistan",              ["Jazz","Telenor PK","Zong","Ufone"]),
    "93":  ("AF",    "Afghanistan",           ["Roshan","MTN AF","Etisalat AF"]),
    "94":  ("LK",    "Sri Lanka",             ["Dialog","Mobitel","Hutch"]),
    "95":  ("MM",    "Myanmar",               ["MPT","Ooredoo MM","Mytel"]),
    "98":  ("IR",    "Iran",                  ["Hamrahe Aval","Irancell","RighTel"]),
    "212": ("MA",    "Morocco",               ["Maroc Telecom","Orange MA","Inwi"]),
    "213": ("DZ",    "Algeria",               ["Djezzy","Mobilis","Ooredoo DZ"]),
    "216": ("TN",    "Tunisia",               ["Tunisie Telecom","Ooredoo TN","Orange TN"]),
    "218": ("LY",    "Libya",                 ["Libyana","Almadar"]),
    "234": ("NG",    "Nigeria",               ["MTN NG","Airtel NG","Glo","9mobile"]),
    "254": ("KE",    "Kenya",                 ["Safaricom","Airtel KE"]),
    "971": ("AE",    "UAE",                   ["Etisalat","du"]),
    "972": ("IL",    "Israel",                ["Cellcom","Partner","Hot Mobile"]),
    "974": ("QA",    "Qatar",                 ["Ooredoo QA","Vodafone QA"]),
    "966": ("SA",    "Saudi Arabia",          ["STC","Mobily","Zain SA"]),
    "965": ("KW",    "Kuwait",                ["Zain KW","Ooredoo KW","Viva KW"]),
    "962": ("JO",    "Jordan",                ["Zain JO","Orange JO","Umniah"]),
    "961": ("LB",    "Lebanon",               ["touch","Alfa"]),
}

# Line type prefixes (country-specific, simplified)
_US_MOBILE_PREFIXES = ["201","202","203","204","205","206","207","208","209","210",
                        "212","213","214","215","216","217","218","219","220"]

# ─── NORMALIZE ────────────────────────────────────────────────

def _normalize(raw: str) -> str:
    """Remove spaces, dashes, parentheses — keep digits and leading +.
    Handles national formats: 06/07 (FR), 07 (UK), 0-prefix (DE/IT/ES/NL/BE...)
    """
    cleaned = re.sub(r"[\s\-\(\)\.]+", "", raw.strip())

    if cleaned.startswith("+"):
        return cleaned

    if cleaned.startswith("00"):
        return "+" + cleaned[2:]

    # National format starting with 0 — try to infer country
    if cleaned.startswith("0"):
        digits = cleaned[1:]  # strip leading 0
        # France: 06/07 mobile (10 digits total), 01-05 landline
        if re.match(r"[1-9]\d{8}$", digits):  # 9 digits after 0 = 10 digit FR/EU number
            prefix2 = cleaned[:2]  # e.g. "06", "07"
            # France mobile: 06/07, landline: 01-05, special: 08/09
            if prefix2 in ("06", "07", "01", "02", "03", "04", "05", "08", "09"):
                return "+33" + digits
            # UK mobile: 07xxx (11 digits total)
            if prefix2 == "07" and len(cleaned) == 11:
                return "+44" + digits
            # Germany: 0xxx (variable length)
            if len(cleaned) in (10, 11, 12):
                return "+49" + digits
        # Fallback: just prepend + and let parse figure it out
        return "+" + cleaned

    # No prefix at all — assume already without country code, prepend +
    return "+" + cleaned

def _parse_number(e164: str) -> dict:
    """Parse E.164 number against country code table."""
    digits = e164.lstrip("+")
    result = {
        "e164": e164,
        "digits": digits,
        "country_code": "?",
        "country": "Unknown",
        "iso": "?",
        "national": digits,
        "carriers": [],
        "line_type": "Unknown",
        "valid": False,
    }

    # Try longest prefix first (up to 3 digits)
    for prefix_len in (3, 2, 1):
        prefix = digits[:prefix_len]
        if prefix in _COUNTRY_CODES:
            iso, country, carriers = _COUNTRY_CODES[prefix]
            result["country_code"] = prefix
            result["country"]      = country
            result["iso"]          = iso
            result["national"]     = digits[prefix_len:]
            result["carriers"]     = carriers
            result["valid"]        = len(digits) >= 7
            break

    # Guess line type (simplified heuristics)
    national = result["national"]
    length   = len(result["digits"])

    if result["country_code"] == "33":  # France
        if national.startswith("6") or national.startswith("7"):
            result["line_type"] = "Mobile"
        elif national.startswith("0800") or national.startswith("0900"):
            result["line_type"] = "Toll-free / Premium"
        else:
            result["line_type"] = "Landline"
    elif result["country_code"] == "44":  # UK
        if national.startswith("7"):
            result["line_type"] = "Mobile"
        elif national.startswith("800") or national.startswith("808"):
            result["line_type"] = "Toll-free"
        elif national.startswith("9"):
            result["line_type"] = "Premium"
        else:
            result["line_type"] = "Landline"
    elif result["country_code"] == "49":  # Germany
        if national.startswith(("15","16","17")):
            result["line_type"] = "Mobile"
        elif national.startswith("800"):
            result["line_type"] = "Toll-free"
        else:
            result["line_type"] = "Landline"
    elif result["country_code"] == "1":  # US/CA
        if length == 11:
            result["line_type"] = "Mobile or Landline (US/CA)"
        result["line_type"] = "Unknown (US/CA — carrier lookup needed)"
    elif result["country_code"] in ("91",):  # India
        if national.startswith(("6","7","8","9")):
            result["line_type"] = "Mobile"
        else:
            result["line_type"] = "Landline"
    elif result["country_code"] in ("86",):  # China
        if national.startswith(("13","14","15","16","17","18","19")):
            result["line_type"] = "Mobile"
        else:
            result["line_type"] = "Landline"
    else:
        if 10 <= length <= 12:
            result["line_type"] = "Likely Mobile (typical length)"
        else:
            result["line_type"] = "Unknown"

    return result

# ─── EXTERNAL LOOKUPS ─────────────────────────────────────────

def _numverify(number: str) -> dict:
    """numverify.com — free tier (250 req/month, no key needed for basic)."""
    try:
        r = requests.get(
            "http://apilayer.net/api/validate",
            params={"number": number, "access_key": "free"},
            timeout=8, verify=False,
            headers={"User-Agent": _UA}
        )
        d = r.json()
        if d.get("valid"):
            return {
                "provider":   "numverify",
                "valid":      d.get("valid"),
                "number":     d.get("number"),
                "local":      d.get("local_format"),
                "intl":       d.get("international_format"),
                "country":    d.get("country_name"),
                "location":   d.get("location"),
                "carrier":    d.get("carrier"),
                "line_type":  d.get("line_type"),
            }
    except Exception:
        pass
    return {}

def _hlr_lookups(number: str) -> dict:
    """hlr-lookups.com test endpoint — limited free queries."""
    try:
        r = requests.get(
            "https://www.hlr-lookups.com/api/sync-lookup",
            params={"msisdn": number, "route": "IP2", "api_key": "test"},
            timeout=8, verify=False,
            headers={"User-Agent": _UA}
        )
        d = r.json()
        if d.get("success"):
            return {
                "provider":     "hlr-lookups",
                "msisdn":       d.get("msisdn"),
                "network":      d.get("mnc_network"),
                "country":      d.get("country_name"),
                "status":       d.get("gsm_network_error_code"),
                "roaming":      d.get("imsi","")[:3],
                "ported":       d.get("is_ported"),
            }
    except Exception:
        pass
    return {}

# ─── OSINT LINKS ──────────────────────────────────────────────

def _osint_links(e164: str, raw: str) -> list:
    digits = e164.lstrip("+").replace(" ","")
    encoded = e164.replace("+", "%2B")
    return [
        ("Google Search",      f"https://www.google.com/search?q={encoded}"),
        ("Google Images",      f"https://www.google.com/search?tbm=isch&q={encoded}"),
        ("Truecaller",         f"https://www.truecaller.com/search/us/{digits}"),
        ("Sync.me",            f"https://sync.me/search/?number={digits}"),
        ("SpyDialer",          f"https://www.spydialer.com/default.aspx?phone={digits}"),
        ("WhitePages",         f"https://www.whitepages.com/phone/{digits}"),
        ("NumLookup",          f"https://www.numlookup.com/?phone={encoded}"),
        ("PhoneInfoga",        f"https://github.com/sundowndev/phoneinfoga"),
        ("Telegram",           f"https://t.me/{digits}"),
        ("WhatsApp",           f"https://api.whatsapp.com/send?phone={digits}"),
    ]

# ─── SAVE ─────────────────────────────────────────────────────

def _save(number: str, data: dict):
    os.makedirs("data", exist_ok=True)
    safe = re.sub(r"[^\w]", "_", number)
    fname = f"data/phonelookup_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    ok(f"Saved → {fname}")

# ─── MAIN ─────────────────────────────────────────────────────

def run():
    show_module_banner("phonelookup")
    if not HAS_REQUESTS:
        err("requests not installed"); return

    console.print(f"\n  [{CY}]Phone Number Intelligence[/]")
    console.print(f"  [{DM}]E.164 normalize · country/carrier · line type · HLR · OSINT links[/]\n")

    raw = ask_target("Phone number (any format: +33612345678 / 0612345678 / 0033612345678)")
    if not raw:
        return

    e164 = _normalize(raw)
    info(f"Normalized: {e164}")

    parsed = _parse_number(e164)

    console.print(f"\n  [{CY}]── Local Analysis ──[/]")
    valid_color = G1 if parsed["valid"] else RD
    console.print(f"  [{valid_color}]{'Valid' if parsed['valid'] else 'Invalid / Unrecognized'}[/{valid_color}]  E.164: {parsed['e164']}")
    info(f"  Country:       {parsed['country']}  ({parsed['iso']})")
    info(f"  Country code:  +{parsed['country_code']}")
    info(f"  National #:    {parsed['national']}")
    info(f"  Line type:     {parsed['line_type']}")

    if parsed["carriers"]:
        info(f"  Known carriers in {parsed['iso']}: {', '.join(parsed['carriers'][:4])}")

    # External lookups
    console.print(f"\n  [{CY}]── External Lookups ──[/]")
    ext_data = {}

    nv = _numverify(e164)
    if nv:
        ok(f"  numverify: {nv.get('carrier','?')} · {nv.get('line_type','?')} · {nv.get('location','?')}")
        ext_data["numverify"] = nv
    else:
        warn("  numverify: no result (free tier limit or no key)")

    hlr = _hlr_lookups(e164.lstrip("+"))
    if hlr:
        ok(f"  HLR: {hlr.get('network','?')} · ported={hlr.get('ported','?')}")
        ext_data["hlr"] = hlr
    else:
        info("  HLR: no result (limited free tier)")

    # OSINT links
    console.print(f"\n  [{CY}]── OSINT Links ──[/]  [{DM}](open manually)[/]")
    links = _osint_links(e164, raw)
    rows = [[name, url] for name, url in links]
    print_result_table("OSINT Links", ["Service", "URL"], rows)

    # Abuse / spam check hint
    console.print(f"\n  [{CY}]── Spam / Abuse Check ──[/]")
    info("  Check manually:")
    console.print(f"  [{DM}]  https://www.shouldianswer.com/phone-number/{e164.lstrip('+')}[/]")
    console.print(f"  [{DM}]  https://www.whocallsme.com/phone-call.aspx/{e164.lstrip('+')}[/]")

    all_data = {
        "input":   raw,
        "e164":    e164,
        "parsed":  parsed,
        "external": ext_data,
        "osint_links": {name: url for name, url in links},
        "ts":      datetime.now().isoformat(),
    }
    _save(e164, all_data)
    cat_talk(CAT_FOUND if parsed["valid"] else CAT_SCAN, f"Phone lookup complete: {e164}")
