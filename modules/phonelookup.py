# -*- coding: utf-8 -*-
"""
MEOW-SEC :: PHONELOOKUP — Phone Number Intelligence
For authorized OSINT and security research only.
"""
import os, json, re, socket, time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_target, ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

_UA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
_UA2 = "MEOW-SEC/1.5 (authorized-osint)"

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

# ─── NORMALIZE ────────────────────────────────────────────────

def _normalize(raw: str) -> str:
    cleaned = re.sub(r"[\s\-\(\)\.]+", "", raw.strip())

    if cleaned.startswith("+"):
        return cleaned
    if cleaned.startswith("00"):
        return "+" + cleaned[2:]

    if cleaned.startswith("0"):
        digits = cleaned[1:]
        prefix2 = cleaned[:2]
        # France: 06/07 mobile, 01-05 landline, 08/09 special (10 digits)
        if len(cleaned) == 10 and prefix2 in ("06","07","01","02","03","04","05","08","09"):
            return "+33" + digits
        # UK: 07xxx mobile (11 digits)
        if len(cleaned) == 11 and prefix2 == "07":
            return "+44" + digits
        # Generic European 0-prefix
        if len(cleaned) in (10, 11, 12):
            return "+" + cleaned

    return "+" + cleaned

# ─── PARSE ────────────────────────────────────────────────────

def _parse_number(e164: str) -> dict:
    digits = e164.lstrip("+")
    result = {
        "e164": e164, "digits": digits,
        "country_code": "?", "country": "Unknown",
        "iso": "?", "national": digits,
        "carriers": [], "line_type": "Unknown", "valid": False,
    }

    for prefix_len in (3, 2, 1):
        prefix = digits[:prefix_len]
        if prefix in _COUNTRY_CODES:
            iso, country, carriers = _COUNTRY_CODES[prefix]
            result.update({
                "country_code": prefix, "country": country,
                "iso": iso, "national": digits[prefix_len:],
                "carriers": carriers, "valid": len(digits) >= 7,
            })
            break

    national = result["national"]
    cc = result["country_code"]

    if cc == "33":   # France
        if national.startswith("6") or national.startswith("7"):
            result["line_type"] = "Mobile"
        elif national.startswith(("800","805","806","809")):
            result["line_type"] = "Toll-free / Numéro vert"
        elif national.startswith("08"):
            result["line_type"] = "Numéro spécial (surtaxé)"
        elif national.startswith("9"):
            result["line_type"] = "Landline (nouveau)"
        else:
            result["line_type"] = "Landline"
    elif cc == "44":  # UK
        if national.startswith("7"):    result["line_type"] = "Mobile"
        elif national.startswith("800"): result["line_type"] = "Toll-free"
        elif national.startswith("9"):   result["line_type"] = "Premium"
        else:                            result["line_type"] = "Landline"
    elif cc == "49":  # Germany
        if national.startswith(("15","16","17")): result["line_type"] = "Mobile"
        elif national.startswith("800"):          result["line_type"] = "Toll-free"
        else:                                     result["line_type"] = "Landline"
    elif cc == "1":   # US/CA
        result["line_type"] = "Mobile or Landline (carrier lookup needed)"
    elif cc == "91":  # India
        result["line_type"] = "Mobile" if national[:1] in "6789" else "Landline"
    elif cc == "86":  # China
        result["line_type"] = "Mobile" if national[:2] in ("13","14","15","16","17","18","19") else "Landline"
    else:
        length = len(digits)
        result["line_type"] = "Likely Mobile" if 10 <= length <= 12 else "Unknown"

    return result

# ─── EXTERNAL LOOKUPS ─────────────────────────────────────────

# ─── CARRIER PREFIX TABLE (offline, ARCEP data) ───────────────

# France — table basée sur les tranches ARCEP (4 premiers chiffres du numéro national)
_FR_CARRIER = {}
for _pfx in ["0600","0601","0602","0603","0604","0605","0606","0607","0608","0609",
             "0610","0611","0612","0613","0614","0615","0616","0617","0618","0619",
             "0660","0661","0662","0663","0664","0665","0666","0667","0668","0669",
             "0690","0691","0692","0693","0694","0695","0696","0697","0698","0699"]:
    _FR_CARRIER[_pfx] = "Orange"
for _pfx in ["0620","0621","0622","0623","0624","0625","0626","0627","0628","0629",
             "0630","0631","0632","0633","0634","0635","0636","0637","0638","0639",
             "0670","0671","0672","0673","0674","0675","0676","0677","0678","0679"]:
    _FR_CARRIER[_pfx] = "SFR"
for _pfx in ["0640","0641","0642","0643","0644","0645","0646","0647","0648","0649",
             "0650","0651","0652","0653","0654","0655","0656","0657","0658","0659",
             "0680","0681","0682","0683","0684","0685","0686","0687","0688","0689"]:
    _FR_CARRIER[_pfx] = "Bouygues Telecom"
for _pfx in ["0700","0701","0702","0703","0704","0705","0706","0707","0708","0709",
             "0710","0711","0712","0713","0714","0715","0716","0717","0718","0719",
             "0720","0721","0722","0723","0724","0725","0726","0727","0728","0729",
             "0730","0731","0732","0733","0734","0735","0736","0737","0738","0739",
             "0740","0741","0742","0743","0744","0745","0746","0747","0748","0749",
             "0750","0751","0752","0753","0754","0755","0756","0757","0758","0759",
             "0760","0761","0762","0763","0764","0765","0766","0767","0768","0769",
             "0770","0771","0772","0773","0774","0775","0776","0777","0778","0779",
             "0780","0781","0782","0783","0784","0785","0786","0787","0788","0789",
             "0790","0791","0792","0793","0794","0795","0796","0797","0798","0799"]:
    _FR_CARRIER[_pfx] = "Free Mobile"

def _carrier_from_prefix(parsed: dict) -> str:
    """Détecte l'opérateur hors ligne via la table ARCEP (France uniquement)."""
    if parsed["country_code"] != "33":
        return ""
    national = parsed["national"]  # ex: "687798996" pour +33687798996
    # Reconstruire le numéro national format "06XXXXXXXX"
    national_full = "0" + national  # "0687798996"
    prefix4 = national_full[:4]     # "0687"
    return _FR_CARRIER.get(prefix4, "")

def _scrape_owner(e164: str, national_full: str) -> dict:
    """Scrape annuaire-inverse.org et spy-numerics.fr pour trouver le propriétaire."""
    digits_no_plus = e164.lstrip("+")
    result = {"owner": "", "owner_type": "", "city": "", "source": ""}

    # ── annuaire-inverse.org ─────────────────────────────────
    try:
        r = requests.get(
            f"https://annuaire-inverse.org/{national_full}",
            timeout=10, verify=False,
            headers={"User-Agent": _UA, "Accept-Language": "fr-FR,fr;q=0.9"}
        )
        html = r.text
        # Chercher le nom dans les balises h1/h2/title ou schéma Person
        name_match = (
            re.search(r'<h1[^>]*>([^<]{3,60})</h1>', html, re.I) or
            re.search(r'"name"\s*:\s*"([^"]{3,60})"', html) or
            re.search(r'itemprop="name"[^>]*>([^<]{3,60})<', html) or
            re.search(r'<title>([^<]{3,80})</title>', html)
        )
        city_match = re.search(r'(?:ville|city|localit[eé])[^>]*>([^<]{2,40})<', html, re.I)
        type_match = re.search(r'(?:particulier|entreprise|association|spam|commercial)', html, re.I)

        if name_match:
            name = name_match.group(1).strip()
            # Filtrer les titres génériques
            if not any(x in name.lower() for x in ["annuaire","inverse","qui appelle","recherche","numéro"]):
                result["owner"] = name
                result["source"] = "annuaire-inverse.org"
        if city_match:
            result["city"] = city_match.group(1).strip()
        if type_match:
            result["owner_type"] = type_match.group(0).lower()
    except Exception:
        pass

    # ── spy-numerics.fr (si pas trouvé) ─────────────────────
    if not result["owner"]:
        try:
            r = requests.get(
                f"https://www.spy-numerics.fr/{national_full}",
                timeout=10, verify=False,
                headers={"User-Agent": _UA, "Accept-Language": "fr-FR,fr;q=0.9"}
            )
            html = r.text
            name_match = (
                re.search(r'<h1[^>]*>([^<]{3,60})</h1>', html, re.I) or
                re.search(r'"name"\s*:\s*"([^"]{3,60})"', html) or
                re.search(r'itemprop="name"[^>]*>([^<]{3,60})<', html)
            )
            if name_match:
                name = name_match.group(1).strip()
                if not any(x in name.lower() for x in ["spy","numerics","qui appelle","téléphone"]):
                    result["owner"] = name
                    result["source"] = "spy-numerics.fr"
        except Exception:
            pass

    # ── pagesjaunes.fr (pour les landlines) ─────────────────
    if not result["owner"]:
        try:
            r = requests.get(
                f"https://www.pagesjaunes.fr/pagesblanches/recherche?quoiqui={national_full}",
                timeout=10, verify=False,
                headers={"User-Agent": _UA, "Accept-Language": "fr-FR,fr;q=0.9"}
            )
            html = r.text
            name_match = re.search(r'class="[^"]*denomination[^"]*"[^>]*>([^<]{3,60})<', html, re.I)
            if name_match:
                result["owner"] = name_match.group(1).strip()
                result["source"] = "pagesjaunes.fr"
        except Exception:
            pass

    return result

def _scrape_tellows(national_full: str) -> dict:
    """Scrape tellows.fr pour score, opérateur, type d'appelant et appréciation."""
    result = {
        "score": "?", "caller_type": "?", "reports": "?",
        "carrier": "", "appreciation": "?",
        "url": f"https://www.tellows.fr/num/{national_full}"
    }
    try:
        r = requests.get(
            f"https://www.tellows.fr/num/{national_full}",
            timeout=10, verify=False,
            headers={"User-Agent": _UA, "Accept-Language": "fr-FR,fr;q=0.9"}
        )
        html = r.text

        # Score — "Score 5" ou "note : 5"
        score = (re.search(r'Score\s+(\d)', html, re.I) or
                 re.search(r'score["\s:>]+(\d)\b', html, re.I) or
                 re.search(r'tellows.*?(\d)\s*(?:/\s*9)?', html, re.I))
        if score:
            result["score"] = score.group(1)

        # Signalements
        reports = (re.search(r'(\d+)\s*(?:commentaire|évaluation|signalement|avis)', html, re.I) or
                   re.search(r'(\d+)\s*(?:comment|rating|report)', html, re.I))
        if reports:
            result["reports"] = reports.group(1)

        # Opérateur réseau — "Indicatif : Orange France - F"
        carrier = (re.search(r'Indicatif\s*:\s*([^\n<\-]{3,40})', html, re.I) or
                   re.search(r'de\s+([A-Z][a-zA-Z\s]{3,30}(?:France|Mobile|Telecom|SFR|Bouygues|Free)[a-zA-Z\s]*)', html) or
                   re.search(r'"carrier"\s*:\s*"([^"]{3,40})"', html))
        if carrier:
            result["carrier"] = carrier.group(1).strip().rstrip(" -").strip()

        # Type d'appelant — "Votre numéro? Entrée commerciale" / "Entrée commerciale"
        ctype = (re.search(r'Votre num[eé]ro\s*\?\s*([^\n<]{3,50})', html, re.I) or
                 re.search(r'(?:Entr[eé]e commerciale|Particulier|Service client|Spam|Arnaque|Démarchage|Inconnu)', html, re.I) or
                 re.search(r'callerType["\s:>]+([^"<\n]{3,40})', html, re.I))
        if ctype:
            result["caller_type"] = ctype.group(1).strip() if ctype.lastindex else ctype.group(0).strip()

        # Appréciation — "neutre", "positif", "négatif"
        appr = re.search(r'Appr[eé]ciation\s*:\s*(\w+)', html, re.I)
        if appr:
            result["appreciation"] = appr.group(1).lower()

    except Exception:
        pass
    return result

def _scrape_lesarnaques(national_full: str) -> dict:
    """Scrape les-arnaques.com — spécialisé FR pour les numéros frauduleux."""
    url = f"https://www.les-arnaques.com/victime/arnaque-telephonique?phone={national_full}"
    result = {"url": url, "reports": "?", "fraud_type": "?"}
    try:
        r = requests.get(url, timeout=8, verify=False, headers={"User-Agent": _UA})
        html = r.text
        reports = re.search(r'(\d+)\s*(?:signalement|plainte|victime)', html, re.I)
        ftype   = re.search(r'(?:type)[^>]*>([^<]{3,50})<', html, re.I)
        if reports: result["reports"] = reports.group(1)
        if ftype:   result["fraud_type"] = ftype.group(1).strip()
    except Exception:
        pass
    return result

def _scrape_commentcamarche(national_full: str) -> dict:
    """Scrape commentcamarche.net — forum FR avec signalements."""
    url = f"https://www.commentcamarche.net/telephonie/numero-de-telephone/?num={national_full}"
    result = {"url": url, "reports": "?", "verdict": "?"}
    try:
        r = requests.get(url, timeout=8, verify=False, headers={"User-Agent": _UA})
        html = r.text
        reports = re.search(r'(\d+)\s*(?:commentaire|signalement|avis)', html, re.I)
        verdict = re.search(r'(?:dangereux|spam|fiable|sûr|arnaque)', html, re.I)
        if reports: result["reports"] = reports.group(1)
        if verdict: result["verdict"] = verdict.group(0).lower()
    except Exception:
        pass
    return result

def _check_whatsapp(e164: str) -> dict:
    digits = e164.lstrip("+")
    result = {"registered": None, "url": f"https://wa.me/{digits}"}
    try:
        r = requests.get(
            f"https://api.whatsapp.com/send?phone={digits}",
            timeout=8, verify=False,
            headers={"User-Agent": _UA}, allow_redirects=False
        )
        # WhatsApp redirige vers l'app si le numéro est valide
        if r.status_code in (301, 302):
            loc = r.headers.get("Location", "")
            result["registered"] = "invalid" not in loc.lower()
            result["redirect"] = loc
        else:
            result["registered"] = None  # impossible à déterminer sans session
    except Exception:
        pass
    return result

def _check_telegram(e164: str) -> dict:
    digits = e164.lstrip("+")
    result = {"registered": False, "url": f"https://t.me/+{digits}"}
    try:
        r = requests.get(
            f"https://t.me/+{digits}",
            timeout=10, verify=False,
            headers={"User-Agent": _UA}, allow_redirects=True
        )
        html = r.text
        # Telegram affiche "Join Group" ou "Open" si le numéro a un profil public
        if any(x in html.lower() for x in ["tgme_page_photo", "og:image", "tgme_page_description"]):
            result["registered"] = True
    except Exception:
        pass
    return result

def _google_dorking(e164: str, raw: str) -> list:
    """Génère des dorks Google ciblés pour trouver des mentions du numéro."""
    digits_clean = e164.lstrip("+")
    # Variantes d'affichage courantes
    national = digits_clean[2:] if digits_clean.startswith("33") else digits_clean
    nat_spaced = " ".join([national[i:i+2] for i in range(0, len(national), 2)])
    nat_dot    = ".".join([national[i:i+2] for i in range(0, len(national), 2)])
    nat_dash   = "-".join([national[i:i+2] for i in range(0, len(national), 2)])

    import urllib.parse
    def g(q): return f"https://www.google.com/search?q={urllib.parse.quote(q)}"

    return [
        ("Google — numéro exact",      g(f'"{e164}"')),
        ("Google — format national",   g(f'"{nat_spaced}" OR "{nat_dot}" OR "{nat_dash}"')),
        ("Google — pages persos/CV",   g(f'"{national}" site:linkedin.com OR site:facebook.com OR site:viadeo.com')),
        ("Google — forums/signalements", g(f'"{national}" signalement OR spam OR arnaque OR qui appelle')),
        ("Google — annonces",          g(f'"{national}" site:leboncoin.fr OR site:lacentrale.fr OR site:seloger.com')),
        ("Google — réseaux sociaux",   g(f'"{national}" site:twitter.com OR site:instagram.com OR site:tiktok.com')),
        ("Bing — numéro exact",        f"https://www.bing.com/search?q={urllib.parse.quote(e164)}"),
        ("Yandex",                     f"https://yandex.com/search/?text={urllib.parse.quote(e164)}"),
    ]

def _social_media_links(e164: str) -> list:
    """Liens directs vers des recherches de compte par numéro sur les réseaux."""
    digits = e164.lstrip("+")
    return [
        ("WhatsApp (ouvrir chat)",  f"https://wa.me/{digits}"),
        ("Telegram (ouvrir profil)",f"https://t.me/+{digits}"),
        ("Signal",                 f"https://signal.me/#p/{e164}"),
        ("Viber",                  f"viber://chat?number={e164}"),
        ("Facebook (recherche)",   f"https://www.facebook.com/search/top?q={e164}"),
        ("Instagram (recherche)",  f"https://www.instagram.com/{digits}/"),
        ("LinkedIn (recherche)",   f"https://www.linkedin.com/search/results/all/?keywords={e164}"),
        ("LinkedIn Search",        f"https://www.linkedin.com/search/results/people/?keywords={digits}"),
        ("Facebook Search",        f"https://www.facebook.com/search/people/?q={digits}"),
        ("Snapchat (recherche)",   f"https://www.snapchat.com/search?q={digits}"),
        ("TikTok (recherche)",     f"https://www.tiktok.com/search?q={e164}"),
        ("Skype (recherche)",      f"https://web.skype.com/search?query={e164}"),
        ("Botim (MENA)",           f"https://botim.me/{digits}"),
        ("NumSpy OSINT",           f"https://numspy.io/search?q={digits}"),
    ]

def _reverse_lookup_links(e164: str) -> list:
    """Sites de reverse phone lookup gratuits."""
    digits = e164.lstrip("+")
    return [
        ("Truecaller",   f"https://www.truecaller.com/search/fr/{digits}"),
        ("Sync.me",      f"https://sync.me/search/?number={digits}"),
        ("SpyDialer",    f"https://www.spydialer.com/default.aspx?phone={digits}"),
        ("NumLookup",    f"https://www.numlookup.com/?phone={e164}"),
        ("Infobel",      f"https://www.infobel.com/fr/france/phonebook/{digits}"),
        ("PagesJaunes",  f"https://www.pagesjaunes.fr/pagesblanches/recherche?quoiqui={digits}"),
        ("Spy-Numerics", f"https://www.spy-numerics.fr/{digits}"),
        ("PhoneInfoga",  f"https://github.com/sundowndev/phoneinfoga"),
        ("CallerID Test",f"https://www.calleridtest.com/{digits}"),
        ("AnnuaireMobile",f"https://annuaire-inverse.org/{digits}"),
    ]

# ─── SAVE ─────────────────────────────────────────────────────

def _save(number: str, data: dict):
    os.makedirs("data", exist_ok=True)
    safe = re.sub(r"[^\w]", "_", number)
    fname = f"data/phonelookup_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    ok(f"Saved → {fname}")

# ─── MAIN ─────────────────────────────────────────────────────

def run():
    show_module_banner("phonelookup")
    if not HAS_REQUESTS:
        err("requests not installed"); return

    console.print(f"\n  [{CY}]Phone Number Intelligence[/]")
    console.print(f"  [{DM}]Carrier offline · Owner scraping · Spam · WhatsApp · Telegram · Dorks[/]\n")

    raw = ask_target("Phone number (0612345678 / +33612345678 / 0033612345678)")
    if not raw:
        return

    e164 = _normalize(raw)
    info(f"Normalized → {e164}")

    parsed = _parse_number(e164)
    digits = e164.lstrip("+")
    # Format national complet (ex: "0687798996" pour la France)
    national_full = "0" + parsed["national"] if parsed["country_code"] == "33" else parsed["national"]

    # ── 1. LOCAL ANALYSIS ──────────────────────────────────────
    console.print(f"\n  [{CY}]╔══ NUMÉRO ══╗[/]")
    valid_color = G1 if parsed["valid"] else RD
    console.print(f"  [{valid_color}]{'✓ Valid E.164' if parsed['valid'] else '✗ Invalid / Unrecognized'}[/]  [{G1}]{parsed['e164']}[/]")
    console.print(f"  [{CY}]Pays :[/]         {parsed['country']}  ({parsed['iso']})")
    console.print(f"  [{CY}]Indicatif :[/]    +{parsed['country_code']}")
    console.print(f"  [{CY}]National :[/]     {national_full}")
    lt_color = G1 if "Mobile" in parsed["line_type"] else CY
    console.print(f"  [{CY}]Type :[/]         [{lt_color}]{parsed['line_type']}[/]")

    # ── 2. OPÉRATEUR (offline ARCEP + tellows confirmera) ───────
    carrier_offline = _carrier_from_prefix(parsed)
    if carrier_offline:
        info(f"Opérateur d'origine (ARCEP) : {carrier_offline}  [{DM}](avant portabilité éventuelle)[/]")
    else:
        info(f"Opérateur : hors table ARCEP")
        if parsed["carriers"]:
            info(f"Opérateurs connus dans {parsed['iso']} : {', '.join(parsed['carriers'][:4])}")

    # ── 3. PROPRIÉTAIRE (scraping parallèle) ───────────────────
    console.print(f"\n  [{CY}]╔══ PROPRIÉTAIRE ══╗[/]")
    info("Scraping annuaire-inverse, spy-numerics, pagesjaunes...")

    with ThreadPoolExecutor(max_workers=4) as pool:
        f_owner   = pool.submit(_scrape_owner, e164, national_full)
        f_tellows = pool.submit(_scrape_tellows, national_full)
        f_arnaques= pool.submit(_scrape_lesarnaques, national_full)
        f_ccm     = pool.submit(_scrape_commentcamarche, national_full)

        owner_data   = f_owner.result()
        tellows_data = f_tellows.result()
        arnaques_data= f_arnaques.result()
        ccm_data     = f_ccm.result()

    if owner_data.get("owner"):
        find(f"Propriétaire : {owner_data['owner']}")
        if owner_data.get("city"):
            info(f"  Ville : {owner_data['city']}")
        if owner_data.get("owner_type"):
            info(f"  Type  : {owner_data['owner_type']}")
        info(f"  Source: {owner_data['source']}")
    else:
        warn("Propriétaire : non trouvé dans les annuaires publics")
        info("  → Mobile non-listé, numéro professionnel, ou scraping bloqué")

    # Opérateur confirmé par tellows (avec portabilité)
    if tellows_data.get("carrier"):
        find(f"Opérateur (Tellows live) : {tellows_data['carrier']}")

    # ── 4. SPAM / SIGNALEMENTS ─────────────────────────────────
    console.print(f"\n  [{CY}]╔══ SPAM & SIGNALEMENTS ══╗[/]")

    tw_score = tellows_data.get("score","?")
    if tw_score == "?":                 tw_color = DM
    elif tw_score in ("7","8","9"):     tw_color = RD
    elif tw_score in ("4","5","6"):     tw_color = OR
    else:                               tw_color = G1
    console.print(f"  [{CY}]Tellows score  :[/]  [{tw_color}]{tw_score}/9[/]  (1=fiable · 9=dangereux)")

    # Opérateur confirmé par tellows (tient compte de la portabilité)
    tw_carrier = tellows_data.get("carrier","")
    if tw_carrier:
        find(f"Opérateur actuel (Tellows) : {tw_carrier}")
    console.print(f"  [{CY}]Type appelant  :[/]  {tellows_data.get('caller_type','?')}")
    console.print(f"  [{CY}]Appréciation   :[/]  {tellows_data.get('appreciation','?')}")
    console.print(f"  [{CY}]Signalements   :[/]  {tellows_data.get('reports','?')}")
    console.print(f"  [{DM}]  {tellows_data['url']}[/]")

    ar_rep = arnaques_data.get("reports","?")
    ar_color = RD if ar_rep not in ("?","0") else DM
    console.print(f"\n  [{CY}]Les-Arnaques   :[/]  [{ar_color}]{ar_rep} signalement(s)[/]  {arnaques_data.get('fraud_type','')}  [{DM}]{arnaques_data['url']}[/]")
    console.print(f"  [{CY}]CommentCaMarche:[/]  {ccm_data.get('reports','?')} commentaire(s) · verdict={ccm_data.get('verdict','?')}  [{DM}]{ccm_data['url']}[/]")

    # ── 5. MESSAGERIES ────────────────────────────────────────
    console.print(f"\n  [{CY}]╔══ MESSAGERIES ══╗[/]")
    info("Vérification WhatsApp & Telegram...")

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_wa = pool.submit(_check_whatsapp, e164)
        f_tg = pool.submit(_check_telegram, e164)
        wa   = f_wa.result()
        tg   = f_tg.result()

    wa_status = "✓ Enregistré" if wa.get("registered") is True else ("✗ Non enregistré" if wa.get("registered") is False else "? Vérifier manuellement")
    tg_status = "✓ Profil public détecté" if tg.get("registered") else "? Vérifier manuellement"
    wa_color  = G1 if wa.get("registered") is True else (RD if wa.get("registered") is False else DM)
    tg_color  = G1 if tg.get("registered") else DM

    console.print(f"  WhatsApp : [{wa_color}]{wa_status}[/]  [{DM}]{wa['url']}[/]")
    console.print(f"  Telegram : [{tg_color}]{tg_status}[/]  [{DM}]{tg['url']}[/]")
    console.print(f"  Signal   : [{DM}]https://signal.me/#p/{e164}[/]  [{DM}](vérifier manuellement)[/]")

    # ── 6. GOOGLE DORKS ────────────────────────────────────────
    console.print(f"\n  [{CY}]╔══ GOOGLE DORKS ══╗[/]")
    dorks = _google_dorking(e164, raw)
    print_result_table("Google Dorks", ["Recherche", "URL"], [[d[0], d[1]] for d in dorks])

    # ── 7. SOCIAL MEDIA + REVERSE LOOKUP ──────────────────────
    console.print(f"\n  [{CY}]╔══ SOCIAL MEDIA ══╗[/]")
    social = _social_media_links(e164)
    print_result_table("Social Media", ["Plateforme", "URL"], [[s[0], s[1]] for s in social])

    console.print(f"\n  [{CY}]╔══ ANNUAIRES INVERSÉS ══╗[/]")
    reverse = _reverse_lookup_links(e164)
    print_result_table("Reverse Lookup", ["Service", "URL"], [[r[0], r[1]] for r in reverse])

    # ── 8. RÉSUMÉ FINAL ────────────────────────────────────────
    console.print(f"\n  [{G1}]╔══════════════ RÉSUMÉ ══════════════╗[/]")
    spam_flag = tw_score not in ("?","1","2","3") or ar_rep not in ("?","0")
    summary_rows = [
        ["Numéro E.164",    e164],
        ["Pays",            f"{parsed['country']} (+{parsed['country_code']})"],
        ["Type de ligne",   parsed["line_type"]],
        ["Opérateur actuel", tellows_data.get("carrier") or carrier_offline or "Inconnu"],
        ["Réseau d'origine", carrier_offline or "—"],
        ["Propriétaire",    owner_data.get("owner") or "Non trouvé"],
        ["Ville",           owner_data.get("city") or "—"],
        ["WhatsApp",        wa_status],
        ["Telegram",        tg_status],
        ["Tellows score",   f"{tw_score}/9"],
        ["Signalements spam", ar_rep if ar_rep != "?" else "0"],
    ]
    print_result_table("Phone Intel", ["Champ", "Valeur"], summary_rows)

    if spam_flag:
        find(f"ATTENTION — numéro signalé comme spam/arnaque (Tellows score {tw_score})")

    all_data = {
        "input": raw, "e164": e164, "parsed": parsed,
        "carrier_offline": carrier_offline,
        "owner": owner_data,
        "tellows": tellows_data,
        "arnaques": arnaques_data,
        "commentcamarche": ccm_data,
        "messaging": {"whatsapp": wa, "telegram": tg},
        "dorks": {d[0]: d[1] for d in dorks},
        "social_media": {s[0]: s[1] for s in social},
        "reverse_lookup": {r[0]: r[1] for r in reverse},
        "ts": datetime.now().isoformat(),
    }
    _save(e164, all_data)
    cat_talk(CAT_FOUND if parsed["valid"] else CAT_SCAN, f"Phone lookup complete: {e164}")
