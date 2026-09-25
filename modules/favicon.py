# -*- coding: utf-8 -*-
"""MEOW-SEC :: FAVICON — Favicon Hash Fingerprinting (module #65)"""
import os, re, json, base64, struct
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_FOUND, CAT_SCAN
from rich.panel  import Panel
from rich.table  import Table
from rich.prompt import Prompt, Confirm
from rich.rule   import Rule
from rich        import box

try:
    import requests as _req
    _req.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False

try:
    import mmh3
    HAS_MMH3 = True
except Exception:
    HAS_MMH3 = False


# ─── MurmurHash3 32-bit — implémentation pure Python ─────────────────────────

def _mmh3(data: bytes) -> int:
    """MurmurHash3 32-bit — fallback pur Python (compatible Shodan)."""
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    seed = 0
    h1 = seed
    length = len(data)
    chunk_size = 4
    chunks = length // chunk_size

    for i in range(chunks):
        k1 = struct.unpack_from("<I", data, i * chunk_size)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = ((h1 * 5) + 0xe6546b64) & 0xFFFFFFFF

    tail = data[chunks * chunk_size:]
    k1 = 0
    tail_len = length & 3
    if tail_len >= 3:
        k1 ^= tail[2] << 16
    if tail_len >= 2:
        k1 ^= tail[1] << 8
    if tail_len >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    # Finalisation (fmix32)
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Convertir en entier signé 32-bit (convention Shodan / mmh3)
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


def _favicon_hash(favicon_bytes: bytes) -> int:
    """Calcule le hash Shodan du favicon (MurmurHash3 sur base64 encodé)."""
    b64 = base64.encodebytes(favicon_bytes)  # base64 avec newlines (style mmh3/Shodan)
    if HAS_MMH3:
        return mmh3.hash(b64)
    else:
        return _mmh3(b64)


# ─── BASE DE DONNÉES DE HASHES CONNUS ────────────────────────────────────────

_KNOWN_HASHES = {
    # Serveurs web
    -878682257:   "Apache HTTP Server (default page)",
    1278501876:   "Apache Tomcat",
    -335242539:   "Nginx (default page)",
    442749392:    "Microsoft IIS (default page)",
    -1427405592:  "IIS 7/8",

    # CI/CD & monitoring
    -1115928904:  "Jenkins",
    -1424337905:  "Grafana",
    590609109:    "Kibana",
    1505873285:   "Elasticsearch",
    -1501783148:  "Prometheus",
    -771557959:   "Nagios",

    # Dev & collaboration
    -1350222589:  "GitLab",
    -1562781744:  "Jira",
    -1909820456:  "Confluence",
    -1185258157:  "Bitbucket",
    1278670635:   "Redmine",
    -1399730269:  "SonarQube",
    -1649533228:  "Nexus Repository",

    # CMS
    -1139501792:  "WordPress",
    1572905066:   "Drupal",
    -508154753:   "Joomla",
    2098077346:   "Magento",
    -388776756:   "PrestaShop",
    -1613780987:  "Shopify",
    -897293443:   "Typo3",
    -1295751596:  "MODX",

    # Administration / bases de données
    -1442893026:  "phpMyAdmin",
    -1427940649:  "Webmin",
    -771836890:   "cPanel",
    -395082312:   "Plesk",
    1685765027:   "Adminer",

    # Virtualisation / infrastructure
    -1442842063:  "VMware vSphere",
    1166875475:   "VMware ESXi",
    -674622928:   "Proxmox VE",
    1775351732:   "pfSense",
    -1042505673:  "OPNsense",

    # Réseau / sécurité
    -199224632:   "Fortinet FortiGate",
    -1408788634:  "Cisco (generic)",
    1501752925:   "Cisco ASA",
    -878682050:   "Palo Alto Networks",
    -1626877282:  "F5 BIG-IP",
    1474866773:   "SonicWall",
    -1651820558:  "Juniper",
    -247986596:   "Check Point",

    # Identity & SSO
    -814759802:   "Keycloak",
    1484579468:   "Okta",
    -1742416539:  "Auth0",
    -1026485384:  "Shibboleth IdP",

    # Cloud & containers
    -698401542:   "Nextcloud",
    -1417539797:  "ownCloud",
    1485842550:   "Portainer",
    -1499307706:  "Traefik",
    1616416632:   "Rancher",
    -1294764374:  "Harbor (container registry)",
    -1082439244:  "MinIO",

    # Divers
    1320365940:   "GitBook",
    -1218940118:  "Graylog",
    -1742105498:  "Zabbix",
    -441490773:   "Cacti",
}


# ─── RÉCUPÉRATION DU FAVICON ─────────────────────────────────────────────────

def _get_favicon_from_html(html: str, base_url: str) -> list:
    """Extrait les URLs de favicon depuis le HTML."""
    urls = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # <link rel="icon"> / <link rel="shortcut icon">
    for m in re.finditer(
        r'<link[^>]+rel=["\']([^"\']*icon[^"\']*)["\'][^>]+href=["\']([^"\']+)["\']',
        html, re.I
    ):
        href = m.group(2)
        if href.startswith("http"):
            urls.append(href)
        elif href.startswith("//"):
            urls.append(f"{parsed.scheme}:{href}")
        elif href.startswith("/"):
            urls.append(f"{origin}{href}")
        else:
            urls.append(urljoin(base_url, href))

    # Version inversée (href avant rel)
    for m in re.finditer(
        r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\']([^"\']*icon[^"\']*)["\']',
        html, re.I
    ):
        href = m.group(1)
        if href.startswith("http"):
            urls.append(href)
        elif href.startswith("//"):
            urls.append(f"{parsed.scheme}:{href}")
        elif href.startswith("/"):
            urls.append(f"{origin}{href}")
        else:
            urls.append(urljoin(base_url, href))

    return list(dict.fromkeys(urls))


def _fetch_favicon(target_url: str) -> tuple:
    """
    Tente de récupérer le favicon d'une URL.
    Retourne (bytes, url_utilisée) ou (None, None).
    """
    if not HAS_REQUESTS:
        return None, None

    parsed = urlparse(target_url)
    if not parsed.scheme:
        target_url = "https://" + target_url
        parsed = urlparse(target_url)

    origin = f"{parsed.scheme}://{parsed.netloc}"
    headers = {"User-Agent": "MEOW-FAVICON/1.0"}

    # 1) Parser le HTML pour trouver <link rel="icon">
    try:
        r = _req.get(target_url, timeout=10, verify=False, headers=headers,
                     allow_redirects=True)
        if r.status_code == 200:
            html_urls = _get_favicon_from_html(r.text, r.url)
            for fav_url in html_urls:
                try:
                    fr = _req.get(fav_url, timeout=8, verify=False, headers=headers)
                    if fr.status_code == 200 and len(fr.content) > 10:
                        return fr.content, fav_url
                except Exception:
                    pass
    except Exception:
        pass

    # 2) Essayer les chemins standards
    fallback_paths = [
        "/favicon.ico",
        "/favicon.png",
        "/favicon-32x32.png",
        "/favicon-16x16.png",
        "/apple-touch-icon.png",
        "/apple-touch-icon-precomposed.png",
    ]
    for path in fallback_paths:
        url = origin + path
        try:
            r = _req.get(url, timeout=8, verify=False, headers=headers)
            if r.status_code == 200 and len(r.content) > 10:
                return r.content, url
        except Exception:
            pass

    return None, None


# ─── LIENS DE RECHERCHE ──────────────────────────────────────────────────────

def _shodan_link(hash_val: int) -> str:
    return f"https://www.shodan.io/search?query=http.favicon.hash:{hash_val}"


def _fofa_link(hash_val: int) -> str:
    query = f'icon_hash="{hash_val}"'
    b64q  = base64.b64encode(query.encode()).decode()
    return f"https://fofa.info/result?qbase64={b64q}"


def _censys_link(hash_val: int) -> str:
    return f"https://search.censys.io/search?resource=hosts&q=services.http.response.favicons.md5_hash%3D{hash_val}"


# ─── ANALYSE D'UN DOMAINE ────────────────────────────────────────────────────

def _analyze_target(url: str) -> dict:
    """Récupère et analyse le favicon d'une URL."""
    result = {
        "url": url,
        "favicon_url": None,
        "hash": None,
        "size_bytes": 0,
        "technology": None,
        "shodan_link": None,
        "fofa_link": None,
        "error": None,
    }

    info(f"Fetching favicon for [{CY}]{url}[/]...")
    favicon_bytes, favicon_url = _fetch_favicon(url)

    if not favicon_bytes:
        result["error"] = "No favicon found"
        warn(f"No favicon found for {url}")
        return result

    result["favicon_url"]  = favicon_url
    result["size_bytes"]   = len(favicon_bytes)

    hash_val = _favicon_hash(favicon_bytes)
    result["hash"] = hash_val

    tech = _KNOWN_HASHES.get(hash_val)
    result["technology"] = tech

    result["shodan_link"] = _shodan_link(hash_val)
    result["fofa_link"]   = _fofa_link(hash_val)

    return result


def _print_result(res: dict):
    """Affiche le résultat d'une analyse favicon."""
    url  = res["url"]
    h    = res.get("hash")
    tech = res.get("technology")
    err_ = res.get("error")

    if err_:
        warn(f"{url} — {err_}")
        return

    if tech:
        find(f"[{url}]  Hash: [{CY}]{h}[/]  →  [{G1}]{tech}[/]")
    else:
        info(f"[{url}]  Hash: [{CY}]{h}[/]  → Unknown technology")

    if res.get("favicon_url"):
        info(f"  Favicon URL : [{DM}]{res['favicon_url']}[/]")
    if res.get("size_bytes"):
        info(f"  Size        : {res['size_bytes']} bytes")
    console.print(f"  [{G2}]Shodan :[/] [{DM}]{res['shodan_link']}[/]")
    console.print(f"  [{G2}]FOFA   :[/] [{DM}]{res['fofa_link']}[/]")


def _save(target: str, results: list):
    os.makedirs("data", exist_ok=True)
    safe = re.sub(r"[^\w\-]", "_", target)[:40]
    fname = f"data/favicon_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({
            "target": target,
            "results": results,
            "timestamp": datetime.now().isoformat(),
        }, f, indent=2)
    ok(f"Results saved: [bold]{fname}[/]")


# ─── POINT D'ENTRÉE ──────────────────────────────────────────────────────────

def run():
    show_module_banner("favicon")
    cat_talk(CAT_SCAN, "Favicon hash fingerprinting — Shodan-style technology detection", G1)
    console.print()

    if not HAS_REQUESTS:
        err("requests library not available. Install it: pip install requests"); return

    if not HAS_MMH3:
        warn("mmh3 not installed — using built-in pure-Python MurmurHash3.")
        info("For faster hashing: [bold]pip install mmh3[/]")

    console.print(f"\n  [{G1}][1][/] Single URL / domain")
    console.print(f"  [{G1}][2][/] Multiple subdomains (compare hashes)")
    console.print(f"  [{G1}][3][/] Direct favicon URL")
    mode = Prompt.ask(f"  [{CY}]◈ Mode[/]", default="1").strip()

    all_results = []
    target_label = ""

    # ── Mode 1 : URL unique ─────────────────────────────────────
    if mode == "1":
        url = Prompt.ask(f"  [{G1}]◈ Target URL or domain[/]").strip()
        if not url.startswith("http"):
            url = "https://" + url
        target_label = url
        res = _analyze_target(url)
        all_results.append(res)
        console.print()
        _print_result(res)

    # ── Mode 2 : multi sous-domaines ────────────────────────────
    elif mode == "2":
        raw = Prompt.ask(
            f"  [{G1}]◈ Subdomains / URLs (comma or newline separated)[/]"
        ).strip()
        urls = [u.strip() for u in re.split(r"[,\n]+", raw) if u.strip()]
        if not urls:
            err("No targets provided."); return
        target_label = urls[0]

        for url in urls:
            if not url.startswith("http"):
                url = "https://" + url
            res = _analyze_target(url)
            all_results.append(res)

        console.print()

        # Afficher les résultats individuels
        for res in all_results:
            _print_result(res)

        # Comparer les hashes
        console.print()
        hashes = {r["url"]: r.get("hash") for r in all_results if r.get("hash") is not None}
        if len(hashes) > 1:
            unique_hashes = list(dict.fromkeys(hashes.values()))
            if len(unique_hashes) == 1:
                find(f"All {len(urls)} targets share the SAME favicon hash → [{G1}]same infra likely![/]")
            else:
                info(f"{len(unique_hashes)} distinct hashes across {len(urls)} targets")
                # Regrouper par hash
                groups: dict = {}
                for url, h in hashes.items():
                    groups.setdefault(h, []).append(url)
                t = Table(
                    title=f"[{G1}]Hash Groups[/]",
                    box=box.MINIMAL_DOUBLE_HEAD,
                    border_style=G2, header_style=CY
                )
                t.add_column("Hash",        style=CY,  min_width=14)
                t.add_column("Technology",  style=G1,  min_width=22)
                t.add_column("Targets",     style="grey93", min_width=30)
                for h, urls_in_group in groups.items():
                    tech = _KNOWN_HASHES.get(h, "Unknown")
                    t.add_row(str(h), tech, ", ".join(urls_in_group))
                console.print(t)

    # ── Mode 3 : URL favicon directe ────────────────────────────
    elif mode == "3":
        fav_url = Prompt.ask(f"  [{G1}]◈ Favicon URL[/]").strip()
        if not fav_url.startswith("http"):
            fav_url = "https://" + fav_url
        target_label = fav_url
        info(f"Downloading favicon from {fav_url}...")
        try:
            r = _req.get(fav_url, timeout=10, verify=False,
                         headers={"User-Agent": "MEOW-FAVICON/1.0"})
            if r.status_code != 200 or len(r.content) <= 10:
                err(f"Could not fetch favicon (HTTP {r.status_code})."); return
            favicon_bytes = r.content
        except Exception as e:
            err(f"Download error: {e}"); return

        hash_val = _favicon_hash(favicon_bytes)
        tech = _KNOWN_HASHES.get(hash_val)

        res = {
            "url": fav_url,
            "favicon_url": fav_url,
            "hash": hash_val,
            "size_bytes": len(favicon_bytes),
            "technology": tech,
            "shodan_link": _shodan_link(hash_val),
            "fofa_link":   _fofa_link(hash_val),
            "error": None,
        }
        all_results.append(res)
        console.print()
        _print_result(res)
    else:
        err("Unknown mode."); return

    # ── Résumé ──────────────────────────────────────────────────
    console.print()
    identified = [r for r in all_results if r.get("technology")]
    if identified:
        find(f"Identified [{G1}]{len(identified)}[/] technology/technologies:")
        for r in identified:
            info(f"  [{G1}]{r['technology']}[/] on {r['url']}")

    if all_results:
        _save(target_label, all_results)
    else:
        warn("No results to save.")
