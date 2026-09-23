```
   /\_/\
  ( o.o )  ~ nyaa ~
   > ^ <
  /|   |\
 (_|   |_)
```

# MEOW-SEC

**By cat-project-hat // v1.1 // 2026**

Toolkit de sécurité offensif Python 3 — interface TUI Rich — 34 modules — thème chat hacker

![Python](https://img.shields.io/badge/Python-3.10+-green?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue?style=flat-square)
![Modules](https://img.shields.io/badge/Modules-34-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-Educational-red?style=flat-square)
![Proxy](https://img.shields.io/badge/Proxy-Rotation-orange?style=flat-square)
![CF Bypass](https://img.shields.io/badge/Cloudflare-Bypass-yellow?style=flat-square)

---

## ⚠️ Avertissement

> **Ce projet est strictement éducatif.** Utilisation réservée aux CTF, tests d'intrusion autorisés et recherche en sécurité. L'utilisation sur des systèmes sans autorisation explicite est **illégale**. Les auteurs déclinent toute responsabilité en cas d'utilisation abusive.

---

## 🗂️ Structure

```
meow-sec/
├── meow.py              ← Point d'entrée — menu TUI interactif
├── meow.bat             ← Lanceur Windows
├── requirements.txt
├── core/
│   ├── ui.py            ← Interface Rich (bannière, menu 4 colonnes, helpers)
│   ├── cats.py          ← Art ASCII chats + animations
│   └── proxy_manager.py ← Rotation de proxies (download, validate, rotate — 35+ sources)
├── data/
│   ├── proxies.json     ← Pool de proxies validés
│   ├── dstat_http.txt   ← (optionnel) proxies dstat.st téléchargés manuellement
│   ├── dstat_socks4.txt
│   └── dstat_socks5.txt
└── modules/
    ├── claw.py          ← Port & service scanner
    ├── purr.py          ← HTTP recon & header analyzer
    ├── scratch.py       ← Directory brute force
    ├── whisker.py       ← DNS / WHOIS / IP OSINT + AXFR + crt.sh
    ├── hiss.py          ← SQLi / XSS / SSRF / CRLF / open redirect / host header
    ├── catnap.py        ← Subdomain enumerator
    ├── proxycat.py      ← Proxy manager (35+ sources, validation parallèle)
    ├── ghost.py         ← Username OSINT
    ├── osint_ext.py     ← Email / phone / dorks / IP OSINT étendu
    ├── paws.py          ← Password generator
    ├── mewhash.py       ← Hash tools + rule-based cracker
    ├── codec.py         ← Encoder / decoder multi-format
    ├── payload.py       ← Payload library
    ├── netkit.py        ← Network utilities (ping, traceroute, CIDR scan /16)
    ├── stress.py        ← Stress tester L3/L4/L7 (17 méthodes + bypass CF)
    ├── loot.py          ← Saved results viewer
    ├── revshell.py      ← Reverse shell generator (21 types)
    ├── waf.py           ← WAF / CDN fingerprinting
    ├── jwtcat.py        ← JWT attacker (alg:none, RS256→HS256, HMAC brute)
    ├── report.py        ← HTML report generator (dark matrix theme)
    ├── brute.py         ← HTTP login brute force (form + Basic auth)
    ├── cms.py           ← CMS fingerprinting (11 frameworks)
    ├── sslscan.py       ← SSL/TLS deep scanner + crt.sh CT lookup
    ├── phish.py         ← Phishing page + tunnel (serveo / localhost.run)
    ├── cors.py          ← CORS misconfiguration tester
    ├── lfi.py           ← LFI / RFI tester (traversal, PHP wrappers)
    ├── fuzz.py          ← Parameter & endpoint fuzzer
    ├── cve.py           ← CVE lookup & version matcher (NVD + CIRCL)
    ├── harvest.py       ← Email harvester (crt.sh, archive.org, GitHub)
    ├── takeover.py      ← Subdomain takeover checker (27 services)
    ├── bucket.py        ← Cloud bucket finder (S3, GCS, Azure, DO)
    ├── spray.py         ← Password spraying (HTTP form, Basic, NTLM)
    ├── graphql.py       ← GraphQL security tester
    └── twofa.py         ← 2FA bypass tester
```

---

## ⚡ Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | **CLAW** | Port & service scanner — TCP connect, banner grab, service detection |
| 2 | **PURR** | HTTP recon — headers, techs, security headers, path scan |
| 3 | **SCRATCH** | Directory brute force — soft-404 detection, custom wordlist |
| 4 | **WHISKER** | DNS/WHOIS/GeoIP + Zone Transfer (AXFR) + crt.sh subdomains |
| 5 | **HISS** | SQLi · XSS · SSRF · CRLF · Open Redirect · Host Header injection |
| 6 | **CATNAP** | Subdomain enumerator — DNS + HTTP check |
| 7 | **LOOT** | Saved results viewer — JSON browser |
| 8 | **PROXYCAT** | Proxy manager — 35+ sources, validation parallèle, HTTP/SOCKS4/SOCKS5 |
| 9 | **GHOST** | Username OSINT — vérification sur 30+ plateformes |
| 10 | **OSINT+** | Email / phone / IP / Google dorks OSINT étendu |
| 11 | **PAWS** | Password generator — patterns, wordlists, PIN |
| 12 | **MEWHASH** | Hash tools — crack offline + rule-based (l33t, mutations) + lookup sans API |
| 13 | **CODEC** | Encoder / decoder — Base64/32/16, URL, HTML, ROT13, hex, XOR... |
| 14 | **PAYLOAD** | Payload library — XSS, SQLi, path traversal, LFI, SSTI... |
| 15 | **NETKIT** | Network utilities — ping, traceroute, WHOIS, CIDR scan (jusqu'à /16) |
| 16 | **STRESS** | Stress tester — 17 méthodes L7/L4/L3 + bypass Cloudflare (voir détail) |
| 17 | **REVSHELL** | Reverse shell generator — 21 types (Bash, Python, PHP, PowerShell, Netcat...) |
| 18 | **WAF** | WAF / CDN fingerprinting — 11 signatures (Cloudflare, Akamai, AWS WAF...) |
| 19 | **JWTCAT** | JWT attacker — alg:none, RS256→HS256 confusion, HMAC brute force, forge |
| 20 | **REPORT** | HTML report generator — agrège tous les scans, dark matrix theme |
| 21 | **BRUTE** | HTTP brute force — form auto-detect + CSRF, Basic auth, proxy rotation |
| 22 | **CMS** | CMS fingerprinting — WordPress, Drupal, Joomla, Laravel, Django, Flask... |
| 23 | **SSLSCAN** | SSL/TLS deep scanner — protocols, ciphers, cert, HTTP security headers |
| 24 | **PHISH** | Phishing page + tunnel sans port forwarding — Microsoft 365 / Google / LinkedIn |
| 25 | **CORS** | CORS misconfiguration tester — wildcard, null origin, credentials reflection |
| 26 | **LFI** | LFI / RFI tester — path traversal, double-encode, PHP wrappers |
| 27 | **FUZZ** | Parameter & endpoint fuzzer — param discovery, path discovery, value fuzzing |
| 28 | **CVE** | CVE lookup & version matcher — NVD API + CIRCL.lu, auto-fingerprint cible |
| 29 | **HARVEST** | Email harvester — crt.sh, archive.org, GitHub, scraping, pattern generation |
| 30 | **TAKEOVER** | Subdomain takeover checker — 27 services (GitHub Pages, S3, Vercel, Heroku...) |
| 31 | **BUCKET** | Cloud bucket finder — AWS S3, GCS, Azure Blob, DigitalOcean Spaces |
| 32 | **SPRAY** | Password spraying — HTTP form, Basic auth, NTLM (auth requise) |
| 33 | **GRAPHQL** | GraphQL security tester — introspection, injection, mutations |
| 34 | **2FA** | 2FA bypass tester — OTP brute, reuse, response manip, backup codes, skip |

---

## 🐱 Menu

```
╭──────────────── ◈  MEOW-SEC  v1.1  ::  34 modules  ◈ ────────────────╮
│  /\_/\          /\_/\          /\_/\          /\_/\                   │
│ ( o.o )        ( >.< )        ( ^.^ )        ( o_o )                  │
│   > w <          > ~ <          > v <          > x <                  │
│ ─ RECON ─      ─ TOOLS ─      ─NETWORK─      ─ UTILS ─               │
│ ────────────   ────────────   ────────────   ────────────             │
│  [ 1] CLAW      [11] PAWS      [ 8] PROXYCAT  [ 7] LOOT              │
│  [ 2] PURR      [12] MEWHASH   [15] NETKIT    [20] REPORT             │
│  [ 3] SCRATCH   [13] CODEC     [16] STRESS    [24] PHISH              │
│  [ 4] WHISKER   [14] PAYLOAD   [21] BRUTE     [ 0] EXIT               │
│  [ 5] HISS      [17] REVSHELL  [22] CMS                               │
│  [ 6] CATNAP    [19] JWTCAT    [23] SSLSCAN                           │
│  [ 9] GHOST     [32] SPRAY     [31] BUCKET                            │
│  [10] OSINT+    [33] GRAPHQL                                           │
│  [18] WAF       [34] 2FA                                              │
│  [25] CORS                                                             │
│  [26] LFI                                                             │
│  [27] FUZZ                                                            │
│  [28] CVE                                                             │
│  [29] HARVEST                                                         │
│  [30] TAKEOVER                                                        │
╰───────────────────────────────────────────────────────────────────────╯
```

---

## 🔄 Proxy Rotation

Tous les modules HTTP utilisent la rotation automatique via `core/proxy_manager.py`.

```
PROXYCAT [8] → télécharge depuis 35+ sources publiques (ProxyScrape, GeoNode,
                GitHub listes quotidiennes, dstat.st*)
             → valide en parallèle (100 workers)
             → conserve le top 30% le plus rapide
             → sauvegarde dans data/proxies.json
```

*dstat.st est protégé par DiamWall — télécharger manuellement et placer dans `data/dstat_http.txt`.*

Chaque module HTTP fait `proxies=px()` — si aucun proxy disponible, connexion directe automatique.

### Proxy types supportés

| Type | Format | Notes |
|------|--------|-------|
| HTTP | `ip:port` | Défaut |
| SOCKS4 | `socks4://ip:port` | Méthodes socket raw |
| SOCKS5 | `socks5://ip:port` | Recommandé pour l'anonymat |

---

## 💥 Détail des méthodes STRESS (17 méthodes)

### Proxy healthcheck automatique

Avant chaque attaque avec `proxy=ON`, le module effectue un **checkup rapide** :
- Teste 50 proxies du pool en parallèle (timeout 4s) contre l'URL cible
- Marque les proxies morts → ne seront plus distribués aux workers
- Affiche le nombre de proxies vivants avant de lancer les threads

### Méthodes disponibles

| Layer | # | Méthode | Description |
|-------|---|---------|-------------|
| L7 | 1 | `HTTP_GET` | GET flood avec User-Agent rotation + proxy |
| L7 | 2 | `HTTP_POST` | POST flood avec body aléatoire + proxy |
| L7 | 3 | `HTTP_HEAD` | HEAD flood avec cache-busting + proxy |
| L7 | 4 | `HTTP_BYPASS` | X-Forwarded-For random + Pragma/no-cache + referrer spoof |
| L7 | 5 | `HTTP_JSON` | JSON POST flood (REST APIs) + proxy |
| L7 | 6 | `HTTP_COOKIE` | Cookie overflow — 50-100 cookies par requête + proxy |
| L7 | 7 | `HTTP_XMLRPC` | WordPress xmlrpc.php multicall (100 auth/req) + proxy |
| L7 | 8 | `HTTP_RANGE` | Range header abuse (CVE-2011-3192 style) + proxy |
| L7 | 9 | `HTTP_MIXED` | Rotation aléatoire GET/POST/HEAD/BYPASS + proxy |
| L7 | 16 | `RESONANCE` | Saturation adaptative via loi de Little — P75-based interval |
| L7 | 17 | `PULSAR` | **Vagues synchronisées** — threading.Barrier, sature accept() OS |
| L7 | 10 | `SLOWLORIS` | Keepalive starvation — connexions incomplètes (SOCKS) |
| L7 | 11 | `RUDY` | R-U-Dead-Yet — slow POST, Content-Length=999999, 1 byte/tick |
| L7 | 12 | `TLS` | TLS handshake flood — CPU-heavy sur le serveur (SOCKS) |
| L4 | 13 | `TCP` | TCP connect flood (SOCKS) |
| L4 | 14 | `UDP` | UDP datagram flood (raw socket) |
| L3 | 15 | `ICMP` | ICMP echo flood |

### RESONANCE

Basée sur la **loi de Little** (L = λW) : chaque worker calcule l'intervalle optimal entre requêtes pour maintenir exactement 100% de charge sans créer de file d'attente. Un timer adaptatif recalcule le P75 toutes les 3 secondes.

### PULSAR ⚡ (méthode inédite)

`threading.Barrier(N)` synchronise **tous les workers à la même milliseconde**.

```
t=0ms  : N workers tirent simultanément → sature le pool accept() OS (128-512 slots)
t=Xms  : tous les workers dorment ensemble (coordonné)
t=2Xms : nouvelle vague — repeat
```

- Les rate limiters mesurent 0 req/s pendant X ms puis N req en < 5 ms → la moyenne reste basse, le pic détruit le serveur
- `stream=True` + `r.close()` immédiat → serveur génère la réponse complète mais ne peut pas la livrer → RAM bufferisée pour rien
- Connexion fraîche à chaque burst (`Connection: close`) → impossible de réutiliser les sessions

### Bypass Cloudflare / JA3 (`curl_cffi`)

Disponible pour toutes les méthodes HTTP (1-9, 16, 17) :

```bash
pip install curl_cffi
```

Active dans le menu via l'option **"Bypass Cloudflare/JA3?"**. Utilise `curl_cffi` avec les vraies empreintes TLS de Chrome (JA3 fingerprint, HTTP/2 SETTINGS frames, cipher suites order) — Cloudflare Bot Score voit du trafic Chrome légitime.

| Mode | TLS Fingerprint | Cloudflare Score |
|------|----------------|-----------------|
| `requests` | Python/urllib (connu) | Bloqué |
| `curl_cffi` | Chrome 110 / Firefox 102 | Légitime |

Activé par défaut pour PULSAR.

---

## 🔒 Détail HISS (injections web)

| Option | Type | Description |
|--------|------|-------------|
| 1 | SQLi | 20+ payloads — error-based, blind, time-based |
| 2 | XSS | 15+ payloads — reflected, DOM, bypass encodages |
| 3 | SQLi + XSS | Combiné |
| 4 | Form crawl | Détection et test automatique des formulaires |
| 5 | SSRF | 15 payloads — AWS/GCP/Azure metadata, IPv6, decimal/hex/octal |
| 6 | CRLF | 6 payloads — header injection, Unicode bypass |
| 7 | Open Redirect | 12 payloads — `//evil.com`, encoded, javascript: |
| 8 | Host Header | 5 headers testés — Host, X-Forwarded-Host, X-Host... |
| 9 | All | Tous les tests |

---

## 🔑 Détail JWTCAT

| Attaque | Description |
|---------|-------------|
| **alg:none** | 5 variantes de casse (none/None/NONE/nOnE/NoNe) |
| **RS256→HS256** | Confusion algorithme — signe avec la clé publique comme secret HMAC |
| **HMAC brute force** | HS256/384/512 — wordlist custom ou dictionnaire intégré 35 secrets communs |
| **Token forge** | Édition libre du payload + resign |

---

## 🌐 Détail WHISKER

| Option | Description |
|--------|-------------|
| 1 | Full recon (DNS + WHOIS + GeoIP) |
| 2 | DNS only (A, NS, MX, TXT, AAAA, CNAME...) |
| 3 | WHOIS only |
| 4 | GeoIP only |
| 5 | **Zone Transfer (AXFR)** — test sur chaque NS record |
| 6 | **Certificate Transparency (crt.sh)** — subdomains sans clé API |
| 7 | Full recon + AXFR + crt.sh |

---

## 🖥️ Reverse Shells (REVSHELL)

21 types générés automatiquement avec IP/port configurables :

`bash_tcp` · `bash_b64` · `sh_udp` · `python3` · `python2` · `python_b64` · `php_exec` · `php_proc` · `nc_e` · `nc_mkfifo` · `perl` · `ruby` · `powershell` · `powershell_b64` · `powershell_download` · `node` · `socat` · `golang` · `java` · `awk` · `lua`

Listener intégré : `nc`, `ncat`, `socat`, `pwncat`, `metasploit`

---

## ☁️ Détail BUCKET (cloud buckets)

| Provider | URL pattern | Détection |
|----------|-------------|-----------|
| AWS S3 | `s3.amazonaws.com/<name>` | PUBLIC_READ (listing), EXISTS_403 |
| GCS | `storage.googleapis.com/<name>` | PUBLIC_READ, EXISTS_403 |
| Azure Blob | `<name>.blob.core.windows.net` | EXISTS_200/403 |
| DigitalOcean | `<name>.nyc3.digitaloceanspaces.com` | PUBLIC_READ, EXISTS_403 |

50+ variantes de noms générées automatiquement (préfixes/suffixes : -backup, -dev, -prod, -assets...).

---

## 🔄 Détail TAKEOVER (subdomain takeover)

27 services fingerprrintés :

GitHub Pages · Heroku · AWS S3 · Vercel · Netlify · Fastly · Shopify · Tumblr · WP Engine · Ghost · Surge.sh · Readme.io · Statuspage · Zendesk · UserVoice · Freshdesk · HubSpot · Intercom · Campaign Monitor · Helpscout · Pingdom · Tilda · Webflow · Strikingly · Cargo · Uberflip · Fly.io

---

## 🌐 Phishing sans ouvrir de port

```
PHISH [24] → choisir un template (Microsoft 365 / Google / LinkedIn / Generic / Custom HTML)
           → serveur HTTP local Python (aucune dépendance)
           → tunnel via serveo.net ou localhost.run (juste SSH, rien à installer)
           → URL publique générée automatiquement
           → credentials capturés en live → data/phish_YYYYMMDD.log
           → redirect automatique vers le vrai site après capture
```

| Service | Prérequis |
|---------|-----------|
| **serveo.net** | SSH uniquement |
| **localhost.run** | SSH uniquement |
| **bore.pub** | `cargo install bore-cli` |

---

## 📦 Installation

```bash
# Cloner / copier le dossier
cd meow-sec

# Dépendances Python (auto-install au démarrage)
pip install -r requirements.txt

# Lancer
python meow.py

# Lancement direct d'un module
python meow.py stress
python meow.py pulsar
python meow.py cors
python meow.py cve
```

**requirements.txt**
```
rich>=13.7.0
colorama>=0.4.6
requests>=2.31.0
PySocks>=1.7.1
curl_cffi>=0.6.0     ← optionnel, bypass Cloudflare JA3
```

> Les dépendances manquantes sont installées automatiquement au premier lancement via `_ensure_deps()`.

---

## 📊 Rapport HTML (REPORT)

Le module REPORT agrège tous les fichiers JSON de `data/` et génère un rapport HTML standalone :
- Résumé timeline de tous les scans
- Sections : Ports, Web Recon, DNS, WAF, OSINT, Stress, CVE, Takeover, Buckets
- Sections collapsibles (JS)
- Dark matrix theme inline (aucune dépendance externe)
- Ouverture automatique dans le navigateur

---

## Disclaimer

> **Ce projet est strictement éducatif.** Utilisation réservée aux CTF, red team autorisé et recherche en sécurité. L'utilisation de cet outil sur des systèmes sans autorisation explicite est illégale dans la plupart des juridictions. Les auteurs ne sont pas responsables de toute utilisation abusive. Respectez la loi.

---

## Credits

**by cat-project-hat** *(we do the best for you)*

---

```
   /\_/\
  ( o.o )   MEOW-SEC v1.1 // BY CAT-PROJECT-HAT // 2026
   > ^ <
  /|   |\
 (_|   |_)
```
