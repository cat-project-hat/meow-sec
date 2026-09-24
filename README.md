```
   /\_/\
  ( o.o )  ~ nyaa ~
   > ^ <
  /|   |\
 (_|   |_)
```

<div align="center">

# 🐱 MEOW-SEC

### Cat-Themed Offensive Security Toolkit

**Python 3 · Rich TUI · 61 modules · No BS**

[![Python](https://img.shields.io/badge/Python-3.10+-brightgreen?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue?style=for-the-badge)](.)
[![Modules](https://img.shields.io/badge/Modules-61-brightgreen?style=for-the-badge)](.)
[![Version](https://img.shields.io/badge/Version-1.5-orange?style=for-the-badge)](.)
[![License](https://img.shields.io/badge/License-Educational-red?style=for-the-badge)](.)
[![Proxy](https://img.shields.io/badge/Proxy-Auto--Rotate-yellow?style=for-the-badge)](.)
[![CF Bypass](https://img.shields.io/badge/Cloudflare-JA3%20Bypass-purple?style=for-the-badge)](.)

*by cat-project-hat // 2026*

</div>

---

## ⚠️ Avertissement légal

> **Ce projet est strictement éducatif.** Utilisation réservée aux **CTF**, **tests d'intrusion autorisés** et **recherche en sécurité**. L'utilisation sur des systèmes sans autorisation explicite écrite est **illégale** dans toutes les juridictions. Les auteurs déclinent toute responsabilité en cas d'utilisation abusive. **Use responsibly.**

---

## 🚀 Quick Start

```bash
# 1. Clone / copier
cd meow-sec

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer le menu interactif
python meow.py

# 4. Lancer un module directement
python meow.py sqli
python meow.py iplookup
python meow.py urlspoof
python meow.py phonelookup
python meow.py wpscan
```

> **Les dépendances manquantes sont installées automatiquement** au premier lancement via `_ensure_deps()`. Aucune configuration requise.

---

## 📦 Requirements

```
rich>=13.7.0          ← TUI / terminal rendering
colorama>=0.4.6       ← couleurs Windows
requests>=2.31.0      ← HTTP client
PySocks>=1.7.1        ← SOCKS4/5 proxies
curl_cffi>=0.6.0      ← [optionnel] bypass Cloudflare JA3
stem>=1.8.0           ← [optionnel] Tor circuit renewal (SPECTER)
```

---

## 🗂️ Structure du projet

```
meow-sec/
├── meow.py              ← Point d'entrée — menu TUI + dispatch CLI
├── meow.bat             ← Lanceur Windows (double-clic)
├── requirements.txt
│
├── core/
│   ├── ui.py            ← Rich TUI (bannière, menu 4 colonnes, helpers ok/err/find)
│   ├── cats.py          ← ASCII art chats + animations + typewriter
│   ├── proxy_manager.py ← Rotation de proxies (35+ sources, validation parallèle)
│   └── tunnel.py        ← Tunnel centralisé (cloudflared / serveo / localhost.run / bore)
│
├── data/                ← Résultats JSON + logs (auto-créé)
│
└── modules/
    │
    ── RECON ──────────────────────────────────────────────────────
    ├── claw.py          ← Port & service scanner (TCP connect + banner grab)
    ├── purr.py          ← HTTP recon & header analyzer
    ├── scratch.py       ← Directory brute force (soft-404 detection)
    ├── whisker.py       ← DNS / WHOIS / GeoIP + AXFR + crt.sh
    ├── catnap.py        ← Subdomain enumerator
    ├── ghost.py         ← Username OSINT (30+ plateformes)
    ├── osint_ext.py     ← Email / phone / dorks / IP OSINT étendu
    ├── harvest.py       ← Email harvester (crt.sh, archive.org, GitHub)
    ├── waf.py           ← WAF / CDN fingerprinting (11 signatures)
    ├── cve.py           ← CVE lookup & version matcher (NVD + CIRCL)
    ├── takeover.py      ← Subdomain takeover (27 services, multi-source)
    ├── gitdump.py       ← Git + 50+ fichiers sensibles exposés
    ├── secretscan.py    ← Secret / credential scanner (15 patterns regex)
    ├── breach.py        ← Data breach checker (HIBP k-anonymity)
    ├── shodan_lite.py   ← Shodan-Lite (internetdb.shodan.io, sans clé)
    ├── iplookup.py      ← IP/Domain intel (GeoIP · ASN · Shodan · AbuseIPDB · RDAP)
    ├── phonelookup.py   ← Phone OSINT (pays · carrier · type · HLR · liens OSINT)
    │
    ── EXPLOIT ────────────────────────────────────────────────────
    ├── hiss.py          ← SQLi / XSS / SSRF / CRLF / open redirect / host header
    ├── sqli.py          ← SQL injection avancé (error-based / blind / time / UNION / MariaDB)
    ├── cmdi.py          ← OS command injection (verbose + blind + headers)
    ├── nosqli.py        ← NoSQL injection (MongoDB $ne/$gt/$regex/$where)
    ├── ormi.py          ← ORM injection (TypeORM / HQL / JPQL / LINQ / Django / Sequelize)
    ├── cors.py          ← CORS misconfiguration tester
    ├── lfi.py           ← LFI / RFI (traversal, double-encode, PHP wrappers)
    ├── fuzz.py          ← Parameter & endpoint fuzzer
    ├── smuggle.py       ← HTTP request smuggling (CL.TE / TE.CL / TE.TE)
    ├── xxe.py           ← XML External Entity (10 payloads, OOB, SSRF)
    ├── ssti.py          ← Server-side template injection
    ├── cache.py         ← Web cache poisoning & deception
    ├── oauth.py         ← OAuth 2.0 / OIDC misconfiguration
    ├── deseria.py       ← Deserialization (PHP / Java / Pickle / Node)
    ├── proto.py         ← Prototype pollution (Node.js)
    ├── idor.py          ← IDOR / BOLA (path / param / JSON / REST patterns)
    ├── upload.py        ← File upload bypass (21 techniques)
    ├── race.py          ← Race condition (threading.Barrier burst)
    ├── ldapi.py         ← LDAP injection (auth bypass / blind / user enum)
    │
    ── RÉSEAU / INFRASTRUCTURE ────────────────────────────────────
    ├── proxycat.py      ← Proxy manager (35+ sources, HTTP/SOCKS4/SOCKS5)
    ├── netkit.py        ← Ping, traceroute, WHOIS, CIDR scan (/16)
    ├── stress.py        ← Stress tester L3/L4/L7 (26 méthodes + SWARM)
    ├── brute.py         ← HTTP login brute force (form + CSRF + Basic)
    ├── cms.py           ← CMS fingerprinting (11 frameworks)
    ├── sslscan.py       ← SSL/TLS deep scanner + CT lookup
    ├── wpscan.py        ← WordPress scanner (CVEs / plugins / users / XMLRPC)
    ├── frontscan.py     ← React/TypeScript/TSX scanner (statique + remote)
    ├── bucket.py        ← Cloud bucket finder (S3 / GCS / Azure / DO)
    ├── spray.py         ← Password spraying (HTTP form / Basic / NTLM)
    ├── graphql.py       ← GraphQL tester (introspection / injection / mutations)
    ├── twofa.py         ← 2FA bypass (OTP brute / reuse / skip)
    │
    ── PHISHING / RED TEAM ────────────────────────────────────────
    ├── phish.py         ← Phishing page + tunnel (7 templates pixel-perfect)
    ├── phish_templates/ ← HTML séparés (Microsoft / Google / LinkedIn / Discord / Steam / Instagram / Generic)
    ├── track.py         ← IP Grabber (OGP bait / og:video Discord embed / GeoIP live)
    ├── urlspoof.py      ← URL spoofing (IDN homograph / typosquat / subdomain / @ trick / bit-squat)
    ├── mailspoof.py     ← Email spoofing (display name / reply-to / open relay / SMTP send)
    │
    ── EMAIL SECURITY ─────────────────────────────────────────────
    ├── emailsec.py      ← SPF / DKIM / DMARC analysis + spoof risk score 0-10
    │
    ── UTILS ──────────────────────────────────────────────────────
    ├── paws.py          ← Password generator (patterns, wordlists, PIN)
    ├── mewhash.py       ← Hash tools (crack offline + rule-based + lookup)
    ├── codec.py         ← Encoder/decoder multi-format
    ├── payload.py       ← Payload library (XSS / SQLi / LFI / SSTI...)
    ├── revshell.py      ← Reverse shell generator (21 types)
    ├── jwtcat.py        ← JWT attacker (alg:none / RS256→HS256 / HMAC brute)
    ├── loot.py          ← Saved results viewer (JSON browser)
    └── report.py        ← HTML report generator (dark matrix theme)
```

---

## ⚡ Modules — Référence complète

### RECON (Reconnaissance)

| # | Module | Description |
|---|--------|-------------|
| 1 | **CLAW** | Port & service scanner — TCP connect, banner grab, service detection |
| 2 | **PURR** | HTTP recon — headers, technologies, security headers, path scan |
| 3 | **SCRATCH** | Directory brute force — soft-404 detection, wordlist custom |
| 4 | **WHISKER** | DNS/WHOIS/GeoIP + Zone Transfer (AXFR) + crt.sh subdomains |
| 6 | **CATNAP** | Subdomain enumerator — DNS + HTTP check |
| 9 | **GHOST** | Username OSINT — vérification sur 30+ plateformes |
| 10 | **OSINT+** | Email / phone / IP / Google dorks OSINT étendu |
| 18 | **WAF** | WAF / CDN fingerprinting — 11 signatures (Cloudflare, Akamai, AWS WAF...) |
| 28 | **CVE** | CVE lookup & version matcher — NVD API + CIRCL.lu |
| 29 | **HARVEST** | Email harvester — crt.sh, archive.org, GitHub, scraping |
| 30 | **TAKEOVER** | Subdomain takeover checker — 27 services, fallback multi-source |
| 37 | **GITDUMP** | Exposed git repo + 50+ sensitive file scanner |
| 39 | **SECRETSCAN** | Secret/credential scanner — AWS, GitHub, JWT, Stripe, 15 patterns |
| 44 | **BREACH** | Data breach checker — HIBP k-anonymity (FREE), email lookup |
| 45 | **SHODAN** | Shodan-Lite IP recon — internetdb.shodan.io (no key), CIDR scan |
| 60 | **IPLOOKUP** | IP/Domain intelligence — GeoIP, ASN, Shodan, AbuseIPDB, RDAP WHOIS |
| 61 | **PHONELOOKUP** | Phone number OSINT — pays, carrier, line type, HLR, liens OSINT |

### EXPLOIT (Web & App)

| # | Module | Description |
|---|--------|-------------|
| 5 | **HISS** | SQLi · XSS · SSRF · CRLF · Open Redirect · Host Header injection |
| 47 | **SQLI** | SQL injection avancé — error-based, boolean-blind, time-based, UNION, MariaDB |
| 48 | **CMDI** | OS command injection — verbose output, blind time-based, HTTP headers |
| 49 | **NOSQLI** | NoSQL injection — MongoDB $ne/$gt/$regex/$where, array confusion, JSON bypass |
| 50 | **ORMI** | ORM injection — TypeORM QB/orderBy/find, HQL, JPQL, LINQ, Django, Sequelize |
| 25 | **CORS** | CORS misconfiguration tester — wildcard, null origin, credentials |
| 26 | **LFI** | LFI / RFI tester — path traversal, double-encode, PHP wrappers |
| 27 | **FUZZ** | Parameter & endpoint fuzzer — param discovery, path discovery, value fuzzing |
| 35 | **SMUGGLE** | HTTP request smuggling — CL.TE / TE.CL / TE.TE (raw sockets) |
| 36 | **XXE** | XML External Entity injection — 10 payloads, OOB, SSRF, error-based |
| 38 | **SSTI** | Server-side template injection — 10 payloads, RCE hints |
| 40 | **CACHE** | Web cache poisoning & deception — 10 unkeyed header tests |
| 41 | **OAUTH** | OAuth 2.0 / OIDC misconfiguration — open redirect, state CSRF, PKCE |
| 42 | **DESERIA** | Deserialization tester — PHP / Java / Python pickle / Node.js |
| 43 | **PROTO** | Prototype pollution tester — query, JSON, form, path injection |
| 53 | **IDOR** | IDOR / BOLA — path swap, param swap, JSON field, REST pattern discovery |
| 54 | **UPLOAD** | File upload bypass — 21 techniques (double ext, magic bytes, .htaccess, JSP...) |
| 55 | **RACE** | Race condition — synchronized burst (threading.Barrier), double-spend detection |
| 56 | **LDAPI** | LDAP injection — 15 auth bypass payloads, blind, user enumeration |

### RÉSEAU / INFRASTRUCTURE

| # | Module | Description |
|---|--------|-------------|
| 8 | **PROXYCAT** | Proxy manager — 35+ sources, validation parallèle, HTTP/SOCKS4/SOCKS5 |
| 15 | **NETKIT** | Network utilities — ping, traceroute, WHOIS, CIDR scan (jusqu'à /16) |
| 16 | **STRESS** | Stress tester — 26 méthodes L7/L4/L3 + SWARM + bypass Cloudflare + SPECTER/WRAITH |
| 21 | **BRUTE** | HTTP brute force — form auto-detect + CSRF, Basic auth, proxy rotation |
| 22 | **CMS** | CMS fingerprinting — WordPress, Drupal, Joomla, Laravel, Django, Flask... |
| 23 | **SSLSCAN** | SSL/TLS deep scanner — protocols, ciphers, cert, HTTP security headers |
| 31 | **BUCKET** | Cloud bucket finder — AWS S3, GCS, Azure Blob, DigitalOcean Spaces |
| 32 | **SPRAY** | Password spraying — HTTP form, Basic auth, NTLM |
| 33 | **GRAPHQL** | GraphQL security tester — introspection, injection, mutations |
| 34 | **2FA** | 2FA bypass tester — OTP brute, reuse, response manip, backup codes, skip |
| 51 | **WPSCAN** | WordPress vuln scanner — version + CVEs, plugins, thèmes, user enum, XMLRPC |
| 52 | **FRONTSCAN** | React/TypeScript/TSX — analyse statique .ts/.tsx + scan remote bundle/sourcemaps |

### PHISHING / RED TEAM

| # | Module | Description |
|---|--------|-------------|
| 24 | **PHISH** | Phishing page + tunnel — 7 templates pixel-perfect + cloudflared auto-dl |
| 46 | **TRACK** | Chameleon IP Grabber — OGP bait + og:video Discord embed + GeoIP live |
| 58 | **URLSPOOF** | URL spoofing — IDN homograph (Cyrillique/Grec), typosquatting, subdomain tricks, @ trick, data:URI, bit-squatting |
| 59 | **MAILSPOOF** | Email spoofing — display name, reply-to hijack, lookalike domain, open relay test, SMTP send |

### EMAIL SECURITY

| # | Module | Description |
|---|--------|-------------|
| 57 | **EMAILSEC** | SPF / DKIM / DMARC / BIMI analysis + spoof risk score 0–10 |

### UTILS

| # | Module | Description |
|---|--------|-------------|
| 11 | **PAWS** | Password generator — patterns, wordlists, PIN |
| 12 | **MEWHASH** | Hash tools — crack offline + rule-based (l33t, mutations) + lookup sans API |
| 13 | **CODEC** | Encoder / decoder — Base64/32/16, URL, HTML, ROT13, hex, XOR... |
| 14 | **PAYLOAD** | Payload library — XSS, SQLi, path traversal, LFI, SSTI... |
| 17 | **REVSHELL** | Reverse shell generator — 21 types (Bash, Python, PHP, PowerShell, Netcat...) |
| 19 | **JWTCAT** | JWT attacker — alg:none, RS256→HS256 confusion, HMAC brute force, forge |
| 7 | **LOOT** | Saved results viewer — JSON browser |
| 20 | **REPORT** | HTML report generator — dark matrix theme, toutes sections |

---

## 🐱 Menu interactif

```
╭──────────────── ◈  MEOW-SEC  v1.5  ::  61 modules  ◈ ────────────────╮
│  /\_/\           /\_/\           /\_/\           /\_/\                │
│ ( o.o )         ( >.< )         ( ^.^ )         ( o_o )               │
│   > w <           > ~ <           > v <           > x <               │
│ ─ RECON ─       ─EXPLOIT─       ─RÉSEAU─        ─ UTILS ─             │
│ ──────────────  ──────────────  ──────────────  ──────────────        │
│  [ 1] CLAW       [ 5] HISS       [ 8] PROXYCAT   [11] PAWS            │
│  [ 2] PURR       [47] SQLI       [15] NETKIT     [12] MEWHASH          │
│  [ 3] SCRATCH    [48] CMDI       [16] STRESS     [13] CODEC            │
│  [ 4] WHISKER    [49] NOSQLI     [21] BRUTE      [14] PAYLOAD          │
│  [ 6] CATNAP     [50] ORMI       [22] CMS        [17] REVSHELL         │
│  [ 9] GHOST      [53] IDOR       [23] SSLSCAN    [19] JWTCAT           │
│  [10] OSINT+     [54] UPLOAD     [31] BUCKET     [ 7] LOOT             │
│  [18] WAF        [55] RACE       [32] SPRAY      [20] REPORT           │
│  [28] CVE        [56] LDAPI      [33] GRAPHQL    [24] PHISH            │
│  [29] HARVEST    [58] URLSPOOF   [34] 2FA        [46] TRACK            │
│  [30] TAKEOVER   [59] MAILSPOOF  [51] WPSCAN     [ 0] EXIT             │
│  [37] GITDUMP    [25] CORS       [52] FRONTSCAN                        │
│  [39] SECRETSCAN [26] LFI        [57] EMAILSEC                        │
│  [44] BREACH     [35] SMUGGLE    [60] IPLOOKUP                        │
│  [45] SHODAN     [36] XXE        [61] PHONELOOKUP                     │
│  [60] IPLOOKUP   [40] CACHE                                            │
│  [61] PHONELOOKUP[41] OAUTH                                            │
╰────────────────────────────────────────────────────────────────────────╯
```

---

## 🔎 Détail des modules — Deep Dive

### RECON

#### Module 60 — IPLOOKUP (IP / Domain Intelligence)
Lookup multi-sources en parallèle, sans clé API requise :
- **GeoIP** : pays, région, ville, coordonnées, timezone via `ip-api.com` + `ipinfo.io`
- **ASN / ISP** : numéro AS, organisation, provider, CIDR via `bgp.tools`
- **Shodan InternetDB** : ports ouverts, CPEs, hostnames, tags (honeypot/VPN/CDN), CVEs
- **AbuseIPDB** : score d'abus 0–100, nombre de signalements, flag Tor
- **RDAP WHOIS** : ARIN / RIPE (selon région) — handle, organisation, country
- **Reverse DNS** : résolution PTR socket
- **Lien Google Maps** automatique avec coordonnées GPS
- **Modes** : IP/domaine unique · scan CIDR (jusqu'à /24) · bulk depuis fichier

#### Module 61 — PHONELOOKUP (Phone Number OSINT)
- **Normalisation E.164** : accepte tous formats (`0612345678`, `+33612345678`, `0033612345678`)
- **Table de pays** : 60+ préfixes nationaux avec carriers connus par pays
- **Type de ligne** : heuristiques par pays (mobile/landline/toll-free/premium)
  - France : `06`/`07` = Mobile, `08` = Spécial, `01`-`05` = Fixe
  - UK : `07` = Mobile, `080` = Gratuit, `09` = Premium
  - Allemagne : `015x/016x/017x` = Mobile
  - Inde : `6`-`9` = Mobile
  - Chine : `13x-19x` = Mobile
- **HLR Lookup** (free tier) : réseau actuel, numéro porté, opérateur
- **numverify** (free tier) : carrier, type, location
- **10 liens OSINT** : Truecaller, Sync.me, SpyDialer, WhitePages, NumLookup, WhatsApp, Telegram...
- **Liens spam check** : ShouldIAnswer, WhocallsMe

---

### PHISHING / RED TEAM

#### Module 58 — URLSPOOF (URL Spoofing & Lookalike Domain)
Génère toutes les variantes d'un domaine pour phishing / awareness training :

| Technique | Exemple | Risque |
|-----------|---------|--------|
| **IDN Homograph** | `pаypal.com` (Cyrillique а) | CRITICAL |
| **IDN Homograph (Grec)** | `payρal.com` (ρ = rho) | CRITICAL |
| **Typosquatting — missing** | `paypl.com` | HIGH |
| **Typosquatting — double** | `payypal.com` | HIGH |
| **Typosquatting — keyboard** | `oaypal.com` (p→o) | HIGH |
| **TLD swap** | `paypal.co`, `paypal.io` | MEDIUM |
| **Subdomain trick** | `paypal.login-secure.com` | CRITICAL |
| **Brand-keyword combo** | `paypal-secure.com` | HIGH |
| **@ trick (RFC3986)** | `https://paypal.com@evil.com` | HIGH |
| **data: URI** | `data:text/html;base64,...` | MEDIUM |
| **Open redirect chain** | `https://real.com/redirect?url=evil` | CRITICAL |
| **Bit-squatting** | `paypal.com` (bit flip) | MEDIUM |

- **Vérification DNS** automatique : domaines FREE (non enregistrés) vs TAKEN
- Export JSON complet

#### Module 59 — MAILSPOOF (Email Spoofing)
- **Vérification spoofabilité** : SPF + DMARC check automatique — verdict SPOOFABLE / PROTECTED
- **8 techniques générées** :
  - Display name spoof (`"PayPal Security" <noreply@evil.com>`)
  - Reply-To hijack (From légitime, réponse vers attaquant)
  - Subaddressing (`security+paypal@gmail.com`)
  - Unicode dans le display name (Cyrillique Ѕ → S)
  - Lookalike domain (o→0 substitution)
  - Cousin domain (TLD swap `.co`)
  - IDN / Punycode
  - Direct From spoof si SPF `~all` ou DMARC `p=none`
- **Test open relay** : SMTP port 25, MAIL FROM + RCPT TO — détecte serveurs relais ouverts
- **Envoi SMTP** configurable : From forgé, Reply-To attaquant, body HTML, STARTTLS/SSL

---

### INJECTION WEB

#### Module 47 — SQLI (SQL Injection Avancé)
4 méthodes, 7 bases détectées :

| Méthode | Description |
|---------|-------------|
| **Error-based** | Signatures d'erreur par DB (MySQL, MariaDB, PostgreSQL, MSSQL, Oracle, SQLite) |
| **Boolean-blind** | AND 1=1 vs AND 1=2 — comparaison taille + status |
| **Time-based blind** | SLEEP/WAITFOR/pg_sleep — seuil 3× baseline |
| **UNION-based** | Détection automatique du nombre de colonnes (jusqu'à 20) |

**MariaDB** spécifique : `er_parse_error`, `com.mariadb.jdbc` — extraction avec champ `engine` depuis `information_schema`

#### Module 48 — CMDI (OS Command Injection)
- **Verbose** : marqueurs Unix (`uid=`, `root`, `www-data`) + Windows (`NT AUTHORITY`, `system32`)
- **Blind time-based** : `sleep 4` Linux / `ping -n 5 127.0.0.1` Windows
- **Header injection** : User-Agent, Referer, X-Forwarded-For, X-Real-IP

#### Module 49 — NOSQLI (NoSQL Injection)
- MongoDB `$ne/$gt/$regex/$where/$nin` (GET params et JSON body)
- Array type confusion (`param=val` → `param[]=val`)
- `$where` JavaScript injection + blind timing
- Redis / CouchDB error signatures

#### Module 50 — ORMI (ORM Injection)
Supporte : **TypeORM** · Hibernate/HQL · JPQL · LINQ · Django ORM · Eloquent · ActiveRecord · Sequelize

**TypeORM spécifique :**
- `QueryBuilder.where()` string concat — 10 payloads ciblés
- `.orderBy(userInput)` ORDER BY injection
- `find({where: req.body})` operator bypass avec FindOperator internals `{"_type": "moreThan"}`
- `dataSource.query(\`${input}\`)` raw query injection

#### Module 53 — IDOR (Insecure Direct Object Reference)
- **Path swap** : ±5 IDs voisins, UUID variants, termes communs (`admin`, `null`, `root`)
- **Param swap** : même logique sur query string
- **JSON body** : swaps sur champ configurable (POST REST API)
- **BOLA patterns** : 15 routes REST standard auto-testées

#### Module 54 — UPLOAD (File Upload Bypass)
21 techniques dont :
- Double extension `.php.jpg`, `.jpg.php`, `.php5`, `.phtml`, case mixing `.pHp`
- MIME spoof : shell PHP envoyé en `image/jpeg`/`image/png`
- Magic bytes polyglot : `GIF89a` + shell PHP
- `.htaccess` : `AddType application/x-httpd-php .jpg`
- `web.config` IIS
- Path traversal filename : `../shell.php`
- SVG/HTML XSS si servi directement
- JSP et ASPX shells
- Null byte `%00`
- Vérification d'exécution automatique sur 8+ chemins

#### Module 55 — RACE (Race Condition)
- `threading.Barrier(N)` — tous les threads tirent à la même milliseconde
- Pré-warm TCP : connexion préalable pour éliminer latence TLS
- Scénarios : coupon, vote, gift card, password reset, achat, 2FA, custom
- Détection : variance de taille, mix 200/409, succès universel

#### Module 56 — LDAPI (LDAP Injection)
- 15 payloads auth bypass : `*)(uid=*`, `admin)(&`, `*))%00`, `\2a` hex, nested OR/NOT
- Blind : comparaison status/taille
- Enum : 14 usernames communs avec wildcard password

---

### WORDPRESS & FRONTEND

#### Module 51 — WPSCAN (WordPress Scanner)
- **Version** : `readme.html`, meta generator, RSS, `?ver=` assets
- **CVEs intégrés** : WP 4.x → 6.4+ avec CVE-ID, sévérité, description
- **20 plugins vulnérables** : contact-form-7, woocommerce, elementor, wp-file-manager, revslider, duplicator, timthumb...
- **5 thèmes vulnérables** : divi, avada, enfold, newspaper
- **User enum** : REST API `/wp-json/wp/v2/users` + redirect `?author=1..5`
- **XML-RPC** : détection + `system.listMethods` (amplification)
- **25 fichiers sensibles** : `wp-config.php`, `.env`, `debug.log`, `phpinfo.php`...

#### Module 52 — FRONTSCAN (React / TypeScript / TSX)
**Analyse statique** (fichiers `.ts/.tsx/.js/.jsx`) — 40+ patterns :

| Catégorie | Patterns |
|-----------|---------|
| XSS | `dangerouslySetInnerHTML`, `innerHTML =`, `document.write`, `eval()` |
| TypeORM inject | QueryBuilder concat, `.orderBy(req.)`, `dataSource.query(\`${}\`)`, `find({where: req.body})` |
| Secrets | `apiKey`, `secretKey`, `password =`, clés AWS/Stripe/GitHub hardcodées |
| Stockage sensible | `localStorage`/`sessionStorage` avec `password`/`token`/`secret` |
| Open redirect | `window.location = params.`, navigation vers user input |
| Prototype pollution | `Object.assign({}, userInput)`, spread `...req.body` |

**Scan remote** : source maps exposées, secrets dans bundles, GraphQL introspection, `window.__INITIAL_STATE__`

---

### EMAIL SECURITY

#### Module 57 — EMAILSEC (Email Security Checker)
Analyse complète via DNS-over-HTTPS Cloudflare (sans dépendance dnspython) :

| Check | Détails |
|-------|---------|
| **SPF** | `+all` = CRITICAL · `~all` = MEDIUM · `-all` = OK · >10 DNS lookups = PermError |
| **DKIM** | 20+ sélecteurs testés auto · clé vide = révoquée · `t=y` = test mode |
| **DMARC** | `p=none` = HIGH · `p=quarantine` = LOW · `p=reject` = OK · `sp=` sous-domaines · `pct=` |
| **MX** | Présence et liste des serveurs |
| **BIMI** | Brand indicator (optionnel) |
| **Spoof score** | 0–10 composite SPF+DKIM+DMARC |

Verdict : `HIGHLY SPOOFABLE` / `MODERATELY SPOOFABLE` / `PARTIALLY PROTECTED` / `WELL PROTECTED`

---

## 🔄 Proxy Rotation

Tous les modules HTTP utilisent la rotation automatique via `core/proxy_manager.py` :

```
PROXYCAT [8] → télécharge depuis 35+ sources publiques
             → valide en parallèle (100 workers)
             → conserve le top 30% le plus rapide
             → sauvegarde dans data/proxies.json
```

Chaque module fait `proxies=px()` — si aucun proxy disponible, connexion directe automatique.

| Type | Format | Notes |
|------|--------|-------|
| HTTP | `ip:port` | Défaut |
| SOCKS4 | `socks4://ip:port` | Méthodes socket raw |
| SOCKS5 | `socks5://ip:port` | Recommandé pour l'anonymat |

---

## 🌐 Tunnels (`core/tunnel.py`)

| # | Service | Prérequis | Notes |
|---|---------|-----------|-------|
| 1 | **cloudflared** | Auto-téléchargé (~20 MB) | HTTPS, le plus fiable |
| 2 | **serveo.net** | SSH | Aucun install |
| 3 | **localhost.run** | SSH | Aucun install |
| 4 | **bore.pub** | `cargo install bore-cli` | Nécessite Rust |
| 5 | **Pas de tunnel** | — | LAN uniquement |

---

## 💥 STRESS — 26 méthodes

| Layer | Méthode | Description |
|-------|---------|-------------|
| L7 | `HTTP_GET/POST/HEAD` | Flood classique + User-Agent rotation + proxy |
| L7 | `HTTP_BYPASS` | X-Forwarded-For random + Pragma/no-cache + referrer |
| L7 | `HTTP_JSON` | JSON POST flood (REST APIs) |
| L7 | `HTTP_COOKIE` | Cookie overflow — 50-100 cookies/req |
| L7 | `HTTP_XMLRPC` | WordPress xmlrpc.php multicall (100 auth/req) |
| L7 | `RESONANCE` | Loi de Little — P75-based adaptive interval |
| L7 | `PULSAR` | **Vagues synchronisées** — threading.Barrier, sature accept() OS |
| L7 | `SLOWLORIS` | Keepalive starvation — connexions incomplètes |
| L7 | `RUDY` | R-U-Dead-Yet — slow POST, 1 byte/tick |
| L7 | `TLS` | TLS handshake flood — CPU-heavy |
| L4 | `TCP/UDP` | Connect flood / datagram flood |
| L3 | `ICMP` | Echo flood |
| L7 | `H2_CONTINUATION` | ★★★★★ CVE-2024-27316 — HEADERS sans END_HEADERS |
| L7 | `H2_RST` | ★★★★ CVE-2023-44487 — RST Storm |
| L7 | `WS_FLOOD` | ★★★★ WebSocket PING flood |
| ANON | `SPECTER` | ★★★★ Tor flood — auto-install, circuit renewal |
| ANON | `WRAITH` | ★★★★ I2P flood — garlic routing |
| ANON | `PHANTOM_MIX` | ★★★★ Tor + I2P alternés |
| MEGA | **`SWARM`** | ★★★★★ 5 méthodes simultanées |

**PULSAR** : `threading.Barrier(N)` synchronise tous les workers à la même milliseconde → sature le pool `accept()` OS.

**SWARM** : 30% BYPASS + 25% PULSAR + 20% COOKIE + 15% SLOWLORIS + 10% TLS.

**Bypass Cloudflare / JA3** : `curl_cffi` avec vraie empreinte TLS Chrome 110 — Cloudflare Bot Score voit du trafic légitime.

---

## 🎣 PHISH — 7 templates

| # | Template | Fidélité | Redirect |
|---|----------|----------|---------|
| 1 | **Microsoft 365** | Logo SVG 4 carrés, Segoe UI, card blanche | login.microsoftonline.com |
| 2 | **Google** | Logo SVG coloré, Roboto, floating labels animés | accounts.google.com |
| 3 | **LinkedIn** | Navbar complète, SVG, hero bordeaux | linkedin.com |
| 4 | **Discord** | Split-panel dark `#2b2d31`, blurple `#5865f2` | discord.com |
| 5 | **Steam** | Navbar dark blue, panel vert gradient | steampowered.com |
| 6 | **Instagram** | Logo SVG, "Log in with Facebook" | instagram.com |
| 7 | **Generic** | Terminal hacker — scanlines CSS, ASCII art | configurable |
| + | **Custom HTML** | Charge n'importe quel `.html` externe | configurable |

---

## 🕵️ TRACK — IP Grabber

| Thème | Type | Comportement Discord |
|-------|------|---------------------|
| Photo partagée | Image | Preview card → IP sur clic |
| Suivi de colis | Image | Preview card → IP sur clic |
| Document partagé | Image | Preview card → IP sur clic |
| Alerte sécurité | Image | Preview card → IP sur clic |
| Vidéo exclusive 🔥 | **og:video** | Embed ▶ Play → IP sur lecture |
| Clip inédit | **og:video** | Embed ▶ Play → IP sur lecture |
| Fail du jour 😂 | **og:video** | Embed ▶ Play → IP sur lecture |

---

## 🔑 JWTCAT — Attaques JWT

| Attaque | Description |
|---------|-------------|
| **alg:none** | 5 variantes de casse (none/None/NONE/nOnE/NoNe) |
| **RS256→HS256** | Confusion algorithme — signe avec la clé publique comme secret HMAC |
| **HMAC brute** | HS256/384/512 — wordlist custom ou dictionnaire 35 secrets communs |
| **Token forge** | Édition libre du payload + resign |

---

## 🖥️ Reverse Shells (21 types)

`bash_tcp` · `bash_b64` · `sh_udp` · `python3` · `python2` · `python_b64` · `php_exec` · `php_proc` · `nc_e` · `nc_mkfifo` · `perl` · `ruby` · `powershell` · `powershell_b64` · `powershell_download` · `node` · `socat` · `golang` · `java` · `awk` · `lua`

Listener intégré : `nc`, `ncat`, `socat`, `pwncat`, `metasploit`

---

## ☁️ BUCKET — Cloud Storage

| Provider | URL pattern | Détection |
|----------|-------------|-----------|
| AWS S3 | `s3.amazonaws.com/<name>` | PUBLIC_READ, EXISTS_403 |
| GCS | `storage.googleapis.com/<name>` | PUBLIC_READ, EXISTS_403 |
| Azure Blob | `<name>.blob.core.windows.net` | EXISTS_200/403 |
| DigitalOcean | `<name>.nyc3.digitaloceanspaces.com` | PUBLIC_READ, EXISTS_403 |

50+ variantes de noms auto-générées (préfixes/suffixes : `-backup`, `-dev`, `-prod`, `-assets`...)

---

## 📊 Rapport HTML (REPORT)

- Résumé timeline de tous les scans `data/*.json`
- Sections collapsibles : Ports, Web Recon, DNS, WAF, OSINT, Injections, CVE, Takeover, Buckets
- Dark matrix theme inline (aucune dépendance externe)
- Ouverture automatique dans le navigateur

---

## 🔄 Changelog

| Version | Modules | Nouveautés |
|---------|---------|------------|
| **v1.5** | 61 | URLSPOOF · MAILSPOOF · IPLOOKUP · PHONELOOKUP |
| **v1.4** | 57 | IDOR · UPLOAD · RACE · LDAPI · EMAILSEC |
| **v1.3** | 52 | SQLI · CMDI · NOSQLI · ORMI · WPSCAN · FRONTSCAN |
| **v1.2** | 46 | SMUGGLE · XXE · GITDUMP · SSTI · SECRETSCAN · CACHE · OAUTH · DESERIA · PROTO · BREACH · SHODAN · TRACK |
| **v1.1** | 34 | CORS · LFI · FUZZ · CVE · HARVEST · TAKEOVER · BUCKET · SPRAY · GRAPHQL · 2FA |
| **v1.0** | 24 | Core modules |

---

## Disclaimer

> **Ce projet est strictement éducatif.** Utilisation réservée aux CTF, red team autorisé et recherche en sécurité. L'utilisation de cet outil sur des systèmes sans autorisation explicite est illégale dans la plupart des juridictions. Les auteurs ne sont pas responsables de toute utilisation abusive. **Respectez la loi. Stay legal.**

---

## Credits

**by cat-project-hat** *(we do the best for you)*

---

```
   /\_/\
  ( o.o )   MEOW-SEC v1.5 // BY CAT-PROJECT-HAT // 2026
   > ^ <    61 modules · Python 3 · Rich TUI
  /|   |\   Stay in the shadows. Stay curious.
 (_|   |_)
```
