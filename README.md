```
   /\_/\
  ( o.o )  ~ nyaa ~
   > ^ <
  /|   |\
 (_|   |_)
```

# MEOW-SEC

**By cat-project-hat // v1.1 // 2026**

Toolkit de sécurité offensif Python 3 — interface TUI Rich — 24 modules — thème chat hacker

![Python](https://img.shields.io/badge/Python-3.10+-green?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue?style=flat-square)
![Modules](https://img.shields.io/badge/Modules-24-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-Educational-red?style=flat-square)
![Proxy](https://img.shields.io/badge/Proxy-Rotation-orange?style=flat-square)

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
│   └── proxy_manager.py ← Rotation de proxies (download, validate, rotate)
└── modules/
    ├── claw.py          ← Port & service scanner
    ├── purr.py          ← HTTP recon & header analyzer
    ├── scratch.py       ← Directory brute force
    ├── whisker.py       ← DNS / WHOIS / IP OSINT + AXFR + crt.sh
    ├── hiss.py          ← SQLi / XSS / SSRF / CRLF / open redirect / host header
    ├── catnap.py        ← Subdomain enumerator
    ├── proxycat.py      ← Proxy manager
    ├── ghost.py         ← Username OSINT
    ├── osint_ext.py     ← Email / phone / dorks / IP OSINT étendu
    ├── paws.py          ← Password generator
    ├── mewhash.py       ← Hash tools + rule-based cracker
    ├── codec.py         ← Encoder / decoder multi-format
    ├── payload.py       ← Payload library
    ├── netkit.py        ← Network utilities (ping, traceroute, CIDR scan /16)
    ├── stress.py        ← Stress tester L3/L4/L7 (9 méthodes)
    ├── loot.py          ← Saved results viewer
    ├── revshell.py      ← Reverse shell generator (21 types)
    ├── waf.py           ← WAF / CDN fingerprinting
    ├── jwtcat.py        ← JWT attacker (alg:none, RS256→HS256, HMAC brute)
    ├── report.py        ← HTML report generator (dark matrix theme)
    ├── brute.py         ← HTTP login brute force (form + Basic auth)
    ├── cms.py           ← CMS fingerprinting (11 frameworks)
    ├── sslscan.py       ← SSL/TLS deep scanner + crt.sh CT lookup
    └── phish.py         ← Phishing page + tunnel (serveo / localhost.run)
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
| 8 | **PROXYCAT** | Proxy manager — download, validate, rotate (5 sources publiques) |
| 9 | **GHOST** | Username OSINT — vérification sur 30+ plateformes |
| 10 | **OSINT+** | Email / phone / IP / Google dorks OSINT étendu |
| 11 | **PAWS** | Password generator — patterns, wordlists, PIN |
| 12 | **MEWHASH** | Hash tools — crack offline + rule-based (l33t, mutations) + lookup sans API |
| 13 | **CODEC** | Encoder / decoder — Base64/32/16, URL, HTML, ROT13, hex, XOR... |
| 14 | **PAYLOAD** | Payload library — XSS, SQLi, path traversal, LFI, SSTI... |
| 15 | **NETKIT** | Network utilities — ping, traceroute, WHOIS, CIDR scan (jusqu'à /16) |
| 16 | **STRESS** | Stress tester — L7: HTTP_GET/POST/HEAD/BYPASS/SLOWLORIS/RUDY · L4: TCP/UDP · L3: ICMP |
| 17 | **REVSHELL** | Reverse shell generator — 21 types (Bash, Python, PHP, PowerShell, Netcat...) |
| 18 | **WAF** | WAF / CDN fingerprinting — 11 signatures (Cloudflare, Akamai, AWS WAF...) |
| 19 | **JWTCAT** | JWT attacker — alg:none, RS256→HS256 confusion, HMAC brute force, forge |
| 20 | **REPORT** | HTML report generator — agrège tous les scans, dark matrix theme |
| 21 | **BRUTE** | HTTP brute force — form auto-detect + CSRF, Basic auth, proxy rotation |
| 22 | **CMS** | CMS fingerprinting — WordPress, Drupal, Joomla, Laravel, Django, Flask... |
| 23 | **SSLSCAN** | SSL/TLS deep scanner — protocols, ciphers, cert, HTTP security headers |
| 24 | **PHISH** | Phishing page + tunnel sans port forwarding — Microsoft 365 / Google / LinkedIn |

---

## 🐱 Menu

```
╭──────────────── ◈  MEOW-SEC  v1.1  ::  24 modules  ◈ ────────────────╮
│  /\_/\          /\_/\          /\_/\          /\_/\                   │
│ ( o.o )        ( >.< )        ( ^.^ )        ( o_o )                  │
│   > w <          > ~ <          > v <          > x <                  │
│ ─ RECON ─      ─ TOOLS ─      ─NETWORK─      ─ UTILS ─                │
│ ────────────   ────────────   ────────────   ────────────             │
│  [ 1] CLAW      [11] PAWS      [ 8] PROXYCAT  [ 7] LOOT               │
│  [ 2] PURR      [12] MEWHASH   [15] NETKIT    [20] REPORT             │
│  [ 3] SCRATCH   [13] CODEC     [16] STRESS    [24] PHISH              │
│  [ 4] WHISKER   [14] PAYLOAD   [21] BRUTE     [ 0] EXIT               │
│  [ 5] HISS      [17] REVSHELL  [22] CMS                               │
│  [ 6] CATNAP    [19] JWTCAT    [23] SSLSCAN                           │
│  [ 9] GHOST                                                           │
│  [10] OSINT+                                                          │
│  [18] WAF                                                             │
╰───────────────────────────────────────────────────────────────────────╯
```

---

## 🔄 Proxy Rotation

Tous les modules HTTP utilisent la rotation automatique de proxies via `core/proxy_manager.py`.

```
PROXYCAT [1] → télécharge 1000+ proxies depuis 5 sources publiques
             → valide en parallèle (100 workers)
             → sauvegarde dans data/proxies.json
```

Chaque module fait `proxies=px()` — si aucun proxy disponible, connexion directe automatique.

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

Tunnels disponibles :
| Service | Commande interne | Prérequis |
|---------|-----------------|-----------|
| **serveo.net** | `ssh -R 80:localhost:PORT serveo.net` | SSH uniquement |
| **localhost.run** | `ssh -R 80:localhost:PORT nokey@localhost.run` | SSH uniquement |
| **bore.pub** | `bore local PORT --to bore.pub` | `cargo install bore-cli` |

---

## 📦 Installation

```bash
# Cloner / copier le dossier
cd meow-sec

# Dépendances Python
pip install -r requirements.txt
# OU
pip install rich colorama requests

# Lancer
python meow.py

# Lancement direct d'un module
python meow.py claw
python meow.py hiss
python meow.py phish
```

**requirements.txt**
```
rich>=13.7.0
colorama>=0.4.6
requests>=2.31.0
```

---

## 🔧 Détail des méthodes STRESS

| Layer | Méthode | Description |
|-------|---------|-------------|
| L7 | `HTTP_GET` | GET flood avec User-Agent rotation |
| L7 | `HTTP_POST` | POST flood avec body aléatoire |
| L7 | `HTTP_HEAD` | HEAD flood avec cache-busting |
| L7 | `HTTP_BYPASS` | X-Forwarded-For random + Pragma/no-cache + referrer spoofing |
| L7 | `SLOWLORIS` | Keepalive starvation — connexions incomplètes |
| L7 | `RUDY` | R-U-Dead-Yet — slow POST (Content-Length=999999, 1 byte/tick) |
| L4 | `TCP` | TCP connect flood |
| L4 | `UDP` | UDP datagram flood |
| L3 | `ICMP` | ICMP echo flood (raw socket) |

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

## 🌐 Détail WHISKER (nouvelles options)

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

## 📊 Rapport HTML (REPORT)

Le module REPORT agrège tous les fichiers JSON de `data/` et génère un rapport HTML standalone avec :
- Résumé timeline de tous les scans
- Sections : Ports, Web Recon, DNS, WAF, OSINT, Stress
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
