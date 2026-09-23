```
   /\_/\
  ( o.o )  ~ nyaa ~
   > ^ <
  /|   |\
 (_|   |_)
```

# MEOW-SEC

**By cat-project-hat // v1.2 // 2026**

Toolkit de sécurité offensif Python 3 — interface TUI Rich — 46 modules — thème chat hacker

![Python](https://img.shields.io/badge/Python-3.10+-green?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue?style=flat-square)
![Modules](https://img.shields.io/badge/Modules-46-brightgreen?style=flat-square)
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
│   ├── proxy_manager.py ← Rotation de proxies (download, validate, rotate — 35+ sources)
│   └── tunnel.py        ← Tunnel manager centralisé (cloudflared / serveo / localhost.run / bore)
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
    ├── stress.py        ← Stress tester L3/L4/L7 (26 méthodes + SWARM + bypass CF)
    ├── loot.py          ← Saved results viewer
    ├── revshell.py      ← Reverse shell generator (21 types)
    ├── waf.py           ← WAF / CDN fingerprinting
    ├── jwtcat.py        ← JWT attacker (alg:none, RS256→HS256, HMAC brute)
    ├── report.py        ← HTML report generator (dark matrix theme)
    ├── brute.py         ← HTTP login brute force (form + Basic auth)
    ├── cms.py           ← CMS fingerprinting (11 frameworks)
    ├── sslscan.py       ← SSL/TLS deep scanner + crt.sh CT lookup
    ├── phish.py         ← Phishing page + tunnel — 7 templates pixel-perfect
    ├── phish_templates/ ← HTML séparés (Microsoft / Google / LinkedIn / Discord / Steam / Instagram / Generic)
    ├── cors.py          ← CORS misconfiguration tester
    ├── lfi.py           ← LFI / RFI tester (traversal, PHP wrappers)
    ├── fuzz.py          ← Parameter & endpoint fuzzer
    ├── cve.py           ← CVE lookup & version matcher (NVD + CIRCL)
    ├── harvest.py       ← Email harvester (crt.sh, archive.org, GitHub)
    ├── takeover.py      ← Subdomain takeover checker (27 services, multi-source fallback)
    ├── bucket.py        ← Cloud bucket finder (S3, GCS, Azure, DO)
    ├── spray.py         ← Password spraying (HTTP form, Basic, NTLM)
    ├── graphql.py       ← GraphQL security tester
    ├── twofa.py         ← 2FA bypass tester
    ├── smuggle.py       ← HTTP request smuggling tester (CL.TE / TE.CL / TE.TE)
    ├── xxe.py           ← XML external entity injection tester (10 payloads)
    ├── gitdump.py       ← Exposed git + sensitive file scanner (50+ paths)
    ├── ssti.py          ← Server-side template injection tester
    ├── secretscan.py    ← Secret / credential scanner in HTTP responses
    ├── cache.py         ← Web cache poisoning & deception tester
    ├── oauth.py         ← OAuth 2.0 / OIDC misconfiguration tester
    ├── deseria.py       ← Deserialization vulnerability tester (PHP/Java/Pickle/Node)
    ├── proto.py         ← Prototype pollution tester (Node.js)
    ├── breach.py        ← Data breach checker (HIBP k-anonymity + LeakCheck)
    ├── shodan_lite.py   ← Shodan-Lite IP recon (internetdb.shodan.io, no key)
    └── track.py         ← Chameleon IP Grabber — OGP bait + og:video Discord embed
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
| 16 | **STRESS** | Stress tester — 26 méthodes L7/L4/L3 + SWARM + bypass Cloudflare + SPECTER/WRAITH auto-install |
| 17 | **REVSHELL** | Reverse shell generator — 21 types (Bash, Python, PHP, PowerShell, Netcat...) |
| 18 | **WAF** | WAF / CDN fingerprinting — 11 signatures (Cloudflare, Akamai, AWS WAF...) |
| 19 | **JWTCAT** | JWT attacker — alg:none, RS256→HS256 confusion, HMAC brute force, forge |
| 20 | **REPORT** | HTML report generator — agrège tous les scans, dark matrix theme |
| 21 | **BRUTE** | HTTP brute force — form auto-detect + CSRF, Basic auth, proxy rotation |
| 22 | **CMS** | CMS fingerprinting — WordPress, Drupal, Joomla, Laravel, Django, Flask... |
| 23 | **SSLSCAN** | SSL/TLS deep scanner — protocols, ciphers, cert, HTTP security headers |
| 24 | **PHISH** | Phishing page + tunnel — 7 templates pixel-perfect + cloudflared auto-dl |
| 25 | **CORS** | CORS misconfiguration tester — wildcard, null origin, credentials reflection |
| 26 | **LFI** | LFI / RFI tester — path traversal, double-encode, PHP wrappers |
| 27 | **FUZZ** | Parameter & endpoint fuzzer — param discovery, path discovery, value fuzzing |
| 28 | **CVE** | CVE lookup & version matcher — NVD API + CIRCL.lu, auto-fingerprint cible |
| 29 | **HARVEST** | Email harvester — crt.sh, archive.org, GitHub, scraping, pattern generation |
| 30 | **TAKEOVER** | Subdomain takeover checker — 27 services, fallback multi-source (crt.sh → HackerTarget → riddler) |
| 31 | **BUCKET** | Cloud bucket finder — AWS S3, GCS, Azure Blob, DigitalOcean Spaces |
| 32 | **SPRAY** | Password spraying — HTTP form, Basic auth, NTLM (auth requise) |
| 33 | **GRAPHQL** | GraphQL security tester — introspection, injection, mutations |
| 34 | **2FA** | 2FA bypass tester — OTP brute, reuse, response manip, backup codes, skip |
| 35 | **SMUGGLE** | HTTP request smuggling tester — CL.TE / TE.CL / TE.TE (raw sockets) |
| 36 | **XXE** | XML External Entity injection tester — 10 payloads, OOB, SSRF, error-based |
| 37 | **GITDUMP** | Exposed git repo + 50+ sensitive file scanner (keys, .env, backups) |
| 38 | **SSTI** | Server-side template injection — 10 detection payloads, RCE hints |
| 39 | **SECRETSCAN** | Secret/credential scanner in responses — AWS, GitHub, JWT, Stripe, 15 patterns |
| 40 | **CACHE** | Web cache poisoning & deception tester — 10 unkeyed header tests |
| 41 | **OAUTH** | OAuth 2.0 / OIDC misconfiguration — open redirect, state, PKCE, implicit flow |
| 42 | **DESERIA** | Deserialization vulnerability tester — PHP / Java / Python pickle / Node.js |
| 43 | **PROTO** | Prototype pollution tester — query, JSON, form, path injection vectors |
| 44 | **BREACH** | Data breach checker — HIBP k-anonymity (FREE), email lookup, breach list |
| 45 | **SHODAN** | Shodan-Lite IP recon — internetdb.shodan.io (no key), CIDR scan, crt.sh |
| 46 | **TRACK** | Chameleon IP Grabber — OGP bait + og:video Discord embed + GeoIP live |

---

## 🔍 Détail des modules injection/exploit

### Module 35 — SMUGGLE (HTTP Request Smuggling)
Utilise des raw sockets (pas de requests) pour envoyer des payloads HTTP précis :
- **CL.TE** : Content-Length inclut des octets après le 0-chunk TE — mesure le delta de temps
- **TE.CL** : Transfer-Encoding chunked 1 octet, CL=3 — détecte 400/500 ou hang
- **TE.TE** : 5 variantes d'obfuscation du header Transfer-Encoding

### Module 36 — XXE (XML External Entity)
10 payloads testés avec `application/xml` et `text/xml` :
- Lecture de fichiers locaux (`/etc/passwd`, `win.ini`)
- SSRF vers les métadonnées AWS (169.254.169.254) et localhost:22
- Blind OOB avec callback URL configurable
- Error-based, CDATA exfil, SVG XXE, PHP `expect://`, SOAP XXE

### Module 37 — GITDUMP (Git & Sensitive File Scanner)
- Phase 1 : 50+ chemins sensibles (`.git/`, `.env`, clés privées, backups, configs)
- Phase 2 : si `.git/HEAD` trouvé → télécharge les internals git, parse les URLs de remote
- Risque HIGH : fichiers git, `.env`, credentials, clés privées

### Module 38 — SSTI (Template Injection)
10 payloads de détection testés via GET, POST form, POST JSON, segment de path :
- Détection d'engine par la valeur retournée (49, 7777777, A...)
- Suggestions de payloads RCE pour Jinja2, Twig, FreeMarker, Mako

### Module 39 — SECRETSCAN (Secret Scanner)
15 patterns regex (AWS, GitHub, Google, JWT, clé privée, DB URL, Slack, Stripe...) :
- Mode single URL ou crawl (profondeur 2, max 50 pages)
- Tronque les valeurs trouvées à 40 chars pour éviter l'exposition

### Module 40 — CACHE (Cache Poisoning)
- 10 tests d'headers non-keyés (X-Forwarded-Host, X-Original-URL, Fat GET...)
- Compare status + taille de réponse avec le baseline
- Test cache deception : extensions statiques fake sur des chemins protégés

### Module 41 — OAUTH (OAuth 2.0 Misconfiguration)
- Découverte automatique (`.well-known/openid-configuration`)
- 7 vérifications : open redirect_uri, state CSRF, implicit flow, PKCE, client secret en JS, token endpoint GET
- Scan du source de la page pour `client_secret` / `clientSecret`

### Module 42 — DESERIA (Deserialization)
- **PHP** : payloads `O:8:"stdClass":0:{}`, détection via erreurs `__wakeup`/`__destruct`
- **Java** : magic bytes `AC ED 00 05`, détection ClassNotFoundException
- **Python pickle** : magic `\x80\x04`, détection erreurs unpickling
- **Node.js** : `_$$ND_FUNC$$_` node-serialize RCE pattern

### Module 43 — PROTO (Prototype Pollution)
- Injection via query string (`__proto__[testprop]=marker`)
- Injection via JSON body (`{"__proto__": {...}}`)
- Injection via form POST et segment de chemin URL
- Détection si le marker `meow_polluted_7749` apparaît dans la réponse

### Module 44 — BREACH (Data Breach Checker)
- **Mode 1** : check mot de passe par k-anonymité HIBP (SHA1, envoie seulement 5 chars, **GRATUIT**)
- **Mode 2** : check email via HIBP v3 (clé API requise) + LeakCheck.io (free tier)
- **Mode 3** : liste toutes les brèches connues, filtrable par domaine

### Module 45 — SHODAN (Shodan-Lite)
- Utilise `https://internetdb.shodan.io/{ip}` (API publique, sans clé)
- Affiche : ports ouverts, CPEs, hostnames, tags (honeypot/VPN/CDN), CVE IDs
- Scan CIDR /24 (256 IPs) en parallèle
- Lookup de domaine + résolution DNS + crt.sh pour les sous-domaines via CT

---

## 🐱 Menu

```
╭─────────────── ◈  MEOW-SEC  v1.2  ::  46 modules  ◈ ─────────────────╮
│  /\_/\           /\_/\           /\_/\           /\_/\                │
│ ( o.o )         ( >.< )         ( ^.^ )         ( o_o )               │
│   > w <           > ~ <           > v <           > x <               │
│ ─ RECON ─       ─EXPLOIT─       ─NETWORK─       ─ UTILS ─             │
│ ──────────────  ──────────────  ──────────────  ──────────────        │
│  [ 1] CLAW       [ 5] HISS       [ 8] PROXYCAT   [11] PAWS            │
│  [ 2] PURR       [25] CORS       [15] NETKIT     [12] MEWHASH          │
│  [ 3] SCRATCH    [26] LFI        [16] STRESS     [13] CODEC            │
│  [ 4] WHISKER    [27] FUZZ       [21] BRUTE      [14] PAYLOAD          │
│  [ 6] CATNAP     [35] SMUGGLE    [22] CMS        [17] REVSHELL         │
│  [ 9] GHOST      [36] XXE        [23] SSLSCAN    [19] JWTCAT           │
│  [10] OSINT+     [38] SSTI       [31] BUCKET     [ 7] LOOT             │
│  [18] WAF        [40] CACHE      [32] SPRAY      [20] REPORT           │
│  [28] CVE        [41] OAUTH      [33] GRAPHQL    [24] PHISH            │
│  [29] HARVEST    [42] DESERIA    [34] 2FA        [46] TRACK            │
│  [30] TAKEOVER   [43] PROTO                      [ 0] EXIT             │
│  [37] GITDUMP                                                          │
│  [39] SECRETSCAN                                                       │
│  [44] BREACH                                                           │
│  [45] SHODAN                                                           │
╰────────────────────────────────────────────────────────────────────────╯
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

## 🌐 Tunnels (`core/tunnel.py`)

Tous les modules nécessitant une URL publique (PHISH, TRACK) partagent le même gestionnaire de tunnel :

| # | Service | Prérequis | Notes |
|---|---------|-----------|-------|
| 1 | **cloudflared** | Auto-téléchargé (~20 MB, une seule fois) | HTTPS, le plus fiable, vérifié avant usage |
| 2 | **serveo.net** | SSH | Aucun install |
| 3 | **localhost.run** | SSH | Aucun install |
| 4 | **bore.pub** | `cargo install bore-cli` | Nécessite Rust |
| 5 | **Pas de tunnel** | — | LAN uniquement |

Le tunnel attend activement que l'URL soit joignable (probe HTTP, max 15s) avant d'afficher le lien — plus de `ERR_NAME_NOT_RESOLVED`.

---

## 💥 Détail des méthodes STRESS (26 méthodes)

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
| L7 | 18 | `MIRROR` | Multi-target round-robin — frappe N cibles en parallèle |
| L7 | 19 | `H2_CONTINUATION` | ★★★★★ HEADERS sans END_HEADERS → OOM serveur (CVE-2024-27316) |
| L7 | 20 | `H2_RST` | ★★★★ RST Storm → alloc/dealloc par stream (CVE-2023-44487) |
| L7 | 21 | `WS_FLOOD` | ★★★★ WebSocket PING flood → PONG obligatoire RFC 6455 |
| L7 | 22 | `SLOW_CHUNK` | ★★★ Chunked slow body → bypass mitigations RUDY |
| L4 | 23 | `QUIC_FLOOD` | ★★★ UDP/443 QUIC Initial flood → cibles HTTP/3 |
| ANON | 24 | `SPECTER` | ★★★★ Tor flood — auto-install Tor + stem, circuit renewal |
| ANON | 25 | `WRAITH` | ★★★★ I2P flood — garlic routing, auto-install i2p (Linux) |
| ANON | 26 | `PHANTOM_MIX` | ★★★★ Tor + I2P alternés — double pool d'exit IPs, auto-fallback |
| MEGA | — | `SWARM` | ★★★★★ MULTI-VECTEUR 5 méthodes simultanées (voir ci-dessous) |

### Méthodes anonymes — auto-install

SPECTER, WRAITH et PHANTOM_MIX installent et démarrent automatiquement les outils nécessaires :

| Méthode | Dépendance | Windows | Linux | macOS |
|---------|-----------|---------|-------|-------|
| SPECTER | Tor daemon | winget → Tor Expert Bundle (auto-dl) | apt/dnf/pacman install tor + systemctl | brew install tor |
| SPECTER | stem (Python) | pip install stem | pip install stem | pip install stem |
| WRAITH | I2P + proxy port 4444 | instructions manuelles | apt install i2p + i2prouter start | instructions manuelles |
| PHANTOM_MIX | Tor + I2P | combiné ci-dessus | combiné ci-dessus | combiné ci-dessus |

Le module attend activement que le port réponde (9050 pour Tor, 4444 pour I2P) avant de lancer les workers.

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

### SWARM 🌪️ (multi-vecteur — pire qu'un botnet)

Lance **5 factions simultanées** sur la même cible :

| Faction | % workers | Méthode |
|---------|-----------|---------|
| BYPASS | 30% | HTTP_BYPASS — headers X-Forwarded-For aléatoires |
| PULSAR | 25% | Vagues synchronisées (Barrier) |
| COOKIE | 20% | Cookie overflow — 50-100 cookies/req |
| SLOWLORIS | 15% | Keepalive starvation |
| TLS | 10% | TLS handshake flood |

```bash
# Exemple : 200 workers SWARM pendant 120s
[16] STRESS → SWARM → workers=200 → duration=120s
# Distribution automatique : 60 BYPASS + 50 PULSAR + 40 COOKIE + 30 SLOW + 20 TLS
```

---

## 🎣 PHISH — Phishing avec tunnel

```
PHISH [24] → choisir un template
           → serveur HTTP local Python (aucune dépendance)
           → tunnel (cloudflared auto-dl / serveo / localhost.run / bore)
           → URL vérifiée joignable avant affichage
           → credentials capturés en live → data/phish_YYYYMMDD.log
           → redirect automatique vers le vrai site après capture
```

### Templates disponibles (fichiers HTML séparés dans `phish_templates/`)

| # | Template | Fidélité | Redirect |
|---|----------|----------|---------|
| 1 | **Microsoft 365** | Logo SVG 4 carrés, Segoe UI, card blanche, bouton bleu | login.microsoftonline.com |
| 2 | **Google** | Logo SVG coloré, Roboto/Google Sans, floating labels animés, footer langue | accounts.google.com |
| 3 | **LinkedIn** | Navbar complète SVG, hero texte bordeaux, divider OR | linkedin.com |
| 4 | **Discord** | Split-panel dark `#2b2d31`, blurple `#5865f2`, logo SVG, QR Code link | discord.com |
| 5 | **Steam** | Navbar dark blue, panel vert gradient, bouton SIGN IN exact, Mobile App link | steampowered.com |
| 6 | **Instagram** | Logo SVG, "Log in with Facebook", boutons App Store | instagram.com |
| 7 | **Generic** | Terminal hacker — scanlines CSS, ASCII art, animations | configurable |
| + | **Custom HTML** | Charge n'importe quel `.html` externe | configurable |

> Ajouter un template : créer `phish_templates/monsite.html` + ajouter une entrée dans `_TPL_META` dans `phish.py`.

---

## 🕵️ TRACK — Chameleon IP Grabber

```
TRACK [46] → génère un token unique (/t/TOKEN)
           → OGP bait : vraie image HD (picsum.photos) → Discord/Telegram affichent la preview
           → og:video (thèmes 5-7) : Discord affiche un embed ▶ Play → IP loggée au clic
           → IP JS confirmée via ipify (sendBeacon /log/TOKEN)
           → Image redirect (/t/TOKEN.jpg) : Telegram/WhatsApp chargent directement → IP auto
           → Email pixel (/px/TOKEN) : log à l'ouverture du mail
           → GeoIP live (ip-api.com) + User-Agent detection (Discord/Telegram/WhatsApp/browser)
           → Tunnel : cloudflared / serveo / localhost.run / bore / LAN
```

### Thèmes leurres

| # | Thème | Type | Comportement Discord |
|---|-------|------|---------------------|
| 1 | Photo partagée | Image | Preview card → IP sur clic |
| 2 | Suivi de colis | Image | Preview card → IP sur clic |
| 3 | Document partagé | Image | Preview card → IP sur clic |
| 4 | Alerte sécurité | Image | Preview card → IP sur clic |
| 5 | Vidéo exclusive 🔥 | **og:video** | Embed ▶ Play → IP sur lecture |
| 6 | Clip inédit | **og:video** | Embed ▶ Play → IP sur lecture |
| 7 | Fail du jour 😂 | **og:video** | Embed ▶ Play → IP sur lecture |

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

## 🔄 Détail TAKEOVER (subdomain takeover)

27 services fingerrintés avec **fallback multi-source** :

```
crt.sh (3 tentatives, timeout progressif 10-20-30s)
  ↓ si timeout/échec
HackerTarget hostsearch API (gratuit, sans clé)
  ↓ si échec
riddler.io fdns search
  ↓ si tout échoue
Saisie manuelle proposée automatiquement
```

GitHub Pages · Heroku · AWS S3 · Vercel · Netlify · Fastly · Shopify · Tumblr · WP Engine · Ghost · Surge.sh · Readme.io · Statuspage · Zendesk · UserVoice · Freshdesk · HubSpot · Intercom · Campaign Monitor · Helpscout · Pingdom · Tilda · Webflow · Strikingly · Cargo · Uberflip · Fly.io

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

## 📦 Installation

```bash
# Cloner / copier le dossier
cd meow-sec

# Dépendances Python
pip install -r requirements.txt

# Lancer
python meow.py

# Lancement direct d'un module
python meow.py stress
python meow.py phish
python meow.py track
python meow.py cors
```

**requirements.txt**
```
rich>=13.7.0
colorama>=0.4.6
requests>=2.31.0
PySocks>=1.7.1
curl_cffi>=0.6.0     ← optionnel, bypass Cloudflare JA3
stem>=1.8.0          ← optionnel, circuit renewal Tor (SPECTER)
```

> Les dépendances manquantes sont installées automatiquement au premier lancement via `_ensure_deps()`.
> Les outils anonymiseurs (Tor, I2P) sont installés automatiquement à l'entrée de SPECTER/WRAITH/PHANTOM_MIX.

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
  ( o.o )   MEOW-SEC v1.2 // BY CAT-PROJECT-HAT // 2026
   > ^ <
  /|   |\
 (_|   |_)
```
