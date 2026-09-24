# -*- coding: utf-8 -*-
"""MEOW-SEC :: FRONTSCAN — React / TypeScript / TSX Vulnerability Scanner
Deux modes :
  1. Static  — analyse les fichiers .ts/.tsx/.js/.jsx locaux
  2. Remote  — scanne une app React déployée (source maps, clés API, erreurs)
"""
import os, re, json
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN, CAT_FOUND
from rich.panel    import Panel
from rich.table    import Table
from rich.prompt   import Prompt, Confirm
from rich.rule     import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
from rich          import box

try:
    import requests as _req
    _req.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

_UA = "Mozilla/5.0 (compatible; MEOW-FRONTSCAN/1.0; authorized-test)"

# ─── PATTERNS STATIQUES (fichiers .ts/.tsx/.js/.jsx) ─────────

_STATIC_PATTERNS = [
    # ── XSS risks ──────────────────────────────────────────────
    (r"dangerouslySetInnerHTML\s*=\s*\{\s*\{",
     "dangerouslySetInnerHTML", "XSS", "HIGH",
     "Contenu HTML injecté sans sanitize (XSS possible)"),
    (r"innerHTML\s*=",
     "innerHTML assignment", "XSS", "HIGH",
     "Assignation directe innerHTML (XSS)"),
    (r"document\.write\s*\(",
     "document.write()", "XSS", "HIGH",
     "document.write() obsolète et dangereux"),
    (r"outerHTML\s*=",
     "outerHTML assignment", "XSS", "MEDIUM",
     "Assignation outerHTML"),
    (r"insertAdjacentHTML\s*\(",
     "insertAdjacentHTML()", "XSS", "MEDIUM",
     "insertAdjacentHTML sans sanitize"),

    # ── Code injection ──────────────────────────────────────────
    (r"\beval\s*\(",
     "eval()", "CODE_INJECTION", "CRITICAL",
     "eval() = exécution de code arbitraire"),
    (r"new\s+Function\s*\(",
     "new Function()", "CODE_INJECTION", "CRITICAL",
     "new Function() = eval indirect"),
    (r"setTimeout\s*\(\s*['\"]",
     "setTimeout(string)", "CODE_INJECTION", "HIGH",
     "setTimeout avec string (éval de code)"),
    (r"setInterval\s*\(\s*['\"]",
     "setInterval(string)", "CODE_INJECTION", "HIGH",
     "setInterval avec string (éval de code)"),

    # ── Secrets hardcodés ───────────────────────────────────────
    (r"""(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"][A-Za-z0-9_\-]{16,}['"]""",
     "Hardcoded API key", "SECRET", "CRITICAL",
     "Clé API hardcodée dans le code source"),
    (r"""(?i)(?:secret[_-]?key|secretkey|app[_-]?secret)\s*[=:]\s*['"][A-Za-z0-9_\-]{16,}['"]""",
     "Hardcoded secret", "SECRET", "CRITICAL",
     "Secret hardcodé"),
    (r"""(?i)(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{6,}['"]""",
     "Hardcoded password", "SECRET", "CRITICAL",
     "Mot de passe hardcodé"),
    (r"""(?i)(?:token|auth[_-]?token|bearer[_-]?token)\s*[=:]\s*['"][A-Za-z0-9._\-]{20,}['"]""",
     "Hardcoded token", "SECRET", "CRITICAL",
     "Token d'authentification hardcodé"),
    (r"""(?i)(?:private[_-]?key|rsa[_-]?key)\s*[=:]\s*['"][-]{5}BEGIN""",
     "Hardcoded private key", "SECRET", "CRITICAL",
     "Clé privée RSA hardcodée"),
    (r"""REACT_APP_(?:SECRET|PRIVATE|KEY|TOKEN|PASSWORD)[A-Z_]*\s*=\s*[^\n]{8,}""",
     "Sensitive env var in .env", "SECRET", "HIGH",
     "Variable d'environnement sensible dans .env (exposée au bundle)"),

    # ── Communication non sécurisée ─────────────────────────────
    (r"""fetch\s*\(\s*['"]http://""",
     "HTTP fetch (not HTTPS)", "TRANSPORT", "MEDIUM",
     "Appel API en HTTP non chiffré"),
    (r"""axios\s*\.\s*(?:get|post|put|delete)\s*\(\s*['"]http://""",
     "HTTP axios call", "TRANSPORT", "MEDIUM",
     "Requête axios en HTTP"),
    (r"""(?:url|endpoint|baseURL|baseUrl)\s*[=:]\s*['"]http://""",
     "HTTP base URL", "TRANSPORT", "MEDIUM",
     "URL de base en HTTP"),

    # ── postMessage sans vérification origin ────────────────────
    (r"""addEventListener\s*\(\s*['"]message['"]""",
     "postMessage listener", "ORIGIN", "MEDIUM",
     "Listener postMessage — vérifier l'origin (e.origin === '...')"),
    (r"""window\.postMessage\s*\(""",
     "postMessage send", "ORIGIN", "LOW",
     "postMessage envoyé — vérifier le targetOrigin"),

    # ── Stockage sensible ────────────────────────────────────────
    (r"""localStorage\.setItem\s*\(\s*['"](?:token|jwt|password|secret|auth)['"]\s*,""",
     "Sensitive localStorage", "STORAGE", "HIGH",
     "Token/password stocké dans localStorage (accessible via XSS)"),
    (r"""sessionStorage\.setItem\s*\(\s*['"](?:token|jwt|password|secret|auth)['"]\s*,""",
     "Sensitive sessionStorage", "STORAGE", "MEDIUM",
     "Token/password dans sessionStorage"),
    (r"""document\.cookie\s*=(?!.*httpOnly)""",
     "Cookie sans httpOnly", "STORAGE", "MEDIUM",
     "Cookie positionné sans httpOnly flag"),

    # ── Console leaks ────────────────────────────────────────────
    (r"""console\.log\s*\(.*(?:password|token|secret|key|jwt)""",
     "console.log secret", "LEAK", "MEDIUM",
     "Données sensibles loggées en console"),
    (r"""console\.(?:log|warn|error|debug)\s*\(.*user""",
     "console.log user data", "LEAK", "LOW",
     "Données utilisateur loggées"),

    # ── Redirect non sécurisé ────────────────────────────────────
    (r"""window\.location\s*=\s*(?:params|query|search|hash|input)""",
     "Open redirect", "REDIRECT", "HIGH",
     "Redirection basée sur user input (open redirect)"),
    (r"""window\.location\.href\s*=\s*(?:params|query|props\.)""",
     "Open redirect via props", "REDIRECT", "HIGH",
     "Redirection via props non validées"),

    # ── Prototype pollution ──────────────────────────────────────
    (r"""Object\.assign\s*\(\s*\{\s*\}\s*,\s*(?:req\.|params|query|body|input)""",
     "Prototype pollution", "INJECTION", "HIGH",
     "Object.assign avec user input (prototype pollution)"),
    (r"""__proto__""",
     "__proto__ access", "INJECTION", "HIGH",
     "Accès direct à __proto__"),

    # ── CORS trop permissif ──────────────────────────────────────
    (r"""(?:cors|origin)\s*:\s*['"]\*['"]""",
     "CORS wildcard *", "CORS", "HIGH",
     "CORS avec wildcard * (trop permissif)"),
    (r"""Access-Control-Allow-Origin['"]\s*:\s*['"]\*['"]""",
     "CORS header wildcard", "CORS", "HIGH",
     "Header CORS Access-Control-Allow-Origin: *"),

    # ── Artifacts de dev ─────────────────────────────────────────
    (r"""(?i)//\s*TODO\s*:.*(?:security|auth|password|token|key|secret)""",
     "Security TODO", "HYGIENE", "LOW",
     "TODO de sécurité non résolu"),
    (r"""(?i)//\s*FIXME\s*:""",
     "FIXME comment", "HYGIENE", "LOW",
     "FIXME laissé dans le code"),
    (r"""(?i)debugger\s*;""",
     "debugger statement", "HYGIENE", "LOW",
     "Statement debugger laissé en prod"),
    (r"""process\.env\.NODE_ENV\s*===?\s*['"]development['"]""",
     "Dev env check in prod", "HYGIENE", "LOW",
     "Vérification d'env dev dans le code"),

    # ── Injection SQL / NoSQL via ORM client-side ─────────────────
    (r"""(?:query|where|filter)\s*\(\s*['"`][^'"`]*\$\{""",
     "Template literal in query", "INJECTION", "HIGH",
     "Template literal dans une query (injection possible)"),
    (r"""(?:knex|sequelize|prisma|mongoose)\s*\.\s*raw\s*\(""",
     "ORM raw query", "INJECTION", "MEDIUM",
     "Raw query ORM — vérifier les paramètres"),

    # ── TypeORM spécifique ────────────────────────────────────────
    # QueryBuilder avec concaténation de chaînes — VECTEUR LE PLUS COURANT
    (r"""\.where\s*\(\s*[`'"]\s*\w+\.\w+\s*=\s*(?:\$\{|['"]?\s*\+)""",
     "TypeORM QueryBuilder inject", "INJECTION", "CRITICAL",
     "QueryBuilder .where() avec concaténation ou template literal — SQLi garanti"),
    (r"""createQueryBuilder\b.*\n?.*\.where\s*\(\s*`[^`]*\$\{""",
     "TypeORM QB template literal", "INJECTION", "CRITICAL",
     "createQueryBuilder().where() avec template literal `${input}` — SQLi"),
    # .orderBy() avec input direct
    (r"""\.orderBy\s*\(\s*(?:req\.|params\.|query\.|body\.|sort|order|column)\w*""",
     "TypeORM orderBy inject", "INJECTION", "HIGH",
     ".orderBy(userInput) — ORDER BY injection possible"),
    (r"""\.orderBy\s*\(\s*`[^`]*\$\{""",
     "TypeORM orderBy template", "INJECTION", "HIGH",
     ".orderBy() avec template literal — ORDER BY injection"),
    # Raw query avec template literals
    (r"""(?:dataSource|getConnection|AppDataSource)\s*\.\s*query\s*\(\s*`[^`]*\$\{""",
     "TypeORM raw query inject", "INJECTION", "CRITICAL",
     "dataSource.query() avec template literal `${input}` — SQLi directe"),
    (r"""(?:dataSource|getConnection)\s*\.\s*query\s*\(\s*['"]\s*SELECT.*\+""",
     "TypeORM raw concat", "INJECTION", "CRITICAL",
     "dataSource.query() avec concaténation — SQLi directe"),
    # find() / findOne() avec objet user-controlled passé directement
    (r"""(?:find|findOne|findAndCount)\s*\(\s*\{\s*where\s*:\s*(?:req\.|body\.|params\.|query\.)""",
     "TypeORM find() user where", "INJECTION", "HIGH",
     "find({ where: req.body }) — operator bypass possible"),
    # .select() avec colonnes contrôlées par l'user
    (r"""\.select\s*\(\s*\[\s*(?:req\.|body\.|params\.|query\.)""",
     "TypeORM select inject", "INJECTION", "HIGH",
     ".select([userInput]) — injection de colonne"),
    # setParameter vs concaténation
    (r"""\.setParameter\s*\(\s*['"][^'"]+['"]\s*,\s*(?:req\.|body\.|params\.)""",
     "TypeORM setParameter — safe", "INJECTION", "LOW",
     "setParameter() utilisé — correct si pas de concaténation dans le WHERE"),
    # Pas de paramètre nommé — index binding oublié
    (r"""\.where\s*\(\s*[`'"]\w+\.\w+\s*=\s*:\w+['"`]\s*\)(?!\s*,)""",
     "TypeORM missing binding", "INJECTION", "MEDIUM",
     ".where(':param') sans objet de binding — la valeur n'est pas substituée"),

    # ── SSRF côté client ─────────────────────────────────────────
    (r"""fetch\s*\(\s*(?:params|query|input|props\.)""",
     "SSRF potential", "SSRF", "MEDIUM",
     "fetch() avec URL contrôlée par l'utilisateur"),
]

# ─── PATTERNS REMOTE (bundle JS déployé) ─────────────────────

_SECRET_PATTERNS = [
    (r"""(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?""",
     "API Key in bundle",    "CRITICAL"),
    (r"""(?i)(?:secret[_\-]?key|app[_\-]?secret)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?""",
     "Secret in bundle",     "CRITICAL"),
    (r"""(?i)(?:aws[_\-]?access[_\-]?key[_\-]?id)\s*[:=]\s*["']?([A-Z0-9]{20})["']?""",
     "AWS Access Key",       "CRITICAL"),
    (r"""(?i)REACT_APP_(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)[A-Z_]*\s*[:=]\s*["']?([^"'\s]{8,})["']?""",
     "Exposed React env var", "HIGH"),
    (r"""(?i)(?:firebase[_\-]?api[_\-]?key)\s*[:=]\s*["']?([A-Za-z0-9_\-]{30,})["']?""",
     "Firebase API Key",     "HIGH"),
    (r"""(?i)(?:stripe[_\-]?(?:public|secret)[_\-]?key)\s*[:=]\s*["']?((?:pk|sk)_[A-Za-z0-9]{20,})["']?""",
     "Stripe Key",           "CRITICAL"),
    (r"""(?i)(?:github[_\-]?token|gh[_\-]?token)\s*[:=]\s*["']?(ghp_[A-Za-z0-9]{36})["']?""",
     "GitHub Token",         "CRITICAL"),
    (r"""(?i)(?:sendgrid[_\-]?api[_\-]?key)\s*[:=]\s*["']?(SG\.[A-Za-z0-9._\-]{60,})["']?""",
     "SendGrid API Key",     "CRITICAL"),
    (r"""(?i)(?:twilio[_\-]?(?:auth[_\-]?token|api[_\-]?key))\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?""",
     "Twilio Key",           "HIGH"),
    (r"""(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})""",
     "JWT token exposed",    "HIGH"),
    (r"""(?i)password\s*[:=]\s*["']([^"']{6,})["']""",
     "Hardcoded password",   "CRITICAL"),
]

_REMOTE_CHECKS = [
    ("/static/js/main.*.js.map",     "Source map exposed",         "HIGH"),
    ("/asset-manifest.json",         "Asset manifest exposed",     "LOW"),
    ("/precache-manifest.*.js",      "Precache manifest",          "LOW"),
    ("/service-worker.js",           "Service worker exposed",     "INFO"),
    ("/.env",                        ".env file exposed",          "CRITICAL"),
    ("/.env.local",                  ".env.local exposed",         "CRITICAL"),
    ("/.env.production",             ".env.production exposed",    "CRITICAL"),
    ("/.env.development",            ".env.development exposed",   "HIGH"),
    ("/env.js",                      "env.js exposed",             "HIGH"),
    ("/config.js",                   "config.js exposed",          "HIGH"),
    ("/app.config.js",               "app.config.js exposed",      "HIGH"),
    ("/tsconfig.json",               "tsconfig.json exposed",      "LOW"),
    ("/package.json",                "package.json exposed",       "MEDIUM"),
    ("/package-lock.json",           "package-lock.json exposed",  "MEDIUM"),
    ("/webpack-stats.json",          "Webpack stats exposed",      "MEDIUM"),
    ("/build-manifest.json",         "Build manifest",             "LOW"),
    ("/graphql",                     "GraphQL endpoint",           "INFO"),
    ("/api/__introspect",            "API introspect endpoint",    "MEDIUM"),
    ("/__webpack_hmr",               "Webpack HMR (dev mode?)",    "HIGH"),
    ("/sockjs-node",                 "SockJS dev server",          "HIGH"),
]

_SECURITY_HEADERS = [
    ("Content-Security-Policy",          "XSS policy"),
    ("X-Frame-Options",                  "Clickjacking"),
    ("X-Content-Type-Options",           "MIME sniffing"),
    ("Strict-Transport-Security",        "HTTPS enforce"),
    ("Referrer-Policy",                  "Referrer leak"),
    ("Permissions-Policy",               "Browser features"),
    ("Cross-Origin-Opener-Policy",       "Cross-origin isolation"),
    ("Cross-Origin-Embedder-Policy",     "COEP"),
]

# ─── STATIC SCAN ─────────────────────────────────────────────

def _scan_file(filepath):
    findings = []
    try:
        content = Path(filepath).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    for lineno, line in enumerate(content.splitlines(), 1):
        for pattern, label, category, severity, desc in _STATIC_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    "file":     str(filepath),
                    "line":     lineno,
                    "label":    label,
                    "category": category,
                    "severity": severity,
                    "desc":     desc,
                    "snippet":  line.strip()[:100],
                })
    return findings


def _static_scan(root_dir):
    exts = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".env",
            ".env.local", ".env.production", ".env.development"}
    findings = []
    files = []

    for path in Path(root_dir).rglob("*"):
        if path.is_file() and path.suffix.lower() in exts:
            skip_dirs = {"node_modules", ".git", "dist", "build", ".next",
                         ".nuxt", "coverage", ".turbo", ".yarn"}
            if any(d in path.parts for d in skip_dirs):
                continue
            files.append(path)

    info(f"  Scanning [{CY}]{len(files)}[/] files in [{G1}]{root_dir}[/]...")
    console.print()

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), MofNCompleteColumn(),
                  console=console, transient=True) as prog:
        task = prog.add_task("[green]Scanning...", total=len(files))
        for fp in files:
            file_findings = _scan_file(fp)
            findings.extend(file_findings)
            prog.advance(task)

    return findings


# ─── REMOTE SCAN ─────────────────────────────────────────────

def _get(url):
    try:
        return _req.get(url, verify=False, timeout=10,
                        allow_redirects=True, proxies=_px(),
                        headers={"User-Agent": _UA})
    except Exception:
        return None


def _find_js_bundles(base):
    """Cherche les bundles JS principaux depuis index.html."""
    bundles = []
    r = _get(base)
    if not r:
        return bundles
    # Find all JS references
    matches = re.findall(r'src=["\'](/[^"\']+\.js)["\']', r.text)
    for m in matches:
        if any(k in m for k in ("main", "chunk", "bundle", "app", "index")):
            bundles.append(urljoin(base, m))
    return bundles[:5]


def _scan_bundle_for_secrets(url):
    """Cherche des secrets dans un bundle JS déployé."""
    findings = []
    r = _get(url)
    if not r or r.status_code != 200:
        return findings
    content = r.text
    for pattern, label, severity in _SECRET_PATTERNS:
        matches = re.findall(pattern, content)
        for m in matches:
            val = m if isinstance(m, str) else m[0]
            val_preview = val[:24] + "..." if len(val) > 24 else val
            find(f"[{RD}]{severity}[/] [{G1}]{label}[/] in bundle: [{OR}]{val_preview}[/]")
            findings.append({"url": url, "label": label, "severity": severity,
                             "evidence": val_preview, "type": "secret-in-bundle"})
    return findings


def _check_graphql_introspect(base):
    """Vérifie si GraphQL introspection est activée."""
    findings = []
    for path in ("/graphql", "/api/graphql", "/v1/graphql", "/query"):
        url = base.rstrip("/") + path
        try:
            r = _req.post(url, json={"query": "{ __schema { types { name } } }"},
                          verify=False, timeout=10, proxies=_px(),
                          headers={"User-Agent": _UA, "Content-Type": "application/json"})
            if r and r.status_code == 200:
                try:
                    d = r.json()
                    if "__schema" in str(d):
                        find(f"GraphQL introspection [{RD}]ENABLED[/] at [{G1}]{path}[/]")
                        findings.append({"path": path, "severity": "MEDIUM",
                                         "type": "graphql-introspect"})
                except Exception:
                    pass
        except Exception:
            pass
    return findings


def _check_window_state(base):
    """Cherche __INITIAL_STATE__ / Redux state exposé."""
    findings = []
    r = _get(base)
    if not r:
        return findings
    patterns = [
        (r"window\.__INITIAL_STATE__\s*=\s*(\{[^;]{0,500})",
         "__INITIAL_STATE__ exposed"),
        (r"window\.__REDUX_STATE__\s*=\s*(\{[^;]{0,500})",
         "__REDUX_STATE__ exposed"),
        (r"window\.__NEXT_DATA__\s*=\s*(\{[^;]{0,500})",
         "__NEXT_DATA__ exposed"),
        (r"window\.__PRELOADED_STATE__\s*=\s*(\{[^;]{0,500})",
         "__PRELOADED_STATE__ exposed"),
    ]
    for pat, label in patterns:
        m = re.search(pat, r.text)
        if m:
            find(f"[{OR}]State leak:[/] [{G1}]{label}[/]  preview: [{DM}]{m.group(1)[:80]}[/]")
            findings.append({"type": "state-leak", "label": label,
                             "severity": "HIGH", "preview": m.group(1)[:80]})
    return findings


def _check_remote_paths(base):
    """Vérifie les fichiers sensibles connus."""
    findings = []
    for path, desc, severity in _REMOTE_CHECKS:
        url = base.rstrip("/") + path
        r = _get(url)
        if not r:
            continue
        if r.status_code == 200:
            sev_c = RD if severity == "CRITICAL" else (OR if severity == "HIGH" else CY)
            find(f"[{sev_c}]{severity}[/] [{G1}]{path}[/] — {desc}")
            findings.append({"path": path, "desc": desc, "severity": severity,
                             "url": url})
    return findings


def _check_headers(base):
    missing = []
    r = _get(base)
    if not r:
        return missing
    hdrs = {k.lower() for k in r.headers}
    for hdr, desc in _SECURITY_HEADERS:
        if hdr.lower() not in hdrs:
            warn(f"  Missing: [{OR}]{hdr}[/]  [{DM}]({desc})[/]")
            missing.append({"header": hdr, "desc": desc})
    return missing


# ─── SAVE ────────────────────────────────────────────────────

def _save(target, results):
    os.makedirs("data", exist_ok=True)
    slug = re.sub(r"[^a-zA-Z0-9_-]", "_", target)[:40]
    fname = f"data/frontscan_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "results": results,
                   "timestamp": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{fname}[/]")


# ─── MAIN ────────────────────────────────────────────────────

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def run():
    show_module_banner("frontscan")
    cat_talk(CAT_SCAN, "React/TS/TSX Scanner — static source analysis + remote bundle scan", RD)
    console.print()
    warn("AUTHORIZED USE ONLY — Unauthorized testing is illegal.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    console.print(f"\n  [{G1}][1][/] Static — analyse fichiers TS/TSX/JS locaux")
    console.print(f"  [{G1}][2][/] Remote — scanne app React déployée (URL)")
    console.print(f"  [{G1}][3][/] Les deux")
    mode = ask_choice("Mode", "1")

    all_findings = []

    # ── STATIC ──
    if mode in ("1", "3"):
        console.print()
        root = Prompt.ask(f"  [{G1}]◈ Répertoire racine du projet[/]",
                          default=os.getcwd()).strip()
        if not os.path.isdir(root):
            err(f"Répertoire introuvable : {root}"); return

        console.print(Rule(f"[{G1}] STATIC ANALYSIS", style=G2))
        static_findings = _static_scan(root)
        all_findings.extend(static_findings)

        if static_findings:
            # Trier par sévérité
            static_findings.sort(key=lambda x: _SEVERITY_ORDER.get(x["severity"], 9))
            cat_talk(CAT_FOUND, f"{len(static_findings)} vulnerability pattern(s) in source code!", G1)

            t = Table(title=f"[{G1}]Static Analysis Results[/]", box=box.MINIMAL_DOUBLE_HEAD,
                      border_style=G2, header_style=CY, show_lines=False)
            t.add_column("Severity",  min_width=10)
            t.add_column("Category",  min_width=14)
            t.add_column("Label",     min_width=24)
            t.add_column("File:Line", min_width=24)
            t.add_column("Snippet",   min_width=30)

            for f in static_findings[:50]:
                sev_c = (RD if f["severity"] == "CRITICAL" else
                         OR if f["severity"] == "HIGH" else
                         CY if f["severity"] == "MEDIUM" else DM)
                file_short = Path(f["file"]).name
                t.add_row(
                    f"[{sev_c}]{f['severity']}[/]",
                    f["category"],
                    f["label"],
                    f"{file_short}:{f['line']}",
                    f["snippet"][:40],
                )
            console.print(t)
            if len(static_findings) > 50:
                info(f"  [{DM}]... {len(static_findings) - 50} more findings in saved JSON[/]")
        else:
            ok("No vulnerability patterns detected in source code.")

    # ── REMOTE ──
    if mode in ("2", "3"):
        if not HAS_REQUESTS:
            err("requests not available. Run: pip install requests"); return

        console.print()
        url = Prompt.ask(f"  [{G1}]◈ URL de l'app React déployée[/]").strip()
        if not url.startswith("http"):
            url = "https://" + url
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"

        console.print(Rule(f"[{G1}] REMOTE SCAN — {base}", style=G2))

        console.print(Rule(f"[{G1}] Sensitive files", style=G2))
        remote_path_findings = _check_remote_paths(base)
        all_findings.extend([{**f, "type": "remote-path"} for f in remote_path_findings])

        console.print(Rule(f"[{G1}] JS Bundles — secret detection", style=G2))
        bundles = _find_js_bundles(base)
        info(f"  Found [{CY}]{len(bundles)}[/] JS bundles")
        bundle_findings = []
        for b in bundles:
            bfindings = _scan_bundle_for_secrets(b)
            bundle_findings.extend(bfindings)
        all_findings.extend(bundle_findings)
        if not bundle_findings: info(f"  [{DM}]No secrets in bundles[/]")

        console.print(Rule(f"[{G1}] Window state leak", style=G2))
        state_findings = _check_window_state(base)
        all_findings.extend(state_findings)
        if not state_findings: info(f"  [{DM}]No exposed state[/]")

        console.print(Rule(f"[{G1}] GraphQL introspection", style=G2))
        gql_findings = _check_graphql_introspect(base)
        all_findings.extend(gql_findings)
        if not gql_findings: info(f"  [{DM}]GraphQL introspection disabled or not found[/]")

        console.print(Rule(f"[{G1}] Security headers", style=G2))
        hdr_missing = _check_headers(base)
        all_findings.extend([{**h, "type": "missing-header"} for h in hdr_missing])
        if not hdr_missing: ok("  All security headers present")

    # ── RÉSUMÉ FINAL ──
    console.print()
    total = len(all_findings)
    critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high     = sum(1 for f in all_findings if f.get("severity") == "HIGH")

    if total:
        cat_talk(CAT_FOUND, f"{total} findings — {critical} CRITICAL, {high} HIGH", G1)
    else:
        ok("No vulnerabilities found.")

    _save("frontscan", {"findings": all_findings,
                        "summary": {"total": total, "critical": critical, "high": high}})
