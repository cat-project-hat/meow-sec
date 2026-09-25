# -*- coding: utf-8 -*-
"""
MEOW-SEC :: ARCHIVEBRUTE (#71) — Archive & PDF Password Brute Force
  · Formats : ZIP (natif), RAR (rarfile / unrar), 7z (subprocess), PDF (pikepdf / PyPDF2 / qpdf)
  · Modes   : wordlist fichier · wordlist intégrée · attaque par règles (mutations)
  · Multi-threadé (ThreadPoolExecutor) — stop immédiat dès le mot de passe trouvé
  · Barre de progression Rich + passwords/sec en temps réel
"""
import os, re, json, time, zipfile, tempfile, shutil, subprocess, threading
import concurrent.futures
from datetime import datetime

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_target, ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk

from rich.rule    import Rule
from rich.panel   import Panel
from rich.prompt  import Prompt, Confirm
from rich.progress import (Progress, SpinnerColumn, BarColumn, TextColumn,
                           MofNCompleteColumn, TimeElapsedColumn, TaskProgressColumn)
from rich         import box

# ─── DISPONIBILITÉ DES LIBS OPTIONNELLES ─────────────────────

try:
    import rarfile as _rarfile
    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False

try:
    import pikepdf as _pikepdf
    HAS_PIKEPDF = True
except ImportError:
    HAS_PIKEPDF = False

try:
    import PyPDF2 as _pypdf2
    HAS_PYPDF2 = True
except ImportError:
    HAS_PYPDF2 = False

HAS_UNRAR  = shutil.which("unrar")  is not None
HAS_7Z     = (shutil.which("7z")    is not None or
              shutil.which("7za")   is not None or
              shutil.which("7zz")   is not None)
HAS_QPDF   = shutil.which("qpdf")  is not None

# ─── WORDLIST INTÉGRÉE (top-200 rockyou + divers) ────────────

_BUILTIN_WORDLIST = [
    # Basiques
    "123456", "password", "123456789", "12345678", "12345", "1234567", "1234567890",
    "qwerty", "abc123", "password1", "iloveyou", "admin", "letmein", "monkey",
    "1234", "dragon", "master", "sunshine", "princess", "welcome",
    # Variantes communes
    "Password1", "Password123", "P@ssw0rd", "P@ssword", "passw0rd", "Passw0rd",
    "admin123", "Admin123", "root", "toor", "password123", "Pass@123",
    # Années
    "2020", "2021", "2022", "2023", "2024", "2025",
    "password2023", "password2024", "Password2024!",
    # Clavier
    "qwerty123", "azerty", "azerty123", "111111", "000000", "121212",
    "654321", "123321", "987654321", "qwertyuiop",
    # Noms courants
    "michael", "jessica", "batman", "superman", "soccer", "football",
    "shadow", "baseball", "hockey", "123abc", "test", "test123",
    # Patterns entreprise
    "Company123", "company123", "Winter2024!", "Summer2024!", "Spring2024!",
    "Autumn2024!", "Monday1!", "January1!", "changeme", "changeme1",
    # Vides / basiques
    "", "0", "1",
    # ZIP spécifiques
    "zip", "archive", "backup", "secret", "private", "locked",
    # Chiffres simples
    "00000000", "11111111", "22222222", "99999999", "10101010",
    # Phrases
    "letmein1", "iloveyou1", "trustno1", "starwars", "login", "passpass",
    # Prénoms + chiffres
    "michael1", "jessica1", "thomas1", "jennifer1", "angel1", "jordan1",
    # Plus 100 autres du top 200 rockyou
    "princess1", "1q2w3e4r", "sunshine1", "chocolate", "hello", "whatever",
    "696969", "pokemon", "superman1", "batman1", "ninja", "mustang",
    "access", "ashley", "bailey", "passw0rd1", "shadow1", "master1",
    "myspace1", "soccer1", "hello123", "donald", "654321", "pussy",
    "aa123456", "passw0rd", "hello1", "charlie", "donald1", "password2",
    "1234qwer", "qwerty1", "password01", "abcdef", "football1", "computer",
    "a123456", "tigger", "ginger", "hammer", "silver", "ranger", "dakota",
    "cookie", "maggie", "apple", "monkey1", "jessica", "cheese", "butter",
    "tennis", "purple", "diablo", "asdfgh", "zxcvbn", "hunter", "baseball1",
    # French common
    "motdepasse", "mdp123", "azerty123", "bonjour", "soleil", "france",
    "paris123", "france2024", "Soleil1!", "Bonjour1",
]

# ─── MUTATIONS (mode règles) ──────────────────────────────────

_L33T = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"}


def _mutate(keyword: str) -> list:
    """Génère des variantes à partir d'un mot-clé (prénom, nom d'entreprise...)"""
    w  = keyword
    wl = keyword.lower()
    wu = keyword.upper()
    wc = keyword.capitalize()

    # Leetspeak
    l33t = "".join(_L33T.get(c.lower(), c) for c in wl)

    variants = set()

    # Formes de base
    for base in (w, wl, wu, wc):
        variants.add(base)
        variants.add(base + "!")
        variants.add(base + "@")
        variants.add(base + "#1")
        variants.add(base + "1")
        variants.add(base + "12")
        variants.add(base + "123")
        variants.add(base + "1234")
        variants.add(base + "01")
        variants.add(base + "_2024")
        variants.add(base + ".2024")

    # Avec années 2020-2025
    for yr in range(2020, 2026):
        variants.add(wl  + str(yr))
        variants.add(wc  + str(yr))
        variants.add(wl  + str(yr) + "!")
        variants.add(wc  + str(yr) + "!")

    # Avec chiffres courants
    for n in ("2024", "2025", "123", "1234", "1!", "123!", "@123"):
        variants.add(wc + n)

    # Leetspeak variants
    variants.add(l33t)
    variants.add(l33t.capitalize())
    variants.add(l33t + "!")
    variants.add(l33t + "1")
    variants.add(l33t + "123")
    variants.add(l33t + "2024")

    return list(variants)

# ─── DÉTECTION DU FORMAT ─────────────────────────────────────

_MAGIC = {
    b"PK\x03\x04":        "zip",
    b"Rar!":              "rar",
    b"7z\xbc\xaf":        "7z",
    b"%PDF":              "pdf",
}


def _detect_format(path: str) -> str | None:
    """Détecte le format via magic bytes, puis extension en fallback."""
    try:
        with open(path, "rb") as fh:
            header = fh.read(8)
        for magic, fmt in _MAGIC.items():
            if header.startswith(magic):
                return fmt
    except Exception:
        pass
    ext = os.path.splitext(path)[1].lower()
    return {"zip": "zip", ".zip": "zip",
            ".rar": "rar", ".7z": "7z",
            ".pdf": "pdf"}.get(ext)

# ─── MOTEURS DE TEST ─────────────────────────────────────────

def _try_zip(path: str, password: str) -> bool:
    """Teste un mot de passe sur un ZIP natif Python."""
    try:
        with zipfile.ZipFile(path) as zf:
            tmpdir = tempfile.mkdtemp(prefix="meowtmp_")
            try:
                zf.extractall(path=tmpdir, pwd=password.encode("utf-8", errors="replace"))
                return True
            except (RuntimeError, zipfile.BadZipFile, Exception):
                return False
            finally:
                try:
                    shutil.rmtree(tmpdir, ignore_errors=True)
                except Exception:
                    pass
    except zipfile.BadZipFile:
        return False
    except Exception:
        return False


def _try_rar(path: str, password: str) -> bool:
    """Teste un mot de passe sur un RAR (rarfile ou unrar CLI)."""
    if HAS_RARFILE:
        try:
            with _rarfile.RarFile(path) as rf:
                rf.setpassword(password)
                # Tenter d'extraire le premier fichier dans un buffer
                names = rf.namelist()
                if names:
                    rf.read(names[0])
                return True
        except Exception:
            return False
    if HAS_UNRAR:
        try:
            result = subprocess.run(
                ["unrar", "t", f"-p{password}", "-y", path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=15
            )
            return result.returncode == 0
        except Exception:
            return False
    return False


def _try_7z(path: str, password: str) -> bool:
    """Teste un mot de passe sur un 7z via CLI."""
    cmd = shutil.which("7z") or shutil.which("7za") or shutil.which("7zz")
    if not cmd:
        return False
    try:
        result = subprocess.run(
            [cmd, "t", f"-p{password}", "-y", path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15
        )
        return result.returncode == 0
    except Exception:
        return False


def _try_pdf(path: str, password: str) -> bool:
    """Teste un mot de passe sur un PDF (pikepdf, PyPDF2, ou qpdf CLI)."""
    if HAS_PIKEPDF:
        try:
            with _pikepdf.open(path, password=password):
                return True
        except Exception:
            return False
    if HAS_PYPDF2:
        try:
            reader = _pypdf2.PdfReader(path)
            if reader.is_encrypted:
                result = reader.decrypt(password)
                return result != 0
            return True
        except Exception:
            return False
    if HAS_QPDF:
        try:
            result = subprocess.run(
                ["qpdf", f"--password={password}", "--decrypt",
                 path, os.devnull],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=15
            )
            return result.returncode == 0
        except Exception:
            return False
    return False

# ─── VÉRIFICATION DES DÉPENDANCES ────────────────────────────

def _check_deps(fmt: str) -> bool:
    """Vérifie les dépendances disponibles pour un format et informe l'utilisateur."""
    if fmt == "zip":
        ok(f"ZIP engine: [{CY}]Python zipfile (natif)[/]")
        return True

    if fmt == "rar":
        if HAS_RARFILE:
            ok(f"RAR engine: [{CY}]rarfile (Python)[/]")
        elif HAS_UNRAR:
            ok(f"RAR engine: [{CY}]unrar (CLI)[/]")
        else:
            err("RAR: aucun moteur disponible. Installez rarfile (`pip install rarfile`) ou unrar.")
            return False
        return True

    if fmt == "7z":
        if HAS_7Z:
            cmd = shutil.which("7z") or shutil.which("7za") or shutil.which("7zz")
            ok(f"7z engine: [{CY}]{cmd}[/]")
        else:
            err("7z: 7z/7za introuvable dans le PATH. Installez 7-Zip.")
            return False
        return True

    if fmt == "pdf":
        if HAS_PIKEPDF:
            ok(f"PDF engine: [{CY}]pikepdf (Python)[/]")
        elif HAS_PYPDF2:
            ok(f"PDF engine: [{CY}]PyPDF2 (Python)[/]")
        elif HAS_QPDF:
            ok(f"PDF engine: [{CY}]qpdf (CLI)[/]")
        else:
            err("PDF: aucun moteur disponible. Installez pikepdf (`pip install pikepdf`) ou PyPDF2 (`pip install PyPDF2`).")
            return False
        return True

    return False

# ─── CHARGEMENT DE LA WORDLIST ───────────────────────────────

def _load_wordlist() -> list | None:
    """Propose les 3 modes de wordlist et retourne la liste de mots de passe."""
    console.print()
    console.print(f"  [{G1}][1][/] Wordlist intégrée  ([{CY}]{len(_BUILTIN_WORDLIST)}[/] mots de passe courants)")
    console.print(f"  [{G1}][2][/] Wordlist depuis fichier  (.txt, un mot par ligne)")
    console.print(f"  [{G1}][3][/] Attaque par règles  (mutations d'un mot-clé)")
    console.print(f"  [{G1}][0][/] Annuler")
    console.print()
    choice = ask_choice("WORDLIST") or "1"

    if choice == "0":
        return None

    if choice == "1":
        info(f"Wordlist intégrée chargée : [{G1}]{len(_BUILTIN_WORDLIST)}[/] mots de passe")
        return list(_BUILTIN_WORDLIST)

    if choice == "2":
        path = Prompt.ask(f"  [{G1}]◈ Chemin vers le fichier wordlist[/]").strip().strip('"')
        if not os.path.exists(path):
            err(f"Fichier introuvable : {path}")
            return None
        try:
            words = [line.rstrip("\r\n") for line in
                     open(path, encoding="utf-8", errors="ignore")
                     if line.rstrip("\r\n") != "\n"]
            # Conserver les lignes vides comme mot de passe vide
            words = [line.rstrip("\r\n") for line in
                     open(path, encoding="utf-8", errors="ignore")]
            info(f"Wordlist chargée : [{G1}]{len(words):,}[/] entrées  —  [{DM}]{path}[/]")
            return words
        except Exception as e:
            err(f"Lecture échouée : {e}")
            return None

    if choice == "3":
        keyword = Prompt.ask(f"  [{G1}]◈ Mot-clé (prénom, nom entreprise...)[/]").strip()
        if not keyword:
            err("Mot-clé vide.")
            return None
        words = _mutate(keyword)
        info(f"Mutations générées : [{G1}]{len(words)}[/] variantes  (base: [{CY}]{keyword}[/])")
        return words

    return None

# ─── BRUTE FORCE ENGINE ──────────────────────────────────────

def _run_brute(path: str, fmt: str, wordlist: list) -> dict | None:
    """
    Lance le brute force multi-threadé.
    Retourne {"password": ..., "elapsed": ...} si trouvé, None sinon.
    """
    workers = 4 if fmt in ("rar", "7z") else 8
    engines = {"zip": _try_zip, "rar": _try_rar, "7z": _try_7z, "pdf": _try_pdf}
    engine  = engines[fmt]

    found_pwd: list = []          # contiendra le mot de passe trouvé
    stop      = threading.Event()
    lock      = threading.Lock()
    t0        = time.monotonic()
    tested    = [0]               # compteur partagé (liste pour mutabilité dans closure)

    def _worker(pwd: str):
        if stop.is_set():
            return
        result = engine(path, pwd)
        with lock:
            tested[0] += 1
        if result:
            stop.set()
            with lock:
                if not found_pwd:
                    found_pwd.append(pwd)

    total = len(wordlist)
    info(f"Lancement du brute force — [{G1}]{total:,}[/] mots de passe  /  [{CY}]{workers}[/] threads")
    console.print()

    with Progress(
        SpinnerColumn(style=G1),
        TextColumn(f"[{G1}]ARCHIVEBRUTE"),
        BarColumn(bar_width=35, style=G2, complete_style=G1),
        MofNCompleteColumn(),
        TextColumn(f"[{DM}]|[/]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as prog:
        task = prog.add_task("", total=total)

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_worker, pwd): pwd for pwd in wordlist}
            for fut in concurrent.futures.as_completed(futures):
                prog.advance(task, 1)
                if stop.is_set():
                    # Annuler les futures restants
                    for f in futures:
                        f.cancel()
                    break

    elapsed = time.monotonic() - t0

    if found_pwd:
        return {"password": found_pwd[0], "elapsed": round(elapsed, 2)}
    return None

# ─── SAUVEGARDE ──────────────────────────────────────────────

def _save_result(archive_path: str, fmt: str, result: dict | None, total_tested: int):
    os.makedirs("data", exist_ok=True)
    basename  = os.path.splitext(os.path.basename(archive_path))[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname     = f"data/archivebrute_{basename}_{timestamp}.json"
    payload   = {
        "archive":       archive_path,
        "format":        fmt,
        "timestamp":     datetime.now().isoformat(),
        "total_tested":  total_tested,
        "found":         result is not None,
        "password":      result["password"] if result else None,
        "elapsed_sec":   result["elapsed"]  if result else None,
    }
    try:
        with open(fname, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        ok(f"Résultat sauvegardé : [{CY}]{fname}[/]")
    except Exception as e:
        warn(f"Sauvegarde échouée : {e}")

# ─── AFFICHAGE DU RÉSULTAT ───────────────────────────────────

def _show_result(result: dict | None, wordlist: list, archive_path: str, fmt: str):
    console.print()
    if result:
        pwd = result["password"]
        find(f"MOT DE PASSE TROUVÉ : [{CY}]{pwd!r}[/]")
        cat_talk(CAT_FOUND,
                 f"Password cracked: {pwd!r}  ({result['elapsed']}s)",
                 G1)
        console.print()
        print_result_table(
            f"ARCHIVEBRUTE — {os.path.basename(archive_path)}",
            ["Champ", "Valeur"],
            [
                ("Fichier",    archive_path),
                ("Format",     fmt.upper()),
                ("Mot de passe", f"[bold {G1}]{pwd}[/]"),
                ("Temps",      f"{result['elapsed']} s"),
                ("Testés",     str(len(wordlist))),
            ]
        )
    else:
        warn(f"Mot de passe introuvable dans la wordlist ({len(wordlist):,} mots testés).")
        info("Essayez une wordlist plus grande (ex. rockyou.txt) ou le mode règles.")

# ─── POINT D'ENTRÉE ──────────────────────────────────────────

def run():
    show_module_banner("archivebrute")
    cat_talk(CAT_SCAN, "Archive brute force engine loaded.", OR)
    console.print()
    warn("Utilisez uniquement sur des fichiers vous appartenant ou avec autorisation écrite.")
    console.print()

    while True:
        # 1. Chemin du fichier
        console.print(Rule(f"[{G1}] ARCHIVEBRUTE — Archive & PDF Password Cracker ", style=G2))
        path = (ask_target("Chemin vers le fichier (ZIP / RAR / 7z / PDF)") or "").strip().strip('"')
        if not path:
            break
        if not os.path.isfile(path):
            err(f"Fichier introuvable : {path}")
            console.print()
            continue

        # 2. Détection du format
        fmt = _detect_format(path)
        if not fmt:
            err("Format non reconnu. Formats supportés : .zip  .rar  .7z  .pdf")
            console.print()
            continue
        info(f"Format détecté : [{G1}]{fmt.upper()}[/]  —  [{DM}]{os.path.basename(path)}[/]")

        # 3. Vérification des dépendances
        if not _check_deps(fmt):
            console.print()
            if not Confirm.ask(f"  [{OR}]◈ Continuer quand même ?[/]", default=False):
                console.print()
                continue

        # 4. Wordlist
        wordlist = _load_wordlist()
        if wordlist is None:
            console.print()
            continue

        if not wordlist:
            warn("Wordlist vide.")
            console.print()
            continue

        # 5. Brute force
        console.print()
        result = _run_brute(path, fmt, wordlist)

        # 6. Affichage
        _show_result(result, wordlist, path, fmt)

        # 7. Sauvegarde
        _save_result(path, fmt, result, len(wordlist))

        console.print()
        if not Confirm.ask(f"  [{G1}]◈ Tester un autre fichier ?[/]", default=False):
            break
        console.print()
