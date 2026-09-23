# -*- coding: utf-8 -*-
"""
MEOW-SEC :: MEWHASH — Hash Tools
  · Identifier de type de hash
  · Hasher une chaîne (MD5, SHA1, SHA256, SHA512, bcrypt, NTLM...)
  · Cracker un hash avec wordlist
  · Lookup en ligne (HIBP k-anonymity, md5decrypt...)
"""
import hashlib, os, re, time, json
import concurrent.futures
from datetime import datetime

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN, CAT_FOUND
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn, TimeElapsedColumn
from rich import box

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── HASH SIGNATURES ─────────────────────────────────────────

HASH_PATTERNS = [
    (r"^[a-f0-9]{32}$",     ["MD5",      "MD4",      "NTLM", "LM"]),
    (r"^[a-f0-9]{40}$",     ["SHA-1",    "MySQL5",   "HmacSHA1"]),
    (r"^[a-f0-9]{56}$",     ["SHA-224",  "Haval-224"]),
    (r"^[a-f0-9]{64}$",     ["SHA-256",  "SHA3-256", "Keccak-256", "Blake2s"]),
    (r"^[a-f0-9]{96}$",     ["SHA-384",  "SHA3-384"]),
    (r"^[a-f0-9]{128}$",    ["SHA-512",  "SHA3-512", "Whirlpool", "Blake2b"]),
    (r"^\$2[ayb]\$.{56}$",  ["bcrypt"]),
    (r"^\$1\$.{8,}\$",      ["MD5crypt (Unix)"]),
    (r"^\$5\$.+\$.{43}$",   ["SHA-256crypt (Unix)"]),
    (r"^\$6\$.+\$.{86}$",   ["SHA-512crypt (Unix)"]),
    (r"^[a-f0-9]{16}$",     ["MySQL3",   "CRC64",    "FNV-64"]),
    (r"^\$apr1\$.+\$.+$",   ["md5apr1 (Apache)"]),
    (r"^\$P\$",             ["PHPass (WordPress)"]),
    (r"^\$H\$",             ["PHPass"]),
    (r"^[A-Z0-9]{13}$",     ["DES crypt"]),
    (r"^[a-f0-9]{8}$",      ["Adler32",  "CRC32",    "FNV-32"]),
    (r"^\{SHA\}",           ["SHA-1 (Base64 prefixed)"]),
    (r"^pbkdf2",            ["PBKDF2"]),
    (r"^sha256\$",          ["Django SHA-256"]),
    (r"^sha1\$",            ["Django SHA-1"]),
    (r"^\*[A-F0-9]{40}$",   ["MySQL 4.1+"]),
    (r"^0x[a-f0-9]+$",      ["MSSQL varbinary"]),
]


def _ntlm(s: str) -> str:
    """NTLM hash (MD4 of UTF-16LE) — pure Python fallback"""
    data = s.encode("utf-16-le")
    try:
        return hashlib.new("md4", data).hexdigest()
    except ValueError:
        # Python 3.14+ / OpenSSL 3 legacy: pure Python MD4
        return _md4_pure(data)

def _md4_pure(data: bytes) -> str:
    """Pure-Python MD4 implementation (RFC 1320)"""
    import struct
    def F(x,y,z): return (x&y)|((~x)&z)
    def G(x,y,z): return (x&y)|(x&z)|(y&z)
    def H(x,y,z): return x^y^z
    def rol(v,n): return ((v<<n)|(v>>(32-n)))&0xFFFFFFFF
    def u32(x):   return x & 0xFFFFFFFF

    msg = bytearray(data)
    orig_len = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig_len)

    a,b,c,d = 0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476
    for i in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[i:i+64]))
        aa,bb,cc,dd = a,b,c,d
        for j in [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]:
            a=rol(u32(a+F(b,c,d)+X[j]),   [3,7,11,19][j%4])
            a,b,c,d=d,a,b,c
        for k,s in [(0,3),(4,5),(8,9),(12,13),(1,3),(5,5),(9,9),(13,13),
                    (2,3),(6,5),(10,9),(14,13),(3,3),(7,5),(11,9),(15,13)]:
            a=rol(u32(a+G(b,c,d)+X[k]+0x5A827999),[3,5,9,13][[0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15].index(k)%4])
            a,b,c,d=d,a,b,c
        for k,s in [(0,3),(8,9),(4,11),(12,15),(2,3),(10,9),(6,11),(14,15),
                    (1,3),(9,9),(5,11),(13,15),(3,3),(11,9),(7,11),(15,15)]:
            a=rol(u32(a+H(b,c,d)+X[k]+0x6ED9EBA1),s)
            a,b,c,d=d,a,b,c
        a,b,c,d=u32(a+aa),u32(b+bb),u32(c+cc),u32(d+dd)
    return struct.pack("<4I",a,b,c,d).hex()

def _mysql3(s: str) -> str:
    # MySQL old-style hash
    nr, nr2, add = 1345345333, 305419896, 7
    for c in s:
        if c in (' ', '\t'): continue
        tmp = ord(c)
        nr ^= (((nr & 63) + add) * tmp) + (nr << 8)
        nr2 += (nr2 << 8) ^ nr
        add += tmp
    return f"{nr & 0x7FFFFFFF:08x}{nr2 & 0x7FFFFFFF:08x}"
# ----- HASH FUNCTIONS -----

HASH_FUNCTIONS = {
    "md5":        lambda s: hashlib.md5(s.encode()).hexdigest(),
    "sha1":       lambda s: hashlib.sha1(s.encode()).hexdigest(),
    "sha224":     lambda s: hashlib.sha224(s.encode()).hexdigest(),
    "sha256":     lambda s: hashlib.sha256(s.encode()).hexdigest(),
    "sha384":     lambda s: hashlib.sha384(s.encode()).hexdigest(),
    "sha512":     lambda s: hashlib.sha512(s.encode()).hexdigest(),
    "sha3_256":   lambda s: hashlib.sha3_256(s.encode()).hexdigest(),
    "sha3_512":   lambda s: hashlib.sha3_512(s.encode()).hexdigest(),
    "blake2b":    lambda s: hashlib.blake2b(s.encode()).hexdigest(),
    "blake2s":    lambda s: hashlib.blake2s(s.encode()).hexdigest(),
    "ntlm":       _ntlm,
    "md5_double": lambda s: hashlib.md5(hashlib.md5(s.encode()).digest()).hexdigest(),
    "mysql3":     _mysql3,
    "mysql4":     lambda s: "*" + hashlib.sha1(hashlib.sha1(s.encode()).digest()).hexdigest().upper(),
}


# ─── MINI WORDLIST ───────────────────────────────────────────

MINI_WORDLIST = [
    "password", "123456", "password1", "123456789", "qwerty", "abc123",
    "letmein", "monkey", "1234567", "iloveyou", "admin", "password123",
    "dragon", "master", "111111", "baseball", "football", "shadow",
    "sunshine", "princess", "welcome", "login", "hello", "pass",
    "root", "toor", "test", "guest", "user", "default", "secret",
    "password2", "qwerty123", "p@ssw0rd", "pa$$word", "P@ssw0rd",
    "admin123", "Admin123!", "Password1!", "Welcome1", "Summer2024",
    "cat", "dog", "hacker", "1234", "0000", "9999", "2580", "1111",
]

# ─── RIPPER — MUTATION RULES ─────────────────────────────────

L33T_MAP = {"a":"@","e":"3","i":"1","o":"0","s":"$","t":"7","l":"1","g":"9"}

def _apply_rules(word: str) -> list:
    """Génère des mutations d'un mot (style John the Ripper / Hashcat)"""
    variants = set()
    variants.add(word)
    variants.add(word.lower())
    variants.add(word.upper())
    variants.add(word.capitalize())
    variants.add(word[::-1])                       # reverse

    # Append numbers
    for n in ["1","2","123","1234","12345","0","99","2023","2024","2025","2026"]:
        variants.add(word + n)
        variants.add(word.capitalize() + n)

    # Append symbols
    for sym in ["!","@","#","$","!@#","123!"]:
        variants.add(word + sym)
        variants.add(word.capitalize() + sym)

    # Append year
    for y in range(2020, 2027):
        variants.add(word + str(y))
        variants.add(word.capitalize() + str(y))

    # L33t speak
    l33t = "".join(L33T_MAP.get(c.lower(), c) for c in word)
    variants.add(l33t)
    variants.add(l33t.capitalize())
    variants.add(l33t + "!")
    variants.add(l33t + "1")

    # Double word
    variants.add(word + word)
    variants.add(word.capitalize() + word)

    # Prepend
    variants.add("1" + word)
    variants.add("the" + word)
    variants.add("my" + word)

    return list(variants)

def crack_with_rules(hash_str: str, algo: str, wordlist: list) -> str | None:
    """Crack avec mutations type John-the-Ripper sur chaque mot de la wordlist"""
    hash_str = hash_str.strip().lower()
    fn = HASH_FUNCTIONS.get(algo.lower())
    if not fn:
        err(f"Unknown algorithm: {algo}"); return None

    # Générer toutes les mutations
    all_candidates = []
    for word in wordlist:
        all_candidates.extend(_apply_rules(word))
    # Dédupliquer en conservant l'ordre
    seen = set()
    candidates = []
    for c in all_candidates:
        if c not in seen:
            seen.add(c)
            candidates.append(c)

    with Progress(
        SpinnerColumn(style=G1),
        TextColumn(f"[{G1}]Rule-based crack"),
        BarColumn(bar_width=30, style=G2, complete_style=G1),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console
    ) as prog:
        task = prog.add_task("", total=len(candidates))
        for word in candidates:
            prog.advance(task)
            try:
                if fn(word).lower() == hash_str:
                    prog.log(f"  [{G1}]★  CRACKED: {word}[/]")
                    return word
            except Exception:
                continue
    return None

# ─── IDENTIFY ────────────────────────────────────────────────

def identify(hash_str: str) -> list:
    h = hash_str.strip()
    matches = []
    for pattern, types in HASH_PATTERNS:
        if re.match(pattern, h, re.I):
            matches.extend(types)
    return matches

# ─── CRACK ───────────────────────────────────────────────────

def crack_hash(hash_str: str, algo: str, wordlist: list, show_progress: bool = True) -> str | None:
    """Crack un hash en comparant avec une wordlist"""
    hash_str = hash_str.strip().lower()
    fn = HASH_FUNCTIONS.get(algo.lower())
    if not fn:
        err(f"Unknown algorithm: {algo}"); return None

    if show_progress:
        with Progress(
            SpinnerColumn(style=G1),
            TextColumn(f"[{G1}]Cracking"),
            BarColumn(bar_width=35, style=G2, complete_style=G1),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console
        ) as prog:
            task = prog.add_task("", total=len(wordlist))
            for word in wordlist:
                prog.advance(task)
                try:
                    if fn(word).lower() == hash_str:
                        prog.log(f"  [{G1}]★  CRACKED: {word}[/]")
                        return word
                except Exception:
                    continue
    else:
        for word in wordlist:
            try:
                if fn(word).lower() == hash_str:
                    return word
            except Exception:
                continue
    return None

# ─── ONLINE LOOKUP ───────────────────────────────────────────

def online_lookup(hash_str: str) -> str | None:
    """Lookup multi-sources (MD5/SHA1/SHA256) — style dehash.me / crackstation"""
    if not HAS_REQUESTS:
        return None
    h = hash_str.strip().lower()
    import re as _re
    hdr = {"User-Agent": "Mozilla/5.0"}

    # 1. nitrxgen — pas de clé, MD5/SHA1
    try:
        r = requests.get(f"https://www.nitrxgen.net/md5db/{h}", timeout=8, headers=hdr)
        val = r.text.strip()
        if r.status_code == 200 and val and len(val) < 128:
            return val
    except Exception:
        pass

    # 2. md5.gromweb.com — pas de clé
    try:
        r = requests.get("https://md5.gromweb.com/", timeout=10,
                         params={"md5": h}, timeout=8, headers=hdr)
        m = _re.search(r'<em class="long-string">([^<]+)</em>', r.text)
        if m:
            return m.group(1)
    except Exception:
        pass

    # 3. md5hashing.net — pas de clé
    try:
        r = requests.get(f"https://md5hashing.net/hash/md5/{h}", timeout=10,
                         timeout=8, headers=hdr)
        m = _re.search(r'<td[^>]*>\s*([^<]{1,80})\s*</td>', r.text)
        if m:
            val = m.group(1).strip()
            if val and val != h and len(val) < 80:
                return val
    except Exception:
        pass

    # 4. hashtoolkit.com — pas de clé
    try:
        r = requests.get(f"https://hashtoolkit.com/reverse-hash/?hash={h}", timeout=10,
                         timeout=8, headers=hdr)
        m = _re.search(r'<span[^>]+title="Decrypted Text"[^>]*>([^<]+)</span>', r.text)
        if m:
            val = m.group(1).strip()
            if val and val != h:
                return val
    except Exception:
        pass

    return None

# ─── HIBP PASSWORD CHECK ─────────────────────────────────────

def hibp_password(password: str) -> int:
    """k-anonymity check — ne transmet jamais le mot de passe complet"""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    if not HAS_REQUESTS:
        warn("requests not available"); return -1
    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10,
                         timeout=8, headers={"User-Agent": "MEOW-SEC/1.0"})
        for line in r.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count)
        return 0
    except Exception as e:
        err(f"HIBP error: {e}"); return -1

# ─── MAIN MEWHASH ────────────────────────────────────────────

def run():
    show_module_banner("mewhash")
    cat_talk(CAT_SCAN, "MEWHASH hash engine loaded...", OR)
    console.print()

    while True:
        console.print(f"  [{G1}][1][/] Identify hash type")
        console.print(f"  [{G1}][2][/] Hash a string  (MD5, SHA256, NTLM, MySQL...)")
        console.print(f"  [{G1}][3][/] Crack a hash   (wordlist attack)")
        console.print(f"  [{G1}][4][/] Crack with rules  (John/Hashcat mutations)")
        console.print(f"  [{G1}][5][/] HIBP password check  (k-anonymity)")
        console.print(f"  [{G1}][6][/] Hash file contents")
        console.print(f"  [{G1}][0][/] Back")
        console.print()
        choice = ask_choice("MEWHASH", "0")

        if choice == "0": break
        elif choice == "1": _identify_menu()
        elif choice == "2": _hash_menu()
        elif choice == "3": _crack_menu()
        elif choice == "4": _ripper_menu()
        elif choice == "5": _hibp_menu()
        elif choice == "6": _file_hash_menu()
        console.print()

def _identify_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] HASH IDENTIFIER ", style=G2))
    h = Prompt.ask(f"  [{G1}]◈ Hash string[/]").strip()
    if not h: return
    types = identify(h)
    if types:
        find(f"Possible types: [{CY}]{', '.join(types)}[/]")
        console.print(f"  [{DM}]Hash length: {len(h)} chars[/]")
    else:
        warn("Unknown hash type or not a hash.")

def _hash_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] HASH STRING ", style=G2))
    text = Prompt.ask(f"  [{G1}]◈ String to hash[/]").strip()
    if not text: return

    console.print()
    t = Table(box=box.SIMPLE, border_style=G2, header_style=CY, show_edge=False)
    t.add_column("Algorithm", style=CY, width=14)
    t.add_column("Hash",      style=G1)

    SHOW_ALGOS = ["md5","sha1","sha256","sha512","ntlm","mysql4","blake2b","md5_double"]
    for algo in SHOW_ALGOS:
        fn = HASH_FUNCTIONS.get(algo)
        if fn:
            try:
                digest = fn(text)
                t.add_row(algo.upper(), digest)
            except Exception as e:
                t.add_row(algo.upper(), f"[{RD}]error: {e}[/]")
    console.print(t)

def _crack_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] HASH CRACKER ", style=G2))

    target_hash = Prompt.ask(f"  [{G1}]◈ Hash to crack[/]").strip()
    if not target_hash: return

    # Identification automatique
    types = identify(target_hash)
    if types:
        info(f"Detected type(s): [{CY}]{', '.join(types)}[/]")

    algo = Prompt.ask(f"  [{G1}]◈ Algorithm[/]",
                      default=types[0].lower().replace("-","").replace(" ","_") if types else "md5")

    # Wordlist
    console.print(f"  [{G1}][1][/] Built-in mini wordlist  ({len(MINI_WORDLIST)} words)")
    console.print(f"  [{G1}][2][/] Custom wordlist file")
    console.print(f"  [{G1}][3][/] Built-in + custom file")
    wl_choice = ask_choice("Wordlist", "1")

    wordlist = []
    if wl_choice in ("1", "3"):
        wordlist += MINI_WORDLIST
    if wl_choice in ("2", "3"):
        path = Prompt.ask(f"  [{G1}]◈ Wordlist path[/]").strip()
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="ignore") as f:
                wordlist += [l.strip() for l in f if l.strip()]
        else:
            err(f"File not found: {path}")

    # Lookup online first?
    if HAS_REQUESTS:
        info("Trying online lookup first...")
        result = online_lookup(target_hash)
        if result:
            find(f"Online lookup: [{CY}]{result}[/]"); return

    info(f"Cracking with [{G1}]{len(wordlist)}[/] words...")
    result = crack_hash(target_hash, algo, wordlist)
    if result:
        cat_talk(CAT_FOUND, f"CRACKED: {result}", G1)
    else:
        warn("Hash not cracked with current wordlist.")

def _ripper_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] RIPPER — RULE-BASED CRACK ", style=G2))
    info("Applies John-the-Ripper / Hashcat mutations: l33t, append numbers/symbols/years, reverse...")
    console.print()

    target_hash = Prompt.ask(f"  [{G1}]◈ Hash to crack[/]").strip()
    if not target_hash: return

    types = identify(target_hash)
    if types:
        info(f"Detected type(s): [{CY}]{', '.join(types)}[/]")

    algo = Prompt.ask(f"  [{G1}]◈ Algorithm[/]",
                      default=types[0].lower().replace("-","").replace(" ","_") if types else "md5")

    # Wordlist base
    console.print(f"  [{G1}][1][/] Built-in mini wordlist  ({len(MINI_WORDLIST)} words → ~{len(MINI_WORDLIST)*30} mutations)")
    console.print(f"  [{G1}][2][/] Custom wordlist file")
    console.print(f"  [{G1}][3][/] Built-in + custom file")
    wl_choice = ask_choice("Base wordlist", "1")

    wordlist = []
    if wl_choice in ("1", "3"):
        wordlist += MINI_WORDLIST
    if wl_choice in ("2", "3"):
        path = Prompt.ask(f"  [{G1}]◈ Wordlist path[/]").strip()
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="ignore") as f:
                wordlist += [l.strip() for l in f if l.strip()]
        else:
            err(f"File not found: {path}")

    if not wordlist:
        wordlist = MINI_WORDLIST

    # Online first
    if HAS_REQUESTS:
        info("Trying online lookup first (4 sources)...")
        result = online_lookup(target_hash)
        if result:
            find(f"Online dehash: [{CY}]{result}[/]"); return

    info(f"Running rule-based crack on [{G1}]{len(wordlist)}[/] base words...")
    result = crack_with_rules(target_hash, algo, wordlist)
    if result:
        from core.cats import CAT_FOUND
        cat_talk(CAT_FOUND, f"CRACKED: {result}", G1)
    else:
        warn("Not cracked. Try a larger wordlist or different algorithm.")

def _hibp_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] HIBP CHECK ", style=G2))
    info("Your password is NEVER sent — only first 5 chars of SHA1 hash (k-anonymity)")
    pwd = Prompt.ask(f"  [{G1}]◈ Password to check[/]").strip()
    if not pwd: return
    count = hibp_password(pwd)
    if count > 0:
        warn(f"Found in [{RD}]{count:,}[/] breach(es)! Change this password.")
    elif count == 0:
        ok("Not found in known breaches.")

def _file_hash_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] FILE HASH ", style=G2))
    path = Prompt.ask(f"  [{G1}]◈ File path[/]").strip().strip('"')
    if not os.path.exists(path):
        err(f"File not found: {path}"); return

    data = open(path, "rb").read()
    algos = ["md5","sha1","sha256","sha512"]
    rows = []
    for algo in algos:
        h = hashlib.new(algo, data).hexdigest()
        rows.append((algo.upper(), h))
    print_result_table(f"File Hash :: {os.path.basename(path)}",
        ["Algorithm", "Hash"], rows)

def _banner():
    logo = Text(r"""
 ███╗   ███╗███████╗██╗    ██╗██╗  ██╗ █████╗ ███████╗██╗  ██╗
 ████╗ ████║██╔════╝██║    ██║██║  ██║██╔══██╗██╔════╝██║  ██║
 ██╔████╔██║█████╗  ██║ █╗ ██║███████║███████║███████╗███████║
 ██║╚██╔╝██║██╔══╝  ██║███╗██║██╔══██║██╔══██║╚════██║██╔══██║
 ██║ ╚═╝ ██║███████╗╚███╔███╔╝██║  ██║██║  ██║███████║██║  ██║
 ╚═╝     ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
      [HASH IDENTIFIER · HASHER · CRACKER]""", style=f"bold {G1}")
    console.print(Panel(Align(logo, align="center"), border_style=RD, padding=(0,1)))
