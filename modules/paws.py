# -*- coding: utf-8 -*-
"""
MEOW-SEC :: PAWS — Password Generator
  · Random passwords (custom charset, length, rules)
  · Passphrase generator (word-based, memorable)
  · Pattern-based (e.g. Cvccvcc##!)
  · PIN / numeric codes
  · Password strength analyzer
  · Bulk export
"""
import os, json, random, string, re, math
from datetime import datetime

from core.ui import (console, ok, err, info, warn, find,
                     ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_FOUND
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.prompt import Prompt, IntPrompt, Confirm
from rich import box

# ─── WORDLISTS ───────────────────────────────────────────────

WORDS_ANIMALS = [
    "cat","dog","fox","wolf","bear","lion","tiger","eagle","hawk","shark",
    "cobra","panther","jaguar","falcon","raven","viper","lynx","gecko",
    "puma","orca","manta","hydra","phoenix","dragon","kraken","sphinx",
]
WORDS_TECH = [
    "cyber","hack","code","dark","net","root","shell","null","void","zero",
    "ghost","pixel","cipher","venom","shadow","matrix","vector","kernel",
    "daemon","proxy","virus","trojan","binary","crypto","stealth","recon",
]
WORDS_ADJECTIVES = [
    "silent","hidden","dark","swift","bold","sharp","fierce","cold","deep",
    "black","red","iron","steel","frozen","burning","electric","sacred",
    "ancient","toxic","cursed","volatile","invisible","broken","elite",
]
WORDS_NOUNS = [
    "storm","fire","blade","claw","fang","void","gate","rift","core","node",
    "shard","vault","realm","forge","nexus","pulse","surge","dusk","dawn",
    "tomb","rune","chain","lock","seal","mark","trace","shadow","echo",
]
ALL_WORDS = WORDS_ANIMALS + WORDS_TECH + WORDS_ADJECTIVES + WORDS_NOUNS

# ─── CHARSET ─────────────────────────────────────────────────

CHARSETS = {
    "lower":   string.ascii_lowercase,
    "upper":   string.ascii_uppercase,
    "digits":  string.digits,
    "symbols": "!@#$%^&*()_+-=[]{}|;:,.<>?/~",
    "safe_sym": "!@#$%^&*_+-=",
    "hex":     "0123456789abcdef",
    "alphanum": string.ascii_letters + string.digits,
    "all":     string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?",
}

# ─── STRENGTH ────────────────────────────────────────────────

def strength(pwd: str) -> dict:
    score = 0
    checks = {
        "length >= 8":    len(pwd) >= 8,
        "length >= 12":   len(pwd) >= 12,
        "length >= 16":   len(pwd) >= 16,
        "uppercase":      bool(re.search(r"[A-Z]", pwd)),
        "lowercase":      bool(re.search(r"[a-z]", pwd)),
        "digits":         bool(re.search(r"\d", pwd)),
        "symbols":        bool(re.search(r"[^a-zA-Z0-9]", pwd)),
        "no repeats":     len(set(pwd)) > len(pwd) * 0.6,
    }
    score = sum(1 for v in checks.values() if v)

    # Entropie
    charset_size = 0
    if re.search(r"[a-z]", pwd): charset_size += 26
    if re.search(r"[A-Z]", pwd): charset_size += 26
    if re.search(r"\d", pwd):    charset_size += 10
    if re.search(r"[^a-zA-Z0-9]", pwd): charset_size += 32
    entropy = len(pwd) * math.log2(charset_size) if charset_size else 0

    if score <= 3:   grade, col = "WEAK",      RD
    elif score <= 5: grade, col = "FAIR",      OR
    elif score <= 7: grade, col = "STRONG",    G1
    else:            grade, col = "EXCELLENT", f"bold {G1}"

    return {
        "grade":   grade,
        "color":   col,
        "score":   score,
        "entropy": round(entropy, 1),
        "checks":  checks,
    }

# ─── GENERATORS ──────────────────────────────────────────────

def gen_random(length: int = 16, use_upper=True, use_digits=True,
               use_symbols=True, symbols: str = None) -> str:
    pool = string.ascii_lowercase
    if use_upper:   pool += string.ascii_uppercase
    if use_digits:  pool += string.digits
    if use_symbols: pool += (symbols or CHARSETS["safe_sym"])

    # Garantit au moins un caractère de chaque type choisi
    pwd = []
    if use_upper:   pwd.append(random.choice(string.ascii_uppercase))
    if use_digits:  pwd.append(random.choice(string.digits))
    if use_symbols: pwd.append(random.choice(symbols or CHARSETS["safe_sym"]))
    pwd.append(random.choice(string.ascii_lowercase))

    remaining = length - len(pwd)
    pwd += random.choices(pool, k=remaining)
    random.shuffle(pwd)
    return "".join(pwd)

def gen_passphrase(num_words: int = 4, separator: str = "-",
                   capitalize: bool = True, add_number: bool = True) -> str:
    words = random.choices(ALL_WORDS, k=num_words)
    if capitalize:
        words = [w.capitalize() for w in words]
    phrase = separator.join(words)
    if add_number:
        phrase += str(random.randint(10, 999))
    return phrase

def gen_pattern(pattern: str) -> str:
    """
    Pattern syntax:
      C = uppercase consonant   c = lowercase consonant
      V = uppercase vowel       v = lowercase vowel
      L = uppercase letter      l = lowercase letter
      D = digit                 # = digit 1-9
      S = symbol                A = alphanumeric
      * = any character
      tout autre char = littéral
    """
    CONSONANTS_L = "bcdfghjklmnpqrstvwxyz"
    CONSONANTS_U = CONSONANTS_L.upper()
    VOWELS_L     = "aeiou"
    VOWELS_U     = "AEIOU"
    SYMBOLS      = CHARSETS["safe_sym"]

    result = []
    for ch in pattern:
        if   ch == "C": result.append(random.choice(CONSONANTS_U))
        elif ch == "c": result.append(random.choice(CONSONANTS_L))
        elif ch == "V": result.append(random.choice(VOWELS_U))
        elif ch == "v": result.append(random.choice(VOWELS_L))
        elif ch == "L": result.append(random.choice(string.ascii_uppercase))
        elif ch == "l": result.append(random.choice(string.ascii_lowercase))
        elif ch == "D": result.append(random.choice(string.digits))
        elif ch == "#": result.append(random.choice("123456789"))
        elif ch == "S": result.append(random.choice(SYMBOLS))
        elif ch == "A": result.append(random.choice(string.ascii_letters + string.digits))
        elif ch == "*": result.append(random.choice(CHARSETS["all"]))
        else:           result.append(ch)
    return "".join(result)

def gen_pin(length: int = 4) -> str:
    return "".join(random.choices(string.digits, k=length))

def gen_hex_key(bits: int = 256) -> str:
    return "".join(random.choices(string.hexdigits[:16], k=bits // 4))

def gen_wpa_key() -> str:
    """WPA-style 64-char hex key"""
    return gen_hex_key(256)

def gen_wifi_password() -> str:
    """Password style réseau WiFi — 8-63 chars"""
    return gen_random(12, use_upper=True, use_digits=True, use_symbols=False)

# ─── DISPLAY ─────────────────────────────────────────────────

def show_password(pwd: str, label: str = ""):
    s = strength(pwd)
    grade_str = f"[{s['color']}]{s['grade']}[/]"
    entropy_str = f"[{CY}]{s['entropy']} bits[/]"
    label_str = f"[{DM}]{label}[/]  " if label else ""
    console.print(
        f"  {label_str}"
        f"[bold {G1}]{pwd}[/]"
        f"  {grade_str}"
        f"  entropy={entropy_str}"
        f"  [{DM}]({len(pwd)} chars)[/]"
    )

def show_strength_detail(pwd: str):
    s = strength(pwd)
    rows = [(k, f"[{G1}]✓[/]" if v else f"[{RD}]✗[/]") for k, v in s["checks"].items()]
    rows.append(("Entropy", f"{s['entropy']} bits"))
    rows.append(("Grade",   f"[{s['color']}]{s['grade']}[/]"))
    print_result_table(f"Strength :: {pwd}", ["Check", "Result"], rows)

# ─── MAIN PAWS ───────────────────────────────────────────────

def run():
    show_module_banner("paws")
    cat_talk(CAT_FOUND, "PAWS password engine ready — generating secrets...", OR)
    console.print()

    while True:
        console.print(f"  [{G1}][1][/] Random password")
        console.print(f"  [{G1}][2][/] Passphrase (word-based, memorable)")
        console.print(f"  [{G1}][3][/] Pattern-based  (e.g. CvcvDD##S)")
        console.print(f"  [{G1}][4][/] PIN / numeric code")
        console.print(f"  [{G1}][5][/] Hex API key / WPA key")
        console.print(f"  [{G1}][6][/] Bulk generate + export")
        console.print(f"  [{G1}][7][/] Analyze password strength")
        console.print(f"  [{G1}][0][/] Back")
        console.print()

        choice = ask_choice("PAWS", "0")
        if choice == "0":
            break
        elif choice == "1": _random_menu()
        elif choice == "2": _passphrase_menu()
        elif choice == "3": _pattern_menu()
        elif choice == "4": _pin_menu()
        elif choice == "5": _key_menu()
        elif choice == "6": _bulk_menu()
        elif choice == "7": _analyze_menu()
        console.print()

def _random_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] RANDOM PASSWORD ", style=G2))
    length  = IntPrompt.ask(f"  [{G1}]◈ Length[/]", default=16)
    upper   = Confirm.ask(f"  [{G1}]◈ Uppercase?[/]",    default=True)
    digits  = Confirm.ask(f"  [{G1}]◈ Digits?[/]",       default=True)
    symbols = Confirm.ask(f"  [{G1}]◈ Symbols?[/]",      default=True)
    count   = IntPrompt.ask(f"  [{G1}]◈ How many?[/]",   default=5)
    console.print()
    for i in range(count):
        show_password(gen_random(length, upper, digits, symbols), f"#{i+1}")

def _passphrase_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] PASSPHRASE ", style=G2))
    words = IntPrompt.ask(f"  [{G1}]◈ Number of words[/]",       default=4)
    sep   = Prompt.ask(f"  [{G1}]◈ Separator (default: -)[/]",  default="-")
    cap   = Confirm.ask(f"  [{G1}]◈ Capitalize words?[/]",      default=True)
    num   = Confirm.ask(f"  [{G1}]◈ Add number at end?[/]",     default=True)
    count = IntPrompt.ask(f"  [{G1}]◈ How many?[/]",             default=5)
    console.print()
    for i in range(count):
        show_password(gen_passphrase(words, sep, cap, num), f"#{i+1}")

def _pattern_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] PATTERN ", style=G2))
    console.print(f"  [{DM}]C=Consonant  V=Vowel  L=Letter  D=Digit  #=Digit1-9  S=Symbol  A=AlphaNum  *=Any[/]")
    console.print(f"  [{DM}]Examples: CvcvDD##S  ·  LlllDDSS  ·  LLLLDDSS  ·  Cvccvcc##![/]")
    console.print()
    pattern = Prompt.ask(f"  [{G1}]◈ Pattern[/]", default="CvcvDD##S")
    count   = IntPrompt.ask(f"  [{G1}]◈ How many?[/]", default=5)
    console.print()
    for i in range(count):
        show_password(gen_pattern(pattern), f"#{i+1}")

def _pin_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] PIN / CODE ", style=G2))
    length = IntPrompt.ask(f"  [{G1}]◈ PIN length[/]", default=6)
    count  = IntPrompt.ask(f"  [{G1}]◈ How many?[/]",  default=5)
    console.print()
    for i in range(count):
        console.print(f"  [bold {G1}]{gen_pin(length)}[/]")

def _key_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] HEX KEY / WPA ", style=G2))
    console.print(f"  [{G1}][1][/] 128-bit hex key (32 chars)")
    console.print(f"  [{G1}][2][/] 256-bit hex key (64 chars)")
    console.print(f"  [{G1}][3][/] WPA2 hex key    (64 chars)")
    console.print(f"  [{G1}][4][/] WiFi password   (12 chars)")
    choice = ask_choice("Key type", "2")
    console.print()
    for _ in range(5):
        if   choice == "1": console.print(f"  [bold {CY}]{gen_hex_key(128)}[/]")
        elif choice == "2": console.print(f"  [bold {CY}]{gen_hex_key(256)}[/]")
        elif choice == "3": console.print(f"  [bold {CY}]{gen_wpa_key()}[/]")
        elif choice == "4": show_password(gen_wifi_password())

def _bulk_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] BULK GENERATE ", style=G2))
    console.print(f"  [{G1}][1][/] Random passwords")
    console.print(f"  [{G1}][2][/] Passphrases")
    console.print(f"  [{G1}][3][/] Mixed")
    gen_type = ask_choice("Type", "3")
    count    = IntPrompt.ask(f"  [{G1}]◈ How many?[/]", default=20)
    length   = IntPrompt.ask(f"  [{G1}]◈ Password length[/]", default=16)

    passwords = []
    for _ in range(count):
        if gen_type == "1":
            passwords.append(gen_random(length))
        elif gen_type == "2":
            passwords.append(gen_passphrase())
        else:
            if random.random() > 0.5:
                passwords.append(gen_random(length))
            else:
                passwords.append(gen_passphrase())

    console.print()
    for i, pwd in enumerate(passwords, 1):
        show_password(pwd, f"#{i:02d}")

    # Export
    if Confirm.ask(f"\n  [{G1}]◈ Export to file?[/]", default=True):
        out_dir = os.path.join(os.path.dirname(__file__), "..", "data")
        os.makedirs(out_dir, exist_ok=True)
        fname = os.path.join(out_dir, f"passwords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(fname, "w", encoding="utf-8") as f:
            f.write(f"# MEOW-SEC PAWS — Generated {datetime.now()}\n\n")
            for pwd in passwords:
                f.write(pwd + "\n")
        ok(f"Exported [{G1}]{len(passwords)}[/] passwords → [{CY}]{os.path.basename(fname)}[/]")

def _analyze_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] STRENGTH ANALYZER ", style=G2))
    pwd = Prompt.ask(f"  [{G1}]◈ Password to analyze[/]").strip()
    if pwd:
        show_strength_detail(pwd)

def _banner():
    logo = Text(r"""
 ██████╗  █████╗ ██╗    ██╗███████╗
 ██╔══██╗██╔══██╗██║    ██║██╔════╝
 ██████╔╝███████║██║ █╗ ██║███████╗
 ██╔═══╝ ██╔══██║██║███╗██║╚════██║
 ██║     ██║  ██║╚███╔███╔╝███████║
 ╚═╝     ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝
  [PASSWORD GENERATOR & ANALYZER]""", style=f"bold {G1}")
    console.print(Panel(Align(logo, align="center"), border_style=RD, padding=(0,1)))
