# -*- coding: utf-8 -*-
"""
MEOW-SEC :: CODEC — Encoder / Decoder Swiss Army Knife
  · Base64, Base32, Base16/Hex
  · URL encode/decode
  · HTML entities
  · Binary / ASCII
  · ROT13 / Caesar cipher
  · XOR cipher
  · Morse code
  · JWT decoder (no verify)
  · String analysis
"""
import base64, urllib.parse, html, json, re, string
from datetime import datetime

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich import box

# ─── MORSE CODE ──────────────────────────────────────────────

MORSE = {
    'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....',
    'I':'..','J':'.---','K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.',
    'Q':'--.-','R':'.-.','S':'...','T':'-','U':'..-','V':'...-','W':'.--','X':'-..-',
    'Y':'-.--','Z':'--..','0':'-----','1':'.----','2':'..---','3':'...--','4':'....-',
    '5':'.....','6':'-....','7':'--...','8':'---..','9':'----.','.':".-.-.-",
    ',':"--..--",'?':'..--..','/':'-..-.','@':'.--.-.','=':'-...-',
}
MORSE_REV = {v: k for k, v in MORSE.items()}

def to_morse(text: str) -> str:
    return " / ".join(
        " ".join(MORSE.get(c.upper(), "?") for c in word)
        for word in text.split()
    )

def from_morse(morse: str) -> str:
    return " ".join(
        "".join(MORSE_REV.get(code, "?") for code in word.split())
        for word in morse.split(" / ")
    )

# ─── CAESAR / ROT ────────────────────────────────────────────

def caesar(text: str, shift: int = 13, decode: bool = False) -> str:
    if decode: shift = -shift
    result = []
    for c in text:
        if c.isupper():
            result.append(chr((ord(c) - 65 + shift) % 26 + 65))
        elif c.islower():
            result.append(chr((ord(c) - 97 + shift) % 26 + 97))
        else:
            result.append(c)
    return "".join(result)

def caesar_bruteforce(text: str) -> list:
    return [(shift, caesar(text, shift, decode=True)) for shift in range(1, 26)]

# ─── XOR ─────────────────────────────────────────────────────

def xor_encrypt(text: str, key: str) -> str:
    if not key: return text
    result = bytearray()
    for i, c in enumerate(text.encode()):
        result.append(c ^ ord(key[i % len(key)]))
    return result.hex()

def xor_decrypt(hex_str: str, key: str) -> str:
    try:
        data = bytes.fromhex(hex_str)
        result = bytearray()
        for i, c in enumerate(data):
            result.append(c ^ ord(key[i % len(key)]))
        return result.decode(errors="replace")
    except Exception as e:
        return f"Error: {e}"

# ─── JWT ─────────────────────────────────────────────────────

def decode_jwt(token: str) -> dict:
    """Décode un JWT sans vérification de signature"""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return {"error": "Not a valid JWT (need 3 parts)"}

    def b64decode(s: str) -> dict:
        # JWT base64url: pas de padding standard
        s += "=" * (4 - len(s) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(s).decode())
        except Exception as e:
            return {"decode_error": str(e)}

    return {
        "header":    b64decode(parts[0]),
        "payload":   b64decode(parts[1]),
        "signature": parts[2],
        "note":      "Signature NOT verified",
    }

# ─── STRING ANALYSIS ─────────────────────────────────────────

def analyze_string(text: str) -> dict:
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    top5 = sorted(freq.items(), key=lambda x: -x[1])[:5]

    printable = sum(1 for c in text if c in string.printable)
    entropy = 0.0
    n = len(text)
    if n > 0:
        import math
        for count in freq.values():
            p = count / n
            entropy -= p * math.log2(p)

    return {
        "length":      n,
        "printable":   printable,
        "non_print":   n - printable,
        "unique_chars": len(freq),
        "entropy":     round(entropy, 3),
        "top_chars":   top5,
        "hex":         text.encode().hex(),
        "base64":      base64.b64encode(text.encode()).decode(),
        "is_base64":   _is_base64(text),
        "is_hex":      bool(re.match(r"^[0-9a-fA-F]+$", text)) and len(text) % 2 == 0,
        "is_json":     _is_json(text),
    }

def _is_base64(s: str) -> bool:
    try:
        s2 = s.strip().rstrip("=")
        if len(s2) % 4 not in (0, 2, 3): return False
        base64.b64decode(s + "==")
        return bool(re.match(r"^[A-Za-z0-9+/=]+$", s))
    except Exception:
        return False

def _is_json(s: str) -> bool:
    try:
        json.loads(s); return True
    except Exception:
        return False

# ─── ALL OPERATIONS ──────────────────────────────────────────

OPERATIONS = {
    # Encode
    "b64_encode":      lambda t, _: base64.b64encode(t.encode()).decode(),
    "b64_decode":      lambda t, _: base64.b64decode(t + "==").decode(errors="replace"),
    "b64url_encode":   lambda t, _: base64.urlsafe_b64encode(t.encode()).decode(),
    "b64url_decode":   lambda t, _: base64.urlsafe_b64decode(t + "==").decode(errors="replace"),
    "b32_encode":      lambda t, _: base64.b32encode(t.encode()).decode(),
    "b32_decode":      lambda t, _: base64.b32decode(t + "=" * (8 - len(t) % 8)).decode(errors="replace"),
    "hex_encode":      lambda t, _: t.encode().hex(),
    "hex_decode":      lambda t, _: bytes.fromhex(t).decode(errors="replace"),
    "url_encode":      lambda t, _: urllib.parse.quote(t),
    "url_decode":      lambda t, _: urllib.parse.unquote(t),
    "url_encode_full": lambda t, _: urllib.parse.quote(t, safe=""),
    "html_encode":     lambda t, _: html.escape(t),
    "html_decode":     lambda t, _: html.unescape(t),
    "binary_encode":   lambda t, _: " ".join(f"{ord(c):08b}" for c in t),
    "binary_decode":   lambda t, _: "".join(chr(int(b, 2)) for b in t.split()),
    "rot13":           lambda t, _: t.translate(str.maketrans(
                            string.ascii_uppercase + string.ascii_lowercase,
                            string.ascii_uppercase[13:] + string.ascii_uppercase[:13] +
                            string.ascii_lowercase[13:] + string.ascii_lowercase[:13])),
    "morse_encode":    lambda t, _: to_morse(t),
    "morse_decode":    lambda t, _: from_morse(t),
    "reverse":         lambda t, _: t[::-1],
    "upper":           lambda t, _: t.upper(),
    "lower":           lambda t, _: t.lower(),
    "md5":             lambda t, _: __import__("hashlib").md5(t.encode()).hexdigest(),
    "sha256":          lambda t, _: __import__("hashlib").sha256(t.encode()).hexdigest(),
}

# ─── MAIN CODEC ──────────────────────────────────────────────

def run():
    show_module_banner("codec")
    console.print()

    while True:
        _show_ops_menu()
        choice = ask_choice("CODEC", "0")
        if choice == "0": break

        if choice == "1":   _encode_decode_menu()
        elif choice == "2": _caesar_menu()
        elif choice == "3": _xor_menu()
        elif choice == "4": _jwt_menu()
        elif choice == "5": _analyze_menu()
        elif choice == "6": _multi_encode()
        console.print()

def _show_ops_menu():
    console.print(f"  [{G1}][1][/] Encode / Decode  (B64, hex, URL, HTML, binary, morse...)")
    console.print(f"  [{G1}][2][/] Caesar / ROT bruteforce")
    console.print(f"  [{G1}][3][/] XOR cipher")
    console.print(f"  [{G1}][4][/] JWT decoder")
    console.print(f"  [{G1}][5][/] String analysis   (entropy, frequency, detect type)")
    console.print(f"  [{G1}][6][/] Multi-encode chain  (apply multiple ops in sequence)")
    console.print(f"  [{G1}][0][/] Back")
    console.print()

def _encode_decode_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] ENCODE / DECODE ", style=G2))
    text = Prompt.ask(f"  [{G1}]◈ Input text[/]").strip()
    if not text: return

    ops_display = [
        ("1",  "Base64 encode"),       ("2",  "Base64 decode"),
        ("3",  "Base64url encode"),     ("4",  "Base64url decode"),
        ("5",  "Base32 encode"),        ("6",  "Base32 decode"),
        ("7",  "Hex encode"),           ("8",  "Hex decode"),
        ("9",  "URL encode"),           ("10", "URL decode"),
        ("11", "URL encode (full)"),    ("12", "HTML encode"),
        ("13", "HTML decode"),          ("14", "Binary encode"),
        ("15", "Binary decode"),        ("16", "ROT13"),
        ("17", "Morse encode"),         ("18", "Morse decode"),
        ("19", "Reverse string"),       ("20", "To uppercase"),
        ("21", "To lowercase"),         ("22", "MD5 hash"),
        ("23", "SHA256 hash"),
    ]
    op_keys = [
        "b64_encode","b64_decode","b64url_encode","b64url_decode",
        "b32_encode","b32_decode","hex_encode","hex_decode",
        "url_encode","url_decode","url_encode_full","html_encode",
        "html_decode","binary_encode","binary_decode","rot13",
        "morse_encode","morse_decode","reverse","upper","lower",
        "md5","sha256",
    ]

    t = Table(box=box.SIMPLE, border_style=G2, header_style=CY, show_edge=False)
    t.add_column("#", style=CY, width=4)
    t.add_column("Operation", style=G1, width=22)
    t.add_column("#", style=CY, width=4)
    t.add_column("Operation", style=G1)

    pairs = list(zip(ops_display[::2], ops_display[1::2]))
    for (k1,v1), (k2,v2) in pairs:
        t.add_row(k1, v1, k2, v2)
    if len(ops_display) % 2:
        k, v = ops_display[-1]
        t.add_row(k, v, "", "")
    console.print(t)
    console.print()

    sel = Prompt.ask(f"  [{G1}]◈ Operation #[/]").strip()
    try:
        idx = int(sel) - 1
        key = op_keys[idx]
        fn  = OPERATIONS[key]
        result = fn(text, None)
        console.print()
        console.print(Panel(
            Text(result, style=f"bold {G1}"),
            title=f"[{G1}]{ops_display[idx][1]}",
            border_style=G2
        ))
    except (ValueError, IndexError, Exception) as e:
        err(f"Error: {e}")

def _caesar_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] CAESAR / ROT ", style=G2))
    text = Prompt.ask(f"  [{G1}]◈ Text[/]").strip()
    if not text: return

    console.print(f"  [{G1}][1][/] Encode with shift")
    console.print(f"  [{G1}][2][/] Decode with shift")
    console.print(f"  [{G1}][3][/] Bruteforce all 25 shifts")
    mode = ask_choice("", "3")

    if mode == "3":
        console.print()
        t = Table(box=box.SIMPLE, border_style=G2, header_style=CY)
        t.add_column("Shift", style=CY, width=6)
        t.add_column("Result", style=G1)
        for shift, decoded in caesar_bruteforce(text):
            t.add_row(str(shift), decoded)
        console.print(t)
    else:
        shift = int(Prompt.ask(f"  [{G1}]◈ Shift[/]", default="13"))
        decode = (mode == "2")
        result = caesar(text, shift, decode)
        console.print(Panel(Text(result, style=f"bold {G1}"),
                            title=f"[{G1}]Caesar shift={shift}", border_style=G2))

def _xor_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] XOR CIPHER ", style=G2))
    console.print(f"  [{G1}][1][/] Encrypt (text → hex)")
    console.print(f"  [{G1}][2][/] Decrypt (hex → text)")
    mode = ask_choice("", "1")

    key = Prompt.ask(f"  [{G1}]◈ XOR key[/]").strip()
    if not key: return

    if mode == "1":
        text = Prompt.ask(f"  [{G1}]◈ Plaintext[/]").strip()
        result = xor_encrypt(text, key)
    else:
        hexstr = Prompt.ask(f"  [{G1}]◈ Hex ciphertext[/]").strip()
        result = xor_decrypt(hexstr, key)

    console.print(Panel(Text(result, style=f"bold {G1}"),
                        title=f"[{G1}]XOR result", border_style=G2))

def _jwt_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] JWT DECODER ", style=G2))
    token = Prompt.ask(f"  [{G1}]◈ JWT token[/]").strip()
    if not token: return
    decoded = decode_jwt(token)
    console.print(Panel(
        Syntax(json.dumps(decoded, indent=2), "json", theme="monokai"),
        title=f"[{G1}]JWT Decoded  (signature NOT verified)",
        border_style=OR
    ))
    if "payload" in decoded:
        payload = decoded["payload"]
        if isinstance(payload, dict):
            if "exp" in payload:
                import time
                exp = payload["exp"]
                now = time.time()
                if exp < now:
                    warn(f"Token EXPIRED {(now-exp)/3600:.1f}h ago!")
                else:
                    ok(f"Token valid for [{G1}]{(exp-now)/3600:.1f}h[/] more")

def _analyze_menu():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] STRING ANALYSIS ", style=G2))
    text = Prompt.ask(f"  [{G1}]◈ String to analyze[/]").strip()
    if not text: return
    a = analyze_string(text)

    rows = [
        ("Length",       str(a["length"])),
        ("Printable",    str(a["printable"])),
        ("Non-printable",str(a["non_print"])),
        ("Unique chars", str(a["unique_chars"])),
        ("Entropy",      f"{a['entropy']} bits/char"),
        ("Is Base64",    "YES" if a["is_base64"] else "no"),
        ("Is Hex",       "YES" if a["is_hex"] else "no"),
        ("Is JSON",      "YES" if a["is_json"] else "no"),
        ("Top chars",    str([(c, n) for c, n in a["top_chars"]])),
        ("As Hex",       a["hex"][:60]),
        ("As Base64",    a["base64"][:60]),
    ]
    from core.ui import print_result_table
    print_result_table("String Analysis", ["Property", "Value"], rows)

def _multi_encode():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] MULTI-ENCODE CHAIN ", style=G2))
    text = Prompt.ask(f"  [{G1}]◈ Input[/]").strip()
    if not text: return

    short_ops = {
        "b64e": "b64_encode",  "b64d": "b64_decode",
        "hexe": "hex_encode",  "hexd": "hex_decode",
        "urle": "url_encode",  "urld": "url_decode",
        "rot13": "rot13",      "rev": "reverse",
        "md5": "md5",          "sha256": "sha256",
    }
    info(f"Available ops: {', '.join(short_ops.keys())}")
    chain_str = Prompt.ask(f"  [{G1}]◈ Chain (e.g. b64e,urle,rot13)[/]").strip()
    ops = [o.strip() for o in chain_str.split(",")]

    current = text
    console.print()
    for op in ops:
        key = short_ops.get(op, op)
        fn  = OPERATIONS.get(key)
        if fn:
            try:
                current = fn(current, None)
                console.print(f"  [{CY}]{op}[/] → [{G1}]{current[:80]}[/]")
            except Exception as e:
                err(f"Op '{op}' failed: {e}"); break
        else:
            warn(f"Unknown op: {op}")
    console.print()
    console.print(Panel(Text(current, style=f"bold {G1}"),
                        title=f"[{G1}]Final result", border_style=G2))

def _banner():
    logo = Text(r"""
  ██████╗ ██████╗ ██████╗ ███████╗ ██████╗
 ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝
 ██║     ██║   ██║██║  ██║█████╗  ██║
 ██║     ██║   ██║██║  ██║██╔══╝  ██║
 ╚██████╗╚██████╔╝██████╔╝███████╗╚██████╗
  ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝
  [B64·HEX·URL·MORSE·XOR·ROT·JWT·BINARY]""", style=f"bold {G1}")
    console.print(Panel(Align(logo, align="center"), border_style=RD, padding=(0,1)))
