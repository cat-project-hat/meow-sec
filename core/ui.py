# -*- coding: utf-8 -*-
"""
MEOW-SEC :: Terminal UI Components
"""
import time, random
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, MofNCompleteColumn
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.prompt import Prompt
from rich import box
from rich.rule import Rule
from rich.live import Live

from core.cats import MEOW_LOGO, BANNER_CAT, MODULE_LOGOS

import sys as _sys, io as _io
_out = (_io.TextIOWrapper(_sys.stdout.buffer, encoding="utf-8", errors="replace")
        if hasattr(_sys.stdout, "buffer") else _sys.stdout)
console = Console(file=_out, legacy_windows=False, highlight=False)

# ─── COULEURS MEOW-SEC ───────────────────────────────────────
G1 = "bright_green"       # vert matrix vif
G2 = "green"              # vert matrix dim
G3 = "dark_green"         # vert sombre
CY = "bright_cyan"        # cyan info
OR = "#FF8C00"            # orange chat
RD = "bright_red"         # rouge alerte
WH = "grey93"             # blanc texte
DM = "grey50"             # gris dim

# ─── HELPERS ─────────────────────────────────────────────────

def clr():
    import os; os.system("cls" if os.name == "nt" else "clear")

def rule(title: str = "", color: str = G2):
    console.print(Rule(title, style=color))

def ok(msg):   console.print(f"[{G1}]  [✓][/]  {msg}")
def err(msg):  console.print(f"[{RD}]  [✗][/]  [{RD}]{msg}[/]")
def info(msg): console.print(f"[{CY}]  [i][/]  {msg}")
def warn(msg): console.print(f"[{OR}]  [!][/]  [{OR}]{msg}[/]")
def find(msg): console.print(f"[bold {G1}]  [★][/]  [bold {G1}]{msg}[/]")

def tag(text: str, color: str = G2) -> str:
    return f"[{color}][{text}][/{color}]"

# ─── MAIN BANNER ─────────────────────────────────────────────

def show_banner():
    clr()
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

    # Logo compact sur une ligne + chat inline
    header = Table.grid(expand=True, padding=(0, 2))
    header.add_column(ratio=3)
    header.add_column(ratio=1, justify="right")

    logo_text = Text()
    logo_text.append("◈ MEOW-SEC ", style=f"bold {G1}")
    logo_text.append("v1.1", style=G2)
    logo_text.append("  ::  CAT HACKER TOOLKIT", style=DM)

    meta_text = Text()
    meta_text.append(f"{now}  ", style=DM)
    meta_text.append("● ONLINE", style=f"bold {G1}")

    header.add_row(logo_text, meta_text)
    console.print(Panel(header, border_style=G2, padding=(0, 1)))

def show_module_banner(module: str):
    """Bannière compacte d'une ligne — pas de gros ASCII art"""
    names = {
        "claw":     ("CLAW",     "Port & Service Scanner",    G1),
        "purr":     ("PURR",     "HTTP Recon & Headers",      CY),
        "scratch":  ("SCRATCH",  "Directory Brute Force",     OR),
        "whisker":  ("WHISKER",  "DNS / WHOIS / IP Recon",    CY),
        "hiss":     ("HISS",     "SQLi / XSS Tester",         RD),
        "catnap":   ("CATNAP",   "Subdomain Enumerator",      G1),
        "proxycat": ("PROXYCAT", "Proxy Manager",             G2),
        "ghost":    ("GHOST",    "Username OSINT",            CY),
        "osint":    ("OSINT+",   "Extended OSINT",            OR),
        "paws":     ("PAWS",     "Password Generator",        G1),
        "mewhash":  ("MEWHASH",  "Hash Tools",                G1),
        "codec":    ("CODEC",    "Encoder / Decoder",         CY),
        "payload":  ("PAYLOAD",  "Payload Library",           RD),
        "netkit":   ("NETKIT",   "Network Utilities",         CY),
        "stress":   ("STRESS",   "Stress Tester (17 methods)", RD),
        "revshell": ("REVSHELL", "Reverse Shell Generator",   G1),
        "waf":      ("WAF",      "WAF / CDN Fingerprinting",  CY),
        "jwtcat":   ("JWTCAT",   "JWT Attacker",              OR),
        "report":   ("REPORT",   "HTML Report Generator",     G2),
        "loot":     ("LOOT",     "Saved Results Viewer",      G2),
        "brute":    ("BRUTE",    "HTTP Login Brute Force",    RD),
        "cms":      ("CMS",      "CMS Fingerprinting",        CY),
        "sslscan":  ("SSLSCAN",  "SSL/TLS Deep Scanner",      G1),
        "phish":    ("PHISH",    "Phishing + Tunnel (red team)", RD),
        "cors":     ("CORS",     "CORS Misconfiguration Tester", OR),
        "lfi":      ("LFI",      "Local/Remote File Inclusion",  RD),
        "fuzz":     ("FUZZ",     "Parameter & Endpoint Fuzzer",  OR),
        "cve":      ("CVE",      "CVE Lookup & Version Matcher", CY),
        "harvest":  ("HARVEST",  "Email Harvester",              CY),
        "takeover": ("TAKEOVER", "Subdomain Takeover Checker",   OR),
        "bucket":   ("BUCKET",   "Cloud Bucket Finder",          CY),
        "spray":    ("SPRAY",    "Password Spraying",            RD),
        "graphql":    ("GRAPHQL",    "GraphQL Security Tester",        CY),
        "2fa":        ("2FA",        "2FA Bypass Tester",              OR),
        "smuggle":    ("SMUGGLE",    "HTTP Request Smuggling",         OR),
        "xxe":        ("XXE",        "XML External Entity Tester",     RD),
        "gitdump":    ("GITDUMP",    "Git & Sensitive File Scanner",   G1),
        "ssti":       ("SSTI",       "Template Injection Tester",      RD),
        "secretscan": ("SECRETSCAN", "Secret / Credential Scanner",    OR),
        "cache":      ("CACHE",      "Cache Poisoning Tester",         CY),
        "oauth":      ("OAUTH",      "OAuth 2.0 Misconfiguration",     OR),
        "deseria":    ("DESERIA",    "Deserialization Tester",         RD),
        "proto":      ("PROTO",      "Prototype Pollution Tester",     OR),
        "breach":     ("BREACH",     "Data Breach Checker",            CY),
        "shodan":     ("SHODAN",     "Shodan-Lite IP Recon (no key)",  G1),
    }
    name, desc, color = names.get(module.lower(), (module.upper(), "", G1))
    console.print(Rule(f"[bold {color}] {name} [/][{DM}] {desc} ", style=G2))

# ─── MAIN MENU ───────────────────────────────────────────────

# Format : (key, name, short_desc)
_MENU_RECON = [
    ("1",  "CLAW",      "ports"),
    ("2",  "PURR",      "HTTP recon"),
    ("3",  "SCRATCH",   "dir brute"),
    ("4",  "WHISKER",   "DNS/WHOIS"),
    ("6",  "CATNAP",    "subdomains"),
    ("9",  "GHOST",     "usernames"),
    ("10", "OSINT+",    "email/IP"),
    ("18", "WAF",       "WAF detect"),
    ("28", "CVE",       "CVE lookup"),
    ("29", "HARVEST",   "email harvest"),
    ("30", "TAKEOVER",  "subdomain tkover"),
    ("37", "GITDUMP",   "git exposure"),
    ("39", "SECRETSCAN","secrets scan"),
    ("44", "BREACH",    "breach check"),
    ("45", "SHODAN",    "IP recon"),
]
_MENU_EXPLOIT = [
    ("5",  "HISS",    "SQLi/XSS+"),
    ("25", "CORS",    "CORS misconfig"),
    ("26", "LFI",     "LFI/RFI"),
    ("27", "FUZZ",    "param fuzz"),
    ("35", "SMUGGLE", "HTTP smuggling"),
    ("36", "XXE",     "XXE inject"),
    ("38", "SSTI",    "template inject"),
    ("40", "CACHE",   "cache poison"),
    ("41", "OAUTH",   "OAuth misconfig"),
    ("42", "DESERIA", "deserializ"),
    ("43", "PROTO",   "proto pollut"),
]
_MENU_NET = [
    ("8",  "PROXYCAT","proxies"),
    ("15", "NETKIT",  "net tools"),
    ("16", "STRESS",  "stress/flood"),
    ("21", "BRUTE",   "HTTP brute"),
    ("22", "CMS",     "CMS detect"),
    ("23", "SSLSCAN", "SSL/TLS"),
    ("31", "BUCKET",  "cloud buckets"),
    ("32", "SPRAY",   "pwd spray"),
    ("33", "GRAPHQL", "GraphQL atk"),
    ("34", "2FA",     "2FA bypass"),
]
_MENU_UTILS = [
    ("11", "PAWS",    "passgen"),
    ("12", "MEWHASH", "hash/crack"),
    ("13", "CODEC",   "encode"),
    ("14", "PAYLOAD", "payloads"),
    ("17", "REVSHELL","rev shell"),
    ("19", "JWTCAT",  "JWT atk"),
    ("7",  "LOOT",    "results"),
    ("20", "REPORT",  "HTML report"),
    ("24", "PHISH",   "phish+tunnel"),
    ("0",  "EXIT",    "quit"),
]

# (col_color, ears, eyes, nose_mouth)
_CAT_DEFS = [
    (G1,  r"/\_/\ ", "( o.o )", " > w < "),   # RECON   — vert, yeux ouverts
    (RD,  r"/\_/\ ", "( >.< )", " > ~ < "),   # EXPLOIT — rouge, yeux plissés
    (OR,  r"/\_/\ ", "( ^.^ )", " > v < "),   # NET     — orange, souriant
    (CY,  r"/\_/\ ", "( o_o )", " > x < "),   # UTILS   — cyan, stoïque
]

def _fmt_row(key: str, name: str, desc: str, c_key=CY, c_name=None, c_desc=None) -> str:
    cn = c_name or G1
    cd = c_desc or DM
    return (f" [{c_key}][{key:>2}][/] "
            f"[bold {cn}]{name:<8}[/] "
            f"[{cd}]{desc}[/]")

def show_menu():
    cols   = [_MENU_RECON, _MENU_EXPLOIT, _MENU_NET, _MENU_UTILS]
    heads  = [" RECON ", "EXPLOIT", "NETWORK", " UTILS "]

    def build_col(items, head, cat_def):
        col_c, ears, eyes, nose = cat_def
        lines = [
            f"[{col_c}] {ears}[/]",
            f"[bold {col_c}]{eyes}[/]",
            f"[{col_c}] {nose}[/]",
            f"[bold {col_c}]─{head}─[/]",
            f"[{G2}]{'─'*20}[/]",
        ]
        for key, name, desc in items:
            lines.append(_fmt_row(key, name, desc,
                                  c_key=col_c, c_name=col_c))
        return lines

    col_lines = [build_col(c, h, d)
                 for c, h, d in zip(cols, heads, _CAT_DEFS)]

    max_rows = max(len(c) for c in col_lines)
    for cl in col_lines:
        while len(cl) < max_rows:
            cl.append("")

    t = Table(box=box.SIMPLE_HEAD, border_style=G2,
              show_header=False, show_edge=True,
              padding=(0, 0), expand=True)
    for _ in cols:
        t.add_column("", min_width=22, no_wrap=True)

    for i in range(max_rows):
        t.add_row(*[col_lines[ci][i] for ci in range(4)])

    console.print(Panel(
        t,
        title=f"[bold {G1}]◈  MEOW-SEC  v1.1  ::  45 modules  ◈",
        border_style=G2,
        padding=(0, 1),
    ))

# ─── PROGRESS BARS ───────────────────────────────────────────

def meow_progress(desc: str, total: int = 100):
    """Retourne un contexte Progress prêt à l'emploi"""
    return Progress(
        SpinnerColumn(style=G1),
        TextColumn(f"[{G1}]{{task.description}}"),
        BarColumn(bar_width=38, style=G2, complete_style=G1),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console
    )

def boot_progress(steps: list):
    """Barre multi-étapes pour le boot / scans lents"""
    with Progress(
        SpinnerColumn(style=G1),
        TextColumn(f"[{G1}]{{task.description:<40}}"),
        BarColumn(bar_width=30, style=G2, complete_style=G1),
        TextColumn(f"[{CY}]{{task.percentage:>3.0f}}%"),
        console=console
    ) as p:
        task = p.add_task("", total=len(steps))
        for step in steps:
            p.update(task, description=step)
            time.sleep(random.uniform(0.15, 0.45))
            p.advance(task)
        p.update(task, description=f"[{G1}]Done.")

# ─── INPUT HELPERS ───────────────────────────────────────────

def ask_target(prompt_label: str = "Target (URL / IP)") -> str:
    console.print()
    rule(f" {prompt_label} ", G2)
    val = Prompt.ask(f"  [{G1}]◈[/]").strip()
    console.print()
    return val

def ask_choice(prompt_label: str = "Choice", default: str = "0") -> str:
    console.print()
    return Prompt.ask(f"[{G1}]◈ {prompt_label}[/]", default=default).strip()

def wait_enter():
    console.print(f"\n  [{G2}][ Press ENTER to continue ][/]", end="")
    input()

# ─── RESULT TABLES ───────────────────────────────────────────

def result_table(title: str, columns: list, rows: list, color_col: int = -1) -> Table:
    """
    columns: list of str
    rows:    list of list/tuple
    color_col: colonne dont la couleur change selon la valeur (sévérité)
    """
    sev_colors = {
        "CRITICAL": "bold " + RD,
        "HIGH":     RD,
        "MEDIUM":   OR,
        "LOW":      CY,
        "INFO":     DM,
        "OPEN":     G1,
        "CLOSED":   DM,
        "FILTERED": OR,
        "FOUND":    G1,
    }

    t = Table(title=f"[{G1}]{title}[/]",
              box=box.MINIMAL_DOUBLE_HEAD,
              border_style=G2,
              header_style=CY,
              show_lines=False)

    for col in columns:
        t.add_column(col)

    for row in rows:
        row = list(row)
        if 0 <= color_col < len(row):
            val = str(row[color_col]).upper()
            c = sev_colors.get(val, WH)
            row[color_col] = f"[{c}]{row[color_col]}[/]"
        t.add_row(*[str(x) for x in row])

    return t

def print_result_table(title: str, columns: list, rows: list, color_col: int = -1):
    t = result_table(title, columns, rows, color_col)
    console.print(t)
    console.print(f"  [{G2}]Total: {len(rows)} result(s)[/]\n")
