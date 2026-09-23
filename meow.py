#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MEOW-SEC v1.1 — Cat-Themed Security Toolkit
By cat-project-hat // 2026

For authorized penetration testing, CTF challenges and security research only.
Unauthorized use is illegal. Use only on systems you own or have explicit written permission to test.

45 modules: CLAW · PURR · SCRATCH · WHISKER · HISS · CATNAP · GHOST · OSINT+
            PROXYCAT · PAWS · MEWHASH · CODEC · PAYLOAD · NETKIT · STRESS · LOOT
            REVSHELL · WAF · JWTCAT · REPORT · BRUTE · CMS · SSLSCAN · PHISH
            CORS · LFI · FUZZ · CVE · HARVEST · TAKEOVER · BUCKET · SPRAY · GRAPHQL · 2FA
            SMUGGLE · XXE · GITDUMP · SSTI · SECRETSCAN · CACHE · OAUTH · DESERIA · PROTO
            BREACH · SHODAN
"""

import sys
import os
import time
import warnings

# Ajouter le répertoire courant au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ─── AUTO-INSTALL DEPENDENCIES ───────────────────────────────
def _ensure_deps():
    """Installe automatiquement les dépendances manquantes au démarrage."""
    import subprocess, importlib

    req_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    if not os.path.exists(req_file):
        return

    # Mapping package_name -> import_name
    pkg_map = {
        "rich":       "rich",
        "colorama":   "colorama",
        "requests":   "requests",
        "PySocks":    "socks",
        "curl_cffi":  "curl_cffi",
    }

    missing = []
    for pkg, imp in pkg_map.items():
        try:
            importlib.import_module(imp)
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"[MEOW-SEC] Installing missing packages: {', '.join(missing)}")
        for pkg in missing:
            for pip in [
                [sys.executable, "-m", "pip", "install", "--quiet", pkg],
            ]:
                try:
                    result = subprocess.run(pip, capture_output=True, text=True)
                    if result.returncode == 0:
                        print(f"  [OK] {pkg}")
                    else:
                        print(f"  [!!] {pkg} failed — run: pip install {pkg}")
                except Exception as e:
                    print(f"  [!!] {pkg} error: {e}")

_ensure_deps()

warnings.filterwarnings("ignore", message="Unverified HTTPS")
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

try:
    from rich.console import Console
    from rich.prompt import Prompt
    from rich.panel import Panel
    from rich.text import Text
    from rich.align import Align
    import colorama
    colorama.init()
except ImportError:
    print("Missing dependencies!\nRun: pip install rich colorama requests PySocks")
    sys.exit(1)

from core.ui import (
    console, show_banner, show_menu, ask_choice, wait_enter,
    ok, err, info, warn, clr, G1, G2, CY, OR, RD, DM
)
from core.cats import matrix_rain, glitch_line as glitch_text, CAT_IDLE, MEOW_LOGO, typewriter

# ─── BOOT ────────────────────────────────────────────────────

def boot():
    clr()
    console.print()

    BOOT_MSGS = [
        (f"[{G1}]BOOT[/]", "meow.sec kernel loaded — 45 modules active"),
        (f"[{OR}]WARN[/]", "authorized targets only"),
        (f"[bold {G1}]READY[/]", "MEOW-SEC v1.1 — 45 modules active"),
    ]
    for tag, msg in BOOT_MSGS:
        time.sleep(0.08)
        console.print(f"  [{G2}][[/]{tag}[{G2}]][/]  [{DM}]{msg}[/]")

    console.print()

# ─── MODULE ROUTER ───────────────────────────────────────────

def dispatch(choice: str):
    """Lance le module correspondant au choix"""
    choice = choice.strip()

    if choice == "1":
        from modules import claw
        claw.run()

    elif choice == "2":
        from modules import purr
        purr.run()

    elif choice == "3":
        from modules import scratch
        scratch.run()

    elif choice == "4":
        from modules import whisker
        whisker.run()

    elif choice == "5":
        from modules import hiss
        hiss.run()

    elif choice == "6":
        from modules import catnap
        catnap.run()

    elif choice == "7":
        from modules import loot
        loot.run()

    elif choice == "8":
        from modules import proxycat
        proxycat.run()

    elif choice == "9":
        from modules import ghost
        ghost.run()

    elif choice in ("10", "o", "osint"):
        from modules import osint_ext
        osint_ext.run()

    elif choice in ("11", "paws", "pass", "password"):
        from modules import paws
        paws.run()

    elif choice in ("12", "mewhash", "hash"):
        from modules import mewhash
        mewhash.run()

    elif choice in ("13", "codec", "encode", "decode"):
        from modules import codec
        codec.run()

    elif choice in ("14", "payload", "payloads"):
        from modules import payload
        payload.run()

    elif choice in ("15", "netkit", "net"):
        from modules import netkit
        netkit.run()

    elif choice in ("16", "stress", "flood"):
        from modules import stress
        stress.run()

    elif choice in ("17", "revshell", "shell"):
        from modules import revshell
        revshell.run()

    elif choice in ("18", "waf"):
        from modules import waf
        waf.run()

    elif choice in ("19", "jwt", "jwtcat"):
        from modules import jwtcat
        jwtcat.run()

    elif choice in ("20", "report"):
        from modules import report
        report.run()

    elif choice in ("21", "brute"):
        from modules import brute
        brute.run()

    elif choice in ("22", "cms"):
        from modules import cms
        cms.run()

    elif choice in ("23", "ssl", "sslscan"):
        from modules import sslscan
        sslscan.run()

    elif choice in ("24", "phish", "phishing"):
        from modules import phish
        phish.run()

    elif choice in ("25", "cors"):
        from modules import cors
        cors.run()

    elif choice in ("26", "lfi"):
        from modules import lfi
        lfi.run()

    elif choice in ("27", "fuzz"):
        from modules import fuzz
        fuzz.run()

    elif choice in ("28", "cve"):
        from modules import cve
        cve.run()

    elif choice in ("29", "harvest"):
        from modules import harvest
        harvest.run()

    elif choice in ("30", "takeover"):
        from modules import takeover
        takeover.run()

    elif choice in ("31", "bucket"):
        from modules import bucket
        bucket.run()

    elif choice in ("32", "spray"):
        from modules import spray
        spray.run()

    elif choice in ("33", "graphql"):
        from modules import graphql
        graphql.run()

    elif choice in ("34", "2fa", "twofa"):
        from modules import twofa
        twofa.run()

    elif choice in ("35", "smuggle"):
        from modules import smuggle; smuggle.run()

    elif choice in ("36", "xxe"):
        from modules import xxe; xxe.run()

    elif choice in ("37", "gitdump"):
        from modules import gitdump; gitdump.run()

    elif choice in ("38", "ssti"):
        from modules import ssti; ssti.run()

    elif choice in ("39", "secretscan", "secrets"):
        from modules import secretscan; secretscan.run()

    elif choice in ("40", "cache"):
        from modules import cache; cache.run()

    elif choice in ("41", "oauth"):
        from modules import oauth; oauth.run()

    elif choice in ("42", "deseria", "deserial"):
        from modules import deseria; deseria.run()

    elif choice in ("43", "proto"):
        from modules import proto; proto.run()

    elif choice in ("44", "breach"):
        from modules import breach; breach.run()

    elif choice in ("45", "shodan"):
        from modules import shodan_lite; shodan_lite.run()

    elif choice in ("0", "exit", "quit", "q"):
        return False

    else:
        warn(f"Unknown option: {choice}")
        time.sleep(0.5)

    return True

# ─── MAIN LOOP ───────────────────────────────────────────────

def main():
    # Gestion des arguments CLI
    args = sys.argv[1:]

    if args:
        module_map = {
            "claw":     "1",
            "purr":     "2",
            "scratch":  "3",
            "whisker":  "4",
            "hiss":     "5",
            "catnap":   "6",
            "loot":     "7",
            "proxycat": "8",
            "proxy":    "8",
            "ghost":    "9",
            "osint":    "10",
            "osint+":   "10",
            "paws":     "11",
            "pass":     "11",
            "hash":     "12",
            "mewhash":  "12",
            "codec":    "13",
            "encode":   "13",
            "payload":  "14",
            "payloads": "14",
            "netkit":   "15",
            "net":      "15",
            "stress":   "16",
            "flood":    "16",
            "revshell": "17",
            "shell":    "17",
            "waf":      "18",
            "jwt":      "19",
            "jwtcat":   "19",
            "report":   "20",
            "brute":    "21",
            "cms":      "22",
            "ssl":      "23",
            "sslscan":  "23",
            "phish":    "24",
            "phishing": "24",
            "cors":     "25",
            "lfi":      "26",
            "rfi":      "26",
            "fuzz":     "27",
            "cve":      "28",
            "harvest":  "29",
            "takeover": "30",
            "bucket":   "31",
            "spray":    "32",
            "graphql":  "33",
            "2fa":       "34",
            "twofa":     "34",
            "smuggle":   "35",
            "xxe":       "36",
            "gitdump":   "37",
            "ssti":      "38",
            "secretscan":"39",
            "secrets":   "39",
            "cache":     "40",
            "oauth":     "41",
            "deseria":   "42",
            "deserial":  "42",
            "proto":     "43",
            "breach":    "44",
            "shodan":    "45",
        }
        mod = args[0].lower()
        if mod in module_map:
            boot()
            dispatch(module_map[mod])
            return
        elif mod in ("--help", "-h", "help"):
            _print_help()
            return

    boot()

    while True:
        show_banner()
        show_menu()

        choice = ask_choice("SELECT MODULE").lower()

        if choice in ("0", "exit", "quit", "q"):
            break

        running = dispatch(choice)
        if not running:
            break

        wait_enter()

    # Exit screen
    clr()
    console.print()
    console.print(Panel(
        Align(Text(r"""
  /\_/\
 ( -.- ) ... disconnecting
  >   <
 |||||||| meow.
""", style=OR), align="center"),
        title=f"[{G1}]◈  MEOW-SEC  ::  SESSION CLOSED  ◈",
        border_style=G2
    ))
    console.print(f"\n  [{G2}]Stay in the shadows. Stay curious. 🐱[/]\n")

# ─── HELP ────────────────────────────────────────────────────

def _print_help():
    console.print(f"""
[bold {G1}]MEOW-SEC[/]  v1.1  —  Cat-Themed Security Toolkit
[{DM}]by cat-project-hat // 2026[/]

[{CY}]Usage:[/]
  python meow.py                  Interactive menu
  python meow.py <module>         Launch module directly

[{CY}]Modules:[/]
  claw      Port scanner              purr      HTTP recon
  scratch   Dir brute force           whisker   DNS/WHOIS/OSINT
  hiss      SQLi/XSS/SSRF/CRLF        catnap    Subdomain enum
  ghost     Username OSINT            osint     Email/IP/dorks
  proxycat  Proxy manager             paws      Password gen
  hash      Hash crack/tools          codec     Encode/decode
  payload   Payload library           netkit    Net utilities
  stress    Stress tester (L3/L4/L7)  revshell  Rev shell gen
  waf       WAF fingerprint           jwt       JWT attacker
  brute     HTTP brute force          cms       CMS detect
  ssl       SSL/TLS scanner           phish     Phishing tunnel
  report    HTML report               loot      View results
  cors      CORS misconfig tester     lfi       LFI/RFI tester
  fuzz      Parameter fuzzer          cve       CVE lookup
  harvest   Email harvester           takeover  Subdomain takeover
  bucket    Cloud bucket finder       spray     Password spraying
  graphql   GraphQL tester            2fa       2FA bypass
  smuggle   HTTP smuggling            xxe       XXE inject
  gitdump   Git exposure              ssti      Template inject
  secretscan Secrets scanner          cache     Cache poisoning
  oauth     OAuth misconfig           deseria   Deserialization
  proto     Proto pollution           breach    Breach check
  shodan    IP recon (no key)

[{G1}]Proxy:[/]
  Run PROXYCAT first to download & validate proxies.
  All HTTP modules auto-rotate proxies from the pool.

[{OR}]Legal:[/]
  Authorized targets only. Unauthorized use is illegal.
""")

# ─── ENTRY POINT ─────────────────────────────────────────────

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(f"\n\n  [{OR}]Interrupted. Exiting... 🐱[/]\n")
        sys.exit(0)
