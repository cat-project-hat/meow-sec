# -*- coding: utf-8 -*-
"""
MEOW-SEC :: core/tunnel.py — Tunnel manager centralisé
  Cloudflared (auto-dl, primaire) · serveo · localhost.run · bore.pub
"""
import os, sys, re, stat, threading, subprocess, time, socket
import urllib.request, urllib.error

from core.ui import console, ok, err, info, warn, G1, CY, OR, DM

# ─── CLOUDFLARED ──────────────────────────────────────────────────────────────

def _cf_path() -> str:
    tmp = os.environ.get("TEMP", os.environ.get("TMPDIR", "/tmp"))
    ext = ".exe" if sys.platform == "win32" else ""
    return os.path.join(tmp, f"meow_cloudflared{ext}")

def _cf_download() -> str | None:
    path = _cf_path()
    if os.path.exists(path):
        return path
    if sys.platform == "win32":
        url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
    elif sys.platform == "darwin":
        url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz"
    else:
        url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
    info("Téléchargement cloudflared (~20 MB, une seule fois)...")
    try:
        urllib.request.urlretrieve(url, path)
        if sys.platform != "win32":
            os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        ok("cloudflared téléchargé.")
        return path
    except Exception as e:
        warn(f"Échec téléchargement cloudflared: {e}")
        return None

def _start_cloudflared(port: int) -> tuple[subprocess.Popen | None, str]:
    cf = _cf_download()
    if not cf:
        return None, ""
    found   = threading.Event()
    url_box = [None]
    _RE     = re.compile(r"https://[a-zA-Z0-9\-]+\.trycloudflare\.com")
    try:
        proc = subprocess.Popen(
            [cf, "tunnel", "--url", f"http://localhost:{port}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
    except Exception as e:
        warn(f"cloudflared: {e}"); return None, ""

    def _read(s):
        for line in s:
            m = _RE.search(line)
            if m and not url_box[0]:
                url_box[0] = m.group(0); found.set()

    for s in (proc.stdout, proc.stderr):
        threading.Thread(target=_read, args=(s,), daemon=True).start()

    if found.wait(timeout=30):
        url = url_box[0]
        ok(f"cloudflared: URL reçue [{G1}]{url}[/]")
        # Attendre que le tunnel soit réellement joignable (DNS + handshake)
        info("Vérification tunnel (jusqu'à 15s)...")
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "meow-probe/1.0"})
                urllib.request.urlopen(req, timeout=4)
                ok(f"Tunnel actif ✓  [{G1}]{url}[/]")
                return proc, url
            except urllib.error.HTTPError:
                # HTTP 4xx/5xx = tunnel répond, DNS OK
                ok(f"Tunnel actif ✓  [{G1}]{url}[/]")
                return proc, url
            except Exception:
                time.sleep(1)
        warn("Tunnel établi mais pas encore joignable — essaie dans quelques secondes.")
        return proc, url   # On retourne quand même l'URL
    proc.kill()
    warn("cloudflared: URL introuvable dans la sortie."); return None, ""

# ─── SSH TUNNELS ──────────────────────────────────────────────────────────────

_SSH_TUNNELS = {
    "serveo":      ["ssh", "-o", "StrictHostKeyChecking=no",
                    "-o", "ServerAliveInterval=30", "-o", "ConnectTimeout=20",
                    "-R", "80:localhost:{port}", "serveo.net"],
    "localhostrun": ["ssh", "-o", "StrictHostKeyChecking=no",
                    "-o", "ServerAliveInterval=30", "-o", "ConnectTimeout=20",
                    "-R", "80:localhost:{port}", "nokey@localhost.run"],
}

def _start_ssh_tunnel(kind: str, port: int) -> tuple[subprocess.Popen | None, str]:
    tmpl = _SSH_TUNNELS.get(kind)
    if not tmpl:
        return None, ""
    cmd     = [c.replace("{port}", str(port)) for c in tmpl]
    _RE     = re.compile(r"https?://[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-\.]{3,}")
    found   = threading.Event()
    url_box = [None]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
    except FileNotFoundError:
        warn("ssh introuvable — installe OpenSSH."); return None, ""

    def _read(s):
        for line in s:
            m = _RE.search(line)
            if m and not url_box[0]:
                u = m.group(0).rstrip("/")
                if "." in u and len(u) > 12:
                    url_box[0] = u; found.set()

    for s in (proc.stdout, proc.stderr):
        threading.Thread(target=_read, args=(s,), daemon=True).start()

    if found.wait(timeout=25):
        url = url_box[0]
        ok(f"{kind}: URL reçue [{G1}]{url}[/]")
        info("Vérification tunnel (jusqu'à 12s)...")
        deadline = time.time() + 12
        while time.time() < deadline:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "meow-probe/1.0"})
                urllib.request.urlopen(req, timeout=4)
                ok(f"Tunnel actif ✓"); return proc, url
            except urllib.error.HTTPError:
                ok(f"Tunnel actif ✓"); return proc, url
            except Exception:
                time.sleep(1)
        warn("Tunnel URL obtenue mais vérification échouée — essaie quand même.")
        return proc, url
    proc.kill()
    warn(f"{kind}: URL introuvable."); return None, ""

# ─── BORE.PUB ─────────────────────────────────────────────────────────────────

def _start_bore(port: int) -> tuple[subprocess.Popen | None, str]:
    _RE   = re.compile(r"bore\.pub:\d+")
    found = threading.Event()
    url_b = [None]
    try:
        proc = subprocess.Popen(
            ["bore", "local", str(port), "--to", "bore.pub"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
    except FileNotFoundError:
        warn("bore introuvable — installe-le: https://github.com/ekzhang/bore"); return None, ""

    def _read(s):
        for line in s:
            m = _RE.search(line)
            if m and not url_b[0]:
                url_b[0] = "http://" + m.group(0); found.set()

    threading.Thread(target=_read, args=(proc.stdout,), daemon=True).start()
    if found.wait(timeout=20):
        ok(f"bore.pub: [{G1}]{url_b[0]}[/]")
        return proc, url_b[0]
    proc.kill()
    warn("bore.pub: URL introuvable."); return None, ""

# ─── INTERFACE UNIFIÉE ────────────────────────────────────────────────────────

TUNNEL_MENU = [
    ("cloudflared", "cloudflare.com   (auto-dl, HTTPS, le plus fiable)"),
    ("serveo",      "serveo.net       (SSH, sans install)"),
    ("localhostrun","localhost.run    (SSH, sans install)"),
    ("bore",        "bore.pub         (nécessite: cargo install bore-cli)"),
    ("none",        "Pas de tunnel    (LAN uniquement)"),
]

def print_tunnel_menu():
    """Affiche le menu tunnel numéroté."""
    for i, (_, label) in enumerate(TUNNEL_MENU, 1):
        console.print(f"  [{G1}][{i}][/] {label}")

def start_tunnel(choice: str, port: int) -> tuple[subprocess.Popen | None, str]:
    """
    choice = "1".."5" ou clé ("cloudflared","serveo",...,"none").
    Retourne (proc_ou_None, public_url_ou_"").
    """
    # Résoudre numéro → clé
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(TUNNEL_MENU):
            choice = TUNNEL_MENU[idx][0]

    if choice == "cloudflared":
        info("Démarrage cloudflared...")
        return _start_cloudflared(port)
    elif choice in ("serveo", "localhostrun"):
        info(f"Démarrage tunnel SSH {choice}...")
        return _start_ssh_tunnel(choice, port)
    elif choice == "bore":
        info("Démarrage bore.pub...")
        return _start_bore(port)
    else:
        return None, ""
