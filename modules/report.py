# -*- coding: utf-8 -*-
"""
MEOW-SEC :: REPORT — HTML Report Generator
  · Agrège tous les JSON de data/
  · Génère un rapport HTML autonome (inline CSS/JS)
  · Timeline, ports ouverts, vulns, OSINT, stress
"""
import os, json, glob
from datetime import datetime

from core.ui import (console, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich.align   import Align
from rich.prompt  import Prompt, Confirm
from rich         import box
from rich.rule    import Rule

# ─── SCAN READER ─────────────────────────────────────────────

def _load_scans(data_dir: str = "data") -> list:
    scans = []
    for fpath in sorted(glob.glob(os.path.join(data_dir, "*.json"))):
        try:
            with open(fpath, encoding="utf-8") as f:
                d = json.load(f)
            d["_file"]  = os.path.basename(fpath)
            d["_mtime"] = os.path.getmtime(fpath)
            scans.append(d)
        except Exception:
            pass
    return scans

def _classify(scan: dict) -> str:
    fname = scan.get("_file","").lower()
    if "claw"    in fname or "ports"  in fname: return "portscan"
    if "purr"    in fname: return "webrecon"
    if "scratch" in fname: return "dirbust"
    if "whisker" in fname or "dns" in fname: return "dns"
    if "hiss"    in fname: return "vulntest"
    if "catnap"  in fname: return "subdomains"
    if "ghost"   in fname: return "username"
    if "osint"   in fname: return "osint"
    if "stress"  in fname: return "stress"
    if "waf"     in fname: return "waf"
    if "jwt"     in fname: return "jwt"
    if "revshell" in fname: return "revshell"
    if "passwords" in fname: return "passwords"
    return "misc"

# ─── HTML TEMPLATE ───────────────────────────────────────────

HTML_CSS = """
:root{--bg:#0a0f0a;--bg2:#111811;--bg3:#1a221a;
  --g1:#00ff41;--g2:#00c030;--cy:#00e5ff;--or:#ff8c00;
  --rd:#ff3333;--dm:#666;--wh:#e8ffe8;--bd:#1e2e1e}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--wh);font-family:'Courier New',monospace;font-size:13px;line-height:1.6}
a{color:var(--cy);text-decoration:none}a:hover{text-decoration:underline}
.header{background:linear-gradient(180deg,#0d1f0d,var(--bg));
  border-bottom:2px solid var(--g2);padding:32px 40px;text-align:center}
.logo{color:var(--g1);font-size:28px;font-weight:bold;letter-spacing:4px;text-shadow:0 0 20px var(--g1)}
.subtitle{color:var(--g2);margin-top:6px;font-size:13px}
.meta-bar{display:flex;gap:24px;justify-content:center;margin-top:16px;flex-wrap:wrap}
.meta-item{background:var(--bg3);border:1px solid var(--bd);padding:6px 16px;border-radius:4px;font-size:12px}
.meta-item span{color:var(--cy)}
.container{max-width:1200px;margin:0 auto;padding:32px 24px}
.section{background:var(--bg2);border:1px solid var(--bd);border-radius:6px;margin:24px 0;overflow:hidden}
.section-title{background:var(--bg3);padding:12px 20px;color:var(--g1);font-size:14px;
  font-weight:bold;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px;cursor:pointer}
.section-body{padding:20px}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold}
.badge-g{background:#0d2b0d;color:var(--g1);border:1px solid var(--g2)}
.badge-o{background:#2b1a00;color:var(--or);border:1px solid var(--or)}
.badge-r{background:#2b0000;color:var(--rd);border:1px solid var(--rd)}
.badge-c{background:#00232b;color:var(--cy);border:1px solid var(--cy)}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:8px 12px;background:var(--bg3);color:var(--cy);border-bottom:2px solid var(--bd)}
td{padding:7px 12px;border-bottom:1px solid var(--bd);color:var(--wh)}
tr:hover td{background:#151f15}
.open{color:var(--g1);font-weight:bold}
.closed{color:var(--dm)}
.filtered{color:var(--or)}
.found{color:var(--g1);font-weight:bold}
.high{color:var(--rd)}
.medium{color:var(--or)}
.low{color:var(--cy)}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.stat-card{background:var(--bg3);border:1px solid var(--bd);border-radius:4px;padding:14px;text-align:center}
.stat-val{font-size:24px;font-weight:bold;color:var(--g1)}
.stat-lbl{font-size:11px;color:var(--dm);margin-top:4px}
.timeline{list-style:none}
.timeline li{padding:8px 0 8px 24px;border-left:2px solid var(--g2);position:relative;margin-left:8px}
.timeline li::before{content:'◈';position:absolute;left:-10px;color:var(--g1);background:var(--bg2)}
.tl-time{color:var(--dm);font-size:11px}
.tl-file{color:var(--cy)}
.tl-type{color:var(--or);margin-left:8px}
.tag{background:var(--bg3);color:var(--g2);padding:2px 6px;border-radius:2px;font-size:11px;margin:2px}
pre{background:var(--bg3);border:1px solid var(--bd);padding:12px;border-radius:4px;overflow-x:auto;color:var(--g1);font-size:11px}
.footer{text-align:center;padding:24px;color:var(--dm);border-top:1px solid var(--bd);margin-top:32px}
.toggle{float:right;color:var(--dm);font-size:12px}
"""

HTML_JS = """
document.querySelectorAll('.section-title').forEach(t=>{
  t.addEventListener('click',()=>{
    const b=t.nextElementSibling;
    b.style.display=b.style.display==='none'?'block':'none';
    t.querySelector('.toggle').textContent=b.style.display==='none'?'[+]':'[-]';
  });
});
"""

def _badge(val: str) -> str:
    v = str(val).upper()
    if v in ("OPEN","FOUND","ALIVE","SUCCESS"): return f'<span class="badge badge-g">{val}</span>'
    if v in ("HIGH","CRITICAL"):                return f'<span class="badge badge-r">{val}</span>'
    if v in ("MEDIUM","WARNING"):               return f'<span class="badge badge-o">{val}</span>'
    if v in ("LOW","INFO","CLOSED"):            return f'<span class="badge badge-c">{val}</span>'
    return f'<span class="tag">{val}</span>'

def _th(*cols) -> str:
    return "<tr>" + "".join(f"<th>{c}</th>" for c in cols) + "</tr>"

def _td(*vals) -> str:
    def _v(v):
        s = str(v)
        for kw in ("open","found","alive"):
            if kw in s.lower(): return f'<td class="open">{s}</td>'
        for kw in ("closed","filtered"):
            if kw in s.lower(): return f'<td class="closed">{s}</td>'
        return f"<td>{s}</td>"
    return "<tr>" + "".join(_v(v) for v in vals) + "</tr>"

def _section(title: str, icon: str, body: str, collapsed: bool = False) -> str:
    disp = "none" if collapsed else "block"
    tog  = "[+]" if collapsed else "[-]"
    return f"""<div class="section">
  <div class="section-title">{icon} {title}<span class="toggle">{tog}</span></div>
  <div class="section-body" style="display:{disp}">{body}</div>
</div>"""

# ─── SECTION RENDERERS ───────────────────────────────────────

def _render_summary(scans: list, target_hint: str) -> str:
    types    = [_classify(s) for s in scans]
    open_ports = sum(1 for s in scans if "ports" in s and
                     any(p.get("state","") == "open" for p in (s.get("ports") or [])))
    html = f"""<div class="stat-grid">
  <div class="stat-card"><div class="stat-val">{len(scans)}</div><div class="stat-lbl">Scan files</div></div>
  <div class="stat-card"><div class="stat-val">{len(set(types))}</div><div class="stat-lbl">Scan types</div></div>
  <div class="stat-card"><div class="stat-val" style="color:var(--cy)">{target_hint or '?'}</div><div class="stat-lbl">Primary target</div></div>
</div><br>
<p style="color:var(--dm)">Scan types: {', '.join(f'<span class="tag">{t}</span>' for t in set(types))}</p>"""
    return html

def _render_timeline(scans: list) -> str:
    sorted_scans = sorted(scans, key=lambda s: s.get("_mtime",0))
    html = '<ul class="timeline">'
    for s in sorted_scans:
        ts   = datetime.fromtimestamp(s["_mtime"]).strftime("%Y-%m-%d %H:%M")
        kind = _classify(s)
        tgt  = (s.get("target") or s.get("host") or s.get("domain") or "")[:50]
        html += (f'<li><span class="tl-time">{ts}</span> '
                 f'<span class="tl-file">{s["_file"]}</span>'
                 f'<span class="tl-type">[{kind}]</span> {tgt}</li>')
    return html + "</ul>"

def _render_ports(scans: list) -> str:
    rows = ""
    for s in scans:
        if "ports" not in s and _classify(s) != "portscan":
            continue
        host  = s.get("host","?")
        ports = s.get("ports", [])
        if not ports: continue
        for p in ports:
            port    = p.get("port","?")
            state   = p.get("state","?")
            service = p.get("service","")
            banner  = (p.get("banner") or "")[:60]
            cls     = "open" if state == "open" else "closed"
            rows += f"<tr><td>{host}</td><td><b>{port}</b></td><td class='{cls}'>{state}</td><td>{service}</td><td>{banner}</td></tr>"
    if not rows:
        return "<p style='color:var(--dm)'>No port scan results found.</p>"
    return f"<table>{_th('Host','Port','State','Service','Banner')}{rows}</table>"

def _render_web(scans: list) -> str:
    rows = ""
    for s in scans:
        if _classify(s) not in ("webrecon","dirbust","vulntest"):
            continue
        target = s.get("target","?")
        headers = s.get("headers", {})
        for hdr, data in headers.items():
            if isinstance(data, dict):
                sev = data.get("severity","INFO")
                val = data.get("value","?")[:60]
                rows += f"<tr><td>{target}</td><td>{hdr}</td><td class='{sev.lower()}'>{sev}</td><td>{val}</td></tr>"
        paths = s.get("found_paths", [])
        for p in paths[:20]:
            url  = p.get("url","")[:80]
            code = p.get("status","")
            rows += f"<tr><td>{target}</td><td>{url}</td><td class='found'>{code}</td><td>dir/file</td></tr>"
    if not rows:
        return "<p style='color:var(--dm)'>No web recon results found.</p>"
    return f"<table>{_th('Target','Item','Severity/Code','Value')}{rows}</table>"

def _render_dns(scans: list) -> str:
    rows = ""
    for s in scans:
        if _classify(s) not in ("dns","subdomains"):
            continue
        domain = s.get("domain","?")
        for rtype in ("A","AAAA","MX","NS","TXT","CNAME"):
            for val in s.get(rtype, []):
                rows += f"<tr><td>{domain}</td><td class='badge badge-c'>{rtype}</td><td>{str(val)[:80]}</td></tr>"
        for sub in s.get("found", []):
            fqdn = sub.get("fqdn","?")
            ips  = ", ".join(sub.get("ips",[]))
            rows += f"<tr><td>{fqdn}</td><td class='badge badge-g'>SUB</td><td>{ips}</td></tr>"
    if not rows:
        return "<p style='color:var(--dm)'>No DNS results found.</p>"
    return f"<table>{_th('Domain','Type','Value')}{rows}</table>"

def _render_stress(scans: list) -> str:
    rows = ""
    for s in scans:
        if _classify(s) != "stress": continue
        rows += (f"<tr><td>{s.get('target','?')}</td>"
                 f"<td class='badge badge-r'>{s.get('method','?')}</td>"
                 f"<td class='open'>{s.get('rps',0):.1f}</td>"
                 f"<td>{s.get('total',0):,}</td>"
                 f"<td>{s.get('success',0):,}</td>"
                 f"<td>{s.get('avg_latency_ms',0):.1f} ms</td>"
                 f"<td>{s.get('duration_s',0)}s</td></tr>")
    if not rows:
        return "<p style='color:var(--dm)'>No stress test results found.</p>"
    return f"<table>{_th('Target','Method','RPS','Total','Success','Avg Latency','Duration')}{rows}</table>"

def _render_waf(scans: list) -> str:
    rows = ""
    for s in scans:
        if _classify(s) != "waf": continue
        target = s.get("target","?")
        for name, data in (s.get("waf") or {}).items():
            conf  = min(data.get("score",0), 100)
            rows += (f"<tr><td>{target}</td>"
                     f"<td><b>{name}</b></td>"
                     f"<td class='{'open' if conf>=60 else 'medium'}'>{conf}%</td>"
                     f"<td>{', '.join(data.get('matched',[])[:3])}</td></tr>")
    if not rows:
        return "<p style='color:var(--dm)'>No WAF detection results found.</p>"
    return f"<table>{_th('Target','WAF/CDN','Confidence','Evidence')}{rows}</table>"

def _render_osint(scans: list) -> str:
    rows = ""
    for s in scans:
        if _classify(s) not in ("username","osint"): continue
        for item in (s.get("found_on") or [])[:30]:
            platform = item.get("platform","?")
            url      = item.get("url","")
            rows += f"<tr><td>{s.get('username',s.get('target','?'))}</td><td>{platform}</td><td><a href='{url}' target='_blank'>{url[:60]}</a></td></tr>"
    if not rows:
        return "<p style='color:var(--dm)'>No OSINT results found.</p>"
    return f"<table>{_th('Subject','Platform','URL')}{rows}</table>"

# ─── MAIN GENERATE ───────────────────────────────────────────

def generate_report(data_dir: str = "data", target: str = "unknown") -> str:
    scans = _load_scans(data_dir)
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Guess primary target from scans
    for s in scans:
        t = s.get("target") or s.get("host") or s.get("domain")
        if t and target == "unknown":
            target = t; break

    body = ""
    body += _section("Executive Summary",         "◈", _render_summary(scans, target))
    body += _section("Scan Timeline",             "⏱", _render_timeline(scans))
    body += _section("Port Scan Results",         "▸", _render_ports(scans))
    body += _section("Web Recon & Dir Bust",      "▸", _render_web(scans))
    body += _section("DNS & Subdomain Enum",      "▸", _render_dns(scans))
    body += _section("WAF / CDN Detection",       "▸", _render_waf(scans))
    body += _section("OSINT / Username Results",  "▸", _render_osint(scans))
    body += _section("Stress Test Results",       "▸", _render_stress(scans), collapsed=True)

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MEOW-SEC Report :: {target}</title>
<style>{HTML_CSS}</style></head>
<body>
<div class="header">
  <div class="logo">◈  MEOW-SEC  ::  PENTEST REPORT  ◈</div>
  <div class="subtitle">Cat-Themed Security Toolkit — Automated Report</div>
  <div class="meta-bar">
    <div class="meta-item">Target: <span>{target}</span></div>
    <div class="meta-item">Generated: <span>{now}</span></div>
    <div class="meta-item">Files: <span>{len(scans)}</span></div>
    <div class="meta-item" style="color:var(--or)">⚠ Authorized use only</div>
  </div>
</div>
<div class="container">{body}</div>
<div class="footer">
  Generated by MEOW-SEC v1.1 — Cat Hacker Toolkit<br>
  <span style="color:var(--rd)">For authorized penetration testing and CTF challenges only.</span>
</div>
<script>{HTML_JS}</script></body></html>"""
    return html

# ─── MAIN ────────────────────────────────────────────────────

def run():
    show_module_banner("report")
    cat_talk(CAT_SCAN, "Report generator loaded.", OR)
    console.print()

    data_dir = "data"
    if not os.path.isdir(data_dir):
        err("No data/ directory found. Run some scans first."); return

    scans = _load_scans(data_dir)
    if not scans:
        warn("No scan JSON files found in data/"); return

    info(f"Found [{G1}]{len(scans)}[/] scan files in [{CY}]{data_dir}/[/]")

    # Preview
    t = Table(box=box.SIMPLE, header_style=CY, border_style=G2, show_edge=False)
    t.add_column("File",   style=CY, width=40)
    t.add_column("Type",   style=OR, width=14)
    t.add_column("Target", style=G1)
    for s in sorted(scans, key=lambda x: x["_mtime"], reverse=True)[:15]:
        tgt = (s.get("target") or s.get("host") or s.get("domain") or "")[:40]
        t.add_row(s["_file"], _classify(s), tgt)
    console.print(t)
    console.print()

    target = Prompt.ask(f"  [{G1}]◈ Primary target name (for report header)[/]",
                        default="unknown").strip()

    html = generate_report(data_dir, target)

    fname = f"data/report_{target.replace(' ','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(fname, "w", encoding="utf-8") as f:
        f.write(html)

    find(f"Report saved: [{CY}]{fname}[/]")
    ok(f"Open in browser: [{G1}]start {fname}[/]")

    try:
        import subprocess
        if Confirm.ask(f"  [{OR}]◈ Open in browser now?[/]", default=True):
            subprocess.Popen(["start", fname], shell=True)
    except Exception:
        pass

def _banner():
    logo = Text(r"""
 ██████╗ ███████╗██████╗  ██████╗ ██████╗ ████████╗
 ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
 ██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝   ██║
 ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║
 ██║  ██║███████╗██║      ╚██████╔╝██║  ██║   ██║
 ╚═╝  ╚═╝╚══════╝╚═╝       ╚═════╝ ╚═╝  ╚═╝   ╚═╝
     [HTML REPORT GENERATOR — ALL SCANS AGGREGATED]""",
        style=f"bold {G2}")
    console.print(Panel(Align(logo, align="center"), border_style=G2, padding=(0,1)))
