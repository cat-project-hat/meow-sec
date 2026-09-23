# -*- coding: utf-8 -*-
"""MEOW-SEC :: GITDUMP — Exposed Git Repository & Sensitive File Scanner"""
import os, re, json
from datetime import datetime
from urllib.parse import urlparse, urljoin

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN
from rich.panel  import Panel
from rich.table  import Table
from rich.prompt import Prompt, Confirm
from rich.rule   import Rule
from rich        import box

try:
    import requests as _req
    _req.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False


def _save(name, target, results):
    os.makedirs("data", exist_ok=True)
    fname = f"data/{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "results": results,
                   "timestamp": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved: [bold]{fname}[/]")


_SENSITIVE_PATHS = [
    # Git internals
    ("/.git/HEAD",              "HIGH",   "git"),
    ("/.git/config",            "HIGH",   "git"),
    ("/.git/COMMIT_EDITMSG",    "HIGH",   "git"),
    ("/.git/description",       "MEDIUM", "git"),
    ("/.git/info/refs",         "HIGH",   "git"),
    ("/.git/logs/HEAD",         "HIGH",   "git"),
    ("/.git/refs/heads/main",   "MEDIUM", "git"),
    ("/.git/refs/heads/master", "MEDIUM", "git"),
    ("/.git/packed-refs",       "MEDIUM", "git"),
    ("/.git/index",             "HIGH",   "git"),
    # Env files
    ("/.env",                   "HIGH",   "env"),
    ("/.env.local",             "HIGH",   "env"),
    ("/.env.production",        "HIGH",   "env"),
    ("/.env.development",       "HIGH",   "env"),
    ("/.env.staging",           "HIGH",   "env"),
    # Config files
    ("/config.php",             "HIGH",   "config"),
    ("/database.yml",           "HIGH",   "config"),
    ("/wp-config.php",          "HIGH",   "config"),
    ("/config/database.yml",    "HIGH",   "config"),
    ("/application.yml",        "HIGH",   "config"),
    ("/settings.py",            "HIGH",   "config"),
    ("/local_settings.py",      "HIGH",   "config"),
    ("/web.config",             "MEDIUM", "config"),
    ("/composer.json",          "LOW",    "config"),
    ("/package.json",           "LOW",    "config"),
    ("/Dockerfile",             "LOW",    "config"),
    ("/docker-compose.yml",     "MEDIUM", "config"),
    # Credentials & keys
    ("/.htpasswd",              "HIGH",   "creds"),
    ("/id_rsa",                 "HIGH",   "creds"),
    ("/private.key",            "HIGH",   "creds"),
    ("/server.key",             "HIGH",   "creds"),
    ("/secrets.yml",            "HIGH",   "creds"),
    ("/credentials.json",       "HIGH",   "creds"),
    ("/terraform.tfvars",       "HIGH",   "creds"),
    ("/.aws/credentials",       "HIGH",   "creds"),
    # Backups & dumps
    ("/backup.zip",             "HIGH",   "backup"),
    ("/backup.sql",             "HIGH",   "backup"),
    ("/dump.sql",               "HIGH",   "backup"),
    ("/db.sql",                 "HIGH",   "backup"),
    ("/database.sql",           "HIGH",   "backup"),
    # Misc
    ("/.DS_Store",              "MEDIUM", "misc"),
    ("/robots.txt",             "LOW",    "misc"),
    ("/sitemap.xml",            "LOW",    "misc"),
    ("/crossdomain.xml",        "LOW",    "misc"),
    ("/phpinfo.php",            "HIGH",   "misc"),
    ("/info.php",               "HIGH",   "misc"),
    ("/test.php",               "MEDIUM", "misc"),
    ("/admin/config.php",       "HIGH",   "misc"),
    ("/swagger.json",           "LOW",    "misc"),
    ("/openapi.json",           "LOW",    "misc"),
]

_GIT_EXTRA = [
    "/.git/HEAD",
    "/.git/config",
    "/.git/COMMIT_EDITMSG",
    "/.git/description",
    "/.git/info/refs",
    "/.git/logs/HEAD",
]


def _fetch(base_url, path, timeout=8):
    url = base_url.rstrip("/") + path
    try:
        r = _req.get(url, verify=False, allow_redirects=False,
                     timeout=timeout,
                     headers={"User-Agent": "MEOW-GITDUMP/1.1"})
        return r.status_code, r.text[:2048], len(r.content)
    except Exception as e:
        return 0, str(e)[:80], 0


def _parse_git_config_remotes(text):
    """Extract remote URLs from .git/config text."""
    remotes = re.findall(r"url\s*=\s*(.+)", text)
    return [r.strip() for r in remotes]


def run():
    show_module_banner("gitdump")
    cat_talk(CAT_SCAN, "Git exposure & sensitive file scanner — 50+ paths", G1)
    console.print()
    warn("AUTHORIZED USE ONLY — Unauthorized testing is illegal.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    if not HAS_REQUESTS:
        err("requests library not available. Install it: pip install requests"); return

    url = Prompt.ask(f"  [{G1}]◈ Target base URL[/]").strip()
    if not url.startswith("http"):
        url = "https://" + url
    url = url.rstrip("/")

    info(f"Scanning: {url}")
    console.print()

    found = []
    git_head_found = False

    # Phase 1: sensitive file scan
    info(f"[Phase 1] Scanning {len(_SENSITIVE_PATHS)} sensitive paths...")
    for path, risk, category in _SENSITIVE_PATHS:
        status, body, size = _fetch(url, path)
        if status in (200, 206):
            preview = body[:80].replace("\n", " ").strip()
            found.append({
                "path": path, "status": status, "risk": risk,
                "category": category, "preview": preview, "size": size
            })
            sev_color = RD if risk == "HIGH" else OR if risk == "MEDIUM" else CY
            find(f"[{sev_color}][{risk}][/] {path}  ({size}B)")
            if path == "/.git/HEAD":
                git_head_found = True

    # Phase 2: git dump if .git/HEAD found
    if git_head_found:
        info("[Phase 2] .git/HEAD found — downloading git internals...")
        git_config_text = ""
        for gpath in _GIT_EXTRA:
            status, body, size = _fetch(url, gpath)
            if status == 200:
                preview = body[:80].replace("\n", " ").strip()
                if gpath == "/.git/config":
                    git_config_text = body
                    remotes = _parse_git_config_remotes(body)
                    if remotes:
                        for r in remotes:
                            find(f"Remote URL leaked: [{CY}]{r}[/]")
                if gpath not in [f["path"] for f in found]:
                    found.append({
                        "path": gpath, "status": status, "risk": "HIGH",
                        "category": "git", "preview": preview, "size": size
                    })
    else:
        info(".git/HEAD not accessible — skipping git internals phase.")

    console.print()
    if not found:
        ok("No sensitive files found (or all returned 403/404).")
    else:
        t = Table(title=f"[{G1}]Found Files ({len(found)})[/]",
                  box=box.MINIMAL_DOUBLE_HEAD, border_style=G2, header_style=CY)
        t.add_column("Path",     min_width=30)
        t.add_column("Status",   min_width=7)
        t.add_column("Risk",     min_width=8)
        t.add_column("Size",     min_width=7)
        t.add_column("Preview",  min_width=40)

        risk_colors = {"HIGH": RD, "MEDIUM": OR, "LOW": CY}
        for f in found:
            rc = risk_colors.get(f["risk"], DM)
            t.add_row(f["path"], str(f["status"]),
                      f"[{rc}]{f['risk']}[/]",
                      str(f["size"]) + "B",
                      f["preview"][:60])
        console.print(t)

        highs = sum(1 for f in found if f["risk"] == "HIGH")
        find(f"{len(found)} file(s) found — {highs} HIGH risk")

    _save("gitdump", url, found)
