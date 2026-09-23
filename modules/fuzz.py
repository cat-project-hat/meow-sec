# -*- coding: utf-8 -*-
"""
MEOW-SEC :: FUZZ — Parameter & Endpoint Fuzzer
For authorized security testing and CTF challenges only.
"""
import os, json, time, concurrent.futures, threading
from datetime import datetime
from urllib.parse import urlparse, urljoin, urlencode

from core.ui import (console, ok, err, info, warn, find, boot_progress,
                     print_result_table, show_module_banner, ask_target,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn, TimeElapsedColumn

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

# ─── WORDLISTS ────────────────────────────────────────────────
COMMON_PARAMS = [
    "id","user","username","email","pass","password","token","key","api_key",
    "page","limit","offset","sort","order","filter","q","query","search","s",
    "file","path","dir","url","redirect","next","return","ref","callback",
    "action","type","mode","format","lang","locale","theme","debug",
    "admin","role","level","group","org","company","name","first_name","last_name",
    "phone","address","zip","country","city","state","lat","lon","gps",
    "date","from","to","start","end","created","updated","timestamp",
    "code","hash","sig","sign","signature","nonce","csrf","_token",
    "session","auth","jwt","bearer","access","refresh",
    "cat","category","tag","label","section","chapter","post","article",
    "product","item","order_id","invoice","payment","amount","price",
]

COMMON_PATHS = [
    "admin","api","api/v1","api/v2","api/v3","graphql","swagger",
    "robots.txt",".env","config","config.php","config.json","settings",
    "login","logout","register","signup","signin","auth","oauth",
    "users","user","profile","account","me","whoami","info","status",
    "dashboard","panel","console","manage","management","cms",
    "backup","dump","export","import","upload","uploads","files",
    "debug","test","dev","staging","beta","old","archive",
    "wp-admin","wp-login.php","wp-config.php",
    "phpinfo.php","phpmyadmin","adminer",
    ".git/config",".htaccess",".htpasswd",
    "server-status","server-info",
    "actuator","actuator/env","actuator/beans","actuator/mappings",
    "metrics","health","ping","version","info","build",
]

FUZZ_VALUES = [
    "1","0","-1","999999","true","false","null","undefined",
    "''","\"\"","../","../../etc/passwd",
    "<script>alert(1)</script>",
    "' OR 1=1--","1 UNION SELECT 1,2,3--",
    "${7777*7777}","{{7*7}}","#{7*7}",
    "AAAA"*100,
]

_STOP = threading.Event()

def _req(url: str, method: str = "GET", params: dict = None, data: dict = None, timeout: int = 6):
    try:
        h = {"User-Agent": "MEOW-FUZZ/1.1 (authorized-test)"}
        if method == "GET":
            return requests.get(url, params=params, headers=h,
                                timeout=timeout, verify=False,
                                proxies=_px(), allow_redirects=False)
        else:
            return requests.post(url, data=data, headers=h,
                                 timeout=timeout, verify=False,
                                 proxies=_px(), allow_redirects=False)
    except Exception:
        return None

# ─── MODE 1: Parameter Discovery ──────────────────────────────
def _fuzz_params(base_url: str, baseline_len: int, workers: int = 30) -> list:
    findings = []
    lock = threading.Lock()

    def check(param):
        if _STOP.is_set():
            return None
        r = _req(base_url, params={param: "1"})
        if not r:
            return None
        diff = abs(len(r.text) - baseline_len)
        if r.status_code not in (404, 400) and diff > 20:
            return {"param": param, "status": r.status_code,
                    "length": len(r.text), "diff": diff}
        return None

    total = len(COMMON_PARAMS)
    with Progress(SpinnerColumn(style=G1), TextColumn(f"[{G1}]Fuzzing params"),
                  BarColumn(bar_width=36, style=G2, complete_style=G1),
                  MofNCompleteColumn(), TimeElapsedColumn(), console=console) as p:
        task = p.add_task("", total=total)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(check, param): param for param in COMMON_PARAMS}
            for fut in concurrent.futures.as_completed(futures):
                p.advance(task)
                res = fut.result()
                if res:
                    with lock:
                        findings.append(res)
                        find(f"Param [{CY}]{res['param']}[/]  status=[{G1}]{res['status']}[/]  len={res['length']}  diff={res['diff']}")
    return findings

# ─── MODE 2: Path Discovery ────────────────────────────────────
def _fuzz_paths(base_url: str, workers: int = 30) -> list:
    if base_url.endswith("/"):
        base_url = base_url.rstrip("/")
    findings = []
    lock = threading.Lock()

    def check(path):
        if _STOP.is_set():
            return None
        r = _req(f"{base_url}/{path}")
        if not r:
            return None
        if r.status_code not in (404,):
            return {"path": path, "status": r.status_code, "length": len(r.text)}
        return None

    total = len(COMMON_PATHS)
    with Progress(SpinnerColumn(style=G1), TextColumn(f"[{G1}]Fuzzing paths"),
                  BarColumn(bar_width=36, style=G2, complete_style=G1),
                  MofNCompleteColumn(), TimeElapsedColumn(), console=console) as p:
        task = p.add_task("", total=total)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(check, path): path for path in COMMON_PATHS}
            for fut in concurrent.futures.as_completed(futures):
                p.advance(task)
                res = fut.result()
                if res:
                    with lock:
                        findings.append(res)
                        color = G1 if res["status"] == 200 else OR if res["status"] in (301,302,403) else CY
                        find(f"[{color}]{res['status']}[/]  /{res['path']:<40}  len={res['length']}")
    return findings

# ─── MODE 3: Value Fuzzing (param+value) ──────────────────────
def _fuzz_values(base_url: str, param: str) -> list:
    findings = []
    r0 = _req(base_url, params={param: "NORMAL"})
    base_len = len(r0.text) if r0 else 0
    base_status = r0.status_code if r0 else 0

    for val in FUZZ_VALUES:
        r = _req(base_url, params={param: val})
        if not r:
            continue
        diff = abs(len(r.text) - base_len)
        if r.status_code != base_status or diff > 30:
            findings.append({"param": param, "value": val[:40],
                             "status": r.status_code, "diff": diff})
            find(f"Value [{CY}]{val[:40]}[/]  status={r.status_code}  diff={diff}")
        else:
            info(f"  {val[:40]:<40}  [{DM}]{r.status_code}[/]")
    return findings

# ─── MAIN ─────────────────────────────────────────────────────
def run(target: str = None):
    show_module_banner("fuzz")
    cat_talk(CAT_SCAN, "FUZZ engines spinning up — probing hidden parameters...", OR)
    console.print()

    if not target:
        target = ask_target("Target URL (https://example.com/api/v1/user)")
    if not target:
        err("No target."); return

    if not target.startswith("http"):
        target = "https://" + target

    info(f"Target: [{CY}]{target}[/]")
    console.print()

    console.print(f"  [{G1}][1][/] Parameter discovery (common param names)")
    console.print(f"  [{G1}][2][/] Path / endpoint discovery")
    console.print(f"  [{G1}][3][/] Value fuzzing on a specific param")
    console.print(f"  [{G1}][4][/] Full (params + paths)")
    mode = ask_choice("Mode", "1")

    warn("Use ONLY on authorized targets.")

    all_findings = []

    if mode in ("1", "4"):
        boot_progress(["Getting baseline...", "Loading param wordlist..."])
        r0 = _req(target)
        baseline_len = len(r0.text) if r0 else 0
        info(f"Baseline: status={r0.status_code if r0 else 'N/A'}  len={baseline_len}")
        console.print()
        results = _fuzz_params(target, baseline_len)
        all_findings += [{"type": "PARAM", **r} for r in results]

    if mode in ("2", "4"):
        console.print()
        info("Scanning paths...")
        results = _fuzz_paths(target)
        all_findings += [{"type": "PATH", **r} for r in results]

    if mode == "3":
        param = Prompt.ask(f"  [{CY}]Parameter name to fuzz[/]").strip()
        if not param:
            err("No parameter."); return
        info(f"Fuzzing values for [{CY}]{param}[/]...")
        results = _fuzz_values(target, param)
        all_findings += [{"type": "VALUE", **r} for r in results]

    console.print()
    if all_findings:
        rows = []
        for f in all_findings:
            if f["type"] == "PARAM":
                rows.append(("PARAM", f["param"], str(f["status"]), str(f["diff"])))
            elif f["type"] == "PATH":
                rows.append(("PATH", f.get("path",""), str(f["status"]), str(f["length"])))
            elif f["type"] == "VALUE":
                rows.append(("VALUE", f.get("value","")[:30], str(f["status"]), str(f.get("diff",0))))
        print_result_table("FUZZ Discoveries", ["TYPE", "ITEM", "STATUS", "DIFF/LEN"], rows, color_col=2)
    else:
        ok("Nothing interesting found.")

    _save(target, all_findings)

def _save(target, findings):
    out = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out, exist_ok=True)
    fname = os.path.join(out, f"fuzz_{urlparse(target).netloc.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "findings": findings, "time": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
