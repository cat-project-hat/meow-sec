# -*- coding: utf-8 -*-
"""
MEOW-SEC :: RACE — Race Condition Tester
For authorized security testing and CTF challenges only.
"""
import os, json, time, threading
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

_UA = "Mozilla/5.0 (authorized-pentest-race)"

# ─── WORKER ───────────────────────────────────────────────────

class _Worker:
    def __init__(self, method, url, headers, cookies, data, json_body, barrier):
        self.method   = method
        self.url      = url
        self.headers  = headers
        self.cookies  = cookies
        self.data     = data
        self.json_b   = json_body
        self.barrier  = barrier
        self.result   = None
        self.elapsed  = 0.0

    def run(self):
        try:
            s = requests.Session()
            # Pre-open a connection (warm up TCP)
            s.get(self.url, timeout=5, verify=False, proxies=_px())
        except Exception:
            pass

        self.barrier.wait()  # All threads fire simultaneously
        t0 = time.perf_counter()
        try:
            r = requests.request(
                self.method, self.url,
                headers=self.headers,
                cookies=self.cookies,
                data=self.data,
                json=self.json_b,
                timeout=12, verify=False, proxies=_px(),
                allow_redirects=True,
            )
            self.result  = r
            self.elapsed = time.perf_counter() - t0
        except Exception as e:
            self.result  = None
            self.elapsed = time.perf_counter() - t0

# ─── ANALYSIS ─────────────────────────────────────────────────

def _analyze(results: list, baseline_status: int) -> dict:
    statuses = [r.status_code for r in results if r]
    sizes    = [len(r.content) for r in results if r]
    unique_statuses = set(statuses)
    unique_sizes    = set(sizes)

    finding = {
        "total": len(results),
        "errors": sum(1 for r in results if r is None),
        "statuses": statuses,
        "unique_statuses": list(unique_statuses),
        "sizes": sizes,
        "race_likely": False,
        "reason": "",
    }

    # Multiple different sizes with same status → double-spend / duplicate apply
    if len(unique_sizes) > 2 and len(unique_statuses) == 1 and statuses[0] in (200, 201):
        finding["race_likely"] = True
        finding["reason"] = f"Size variance across {len(unique_sizes)} responses — potential double-spend"

    # Mix of success and error → some requests won the race
    if 200 in unique_statuses and any(s in unique_statuses for s in (400, 409, 429, 500)):
        winners = sum(1 for s in statuses if s == 200)
        finding["race_likely"] = True
        finding["reason"] = f"{winners}/{len(statuses)} requests succeeded — race window detected"

    # All succeed when only 1 should
    if all(s in (200, 201) for s in statuses) and len(statuses) > 1:
        finding["race_likely"] = True
        finding["reason"] = f"ALL {len(statuses)} concurrent requests returned 200 — may indicate double-spend"

    return finding

# ─── BASELINE ─────────────────────────────────────────────────

def _baseline(method, url, headers, cookies, data, json_body):
    try:
        r = requests.request(method, url, headers=headers, cookies=cookies,
                             data=data, json=json_body,
                             timeout=10, verify=False, proxies=_px())
        return r
    except Exception:
        return None

# ─── TEST ─────────────────────────────────────────────────────

def _run_race(method, url, headers, cookies, data, json_body, n_threads: int) -> list:
    barrier = threading.Barrier(n_threads)
    workers = [_Worker(method, url, headers, cookies, data, json_body, barrier)
               for _ in range(n_threads)]
    threads = [threading.Thread(target=w.run) for w in workers]

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    return [w.result for w in workers], [w.elapsed for w in workers]

# ─── SCENARIOS ────────────────────────────────────────────────

_SCENARIOS = {
    "1": ("Coupon / promo code apply",       "POST",  "one-time discount applied multiple times"),
    "2": ("Vote / like / reaction",          "POST",  "vote counted multiple times"),
    "3": ("Gift card / credit redemption",   "POST",  "balance consumed multiple times"),
    "4": ("Password reset / OTP consume",    "POST",  "token used more than once"),
    "5": ("Purchase / checkout",             "POST",  "item purchased at wrong price or multiple times"),
    "6": ("2FA code consumption",            "POST",  "OTP valid for multiple concurrent logins"),
    "7": ("Custom endpoint",                 "GET",   "custom request"),
}

# ─── SAVE ─────────────────────────────────────────────────────

def _save(target: str, findings: list):
    if not findings:
        return
    os.makedirs("data", exist_ok=True)
    fname = f"data/race_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "findings": findings, "ts": datetime.now().isoformat()}, f, indent=2)
    ok(f"Saved → {fname}")

# ─── MAIN ─────────────────────────────────────────────────────

def run():
    show_module_banner("race")
    if not HAS_REQUESTS:
        err("requests not installed"); return

    console.print(f"\n  [{CY}]Race Condition Tester[/]  [{DM}]— synchronized burst via threading.Barrier[/]\n")

    console.print(f"  [{CY}]Scenario:[/]")
    for k, (label, method, desc) in _SCENARIOS.items():
        console.print(f"  [{G2}][{k}][/] {label}  [{DM}]({desc})[/]")

    scenario = ask_choice("Scenario")
    if scenario not in _SCENARIOS:
        warn("Invalid scenario"); return

    label, default_method, _ = _SCENARIOS[scenario]

    url = ask_target(f"Target URL for [{label}]")
    if not url:
        return
    if not url.startswith("http"):
        url = "http://" + url

    method = ask_choice(f"HTTP method [{default_method}]") or default_method
    method = method.upper()

    body_raw = ask_choice("POST body (key=value&key2=val2 or JSON) [Enter to skip]")
    data = None
    json_body = None
    if body_raw:
        if body_raw.strip().startswith("{"):
            try:
                json_body = json.loads(body_raw)
            except Exception:
                data = body_raw
        else:
            data = body_raw

    cookie_str = ask_choice("Session cookie (name=value; ...) [Enter to skip]")
    cookies = {}
    if cookie_str and "=" in cookie_str:
        for part in cookie_str.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k.strip()] = v.strip()

    threads_str = ask_choice("Number of concurrent threads [default: 10]") or "10"
    try:
        n_threads = max(2, min(int(threads_str), 50))
    except ValueError:
        n_threads = 10

    rounds_str = ask_choice("Number of burst rounds [default: 3]") or "3"
    try:
        n_rounds = max(1, min(int(rounds_str), 10))
    except ValueError:
        n_rounds = 3

    headers = {
        "User-Agent": _UA,
        "Content-Type": "application/x-www-form-urlencoded" if data else "application/json",
    }

    console.print(f"\n  [{G1}]Baseline request...[/]")
    bl = _baseline(method, url, headers, cookies, data, json_body)
    if bl is None:
        err("Baseline failed — check URL and connectivity"); return
    info(f"Baseline: HTTP {bl.status_code}  {len(bl.content)} bytes")

    all_findings = []

    for rnd in range(1, n_rounds + 1):
        console.print(f"\n  [{CY}]Round {rnd}/{n_rounds}[/]  [{DM}]— {n_threads} threads synchronized[/]")
        results, timings = _run_race(method, url, headers, cookies, data, json_body, n_threads)

        statuses = [r.status_code if r else 0 for r in results]
        console.print(f"  [{G2}]Statuses:[/] {statuses}")

        valid = [r for r in results if r is not None]
        if not valid:
            warn("All requests failed"); continue

        analysis = _analyze(valid, bl.status_code)

        if analysis["race_likely"]:
            find(f"[bold {RD}]RACE CONDITION detected![/]  {analysis['reason']}")
            all_findings.append({
                "round": rnd,
                "url": url,
                "scenario": label,
                "reason": analysis["reason"],
                "statuses": analysis["statuses"],
                "threads": n_threads,
            })
        else:
            ok(f"Round {rnd}: No obvious race — {analysis['statuses']}")

        if rnd < n_rounds:
            time.sleep(1)

    console.print()
    if all_findings:
        cat_talk(CAT_FOUND, f"Race condition found in {len(all_findings)}/{n_rounds} round(s)!", G1)
        rows = [[f["scenario"], str(f["round"]), f["reason"], str(f["threads"])]
                for f in all_findings]
        print_result_table(["Scenario", "Round", "Reason", "Threads"], rows)
        _save(url, all_findings)
    else:
        cat_talk(CAT_SCAN, "No race condition detected — try more threads or rounds, or check scenario.", DM)
