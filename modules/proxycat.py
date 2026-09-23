# -*- coding: utf-8 -*-
"""
MEOW-SEC :: PROXYCAT — Proxy Downloader / Checker / Rotator
"""
import os, json, time
from datetime import datetime

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_choice, wait_enter, print_result_table,
                     G1, G2, CY, OR, RD, DM)
from core.cats import CAT_SCAN, CAT_FOUND, CAT_IDLE, cat_talk
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.prompt import Prompt
from rich import box

MODULE_LOGOS = {
    "proxycat": r"""
 ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗ ██████╗ █████╗ ████████╗
 ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝██╔════╝██╔══██╗╚══██╔══╝
 ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ ██║     ███████║   ██║
 ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  ██║     ██╔══██║   ██║
 ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   ╚██████╗██║  ██║   ██║
 ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝   ╚═╝
        [PROXY DOWNLOADER · CHECKER · ROTATOR]"""
}

def _banner():
    from rich.text import Text
    logo = Text(MODULE_LOGOS["proxycat"], style=f"bold {G1}")
    console.print(Panel(Align(logo, align="center"), border_style=RD, padding=(0,1)))

# ─── MENUS ───────────────────────────────────────────────────

def run():
    show_module_banner("proxycat")
    cat_talk(CAT_IDLE, "PROXYCAT proxy manager online...", OR)
    console.print()

    while True:
        console.print(f"  [{G1}][1][/] Download & validate fresh proxies")
        console.print(f"  [{G1}][2][/] Check saved proxies (re-validate)")
        console.print(f"  [{G1}][3][/] Show proxy stats")
        console.print(f"  [{G1}][4][/] Test a specific proxy")
        console.print(f"  [{G1}][5][/] Export working proxies")
        console.print(f"  [{G1}][0][/] Back")
        console.print()

        choice = ask_choice("PROXYCAT", "0")

        if choice == "0":
            break
        elif choice == "1":
            _download_and_validate()
        elif choice == "2":
            _recheck()
        elif choice == "3":
            _show_stats()
        elif choice == "4":
            _test_single()
        elif choice == "5":
            _export()
        else:
            warn("Invalid option.")
        console.print()

# ─── ACTIONS ─────────────────────────────────────────────────

def _download_and_validate():
    from core.proxy_manager import ProxyManager
    workers = int(Prompt.ask(f"  [{G1}]◈ Validation threads[/]", default="80"))
    pm = ProxyManager()
    pm.refresh(workers=workers)
    cat_talk(CAT_FOUND, f"{len(pm.good)} good proxies in pool!", G1)

def _recheck():
    from core.proxy_manager import get_manager
    pm = get_manager()
    if not pm.good:
        err("No proxies in cache. Download first."); return
    proxies = [p["proxy"] for p in pm.good]
    info(f"Re-validating [{G1}]{len(proxies)}[/] cached proxies...")
    good = pm.validate(proxies)
    pm.good = good
    pm._save()
    ok(f"Done. [{G1}]{len(good)}[/] still working.")

def _show_stats():
    from core.proxy_manager import get_manager
    pm = get_manager()
    if not pm.good:
        warn("No proxies loaded. Download first."); return

    stats = pm.stats()

    t = Table(
        title=f"[{G1}]PROXY POOL STATS[/]",
        box=box.MINIMAL_DOUBLE_HEAD,
        border_style=G2, header_style=CY
    )
    t.add_column("Metric", style=CY)
    t.add_column("Value",  style=G1)

    t.add_row("Total proxies",    str(stats["total"]))
    t.add_row("Available",        str(stats["available"]))
    t.add_row("Marked bad",       str(stats["bad"]))
    t.add_row("Fastest proxy",    stats["fastest"] or "N/A")
    t.add_row("Avg latency",      f"{stats['avg_latency']} ms")

    console.print(t)
    console.print()

    # Top 10 fastest
    if pm.good:
        top = pm.good[:10]
        rows = [(p["proxy"], f"{p['latency_ms']} ms", p.get("validated","")[:19]) for p in top]
        print_result_table("Top 10 Fastest Proxies",
            ["PROXY", "LATENCY", "VALIDATED"], rows)

def _test_single():
    proxy = Prompt.ask(f"  [{G1}]◈ Proxy (ip:port)[/]").strip()
    if not proxy:
        return
    test_url = Prompt.ask(f"  [{G1}]◈ Test URL[/]", default="http://httpbin.org/ip")

    info(f"Testing [{CY}]{proxy}[/] via [{CY}]{test_url}[/]...")
    try:
        import requests
        start = time.time()
        r = requests.get(test_url,
                         proxies={"http": f"http://{proxy}", "https": f"http://{proxy}"},
                         timeout=8, verify=False)
        latency = round((time.time()-start)*1000)
        if r.status_code == 200:
            find(f"WORKING  latency=[{CY}]{latency}ms[/]  response=[{G1}]{r.text[:80]}[/]")
        else:
            warn(f"Status {r.status_code} — might be filtering")
    except Exception as e:
        err(f"Failed: {e}")

def _export():
    from core.proxy_manager import get_manager
    pm = get_manager()
    if not pm.good:
        err("No proxies. Download first."); return

    fmt = ask_choice("Format: [1] txt  [2] json", "1")
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "1":
        fname = os.path.join(out_dir, f"proxies_{ts}.txt")
        with open(fname, "w") as f:
            for p in pm.good:
                f.write(p["proxy"] + "\n")
        ok(f"Exported [{G1}]{len(pm.good)}[/] proxies → [{CY}]{os.path.basename(fname)}[/]")
    else:
        fname = os.path.join(out_dir, f"proxies_{ts}.json")
        with open(fname, "w") as f:
            json.dump(pm.good, f, indent=2)
        ok(f"Exported → [{CY}]{os.path.basename(fname)}[/]")
