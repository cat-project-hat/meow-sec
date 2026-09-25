# -*- coding: utf-8 -*-
"""
MEOW-SEC :: LOOT — View & Manage Scan Results
"""
import os, json
from datetime import datetime

from core.ui import console, ok, err, info, warn, find, show_module_banner, ask_choice, G1, G2, CY, OR, RD, DM
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax
from rich.prompt import Prompt
from rich import box

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

MODULE_COLORS = {
    "claw":    CY,
    "purr":    OR,
    "scratch": G1,
    "whisker": "#88AAFF",
    "hiss":    RD,
    "catnap":  "#AA88FF",
}

def run():
    show_module_banner("loot")
    console.print()

    if not os.path.exists(DATA_DIR):
        warn("No data directory found. Run a scan first."); return

    files = sorted(
        [f for f in os.listdir(DATA_DIR) if f.endswith(".json")],
        reverse=True
    )

    if not files:
        warn("No saved results. Run a scan first."); return

    # Tableau des fichiers
    t = Table(
        title=f"[{G1}]◈ LOOT — Saved Results ◈[/]",
        box=box.MINIMAL_DOUBLE_HEAD,
        border_style=G2,
        header_style=CY
    )
    t.add_column("#", style=CY, width=4)
    t.add_column("Module", width=10)
    t.add_column("File", style=G1)
    t.add_column("Date", style=DM)
    t.add_column("Size", style=DM, justify="right")

    for i, f in enumerate(files, 1):
        mod = f.split("_")[0]
        col = MODULE_COLORS.get(mod, WH if False else G1)
        fpath = os.path.join(DATA_DIR, f)
        size = os.path.getsize(fpath)
        mtime = datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M")
        t.add_row(str(i), f"[{col}]{mod.upper()}[/]", f, mtime, f"{size/1024:.1f}KB")

    console.print(t)
    console.print()

    console.print(f"  [{G1}][1][/] View file   [{G1}][3][/] Diff two sessions   [{DM}][ENTER] Back[/]\n")
    choice = Prompt.ask(
        f"[{G1}]◈ Choice (file #, 3 = diff, ENTER = back)[/]",
        default=""
    ).strip()

    if not choice:
        return

    # ── Mode [3]: diff two sessions ──────────────────────────────
    if choice == "3":
        console.print(f"\n  [{CY}]── Diff Two Sessions ──[/]\n")
        a_choice = Prompt.ask(f"  [{G1}]First file #[/]", default="").strip()
        b_choice = Prompt.ask(f"  [{G1}]Second file #[/]", default="").strip()
        try:
            ia = int(a_choice) - 1
            ib = int(b_choice) - 1
            if not (0 <= ia < len(files) and 0 <= ib < len(files)):
                err("Invalid file number(s).")
                return
            with open(os.path.join(DATA_DIR, files[ia]), encoding="utf-8") as f:
                data_a = json.load(f)
            with open(os.path.join(DATA_DIR, files[ib]), encoding="utf-8") as f:
                data_b = json.load(f)
        except ValueError:
            err("Enter valid numbers.")
            return

        keys_a = set(data_a.keys())
        keys_b = set(data_b.keys())
        new_keys     = keys_b - keys_a
        removed_keys = keys_a - keys_b
        common_keys  = keys_a & keys_b

        console.print(f"\n  [{CY}]A:[/] {files[ia]}   [{CY}]B:[/] {files[ib]}\n")

        if not new_keys and not removed_keys and all(data_a[k] == data_b[k] for k in common_keys):
            ok("Sessions are identical (top-level keys and values match).")
        else:
            for k in sorted(new_keys):
                val = str(data_b[k])[:80]
                console.print(f"  [{G1}][+][/] [{G1}]{k}[/] = {val}")
            for k in sorted(removed_keys):
                console.print(f"  [{RD}][-][/] [{RD}]{k}[/]")
            for k in sorted(common_keys):
                if data_a[k] != data_b[k]:
                    before = str(data_a[k])[:60]
                    after  = str(data_b[k])[:60]
                    console.print(f"  [{OR}][~][/] [{OR}]{k}[/]: {before} [{DM}]→[/] {after}")

        console.print()
        return

    # ── Mode view file ────────────────────────────────────────────
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(files):
            fpath = os.path.join(DATA_DIR, files[idx])
            with open(fpath, encoding="utf-8") as f:
                content = json.load(f)
            console.print(Panel(
                Syntax(json.dumps(content, indent=2), "json",
                       theme="monokai", line_numbers=True),
                title=f"[{G1}]{files[idx]}[/]",
                border_style=G2
            ))
        else:
            err("Invalid number.")
    except ValueError:
        err("Enter a valid number.")
