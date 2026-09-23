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
    show_module_banner("claw")  # fallback visuel
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

    choice = Prompt.ask(
        f"[{G1}]◈ View file # (or ENTER to go back)[/]",
        default=""
    ).strip()

    if not choice:
        return

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
