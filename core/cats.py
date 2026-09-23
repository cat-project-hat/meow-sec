# -*- coding: utf-8 -*-
"""
MEOW-SEC :: ASCII Cat Art & Animations
"""
import random, time, sys, io
from rich.console import Console
from rich.text import Text

_out = (io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        if hasattr(sys.stdout, "buffer") else sys.stdout)
console = Console(file=_out, legacy_windows=False, highlight=False)

# ═══════════════════════════════════════════════
#  CAT ART COLLECTION
# ═══════════════════════════════════════════════

BANNER_CAT = r"""
  /\_____/\
 /  🔴   🔴  \
( ==  ^  == )
 )  MEOW   (
(  SEC v1.0 )
 (_________)"""

CAT_HACKER = r"""
  /\_____/\
 /  ^   ^  \
(  (o) (o)  )
 \   ~~~   /  < i'm in ur system
  \       /
   )     (     [===──────
  (_,   ,_)   MEOW.EXE"""

CAT_SCAN = r"""
   /\__/\
  / ,, ,, \
 ( (o)_(o) )
  \  ~~  /  scanning...
   )    (
  (_    _)
  [~ ~ ~ ~]"""

CAT_FOUND = r"""
   /\  /\
  / ** ** \
 ( (^) (^) )
  \  !! /
   ) ++ (
  (______) FOUND!"""

CAT_ERROR = r"""
   /\  /\
  / xx xx \
 ( (x) (x) )
  \  ~~  /
   ) .. (
  (______) ERR"""

CAT_PWNED = r"""
   /\    /\
  / !!  !! \
 ( (★) (★)  )
  \  ^^^^  /
   )      (    TARGET PWNED
  (________)"""

CAT_IDLE = r"""
  /\_/\
 ( -.-)  zZz
  (  づ)づ
   ||||  """

CAT_MATRIX = r"""
  /\_/\        01001101
 ( 0 0 )  ══►  01000101
  \\_//         01001111
  /   \   ══►  01010111
 |     |"""

CAT_RECON = r"""
   /\  /\
  /  @@  \
 ( (@) (@) )──[ RECON ]
  \  ~~  /
   ) ::  (
  (_______)"""

CAT_NET = r"""
  /\_/\
 ( o.o )─┬─ [TCP]
  > ~ <   ├─ [UDP]
  |   |   └─ [HTTP]
  |___|"""

CAT_BRUTE = r"""
   /\  /\
  / !! !! \
 ( (>) (<) )  BRUTING...
  \======/
   ) ++ (
  (________)"""

CAT_SHIELD = r"""
  /\_____/\
 /  ^   ^  \
(  ( o ) ( o)  )
 \   ---   /
  \  [S]  /
   \_____/  SECURE"""

# ═══════════════════════════════════════════════
#  LOGO MEOW-SEC
# ═══════════════════════════════════════════════

MEOW_LOGO = r"""
███╗   ███╗███████╗ ██████╗ ██╗    ██╗      ███████╗███████╗ ██████╗
████╗ ████║██╔════╝██╔═══██╗██║    ██║      ██╔════╝██╔════╝██╔════╝
██╔████╔██║█████╗  ██║   ██║██║ █╗ ██║█████╗███████╗█████╗  ██║
██║╚██╔╝██║██╔══╝  ██║   ██║██║███╗██║╚════╝╚════██║██╔══╝  ██║
██║ ╚═╝ ██║███████╗╚██████╔╝╚███╔███╔╝      ███████║███████╗╚██████╗
╚═╝     ╚═╝╚══════╝ ╚═════╝  ╚══╝╚══╝       ╚══════╝╚══════╝ ╚═════╝"""

MODULE_LOGOS = {
    "claw":    "  ██████╗██╗      █████╗ ██╗    ██╗\n ██╔════╝██║     ██╔══██╗██║    ██║\n ██║     ██║     ███████║██║ █╗ ██║\n ██║     ██║     ██╔══██║██║███╗██║\n ╚██████╗███████╗██║  ██║╚███╔███╔╝\n  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝\n        [PORT SCANNER]",
    "purr":    "  ██████╗ ██╗   ██╗██████╗ ██████╗\n  ██╔══██╗██║   ██║██╔══██╗██╔══██╗\n  ██████╔╝██║   ██║██████╔╝██████╔╝\n  ██╔═══╝ ██║   ██║██╔══██╗██╔══██╗\n  ██║     ╚██████╔╝██║  ██║██║  ██║\n  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝\n       [WEB RECON]",
    "scratch": "  ███████╗ ██████╗██████╗  █████╗ ████████╗ ██████╗██╗  ██╗\n  ██╔════╝██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║  ██║\n  ███████╗██║     ██████╔╝███████║   ██║   ██║     ███████║\n  ╚════██║██║     ██╔══██╗██╔══██║   ██║   ██║     ██╔══██║\n  ███████║╚██████╗██║  ██║██║  ██║   ██║   ╚██████╗██║  ██║\n  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═╝    ╚═════╝╚═╝  ╚═╝\n       [DIR BRUTE FORCE]",
    "whisker": "  ██╗    ██╗██╗  ██╗██╗███████╗██╗  ██╗███████╗██████╗\n  ██║    ██║██║  ██║██║██╔════╝██║ ██╔╝██╔════╝██╔══██╗\n  ██║ █╗ ██║███████║██║███████╗█████╔╝ █████╗  ██████╔╝\n  ██║███╗██║██╔══██║██║╚════██║██╔═██╗ ██╔══╝  ██╔══██╗\n  ╚███╔███╔╝██║  ██║██║███████║██║  ██╗███████╗██║  ██║\n   ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n       [OSINT & RECON]",
    "hiss":    "  ██╗  ██╗██╗███████╗███████╗\n  ██║  ██║██║██╔════╝██╔════╝\n  ███████║██║███████╗███████╗\n  ██╔══██║██║╚════██║╚════██║\n  ██║  ██║██║███████║███████║\n  ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝\n       [VULN TESTER]",
    "catnap":  "  ██████╗ █████╗ ████████╗███╗  ██╗ █████╗ ██████╗\n ██╔════╝██╔══██╗╚══██╔══╝████╗ ██║██╔══██╗██╔══██╗\n ██║     ███████║   ██║   ██╔██╗██║███████║██████╔╝\n ██║     ██╔══██║   ██║   ██║╚████║██╔══██║██╔═══╝\n ╚██████╗██║  ██║   ██║   ██║ ╚███║██║  ██║██║\n  ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚══╝╚═╝  ╚═╝╚═╝\n       [SUBDOMAIN ENUM]",
}

# ═══════════════════════════════════════════════
#  ANIMATIONS
# ═══════════════════════════════════════════════

MATRIX_CHARS = "ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ01!@#$%"
GLITCH_CHARS = "!@#$%^&*<>?/\\|{}[]~`░▒▓"

def matrix_rain(width: int = 70, duration: float = 0.6):
    from rich.markup import escape as _esc
    start = time.time()
    while time.time() - start < duration:
        t = Text()
        for _ in range(width):
            r = random.random()
            ch = random.choice(MATRIX_CHARS)
            if r < 0.05:
                t.append(ch, style="bold bright_white")
            elif r < 0.3:
                t.append(ch, style="bright_green")
            else:
                t.append(ch, style="green")
        console.print(t)
        time.sleep(0.025)

def glitch_line(text: str, iters: int = 4):
    for i in range(iters):
        g = Text()
        for ch in text:
            if random.random() < 0.12 and ch.strip():
                g.append(random.choice(GLITCH_CHARS),
                         style="bright_red" if i % 2 == 0 else "bright_green")
            else:
                g.append(ch)
        console.print(g, end="\r")
        time.sleep(0.06)
    console.print(Text(text, style="bold bright_green"))

def typewriter(text: str, color: str = "bright_green", delay: float = 0.025):
    for ch in text:
        console.print(f"[{color}]{ch}[/]", end="")
        sys.stdout.flush()
        time.sleep(delay)
    print()

def cat_talk(cat: str, message: str, color: str = "bright_green"):
    """Affiche un chat ASCII + message. Utilise Text pour éviter les bugs markup."""
    for line in cat.strip().split("\n"):
        console.print(Text(line, style=color))
    console.print(Text(f"  ╰─► {message}", style=color))
