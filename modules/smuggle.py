# -*- coding: utf-8 -*-
"""MEOW-SEC :: SMUGGLE — HTTP Request Smuggling Tester"""
import os, time, json, socket, ssl
from datetime import datetime
from urllib.parse import urlparse

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_SCAN
from rich.panel  import Panel
from rich.table  import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.rule   import Rule
from rich        import box


def _save(name, target, results):
    os.makedirs("data", exist_ok=True)
    fname = f"data/{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "results": results,
                   "timestamp": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved: [bold]{fname}[/]")


def _raw_request(host, port, use_ssl, payload_bytes, timeout=12):
    """Send raw bytes over socket, return (response_bytes, elapsed_seconds)."""
    ctx = ssl.create_default_context() if use_ssl else None
    if ctx:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if use_ssl:
            s = ctx.wrap_socket(s, server_hostname=host)
        t0 = time.time()
        s.sendall(payload_bytes)
        resp = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 65536:
                    break
        except socket.timeout:
            pass
        elapsed = time.time() - t0
        s.close()
        return resp, elapsed
    except Exception as e:
        return None, -1.0


def _baseline(host, port, use_ssl, path, timeout=8):
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Connection: close\r\n\r\n"
        f"test"
    ).encode()
    _, elapsed = _raw_request(host, port, use_ssl, req, timeout)
    return elapsed


def _test_cl_te(host, port, use_ssl, path):
    """CL.TE: CL says body is longer than what TE 0-chunk terminates."""
    payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 13\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
        f"SMUGGLED"
    ).encode()
    resp, elapsed = _raw_request(host, port, use_ssl, payload, timeout=14)
    return resp, elapsed


def _test_te_cl(host, port, use_ssl, path):
    """TE.CL: TE says 1-byte body, CL=3 — server confusion."""
    payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 3\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"1\r\n"
        f"A\r\n"
        f"0\r\n"
        f"\r\n"
    ).encode()
    resp, elapsed = _raw_request(host, port, use_ssl, payload, timeout=14)
    return resp, elapsed


def _test_te_te(host, port, use_ssl, path):
    """TE.TE: obfuscated Transfer-Encoding headers."""
    variants = [
        ("xchunked",          "Transfer-Encoding: xchunked"),
        ("Chunked",           "Transfer-Encoding: Chunked"),
        ("chunked\\t",        "Transfer-Encoding: chunked\t"),
        ("chunked identity",  "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"),
        ("X-Transfer-Encoding","X-Transfer-Encoding: chunked"),
    ]
    results = []
    for name, te_header in variants:
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"{te_header}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()
        resp, elapsed = _raw_request(host, port, use_ssl, payload, timeout=10)
        status = "?"
        if resp:
            try:
                first = resp.split(b"\r\n")[0].decode(errors="replace")
                status = first.split(" ")[1] if len(first.split(" ")) > 1 else "?"
            except Exception:
                pass
        results.append((name, status, elapsed))
    return results


def run():
    show_module_banner("smuggle")
    cat_talk(CAT_SCAN, "HTTP Request Smuggling tester — CL.TE / TE.CL / TE.TE", OR)
    console.print()
    warn("AUTHORIZED USE ONLY — Unauthorized testing is illegal.")
    if not Confirm.ask(f"  [{OR}]◈ I confirm this is an authorized target[/]", default=False):
        info("Aborted."); return

    url = Prompt.ask(f"  [{G1}]◈ Target URL[/]").strip()
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    scheme = parsed.scheme
    host   = parsed.hostname
    port   = parsed.port or (443 if scheme == "https" else 80)
    path   = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    use_ssl = (scheme == "https")

    info(f"Target: {host}:{port}{path}  SSL={use_ssl}")
    console.print()

    results = []

    # Baseline
    info("Measuring baseline response time...")
    base_elapsed = _baseline(host, port, use_ssl, path)
    info(f"Baseline: {base_elapsed:.2f}s")
    console.print()

    # CL.TE
    info("[CL.TE] Sending Content-Length / Transfer-Encoding probe...")
    resp_clte, elapsed_clte = _test_cl_te(host, port, use_ssl, path)
    status_clte = "?"
    if resp_clte:
        try:
            status_clte = resp_clte.split(b"\r\n")[0].decode(errors="replace").split(" ")[1]
        except Exception:
            pass
    diff_clte = elapsed_clte - base_elapsed if base_elapsed > 0 else elapsed_clte
    vuln_clte = diff_clte > 2.0
    sev_clte  = "POTENTIAL" if vuln_clte else "SAFE"
    note_clte = f"time diff={diff_clte:.2f}s" if base_elapsed > 0 else f"elapsed={elapsed_clte:.2f}s"
    if vuln_clte:
        find(f"CL.TE timing anomaly detected ({note_clte})")
    results.append({"test": "CL.TE", "status": status_clte,
                    "elapsed": elapsed_clte, "severity": sev_clte, "note": note_clte})

    # TE.CL
    info("[TE.CL] Sending Transfer-Encoding / Content-Length probe...")
    resp_tecl, elapsed_tecl = _test_te_cl(host, port, use_ssl, path)
    status_tecl = "?"
    if resp_tecl:
        try:
            first = resp_tecl.split(b"\r\n")[0].decode(errors="replace")
            parts = first.split(" ")
            status_tecl = parts[1] if len(parts) > 1 else "?"
        except Exception:
            pass
    vuln_tecl = status_tecl in ("400", "500") or elapsed_tecl < 0
    sev_tecl  = "POTENTIAL" if vuln_tecl else "SAFE"
    results.append({"test": "TE.CL", "status": status_tecl,
                    "elapsed": elapsed_tecl, "severity": sev_tecl,
                    "note": f"status={status_tecl}"})

    # TE.TE
    info("[TE.TE] Testing obfuscated Transfer-Encoding headers...")
    te_te_results = _test_te_te(host, port, use_ssl, path)
    statuses = [r[1] for r in te_te_results]
    unique_statuses = set(statuses)
    vuln_tete = len(unique_statuses) > 1
    for name, st, el in te_te_results:
        sev = "POTENTIAL" if (vuln_tete and st not in ("200", "?")) else "SAFE"
        results.append({"test": f"TE.TE:{name}", "status": st,
                        "elapsed": el, "severity": sev, "note": ""})

    # Display table
    console.print()
    t = Table(title=f"[{G1}]Smuggling Results[/]", box=box.MINIMAL_DOUBLE_HEAD,
              border_style=G2, header_style=CY)
    t.add_column("Test",     style=CY, min_width=22)
    t.add_column("Status",   min_width=8)
    t.add_column("Elapsed",  min_width=8)
    t.add_column("Severity", min_width=10)
    t.add_column("Note",     min_width=20)

    sev_colors = {"POTENTIAL": RD, "SAFE": G2}
    for r in results:
        sc = sev_colors.get(r["severity"], DM)
        el = f"{r['elapsed']:.2f}s" if r["elapsed"] >= 0 else "ERR"
        t.add_row(r["test"], r["status"], el,
                  f"[{sc}]{r['severity']}[/]", r["note"])
    console.print(t)

    potentials = [r for r in results if r["severity"] == "POTENTIAL"]
    if potentials:
        find(f"{len(potentials)} potential smuggling vector(s) detected!")
    else:
        ok("No clear smuggling indicators found.")

    _save("smuggle", url, results)
