# -*- coding: utf-8 -*-
"""
MEOW-SEC :: GRAPHQL — GraphQL Introspection & Security Tester
For authorized security testing and CTF challenges only.
"""
import os, re, json
from datetime import datetime
from urllib.parse import urlparse

from core.ui import (console, ok, err, info, warn, find, boot_progress,
                     print_result_table, show_module_banner, ask_target,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import CAT_FOUND, CAT_SCAN, cat_talk
from rich.syntax import Syntax

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.proxy_manager import px as _px

# ─── COMMON GRAPHQL ENDPOINTS ─────────────────────────────────
COMMON_ENDPOINTS = [
    "/graphql", "/graphql/", "/api/graphql", "/api/v1/graphql",
    "/api/v2/graphql", "/v1/graphql", "/v2/graphql", "/query",
    "/gql", "/graphiql", "/playground", "/api/query",
    "/api", "/api/", "/graph",
]

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}
""".strip()

SIMPLE_PROBE = '{"query":"{__typename}"}'

INJECTION_QUERIES = [
    ('SQL injection via argument', '{"query":"{user(id:\\"1 OR 1=1\\") {id name email}}"}'),
    ('Batch query (alias)', '{"query":"{a:__typename b:__typename c:__typename d:__typename e:__typename}"}'),
    ('Deep nested query (DoS)', '{"query":"{a{a{a{a{a{a{a{a{a{a{__typename}}}}}}}}}}}"}'),
    ('Introspection enabled check', json.dumps({"query": INTROSPECTION_QUERY})),
    ('Field suggestion leak', '{"query":"{usrr{id}}"}'),
    ('Type confusion: null arg', '{"query":"{user(id:null){id name}}"}'),
]

MUTATION_PROBES = [
    ('Login mutation', '{"query":"mutation{login(username:\\"admin\\"password:\\"password\\"){token}}"}'),
    ('Register mutation', '{"query":"mutation{register(email:\\"test@test.com\\"password:\\"pass\\"){id}}"}'),
    ('Password reset', '{"query":"mutation{resetPassword(email:\\"admin@test.com\\"){success}}"}'),
]

def _post(url: str, data: str, timeout: int = 10) -> dict:
    try:
        r = requests.post(
            url, data=data,
            headers={"Content-Type": "application/json",
                     "User-Agent": "MEOW-GRAPHQL/1.1 (authorized-test)"},
            timeout=timeout, verify=False, proxies=_px(), allow_redirects=True
        )
        return {"ok": True, "status": r.status_code, "text": r.text[:5000],
                "json": r.json() if r.headers.get("content-type","").startswith("application/json") else None}
    except Exception as e:
        return {"ok": False, "status": 0, "error": str(e)[:60], "text": "", "json": None}

def _find_endpoint(base: str) -> str:
    info("Discovering GraphQL endpoint...")
    if not base.endswith("/"):
        base = base.rstrip("/")
    for path in COMMON_ENDPOINTS:
        url = base + path
        r = _post(url, SIMPLE_PROBE)
        if r["ok"] and r["status"] not in (404, 405):
            if "__typename" in r.get("text","") or "errors" in r.get("text",""):
                ok(f"GraphQL found at [{G1}]{url}[/]")
                return url
    return ""

def _do_introspection(url: str) -> dict:
    info("Running introspection query...")
    r = _post(url, json.dumps({"query": INTROSPECTION_QUERY}))
    if not r["ok"] or r["status"] != 200:
        return {"enabled": False}
    text = r.get("text","")
    if "__schema" in text or "queryType" in text:
        # Parse types
        try:
            data = r["json"] or json.loads(text)
            schema = data.get("data",{}).get("__schema",{})
            types  = [t for t in schema.get("types",[]) if not t["name"].startswith("__")]
            queries = [t["name"] for t in types if t.get("kind") == "OBJECT"]
            field_count = sum(len(t.get("fields") or []) for t in types)
            return {"enabled": True, "types": [t["name"] for t in types[:30]],
                    "queries": queries, "field_count": field_count, "raw": text[:3000]}
        except Exception:
            return {"enabled": True, "raw": text[:1000]}
    if "introspection" in text.lower() and "disabled" in text.lower():
        return {"enabled": False, "note": "Introspection explicitly disabled"}
    return {"enabled": False}

def _test_injections(url: str) -> list:
    findings = []
    for name, query in INJECTION_QUERIES + MUTATION_PROBES:
        r = _post(url, query)
        if not r["ok"]:
            continue
        text = r.get("text","")
        issues = []
        if "sql" in text.lower() or "syntax error" in text.lower():
            issues.append("SQL error in response")
        if '"data":{' in text and r["status"] == 200:
            issues.append("Query executed successfully")
        if "did you mean" in text.lower():
            issues.append("Field suggestion leak")
        if issues:
            findings.append({"name": name, "status": r["status"],
                             "issues": ", ".join(issues), "snippet": text[:200]})
            find(f"[{CY}]{name}[/]  →  [{G1}]{', '.join(issues)}[/]")
    return findings

# ─── MAIN ─────────────────────────────────────────────────────
def run(target: str = None):
    show_module_banner("graphql")
    cat_talk(CAT_SCAN, "GRAPHQL scanner — poking the schema for weaknesses...", CY)
    console.print()

    if not target:
        target = ask_target("Target URL (https://api.example.com  or  https://api.example.com/graphql)")
    if not target:
        err("No target."); return

    if not target.startswith("http"):
        target = "https://" + target

    info(f"Target: [{CY}]{target}[/]")
    console.print()

    console.print(f"  [{G1}][1][/] Endpoint discovery")
    console.print(f"  [{G1}][2][/] Introspection query")
    console.print(f"  [{G1}][3][/] Injection / mutation probes")
    console.print(f"  [{G1}][4][/] Full scan (all of the above)")
    mode = ask_choice("Mode", "4")

    warn("Use ONLY on authorized targets.")
    boot_progress(["Connecting to GraphQL...", "Querying schema...", "Testing mutations..."])
    console.print()

    endpoint = target
    findings = []

    if mode in ("1", "4"):
        discovered = _find_endpoint(target.rstrip("/"))
        if discovered:
            endpoint = discovered
        else:
            # Test target directly
            r = _post(target, SIMPLE_PROBE)
            if r["ok"] and "__typename" in r.get("text",""):
                endpoint = target
                ok(f"GraphQL confirmed at [{G1}]{target}[/]")
            else:
                warn("GraphQL endpoint not found at target. Try specifying the full endpoint URL.")
                if mode == "1":
                    return

    from rich.rule import Rule
    console.print(Rule(f"[{G1}] Endpoint: {endpoint} ", style=G2))
    console.print()

    if mode in ("2", "4"):
        intro = _do_introspection(endpoint)
        if intro.get("enabled"):
            find(f"Introspection ENABLED — [{G1}]{intro.get('field_count',0)}[/] fields, [{G1}]{len(intro.get('types',[]))}[/] types")
            findings.append({"type": "INTROSPECTION", "sev": "MEDIUM",
                             "note": "Schema exposed via introspection"})
            if intro.get("types"):
                info(f"Types: {', '.join(intro['types'][:15])}")
            if intro.get("raw"):
                console.print(Syntax(intro["raw"][:800], "json", theme="monokai",
                                     line_numbers=False))
        else:
            ok(f"Introspection disabled — {intro.get('note','')}")

    if mode in ("3", "4"):
        console.print()
        info("Running injection / mutation probes...")
        inj = _test_injections(endpoint)
        for f in inj:
            findings.append({"type": "INJECTION", "sev": "HIGH",
                             "note": f"{f['name']}: {f['issues']}"})

    console.print()
    if findings:
        rows = [(f["type"], f["sev"], f["note"][:60]) for f in findings]
        print_result_table("GraphQL Security Issues", ["TYPE", "SEV", "NOTE"], rows, color_col=1)
    else:
        ok("No GraphQL vulnerabilities detected.")

    _save(target, findings)

def _save(target, findings):
    out = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out, exist_ok=True)
    fname = os.path.join(out, f"graphql_{urlparse(target).netloc.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({"target": target, "findings": findings, "time": datetime.now().isoformat()}, f, indent=2)
    ok(f"Results saved → [{CY}]{os.path.basename(fname)}[/]")
