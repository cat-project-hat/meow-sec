# -*- coding: utf-8 -*-
"""
MEOW-SEC :: Session Manager
Persiste la cible, les modules lancés et les notes entre deux sessions.
"""
import os, json
from datetime import datetime

SESSION_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "session_current.json")

_DEFAULT = {
    "target": "",
    "started": "",
    "modules_run": [],
    "notes": [],
    "findings_count": 0,
}

def _load() -> dict:
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return dict(_DEFAULT)

def _save(data: dict):
    os.makedirs(os.path.dirname(SESSION_FILE), exist_ok=True)
    with open(SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def get_target() -> str:
    return _load().get("target", "")

def set_target(target: str):
    d = _load()
    d["target"] = target
    if not d.get("started"):
        d["started"] = datetime.now().isoformat()
    _save(d)

def log_module(module_name: str):
    """Enregistrer qu'un module a été lancé."""
    d = _load()
    entry = {"module": module_name, "at": datetime.now().isoformat()}
    d.setdefault("modules_run", []).append(entry)
    _save(d)

def add_note(note: str):
    d = _load()
    d.setdefault("notes", []).append({"note": note, "at": datetime.now().isoformat()})
    _save(d)

def add_finding():
    d = _load()
    d["findings_count"] = d.get("findings_count", 0) + 1
    _save(d)

def summary() -> dict:
    return _load()

def reset():
    _save(dict(_DEFAULT))
