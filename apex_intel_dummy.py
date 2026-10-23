"""
Minimal threat-intel shim.

The original APEX-SEC bundled a full CISA/NVD sync module. That code
pulled a lot of network dependencies we don't need on day one. This
shim keeps the same interface (load_threat_intel) so the orchestrator
and UI keep working, but the data is whatever you drop into
config/threat_intel.json yourself.

If you want the live CISA feed back, drop the sync_cisa_feed function
from the previous version into this file -- nothing else has to change.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from apex_core import KB_FILE, logger

_CACHE: List[Dict[str, Any]] | None = None


def load_threat_intel() -> List[Dict[str, Any]]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    if not KB_FILE.exists():
        _CACHE = []
        return _CACHE
    try:
        with KB_FILE.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            _CACHE = data.get("vulnerabilities", []) or []
        elif isinstance(data, list):
            _CACHE = data
        else:
            _CACHE = []
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Intel load failed: %s", exc)
        _CACHE = []
    return _CACHE


def clear_cache() -> None:
    global _CACHE
    _CACHE = None
