"""
Threat-intel module for APEX-SEC.

Two data sources:

1. Local cache at config/threat_intel.json (offline-first).
2. Live CISA Known Exploited Vulnerabilities JSON feed, fetched on demand
   by the UI's "Sync CISA" button.

The sync is intentionally conservative:
  - only updates the cache on a fully validated response
  - writes atomically (tmp + replace) so a crash cannot corrupt the file
  - preserves the previous cache if the network or schema check fails
  - keeps the existing load_threat_intel() interface intact

Live feed:
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from apex_core import KB_FILE, HTTP_TIMEOUT, logger

CISA_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

MAX_CACHE_ENTRIES = 5000

_CACHE: Optional[List[Dict[str, Any]]] = None


# ---------------------------------------------------------------------------
# Cache read
# ---------------------------------------------------------------------------

def load_threat_intel(force_reload: bool = False) -> List[Dict[str, Any]]:
    """
    Return the cached threat-intel list. Never performs network I/O.
    Call sync_cisa_feed() explicitly to refresh the cache.
    """
    global _CACHE
    if _CACHE is not None and not force_reload:
        return _CACHE
    if not KB_FILE.exists():
        _CACHE = []
        return _CACHE
    try:
        with KB_FILE.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Intel load failed: %s", exc)
        _CACHE = []
        return _CACHE

    if isinstance(data, dict):
        items = data.get("vulnerabilities", []) or []
    elif isinstance(data, list):
        items = data
    else:
        items = []

    _CACHE = [i for i in items if isinstance(i, dict)]
    return _CACHE


def clear_cache() -> None:
    global _CACHE
    _CACHE = None


def cache_info() -> Dict[str, Any]:
    """Return metadata about the current cache for the UI status panel."""
    if not KB_FILE.exists():
        return {"exists": False, "count": 0, "last_sync": None,
                "path": str(KB_FILE)}
    try:
        stat = KB_FILE.stat()
        last_sync = datetime.fromtimestamp(
            stat.st_mtime, tz=timezone.utc
        ).isoformat()
    except OSError:
        last_sync = None
    return {
        "exists": True,
        "count": len(load_threat_intel()),
        "last_sync": last_sync,
        "path": str(KB_FILE),
    }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_item(item: Any) -> bool:
    """A KEV entry must have at least cveID and vulnerabilityName."""
    if not isinstance(item, dict):
        return False
    cve = item.get("cveID")
    name = item.get("vulnerabilityName")
    if not isinstance(cve, str) or not cve.strip():
        return False
    if not isinstance(name, str) or not name.strip():
        return False
    return True


def _parse_feed(payload: Any) -> Tuple[bool, List[Dict[str, Any]], str]:
    """
    Validate the raw JSON payload from CISA. Returns (ok, items, error).

    Accepts two shapes seen in the wild:
      - {"vulnerabilities": [ ... ]}
      - [ ... ]
    """
    if isinstance(payload, dict):
        raw = payload.get("vulnerabilities")
        if not isinstance(raw, list):
            return False, [], "Missing 'vulnerabilities' list in feed."
    elif isinstance(payload, list):
        raw = payload
    else:
        return False, [], "Feed root is neither dict nor list."

    if not raw:
        return False, [], "Feed contains zero entries."

    valid: List[Dict[str, Any]] = []
    for item in raw:
        if _validate_item(item):
            valid.append(item)
        if len(valid) >= MAX_CACHE_ENTRIES:
            break

    if not valid:
        return False, [], "No entries passed schema validation."

    return True, valid, ""


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------

def _write_atomic(path: Path, data: Any) -> None:
    """Write JSON atomically: tmp file first, then os.replace()."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        logger.error("Atomic write failed: %s", exc)
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Live sync
# ---------------------------------------------------------------------------

def sync_cisa_feed(timeout: int = HTTP_TIMEOUT) -> Dict[str, Any]:
    """
    Fetch the CISA KEV feed, validate it, and update the local cache.

    Returns a dict with keys: ok, count, last_sync, error.
    """
    global _CACHE

    try:
        resp = requests.get(
            CISA_FEED_URL,
            timeout=timeout,
            headers={"User-Agent": "APEX-SEC/2.0 (+local)"},
        )
    except requests.exceptions.Timeout:
        return _sync_result(False, "CISA feed request timed out.")
    except requests.exceptions.RequestException as exc:
        return _sync_result(False, f"Network error: {exc}")

    if resp.status_code != 200:
        return _sync_result(
            False, f"CISA returned HTTP {resp.status_code}."
        )

    try:
        payload = resp.json()
    except ValueError as exc:
        return _sync_result(False, f"Invalid JSON: {exc}")

    ok, items, err = _parse_feed(payload)
    if not ok:
        return _sync_result(False, f"Validation failed: {err}")

    envelope = {
        "source": CISA_FEED_URL,
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "count": len(items),
        "vulnerabilities": items,
    }
    try:
        _write_atomic(KB_FILE, envelope)
    except OSError as exc:
        return _sync_result(False, f"Cache write failed: {exc}")

    _CACHE = items
    logger.info("CISA sync complete: %d entries", len(items))
    return _sync_result(True, "")


def _sync_result(ok: bool, error: str) -> Dict[str, Any]:
    info = cache_info()
    return {
        "ok": ok,
        "count": info["count"],
        "last_sync": info["last_sync"],
        "error": error,
    }


# ---------------------------------------------------------------------------
# Convenience search (used by the Tools tab)
# ---------------------------------------------------------------------------

def search_intel(keyword: str, limit: int = 50) -> List[Dict[str, Any]]:
    kw = (keyword or "").strip().lower()
    if not kw:
        return []
    tokens = kw.split()
    out: List[Dict[str, Any]] = []
    for item in load_threat_intel():
        blob = " ".join([
            str(item.get("cveID", "")),
            str(item.get("vulnerabilityName", "")),
            str(item.get("vendorProject", "")),
            str(item.get("product", "")),
            str(item.get("shortDescription", "")),
        ]).lower()
        if all(t in blob for t in tokens):
            out.append(item)
            if len(out) >= limit:
                break
    return out
