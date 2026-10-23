"""
APEX-SEC Core Foundation.

Holds the pieces every other module depends on: constants, logging,
configuration, and the SQLite-backed memory store. Nothing here talks
to the network or to a model -- it is pure plumbing so the higher layers
stay readable.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

APP_NAME = "APEX-SEC"
APP_VERSION = "2.0.0"
APP_TAGLINE = "Advanced Cyber Operations Engine"

BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
EVIDENCE_DIR = CONFIG_DIR / "evidence"
REPORTS_DIR = CONFIG_DIR / "reports"
DB_PATH = CONFIG_DIR / "apex_memory.db"
CONFIG_FILE = CONFIG_DIR / "apex_config.json"
KB_FILE = CONFIG_DIR / "threat_intel.json"
LOG_FILE = CONFIG_DIR / "apex_sec.log"

for _d in (CONFIG_DIR, EVIDENCE_DIR, REPORTS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

MAX_PROMPT_CHARS = 24000
HTTP_TIMEOUT = 20
MAX_RETRIES = 3


def _init_logger() -> logging.Logger:
    log = logging.getLogger(APP_NAME)
    if log.handlers:
        return log
    log.setLevel(logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    try:
        fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except OSError:
        pass
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    return log


logger = _init_logger()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_name(value: str, limit: int = 80) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return (cleaned or "artifact")[:limit]


def human_size(num: int) -> str:
    size = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def truncate_text(text: str, limit: int = MAX_PROMPT_CHARS) -> str:
    if len(text) <= limit:
        return text
    head = int(limit * 0.7)
    tail = limit - head - 40
    return text[:head] + "\n...[truncated]...\n" + text[-tail:]


_MISSING = object()


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------

@dataclass
class VulnerabilityEntry:
    cve_id: str
    severity: str
    title: str = ""
    description: str = ""
    mitigation: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    impact: str = ""
    category: str = ""
    references: List[str] = field(default_factory=list)
    evidence_paths: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    steps_to_reproduce: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=utc_now)


@dataclass
class TargetProfile:
    ip_address: str = ""
    hostname: str = ""
    os_info: str = "Unknown"
    mac_address: str = "Unknown"
    environment: str = "lab"
    scope_notes: str = ""
    organization: str = ""
    authorization_ref: str = ""
    technologies: str = ""
    timestamp: str = field(default_factory=utc_now)


@dataclass
class EvidenceItem:
    evidence_id: str
    filename: str
    filepath: str
    mime_type: str
    size_bytes: int
    caption: str = ""
    linked_cve: str = ""
    extracted_text: str = ""
    timestamp: str = field(default_factory=utc_now)


# ---------------------------------------------------------------------------
# Config manager
# ---------------------------------------------------------------------------

class ConfigManager:
    DEFAULTS: Dict[str, Any] = {
        "model": "llama3",
        "temperature": 0.35,
        "top_p": 0.92,
        "num_predict": 3072,
        "context_messages": 40,
        "context_char_budget": MAX_PROMPT_CHARS,
        "persona": "apex-sec",
        "allow_payload_gen": True,
        "auto_payload_engine": True,
        "custom_prompt": "",
        "report_author": "Security Researcher",
        "report_org": "Independent",
        "enable_ocr": False,
        "require_scope_ack": True,
    }

    def __init__(self, path: Path = CONFIG_FILE) -> None:
        self._path = path
        self._data = dict(self.DEFAULTS)
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            self._save()
            return
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict):
                for k in self.DEFAULTS:
                    if k in raw:
                        self._data[k] = raw[k]
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Config load failed: %s", exc)

    def _save(self) -> None:
        try:
            tmp = self._path.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, ensure_ascii=False)
            tmp.replace(self._path)
        except OSError as exc:
            logger.error("Config save failed: %s", exc)

    def get(self, key: str, default: Any = _MISSING) -> Any:
        if default is _MISSING:
            return self._data.get(key, self.DEFAULTS.get(key))
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> bool:
        if self._data.get(key) == value:
            return False
        self._data[key] = value
        self._save()
        return True

    def update(self, values: Dict[str, Any]) -> bool:
        changed = False
        for k, v in values.items():
            if self._data.get(k) != v:
                self._data[k] = v
                changed = True
        if changed:
            self._save()
        return changed


# ---------------------------------------------------------------------------
# Memory manager
# ---------------------------------------------------------------------------

class MemoryManager:
    """SQLite-backed store for sessions, messages, and evidence."""

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self._db_path = str(db_path)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def _init_schema(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS sessions (
                        session_id  TEXT PRIMARY KEY,
                        title       TEXT NOT NULL,
                        created_at  TEXT NOT NULL,
                        updated_at  TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS messages (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id  TEXT NOT NULL,
                        role        TEXT NOT NULL,
                        content     TEXT NOT NULL,
                        meta        TEXT,
                        created_at  TEXT NOT NULL,
                        FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                            ON DELETE CASCADE
                    );
                    CREATE TABLE IF NOT EXISTS evidence (
                        evidence_id TEXT PRIMARY KEY,
                        session_id  TEXT NOT NULL,
                        filename    TEXT NOT NULL,
                        filepath    TEXT NOT NULL,
                        mime_type   TEXT NOT NULL,
                        size_bytes  INTEGER NOT NULL,
                        caption     TEXT,
                        linked_cve  TEXT,
                        extracted_text TEXT,
                        created_at  TEXT NOT NULL,
                        FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                            ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_messages_session
                        ON messages(session_id, id);
                    CREATE INDEX IF NOT EXISTS idx_evidence_session
                        ON evidence(session_id);
                    """
                )
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("Schema init failed: %s", exc)

    def create_session(self, title: str = "New Session",
                       session_id: Optional[str] = None) -> str:
        sid = session_id or str(uuid.uuid4())
        now = utc_now()
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO sessions VALUES (?, ?, ?, ?)",
                    (sid, title, now, now),
                )
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("Session create failed: %s", exc)
        return sid

    def list_sessions(self) -> List[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM sessions ORDER BY updated_at DESC"
                ).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.Error:
            return []

    def delete_session(self, session_id: str) -> None:
        try:
            with self._connect() as conn:
                conn.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
                conn.execute("DELETE FROM evidence WHERE session_id = ?", (session_id,))
                conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("Delete failed: %s", exc)

    def add_message(self, session_id: str, role: str, content: str,
                    meta: Optional[Dict[str, Any]] = None) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO messages (session_id, role, content, meta, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (session_id, role, content, json.dumps(meta or {}), utc_now()),
                )
                conn.execute(
                    "UPDATE sessions SET updated_at = ? WHERE session_id = ?",
                    (utc_now(), session_id),
                )
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("Message add failed: %s", exc)

    def get_messages(self, session_id: str, limit: Optional[int] = None,
                     include_errors: bool = False) -> List[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                if limit:
                    rows = conn.execute(
                        "SELECT * FROM ("
                        "  SELECT * FROM messages WHERE session_id = ? "
                        "  ORDER BY id DESC LIMIT ?"
                        ") ORDER BY id ASC",
                        (session_id, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM messages WHERE session_id = ? ORDER BY id ASC",
                        (session_id,),
                    ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                if not include_errors:
                    try:
                        meta = json.loads(d.get("meta") or "{}")
                    except json.JSONDecodeError:
                        meta = {}
                    if meta.get("error"):
                        continue
                out.append(d)
            return out
        except sqlite3.Error:
            return []

    def count_messages(self, session_id: str) -> int:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) AS c FROM messages WHERE session_id = ?",
                    (session_id,),
                ).fetchone()
            return int(row["c"]) if row else 0
        except sqlite3.Error:
            return 0

    def build_context(self, session_id: str, last_n: int = 40,
                      char_budget: int = MAX_PROMPT_CHARS) -> str:
        msgs = self.get_messages(session_id, limit=last_n, include_errors=False)
        if not msgs:
            return ""
        chunks: List[str] = []
        total = 0
        for m in reversed(msgs):
            entry = f"{m['role'].capitalize()}: {m['content']}"
            if total + len(entry) > char_budget:
                break
            chunks.append(entry)
            total += len(entry)
        chunks.reverse()
        return "\n\n".join(chunks)

    def add_evidence(self, session_id: str, filename: str, filepath: str,
                     mime_type: str, size_bytes: int, caption: str = "",
                     linked_cve: str = "", extracted_text: str = "") -> str:
        eid = str(uuid.uuid4())
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (eid, session_id, filename, filepath, mime_type,
                     size_bytes, caption, linked_cve, extracted_text, utc_now()),
                )
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("Evidence add failed: %s", exc)
        return eid

    def list_evidence(self, session_id: str) -> List[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM evidence WHERE session_id = ? ORDER BY created_at ASC",
                    (session_id,),
                ).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.Error:
            return []

    def delete_evidence(self, evidence_id: str) -> None:
        try:
            with self._connect() as conn:
                conn.execute("DELETE FROM evidence WHERE evidence_id = ?", (evidence_id,))
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("Evidence delete failed: %s", exc)
