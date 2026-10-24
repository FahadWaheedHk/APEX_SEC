"""
Reasoning engine.

Builds the system prompt, calls the local Ollama model, and produces the
four output formats the UI needs (Markdown, HTML, JSON, raw text).
Prompts are assembled from the vulnerability database and payload engine
so the model always has concrete ammunition in front of it.

Revision notes:
  - to_html() escapes user-controlled Markdown before rendering.
  - save_all() returns [] on total failure instead of raising.
  - generate() handles empty/malformed responses and connection drops.
"""

from __future__ import annotations

import hashlib
import html as _html
import json
import textwrap
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

from apex_core import (
    APP_NAME, APP_VERSION, MAX_PROMPT_CHARS, REPORTS_DIR,
    VulnerabilityEntry, TargetProfile, truncate_text, utc_now, logger,
)
from apex_payload import render_for_prompt as render_payloads
from apex_vulndb import (
    all_vulnerabilities, by_category as vuln_by_category,
    search as vuln_search, total as vuln_total, categories as vuln_categories,
)

try:
    from langchain_community.llms import Ollama
    _OLLAMA_AVAILABLE = True
except ImportError:
    Ollama = None
    _OLLAMA_AVAILABLE = False

try:
    import markdown as _md
    _MD_AVAILABLE = True
except ImportError:
    _md = None
    _MD_AVAILABLE = False


# ---------------------------------------------------------------------------
# Personas
# ---------------------------------------------------------------------------

PERSONAS: Dict[str, Dict[str, Any]] = {
    "apex-sec": {
        "label": "APEX-SEC (Default)",
        "prompt": (
            "You are APEX-SEC, a principal security researcher and lead "
            "penetration tester. You have 15+ years across offensive and "
            "defensive operations.\n\n"
            "Operating rules:\n"
            "- Move in stages. Never dump a wall of commands.\n"
            "- Ask for authorization scope before any active technique.\n"
            "- Explain the why before the what.\n"
            "- When the user pastes an error, diagnose first.\n"
            "- Reference real CVEs, MITRE ATT&CK IDs, and tool flags.\n"
            "- When a finding is confirmed, pivot toward a structured "
            "  write-up with CVSS and remediation."
        ),
    },
    "red-team-lead": {
        "label": "Red Team Lead",
        "prompt": (
            "You lead authorized adversary simulation. Specialties: initial "
            "access, persistence, privilege escalation, lateral movement, "
            "C2, and OPSEC. Every technique gets a MITRE ATT&CK ID and a "
            "one-line OPSEC warning."
        ),
    },
    "blue-team-analyst": {
        "label": "Blue Team Analyst",
        "prompt": (
            "You defend enterprise networks. Tools: Sigma, YARA, Snort, "
            "Suricata, Splunk SPL, Elastic EQL, Sentinel KQL. Every "
            "offensive technique ends with a detection angle."
        ),
    },
    "bug-bounty-hunter": {
        "label": "Bug Bounty Hunter",
        "prompt": (
            "You are a top-tier bug bounty hunter. Web, API, mobile. Your "
            "edge is business logic, race conditions, and chained exploits. "
            "You write reports that get accepted on first pass."
        ),
    },
    "exploit-dev": {
        "label": "Exploit Developer",
        "prompt": (
            "You develop exploits for memory corruption and modern "
            "mitigations. Stack overflows, heap grooming, UAF, type "
            "confusion, ROP/JOP, ASLR/DEP/CFG bypasses. You reason about "
            "mitigations before payload."
        ),
    },
    "cloud-security": {
        "label": "Cloud Security Architect",
        "prompt": (
            "You specialise in AWS, Azure, and GCP attack and defence. "
            "Privilege escalation via IAM, IMDS abuse, cross-account role "
            "chaining, S3/Blob/GCS exposures, Kubernetes RBAC and pod "
            "escape, serverless exploitation."
        ),
    },
    "api-security": {
        "label": "API Security Specialist",
        "prompt": (
            "You break REST, GraphQL, gRPC, and WebSocket APIs. Focus on "
            "OWASP API Top 10: BOLA, BFLA, mass assignment, unrestricted "
            "consumption, broken auth, SSRF. Every finding includes a raw "
            "HTTP request and reproducer."
        ),
    },
    "iot-security": {
        "label": "IoT / Hardware Hacker",
        "prompt": (
            "You assess embedded systems and IoT. Firmware extraction "
            "(binwalk), UART/JTAG/SPI, secure boot bypass, MQTT/CoAP/Zigbee/"
            "BLE, RTSP cameras, Modbus and S7 ICS, hardware fault injection."
        ),
    },
    "malware-analyst": {
        "label": "Malware Analyst",
        "prompt": (
            "You reverse-engineer malicious software. Static: IDA Pro, "
            "Ghidra, Binary Ninja. Dynamic: Cuckoo, CAPE, Procmon, "
            "Wireshark. Unpacking, deobfuscation, C2 protocol recovery, "
            "YARA authoring."
        ),
    },
    "social-engineer": {
        "label": "Social Engineer",
        "prompt": (
            "You conduct authorized social engineering. Pretexts, phishing "
            "infrastructure (GoPhish, Evilginx2), MFA fatigue, OAuth consent "
            "phishing, OSINT profiling, physical intrusion."
        ),
    },
    "compliance-auditor": {
        "label": "Compliance Auditor",
        "prompt": (
            "You map findings to PCI-DSS 4.0, HIPAA, SOC 2, ISO 27001, "
            "GDPR, NIST CSF, NIST 800-53. You translate vulnerabilities "
            "into business risk language executives accept."
        ),
    },
    "custom": {
        "label": "Custom Persona",
        "prompt": "Follow the operator's custom instructions exactly.",
    },
}


def persona_label(key: str) -> str:
    p = PERSONAS.get(key) or PERSONAS["apex-sec"]
    return p.get("label", key)


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

class PromptEngineer:

    INTEL_LIMIT = 15

    @staticmethod
    def _scope_block(target: TargetProfile) -> str:
        lines = ["## Engagement"]
        rows = [
            ("Target", target.ip_address or "unspecified"),
            ("Hostname", target.hostname or "unspecified"),
            ("OS", target.os_info or "unspecified"),
            ("Stack", target.technologies or "unknown"),
            ("Environment", target.environment or "lab"),
            ("Organization", target.organization or "unspecified"),
            ("Authorization", target.authorization_ref or "pending"),
            ("Scope", target.scope_notes or "not specified"),
        ]
        for k, v in rows:
            lines.append(f"- {k}: {v}")
        return "\n".join(lines)

    @classmethod
    def _vulndb_block(cls) -> str:
        cats = vuln_categories()
        lines = [f"## Vulnerability Catalogue ({vuln_total()} entries)"]
        for cat in cats[:20]:
            entries = vuln_by_category().get(cat, [])
            names = ", ".join(e["name"] for e in entries[:4])
            lines.append(f"- {cat}: {names}")
        return "\n".join(lines)

    @classmethod
    def _intel_block(cls, items: List[Dict[str, Any]]) -> str:
        if not items:
            return ""
        lines = ["## Recent CISA KEV Intelligence"]
        for item in items[:cls.INTEL_LIMIT]:
            cve = item.get("cveID", "N/A")
            name = (item.get("vulnerabilityName") or "Unknown")[:80]
            vendor = item.get("vendorProject", "")
            product = item.get("product", "")
            lines.append(f"- {cve}: {name} ({vendor} {product})".strip())
        return "\n".join(lines)

    @staticmethod
    def _directives(allow_payload: bool) -> str:
        payload_rule = (
            "Payload generation is enabled. Provide concrete, tested "
            "payloads with a one-line authorization reminder."
            if allow_payload else
            "Payload generation is disabled. Give conceptual and defensive "
            "guidance only."
        )
        return textwrap.dedent(f"""
            ## Directives

            1. Work in stages. Never more than three commands at once.
            2. Confirm scope before active testing.
            3. Structure every response:
               a) One-line read of the situation
               b) Numbered next steps
               c) Commands or payloads
               d) Verification step
            4. If the user pastes an error, diagnose before advancing.
            5. Reference real CVEs, ATT&CK IDs, and tool flags.
            6. When a finding is reported, offer a structured write-up.
            7. {payload_rule}
            8. Never invent CVE IDs or tool output.
            9. Flag destructive actions before they are run.
        """).strip()

    @classmethod
    def build(cls, persona_key: str, target: TargetProfile,
              allow_payload: bool, custom_prompt: str = "",
              cisa_items: Optional[List[Dict[str, Any]]] = None) -> str:
        persona = PERSONAS.get(persona_key) or PERSONAS["apex-sec"]
        persona_text = persona["prompt"]
        if persona_key == "custom" and custom_prompt.strip():
            persona_text = custom_prompt.strip()

        blocks = [
            f"# Role\n{persona_text}",
            f"# Scope\n{cls._scope_block(target)}",
            f"# {cls._directives(allow_payload)}",
            f"# {cls._vulndb_block()}",
            "## Reference Payloads\n" + render_payloads(limit=10),
        ]

        intel = cls._intel_block(cisa_items or [])
        if intel:
            blocks.append(f"# {intel}")

        blocks.append(
            "# Closing\nStay methodical. Confirm before acting. Keep the "
            "operator in the loop."
        )
        return truncate_text("\n\n".join(blocks), MAX_PROMPT_CHARS)


# ---------------------------------------------------------------------------
# LLM bridge
# ---------------------------------------------------------------------------

class LLMBridge:

    def __init__(self, config) -> None:
        self.config = config
        self._instance = None
        self._sig = ""
        self._last_error = ""

    def is_available(self) -> bool:
        if not _OLLAMA_AVAILABLE:
            return False
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=3)
            return r.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def list_models(self) -> List[str]:
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=5)
            if r.status_code != 200:
                return []
            return [m.get("name", "") for m in r.json().get("models", [])]
        except (requests.exceptions.RequestException, json.JSONDecodeError):
            return []

    def _signature(self, system_prompt: str) -> str:
        parts = "|".join([
            str(self.config.get("model")),
            str(self.config.get("temperature")),
            str(self.config.get("top_p")),
            str(self.config.get("num_predict")),
            hashlib.sha1(system_prompt.encode("utf-8")).hexdigest(),
        ])
        return hashlib.sha1(parts.encode("utf-8")).hexdigest()

    def _build(self, system_prompt: str):
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

    def get_instance(self, system_prompt: str):
        sig = self._signature(system_prompt)
        if self._instance is not None and self._sig == sig:
            return self._instance
        self._instance = self._build(system_prompt)
        self._sig = sig if self._instance else ""
        return self._instance

    def invalidate(self) -> None:
        self._instance = None
        self._sig = ""
        self._last_error = ""

    @property
    def last_error(self) -> str:
        return self._last_error

    def generate(self, prompt: str, system_prompt: str) -> Tuple[bool, str]:
        llm = self.get_instance(system_prompt)
        if llm is None:
            return False, self._last_error or (
                "AI engine offline. Start Ollama:\n"
                "  ollama serve\n"
                "  ollama pull llama3"
            )
        try:
            response = llm.invoke(prompt)
            if not response or not str(response).strip():
                return False, "Model returned an empty response."
            return True, str(response)
        except requests.exceptions.ConnectionError:
            self.invalidate()
            return False, "Lost connection to Ollama."
        except Exception as exc:
            logger.error("Generation failed: %s", exc)
            self._last_error = f"Generation error: {exc}"
            return False, self._last_error

    def health(self) -> Dict[str, Any]:
        models = self.list_models()
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

    @classmethod
    def _risk(cls, summary: Dict[str, int]) -> str:
        if summary.get("Critical", 0):
            return "CRITICAL - Immediate action required"
        if summary.get("High", 0):
            return "HIGH - Remediation required urgently"
        if summary.get("Medium", 0):
            return "MEDIUM - Schedule remediation"
        if summary.get("Low", 0) or summary.get("Info", 0):
            return "LOW - Monitor and address over time"
        return "INFORMATIONAL - No findings recorded"

    @classmethod
    def _chart(cls, summary: Dict[str, int]) -> str:
        if not summary:
            return "No findings."
        top = max(summary.values()) or 1
        lines = []
        for sev in cls.SEVERITY_ORDER:
            count = summary.get(sev, 0)
            if not count:
                continue
            bar = "#" * max(1, int(count / top * 30))
            lines.append(f"{sev:<10} | {bar} {count}")
        return "\n".join(lines) if lines else "No findings."

    @staticmethod
    def _row(k: str, v: Any) -> str:
        return f"| {k} | {v if v not in (None, '') else '-'} |"

    @classmethod
    def _finding_md(cls, idx: int, v: VulnerabilityEntry,
                    evidence: List[Dict[str, Any]]) -> List[str]:
        out = [f"### {idx}. {v.title or v.cve_id}", ""]
        out.append("| Attribute | Value |")
        out.append("| --- | --- |")
        out.append(cls._row("Identifier", v.cve_id))
        out.append(cls._row("Severity", v.severity))
        if v.cvss_score:
            out.append(cls._row("CVSS", f"{v.cvss_score} {v.cvss_vector}".strip()))
        if v.tools_used:
            out.append(cls._row("Tools", ", ".join(v.tools_used)))
        out.append("")
        if v.description:
            out += ["**Description**", "", v.description.strip(), ""]
        if v.impact:
            out += ["**Impact**", "", v.impact.strip(), ""]
        if v.steps_to_reproduce:
            out.append("**Steps to Reproduce**")
            out.append("")
            for i, s in enumerate(v.steps_to_reproduce, 1):
                out.append(f"{i}. {s.strip()}")
            out.append("")
        if evidence:
            out.append("**Evidence**")
            out.append("")
            for ev in evidence:
                cap = f" - {ev['caption']}" if ev.get("caption") else ""
                out.append(f"- `{ev['filename']}`{cap}")
            out.append("")
        if v.mitigation:
            out += ["**Remediation**", "", v.mitigation.strip(), ""]
        if v.references:
            out.append("**References**")
            out.append("")
            for r in v.references:
                out.append(f"- {r}")
            out.append("")
        out.append("---")
        out.append("")
        return out

    @classmethod
    def to_markdown(cls, tracker, evidence: List[Dict[str, Any]],
                    session_id: str, author: str = "Security Researcher",
                    org: str = "Independent") -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        summary = tracker.summary()
        target = tracker.target

        lines = [
            "# Security Assessment Report", "",
            f"**Report ID:** APEX-{session_id[:8].upper()}",
            f"**Date:** {now}",
            f"**Author:** {author}",
            f"**Organization:** {org}",
            f"**Engine:** {APP_NAME} v{APP_VERSION}", "",
            "---", "",
            "## 1. Executive Summary", "",
            f"**Overall Risk:** {cls._risk(summary)}", "",
            f"**Total Findings:** {len(tracker.findings)}", "",
            "### Severity Distribution", "", "```",
            cls._chart(summary), "```", "",
            "---", "",
            "## 2. Engagement Scope", "",
            "| Field | Value |", "| --- | --- |",
            cls._row("Target", target.ip_address),
            cls._row("Hostname", target.hostname),
            cls._row("Operating System", target.os_info),
            cls._row("Stack", target.technologies),
            cls._row("Environment", target.environment),
            cls._row("Organization", target.organization),
            cls._row("Authorization", target.authorization_ref),
            cls._row("Scope Notes", target.scope_notes),
            "", "---", "", "## 3. Findings", "",
        ]
        if not tracker.findings:
            lines.append("_No findings recorded._")
            lines.append("")
        else:
            for idx, v in enumerate(tracker.findings, 1):
                linked = [e for e in evidence
                          if e.get("linked_cve") == v.cve_id]
                lines.extend(cls._finding_md(idx, v, linked))
        lines += [
            "## 4. Methodology", "",
            "Testing followed OWASP Testing Guide, PTES, and MITRE "
            "ATT&CK. All activity was performed under documented "
            "authorization.", "",
            "---", "",
            "## 5. Disclaimer", "",
            "This report is for authorized security assessment only.", "",
            "---", "",
            f"_Generated by {APP_NAME} v{APP_VERSION} on {now}._",
        ]
        return "\n".join(lines)

    @classmethod
    def to_html(cls, md_text: str, title: str = "Security Report") -> str:
        safe_md = _html.escape(md_text, quote=False)
        if _MD_AVAILABLE:
            body = _md.markdown(
                safe_md,
                extensions=["extra", "tables", "fenced_code", "sane_lists"],
            )
        else:
            body = f"<pre>{safe_md}</pre>"
        safe_title = _html.escape(title)
        css = """
        :root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#c9d1d9;
        --muted:#8b949e;--accent:#58a6ff;}
        body{background:var(--bg);color:var(--text);
        font-family:-apple-system,"Segoe UI",Roboto,sans-serif;
        max-width:940px;margin:40px auto;padding:24px;line-height:1.65;}
        h1,h2,h3{color:var(--accent);border-bottom:1px solid var(--border);
        padding-bottom:6px;margin-top:32px;}
        a{color:var(--accent);}
        code{color:#79c0ff;background:var(--surface);padding:1px 5px;
        border-radius:4px;font-size:0.9em;}
        pre{background:var(--surface);border:1px solid var(--border);
        padding:14px;border-radius:6px;overflow-x:auto;}
        table{border-collapse:collapse;width:100%;margin:16px 0;}
        th,td{border:1px solid var(--border);padding:8px 10px;
        text-align:left;vertical-align:top;}
        th{background:var(--surface);color:var(--accent);font-weight:600;}
        hr{border:0;border-top:1px solid var(--border);margin:28px 0;}
        """
        return (
            f"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
            f"<meta charset=\"utf-8\">\n"
            f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>{safe_title}</title>\n<style>{css}</style>\n</head>\n"
            f"<body>\n{body}\n</body>\n</html>\n"
        )

    @classmethod
    def to_json(cls, tracker, evidence: List[Dict[str, Any]],
                session_id: str) -> str:
        payload = {
            "report_id": f"APEX-{session_id[:8].upper()}",
            "generated_at": utc_now(),
            "engine": f"{APP_NAME} v{APP_VERSION}",
            "target": asdict(tracker.target),
            "summary": tracker.summary(),
            "risk_rating": cls._risk(tracker.summary()),
            "findings": [asdict(v) for v in tracker.findings],
            "evidence": evidence,
        }
        return json.dumps(payload, indent=4, ensure_ascii=False, default=str)

    @classmethod
    def save_all(cls, md: str, html: str, js: str,
                 reports_dir=None) -> List:
        from pathlib import Path
        base = Path(reports_dir) if reports_dir else REPORTS_DIR
        try:
            base.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.error("Cannot create reports dir: %s", exc)
            return []
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = []
        for ext, content in (("md", md), ("html", html), ("json", js)):
            path = base / f"apex_report_{stamp}.{ext}"
            try:
                path.write_text(content, encoding="utf-8")
                out.append(path)
            except OSError as exc:
                logger.error("Report save failed: %s", exc)
        return out
