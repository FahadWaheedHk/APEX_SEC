"""
Operations layer.

Holds the per-session vulnerability tracker, the chat orchestrator, and
the Streamlit session bootstrap. Also enforces the authorization gate
that apex_ui.py and the orchestrator both depend on.

Authorization model (v2.0):

  - A target is only "in scope" if an authorization reference is set
    AND the target host matches one of the approved scope entries.
  - Approved scope is stored on the TargetProfile as a comma-separated
    list of hostnames/IPs/CIDRs in `scope_notes`.
  - Active operations (LLM calls that allow payload generation) are
    denied when the target is out of scope. The UI surfaces the reason.
  - This is a guardrail, not a legal contract.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Tuple

from apex_core import (
    APP_NAME, APP_VERSION, ConfigManager, MemoryManager,
    TargetProfile, VulnerabilityEntry, logger, utc_now,
)
from apex_engine import (
    LLMBridge, PromptEngineer, PERSONAS,
)
from apex_intel_dummy import load_threat_intel


# ---------------------------------------------------------------------------
# Target / scope matching
# ---------------------------------------------------------------------------

def _normalize_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def _host_in_cidr(host: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(
            cidr, strict=False
        )
    except ValueError:
        return False


def _scope_matches(target: str, scope_entries: List[str]) -> bool:
    t = _normalize_host(target)
    if not t:
        return False
    for entry in scope_entries:
        e = _normalize_host(entry)
        if not e:
            continue
        if "/" in e and _host_in_cidr(t, e):
            return True
        if e == t:
            return True
        if e.startswith("*.") and t.endswith(e[1:]):
            return True
        if not e.startswith("*") and t.endswith("." + e):
            return True
    return False


# ---------------------------------------------------------------------------
# Vulnerability tracker
# ---------------------------------------------------------------------------

class VulnerabilityTracker:
    """
    Per-session collection of findings plus the active target profile.
    Deduplication is case- and whitespace-insensitive on cve_id.
    """

    def __init__(self, target: Optional[TargetProfile] = None) -> None:
        self.target: TargetProfile = target or TargetProfile()
        self.findings: List[VulnerabilityEntry] = []
        self._index: Dict[str, VulnerabilityEntry] = {}

    def set_target(self, target: TargetProfile) -> None:
        self.target = target

    def approved_scope(self) -> List[str]:
        raw = self.target.scope_notes or ""
        tokens = re.split(r"[,;\n]+", raw)
        return [t.strip() for t in tokens if t.strip()]

    def has_authorization(self) -> bool:
        if not (self.target.authorization_ref or "").strip():
            return False
        if not self.approved_scope():
            return False
        return True

    def target_in_scope(self) -> Tuple[bool, str]:
        if not self.has_authorization():
            return False, "No authorization reference or approved scope set."
        candidate = (
            self.target.ip_address
            or self.target.hostname
            or ""
        ).strip()
        if not candidate:
            return False, "No target host/IP set."
        scope = self.approved_scope()
        if _scope_matches(candidate, scope):
            return True, ""
        return False, (
            f"Target '{candidate}' is not in approved scope "
            f"({', '.join(scope)})."
        )

    @staticmethod
    def _norm_id(cve_id: str) -> str:
        return (cve_id or "").strip().upper()

    def add(self, finding: VulnerabilityEntry) -> bool:
        key = self._norm_id(finding.cve_id)
        if not key:
            return False
        if key in self._index:
            return False
        self.findings.append(finding)
        self._index[key] = finding
        return True

    def remove(self, cve_id: str) -> bool:
        key = self._norm_id(cve_id)
        entry = self._index.pop(key, None)
        if entry is None:
            return False
        try:
            self.findings.remove(entry)
        except ValueError:
            pass
        return True

    def get(self, cve_id: str) -> Optional[VulnerabilityEntry]:
        return self._index.get(self._norm_id(cve_id))

    def summary(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for v in self.findings:
            sev = (v.severity or "Info").strip().capitalize()
            out[sev] = out.get(sev, 0) + 1
        return out

    def clear(self) -> None:
        self.findings.clear()
        self._index.clear()


# ---------------------------------------------------------------------------
# Chat orchestrator
# ---------------------------------------------------------------------------

class ChatOrchestrator:
    """
    Wires the prompt builder, LLM bridge, and memory store together.
    Enforces the authorization gate before active operations.
    """

    def __init__(self, config: ConfigManager, memory: MemoryManager,
                 bridge: LLMBridge) -> None:
        self.config = config
        self.memory = memory
        self.bridge = bridge

    def _build_system_prompt(self, tracker: VulnerabilityTracker) -> str:
        allow = bool(self.config.get("allow_payload_gen"))
        return PromptEngineer.build(
            persona_key=str(self.config.get("persona")),
            target=tracker.target,
            allow_payload=allow,
            custom_prompt=str(self.config.get("custom_prompt", "")),
            cisa_items=load_threat_intel(),
        )

    def process(self, session_id: str, user_input: str,
                tracker: VulnerabilityTracker) -> Tuple[bool, str]:
        allow_payload = bool(self.config.get("allow_payload_gen"))
        if allow_payload:
            in_scope, reason = tracker.target_in_scope()
            if not in_scope:
                msg = (
                    "Refusing to run active operations.\n\n"
                    f"{reason}\n\n"
                    "Set an authorization reference and an approved scope "
                    "in the sidebar before continuing."
                )
                self.memory.add_message(
                    session_id, "assistant", msg,
                    meta={"error": True, "reason": "out_of_scope"},
                )
                return False, msg

        self.memory.add_message(session_id, "user", user_input)

        depth = int(self.config.get("context_messages") or 40)
        budget = int(self.config.get("context_char_budget") or 24000)
        history = self.memory.build_context(
            session_id, last_n=depth, char_budget=budget
        )
        system_prompt = self._build_system_prompt(tracker)

        prompt = user_input
        if history:
            prompt = (
                "Conversation so far (for context):\n\n"
                f"{history}\n\n---\n\n"
                f"Current request:\n{user_input}"
            )

        ok, response = self.bridge.generate(prompt, system_prompt)

        if ok:
            self.memory.add_message(
                session_id, "assistant", response,
                meta={"persona": self.config.get("persona"),
                      "model": self.config.get("model")},
            )
        else:
            self.memory.add_message(
                session_id, "assistant", response,
                meta={"error": True, "reason": "llm_error"},
            )
        return ok, response


# ---------------------------------------------------------------------------
# Streamlit bootstrap
# ---------------------------------------------------------------------------

def bootstrap_session_state() -> None:
    """
    Idempotent init of everything apex_ui.py expects in st.session_state.
    Safe to call on every rerun.
    """
    import streamlit as st

    if "config_mgr" not in st.session_state:
        st.session_state.config_mgr = ConfigManager()
    config: ConfigManager = st.session_state.config_mgr

    if "memory" not in st.session_state:
        st.session_state.memory = MemoryManager()
    memory: MemoryManager = st.session_state.memory

    if "llm_bridge" not in st.session_state:
        st.session_state.llm_bridge = LLMBridge(config)
    bridge: LLMBridge = st.session_state.llm_bridge

    if "orchestrator" not in st.session_state:
        st.session_state.orchestrator = ChatOrchestrator(
            config, memory, bridge
        )

    if "v_tracker" not in st.session_state:
        st.session_state.v_tracker = VulnerabilityTracker()

    if "session_id" not in st.session_state:
        st.session_state.session_id = memory.create_session(
            title="New Engagement"
        )
