"""
Operational layer: vulnerability tracker, chat orchestrator, session
bootstrap. Nothing here knows about Streamlit -- the UI calls into this
module and the CLI can too.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Tuple

from apex_core import (
    MAX_PROMPT_CHARS, VulnerabilityEntry, TargetProfile, human_size,
    truncate_text, utc_now, logger,
)
from apex_engine import PromptEngineer, LLMBridge
from apex_intel_dummy import load_threat_intel  # placeholder; see below


# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------

class VulnerabilityTracker:
    """In-memory store for the current engagement."""

    def __init__(self, system_id: str = "TARGET-ASSET-01") -> None:
        self.system_id = system_id
        self.findings: List[VulnerabilityEntry] = []
        self.target: TargetProfile = TargetProfile()

    def set_target(self, profile: TargetProfile) -> None:
        self.target = profile
        logger.info(
            "Target updated: %s (%s)",
            profile.ip_address or "n/a", profile.environment,
        )

    def has_authorization(self) -> bool:
        return bool(self.target.authorization_ref.strip())

    def add(self, entry: VulnerabilityEntry) -> bool:
        if not entry.cve_id.strip():
            return False
        for existing in self.findings:
            if existing.cve_id == entry.cve_id:
                logger.info("Duplicate finding %s skipped", entry.cve_id)
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

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def export_json(self) -> str:
        return json.dumps({
            "system_id": self.system_id,
            "target": asdict(self.target),
            "findings": [asdict(f) for f in self.findings],
            "summary": self.summary(),
            "exported_at": utc_now(),
        }, indent=4, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class ChatOrchestrator:
    """Runs one conversational turn against the local model."""

    def __init__(self, memory, config, bridge: LLMBridge) -> None:
        self.memory = memory
        self.config = config
        self.bridge = bridge

    def _evidence_context(self, session_id: str) -> str:
        items = self.memory.list_evidence(session_id)
        if not items:
            return ""
        blocks = []
        for ev in items[-6:]:
            header = f"[Evidence] {ev['filename']} ({human_size(ev['size_bytes'])})"
            if ev.get("linked_cve"):
                header += f" - linked to {ev['linked_cve']}"
            if ev.get("caption"):
                header += f"\nCaption: {ev['caption']}"
            if ev.get("extracted_text"):
                text = ev["extracted_text"].strip()
                if len(text) > 800:
                    text = text[:800] + "...[truncated]"
                header += f"\nExtracted text:\n{text}"
            blocks.append(header)
        return "\n\n".join(blocks)

    def _build_user_prompt(self, session_id: str, user_input: str) -> str:
        context = self.memory.build_context(
            session_id,
            last_n=int(self.config.get("context_messages", 40)),
            char_budget=int(self.config.get("context_char_budget", MAX_PROMPT_CHARS)),
        )
        evidence = self._evidence_context(session_id)
        parts = []
        if context:
            parts.append("[Conversation so far]\n" + context)
        if evidence:
            parts.append("[Attached evidence]\n" + evidence)
        parts.append("[Current request]\n" + user_input.strip())
        return truncate_text(
            "\n\n".join(parts),
            int(self.config.get("context_char_budget", MAX_PROMPT_CHARS)),
        )

    def process(self, session_id: str, user_input: str, tracker,
                include_payload_hints: bool = False) -> Tuple[bool, str]:
        user_input = (user_input or "").strip()
        if not user_input:
            return False, "Empty input."

        self.memory.add_message(session_id, "user", user_input)

        system_prompt = PromptEngineer.build(
            persona_key=str(self.config.get("persona")),
            target=tracker.target,
            allow_payload=bool(self.config.get("allow_payload_gen")),
            custom_prompt=str(self.config.get("custom_prompt", "")),
            cisa_items=load_threat_intel(),
        )
        user_prompt = self._build_user_prompt(session_id, user_input)

        ok, response = self.bridge.generate(user_prompt, system_prompt)
        if ok:
            self.memory.add_message(session_id, "assistant", response)
        else:
            self.memory.add_message(
                session_id, "assistant",
                f"[engine error] {response}",
                meta={"error": True},
            )
        return ok, response


# ---------------------------------------------------------------------------
# Session bootstrap
# ---------------------------------------------------------------------------

def bootstrap_session_state() -> None:
    """Populate Streamlit session_state. Safe to call many times."""
    try:
        import streamlit as st
    except ImportError:
        return

    from apex_core import ConfigManager, MemoryManager

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
