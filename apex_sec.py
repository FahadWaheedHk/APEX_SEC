#!/usr/bin/env python3
"""
APEX-SEC main entry point.

Verifies every module is importable, then either boots the Streamlit UI
or falls back to a CLI self-test. The presence check runs first so a
missing file produces a clear error instead of an obscure ImportError
deep in the import chain.

Module map:
    apex_core.py         Configuration, memory, models, logging
    apex_vulndb.py       100+ vulnerability classes
    apex_payload.py      Curated payloads, WAF engine, novel-payload forge
    apex_engine.py       Personas, prompt builder, LLM bridge, reports
    apex_ops.py          Tracker, orchestrator, session bootstrap
    apex_intel_dummy.py  Threat intel shim (drop in CISA sync if wanted)
    apex_ui.py           Streamlit interface

Run:
    streamlit run apex_sec.py      full UI
    python apex_sec.py             self-test
"""

from __future__ import annotations

import importlib
import sys

REQUIRED = [
    "apex_core",
    "apex_vulndb",
    "apex_payload",
    "apex_engine",
    "apex_ops",
    "apex_intel_dummy",
    "apex_ui",
]

missing: list[str] = []
for mod in REQUIRED:
    try:
        importlib.import_module(mod)
    except ImportError as exc:
        missing.append(f"{mod} ({exc})")

if missing:
    print("APEX-SEC startup failed. Missing modules:")
    for m in missing:
        print(f"  - {m}")
    print("Ensure all apex_*.py files sit in the same directory.")
    sys.exit(1)


from apex_core import (
    APP_NAME, APP_VERSION, APP_TAGLINE,
    ConfigManager, MemoryManager, TargetProfile, VulnerabilityEntry,
)
from apex_vulndb import total as vuln_total, categories as vuln_categories
from apex_payload import (
    all_payloads, WAFEngine, PayloadForge,
    categories as payload_categories,
)
from apex_engine import PromptEngineer, ReportGenerator, PERSONAS
from apex_ops import VulnerabilityTracker


def cli_self_test() -> int:
    """Offline sanity check across every module."""
    print(f"{APP_NAME} v{APP_VERSION}")
    print(f"  {APP_TAGLINE}")
    print()

    cfg = ConfigManager()
    print(f"[core] config loaded: model={cfg.get('model')} persona={cfg.get('persona')}")

    mem = MemoryManager()
    sid = mem.create_session(title="self-test")
    mem.add_message(sid, "user", "ping")
    mem.add_message(sid, "assistant", "pong")
    mem.add_message(sid, "assistant", "engine error", meta={"error": True})
    clean = mem.get_messages(sid, include_errors=False)
    assert len(clean) == 2, f"expected 2 messages, got {len(clean)}"
    print(f"[core] memory: session={sid[:8]} messages={len(clean)}")

    print(f"[vulndb] {vuln_total()} vulnerability classes across "
          f"{len(vuln_categories())} categories")

    payloads = all_payloads()
    print(f"[payload] {len(payloads)} curated payloads across "
          f"{len(payload_categories())} categories")

    variants = WAFEngine.generate("' OR 1=1--", waf="cloudflare", count=3, seed=42)
    print(f"[payload] WAF engine produced {len(variants)} variants for cloudflare")
    for v in variants:
        print(f"         seed={v['seed']} payload={v['payload'][:50]}...")

    forged = PayloadForge.forge("sqli", dialect="mysql", waf="modsecurity",
                                count=3, seed=1000)
    print(f"[payload] forge produced {len(forged)} novel payloads")
    for f in forged:
        print(f"         seed={f['seed']} payload={f['payload'][:50]}...")

    target = TargetProfile(
        ip_address="10.0.0.5", os_info="Ubuntu 22.04",
        technologies="nginx, php, mysql",
        authorization_ref="SOW-2024-042",
    )
    system_prompt = PromptEngineer.build(
        persona_key="apex-sec", target=target,
        allow_payload=True, cisa_items=[],
    )
    assert "APEX-SEC" in system_prompt
    assert "SOW-2024-042" in system_prompt
    print(f"[engine] system prompt: {len(system_prompt)} chars")

    tracker = VulnerabilityTracker()
    tracker.set_target(target)
    tracker.add(VulnerabilityEntry(
        cve_id="LAB-001", severity="High",
        title="Reflected XSS in search",
        description="Reflected XSS via q parameter.",
        mitigation="Context-aware encoding, CSP.",
    ))
    md = ReportGenerator.to_markdown(tracker, [], sid)
    html = ReportGenerator.to_html(md)
    js = ReportGenerator.to_json(tracker, [], sid)
    assert "LAB-001" in md
    assert "<html" in html
    assert "LAB-001" in js
    print(f"[engine] report: md={len(md)} html={len(html)} json={len(js)}")

    print()
    print("[status] all modules OK")
    return 0


def main() -> None:
    # Detect Streamlit at runtime. When running under `streamlit run`,
    # streamlit is imported and has a runtime. When running under
    # `python apex_sec.py`, we fall back to the self-test.
    try:
        import streamlit as st  # noqa: F401
    except ImportError:
        sys.exit(cli_self_test())

    try:
        from streamlit.runtime import exists as st_runtime_exists
        if not st_runtime_exists():
            sys.exit(cli_self_test())
    except Exception:
        sys.exit(cli_self_test())

    from apex_ui import main as ui_main
    ui_main()


if __name__ == "__main__":
    main()
