#!/usr/bin/env python3
"""
APEX-SEC main entry point.

Wires all seven sibling modules together and offers three launch paths:

    python apex_sec.py              -> CLI self-test (no Streamlit needed)
    python apex_sec.py --ui         -> Launch Streamlit dashboard
    streamlit run apex_sec.py       -> Streamlit runtime detected, boots UI
    streamlit run apex_ui.py        -> Direct Streamlit launch

The CLI path deliberately does NOT import apex_ui or Streamlit, so
operators can verify install on a headless box. All 8 core modules are
still present on disk and still runnable -- they are just not eagerly
loaded during the self-test.

Module map:
    apex_core.py         Configuration, memory, models, logging
    apex_vulndb.py       Vulnerability catalogue
    apex_payload.py      Curated payloads, WAF engine, novel-payload forge
    apex_engine.py       Personas, prompt builder, LLM bridge, reports
    apex_ops.py          Tracker, orchestrator, session bootstrap
    apex_intel_dummy.py  Threat intel loader + live CISA sync
    apex_ui.py           Streamlit interface (7 tabs)
    apex_sec.py          This file
"""

from __future__ import annotations

import importlib
import sys

APP_NAME = "APEX-SEC"
APP_VERSION = "2.0.0"

# Core modules every entry path needs. apex_ui is intentionally NOT here:
# it pulls in Streamlit, which is optional for the CLI self-test.
CLI_REQUIRED = [
    "apex_core",
    "apex_vulndb",
    "apex_payload",
    "apex_intel_dummy",
    "apex_engine",
    "apex_ops",
]

# UI module is checked separately and only fails if the user asked for UI.
UI_REQUIRED = ["apex_ui"]


# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

def _check_module(name: str) -> bool:
    try:
        importlib.import_module(name)
        print(f"  [ OK ] {name}")
        return True
    except ImportError as exc:
        print(f"  [MISS] {name}: {exc}")
        return False


def _check_cli_deps() -> bool:
    ok = True
    for name in CLI_REQUIRED:
        if not _check_module(name):
            ok = False
    return ok


def _check_ui_deps() -> bool:
    try:
        import streamlit  # noqa: F401
    except ImportError:
        print("  [MISS] streamlit -- install with: pip install streamlit")
        return False
    print("  [ OK ] streamlit")

    ui_ok = True
    for name in UI_REQUIRED:
        if not _check_module(name):
            ui_ok = False
    return ui_ok


# ---------------------------------------------------------------------------
# CLI mode
# ---------------------------------------------------------------------------

def cli_self_test() -> int:
    """Offline sanity check across every non-UI module."""
    print(f"{APP_NAME} v{APP_VERSION} -- self-test\n")

    print("Core modules:")
    core_ok = _check_cli_deps()

    print("\nUI modules (optional for CLI):")
    ui_ok = _check_ui_deps()

    print("\nSummary:")
    print(f"  core: {'ok' if core_ok else 'FAILED'}")
    print(f"  ui:   {'ok' if ui_ok else 'skipped (install streamlit for UI)'}")

    if not core_ok:
        print("\nFix the missing core modules first.")
        print("Ensure all apex_*.py files sit in the same directory as "
              f"{__file__}.")
        return 1

    # Exercise the runtime pieces the UI would use.
    try:
        from apex_core import (
            ConfigManager, MemoryManager, TargetProfile,
            VulnerabilityEntry,
        )
        from apex_vulndb import (
            total as vuln_total,
            categories as vuln_categories,
            validate_entries,
            validate_payload_references,
        )
        from apex_payload import (
            all_payloads, WAFEngine, PayloadForge,
            categories as payload_categories,
        )
        from apex_engine import PromptEngineer, ReportGenerator
        from apex_ops import VulnerabilityTracker

        cfg = ConfigManager()
        print(f"\n[core] model={cfg.get('model')} "
              f"persona={cfg.get('persona')}")

        mem = MemoryManager()
        sid = mem.create_session(title="self-test")
        mem.add_message(sid, "user", "ping")
        mem.add_message(sid, "assistant", "pong")
        mem.add_message(sid, "assistant", "engine error", meta={"error": True})
        clean = mem.get_messages(sid, include_errors=False)
        assert len(clean) == 2, f"expected 2 messages, got {len(clean)}"
        print(f"[core] memory: session={sid[:8]} messages={len(clean)}")

        # Data integrity
        probs = validate_entries()
        assert probs == [], f"vulndb problems: {probs}"
        dangling = validate_payload_references()
        assert dangling == {}, f"dangling payload refs: {dangling}"
        print(f"[vulndb] {vuln_total()} classes across "
              f"{len(vuln_categories())} categories (integrity OK)")

        payloads = all_payloads()
        payload_ids = {p["id"] for p in payloads}
        assert len(payload_ids) == len(payloads), "duplicate payload IDs"
        print(f"[payload] {len(payloads)} payloads across "
              f"{len(payload_categories())} categories")

        variants = WAFEngine.generate(
            "' OR 1=1--", waf="cloudflare", count=3, seed=42
        )
        assert len(variants) == 3, f"expected 3 variants, got {len(variants)}"
        print(f"[payload] WAF engine: {len(variants)} variants (seed=42)")

        forged = PayloadForge.forge(
            "sqli", dialect="mysql", waf="modsecurity", count=3, seed=1000
        )
        assert len(forged) == 3, f"expected 3 forged, got {len(forged)}"
        print(f"[payload] forge: {len(forged)} novel payloads (seed=1000)")

        target = TargetProfile(
            ip_address="10.0.0.5", os_info="Ubuntu 22.04",
            technologies="nginx, php, mysql",
            authorization_ref="SOW-2024-042",
            scope_notes="10.0.0.0/24",
        )
        system_prompt = PromptEngineer.build(
            persona_key="apex-sec", target=target,
            allow_payload=True, cisa_items=[],
        )
        assert "APEX-SEC" in system_prompt
        assert "SOW-2024-042" in system_prompt
        print(f"[engine] system prompt: {len(system_prompt)} chars")

        tracker = VulnerabilityTracker(target=target)
        tracker.add(VulnerabilityEntry(
            cve_id="LAB-001", severity="High",
            title="Reflected XSS in search",
            description="Reflected XSS via q parameter.",
            mitigation="Context-aware encoding, CSP.",
        ))
        # Dedupe check (case-insensitive)
        assert tracker.add(VulnerabilityEntry(
            cve_id="lab-001", severity="High", title="dupe"
        )) is False, "dedupe should reject case-insensitive duplicate"
        print("[ops] dedupe: case-insensitive duplicate rejected")

        md = ReportGenerator.to_markdown(tracker, [], sid)
        html = ReportGenerator.to_html(md)
        js = ReportGenerator.to_json(tracker, [], sid)
        assert "LAB-001" in md
        assert "<html" in html
        assert "LAB-001" in js
        # HTML escape check
        tracker.add(VulnerabilityEntry(
            cve_id="LAB-002", severity="High",
            title="<script>alert(1)</script>",
            description="<img src=x onerror=alert(2)>",
        ))
        md2 = ReportGenerator.to_markdown(tracker, [], sid)
        html2 = ReportGenerator.to_html(md2)
        assert "<script>alert(1)</script>" not in html2, \
            "HTML report must escape inline scripts"
        print(f"[engine] report: md={len(md)} html={len(html)} json={len(js)}"
              " (HTML escape OK)")

        # Authorization gate
        assert tracker.has_authorization(), "authorization should be set"
        in_scope, reason = tracker.target_in_scope()
        assert in_scope, f"target should be in scope: {reason}"
        print("[ops] authorization gate: target in scope")

        # Out-of-scope check
        bad = VulnerabilityTracker(target=TargetProfile(
            ip_address="8.8.8.8",
            authorization_ref="SOW-2024-042",
            scope_notes="10.0.0.0/24",
        ))
        in_scope2, _ = bad.target_in_scope()
        assert in_scope2 is False, "8.8.8.8 should be out of scope"
        print("[ops] authorization gate: out-of-scope target rejected")

    except AssertionError as exc:
        print(f"\n[FAIL] assertion: {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"\n[FAIL] runtime error: {exc}")
        return 1

    print("\n[status] all modules OK")
    print("\nStart the dashboard with:")
    print("  python apex_sec.py --ui")
    print("  or")
    print("  streamlit run apex_ui.py")
    return 0


# ---------------------------------------------------------------------------
# UI mode
# ---------------------------------------------------------------------------

def run_ui() -> int:
    try:
        import streamlit.web.cli as stcli
    except ImportError:
        print(
            "Streamlit is not installed. Run:\n"
            "  pip install streamlit\n"
            "Then retry: python apex_sec.py --ui",
            file=sys.stderr,
        )
        return 1

    from pathlib import Path
    here = Path(__file__).resolve().parent
    ui_file = here / "apex_ui.py"
    if not ui_file.exists():
        print(f"apex_ui.py not found next to {__file__}", file=sys.stderr)
        return 1

    sys.argv = ["streamlit", "run", str(ui_file)]
    return stcli.main()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _running_under_streamlit() -> bool:
    """Detect `streamlit run apex_sec.py` vs `python apex_sec.py`."""
    try:
        from streamlit.runtime import exists as st_runtime_exists
    except ImportError:
        return False
    try:
        return bool(st_runtime_exists())
    except Exception:  # noqa: BLE001
        return False


def main() -> int:
    # 1. Explicit --ui flag
    if "--ui" in sys.argv:
        return run_ui()

    # 2. Running under `streamlit run apex_sec.py` -- let Streamlit drive
    if _running_under_streamlit():
        from apex_ui import main as ui_main
        ui_main()
        return 0

    # 3. Plain `python apex_sec.py` -- CLI self-test
    return cli_self_test()


if __name__ == "__main__":
    raise SystemExit(main())
