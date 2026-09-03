import json
import os
import requests
from datetime import datetime, timezone
import streamlit as st
from langchain_ollama import OllamaLLM

# ---------------------------------------------------------
# 1. Dashboard & UI Configuration
# ---------------------------------------------------------
st.set_page_config(
    page_title="APEX-SEC | Cyber Operations Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
    .main { background-color: #0d1117; color: #c9d1d9; }
    .stButton>button {
        background-color: #da3633;
        color: white;
        font-weight: bold;
        border-radius: 6px;
        border: 1px solid #f85149;
        padding: 10px 24px;
        width: 100%;
    }
    .stButton>button:hover {
        background-color: #b62324;
        border-color: #b62324;
    }
    .stTextInput>div>div>input {
        background-color: #161b22;
        color: #58a6ff;
    }
    </style>
""", unsafe_allow_html=True)

KB_FILE = "live_vuln_db.json"

# ---------------------------------------------------------
# 2. Vulnerability Tracker Module
# ---------------------------------------------------------
class VulnerabilityTracker:
    def __init__(self, system_id: str = "TARGET-ASSET-01"):
        self.system_id = system_id
        self.knowledge_base = []
        self.system_metadata = {}

    def set_system_metadata(self, ip_address: str, mac_address: str, os_info: str):
        self.system_metadata = {
            "ip_address": ip_address,
            "mac_address": mac_address,
            "os_info": os_info,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def add_vulnerability_reference(self, cve_id: str, severity: str, description: str, mitigation: str):
        entry = {
            "cve_id": cve_id,
            "severity": severity,
            "description": description,
            "mitigation_guidance": mitigation,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self.knowledge_base.append(entry)

    def export_report(self) -> str:
        report = {
            "system_id": self.system_id,
            "metadata": self.system_metadata,
            "vulnerabilities": self.knowledge_base
        }
        return json.dumps(report, indent=4)

if "v_tracker" not in st.session_state:
    st.session_state.v_tracker = VulnerabilityTracker()

# ---------------------------------------------------------
# 3. Dynamic Threat Intelligence Engine (CISA KEV)
# ---------------------------------------------------------
def sync_latest_threat_intelligence():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        res = requests.get(url, timeout=12)
        if res.status_code == 200:
            data = res.json().get("vulnerabilities", [])[:50]
            with open(KB_FILE, "w") as f:
                json.dump(data, f, indent=4)
            return True, f"Synced {len(data)} active exploits into knowledge base."
        return False, "Failed to connect to threat intel feed."
    except Exception as e:
        return False, str(e)

# ---------------------------------------------------------
# 4. Sidebar Controls
# ---------------------------------------------------------
st.title("🛡️ APEX-SEC: Advanced Interactive Security Assistant")
st.caption("⚡ Step-by-Step Cyber Operations Engine | Local Ollama Core")

with st.sidebar:
    st.header("⚙️ Command Center")
    st.markdown("---")
    
    st.subheader("🔄 Threat Intelligence Sync")
    if st.button("🚀 Synchronize Database"):
        status, msg = sync_latest_threat_intelligence()
        if status:
            st.success(msg)
            st.rerun()
        else:
            st.error(msg)
            
    st.markdown("---")
    if st.button("🗑️ Clear Chat History"):
        st.session_state.messages = []
        st.rerun()

    st.markdown("---")
    st.subheader("📊 Engine Status")
    st.success("🟢 AI Core: Active (Llama 3)")
    st.info("🗣️ Processing: Multilingual Support")
    st.warning("🔒 Privacy: 100% On-Premises Execution")

# Load Active Knowledge Base
kb_context = ""
if os.path.exists(KB_FILE):
    try:
        with open(KB_FILE, "r") as f:
            cisa_data = json.load(f)
            kb_context = "\n[LIVE CISA THREAT INTEL AGGREGATED]:\n" + "\n".join(
                [f"- {item.get('cveID')}: {item.get('shortDescription')}" for item in cisa_data[:20]]
            )
    except Exception:
        kb_context = ""

# ---------------------------------------------------------
# 5. Master Persona & Directives
# ---------------------------------------------------------
SYSTEM_PROMPT = f"""
You are APEX-SEC, an elite Principal Security Researcher, Master Penetration Tester, Red Team Lead, and Blue Team Defense Analyst.
You act as an interactive, step-by-step security mentor and technical advisor.

Operational Directives & Response Rules:
1. Interactive Step-by-Step Methodology:
   - Do NOT provide massive script dumps immediately. Guide the user sequentially step-by-step.
   - When a user initiates a testing query (e.g., Web App Assessment, Network Recon, Vulnerability Audit), FIRST request essential contextual parameters:
     * Target IP / Domain / Authorized Scope
     * Target OS / Architecture / MAC Address / Environment Details
     * Exact error outputs, log snippets, or HTTP responses if an operation fails.
   - Analyze errors deeply (WAF blocks, privilege escalation issues, syntax mismatches) and suggest step-by-step adjustments.

2. Comprehensive Vulnerability & Research Expertise:
   - Deep knowledge of all web vulnerability classes: SQL Injection, XSS, IDOR, SSRF, RCE, OAuth/JWT bypasses, Race Conditions, Business Logic Flaws, and GraphQL flaws.
   - Coverage of network security, packet artifacts, MAC/OUI analysis, cloud hardening (AWS/Kubernetes), and SIEM detection rules (Sigma/YARA/Snort).
   - Dynamic reference to emerging CVEs and zero-day research discussions using live threat intelligence feeds.

{kb_context}
Always maintain a professional, analytical, and highly structured step-by-step guidance workflow.
"""

# ---------------------------------------------------------
# 6. Model Execution & Chat Interface
# ---------------------------------------------------------
try:
    llm = OllamaLLM(model="llama3", system=SYSTEM_PROMPT)
except Exception:
    st.error("⚠️ Local AI Engine Offline! Please run 'ollama run llama3' in your terminal.")

if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

if prompt := st.chat_input("Enter target scope, command output, bug query, or error log..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        res_box = st.empty()
        with st.spinner("⚡ APEX-SEC analyzing parameters..."):
            try:
                response = llm.invoke(prompt)
                res_box.markdown(response)
                st.session_state.messages.append({"role": "assistant", "content": response})
            except Exception as err:
                st.error(f"Execution Error: {str(err)}")
