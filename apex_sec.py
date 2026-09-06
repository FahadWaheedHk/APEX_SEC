import json
import os
import requests
from datetime import datetime, timezone
import streamlit as st
from langchain_community.llms import Ollama

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
    .stDownloadButton>button {
        background-color: #238636;
        color: white;
        font-weight: bold;
        border-radius: 6px;
        border: 1px solid #2ea043;
        padding: 10px 24px;
        width: 100%;
    }
    .stDownloadButton>button:hover {
        background-color: #2ea043;
        border-color: #2ea043;
    }
    </style>
""", unsafe_allow_html=True)

KB_FILE = "live_vuln_db.json"

# ---------------------------------------------------------
# 2. Vulnerability Tracker Module (FIXED)
# ---------------------------------------------------------
class VulnerabilityTracker:
    def __init__(self, system_id: str = "TARGET-ASSET-01"):
        self.system_id = system_id
        self.knowledge_base = []
        self.system_metadata = {}

    def set_system_metadata(self, ip_address: str, mac_address: str, os_info: str):
        self.system_metadata = {
            "ip_address": ip_address,
            "mac_address": mac_address if mac_address != "N/A" else "Unknown",
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
        # Auto-save to session state
        st.session_state.v_tracker = self

    def export_report(self) -> str:
        report = {
            "system_id": self.system_id,
            "metadata": self.system_metadata,
            "vulnerabilities": self.knowledge_base,
            "export_timestamp": datetime.now(timezone.utc).isoformat()
        }
        return json.dumps(report, indent=4)

# Initialize Vulnerability Tracker with persistence
if "v_tracker" not in st.session_state:
    st.session_state.v_tracker = VulnerabilityTracker()

# ---------------------------------------------------------
# 3. Dynamic Threat Intelligence Engine (CISA KEV) - FIXED
# ---------------------------------------------------------
@st.cache_data(ttl=3600)  # Cache for 1 hour
def load_cisa_data():
    """Load CISA data from local cache with proper error handling"""
    if os.path.exists(KB_FILE):
        try:
            with open(KB_FILE, "r", encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data[:20]  # Return top 20
                return []
        except (json.JSONDecodeError, IOError) as e:
            st.warning(f"⚠️ Error loading CISA data: {str(e)}")
            return []
    return []

def sync_latest_threat_intelligence():
    """Sync with CISA KEV feed with better error handling"""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        # Add user-agent to avoid blocking
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        res = requests.get(url, timeout=15, headers=headers)
        if res.status_code == 200:
            data = res.json().get("vulnerabilities", [])[:50]
            # Validate data structure
            if data and isinstance(data, list):
                with open(KB_FILE, "w", encoding='utf-8') as f:
                    json.dump(data, f, indent=4)
                # Clear cache to reload fresh data
                st.cache_data.clear()
                return True, f"✅ Synced {len(data)} active exploits into knowledge base."
        return False, "❌ Failed to connect to threat intel feed."
    except requests.exceptions.Timeout:
        return False, "❌ Connection timeout - Check your internet connection."
    except requests.exceptions.ConnectionError:
        return False, "❌ Connection error - Unable to reach CISA servers."
    except Exception as e:
        return False, f"❌ Error: {str(e)}"

# ---------------------------------------------------------
# 4. Sidebar Controls & Scope Configuration (FIXED)
# ---------------------------------------------------------
st.title("🛡️ APEX-SEC: Advanced Interactive Security Assistant")
st.caption("⚡ Step-by-Step Cyber Operations Engine | Local Ollama Core")

# Initialize session state for target parameters
if "target_ip" not in st.session_state:
    st.session_state.target_ip = "192.168.1.1"
if "target_os" not in st.session_state:
    st.session_state.target_os = "Linux / Kali"
if "llm_instance" not in st.session_state:
    st.session_state.llm_instance = None

with st.sidebar:
    st.header("⚙️ Command Center")
    st.markdown("---")
    
    st.subheader("🎯 Target Profile")
    target_ip = st.text_input("Target IP / Scope", value=st.session_state.target_ip)
    target_os = st.text_input("Target OS", value=st.session_state.target_os)
    target_mac = st.text_input("MAC Address (Optional)", placeholder="e.g., AA:BB:CC:DD:EE:FF")
    
    if st.button("📌 Save Target Parameters", use_container_width=True):
        st.session_state.target_ip = target_ip
        st.session_state.target_os = target_os
        st.session_state.v_tracker.set_system_metadata(
            target_ip, 
            target_mac if target_mac else "N/A", 
            target_os
        )
        # Reset LLM to apply new context
        st.session_state.llm_instance = None
        st.success("✅ Target metadata saved successfully!")
        st.rerun()

    st.markdown("---")
    st.subheader("🔄 Threat Intelligence Sync")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🚀 Sync Database", use_container_width=True):
            status, msg = sync_latest_threat_intelligence()
            if status:
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)
    with col2:
        if st.button("📊 View Cache", use_container_width=True):
            cisa_data = load_cisa_data()
            if cisa_data:
                st.info(f"✅ {len(cisa_data)} vulnerabilities cached")
            else:
                st.warning("⚠️ No cached data found")
            
    st.markdown("---")
    st.subheader("📋 Report Generation")
    if st.button("📄 Export Vulnerability Report", use_container_width=True):
        report = st.session_state.v_tracker.export_report()
        st.download_button(
            label="⬇️ Download JSON Report",
            data=report,
            file_name=f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )
    
    st.markdown("---")
    if st.button("🗑️ Clear Chat History", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

    st.markdown("---")
    st.subheader("📊 Engine Status")
    st.success("🟢 AI Core: Active (Llama 3)")
    st.info("🗣️ Processing: Multilingual Support")
    st.warning("🔒 Privacy: 100% On-Premises Execution")
    
    # Show current target
    st.markdown("---")
    st.subheader("🎯 Active Target")
    st.code(f"IP: {st.session_state.target_ip}\nOS: {st.session_state.target_os}")

# Load CISA Knowledge Base (FIXED)
cisa_data = load_cisa_data()
kb_context = ""
if cisa_data:
    kb_context = "\n[LIVE CISA THREAT INTEL AGGREGATED]:\n" + "\n".join(
        [f"- {item.get('cveID', 'N/A')}: {item.get('shortDescription', 'No description')}" 
         for item in cisa_data[:20] if item.get('cveID')]
    )

# ---------------------------------------------------------
# 5. Master Persona & Directives (FIXED - Dynamic)
# ---------------------------------------------------------
def get_system_prompt(ip, os_name, context):
    """Generate dynamic system prompt based on current target"""
    return f"""
You are APEX-SEC, an elite Principal Security Researcher, Master Penetration Tester, Red Team Lead, and Blue Team Defense Analyst.
You act as an interactive, step-by-step security mentor and technical advisor.

Current Active Scope:
- Target IP: {ip}
- Target OS: {os_name}

Operational Directives & Response Rules:
1. Interactive Step-by-Step Methodology:
   - Do NOT provide massive script dumps immediately. Guide the user sequentially step-by-step.
   - When a user initiates a testing query, evaluate the target environment first and request missing details if needed.
   - Analyze errors deeply (WAF blocks, privilege escalation issues, syntax mismatches) and suggest step-by-step adjustments.
   - Provide actionable commands that the user can copy-paste and execute.

2. Comprehensive Vulnerability & Research Expertise:
   - Deep knowledge of web vulnerability classes: SQL Injection, XSS, IDOR, SSRF, RCE, OAuth/JWT bypasses, Race Conditions, Business Logic Flaws, and GraphQL flaws.
   - Coverage of network security, packet artifacts, cloud hardening (AWS/Kubernetes), and SIEM detection rules (Sigma/YARA/Snort).
   - Ability to explain complex security concepts in simple, actionable terms.

3. Response Structure:
   - Start with a brief analysis of the user's query.
   - Provide step-by-step guidance with clear numbering.
   - Include code examples where relevant.
   - End with a summary or next steps.

{context}

Always maintain a professional, analytical, and highly structured step-by-step guidance workflow.
"""

# ---------------------------------------------------------
# 6. Model Execution & Chat Interface (FIXED)
# ---------------------------------------------------------
def get_llm():
    """Get or create LLM instance with current context"""
    if st.session_state.llm_instance is None:
        try:
            system_prompt = get_system_prompt(
                st.session_state.target_ip,
                st.session_state.target_os,
                kb_context
            )
            llm = Ollama(
                model="llama3",
                system=system_prompt,
                temperature=0.3,  # More focused responses
                num_predict=2048  # Limit response length
            )
            st.session_state.llm_instance = llm
            return llm
        except Exception as e:
            st.error(f"⚠️ Local AI Engine Error: {str(e)}")
            st.info("💡 Please ensure Ollama is running: 'ollama run llama3'")
            return None
    return st.session_state.llm_instance

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat history
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# Chat input
if prompt := st.chat_input("Enter target scope, command output, bug query, or error log..."):
    # Add user message
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Generate assistant response
    with st.chat_message("assistant"):
        res_box = st.empty()
        with st.spinner("⚡ APEX-SEC analyzing parameters..."):
            llm = get_llm()
            if llm:
                try:
                    # Prepare messages for LangChain
                    response = llm.invoke(prompt)
                    res_box.markdown(response)
                    st.session_state.messages.append({"role": "assistant", "content": response})
                except Exception as err:
                    error_msg = f"❌ Execution Error: {str(err)}"
                    st.error(error_msg)
                    st.info("💡 Try: Check if Ollama is running with 'ollama list'")
            else:
                error_msg = "⚠️ AI Engine is offline. Please start Ollama."
                st.error(error_msg)
                st.info("💡 Run: 'ollama run llama3' in terminal")

# ---------------------------------------------------------
# 7. Auto-save vulnerability tracker state (FIXED)
# ---------------------------------------------------------
# Ensure v_tracker is always saved to session state
if "v_tracker" not in st.session_state:
    st.session_state.v_tracker = VulnerabilityTracker()

# ---------------------------------------------------------
# 8. Footer with additional info
# ---------------------------------------------------------
st.markdown("---")
col1, col2, col3 = st.columns(3)
with col1:
    st.caption("🛡️ APEX-SEC v2.0")
with col2:
    st.caption("🔒 100% On-Premises")
with col3:
    st.caption(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M')}")
