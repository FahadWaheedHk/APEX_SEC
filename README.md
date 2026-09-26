# ⚡ APEX-SEC

<div align="center">

### Enterprise AI Cyber Operations Suite

**The On-Premises Red & Blue Team Tactical Command System**

---

**Version** `1.0.0` · **Platform** `Linux` · **License** `MIT` · **Engine** `Ollama + Llama 3`

**Built by:** Fahad Waheed HK — *For the Operators, by an Operator.*

---

</div>

---

## 📖 Table of Contents

1. [🎯 Overview](#-overview)
2. [⚔️ Core Capabilities](#️-core-capabilities)
3. [🎭 Operator Personas](#-operator-personas)
4. [🧰 Built-in Tools](#-built-in-tools)
5. [🔐 Security Model](#-security-model)
6. [💻 System Requirements](#-system-requirements)
7. [📦 Step-by-Step Installation](#-step-by-step-installation)
8. [🚀 Launch Sequence](#-launch-sequence)
9. [🎬 First-Run Walkthrough](#-first-run-walkthrough)
10. [📡 Threat Intelligence Sync](#-threat-intelligence-sync)
11. [🗂 Project Structure](#-project-structure)
12. [🛠 Troubleshooting](#-troubleshooting)
13. [⚖️ Legal & Educational Purpose](#️-legal--educational-purpose)
14. [📞 Connect with the Developer](#-connect-with-the-developer)
15. [🎁 Appendix — Quick Command Reference](#-appendix--quick-command-reference)

---

## 🎯 Overview

**APEX-SEC** is a fully on-premises, air-gapped Cyber Operations Suite engineered for Principal Security Researchers, Red Team Operators, Bug Bounty Hunters, and SOC Analysts who demand a tactical co-pilot that respects both operational security and methodological rigor.

Unlike typical AI security wrappers that dump static payload lists or produce generic advisories, APEX-SEC behaves as a **stateful tactical operator**. It ingests target parameters — OS fingerprint, network scope, technology stack, and raw terminal output — and responds with **structured, sequential attack or defense workflows**. Every recommendation is scoped, every payload is contextualized, and every session is preserved locally.

The suite is architected around **six operational layers**: foundation (config, logging, constants), persistence (SQLite memory and evidence vault), domain logic (vulnerability tracking, payload library, threat intelligence), intelligence (persona engine, prompt engineering, LLM bridge), interface (Streamlit UI with seven operational tabs), and utilities (encoders, hashers, report generators). This layered design guarantees that intelligence, persistence, and interface concerns remain cleanly separated — enabling the operator to swap models, extend personas, or add tools without destabilizing the core.

Whether you are scoping an external engagement, reproducing a live CVE, authoring a client-ready vulnerability report, or studying adversarial TTPs for detection engineering, APEX-SEC delivers a **single, consistent, expert-level workflow** — fully offline, fully yours.

---

## ⚔️ Core Capabilities

### 🔴 Red Team Operations

| Capability | Description |
| :--- | :--- |
| **Guided Methodology** | Reconnaissance → Scope Profiling → Parameter Analysis → Injection/Bypass → Privilege Escalation |
| **Full-Spectrum Coverage** | Web Applications · REST/GraphQL APIs · Core Infrastructure · IoT Devices |
| **Attack Vectors** | SQLi · XSS · IDOR · SSRF · CSRF · RCE · LFI · XXE · SSTI · JWT/OAuth Bypasses · Race Conditions · Business Logic Flaws · Deserialization |
| **Payload Library** | 50+ curated payloads across 12 categories |

### 🔵 Blue Team Engineering

| Capability | Description |
| :--- | :--- |
| **Detection Engineering** | Sigma · YARA · Snort · Suricata signatures |
| **Infrastructure Hardening** | Docker · Kubernetes · AWS · Linux baselines |
| **Compliance Mapping** | PCI-DSS · HIPAA · SOC2 · ISO 27001 · NIST CSF |

### 🔌 API Security Testing

| Capability | Description |
| :--- | :--- |
| **REST Methodology** | Endpoint enum → injection → auth bypass (10 steps) |
| **GraphQL Methodology** | Introspection abuse · batching · IDOR via nodes |
| **Auth Checklist** | BOLA · BFLA · JWT tampering · mass assignment |
| **curl Generator** | Ready-to-run HTTP request templates |

### 📡 IoT / Network Reconnaissance

| Capability | Description |
| :--- | :--- |
| **Network Discovery** | nmap ping-sweep · arp-scan · netdiscover |
| **Port Scanning** | Full · service · UDP · masscan |
| **IoT Protocols** | MQTT · CoAP · UPnP · RTSP · Modbus · Telnet |
| **Web Recon** | whatweb · gobuster · nikto · nuclei · ffuf |

---

## 🎭 Operator Personas

| Icon | Persona | Specialty |
| :---: | :--- | :--- |
| 🛡️ | **APEX-SEC (Default)** | Master Pentester — Full spectrum |
| 🔴 | **Red Team Lead** | Adversary Simulation |
| 🔵 | **Blue Team Analyst** | Detection Engineering |
| 🎯 | **Bug Bounty Hunter** | Web / API Exploitation |
| 💣 | **Exploit Developer** | Memory Corruption |
| ☁️ | **Cloud Security Architect** | AWS · Azure · GCP |
| 🔌 | **API Security Specialist** | REST · GraphQL · gRPC |
| 📡 | **IoT / Hardware Hacker** | Firmware · UART/JTAG · MQTT |
| 🦠 | **Malware Analyst** | Reverse Engineering |
| 🎭 | **Social Engineer** | Phishing & Pretexting |
| 📋 | **Compliance Auditor** | PCI · HIPAA · SOC2 · NIST |
| ✏️ | **Custom Persona** | User-defined role |

---

## 🧰 Built-in Tools

| Tool | Purpose |
| :--- | :--- |
| **Hash Generator** | MD5 · SHA1 · SHA256 · SHA512 |
| **Base64 Encoder / Decoder** | Encode or decode Base64 strings |
| **URL Encoder / Decoder** | Percent-encoding for URLs |
| **JWT Decoder** | Decode Header · Payload · Signature |
| **Reverse Shell Generator** | Bash · Python3 · NC · PowerShell · PHP · Perl |
| **CVE Lookup** | Live NVD API query |

---

## 🔐 Security Model

| Layer | Implementation |
| :--- | :--- |
| **LLM Engine** | Local Ollama — no external API calls |
| **Persistence** | SQLite on local disk — never synced |
| **Threat Feed** | CISA KEV cached locally in JSON |
| **Evidence Vault** | Screenshots stored in `config/evidence/` |
| **Session Isolation** | Unique session IDs — no cross-contamination |
| **Network** | Zero outbound traffic after model pull |

> 🛡️ **Air-Gapped by Design.** Once dependencies are installed, APEX-SEC works entirely offline.

---

## 💻 System Requirements

| Resource | Minimum | Recommended |
| :--- | :--- | :--- |
| **RAM** | 8 GB DDR4 | 16–32 GB DDR4/DDR5 |
| **CPU** | Intel i5 (8th Gen) / Ryzen 5 | Intel i7/i9 · Ryzen 7/9 |
| **Storage (Free)** | 12 GB | 25 GB NVMe SSD |
| **GPU** | Optional | NVIDIA RTX (CUDA) |
| **OS** | Any modern Linux | Kali Linux 2024.x · Ubuntu 22.04+ |
| **Python** | 3.10+ | 3.11+ |
| **Network** | Required for setup only | Wired preferred |

**Storage Breakdown**

| Component | Size |
| :--- | :--- |
| Code + Virtual Environment | ~2 GB |
| Python Libraries | ~4 GB |
| Llama 3 Model | ~4.7 GB |
| Cache + Logs | ~1 GB |
| **Total** | **~12 GB** |

---

## 📦 Step-by-Step Installation

> [!WARNING]
> 🛠️ **Manual installation.** Copy each command one at a time, paste into your terminal, and press Enter.
>
> ⚠️ *Do NOT skip steps. Do NOT run the next command until the previous one finishes.*

---

### 🐧 Kali · Debian · Ubuntu

**Step 1 — Update System Packages**

```bash
sudo apt update
```

```bash
sudo apt upgrade -y
```

**Step 2 — Install Python 3, pip, venv, curl, git**

```bash
sudo apt install python3 python3-pip python3-venv curl git -y
```

**Step 3 — Verify Python Installation**

```bash
python3 --version
```

**Step 4 — Install Ollama Engine**

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Step 5 — Verify Ollama Installation**

```bash
ollama --version
```

**Step 6 — Pull the Llama 3 Core Model**

```bash
ollama pull llama3
```

**Step 7 — Clone the APEX-SEC Repository**

```bash
cd ~
```

```bash
git clone https://github.com/fahadwaheedhk/apex-sec.git
```

```bash
cd apex-sec
```

**Step 8 — Create a Python Virtual Environment**

```bash
python3 -m venv venv
```

```bash
source venv/bin/activate
```

**Step 9 — Install Python Dependencies**

```bash
pip install --upgrade pip
```

```bash
pip install streamlit requests langchain langchain-community langchain-ollama
```

**Step 10 — Verify All Files Are Present**

```bash
ls -la
```

```bash
chmod +x apex_sec.py
```

---

### 🐧 Arch Linux

**Step 1 — Update System**

```bash
sudo pacman -Syu
```

**Step 2 — Install Dependencies**

```bash
sudo pacman -S python python-pip git curl base-devel
```

**Step 3 — Install Ollama**

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Step 4 — Pull Model**

```bash
ollama pull llama3
```

**Step 5 — Clone Repository**

```bash
cd ~ && git clone https://github.com/fahadwaheedhk/apex-sec.git && cd apex-sec
```

**Step 6 — Create Virtual Environment**

```bash
python3 -m venv venv && source venv/bin/activate
```

**Step 7 — Install Python Packages**

```bash
pip install --upgrade pip && pip install streamlit requests langchain langchain-community langchain-ollama
```

---

### 🐧 Fedora · RHEL

**Step 1 — Update System**

```bash
sudo dnf update -y
```

**Step 2 — Install Dependencies**

```bash
sudo dnf install python3 python3-pip git curl -y
```

**Step 3 — Install Ollama**

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Step 4 — Pull Model**

```bash
ollama pull llama3
```

**Step 5 — Clone Repository**

```bash
cd ~ && git clone https://github.com/fahadwaheedhk/apex-sec.git && cd apex-sec
```

**Step 6 — Create Virtual Environment**

```bash
python3 -m venv venv && source venv/bin/activate
```

**Step 7 — Install Python Packages**

```bash
pip install --upgrade pip && pip install streamlit requests langchain langchain-community langchain-ollama
```

---

## 🚀 Launch Sequence

> 🖥️ **Open THREE separate terminals. Keep them all running.**

### Terminal 1 — Start Ollama Engine

```bash
ollama serve
```

### Terminal 2 — Launch APEX-SEC Dashboard

```bash
cd ~/apex-sec
```

```bash
source venv/bin/activate
```

```bash
streamlit run apex_sec.py
```

### Terminal 3 — Monitor (Optional)

```bash
htop
```

### Access the Web Interface

Open your browser and navigate to:

```
http://localhost:8501
```

### Remote Access (Lab / VM only)

```bash
streamlit run apex_sec.py --server.address 0.0.0.0 --server.port 8501
```

---

## 🎬 First-Run Walkthrough

| # | Step | Action |
| :---: | :--- | :--- |
| 1 | **Sidebar → Target Profile** | Enter target IP, OS, and environment details |
| 2 | **Sidebar → AI Model Config** | Select `llama3` (or `dolphin-mixtral` for uncensored research) |
| 3 | **Sidebar → Persona** | Choose your operator role (e.g., Bug Bounty Hunter) |
| 4 | **Sidebar → Threat Intelligence** | Sync CISA feed to load live KEV entries |
| 5 | **Chat Tab** | Start asking queries for step-by-step guidance |
| 6 | **Payload Library** | Browse 50+ pre-built payloads |
| 7 | **Reports Tab** | Export structured findings into Markdown · HTML · JSON |

---

## 📡 Threat Intelligence Sync

| Step | Action | Result |
| :---: | :--- | :--- |
| 1 | Open dashboard at `http://localhost:8501` | Interface loads |
| 2 | Sidebar → Threat Intelligence → **Sync CISA** | Ingests latest exploited CVEs |
| 3 | Sidebar → **Cache Info** | Displays number of cached entries |
| 4 | Tab → Tools → **CVE Lookup (NVD)** | Fetches a specific CVE from NIST |
| 5 | Tab → Vulnerabilities → **Search CISA cache** | Filters KEV entries by keyword |

---

## 🗂 Project Structure

```
apex-sec/
├── apex_sec.py              # Main application (single-file deployment)
├── README.md                # Documentation
├── LICENSE                  # MIT License
├── requirements.txt         # Python dependencies
├── .gitignore               # Ignore config/, venv/, __pycache__/
└── config/                  # Auto-created on first run
    ├── apex_config.json     # Persistent app configuration
    ├── apex_memory.db       # SQLite conversation memory
    ├── threat_intel.json    # Cached CISA KEV feed
    ├── evidence/            # Uploaded screenshots & artifacts
    ├── reports/             # Generated reports
    └── apex_sec.log         # Application log
```

### `requirements.txt`

```txt
streamlit>=1.30.0
requests>=2.31.0
langchain>=0.2.0
langchain-community>=0.2.0
langchain-ollama>=0.1.0
```

### `.gitignore`

```
__pycache__/
*.pyc
venv/
.env
config/
.streamlit/
*.log
```

---

## 🛠 Troubleshooting

| Problem | Solution |
| :--- | :--- |
| **"AI engine unavailable"** | Start Ollama using `ollama serve` in a separate terminal |
| **"model 'llama3' not found"** | Run `ollama pull llama3` in your terminal |
| **Port 8501 in use** | Run Streamlit on a different port: `streamlit run apex_sec.py --server.port 8502` |
| **CISA sync fails** | Verify internet connectivity — required for initial feed sync |
| **Slow inference** | Lower `Max Tokens` in sidebar settings or ensure 8+ GB free RAM |
| **Permission denied on config/** | Grant read/write permissions: `chmod -R u+w config/` |
| **Streamlit not found** | Ensure virtual environment is active: `source venv/bin/activate` |
| **Ollama won't start** | Check service status: `systemctl status ollama` |
| **Out of memory during inference** | Use a smaller model: `ollama pull llama3:8b-instruct-q4_0` |

---

## ⚖️ Legal & Educational Purpose

> [!CAUTION]
> **MANDATORY SECURITY COMPLIANCE NOTICE**
>
> APEX-SEC is engineered strictly for **authorized security audits**, **academic research**, **defensive infrastructure hardening**, and **legitimate bug bounty operations**.
>
> - **Explicit Authorization** — Operators must secure legal, written consent from target system owners prior to executing any security assessments.
> - **Regulatory Adherence** — Users retain sole legal accountability for complying with all regional, national, and international cybersecurity frameworks.
> - **Educational Use** — This tool is provided for educational and research purposes to help security professionals learn structured methodologies in controlled environments.
> - **Zero Liability** — The developer accepts absolute zero liability or responsibility for unauthorized intrusions, infrastructure damages, or malicious activities conducted utilizing this suite.

### 🙏 Why This Tool Exists

APEX-SEC is built **primarily as an educational platform**. It is intended to:

- Help students and junior analysts learn structured penetration testing methodologies
- Provide a sandboxed environment to study real-world attack vectors safely
- Enable defenders to understand offensive techniques for better detection engineering
- Support researchers in documenting and reproducing vulnerabilities responsibly

**Use it wisely, ethically, and legally.**

---

---

## 📞 Connect with the Developer

| Platform | Channel |
| :--- | :--- |
| **GitHub Repository** | [github.com/FahadWaheedHk](https://github.com/FahadWaheedHk) |
| **Professional Network** | [linkedin.com/in/fahad-waheed-hk](https://pk.linkedin.com/in/fahad-waheed-hk-7a128932a) |
| **Global Communications** | [@Fahad_Waheed_Hk](https://x.com/fahad_waheed_hk) |
| **Secure Email** | [fahadwaheedhk@protonmail.com](mailto:fahadwaheedhk@protonmail.com) |

---
## 🎁 Appendix — Quick Command Reference

### Ollama Operations

```bash
ollama serve
```

```bash
ollama list
```

```bash
ollama pull llama3
```

```bash
ollama pull dolphin-mixtral
```

```bash
ollama pull qwen2.5:14b
```

### Launch Commands

```bash
cd ~/apex-sec
```

```bash
source venv/bin/activate
```

```bash
streamlit run apex_sec.py
```

### Custom Port

```bash
streamlit run apex_sec.py --server.port 8502
```

### Remote Access

```bash
streamlit run apex_sec.py --server.address 0.0.0.0
```

### Logs

```bash
tail -f config/apex_sec.log
```

### Reset Configuration

```bash
rm -rf config/
```

### Update APEX-SEC

```bash
cd ~/apex-sec
```

```bash
git pull
```

```bash
source venv/bin/activate
```

```bash
pip install -r requirements.txt
```

### Application Paths

| Item | Path |
| :--- | :--- |
| Application Script | `~/apex-sec/apex_sec.py` |
| Configuration | `~/apex-sec/config/apex_config.json` |
| Memory Database | `~/apex-sec/config/apex_memory.db` |
| Threat Intel Cache | `~/apex-sec/config/threat_intel.json` |
| Evidence Vault | `~/apex-sec/config/evidence/` |
| Reports | `~/apex-sec/config/reports/` |
| Logs | `~/apex-sec/config/apex_sec.log` |
| Virtual Environment | `~/apex-sec/venv/` |

### Recommended Models

| Model | Size | Best For |
| :--- | :--- | :--- |
| `llama3` | 4.7 GB | General purpose (default) |
| `llama3.1` | 4.7 GB | Improved reasoning |
| `dolphin-mixtral` | 26 GB | Uncensored / exploit research |
| `qwen2.5:14b` | 9 GB | Multilingual |
| `mistral` | 4.1 GB | Fast inference |

---

<div align="center">

## ⚡ APEX-SEC v1.0.0

**Built for the Operators, by an Operator.**

_100% On-Premises. 100% Yours._

[⬆ Back to Top](#-apex-sec)

</div>

---
