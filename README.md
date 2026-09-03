# ⚡ APEX_SEC: Enterprise AI Cyber Operations Suite

### *The On-Premises Red & Blue Team Tactical Command System*
**Developed by Fahad Waheed HK (APEX_SEC)**

---

## 🎯 Overview

**APEX_SEC** is an enterprise-grade, 100% air-gapped Cyber Operations Suite engineered for Principal Security Researchers, Red Team Operators, Bug Bounty Hunters, and SOC Analysts.

Unlike generic AI wrappers that dump detectable payload lists, APEX-SEC functions as an interactive tactical operator. It enforces structured offensive methodologies by evaluating target parameters—OS architecture, network scope, technology stack, and raw terminal logs—before generating precise attack vectors, payload adjustments, and defensive mitigations.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Core Capabilities](#-core-capabilities)
- [Anonymity & Security Features](#-anonymity--security-features)
- [System Requirements](#-system-requirements)
- [Step-by-Step Installation](#-step-by-step-installation)
  - [Windows Setup](#windows-setup)
  - [Linux / Kali Linux Setup](#linux--kali-linux-setup)
- [Execution & Deployment](#-execution--deployment)
- [Threat Intelligence Sync](#-threat-intelligence-sync)
- [Legal Disclaimer](#-legal-disclaimer)

---

## 🛡️ Core Capabilities

### 🔴 Red Team Operations
| Capability | Description |
| :--- | :--- |
| **Guided Methodology** | Mentors operators through Reconnaissance, Scope Profiling, Parameter Analysis, Injection/Bypass, and Privilege Escalation |
| **Full-Spectrum Bug Coverage** | Web Applications, REST/GraphQL APIs, and Core Infrastructure |
| **Supported Attack Vectors** | SQLi, XSS, IDOR, SSRF, RCE, OAuth 2.0/JWT Bypasses, Race Conditions, Business Logic Flaws |

### 🔵 Blue Team Engineering
| Capability | Description |
| :--- | :--- |
| **Signature Generation** | Converts attack vectors into production-ready Sigma, YARA, and Snort detection rules |
| **Infrastructure Hardening** | Automated baseline checks for Docker, Kubernetes, AWS, and Linux environments |

---

## 🔐 Anonymity & Security Features

| Feature | Purpose |
| :--- | :--- |
| **Local LLM Engine** | Operates 100% offline via Ollama; no data leaves physical hardware |
| **Log Sanitization** | Automatically strips credentials and IP addresses from output |
| **Session Isolation** | Volatile in-memory processing with no cloud tracking |
| **Local Threat Cache** | CISA KEV feed cached locally in structured JSON format |

---

## 💻 System Requirements

| System Resource | Minimum Requirement | Recommended Rig |
| :--- | :--- | :--- |
| **RAM (Memory)** | 8 GB DDR4 | 16 GB – 32 GB DDR4 / DDR5 |
| **Storage Space** | 12 GB Free Space | 25 GB NVMe SSD |
| **Processor** | Intel Core i5 (8th Gen) / AMD Ryzen 5 | Intel Core i7 / i9 or AMD Ryzen 7 / 9 |
| **Operating System** | Windows 10/11, Kali Linux, Ubuntu | Windows 11 / Kali Linux 2024.x |

---
⚙️ Step-by-Step Installation

⚠️ IMPORTANT: Follow these instructions in order. Each commands in a dedicated code black for instant one-click copyings

---

Windows Setup

---

Step 1: Launch Terminal as Administrator

Open Command Prompt with Administrator privileges.

```cmd
cmd
```

---

Step 2: Install Python 3.11 Runtime

Download and install Python 3.11 using Windows Package Manager.

```bash
winget install Python.Python.3.11
```

---

Step 3: Verify Python Installation

Confirm Python is correctly installed and accessible.

```bash
python --version
```

---

Step 4: Install Ollama Engine

Install the Ollama local LLM engine.

```bash
winget install Ollama.Ollama
```

---

Step 5: Verify Ollama Installation

Confirm Ollama is correctly installed.

```bash
ollama --version
```

---

Step 6: Pull & Launch Llama 3 Core Model

Download and run the Llama 3 model locally.

```bash
ollama run llama3
```

---

Step 7: Install Required Dependencies

Install Python packages for the application.

```bash
pip install streamlit requests langchain langchain-community langchain-ollama
```

---

Linux / Kali Linux Setup

---

Step 1: Update System Package List

Refresh the package repository cache.

```bash
sudo apt update
```

---

Step 2: Upgrade Installed Packages

Update all system packages to their latest versions.

```bash
sudo apt upgrade -y
```

---

Step 3: Install Python 3 & Tools

Install Python 3, pip, virtual environment, and curl.

```bash
sudo apt install python3 python3-pip python3-venv curl -y
```

---

Step 4: Install Ollama Engine

Download and install Ollama using the official installation script.

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

---

Step 5: Pull & Launch Llama 3 Model

Download and run the Llama 3 model locally.

```bash
ollama run llama3
```

---

Step 6: Install Python Dependencies

Install required Python packages for the application.

```bash
pip3 install streamlit requests langchain langchain-community
```

---

🚀 Execution & Deployment

---

Step 1: Navigate to Project Directory

Change to the directory containing APEX_SEC.

```bash
cd ~/Desktop
```

---

Step 2: Set Execution Permissions

Make the APEX_SEC script executable.

```bash
chmod +x apex_sec.py
```

---

Step 3: Launch Tactical Command Suite

Start the Streamlit application.

```bash
streamlit run apex_sec.py
```

---

Step 4: Access Web Application Interface

Open your browser and navigate to the local server.

```bash
http://localhost:8501
```
---

## 📡 Threat Intelligence Synchronization

> **Real-Time CISA KEV Integration Pipeline**
> APEX_SEC maintains a localized, air-gapped threat feed cache to evaluate active zero-day exploits and real-world attack vectors without relying on live external telemetry.

| Sync Phase | Tactical Action | Operational Result |
| :--- | :--- | :--- |
| **Step 1: Access Interface** | Navigate to the dashboard UI | Open the primary control panel sidebar |
| **Step 2: Trigger Sync** | Click **"Synchronize Vulnerability Database"** | Initiates local ingestion of recent threat intel |
| **Step 3: Local CISA Verification** | Automated payload and vector comparison | Updates `live_vuln_db.json` on local storage |

---

## ⚖️ Legal Disclaimer & Compliance

> [!CAUTION]
> **🔴 MANDATORY SECURITY COMPLIANCE NOTICE**
> 
> APEX-SEC is engineered strictly for authorized security audits, academic research, defensive infrastructure hardening, and legitimate bug bounty operations.
> 
> * **Explicit Authorization:** Operators must secure legal, written consent from target system owners prior to executing any security assessments.
> * **Regulatory Adherence:** Users retain sole legal accountability for complying with all regional, national, and international cybersecurity frameworks.
> * **Zero Liability:** The developer accepts absolute zero liability or responsibility for unauthorized intrusions, infrastructure damages, or malicious activities conducted utilizing this suite.

---

## 📞 Connect with the Developer

| Ecosystem | Professional Profile / Direct Channel |
| :--- | :--- |
| **GitHub Repository** | [github.com/fahadwaheedhk](https://github.com/fahadwaheedhk) |
| **Professional Network** | [linkedin.com/in/fahadwaheedhk](https://linkedin.com/in/fahad-waheed-hk-7a128932a) |
| **Global Communications** | [@Fahad_Waheed_Hk](https://x.com/fahad_waheed_hk?s=11) |
| **Secure Cryptographic Email** | `fahadwaheedhk@protommail.com` |

---

<div align="center">

</div>
