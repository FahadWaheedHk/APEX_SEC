# ⚡ APEX-SEC | Next-Gen AI Cyber Operations & Intelligence Suite

> **The Enterprise On-Premises Red & Blue Team Tactical Command System**

![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![AI Engine Ollama](https://img.shields.io/badge/AI%20Core-Ollama%20%7C%20Llama%203-FF6F00?style=for-the-badge&logo=ollama&logoColor=white)
![Dashboard Streamlit](https://img.shields.io/badge/UI-Streamlit%20Dark-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![Intelligence CISA KEV](https://img.shields.io/badge/Threat%20Feed-CISA%20KEV-0052CC?style=for-the-badge&logo=googlecloud&logoColor=white)
![Privacy 100% Offline](https://img.shields.io/badge/Security-100%25%20Air--Gapped-00A86B?style=for-the-badge&logo=shield&logoColor=white)

---

## 🔬 Overview

**APEX-SEC** is an enterprise-grade, 100% air-gapped Cyber Operations Suite engineered for **Principal Security Researchers, Red Team Operators, Bug Bounty Hunters, and SOC Analysts**.

Unlike generic AI wrappers that dump detectible payload lists, APEX-SEC functions as an **interactive tactical operator**. It enforces structured offensive methodologies by evaluating target parameters—OS architecture, network scope, technology stack, and raw terminal logs—before generating precise attack vectors, payload adjustments, and defensive mitigations.


+---------------------------------------------------------------+
|                      APEX-SEC OPERATIONAL FLOW                |
+---------------------------------------------------------------+
|  [Target Recon] ──► [Scope Profiling] ──► [Vector Audit]      |
|                                                 │             |
|  [Defensive Patch] ◄── [WAF & Log Debug] ◄──────┘             |
+---------------------------------------------------------------+

---

## 🚀 Core Capabilities

### 🔴 Red Team & Offensive Operations
* **Guided Step-by-Step Methodology:** Sequentially mentors operators through Reconnaissance, Scope Profiling, Parameter Analysis, Injection/Bypass, and Privilege Escalation.
* **Full-Spectrum Bug Coverage:** Deep methodology for Web Applications, REST/GraphQL APIs, and Infrastructure:
  * **Critical Web Vectors:** SQL Injection (SQLi), Cross-Site Scripting (XSS), Insecure Direct Object References (IDOR), Server-Side Request Forgery (SSRF), Remote Code Execution (RCE), OAuth 2.0 / JWT Bypasses, Race Conditions, and Business Logic Flaws.
* **Live WAF & Log Debugger:** Paste raw terminal errors, failed cURL requests, or HTTP 403/500 headers. APEX-SEC diagnoses syntax mismatches, bypasses WAF rules, and restructures vectors in real time.

### 🔵 Blue Team & Detection Engineering
* **Detection Signature Generation:** Converts attack vectors into production-ready **Sigma, YARA, and Snort** detection rules.
* **Infrastructure Hardening:** Security baselines and posture checks for Docker, Kubernetes, AWS, and Linux environments.

### ⚡ Threat Intelligence & Local Privacy
* **CISA KEV Dynamic Sync:** Pulls active exploited CVE parameters directly from the **CISA Known Exploited Vulnerabilities Feed** on demand.
* **100% On-Premises Isolation:** Powered locally by **Ollama (Llama 3)**. Target data, corporate IP addresses, and proprietary logs never leave your physical hardware.

---

## 💻 System Requirements

| System Resource | Minimum Requirement | Recommended Research Rig |
| :--- | :--- | :--- |
| **RAM (Memory)** | **8 GB DDR4** | **16 GB – 32 GB DDR4 / DDR5** |
| **Storage Space** | **12 GB Free Space** (HDD) | **25 GB Free Space** (NVMe SSD) |
| **Processor (CPU)** | Intel Core i5 (8th Gen) / AMD Ryzen 5 | Intel Core i7 / i9 (11th Gen+) or AMD Ryzen 7 / 9 |
| **Graphics (GPU)** | Integrated Graphics | Dedicated NVIDIA RTX 3060+ (8 GB+ VRAM) |
| **Operating System**| Windows 10/11, Kali Linux, Ubuntu | Windows 11 / Kali Linux 2024.x |

---

## ⚡ Installation & Setup Guide

### 🪟 Windows Setup

#### Step 1: Launch Terminal as Administrator
Press `Win + S` on your keyboard, type **`cmd`**, right-click **Command Prompt**, and select **Run as Administrator**.

#### Step 2: Install Python 3.11 Runtime
```cmd
winget install Python.Python.3.11

Step 3: Verify Python Installation
python --version

Step 4: Install Ollama Engine
winget install Ollama.Ollama

Step 5: Verify Ollama Installation
ollama --version

Step 6: Pull & Launch Llama 3 Core Model
ollama run llama3

> ⚠️ CRITICAL: Once the model finishes loading and displays >>>, minimize this terminal window and keep it running in the background.
> 
Step 7: Install Required Dependencies
Open a NEW Command Prompt window and run:
pip install streamlit requests langchain langchain-community

🐧 Linux / Kali Linux Setup
Step 1: Update System Repositories
sudo apt update && sudo apt upgrade -y

Step 2: Install Python 3 & Virtual Environment Tools
sudo apt install python3 python3-pip python3-venv curl -y

Step 3: Install Ollama Engine
curl -fsSL [https://ollama.com/install.sh](https://ollama.com/install.sh) | sh

Step 4: Launch Llama 3 Model Core
ollama run llama3

Step 5: Install Required Python Libraries
Open a new terminal tab and execute:
pip3 install streamlit requests langchain langchain-community

🎯 Execution & Deployment Workflow
Step 1: Navigate to Project Directory
 * Windows:
   cd Desktop

 * Linux / Kali Linux:
   cd ~/Desktop

Step 2: Set Execution Permissions (Linux / Unix Only)
chmod +x apex_sec.py

Step 3: Launch Tactical Command Suite
streamlit run apex_sec.py

Step 4: Access Web Application Interface
Open your web browser and navigate to:
http://localhost:8501

Step 5: Synchronize Live Threat Intelligence Feed
 * Open the left sidebar within the dashboard UI.
 * Click 🚀 Synchronize Vulnerability Database.
 * The engine fetches active exploitation data directly from CISA KEV, updating live_vuln_db.json locally.
⚖️ Legal Disclaimer
> 🔴 MANDATORY NOTICE & COMPLIANCE:
> APEX-SEC is engineered strictly for authorized security audits, educational research, defensive infrastructure hardening, and legitimate bug bounty research.
>  * Explicit Written Permission: Operators must secure explicit, written authorization from target system owners prior to executing security assessments.
>  * Regulatory Adherence: Users hold sole responsibility for complying with all local, national, and international cybersecurity laws.
>  * Zero Liability: The developer accepts no legal responsibility or liability for unauthorized access, system damage, or illegal activities conducted with this software suite.
> 

