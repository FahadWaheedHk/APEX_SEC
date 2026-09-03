# APEX-SEC: Enterprise AI Cyber Operations & Threat Intelligence Suite

> **The Enterprise On-Premises Red & Blue Team Tactical Command System**

---

## Overview

**APEX-SEC** is an enterprise-grade, 100% air-gapped Cyber Operations Suite engineered for **Principal Security Researchers, Red Team Operators, Bug Bounty Hunters, and SOC Analysts**. 

Unlike generic AI wrappers that dump detectable payload lists, APEX-SEC functions as an **interactive tactical operator**. It enforces structured offensive methodologies by evaluating target parameters—OS architecture, network scope, technology stack, and raw terminal logs—before generating precise attack vectors, payload adjustments, and defensive mitigations.

---

## Table of Contents

- [Overview](#overview)
- [Core Capabilities](#core-capabilities)
- [Anonymity & Security Features](#anonymity--security-features)
- [System Requirements](#system-requirements)
- [Step-by-Step Installation](#step-by-step-installation)
  - [Windows Setup](#windows-setup)
  - [Linux / Kali Linux Setup](#linux--kali-linux-setup)
- [Execution & Deployment](#execution--deployment)
- [Threat Intelligence Sync](#threat-intelligence-sync)
- [Legal Disclaimer](#legal-disclaimer)

---

## Core Capabilities

### Red Team & Offensive Operations
- **Guided Methodology:** Sequentially mentors operators through Reconnaissance, Scope Profiling, Parameter Analysis, Injection/Bypass, and Privilege Escalation.
- **Full-Spectrum Bug Coverage:** Deep methodology for Web Applications, REST/GraphQL APIs, and Core Infrastructure.
- **Supported Attack Vectors:**
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Insecure Direct Object References (IDOR)
  - Server-Side Request Forgery (SSRF)
  - Remote Code Execution (RCE)
  - OAuth 2.0 / JWT Bypasses
  - Race Conditions & Logic Flaws

### Blue Team & Detection Engineering
- **Detection Signature Generation:** Converts attack vectors directly into production-ready **Sigma**, **YARA**, and **Snort** rules.
- **Infrastructure Hardening:** Automated baseline checks and audit policies for Docker, Kubernetes, AWS, and Linux environments.

---

## Anonymity & Security Features

| Feature | Purpose |
| :--- | :--- |
| **Local LLM Engine** | Operates 100% offline via Ollama; no data leaves physical hardware |
| **Log Sanitization** | Automatically strips credentials and IP addresses from output |
| **Session Isolation** | Volatile in-memory processing with no cloud telemetry or tracking |
| **Local Threat Cache** | CISA KEV feed cached locally in structured JSON format |

---

## System Requirements

| System Resource | Minimum Requirement | Recommended Research Rig |
| :--- | :--- | :--- |
| **RAM (Memory)** | 8 GB DDR4 | 16 GB – 32 GB DDR4 / DDR5 |
| **Storage Space** | 12 GB Free Space | 25 GB NVMe SSD |
| **Processor** | Intel Core i5 (8th Gen) / AMD Ryzen 5 | Intel Core i7 / i9 or AMD Ryzen 7 / 9 |
| **Operating System** | Windows 10/11, Kali Linux, Ubuntu | Windows 11 / Kali Linux 2024.x |

---

## Step-by-Step Installation

### Windows Setup

#### Step 1: Launch Terminal as Administrator
Press `Win + S`, type `cmd`, right-click **Command Prompt**, and select **Run as Administrator**.

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

Step 7: Install Required Dependencies
pip install streamlit requests langchain langchain-community

Linux / Kali Linux Setup
Step 1: Update System Package List
sudo apt update

Step 2: Upgrade Installed Packages
sudo apt upgrade -y

Step 3: Install Python 3 & Dependencies
sudo apt install python3 python3-pip python3-venv curl -y

Step 4: Install Ollama Engine
curl -fsSL [https://ollama.com/install.sh](https://ollama.com/install.sh) | sh

Step 5: Pull & Launch Llama 3 Model
ollama run llama3

Step 6: Install Python Dependencies
pip3 install streamlit requests langchain langchain-community

Execution & Deployment
Step 1: Navigate to Project Directory
cd ~/Desktop

Step 2: Set Execution Permissions (Linux / Unix)
chmod +x apex_sec.py

Step 3: Launch Tactical Command Suite
streamlit run apex_sec.py

Step 4: Access Web Application Interface
Open your browser and navigate to:
http://localhost:8501

Threat Intelligence Sync
 * Open the left sidebar within the dashboard UI.
 * Click Synchronize Vulnerability Database.
 * APEX-SEC fetches active exploitation parameters directly from CISA KEV and updates live_vuln_db.json locally.
Legal Disclaimer
> 🔴 MANDATORY NOTICE & COMPLIANCE:
> APEX-SEC is engineered strictly for authorized security audits, educational research, defensive infrastructure hardening, and legitimate bug bounty research.
>  * Explicit Written Permission: Operators must secure explicit, written authorization from target system owners prior to executing security assessments.
>  * Regulatory Adherence: Users hold sole responsibility for complying with all local, national, and international cybersecurity laws.
>  * Zero Liability: The developer accepts no legal responsibility or liability for unauthorized access, system damage, or illegal activities conducted with this software suite.
> 

