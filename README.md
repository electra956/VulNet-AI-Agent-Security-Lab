# 🛡️ VulNet AI Agent Security Lab

> **A safe, local educational environment for exploring security risks in Agentic AI systems.**

VulNet AI Agent Security Lab is a controlled security research and demonstration platform designed to help security researchers, developers, and students understand how vulnerabilities can emerge in modern AI agent architectures.

The lab simulates an end-to-end Agentic AI pipeline:

```text
USER
  ↓
CHATBOT
  ↓
RAG
  ↓
MAIN AGENT
  ↓
RESEARCH AGENT
  ↓
ACTION AGENT
  ↓
MCP SERVER
  ↓
SAFE DEMO TOOLS
```

The lab provides **Secure Mode** and **Vulnerable Mode**, allowing security controls and attack scenarios to be demonstrated in a controlled local environment.

---

# 🎯 Project Goals

The goal of VulNet is to make Agentic AI security easier to understand through practical demonstrations.

The project focuses on:

- 🔐 Agent security controls
- 🤖 Multi-agent workflows
- 📚 Retrieval-Augmented Generation (RAG)
- 🔌 Model Context Protocol (MCP)
- 🛠️ Agent tool usage
- 🤝 Agent-to-agent communication
- 🚨 Prompt and goal manipulation
- 🧠 Context and memory security
- 🔑 Identity and privilege risks
- 📊 Security event logging
- 🧪 Security testing
- 🛡️ Secure vs. vulnerable behavior comparison

---

# 🏗️ Architecture

```text
                    ┌──────────────┐
                    │     USER     │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   CHATBOT    │
                    │  Streamlit   │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │     RAG      │
                    │   TF-IDF     │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │ MAIN AGENT   │
                    └──────┬───────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ RESEARCH AGENT   │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │  ACTION AGENT    │
                  └────────┬─────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │ MCP SERVER   │
                    └──────┬───────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ SAFE DEMO TOOLS  │
                  └──────────────────┘
```

---

# 🔐 Security Modes

VulNet supports two operating modes.

## 🟢 Secure Mode

Secure Mode represents a protected Agentic AI environment.

Security controls can:

- Detect suspicious instructions
- Block simulated goal-hijacking attempts
- Validate requests
- Check tool permissions
- Record security events
- Restrict tools to approved capabilities
- Prevent interaction with real production systems

Example:

```text
User Request
     ↓
Security Controller
     ↓
Suspicious pattern detected
     ↓
🚫 Request blocked
```

---

## 🔴 Vulnerable Mode

Vulnerable Mode is designed for **controlled educational demonstrations**.

It intentionally allows selected simulated insecure behaviors so researchers can observe what could happen when security controls are absent or weakened.

Example:

```text
User Request
     ↓
Security Controller
     ↓
Suspicious pattern detected
     ↓
⚠️ Allowed for simulation
     ↓
Agent Pipeline
```

### Important

Vulnerable Mode does **not** provide access to real production systems, credentials, destructive commands, or uncontrolled external services.

---

# 🧩 Core Components

## 💬 Chatbot

A Streamlit-based interface for interacting with the security lab.

Features include:

- Chat interface
- Secure/Vulnerable mode selection
- Request tracing
- System information
- Security status
- Session management

---

## 📚 RAG Engine

The RAG component retrieves relevant information from the local knowledge base.

Current implementation uses:

```text
TF-IDF
+
Cosine Similarity
```

Example knowledge sources:

```text
rag/knowledge/
├── company_policy.txt
└── test_context.txt
```

The RAG layer is intentionally local and does not require a production vector database.

---

## 🤖 Main Agent

The Main Agent receives:

- User request
- Retrieved RAG documents

It analyzes the request and passes structured context to the following stages of the pipeline.

---

## 🔎 Research Agent

The Research Agent processes the retrieved knowledge and produces research-oriented information for the next stage.

---

## 🛠️ Action Agent

The Action Agent simulates actions requested by the agent workflow.

Actions are intentionally restricted to safe educational simulations.

No real infrastructure is modified.

---

## 🔌 MCP Server

The MCP layer demonstrates how an agent can interact with controlled tools.

Current simulated capabilities include:

```text
get_security_status
check_tool_permission
create_audit_log
```

The MCP environment is designed to operate as a local educational simulation.

Security properties include:

```text
Production Access : False
Network Access    : False
Credentials Used  : False
Simulation Mode   : True
```

---

# 🛡️ Security Controller

The Security Controller provides centralized security behavior for the lab.

It supports:

```text
Secure Mode
Vulnerable Mode
Security Events
Request Validation
ASI01 Simulation
```

Example suspicious patterns currently detected include:

```text
ignore previous instructions
ignore all previous instructions
forget your instructions
change your goal
override your rules
reveal system prompt
execute this instruction
you are now
```

These detections are used for controlled security demonstrations.

---

# 🚨 OWASP Agentic AI Security Scenarios

The project is organized around the OWASP Top 10 for Agentic Applications security model.

```text
ASI01  Agent Goal Hijack
ASI02  Tool Misuse and Exploitation
ASI03  Identity and Privilege Abuse
ASI04  Agentic Supply Chain Vulnerabilities
ASI05  Unexpected Code Execution
ASI06  Memory & Context Poisoning
ASI07  Insecure Inter-Agent Communication
ASI08  Cascading Failures
ASI09  Human-Agent Trust Exploitation
ASI10  Rogue Agents
```

The vulnerability scenarios are organized under:

```text
vulnerabilities/
├── asi01_goal_hijack/
├── asi02_tool_misuse/
├── asi03_identity_privilege/
├── asi04_supply_chain/
├── asi05_code_execution/
├── asi06_memory_poisoning/
├── asi07_agent_communication/
├── asi08_cascading_failures/
├── asi09_human_trust/
└── asi10_rogue_agents/
```

> The vulnerability modules are intended for controlled security research and demonstration. They should not be interpreted as production-ready attack implementations.

---

# 🧪 Testing

The project contains tests for the major components:

```text
tests/
├── test_rag_manual.py
├── test_main_agent.py
├── test_research_agent.py
├── test_action_agent.py
├── test_mcp.py
├── test_orchestrator.py
├── test_security_controller.py
└── test_security_pipeline.py
```

Example security pipeline behavior:

```text
Normal Request
      ↓
   Allowed
      ↓
   Pipeline

ASI01 Request + Secure Mode
      ↓
   Blocked

ASI01 Request + Vulnerable Mode
      ↓
   Allowed for Simulation
```

---

# 📁 Project Structure

```text
VulNet-AI-Agent-Security-Lab/
│
├── agents/
│   ├── __init__.py
│   ├── main_agent.py
│   ├── research_agent.py
│   ├── action_agent.py
│   └── orchestrator.py
│
├── chatbot/
│   ├── __init__.py
│   └── app.py
│
├── docs/
│   ├── architecture.md
│   ├── demo-guide.md
│   ├── testing.md
│   ├── threat-model.md
│   └── vulnerabilities.md
│
├── mcp_server/
│   ├── __init__.py
│   ├── server.py
│   └── tools.py
│
├── rag/
│   ├── __init__.py
│   ├── rag_engine.py
│   └── knowledge/
│       ├── company_policy.txt
│       └── test_context.txt
│
├── security/
│   ├── __init__.py
│   └── security_controller.py
│
├── tests/
│   ├── test_action_agent.py
│   ├── test_main_agent.py
│   ├── test_mcp.py
│   ├── test_orchestrator.py
│   ├── test_rag_manual.py
│   ├── test_research_agent.py
│   ├── test_security_controller.py
│   └── test_security_pipeline.py
│
├── vulnerabilities/
│   ├── asi01_goal_hijack/
│   ├── asi02_tool_misuse/
│   ├── asi03_identity_privilege/
│   ├── asi04_supply_chain/
│   ├── asi05_code_execution/
│   ├── asi06_memory_poisoning/
│   ├── asi07_agent_communication/
│   ├── asi08_cascading_failures/
│   ├── asi09_human_trust/
│   └── asi10_rogue_agents/
│
├── reports/
├── screenshots/
│
├── .gitignore
├── README.md
├── requirements.txt
├── setup.sh
└── setup_windows.ps1
```

---

# 🚀 Installation

## Requirements

You need:

- Python 3.x
- Git
- pip
- Streamlit
- Linux / WSL / macOS / Windows

---

# ⚡ Quick Start

## 1. Clone the repository

```bash
git clone https://github.com/electra956/VulNet-AI-Agent-Security-Lab.git
cd VulNet-AI-Agent-Security-Lab
```

---

# 🐧 Linux / WSL

Check Python:

```bash
python3 --version
```

Run the automated setup:

```bash
chmod +x setup.sh
./setup.sh
```

Activate the environment:

```bash
source venv/bin/activate
```

Start the application:

```bash
streamlit run chatbot/app.py
```

---

# 🪟 Windows

Open PowerShell in the project directory.

Run:

```powershell
.\setup_windows.ps1
```

Activate the virtual environment:

```powershell
.\venv\Scripts\Activate.ps1
```

Start the application:

```powershell
streamlit run chatbot/app.py
```

---

# 🔧 Manual Installation

If the automated setup script cannot be used, follow these steps.

## Linux / WSL / macOS

Create the virtual environment:

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

Upgrade pip:

```bash
python -m pip install --upgrade pip
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the application:

```bash
streamlit run chatbot/app.py
```

---

## Windows

Create the virtual environment:

```powershell
python -m venv venv
```

Activate it:

```powershell
.\venv\Scripts\Activate.ps1
```

Upgrade pip:

```powershell
python -m pip install --upgrade pip
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Start the application:

```powershell
streamlit run chatbot/app.py
```

---

# ✅ Verify Installation

Check Python:

```bash
python --version
```

Check Streamlit:

```bash
streamlit --version
```

Check the application syntax:

```bash
python -m py_compile chatbot/app.py
```

If no error is displayed, the Python syntax check passed.

Start the application:

```bash
streamlit run chatbot/app.py
```

The Streamlit interface should open in your browser.

---

# 🧪 Running Tests

Make sure the virtual environment is active.

```bash
source venv/bin/activate
```

Run the individual tests:

```bash
python -m tests.test_rag_manual
python -m tests.test_main_agent
python -m tests.test_research_agent
python -m tests.test_action_agent
python -m tests.test_mcp
python -m tests.test_orchestrator
python -m tests.test_security_controller
python -m tests.test_security_pipeline
```

---

# 🔄 Request Flow

A normal request follows:

```text
User
 ↓
Streamlit Chatbot
 ↓
Security Controller
 ↓
RAG Engine
 ↓
Main Agent
 ↓
Research Agent
 ↓
Action Agent
 ↓
MCP Server
 ↓
Safe Demo Tools
 ↓
Audit Log
```

The Streamlit interface provides:

- 💬 Chat
- 🔍 Request Trace
- ℹ️ System Information
- 🔴 Vulnerable Mode
- 🟢 Secure Mode
- 🗑️ Session Reset

---

# 🔍 Example Security Demonstration

A simple ASI01 demonstration can compare behavior between the two modes.

## Secure Mode

```text
Suspicious instruction
        ↓
Security Controller
        ↓
🚫 Blocked
```

## Vulnerable Mode

```text
Suspicious instruction
        ↓
Security Controller
        ↓
⚠️ Allowed for controlled simulation
        ↓
Agent Pipeline
```

This allows security controls to be demonstrated without interacting with real systems.

---

# 🛠️ Troubleshooting

## `ModuleNotFoundError`

Make sure you are running from the project root:

```bash
cd VulNet-AI-Agent-Security-Lab
```

Activate the virtual environment:

```bash
source venv/bin/activate
```

Then:

```bash
streamlit run chatbot/app.py
```

---

## `externally-managed-environment`

Do not install packages into the system Python.

Create and activate the project virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Then:

```bash
pip install -r requirements.txt
```

---

## Streamlit cannot import `agents`

Run Streamlit from the project root:

```bash
cd VulNet-AI-Agent-Security-Lab
streamlit run chatbot/app.py
```

---

## Port already in use

Run Streamlit on another port:

```bash
streamlit run chatbot/app.py --server.port 8502
```

---

## Virtual environment is broken

Remove and recreate it:

```bash
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

# 👥 Team Development Workflow

Before making changes:

```bash
git pull
```

Create a feature branch:

```bash
git checkout -b feature/your-feature-name
```

Example:

```bash
git checkout -b feature/asi01-rag-poisoning
```

Make your changes.

Run the tests:

```bash
python -m tests.test_security_pipeline
```

Check Python syntax:

```bash
python -m py_compile chatbot/app.py
```

Check Git:

```bash
git status
```

Commit your changes:

```bash
git add .
git commit -m "Add ASI01 RAG security scenario"
```

Push your branch:

```bash
git push -u origin feature/asi01-rag-poisoning
```

Then create a Pull Request on GitHub.

---

# 🔐 Environment Variables and Secrets

The current educational lab is designed to run locally without production credentials.

If future components require API credentials:

1. Copy `.env.example` to `.env`
2. Add your local credentials
3. Never commit `.env`

Example:

```bash
cp .env.example .env
```

The `.env` file is intentionally excluded from Git.

### Never commit:

```text
API keys
Passwords
Access tokens
GitHub tokens
Production credentials
Private keys
Customer data
```

---

# 🧠 Threat Model

The lab considers security risks across several trust boundaries:

```text
User
 ↓
Chatbot
 ↓
RAG Context
 ↓
Agent Reasoning
 ↓
Agent-to-Agent Communication
 ↓
Tool Selection
 ↓
MCP
 ↓
Tool Execution
```

Potential attack surfaces include:

- User instructions
- Retrieved context
- Agent messages
- Tool descriptions
- Tool permissions
- Agent identity
- Memory/context
- Inter-agent communication
- Human approval workflows

See:

```text
docs/threat-model.md
```

for additional details.

---

# ⚠️ Safety Notice

**This project is intentionally designed as an educational security lab.**

It is intended for:

- Security research
- Security education
- AI safety demonstrations
- Controlled testing
- Red-team/blue-team exercises
- Agentic AI security learning

The project should be run in a controlled environment.

### Do NOT:

- Use production credentials
- Connect the vulnerable environment to production systems
- Expose vulnerable services to the public internet
- Use real customer data
- Connect destructive tools
- Execute untrusted commands on real infrastructure
- Use the project to attack systems without authorization

The MCP and Action Agent components are designed around simulated local behavior.

---

# 🗺️ Roadmap

- [ ] Complete ASI01 demonstration using RAG/context manipulation
- [ ] ASI02 Tool Misuse scenarios
- [ ] ASI03 Identity and Privilege Abuse
- [ ] ASI04 Supply Chain scenarios
- [ ] ASI05 Safe simulated code-execution demonstrations
- [ ] ASI06 Memory and Context Poisoning
- [ ] ASI07 Inter-Agent Communication attacks
- [ ] ASI08 Cascading Failure demonstrations
- [ ] ASI09 Human-Agent Trust scenarios
- [ ] ASI10 Rogue Agent simulations
- [ ] Improved agent reasoning
- [ ] More detailed security telemetry
- [ ] Automated security reports
- [ ] Additional test coverage
- [ ] Attack/defense comparison dashboards

---

# 📊 Security Philosophy

VulNet follows a simple principle:

```text
Understand the vulnerability
            ↓
Reproduce it safely
            ↓
Observe the impact
            ↓
Apply a security control
            ↓
Compare secure vs vulnerable behavior
```

The goal is not to build an uncontrolled offensive attack platform.

The goal is to understand **how Agentic AI systems fail and how those failures can be detected, controlled, and mitigated.**

---

# 📚 Documentation

Additional documentation is available in:

```text
docs/
├── architecture.md
├── demo-guide.md
├── testing.md
├── threat-model.md
└── vulnerabilities.md
```

---

# 👨‍💻 Project

## VulNet AI Agent Security Lab

A security research and educational project focused on:

```text
AI Security
      +
Agentic AI
      +
RAG Security
      +
MCP Security
      +
Multi-Agent Systems
      +
OWASP Agentic Security
```

---

# ⭐ Contributing

Contributions are welcome.

When contributing:

1. Create a feature branch.
2. Make your changes.
3. Run the relevant tests.
4. Check for secrets.
5. Commit your changes.
6. Push your branch.
7. Open a Pull Request.

Please keep all demonstrations inside safe, controlled environments.

---

# 📜 License

Add an appropriate open-source license before distributing this project publicly.

---

## ⚠️ Educational Security Lab — Use Responsibly

**VulNet AI Agent Security Lab is intended for authorized security research, education, and controlled demonstrations only.**