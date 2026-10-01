# 🛡️ VulNet FinTech AI Agent Security Lab

A safe, local lab for exploring the OWASP Agentic Top 10 (ASI01–ASI10) against a simulated FinTech AI agent. Everything is synthetic: no real bank, customer data, credentials or network access.

## 🚀 Installation

**Requirements:** Python 3.10–3.13, Git, and optionally [Ollama](https://ollama.com) for the real LLM (without it, chat falls back to a labelled offline simulator).

```bash
git clone https://github.com/electra956/VulNet-AI-Agent-Security-Lab.git
cd VulNet-AI-Agent-Security-Lab
```

**Linux / WSL / macOS** — one command installs on first run, then starts everything:

```bash
./start.sh            # Ollama + API :8000 + dashboard :8501
./start.sh status     # check services
./start.sh stop       # stop everything
```

**Windows (PowerShell):**

```powershell
.\setup_windows.ps1
.\venv\Scripts\Activate.ps1
uvicorn api.main:app --host 127.0.0.1 --port 8000      # terminal 1
streamlit run chatbot\app.py                           # terminal 2
```

**Manual setup:**

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn api.main:app --host 127.0.0.1 --port 8000      # terminal 1
streamlit run chatbot/app.py                           # terminal 2
```

**Ollama (optional):**

```bash
ollama serve
ollama pull llama3.2
ollama pull nomic-embed-text
```

Open http://localhost:8501 and sign in (password + simulated MFA code shown on screen). API docs: http://127.0.0.1:8000/docs.

Demo accounts (full list in [docs/demo-guide.md](docs/demo-guide.md)):

| User | Password | Role |
|---|---|---|
| alex_morgan | Cust001Secure!2026 | Customer |
| morgan_vance | Admin001Secure!2026 | Admin |

## ⚔️ Usage

- **Chat** — local `llama3.2`, RAG with citations, guarded tool calls, human approval for high-risk transfers.
- **Attack Lab** and ten **OWASP Agentic Top 10** pages — pick a scenario, run it in secure or vulnerable mode, and see which control acted.

```bash
python -m lab list
python -m lab run ASI01 direct --mode vulnerable     # attack works (synthetic lab)
python -m lab run ASI01 direct --mode secure         # a named control stops it
python -m lab report                                 # writes reports/
```

## 🧪 Tests

```bash
pytest               # full suite: 667 passed, 1 skipped (~4 min)
python -m lab test   # 47 attack scenarios: 43 PASS, 4 SIMULATED (ASI05), 0 FAIL
```

If `source venv/bin/activate` doesn't take effect (WSL), use `venv/bin/python -m pytest` and `venv/bin/python -m lab test`.

## 📚 Docs

[architecture](docs/architecture.md) · [demo guide](docs/demo-guide.md) · [installation](docs/installation.md) · [security model](docs/security-model.md) · [OWASP Agentic Top 10](docs/owasp-agentic-top10.md) · [testing](docs/testing.md) · [threat model](docs/threat-model.md)

## ⚠️ Safety

Educational use only. Run locally, never expose the vulnerable mode to the internet, and never use real credentials or customer data.
