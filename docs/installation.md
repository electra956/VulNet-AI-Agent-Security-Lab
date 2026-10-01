# 🚀 VulNet FinTech AI Agent Security Lab — Installation & Setup

This guide provides instructions for installing and running the VulNet FinTech AI Agent Security Lab on Linux, macOS, WSL, and Windows.

---

## 1. System Requirements
- **Python**: 3.10, 3.11, 3.12, or 3.13
- **Git**: Installed and available in PATH
- **Memory**: Minimum 2 GB RAM
- **Disk Space**: ~500 MB for virtual environment and dependencies
- **Network**: Internet connection required only for initial package installation

---

## 1b. Local LLM (Ollama) — required for real LLM answers and semantic RAG

`setup.sh`, `setup.ps1` and `setup_windows.ps1` attempt steps 1–3 for you and `./start.sh` starts the server; do them by hand if that fails.

1. **Install Ollama**
   * Linux / WSL (needs `curl` and `zstd`): `sudo apt-get install -y curl zstd && curl -fsSL https://ollama.com/install.sh | sh`
   * macOS: installer from https://ollama.com/download or `brew install ollama`
   * Windows: run https://ollama.com/download/OllamaSetup.exe (it starts Ollama automatically)
   * Verify: `ollama --version`
2. **Start the server** (skip if the desktop app / a systemd service already runs it): `ollama serve` → http://127.0.0.1:11434
3. **Pull the models**: `ollama pull llama3.2` (chat) and `ollama pull nomic-embed-text` (embeddings for RAG); check with `ollama list`
4. **Configure** `.env` (copy `.env.example`): `OLLAMA_BASE_URL=http://127.0.0.1:11434`, `OLLAMA_MODEL=llama3.2`, `OLLAMA_EMBED_MODEL=nomic-embed-text`
5. **Verify**: `curl http://127.0.0.1:11434/api/tags` lists both models; the dashboard **🩺 System Health** page shows Ollama and the embedding model as up.

Without Ollama the app still runs: replies are labelled *Offline simulation*, retrieval falls back to TF-IDF, and the Attack Lab uses its
deterministic agent policy. See [llm-and-rag.md](llm-and-rag.md).

---

## 1c. One-command start (Linux / WSL / macOS)
```bash
./start.sh            # sets up if needed, starts Ollama (if installed), API :8000 and dashboard :8501
./start.sh status | stop | test | report
./start.sh --no-ollama
```
Then open http://localhost:8501 (demo users: [demo-guide.md](demo-guide.md)).

---

## 2. Automated Setup

### Linux / WSL / macOS
```bash
git clone https://github.com/electra956/VulNet-AI-Agent-Security-Lab.git
cd VulNet-AI-Agent-Security-Lab

chmod +x setup.sh
./setup.sh

source venv/bin/activate
```

To run the backend and frontend:
```bash
# Terminal 1: Launch FastAPI API Gateway
uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2: Launch Streamlit Web UI
streamlit run chatbot/app.py
```

### Windows (PowerShell)
```powershell
git clone https://github.com/electra956/VulNet-AI-Agent-Security-Lab.git
cd VulNet-AI-Agent-Security-Lab

.\setup_windows.ps1
.\venv\Scripts\Activate.ps1
```

To run the backend and frontend:
```powershell
# Terminal 1: Launch FastAPI API Gateway
uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2: Launch Streamlit Web UI
streamlit run chatbot\app.py
```

---

## 3. Manual Installation

If you prefer to install manually without the automated scripts:

### Step 1: Create Virtual Environment
```bash
# Linux / macOS / WSL
python3 -m venv venv
source venv/bin/activate

# Windows PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 2: Upgrade Pip & Install Dependencies
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Optional Configuration
Copy the example environment file if customization is desired:
```bash
cp .env.example .env
```

### Step 4: Verify Installation with Test Suite
Run the full test suite (366 tests across 38 test suites):
```bash
pytest
```

### Step 5: Start the Services

#### 1. Start FastAPI API Gateway (Backend)
```bash
uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```
- Interactive OpenAPI Swagger documentation: `http://127.0.0.1:8000/docs`
- Alternative ReDoc documentation: `http://127.0.0.1:8000/redoc`
- System Health endpoint: `http://127.0.0.1:8000/health`

#### 2. Start Streamlit Web Interface (Frontend)
```bash
streamlit run chatbot/app.py
```
- Access the FinTech AI Agent dashboard at: `http://localhost:8501`
- If port 8501 is occupied: `streamlit run chatbot/app.py --server.port 8502`

