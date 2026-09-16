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
Run the full test suite (136 tests across 16 test suites):
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

