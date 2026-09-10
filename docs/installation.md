# 🚀 VulNet AI Agent Security Lab — Installation & Setup

This guide provides instructions for installing and running the VulNet AI Agent Security Lab on Linux, macOS, WSL, and Windows.

---

## 1. System Requirements
- **Python**: 3.10, 3.11, 3.12, or 3.13
- **Git**: Installed and available in PATH
- **Memory**: Minimum 2 GB RAM
- **Disk Space**: ~500 MB for virtual environment and packages
- **Network**: Internet connection required only for initial `pip install`

---

## 2. Automated Setup

### Linux / WSL / macOS
```bash
git clone https://github.com/electra956/VulNet-AI-Agent-Security-Lab.git
cd VulNet-AI-Agent-Security-Lab

chmod +x setup.sh
./setup.sh

source venv/bin/activate
streamlit run chatbot/app.py
```

### Windows (PowerShell)
```powershell
git clone https://github.com/electra956/VulNet-AI-Agent-Security-Lab.git
cd VulNet-AI-Agent-Security-Lab

.\setup_windows.ps1
.\venv\Scripts\Activate.ps1
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

### Step 4: Verify Installation
Run the test suite to verify that all components are functioning correctly:
```bash
pytest
```

### Step 5: Start the Application
```bash
streamlit run chatbot/app.py
```
Open your web browser at `http://localhost:8501`.
