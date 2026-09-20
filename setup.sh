#!/usr/bin/env bash

set -e

echo "=============================================="
echo " VulNet FinTech AI Agent Security Lab (Level 2)"
echo " Environment Setup"
echo "=============================================="

echo ""
echo "[1/6] Checking Python..."

if command -v python3 >/dev/null 2>&1; then
    PY_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PY_CMD="python"
else
    echo "ERROR: Python 3 (3.10 - 3.12 recommended) is not installed or not in PATH."
    exit 1
fi

$PY_CMD --version

echo ""
echo "[2/6] Creating virtual environment..."

if [ ! -d "venv" ] || [ ! -f "venv/bin/activate" ]; then
    rm -rf venv
    $PY_CMD -m venv venv
    echo "Virtual environment created in ./venv"
else
    echo "Virtual environment already exists."
fi

echo ""
echo "[3/6] Activating virtual environment..."

source venv/bin/activate

echo ""
echo "[4/6] Upgrading pip..."

python -m pip install --upgrade pip --quiet

echo ""
echo "[5/6] Installing dependencies..."

python -m pip install -r requirements.txt

echo ""
echo "[6/6] Checking Ollama (Local LLM Engine)..."

if ! command -v ollama >/dev/null 2>&1; then
    echo "Ollama CLI not detected. Attempting automatic installation..."

    # Install zstd if needed for extraction
    if ! command -v zstd >/dev/null 2>&1; then
        echo "Installing required extraction tool 'zstd'..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update -y && sudo apt-get install -y zstd curl || true
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y zstd curl || true
        elif command -v pacman >/dev/null 2>&1; then
            sudo pacman -S --noconfirm zstd curl || true
        fi
    fi

    # Run Ollama installer
    if curl -fsSL https://ollama.com/install.sh | sh; then
        echo "Ollama installed successfully!"
    else
        echo "Note: Ollama install was skipped or did not complete."
        echo "VulNet will run with its built-in local fallback simulation engine."
    fi
else
    echo "Ollama is already installed: $(ollama --version 2>/dev/null || echo 'available')"
fi

# If Ollama is available, ensure service is running and pull default model
if command -v ollama >/dev/null 2>&1; then
    if ! curl -s http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
        echo "Starting Ollama service (OLLAMA_HOST=0.0.0.0:11434)..."
        OLLAMA_HOST=0.0.0.0:11434 ollama serve >/dev/null 2>&1 &
        sleep 2
    fi

    echo "Checking local models..."
    if ! ollama list 2>/dev/null | grep -q "llama3.2"; then
        echo "Pulling llama3.2 model (this may take a couple of minutes)..."
        ollama pull llama3.2 || echo "Could not pull llama3.2 automatically. You can pull it later via 'ollama run llama3.2'."
    else
        echo "Model llama3.2 is already installed."
    fi
fi

echo ""
echo "=============================================="
echo " Setup completed successfully!"
echo "=============================================="

echo ""
echo "To run the test suite (329 tests across 32 suites):"
echo "    source venv/bin/activate"
echo "    pytest"
echo ""
echo "To start the FastAPI API Gateway (Backend):"
echo "    source venv/bin/activate"
echo "    uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload"
echo "    (Swagger API Docs at: http://127.0.0.1:8000/docs)"
echo ""
echo "To start the FinTech AI Agent web application (Frontend):"
echo "    source venv/bin/activate"
echo "    streamlit run chatbot/app.py"
echo ""