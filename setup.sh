#!/usr/bin/env bash

set -e

echo "=============================================="
echo " VulNet FinTech AI Agent Security Lab (Level 2)"
echo " Environment Setup"
echo "=============================================="

echo ""
echo "[1/5] Checking Python..."

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
echo "[2/5] Creating virtual environment..."

if [ ! -d "venv" ] || [ ! -f "venv/bin/activate" ]; then
    rm -rf venv
    $PY_CMD -m venv venv
    echo "Virtual environment created in ./venv"
else
    echo "Virtual environment already exists."
fi

echo ""
echo "[3/5] Activating virtual environment..."

source venv/bin/activate

echo ""
echo "[4/5] Upgrading pip..."

python -m pip install --upgrade pip --quiet

echo ""
echo "[5/5] Installing dependencies..."

python -m pip install -r requirements.txt

echo ""
echo "=============================================="
echo " Setup completed successfully!"
echo "=============================================="

echo ""
echo "To run the test suite (136 tests across 16 suites):"
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