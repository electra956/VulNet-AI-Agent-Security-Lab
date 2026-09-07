#!/usr/bin/env bash

set -e

echo "=============================================="
echo " VulNet AI Agent Security Lab"
echo " Environment Setup"
echo "=============================================="

echo ""
echo "[1/5] Checking Python..."

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: Python 3 is not installed."
    exit 1
fi

python3 --version

echo ""
echo "[2/5] Creating virtual environment..."

if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "Virtual environment created."
else
    echo "Virtual environment already exists."
fi

echo ""
echo "[3/5] Activating virtual environment..."

source venv/bin/activate

echo ""
echo "[4/5] Upgrading pip..."

python -m pip install --upgrade pip

echo ""
echo "[5/5] Installing dependencies..."

python -m pip install -r requirements.txt

echo ""
echo "=============================================="
echo " Setup completed successfully!"
echo "=============================================="

echo ""
echo "Start the application with:"
echo ""
echo "    source venv/bin/activate"
echo "    streamlit run chatbot/app.py"
echo ""