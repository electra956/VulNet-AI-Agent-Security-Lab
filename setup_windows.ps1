# VulNet AI Agent Security Lab
# Windows PowerShell Setup Script

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " VulNet AI Agent Security Lab" -ForegroundColor Cyan
Write-Host " Windows Environment Setup" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python
Write-Host "[1/5] Checking Python..." -ForegroundColor Yellow
try {
    $pyVersion = python --version 2>&1
    Write-Host "Found: $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Python is not installed or not in PATH." -ForegroundColor Red
    exit 1
}

# 2. Virtual Environment
Write-Host ""
Write-Host "[2/5] Creating virtual environment..." -ForegroundColor Yellow
if (-not (Test-Path "venv")) {
    python -m venv venv
    Write-Host "Virtual environment created in .\venv" -ForegroundColor Green
} else {
    Write-Host "Virtual environment already exists." -ForegroundColor Green
}

# 3. Activate Virtual Environment
Write-Host ""
Write-Host "[3/5] Virtual environment activation instructions..." -ForegroundColor Yellow
Write-Host "To activate, run: .\venv\Scripts\Activate.ps1" -ForegroundColor Cyan

# 4. Pip Upgrade
Write-Host ""
Write-Host "[4/5] Upgrading pip in virtual environment..." -ForegroundColor Yellow
if (Test-Path ".\venv\Scripts\python.exe") {
    & ".\venv\Scripts\python.exe" -m pip install --upgrade pip --quiet
} else {
    python -m pip install --upgrade pip --quiet
}

# 5. Install Dependencies
Write-Host ""
Write-Host "[5/5] Installing dependencies from requirements.txt..." -ForegroundColor Yellow
if (Test-Path ".\venv\Scripts\python.exe") {
    & ".\venv\Scripts\python.exe" -m pip install -r requirements.txt
} else {
    python -m pip install -r requirements.txt
}

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " Setup completed successfully!" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Start the application with:" -ForegroundColor White
Write-Host "    .\venv\Scripts\Activate.ps1" -ForegroundColor Yellow
Write-Host "    streamlit run chatbot\app.py" -ForegroundColor Yellow
Write-Host ""
