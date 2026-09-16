# VulNet FinTech AI Agent Security Lab (Level 2)
# Windows PowerShell Setup Script

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " VulNet FinTech AI Agent Security Lab (Level 2)" -ForegroundColor Cyan
Write-Host " Windows Environment Setup" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Detect Python Command
Write-Host "[1/5] Checking Python installation..." -ForegroundColor Yellow

$pyCmd = $null
if (Get-Command "py" -ErrorAction SilentlyContinue) {
    # Check if Python 3.12 is available via the py launcher
    $pyList = py --list 2>&1
    if ($pyList -match "3\.12") {
        $pyCmd = "py -3.12"
    } else {
        $pyCmd = "py"
    }
} elseif (Get-Command "python" -ErrorAction SilentlyContinue) {
    $pyCmd = "python"
} else {
    Write-Host "ERROR: Python is not installed or not in PATH." -ForegroundColor Red
    Write-Host "Please install Python 3.10, 3.11, or 3.12." -ForegroundColor Red
    exit 1
}

Write-Host "Using Python launcher: $pyCmd" -ForegroundColor Green
Invoke-Expression "$pyCmd --version"

# 2. Virtual Environment Creation
Write-Host ""
Write-Host "[2/5] Setting up virtual environment..." -ForegroundColor Yellow

# If venv exists but lacks Scripts (e.g. created under WSL/Linux with bin/), recreate for Windows native
if (Test-Path "venv\bin" -and -not (Test-Path "venv\Scripts")) {
    Write-Host "Detected Linux/WSL virtual environment in .\venv. Creating Windows .\venv_win..." -ForegroundColor Yellow
    $venvPath = "venv_win"
} else {
    $venvPath = "venv"
}

if (-not (Test-Path "$venvPath\Scripts\python.exe")) {
    Invoke-Expression "$pyCmd -m venv $venvPath"
    Write-Host "Virtual environment created in .\$venvPath" -ForegroundColor Green
} else {
    Write-Host "Virtual environment already exists in .\$venvPath" -ForegroundColor Green
}

# 3. Pip Upgrade
Write-Host ""
Write-Host "[3/5] Upgrading pip..." -ForegroundColor Yellow
& ".\$venvPath\Scripts\python.exe" -m pip install --upgrade pip --quiet

# 4. Install Dependencies
Write-Host ""
Write-Host "[4/5] Installing dependencies from requirements.txt..." -ForegroundColor Yellow
& ".\$venvPath\Scripts\python.exe" -m pip install -r requirements.txt

# 5. Verification instructions
Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " Setup completed successfully!" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To run test suite (136 tests across 16 suites):" -ForegroundColor White
Write-Host "    .\$venvPath\Scripts\python.exe -m pytest" -ForegroundColor Yellow
Write-Host ""
Write-Host "To start the FastAPI API Gateway (Backend):" -ForegroundColor White
Write-Host "    .\$venvPath\Scripts\Activate.ps1" -ForegroundColor Yellow
Write-Host "    uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload" -ForegroundColor Yellow
Write-Host "    (API Docs: http://127.0.0.1:8000/docs)" -ForegroundColor Gray
Write-Host ""
Write-Host "To start the Streamlit UI (Frontend):" -ForegroundColor White
Write-Host "    .\$venvPath\Scripts\Activate.ps1" -ForegroundColor Yellow
Write-Host "    streamlit run chatbot\app.py" -ForegroundColor Yellow
Write-Host ""
