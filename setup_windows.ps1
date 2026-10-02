# VulNet FinTech AI Agent Security Lab (Level 2)
# Windows PowerShell Setup Script

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " VulNet FinTech AI Agent Security Lab (Level 2)" -ForegroundColor Cyan
Write-Host " Windows Environment Setup" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Detect Python Command
Write-Host "[1/6] Checking Python installation..." -ForegroundColor Yellow

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
Write-Host "[2/6] Setting up virtual environment..." -ForegroundColor Yellow

# If venv exists but lacks Scripts (e.g. created under WSL/Linux with bin/), recreate for Windows native
if ((Test-Path "venv\bin") -and (-not (Test-Path "venv\Scripts"))) {
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
Write-Host "[3/6] Upgrading pip..." -ForegroundColor Yellow
& ".\$venvPath\Scripts\python.exe" -m pip install --upgrade pip --quiet

# 4. Install Dependencies
Write-Host ""
Write-Host "[4/6] Installing dependencies from requirements.txt..." -ForegroundColor Yellow
& ".\$venvPath\Scripts\python.exe" -m pip install -r requirements.txt

# 5. Check & Install Ollama (Local LLM Engine)
Write-Host ""
Write-Host "[5/6] Checking Ollama (Local LLM Engine)..." -ForegroundColor Yellow

$ollamaExe = "$env:LOCALAPPDATA\Programs\Ollama"
$ollamaInstalled = [bool](Get-Command ollama -ErrorAction SilentlyContinue)
if (-not $ollamaInstalled -and (Test-Path "$ollamaExe\ollama.exe")) {
    $env:Path += ";$ollamaExe"
    $ollamaInstalled = $true
}

if (-not $ollamaInstalled) {
    Write-Host "Ollama not detected. Downloading OllamaSetup.exe..." -ForegroundColor Cyan
    $installerPath = "$env:TEMP\OllamaSetup.exe"
    try {
        Invoke-WebRequest -Uri "https://ollama.com/download/OllamaSetup.exe" -OutFile $installerPath -UseBasicParsing
        Start-Process -FilePath $installerPath -ArgumentList "/SILENT" -Wait
        $env:Path += ";$ollamaExe"
        $ollamaInstalled = [bool](Get-Command ollama -ErrorAction SilentlyContinue)
    } catch {
        Write-Host "Could not install Ollama automatically. Install it from https://ollama.com/download/OllamaSetup.exe" -ForegroundColor Yellow
        Write-Host "VulNet will use its built-in offline simulation until Ollama is available." -ForegroundColor Yellow
    }
} else {
    Write-Host "Ollama is already installed." -ForegroundColor Green
}

# 6. Ensure the Ollama service is running and models are pulled
Write-Host ""
Write-Host "[6/6] Verifying Ollama service and models..." -ForegroundColor Yellow
if ($ollamaInstalled) {
    $running = $false
    try {
        Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -TimeoutSec 2 | Out-Null
        $running = $true
    } catch {
        Write-Host "Starting Ollama service..." -ForegroundColor Cyan
        Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden
        for ($i = 0; $i -lt 10 -and -not $running; $i++) {
            Start-Sleep -Seconds 1
            try {
                Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -TimeoutSec 2 | Out-Null
                $running = $true
            } catch {}
        }
    }

    if ($running) {
        $installed = (& ollama list) -join "`n"
        foreach ($model in @("llama3.2", "nomic-embed-text")) {
            if ($installed -notmatch [regex]::Escape($model)) {
                Write-Host "Pulling $model (this may take a few minutes)..." -ForegroundColor Cyan
                & ollama pull $model
            } else {
                Write-Host "Model $model is ready!" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "Ollama service did not start. Run 'ollama serve', then 'ollama pull llama3.2' and 'ollama pull nomic-embed-text'." -ForegroundColor Yellow
    }
}

# Done
Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " Setup completed successfully!" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To run test suite (136 tests across 16 suites):" -ForegroundColor White
Write-Host "    .\$venvPath\Scripts\python.exe -m pytest" -ForegroundColor Yellow
Write-Host ""
Write-Host "To start Ollama (if it is not already running):" -ForegroundColor White
Write-Host "    ollama serve" -ForegroundColor Yellow
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
