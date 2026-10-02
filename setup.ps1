# VulNet FinTech AI Agent Security Lab - Windows Setup Script
# Usage: powershell -ExecutionPolicy Bypass -File .\setup.ps1

$ErrorActionPreference = "Stop"

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " VulNet FinTech AI Agent Security Lab (Level 2)" -ForegroundColor Cyan
Write-Host " Windows Environment Setup" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# 1. Check Python
Write-Host "`n[1/6] Checking Python..." -ForegroundColor Yellow
$pyCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pyCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pyCmd = "py"
} else {
    Write-Error "Python 3 is not installed or not in PATH."
}
& $pyCmd --version

# 2. Virtual Environment
Write-Host "`n[2/6] Checking Virtual Environment..." -ForegroundColor Yellow
$venvDir = "venv_win"
if (-not (Test-Path "$venvDir\Scripts\Activate.ps1")) {
    Write-Host "Creating virtual environment in .\$venvDir..."
    & $pyCmd -m venv $venvDir
} else {
    Write-Host "Virtual environment already exists in .\$venvDir."
}

# 3. Pip Upgrade
Write-Host "`n[3/6] Upgrading pip..." -ForegroundColor Yellow
& ".\$venvDir\Scripts\python.exe" -m pip install --upgrade pip --quiet

# 4. Install Dependencies
Write-Host "`n[4/6] Installing dependencies from requirements.txt..." -ForegroundColor Yellow
& ".\$venvDir\Scripts\python.exe" -m pip install -r requirements.txt

# 5. Check & Install Ollama
Write-Host "`n[5/6] Checking Ollama (Local LLM Engine)..." -ForegroundColor Yellow
$ollamaInstalled = $false

if (Get-Command ollama -ErrorAction SilentlyContinue) {
    $ollamaInstalled = $true
} elseif (Test-Path "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe") {
    $env:Path += ";$env:LOCALAPPDATA\Programs\Ollama"
    $ollamaInstalled = $true
}

if (-not $ollamaInstalled) {
    Write-Host "Ollama not detected on Windows." -ForegroundColor Yellow
    Write-Host "Attempting automatic download of OllamaSetup.exe..." -ForegroundColor Cyan
    $installerUrl = "https://ollama.com/download/OllamaSetup.exe"
    $installerPath = "$env:TEMP\OllamaSetup.exe"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
        Write-Host "Running Ollama installer silently..." -ForegroundColor Cyan
        Start-Process -FilePath $installerPath -ArgumentList "/SILENT" -Wait
        $env:Path += ";$env:LOCALAPPDATA\Programs\Ollama"
        if (Get-Command ollama -ErrorAction SilentlyContinue) {
            $ollamaInstalled = $true
            Write-Host "Ollama installed successfully on Windows!" -ForegroundColor Green
        }
    } catch {
        Write-Host "Warning: Could not automatically download Ollama installer." -ForegroundColor Yellow
        Write-Host "You can manually install Ollama from https://ollama.com/download/OllamaSetup.exe" -ForegroundColor Yellow
        Write-Host "VulNet will seamlessly run using its built-in local fallback simulation engine." -ForegroundColor Green
    }
} else {
    Write-Host "Ollama is already installed." -ForegroundColor Green
}

# 6. Model Verification
Write-Host "`n[6/6] Verifying Local LLM Model..." -ForegroundColor Yellow
if ($ollamaInstalled) {
    try {
        $tags = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -Method Get -TimeoutSec 2 -ErrorAction SilentlyContinue
        foreach ($model in @("llama3.2", "nomic-embed-text")) {
            $has = $false
            if ($tags -and $tags.models) {
                foreach ($m in $tags.models) {
                    if ($m.name -like "*$model*") { $has = $true }
                }
            }
            if (-not $has) {
                Write-Host "Pulling $model model..." -ForegroundColor Cyan
                & ollama pull $model
            } else {
                Write-Host "Model $model is ready!" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "Ollama service is not running yet. Run 'ollama serve' or start Ollama from the start menu to enable real Llama generation." -ForegroundColor Yellow
    }
}

Write-Host "`n==============================================" -ForegroundColor Green
Write-Host " Setup completed successfully!" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green

Write-Host "`nTo run the test suite (329 tests):" -ForegroundColor Cyan
Write-Host "    .\$venvDir\Scripts\python.exe -m pytest"

Write-Host "`nTo start the FastAPI Backend (Port 8000):" -ForegroundColor Cyan
Write-Host "    .\$venvDir\Scripts\python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 8000"

Write-Host "`nTo start the FinTech AI Agent Web Application (Port 8501):" -ForegroundColor Cyan
Write-Host "    .\$venvDir\Scripts\python.exe -m streamlit run chatbot/app.py`n"
