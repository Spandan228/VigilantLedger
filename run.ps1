# ============================================================================
# PROJECT: VigilantLedger
# FILE: run.ps1
# DESCRIPTION: Startup and runtime configuration orchestrator for the 
#              VigilantLedger application.
# ============================================================================

Clear-Host
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "              🛡️  VIGILANTLEDGER SECURE LEDGER SYSTEM  🛡️" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Verify Python Environment
Write-Host "[*] Inspecting local Python environment..." -ForegroundColor Yellow
$PythonCheck = Get-Command python -ErrorAction SilentlyContinue
if (!$PythonCheck) {
    Write-Host "[!] Error: Python runtime environment could not be found." -ForegroundColor Red
    Write-Host "[!] Please ensure Python 3.8+ is installed and present in system environment variables." -ForegroundColor Yellow
    Exit 1
}
$PyVersion = python --version
Write-Host "[+] Environment confirmed: $PyVersion" -ForegroundColor Green

# 2. Sync Package Dependencies
Write-Host "[*] Syncing package dependencies from requirements.txt..." -ForegroundColor Yellow
try {
    python -m pip install -r requirements.txt --quiet
    Write-Host "[+] Package dependencies successfully synchronized." -ForegroundColor Green
}
catch {
    Write-Host "[!] Warning: Error occurred during dependency synchronization. Some features may be unstable." -ForegroundColor Red
    Write-Host "[!] Attempting to run anyways..." -ForegroundColor Yellow
}

# 3. Spin up Dashboard Application
Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "[+] Launching VigilantLedger Security Operations Dashboard (FastAPI)." -ForegroundColor Green
Write-Host "[*] Dashboard will open in default browser at http://127.0.0.1:8501" -ForegroundColor Yellow
Write-Host "[*] Press [Ctrl + C] in this window to terminate execution." -ForegroundColor DarkYellow
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

uvicorn backend.app_api:app --host 127.0.0.1 --port 8501 --reload
