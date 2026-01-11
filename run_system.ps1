$ErrorActionPreference = "Stop"

# Ensure we rely on the local venv python
$VenvPython = ".\.venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "Error: Virtual environment not found. Please run environment setup first." -ForegroundColor Red
    exit 1
}

Write-Host "Starting NIST-Compliant AI Auditor..." -ForegroundColor Cyan
& $VenvPython main.py
