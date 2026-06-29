$ErrorActionPreference = "Stop"

.\.venv\Scripts\python.exe -m PyInstaller --onefile --name vault .\vault.py

Write-Host ""
Write-Host "Built executable:"
Write-Host ".\dist\vault.exe"