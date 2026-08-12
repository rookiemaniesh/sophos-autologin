# Builds a single-file Windows executable.
#   powershell -ExecutionPolicy Bypass -File build.ps1

$ErrorActionPreference = "Stop"

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt pyinstaller

# --windowed  : no console window when the GUI opens
# --onefile   : single distributable exe
# hidden imports: keyring loads its Windows backend dynamically, so
#                 PyInstaller cannot see it by static analysis
pyinstaller `
  --noconfirm `
  --onefile `
  --windowed `
  --name SophosAutoLogin `
  --hidden-import "keyring.backends.Windows" `
  --hidden-import "win32timezone" `
  --collect-submodules keyring.backends `
  --exclude-module numpy `
  --exclude-module pandas `
  --exclude-module matplotlib `
  run.py

Write-Host ""
Write-Host "Built: dist\SophosAutoLogin.exe" -ForegroundColor Green
