Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "   🛡️   CODE-DPDP: Automated Installation & Setup (PowerShell)   " -ForegroundColor White
Write-Host "   India Digital Personal Data Protection Act 2023 & Rules 2025   " -ForegroundColor Yellow
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "[1/5] Detecting Python 3 environment..." -ForegroundColor White
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[!] Error: Python is not installed or not in your PATH." -ForegroundColor Red
    Write-Host "Please download Python 3.10+ from https://www.python.org/downloads/ and check 'Add Python to PATH'."
    Exit 1
}

$pyVer = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$pyMajor = & python -c "import sys; print(sys.version_info.major)"
$pyMinor = & python -c "import sys; print(sys.version_info.minor)"

if ([int]$pyMajor -lt 3 -or ([int]$pyMajor -eq 3 -and [int]$pyMinor -lt 10)) {
    Write-Host "[!] Error: Python 3.10 or higher is required. Found Python $pyVer" -ForegroundColor Red
    Exit 1
}
Write-Host "✓ Found Python $pyVer" -ForegroundColor Green

Write-Host "[2/5] Creating isolated virtual environment (.venv)..." -ForegroundColor White
if (-not (Test-Path ".venv")) {
    & python -m venv .venv
    Write-Host "✓ Created virtual environment in .venv" -ForegroundColor Green
} else {
    Write-Host "✓ Existing .venv directory found." -ForegroundColor Green
}

Write-Host "[3/5] Installing Python dependencies from requirements.txt..." -ForegroundColor White
& .venv\Scripts\python.exe -m pip install --upgrade pip --quiet
if (Test-Path "requirements.txt") {
    & .venv\Scripts\python.exe -m pip install -r requirements.txt --quiet
    Write-Host "✓ Python dependencies successfully installed." -ForegroundColor Green
} else {
    & .venv\Scripts\python.exe -m pip install rich reportlab pyyaml requests pytest python-dotenv pillow --quiet
    Write-Host "✓ Core dependencies installed." -ForegroundColor Green
}

Write-Host "[4/5] Checking Node.js environment (optional)..." -ForegroundColor White
$npmCmd = Get-Command npm -ErrorAction SilentlyContinue
if ($npmCmd) {
    Write-Host "✓ Found npm. Installing package dependencies..." -ForegroundColor Green
    & npm install --no-audit --no-fund --quiet *>$null
} else {
    Write-Host "[-] Node/npm not found. Python standalone engine will be used." -ForegroundColor Yellow
}

Write-Host "[5/5] Configuring command-line launcher..." -ForegroundColor White
$userBin = "$env:USERPROFILE\.local\bin"
if (-not (Test-Path $userBin)) {
    New-Item -ItemType Directory -Path $userBin -Force | Out-Null
}
Copy-Item "code-dpdp.cmd" "$userBin\code-dpdp.cmd" -Force
Write-Host "✓ Local launcher 'code-dpdp.cmd' configured." -ForegroundColor Green
Write-Host ""

Write-Host "[*] Verifying installation with self-test..." -ForegroundColor White
& .\code-dpdp.cmd --version

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Green
Write-Host "   🎉 CODE-DPDP Successfully Installed and Ready to Use!          " -ForegroundColor White
Write-Host "==================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Quick Start Commands:" -ForegroundColor White
Write-Host "  .\code-dpdp.cmd scan .                     - Scan current folder for DPDP violations" -ForegroundColor Cyan
Write-Host "  .\code-dpdp.cmd scan . --pdf report.pdf    - Generate official PDF compliance report" -ForegroundColor Cyan
Write-Host "  .\code-dpdp.cmd rag `"parental consent`"     - Query the complete DPDP Act 2023 rulebook" -ForegroundColor Cyan
Write-Host "  .\code-dpdp.cmd pii .                      - Scan for Indian PII (Aadhaar, PAN, etc.)" -ForegroundColor Cyan
Write-Host "  .\code-dpdp.cmd consent .                  - Audit consent mechanisms & SARAL rules" -ForegroundColor Cyan
Write-Host "  .\code-dpdp.cmd egress .                   - Inspect trackers & data exfiltration" -ForegroundColor Cyan
Write-Host "  .\code-dpdp.cmd penalty .                  - Compute financial penalty exposure" -ForegroundColor Cyan
Write-Host "  .\code-dpdp.cmd patch . --patches out\     - Generate unified diff patches" -ForegroundColor Cyan
Write-Host ""
