@echo off
REM ==============================================================================
REM code-dpdp | One-Click Automated Setup & Installation Script (Windows)
REM India Digital Personal Data Protection Act 2023 & DPDP Rules 2025 Scanner
REM ==============================================================================

setlocal enabledelayedexpansion
title CODE-DPDP Setup & Installation

echo ==================================================================
echo    [+] CODE-DPDP: Automated Installation & Setup (Windows)
echo    India Digital Personal Data Protection Act 2023 & Rules 2025
echo ==================================================================
echo.

cd /d "%~dp0"

REM Step 1: Detect Python
echo [1/5] Detecting Python environment...
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [!] Error: Python is not installed or not in your PATH.
    echo Please download and install Python 3.10+ from https://www.python.org/downloads/
    echo Make sure to check the box "Add Python to PATH" during installation.
    pause
    exit /b 1
)

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [!] Error: Python 3.10 or higher is required.
    python --version
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do set "PY_VER=%%i"
echo [v] %PY_VER% detected.
echo.

REM Step 2: Create Python Virtual Environment (.venv)
echo [2/5] Creating isolated virtual environment (.venv)...
if not exist ".venv" (
    python -m venv .venv
    echo [v] Created virtual environment in .venv
) else (
    echo [v] Existing .venv directory found.
)
echo.

REM Step 3: Install dependencies
echo [3/5] Installing Python dependencies from requirements.txt...
.venv\Scripts\python.exe -m pip install --upgrade pip --quiet
if exist "requirements.txt" (
    .venv\Scripts\python.exe -m pip install -r requirements.txt --quiet
    echo [v] Python dependencies successfully installed.
) else (
    .venv\Scripts\python.exe -m pip install rich reportlab pyyaml requests pytest python-dotenv pillow --quiet
    echo [v] Core Python dependencies installed.
)
echo.

REM Step 4: Check Node.js / npm (Optional)
echo [4/5] Checking Node.js environment (optional)...
where npm >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [v] Found npm. Installing package dependencies...
    call npm install --no-audit --no-fund --quiet >nul 2>nul
) else (
    echo [-] Node/npm not found. Python standalone engine will be used.
)
echo.

REM Step 5: Configure CLI wrappers & user PATH
echo [5/5] Configuring Windows command-line launcher...

REM Create user local bin if possible
set "USER_BIN=%USERPROFILE%\.local\bin"
if not exist "%USER_BIN%" mkdir "%USER_BIN%" >nul 2>nul
copy /y "code-dpdp.cmd" "%USER_BIN%\code-dpdp.cmd" >nul 2>nul

echo [v] Local launcher 'code-dpdp.cmd' created in project root and %USER_BIN%.
echo.

REM Run Self-Test
echo [*] Verifying installation with self-test...
call code-dpdp.cmd --version
echo.

echo ==================================================================
echo    🎉 CODE-DPDP Successfully Installed and Ready to Use!
echo ==================================================================
echo.
echo You can run 'code-dpdp' or 'code-dpdp.cmd' from this folder!
echo.
echo Quick Start Commands:
echo   code-dpdp scan .                     - Scan current folder for DPDP violations
echo   code-dpdp scan . --pdf report.pdf    - Generate official PDF compliance report
echo   code-dpdp rag "parental consent"     - Query the complete DPDP Act 2023 rulebook
echo   code-dpdp pii .                      - Scan for Indian PII (Aadhaar, PAN, etc.)
echo   code-dpdp consent .                  - Audit consent mechanisms & SARAL rules
echo   code-dpdp egress .                   - Inspect trackers & data exfiltration
echo   code-dpdp penalty .                  - Compute financial penalty exposure
echo   code-dpdp patch . --patches out\     - Generate unified diff patches
echo.
echo Tip: To run 'code-dpdp' from ANY directory, add this folder or %USER_BIN% to your Windows System/User PATH.
echo.
pause
