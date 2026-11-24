@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%SCRIPT_DIR%.venv\Scripts\python.exe"
    set "ROOT_DIR=%SCRIPT_DIR%"
) else if exist "%SCRIPT_DIR%..\.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%SCRIPT_DIR%..\.venv\Scripts\python.exe"
    set "ROOT_DIR=%SCRIPT_DIR%..\"
) else (
    set "PYTHON_EXE=python"
    set "ROOT_DIR=%SCRIPT_DIR%"
)
set "PYTHONPATH=%ROOT_DIR%python;%PYTHONPATH%"
"%PYTHON_EXE%" -m dpdp_audit.cli %*
