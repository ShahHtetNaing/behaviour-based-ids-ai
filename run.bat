@echo off
setlocal

cd /d "%~dp0"
set PYTHONUNBUFFERED=1

if exist ".venv\Scripts\python.exe" (
  set "PYTHON_EXE=.venv\Scripts\python.exe"
) else (
  where py >nul 2>nul
  if %errorlevel%==0 (
    set "PYTHON_EXE=py"
  ) else (
    set "PYTHON_EXE=python"
  )
)

echo Running Behaviour-based IPS...
echo Progress bars will appear below while analysis runs.
echo.

"%PYTHON_EXE%" -u main.py

echo.
echo Done. Press any key to close.
pause >nul