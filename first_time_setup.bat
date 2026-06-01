@echo off
setlocal

cd /d "%~dp0"
set PYTHONUNBUFFERED=1
where py >nul 2>nul
if %errorlevel%==0 (
  set "PY_LAUNCHER=py"
) else (
  set "PY_LAUNCHER=python"
)

if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  %PY_LAUNCHER% -m venv .venv
)

echo Installing requirements...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt

echo.
echo Setup complete. Starting analyzer...
".venv\Scripts\python.exe" -u main.py

echo.
echo Done. Press any key to close.
pause >nul
