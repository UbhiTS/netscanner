@echo off
REM ===================================================================
REM  Netryx launcher (Windows)
REM  Double-click this file to start the scanner. It will open in your
REM  browser automatically. Requires Python 3.8+ (no extra packages).
REM ===================================================================
setlocal
cd /d "%~dp0"

REM Prefer the official "py" launcher, fall back to "python".
where py >nul 2>nul
if %errorlevel%==0 (
    py netryx.py %*
    goto :end
)

where python >nul 2>nul
if %errorlevel%==0 (
    python netryx.py %*
    goto :end
)

echo.
echo  Python was not found on this PC.
echo  Install it from https://www.python.org/downloads/  (tick "Add Python to PATH")
echo  then double-click run.bat again.
echo.
pause

:end
endlocal
