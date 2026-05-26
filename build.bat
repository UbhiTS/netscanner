@echo off
REM ===================================================================
REM  Build Netryx into a single standalone Windows .exe
REM
REM  Run this ONCE on your Windows machine. It produces:
REM      dist\Netryx.exe
REM  which you can copy anywhere and run by double-clicking - no Python
REM  required on that machine. The UI, the OpenAPI spec and the MCP
REM  server module are all bundled inside.
REM
REM  Requires Python 3.8+ with internet access (to fetch PyInstaller).
REM ===================================================================
setlocal
cd /d "%~dp0"

set PY=python
where py >nul 2>nul && set PY=py

echo Installing PyInstaller (if needed)...
%PY% -m pip install --upgrade pyinstaller || goto :fail

echo.
echo Building Netryx.exe ...
REM --add-data bundles files into the exe (Windows uses ; as the separator).
REM --hidden-import pulls in the MCP server, which netryx.py imports lazily.
%PY% -m PyInstaller --onefile --name Netryx --console ^
    --add-data "ui.html;." ^
    --add-data "openapi.yaml;." ^
    --hidden-import netryx_mcp ^
    --hidden-import netryx ^
    netryx.py || goto :fail

echo.
echo ===================================================================
echo  Done!  Your standalone app is here:
echo     %~dp0dist\Netryx.exe
echo ===================================================================
echo.
pause
goto :eof

:fail
echo.
echo *** Build failed. See the messages above. ***
pause
exit /b 1
