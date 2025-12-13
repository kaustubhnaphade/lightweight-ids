@echo off
REM Simple IDS GUI Launcher (No Admin Elevation)
REM Use this if the regular launcher has issues

REM Change to the directory where this batch file is located
cd /d "%~dp0"

echo ========================================
echo  Lightweight IDS - GUI Launcher
echo  (Simple Mode - No Auto Elevation)
echo ========================================
echo.

echo Starting IDS GUI...
echo.
echo IMPORTANT: For live packet capture, you must:
echo   1. Right-click this file
echo   2. Select "Run as administrator"
echo.

REM Launch GUI directly
pythonw ids_gui.py
if errorlevel 1 (
    REM Fallback to py
    py ids_gui.py
)

echo.
echo If the GUI didn't open, try running:
echo   py ids_gui.py
echo.
pause
