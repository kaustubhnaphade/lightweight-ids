@echo off
REM IDS GUI Launcher
REM Automatically requests administrator privileges

REM Change to the directory where this batch file is located
cd /d "%~dp0"

echo ========================================
echo  Lightweight IDS - GUI Launcher
echo ========================================
echo.

REM Check if Python is available
py --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not found!
    echo Please install Python 3.7 or higher
    echo.
    pause
    exit /b 1
)

echo Starting IDS GUI...
echo.
echo Note: The GUI will request administrator privileges.
echo       Click "Yes" on the User Account Control prompt.
echo.

REM Launch the GUI (will request admin if needed)
REM Using pythonw to avoid double console windows
start "" pythonw ids_gui.py

REM If pythonw not available, fall back to py
if errorlevel 1 (
    py ids_gui.py
    if errorlevel 1 (
        echo.
        echo Error: Failed to start IDS GUI
        echo Please try running: py ids_gui.py
        echo.
        pause
    )
)
