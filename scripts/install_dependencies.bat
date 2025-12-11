@echo off
REM Install Python dependencies for Hyperion CTI Tenable Integration

echo ========================================
echo Hyperion CTI - Installing Dependencies
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo.
    echo Please install Python from: https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation!
    echo.
    pause
    exit /b 1
)

echo Python found:
python --version
echo.

REM Upgrade pip first
echo Upgrading pip...
python -m pip install --upgrade pip
echo.

REM Install required packages
echo Installing required packages...
echo This may take a few minutes...
echo.

pip install requests==2.31.0
pip install openpyxl==3.1.2
pip install python-dotenv==1.0.0
pip install pandas==2.1.4

echo.
echo ========================================
echo Installation complete!
echo ========================================
echo.
echo You can now run: run_daily_check.bat
echo.

pause