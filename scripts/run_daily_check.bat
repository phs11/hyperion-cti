@echo off
REM Hyperion CTI - Daily CVE Check Runner
REM This batch file runs the Tenable integration script

echo ========================================
echo Hyperion CTI - Daily CVE Check
echo ========================================
echo.

REM Change to script directory
cd /d "%~dp0"

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check if .env file exists (in parent directory)
if not exist "..\\.env" (
    echo ERROR: .env configuration file not found!
    echo Expected location: %~dp0..\\.env
    echo Please create .env file with your API keys in the project root.
    echo See setup guide for details.
    pause
    exit /b 1
)

REM Clean up old reports (older than 3 days)
echo Cleaning up old reports...
if exist "reports" (
    forfiles /p "reports" /s /m *.xlsx /d -3 /c "cmd /c del @path" 2>nul
    if errorlevel 1 (
        echo No old reports to clean up.
    ) else (
        echo Old reports cleaned up successfully.
    )
)
echo.

REM Run the Python script
echo Running CVE check...
echo.
python tenable_checker.py

REM Check if script executed successfully
if errorlevel 1 (
    echo.
    echo ERROR: Script execution failed!
    echo Check the error messages above.
    pause
    exit /b 1
)

echo.
echo ========================================
echo Check complete! Report saved in reports\\ folder.
echo ========================================
echo.

REM Optional: Open the reports folder
REM explorer reports

REM Uncomment below if you want window to stay open
REM pause

exit /b 0