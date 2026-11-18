@echo off
REM ==============================================================================
REM ARTIFEX: Windows Live Incident Forensics & FTK Imager Triage Collector
REM ==============================================================================

setlocal enabledelayedexpansion

echo ======================================================================
echo    ARTIFEX: Live Incident Response ^& FTK Imager Acquisition
echo ======================================================================

REM Check for Administrative privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Administrator privileges required.
    echo [*] Attempting to elevate...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

set CASE_ID=INC-%DATE:~10,4%%DATE:~4,2%%DATE:~7,2%-%TIME:~0,2%%TIME:~3,2%
set CASE_ID=%CASE_ID: =0%
set OUTPUT_DIR=.\case_evidence_%CASE_ID%

echo [*] Case ID: %CASE_ID%
echo [*] Output:  %OUTPUT_DIR%

REM Run ARTIFEX Live Acquisition
python cli.py acquire --output "%OUTPUT_DIR%" --tool auto --case-id "%CASE_ID%" --auto-analyze

echo.
echo [+] Process complete. Check %OUTPUT_DIR% for reports and evidence.
pause

