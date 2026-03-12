@echo off
setlocal
set SCRIPT_DIR=%~dp0
set ROOT=%SCRIPT_DIR%..\..
set IOC=%ROOT%\iocs\seed-iocs.txt

:menu
echo.
echo ================================
echo Defend Endpoint Launcher
echo ================================
echo 1. Audit Mode (safe default)
echo 2. Remediation Mode (admin recommended)
echo 3. Live Connection Dashboard (realtime monitor)
echo 4. Exit
set /p CHOICE=Select option [1-4]: 

if "%CHOICE%"=="1" (
  powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%defend-endpoint.ps1" -Mode audit -IocFile "%IOC%" -BroadcastAlert
  goto end
)
if "%CHOICE%"=="2" (
  powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%defend-endpoint.ps1" -Mode remediate -IocFile "%IOC%" -BroadcastAlert
  goto end
)
if "%CHOICE%"=="3" (
  powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%connection-monitor.ps1" -IntervalSec 2
  goto end
)
if "%CHOICE%"=="4" goto end

echo Invalid selection.
goto menu

:end
echo.
echo Finished.
pause
