@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1

REM ============================================================
REM  GuardianShield Installer v1.0
REM  Pre-compiled deployment package installer (no build tools needed)
REM
REM  Usage (all commands require Administrator):
REM    install.bat /install /key <密钥>
REM    install.bat /install /key <密钥> /config <yaml路径> /auth <auth.list路径>
REM    install.bat /uninstall /key <密钥>
REM    install.bat /start
REM    install.bat /stop
REM    install.bat /status
REM
REM  Exit codes:
REM    0 = success
REM    1 = general error
REM    2 = not running as administrator
REM    3 = missing required parameter
REM    4 = binary not found
REM    5 = key verification failed
REM ============================================================

set "SCRIPT_DIR=%~dp0"
set "INSTALL_DIR=C:\Program Files\GuardianShield"
set "DATA_DIR=C:\ProgramData\GuardianShield"
set "CONFIG_DIR=%DATA_DIR%\config"
set "LOG_DIR=%DATA_DIR%\logs"

set "GA_NAME=svchost_core.exe"
set "GB_NAME=svchost_helper.exe"
set "GC_NAME=winmon.exe"

set "SVC_A=WinDefenderCore"
set "SVC_B=WinDefenderHelper"

REM ============================================================
REM  Parse command line arguments
REM ============================================================
set "CMD="
set "KEY="
set "CUSTOM_CONFIG="
set "CUSTOM_AUTH="

:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="/install"   ( set "CMD=install"   & shift & goto :parse_args )
if /i "%~1"=="/uninstall" ( set "CMD=uninstall" & shift & goto :parse_args )
if /i "%~1"=="/start"     ( set "CMD=start"     & shift & goto :parse_args )
if /i "%~1"=="/stop"      ( set "CMD=stop"      & shift & goto :parse_args )
if /i "%~1"=="/status"    ( set "CMD=status"    & shift & goto :parse_args )
if /i "%~1"=="/key"       ( set "KEY=%~2"       & shift & shift & goto :parse_args )
if /i "%~1"=="/config"    ( set "CUSTOM_CONFIG=%~2" & shift & shift & goto :parse_args )
if /i "%~1"=="/auth"      ( set "CUSTOM_AUTH=%~2"   & shift & shift & goto :parse_args )
echo [ERROR] Unknown parameter: %~1
exit /b 1

:args_done
if "%CMD%"=="" (
    echo.
    echo  GuardianShield Installer v1.0
    echo  ============================================================
    echo.
    echo  Usage:
    echo    install.bat /install /key ^<密钥^>
    echo    install.bat /install /key ^<密钥^> /config ^<yaml路径^> /auth ^<auth.list路径^>
    echo    install.bat /uninstall /key ^<密钥^>
    echo    install.bat /start
    echo    install.bat /stop
    echo    install.bat /status
    echo.
    exit /b 1
)

REM ============================================================
REM  Dispatch to command handler
REM ============================================================
if "%CMD%"=="install"   goto :cmd_install
if "%CMD%"=="uninstall" goto :cmd_uninstall
if "%CMD%"=="start"     goto :cmd_start
if "%CMD%"=="stop"      goto :cmd_stop
if "%CMD%"=="status"    goto :cmd_status
echo [ERROR] Unknown command: %CMD%
exit /b 1

REM ============================================================
REM  /install
REM ============================================================
:cmd_install
call :check_admin
if %errorlevel% neq 0 exit /b 2

if "%KEY%"=="" (
    echo [ERROR] /key parameter is required for installation.
    echo         Usage: install.bat /install /key ^<密钥^>
    exit /b 3
)

echo.
echo  ============================================================
echo        GuardianShield Installation
echo  ============================================================
echo.

REM -- Step 1: Verify source binaries exist --
echo  [1/7] Verifying deployment package...
if not exist "%SCRIPT_DIR%%GA_NAME%" (
    echo [ERROR] %GA_NAME% not found in %SCRIPT_DIR%
    echo         Ensure all binaries are in the same directory as this script.
    exit /b 4
)
if not exist "%SCRIPT_DIR%%GB_NAME%" (
    echo [ERROR] %GB_NAME% not found in %SCRIPT_DIR%
    exit /b 4
)
if not exist "%SCRIPT_DIR%%GC_NAME%" (
    echo [ERROR] %GC_NAME% not found in %SCRIPT_DIR%
    exit /b 4
)
echo  [OK] All binaries found.

REM -- Step 2: Create install directory --
echo  [2/7] Creating install directory...
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to create %INSTALL_DIR%
        exit /b 1
    )
)
echo  [OK] %INSTALL_DIR%

REM -- Step 3: Copy binaries --
echo  [3/7] Copying binaries...
copy /y "%SCRIPT_DIR%%GA_NAME%" "%INSTALL_DIR%\" >nul
if !errorlevel! neq 0 ( echo [ERROR] Failed to copy %GA_NAME% & exit /b 1 )
copy /y "%SCRIPT_DIR%%GB_NAME%" "%INSTALL_DIR%\" >nul
if !errorlevel! neq 0 ( echo [ERROR] Failed to copy %GB_NAME% & exit /b 1 )
copy /y "%SCRIPT_DIR%%GC_NAME%" "%INSTALL_DIR%\" >nul
if !errorlevel! neq 0 ( echo [ERROR] Failed to copy %GC_NAME% & exit /b 1 )
echo  [OK] Binaries copied to %INSTALL_DIR%

REM -- Step 4: Create data directories and copy config --
echo  [4/7] Setting up configuration...
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

REM Determine config source
set "CFG_SRC=%SCRIPT_DIR%guardian_config.yaml"
if not "%CUSTOM_CONFIG%"=="" (
    if exist "%CUSTOM_CONFIG%" (
        set "CFG_SRC=%CUSTOM_CONFIG%"
    ) else (
        echo [WARN] Custom config not found: %CUSTOM_CONFIG%, using default.
    )
)
if exist "%CFG_SRC%" (
    copy /y "%CFG_SRC%" "%CONFIG_DIR%\guardian_config.yaml" >nul
    echo  [OK] Config: %CFG_SRC%
) else (
    echo [WARN] No guardian_config.yaml found. System will use built-in defaults.
)

REM Determine auth.list source
set "AUTH_SRC=%SCRIPT_DIR%auth.list"
if not "%CUSTOM_AUTH%"=="" (
    if exist "%CUSTOM_AUTH%" (
        set "AUTH_SRC=%CUSTOM_AUTH%"
    ) else (
        echo [WARN] Custom auth.list not found: %CUSTOM_AUTH%, using default.
    )
)
if exist "%AUTH_SRC%" (
    copy /y "%AUTH_SRC%" "%CONFIG_DIR%\auth.list" >nul
    echo  [OK] Auth list: %AUTH_SRC%
) else (
    echo [WARN] No auth.list found. System will enter SAFE MODE (monitoring only).
)

REM -- Step 5: Register services --
echo  [5/7] Registering services...
echo.
echo  --- GuardianA (Primary Service) ---
"%INSTALL_DIR%\%GA_NAME%" -install -key "%KEY%"
if !errorlevel! neq 0 (
    echo [ERROR] GuardianA installation failed. Key may be incorrect.
    exit /b 5
)

echo  --- GuardianB (Backup Service) ---
"%INSTALL_DIR%\%GB_NAME%" -install -key "%KEY%"
if !errorlevel! neq 0 (
    echo [ERROR] GuardianB installation failed.
    exit /b 5
)

echo  --- GuardianC (User Monitor) ---
"%INSTALL_DIR%\%GC_NAME%" --install -key "%KEY%"
if !errorlevel! neq 0 (
    echo [ERROR] GuardianC installation failed.
    exit /b 5
)
echo.
echo  [OK] All services registered.

REM -- Step 6: Start services --
echo  [6/7] Starting services...
"%INSTALL_DIR%\%GA_NAME%" -start
ping -n 3 127.0.0.1 >nul
"%INSTALL_DIR%\%GB_NAME%" -start
ping -n 2 127.0.0.1 >nul
start "" "%INSTALL_DIR%\%GC_NAME%" --silent
ping -n 2 127.0.0.1 >nul
echo  [OK] Services started.

REM -- Step 7: Verify --
echo  [7/7] Verifying installation...
echo.
sc query %SVC_A% | findstr /i "RUNNING" >nul 2>&1
if !errorlevel! equ 0 (
    echo  [OK] GuardianA: RUNNING
) else (
    echo  [WARN] GuardianA: NOT RUNNING
)
sc query %SVC_B% | findstr /i "RUNNING" >nul 2>&1
if !errorlevel! equ 0 (
    echo  [OK] GuardianB: RUNNING
) else (
    echo  [WARN] GuardianB: NOT RUNNING
)
tasklist /fi "imagename eq %GC_NAME%" 2>nul | findstr /i "%GC_NAME%" >nul 2>&1
if !errorlevel! equ 0 (
    echo  [OK] GuardianC: RUNNING
) else (
    echo  [WARN] GuardianC: NOT RUNNING
)

echo.
echo  ============================================================
echo    Installation complete.
echo    Install dir:  %INSTALL_DIR%
echo    Data dir:     %DATA_DIR%
echo    Log dir:      %LOG_DIR%
echo  ============================================================
echo.
exit /b 0

REM ============================================================
REM  /uninstall
REM ============================================================
:cmd_uninstall
call :check_admin
if %errorlevel% neq 0 exit /b 2

if "%KEY%"=="" (
    echo [ERROR] /key parameter is required for uninstallation.
    exit /b 3
)

echo.
echo  ============================================================
echo        GuardianShield Uninstallation
echo  ============================================================
echo.

set "GA=%INSTALL_DIR%\%GA_NAME%"
set "GB=%INSTALL_DIR%\%GB_NAME%"
set "GC=%INSTALL_DIR%\%GC_NAME%"

REM -- Step 1: Stop all --
echo  [1/6] Stopping services and processes...
sc stop %SVC_A% >nul 2>&1
sc stop %SVC_B% >nul 2>&1
ping -n 4 127.0.0.1 >nul
taskkill /F /IM %GA_NAME% >nul 2>&1
taskkill /F /IM %GB_NAME% >nul 2>&1
taskkill /F /IM %GC_NAME% >nul 2>&1
ping -n 3 127.0.0.1 >nul
echo  [OK] Stopped.

REM -- Step 2: Uninstall via exe --
echo  [2/6] Unregistering services...
if exist "%GA%" "%GA%" -uninstall -key "%KEY%"
if exist "%GB%" "%GB%" -uninstall -key "%KEY%"
if exist "%GC%" "%GC%" --uninstall -key "%KEY%"
ping -n 3 127.0.0.1 >nul
taskkill /F /IM %GA_NAME% >nul 2>&1
taskkill /F /IM %GB_NAME% >nul 2>&1
taskkill /F /IM %GC_NAME% >nul 2>&1
echo  [OK] Services unregistered.

REM -- Step 3: Force remove service registrations --
echo  [3/6] Cleaning service registrations...
sc delete %SVC_A% >nul 2>&1
sc delete %SVC_B% >nul 2>&1
echo  [OK] Service registrations cleaned.

REM -- Step 4: Clean registry --
echo  [4/6] Cleaning registry...
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v WindowsMonitor /f >nul 2>&1
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v GuardianC /f >nul 2>&1
reg delete "HKLM\SOFTWARE\GuardianShield" /f >nul 2>&1
reg delete "HKCU\SOFTWARE\GuardianShield" /f >nul 2>&1
echo  [OK] Registry cleaned.

REM -- Step 5: Delete files --
echo  [5/6] Removing files...
set "HAS_WARN=0"

if exist "%INSTALL_DIR%" (
    for /L %%R in (1,1,3) do (
        if exist "%INSTALL_DIR%" (
            rmdir /s /q "%INSTALL_DIR%" >nul 2>&1
            if exist "%INSTALL_DIR%" ping -n 2 127.0.0.1 >nul
        )
    )
    if exist "%INSTALL_DIR%" (
        echo  [WARN] Install dir locked. Delete after reboot: %INSTALL_DIR%
        set "HAS_WARN=1"
    ) else (
        echo  [OK] Install directory removed.
    )
) else (
    echo  [OK] Install directory already clean.
)

if exist "%DATA_DIR%" (
    for /L %%R in (1,1,3) do (
        if exist "%DATA_DIR%" (
            rmdir /s /q "%DATA_DIR%" >nul 2>&1
            if exist "%DATA_DIR%" ping -n 2 127.0.0.1 >nul
        )
    )
    if exist "%DATA_DIR%" (
        echo  [WARN] Data dir locked. Delete after reboot: %DATA_DIR%
        set "HAS_WARN=1"
    ) else (
        echo  [OK] Data directory removed.
    )
) else (
    echo  [OK] Data directory already clean.
)

REM -- Step 6: Clean temp --
echo  [6/6] Cleaning temp files...
set "TEMP_GS=%TEMP%\GuardianShield"
if exist "%TEMP_GS%" (
    rmdir /s /q "%TEMP_GS%" >nul 2>&1
)
echo  [OK] Temp cleaned.

echo.
if "%HAS_WARN%"=="1" (
    echo  ============================================================
    echo    Uninstall completed with warnings. Reboot may be needed.
    echo  ============================================================
) else (
    echo  ============================================================
    echo    GuardianShield fully uninstalled.
    echo  ============================================================
)
echo.
exit /b 0

REM ============================================================
REM  /start
REM ============================================================
:cmd_start
call :check_admin
if %errorlevel% neq 0 exit /b 2

if not exist "%INSTALL_DIR%\%GA_NAME%" (
    echo [ERROR] GuardianShield is not installed. Run /install first.
    exit /b 4
)

echo  Starting GuardianA...
"%INSTALL_DIR%\%GA_NAME%" -start
ping -n 3 127.0.0.1 >nul
echo  Starting GuardianB...
"%INSTALL_DIR%\%GB_NAME%" -start
ping -n 2 127.0.0.1 >nul
echo  Starting GuardianC...
start "" "%INSTALL_DIR%\%GC_NAME%" --silent
echo  [OK] All services started.
exit /b 0

REM ============================================================
REM  /stop
REM ============================================================
:cmd_stop
call :check_admin
if %errorlevel% neq 0 exit /b 2

echo  Stopping GuardianA...
sc stop %SVC_A% >nul 2>&1
echo  Stopping GuardianB...
sc stop %SVC_B% >nul 2>&1
echo  Stopping GuardianC...
taskkill /F /IM %GC_NAME% >nul 2>&1
ping -n 3 127.0.0.1 >nul
echo  [OK] All services stopped.
exit /b 0

REM ============================================================
REM  /status
REM ============================================================
:cmd_status
echo.
echo  ============================================================
echo        GuardianShield Status
echo  ============================================================
echo.

if not exist "%INSTALL_DIR%\%GA_NAME%" (
    echo  [NOT INSTALLED] GuardianShield is not installed at %INSTALL_DIR%
    echo.
    exit /b 0
)

echo  Install dir:  %INSTALL_DIR%
echo  Data dir:     %DATA_DIR%
echo.

sc query %SVC_A% >nul 2>&1
if !errorlevel! equ 0 (
    sc query %SVC_A% | findstr /i "RUNNING" >nul 2>&1
    if !errorlevel! equ 0 (
        echo  GuardianA:  RUNNING
    ) else (
        echo  GuardianA:  STOPPED
    )
) else (
    echo  GuardianA:  NOT REGISTERED
)

sc query %SVC_B% >nul 2>&1
if !errorlevel! equ 0 (
    sc query %SVC_B% | findstr /i "RUNNING" >nul 2>&1
    if !errorlevel! equ 0 (
        echo  GuardianB:  RUNNING
    ) else (
        echo  GuardianB:  STOPPED
    )
) else (
    echo  GuardianB:  NOT REGISTERED
)

tasklist /fi "imagename eq %GC_NAME%" 2>nul | findstr /i "%GC_NAME%" >nul 2>&1
if !errorlevel! equ 0 (
    echo  GuardianC:  RUNNING
) else (
    echo  GuardianC:  NOT RUNNING
)

echo.
if exist "%CONFIG_DIR%\guardian_config.yaml" (
    echo  Config:     YAML present ^(will be consumed on next service start^)
) else if exist "%DATA_DIR%\config_cache.bin" (
    echo  Config:     Using cached configuration
) else (
    echo  Config:     Using built-in defaults
)

if exist "%LOG_DIR%" (
    for /f %%A in ('dir /b "%LOG_DIR%\*.json" 2^>nul ^| find /c /v ""') do (
        echo  Log files:  %%A file^(s^) in %LOG_DIR%
    )
) else (
    echo  Log files:  No log directory
)

echo.
exit /b 0

REM ============================================================
REM  Helper: Check administrator privileges
REM ============================================================
:check_admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This operation requires Administrator privileges.
    echo         Right-click Command Prompt ^> "Run as administrator"
    exit /b 2
)
exit /b 0
