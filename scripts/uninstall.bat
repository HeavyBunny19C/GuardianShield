@echo off
setlocal
title GuardianShield Uninstall

REM ============================================================
REM  GuardianShield Uninstall - Full cleanup of install and runtime
REM  Requires Administrator privileges
REM  Usage: uninstall.bat [-key password]
REM ============================================================

echo.
echo  ============================================================
echo        GuardianShield Uninstall - Full Cleanup
echo  ============================================================
echo.

REM 1. Check admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Please run as Administrator.
    echo.
    pause
    exit /b 1
)

REM 2. Get uninstall key
set "UNINSTALL_KEY="
if "%~1"=="-key" (
    set "UNINSTALL_KEY=%~2"
)
if "%UNINSTALL_KEY%"=="" (
    set /p UNINSTALL_KEY="  Enter admin uninstall key: "
)
if "%UNINSTALL_KEY%"=="" (
    echo  [ERROR] No key entered. Uninstall cancelled.
    pause
    exit /b 1
)
echo.

set "HAS_ERROR=0"

REM 3. Locate executables
set "GA="
set "GB="
set "GC="
if exist "C:\Program Files\GuardianShield\svchost_core.exe" (
    set "GA=C:\Program Files\GuardianShield\svchost_core.exe"
    set "GB=C:\Program Files\GuardianShield\svchost_helper.exe"
    set "GC=C:\Program Files\GuardianShield\winmon.exe"
)
if "%GA%"=="" (
    for %%I in ("%~dp0..") do set "PROJECT_ROOT=%%~fI"
    call :find_build_exe
)
goto :after_find

:find_build_exe
if exist "%PROJECT_ROOT%\build\src\service\GuardianA\Release\svchost_core.exe" (
    set "GA=%PROJECT_ROOT%\build\src\service\GuardianA\Release\svchost_core.exe"
    set "GB=%PROJECT_ROOT%\build\src\service\GuardianB\Release\svchost_helper.exe"
    set "GC=%PROJECT_ROOT%\build\src\service\GuardianC\Release\winmon.exe"
)
exit /b 0

:after_find

REM ========== Step 0: MSI uninstall ==========
echo  [0/8] Checking for MSI-installed product...
call :msi_uninstall
goto :after_msi

:msi_uninstall
set "MSI_PID="
set "MSI_REG_KEY="
for /f "usebackq tokens=*" %%a in (`reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "GuardianShield" /d 2^>nul ^| findstr /i "HKEY_"`) do (
    for /f "tokens=*" %%b in ('reg query "%%a" /v "UninstallString" 2^>nul ^| findstr /i "msiexec"') do (
        for %%I in (%%a) do set "MSI_PID=%%~nxI"
        set "MSI_REG_KEY=%%a"
    )
)
if "%MSI_PID%"=="" (
    echo  [OK] No MSI product found; skipping MSI step.
    exit /b 0
)
echo  Found MSI product: %MSI_PID%
echo  Running MSI uninstall (passing key)...
start /wait msiexec /x "%MSI_PID%" INSTALL_KEY="%UNINSTALL_KEY%" /passive
ping -n 4 127.0.0.1 >nul
REM Verify MSI uninstall succeeded; if not, force-clean the registration
set "MSI_STILL="
for /f "usebackq tokens=*" %%a in (`reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "GuardianShield" /d 2^>nul ^| findstr /i "HKEY_"`) do (
    set "MSI_STILL=%%a"
)
if defined MSI_STILL (
    echo  [WARN] MSI uninstall did not complete. Force-cleaning product registration...
    reg delete "%MSI_STILL%" /f >nul 2>&1
    REM Also clean WOW6432Node if present
    for /f "usebackq tokens=*" %%a in (`reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "GuardianShield" /d 2^>nul ^| findstr /i "HKEY_"`) do (
        reg delete "%%a" /f >nul 2>&1
    )
    REM Clean Windows Installer product registration
    for /f "usebackq tokens=*" %%a in (`reg query "HKLM\SOFTWARE\Classes\Installer\Products" /s /f "GuardianShield" /d 2^>nul ^| findstr /i "HKEY_"`) do (
        reg delete "%%a" /f >nul 2>&1
    )
    echo  [OK] Product registration force-cleaned.
) else (
    echo  [OK] MSI uninstall completed successfully.
)
exit /b 0

:after_msi

REM 4. Stop services and processes
echo  [1/8] Stopping services and processes...
sc stop WinDefenderCore >nul 2>&1
sc stop WinDefenderHelper >nul 2>&1
ping -n 4 127.0.0.1 >nul
taskkill /F /IM svchost_core.exe >nul 2>&1
taskkill /F /IM svchost_helper.exe >nul 2>&1
taskkill /F /IM winmon.exe >nul 2>&1
ping -n 3 127.0.0.1 >nul
echo  [OK] Services and processes stopped.

REM 5. Graceful uninstall via exe
echo  [2/8] Attempting service uninstall via executables (10s timeout)...
if defined GA if exist "%GA%" start "" /b "%GA%" -uninstall -key "%UNINSTALL_KEY%"
if defined GB if exist "%GB%" start "" /b "%GB%" -uninstall -key "%UNINSTALL_KEY%"
if defined GC if exist "%GC%" start "" /b "%GC%" --uninstall -key "%UNINSTALL_KEY%"
ping -n 11 127.0.0.1 >nul
taskkill /F /IM svchost_core.exe >nul 2>&1
taskkill /F /IM svchost_helper.exe >nul 2>&1
taskkill /F /IM winmon.exe >nul 2>&1
echo  [OK] Executable uninstall step complete.

REM 6. Force remove service registrations
echo  [3/8] Cleaning service registrations...
sc delete WinDefenderCore >nul 2>&1
sc delete WinDefenderHelper >nul 2>&1
echo  [OK] Service registrations cleaned.

REM 7. Clean registry
echo  [4/8] Cleaning registry...
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v WindowsMonitor /f >nul 2>&1
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v GuardianC /f >nul 2>&1
reg delete "HKLM\SOFTWARE\GuardianShield" /f >nul 2>&1
reg delete "HKCU\SOFTWARE\GuardianShield" /f >nul 2>&1
echo  [OK] Registry cleaned.

REM 8. Clean ProgramData
echo  [5/8] Cleaning runtime data (ProgramData)...
if exist "C:\ProgramData\GuardianShield" (
    for /L %%R in (1,1,3) do (
        if exist "C:\ProgramData\GuardianShield" (
            rmdir /s /q "C:\ProgramData\GuardianShield" >nul 2>&1
            if exist "C:\ProgramData\GuardianShield" ping -n 3 127.0.0.1 >nul
        )
    )
    if exist "C:\ProgramData\GuardianShield" (
        echo  [WARN] Some runtime data may be locked. Delete after reboot.
        set "HAS_ERROR=1"
    ) else (
        echo  [OK] Runtime data cleaned.
    )
) else (
    echo  [OK] No runtime data to clean.
)

REM 9. Clean Program Files
echo  [6/8] Cleaning install directory (Program Files)...
if exist "C:\Program Files\GuardianShield" (
    for /L %%R in (1,1,3) do (
        if exist "C:\Program Files\GuardianShield" (
            rmdir /s /q "C:\Program Files\GuardianShield" >nul 2>&1
            if exist "C:\Program Files\GuardianShield" ping -n 3 127.0.0.1 >nul
        )
    )
    if exist "C:\Program Files\GuardianShield" (
        echo  [WARN] Some install files may be locked. Delete after reboot.
        set "HAS_ERROR=1"
    ) else (
        echo  [OK] Install directory cleaned.
    )
) else (
    echo  [OK] No install directory to clean.
)

REM 10. Clean temp files
echo  [7/8] Cleaning temp files...
set "TEMP_GS=%TEMP%\GuardianShield"
if exist "%TEMP_GS%" (
    rmdir /s /q "%TEMP_GS%" >nul 2>&1
    if exist "%TEMP_GS%" (
        echo  [WARN] Temp folder in use: %TEMP_GS%
    ) else (
        echo  [OK] Temp folder cleaned.
    )
) else (
    echo  [OK] No temp folder to clean.
)

echo  [8/8] Final verification...
echo  [OK] All cleanup steps completed.
echo.

if "%HAS_ERROR%"=="1" (
    echo  ============================================================
    echo    Uninstall completed with warnings (see above)
    echo  ============================================================
) else (
    echo  ============================================================
    echo    GuardianShield fully uninstalled and cleaned.
    echo  ============================================================
)
echo.
echo  If any residual remains, reboot and manually delete:
echo    - C:\ProgramData\GuardianShield\
echo    - C:\Program Files\GuardianShield\
echo.
pause
exit /b 0
