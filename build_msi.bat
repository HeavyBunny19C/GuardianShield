@echo off
setlocal
chcp 65001 >nul 2>&1

set "PROJECT_ROOT=%~dp0"
cd /d "%PROJECT_ROOT%"

echo.
echo ============================================================
echo        GuardianShield MSI Installer Builder
echo ============================================================
echo.

:: ============================================================
:: Step 1: Locate WiX Toolset 3.x
:: ============================================================
set "WIX_BIN="

if defined WIX (
    if exist "%WIX%bin\candle.exe" (
        set "WIX_BIN=%WIX%bin"
        goto :wix_found
    )
)

for /d %%D in ("C:\Program Files (x86)\WiX Toolset v3*") do (
    if exist "%%D\bin\candle.exe" (
        set "WIX_BIN=%%D\bin"
        goto :wix_found
    )
)

where candle.exe >nul 2>&1
if %errorlevel% equ 0 (
    for /f "delims=" %%P in ('where candle.exe') do (
        set "WIX_BIN=%%~dpP"
        goto :wix_found
    )
)

echo [ERROR] WiX Toolset 3.x not found.
echo.
echo   Please install WiX Toolset v3.14:
echo   https://github.com/wixtoolset/wix3/releases
echo.
echo   After installation, candle.exe should be at:
echo   C:\Program Files (x86)\WiX Toolset v3.14\bin\candle.exe
echo.
pause
exit /b 1

:wix_found
echo [OK] WiX Toolset found: %WIX_BIN%

:: ============================================================
:: Step 2: Verify build artifacts
:: ============================================================
set "BUILD_DIR=%PROJECT_ROOT%build"
set "MSI_OUT_DIR=%BUILD_DIR%\bin\Release"
set "GA_EXE=%BUILD_DIR%\src\service\GuardianA\Release\svchost_core.exe"
set "GB_EXE=%BUILD_DIR%\src\service\GuardianB\Release\svchost_helper.exe"
set "GC_EXE=%BUILD_DIR%\src\service\GuardianC\Release\winmon.exe"
set "CA_DLL=%BUILD_DIR%\bin\Release\guardian_ca.dll"

set "MISSING=0"

if not exist "%GA_EXE%" (
    echo [MISSING] svchost_core.exe
    set "MISSING=1"
)
if not exist "%GB_EXE%" (
    echo [MISSING] svchost_helper.exe
    set "MISSING=1"
)
if not exist "%GC_EXE%" (
    echo [MISSING] winmon.exe
    set "MISSING=1"
)
if not exist "%CA_DLL%" (
    echo [MISSING] guardian_ca.dll
    set "MISSING=1"
)

if "%MISSING%"=="1" (
    echo.
    echo [ERROR] Build artifacts not found. Please build the project first:
    echo   run.bat -^> [2] Build Only
    echo   or: build.bat
    echo.
    pause
    exit /b 1
)

echo [OK] All build artifacts found

call :archive_old_msi

:: ============================================================
:: Step 3: Create staging directory
:: ============================================================
set "STAGING=%BUILD_DIR%\msi_staging"
set "OBJ_DIR=%BUILD_DIR%\msi_obj"

if exist "%STAGING%" rmdir /s /q "%STAGING%"
if exist "%OBJ_DIR%" rmdir /s /q "%OBJ_DIR%"
mkdir "%STAGING%"
mkdir "%OBJ_DIR%"

echo Staging build artifacts...
copy /y "%GA_EXE%" "%STAGING%\svchost_core.exe" >nul
copy /y "%GB_EXE%" "%STAGING%\svchost_helper.exe" >nul
copy /y "%GC_EXE%" "%STAGING%\winmon.exe" >nul
copy /y "%CA_DLL%" "%STAGING%\guardian_ca.dll" >nul
copy /y "%PROJECT_ROOT%config\guardian_config.yaml" "%STAGING%\guardian_config.yaml" >nul
copy /y "%PROJECT_ROOT%config\auth.list" "%STAGING%\auth.list" >nul

echo [OK] Staging complete

:: ============================================================
:: Step 4: Compile WiX sources (candle)
:: ============================================================
echo.
echo Compiling WiX sources...

"%WIX_BIN%\candle.exe" -nologo -arch x64 ^
    -ext WixUtilExtension ^
    "-dBuildOutputDir=%STAGING%" ^
    -out "%OBJ_DIR%\\" ^
    "%PROJECT_ROOT%src\installer\GuardianShield.wxs" ^
    "%PROJECT_ROOT%src\installer\InstallDlg.wxs"

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] WiX candle compilation failed.
    pause
    exit /b 1
)

echo [OK] WiX compilation succeeded

:: ============================================================
:: Step 5: Link WiX objects (light)
:: ============================================================
echo.
echo Linking MSI package...

if not exist "%MSI_OUT_DIR%" mkdir "%MSI_OUT_DIR%"

"%WIX_BIN%\light.exe" -nologo ^
    -ext WixUIExtension ^
    -ext WixUtilExtension ^
    -cultures:zh-CN ^
    -sice:ICE17 -sice:ICE20 ^
    -out "%MSI_OUT_DIR%\GuardianShield.msi" ^
    "%OBJ_DIR%\GuardianShield.wixobj" ^
    "%OBJ_DIR%\InstallDlg.wixobj"

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] WiX light linking failed.
    pause
    exit /b 1
)

:: ============================================================
:: Done
:: ============================================================
echo.
echo ============================================================
echo                MSI BUILD SUCCESS!
echo ============================================================
echo.
echo   Output: %MSI_OUT_DIR%\GuardianShield.msi
echo.

:: Clean up intermediate files
rmdir /s /q "%STAGING%" 2>nul
rmdir /s /q "%OBJ_DIR%" 2>nul

pause
exit /b 0

:archive_old_msi
if not exist "%MSI_OUT_DIR%\GuardianShield.msi" exit /b 0
if not exist "%PROJECT_ROOT%releases" mkdir "%PROJECT_ROOT%releases"
if not exist "%PROJECT_ROOT%releases" (
    echo [WARN] Cannot create releases directory, skipping archive
    exit /b 0
)
set "N=0"
:find_next_slot
set /a N+=1
if exist "%PROJECT_ROOT%releases\GuardianShield_build%N%.msi" goto :find_next_slot
copy /y "%MSI_OUT_DIR%\GuardianShield.msi" "%PROJECT_ROOT%releases\GuardianShield_build%N%.msi"
if not exist "%PROJECT_ROOT%releases\GuardianShield_build%N%.msi" (
    echo [WARN] Failed to archive previous MSI, continuing build...
    exit /b 0
)
echo [OK] Previous MSI archived: releases\GuardianShield_build%N%.msi
exit /b 0
