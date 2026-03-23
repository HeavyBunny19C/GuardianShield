@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1

REM ============================================================
REM  GuardianShield Package Builder
REM  Creates a deployment package from build artifacts.
REM
REM  Usage:
REM    package.bat                  (uses default build output)
REM    package.bat <build_dir>      (specify custom build directory)
REM
REM  Output: releases\GuardianShield-<version>\
REM ============================================================

set "PROJECT_ROOT=%~dp0.."
set "VERSION=3.3.0"
set "PACKAGE_NAME=GuardianShield-v%VERSION%"
set "OUTPUT_DIR=%PROJECT_ROOT%\releases\%PACKAGE_NAME%"

REM Determine build directory
if not "%~1"=="" (
    set "BUILD_DIR=%~1"
) else (
    set "BUILD_DIR=%PROJECT_ROOT%\build"
)

set "GA=%BUILD_DIR%\src\service\GuardianA\Release\svchost_core.exe"
set "GB=%BUILD_DIR%\src\service\GuardianB\Release\svchost_helper.exe"
set "GC=%BUILD_DIR%\src\service\GuardianC\Release\winmon.exe"

echo.
echo  ============================================================
echo    GuardianShield Package Builder  v%VERSION%
echo  ============================================================
echo.

REM Verify build artifacts exist
echo  [1/4] Verifying build artifacts...
set "MISSING=0"
if not exist "%GA%" ( echo  [MISSING] %GA% & set "MISSING=1" )
if not exist "%GB%" ( echo  [MISSING] %GB% & set "MISSING=1" )
if not exist "%GC%" ( echo  [MISSING] %GC% & set "MISSING=1" )

if "%MISSING%"=="1" (
    echo.
    echo  [ERROR] Build artifacts not found. Run build.bat first.
    echo          Build dir: %BUILD_DIR%
    exit /b 1
)
echo  [OK] All build artifacts found.

REM Create output directory
echo  [2/4] Creating package directory...
if exist "%OUTPUT_DIR%" (
    rmdir /s /q "%OUTPUT_DIR%"
)
mkdir "%OUTPUT_DIR%"
echo  [OK] %OUTPUT_DIR%

REM Copy files
echo  [3/4] Copying files...

copy /y "%GA%" "%OUTPUT_DIR%\svchost_core.exe" >nul
echo    + svchost_core.exe
copy /y "%GB%" "%OUTPUT_DIR%\svchost_helper.exe" >nul
echo    + svchost_helper.exe
copy /y "%GC%" "%OUTPUT_DIR%\winmon.exe" >nul
echo    + winmon.exe

copy /y "%PROJECT_ROOT%\install.bat" "%OUTPUT_DIR%\install.bat" >nul
echo    + install.bat

if exist "%PROJECT_ROOT%\config\guardian_config.yaml" (
    copy /y "%PROJECT_ROOT%\config\guardian_config.yaml" "%OUTPUT_DIR%\guardian_config.yaml" >nul
    echo    + guardian_config.yaml
)
if exist "%PROJECT_ROOT%\config\auth.list" (
    copy /y "%PROJECT_ROOT%\config\auth.list" "%OUTPUT_DIR%\auth.list" >nul
    echo    + auth.list
)

echo  [OK] Files copied.

REM Summary
echo  [4/4] Package summary:
echo.
echo    Package:   %OUTPUT_DIR%
echo    Contents:
for %%F in ("%OUTPUT_DIR%\*") do (
    for %%S in ("%%~zF") do (
        set "SIZE=%%~S"
        set /a "KB=!SIZE!/1024"
        echo      %%~nxF  (!KB! KB^)
    )
)
echo.
echo  ============================================================
echo    Package ready: %OUTPUT_DIR%
echo.
echo    Deploy to target machine:
echo      1. Copy the %PACKAGE_NAME% folder to target
echo      2. Edit guardian_config.yaml and auth.list
echo      3. Run as Administrator:
echo         install.bat /install /key ^<your-key^>
echo  ============================================================
echo.
exit /b 0
