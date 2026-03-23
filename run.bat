@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1
title GuardianShield Control Panel

set "PROJECT_ROOT=%~dp0"
set "BUILD_DIR=%PROJECT_ROOT%build"
set "GA=%BUILD_DIR%\src\service\GuardianA\Release\svchost_core.exe"
set "GB=%BUILD_DIR%\src\service\GuardianB\Release\svchost_helper.exe"
set "GC=%BUILD_DIR%\src\service\GuardianC\Release\winmon.exe"

:menu
cls
echo.
echo  ============================================================
echo        GuardianShield Control Panel  v1.0.0
echo  ============================================================
echo.
echo    [1]  One-Click Build + Install + Start  (Full Deploy)
echo    [2]  Build Only
echo    [3]  Install Services  (requires Admin)
echo    [4]  Start Services    (requires Admin)
echo    [5]  Stop Services     (requires Admin)
echo    [6]  Check Status
echo    [7]  Uninstall All     (requires Admin)
echo    [8]  Clean Build
echo    [9]  Build MSI Installer  (requires WiX 3.x)
echo    [0]  Exit
echo.
echo  ============================================================
set /p choice="  Select [0-9]: "

if "%choice%"=="1" goto full_deploy
if "%choice%"=="2" goto build
if "%choice%"=="3" goto install
if "%choice%"=="4" goto start_all
if "%choice%"=="5" goto stop_all
if "%choice%"=="6" goto status
if "%choice%"=="7" goto uninstall
if "%choice%"=="8" goto clean
if "%choice%"=="9" goto build_msi
if "%choice%"=="0" goto quit
echo  Invalid selection.
timeout /t 2 >nul
goto menu

:: ============================================================
:: [1] Full Deploy: Build + Install + Start
:: ============================================================
:full_deploy
echo.
echo  [STEP 1/3] Building project...
call :do_build
if %errorlevel% neq 0 (
    echo  [FAILED] Build failed. Fix errors and retry.
    pause
    goto menu
)
echo  [STEP 2/3] Installing services...
call :do_install
echo  [STEP 3/3] Starting services...
call :do_start
echo.
echo  ============================================================
echo                    DEPLOYMENT COMPLETE
echo  ============================================================
call :do_status
pause
goto menu

:: ============================================================
:: [2] Build
:: ============================================================
:build
echo.
call :do_build
if %errorlevel% neq 0 (
    echo  [FAILED] Build failed.
) else (
    echo  [OK] Build succeeded.
)
echo.
pause
goto menu

:: ============================================================
:: [3] Install
:: ============================================================
:install
call :check_admin
if %errorlevel% neq 0 goto menu
call :check_binaries
if %errorlevel% neq 0 goto menu
echo.
call :do_install
echo.
pause
goto menu

:: ============================================================
:: [4] Start
:: ============================================================
:start_all
call :check_admin
if %errorlevel% neq 0 goto menu
call :check_binaries
if %errorlevel% neq 0 goto menu
echo.
call :do_start
echo.
pause
goto menu

:: ============================================================
:: [5] Stop
:: ============================================================
:stop_all
call :check_admin
if %errorlevel% neq 0 goto menu
call :check_binaries
if %errorlevel% neq 0 goto menu
echo.
call :do_stop
echo.
pause
goto menu

:: ============================================================
:: [6] Status
:: ============================================================
:status
call :check_binaries
if %errorlevel% neq 0 goto menu
echo.
call :do_status
echo.
pause
goto menu

:: ============================================================
:: [7] Uninstall
:: ============================================================
:uninstall
call :check_admin
if %errorlevel% neq 0 goto menu
call :check_binaries
if %errorlevel% neq 0 goto menu
echo.
echo  Stopping services...
call :do_stop
echo.
set /p INSTALL_KEY="  请输入卸载密钥: "
echo  Uninstalling...
echo.
echo  --- GuardianA ---
"%GA%" -uninstall -key "%INSTALL_KEY%"
echo  --- GuardianB ---
"%GB%" -uninstall -key "%INSTALL_KEY%"
echo  --- GuardianC ---
"%GC%" --uninstall -key "%INSTALL_KEY%"
echo.
echo  [OK] All services uninstalled.
echo.
pause
goto menu

:: ============================================================
:: [9] Build MSI Installer
:: ============================================================
:build_msi
echo.
call "%PROJECT_ROOT%build_msi.bat"
goto menu

:: ============================================================
:: [8] Clean Build
:: ============================================================
:clean
echo.
echo  Removing build directory...
if exist "%BUILD_DIR%" (
    rmdir /s /q "%BUILD_DIR%" 2>nul
    echo  [OK] Build directory cleaned.
) else (
    echo  [OK] Build directory already clean.
)
echo.
pause
goto menu

:: ============================================================
:: Exit
:: ============================================================
:quit
exit /b 0

:: ============================================================
:: Helper Functions
:: ============================================================

:do_build
    call :setup_msvc_env
    if %errorlevel% neq 0 (
        echo  [ERROR] Visual Studio / CMake not found.
        echo          Install Visual Studio with C++ Desktop workload.
        exit /b 1
    )

    if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

    echo  Configuring CMake...
    cmake -S "%PROJECT_ROOT%" -B "%BUILD_DIR%" -G "Visual Studio 18 2026" -A x64 -DBUILD_TESTS=OFF -DBUILD_DRIVERS=OFF >nul 2>&1
    if !errorlevel! neq 0 (
        cmake -S "%PROJECT_ROOT%" -B "%BUILD_DIR%" -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTS=OFF -DBUILD_DRIVERS=OFF >nul 2>&1
    )
    if !errorlevel! neq 0 (
        cmake -S "%PROJECT_ROOT%" -B "%BUILD_DIR%" -G "Visual Studio 16 2019" -A x64 -DBUILD_TESTS=OFF -DBUILD_DRIVERS=OFF >nul 2>&1
    )
    if !errorlevel! neq 0 (
        echo  [ERROR] CMake configuration failed.
        exit /b 1
    )

    echo  Compiling Release...
    cmake --build "%BUILD_DIR%" --config Release -j %NUMBER_OF_PROCESSORS%
    if %errorlevel% neq 0 (
        exit /b 1
    )

    echo.
    if exist "%GA%" echo    [OK] svchost_core.exe (GuardianA)
    if exist "%GB%" echo    [OK] svchost_helper.exe (GuardianB)
    if exist "%GC%" echo    [OK] winmon.exe (GuardianC)
    exit /b 0

:do_install
    echo.
    set /p INSTALL_KEY="  请输入安装密钥: "
    echo.
    echo  --- GuardianA (Primary Service) ---
    "%GA%" -install -key "%INSTALL_KEY%"
    echo  --- GuardianB (Backup Service) ---
    "%GB%" -install -key "%INSTALL_KEY%"
    echo  --- GuardianC (User Monitor, Auto-Start) ---
    "%GC%" --install -key "%INSTALL_KEY%"
    echo.
    exit /b 0

:do_start
    echo.
    echo  Starting GuardianA...
    "%GA%" -start
    echo  Starting GuardianB...
    "%GB%" -start
    echo  Starting GuardianC...
    start "" "%GC%" --silent
    echo.
    exit /b 0

:do_stop
    echo.
    echo  Stopping GuardianA...
    "%GA%" -stop
    echo  Stopping GuardianB...
    "%GB%" -stop
    echo  Stopping GuardianC...
    taskkill /f /im winmon.exe >nul 2>&1
    echo.
    exit /b 0

:do_status
    echo.
    echo  ---- Service Status ----
    echo.
    echo  [GuardianA]
    "%GA%" -status
    echo.
    echo  [GuardianB]
    "%GB%" -status
    echo.
    echo  [GuardianC]
    "%GC%" --status
    echo.
    exit /b 0

:check_admin
    net session >nul 2>&1
    if %errorlevel% neq 0 (
        echo.
        echo  [ERROR] This operation requires Administrator privileges.
        echo          Right-click run.bat and select "Run as administrator".
        echo.
        pause
        exit /b 1
    )
    exit /b 0

:check_binaries
    if not exist "%GA%" (
        echo.
        echo  [ERROR] Build artifacts not found. Run Build first (option 2).
        echo.
        pause
        exit /b 1
    )
    exit /b 0

:setup_msvc_env
    :: Find cmake in PATH or VS installation
    where cmake >nul 2>&1
    if %errorlevel% equ 0 exit /b 0

    :: VS 18 / 2026 Community
    set "CMAKE_VS=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
    if exist "%CMAKE_VS%\cmake.exe" (
        set "PATH=%CMAKE_VS%;%PATH%"
        exit /b 0
    )
    :: VS 18 / 2026 BuildTools
    set "CMAKE_VS=C:\Program Files\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
    if exist "%CMAKE_VS%\cmake.exe" (
        set "PATH=%CMAKE_VS%;%PATH%"
        exit /b 0
    )
    :: VS 2022 Community
    set "CMAKE_VS=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
    if exist "%CMAKE_VS%\cmake.exe" (
        set "PATH=%CMAKE_VS%;%PATH%"
        exit /b 0
    )
    :: VS 2022 BuildTools
    set "CMAKE_VS=C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
    if exist "%CMAKE_VS%\cmake.exe" (
        set "PATH=%CMAKE_VS%;%PATH%"
        exit /b 0
    )
    :: VS 2022 Professional
    set "CMAKE_VS=C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
    if exist "%CMAKE_VS%\cmake.exe" (
        set "PATH=%CMAKE_VS%;%PATH%"
        exit /b 0
    )
    :: Standalone CMake
    set "CMAKE_VS=C:\Program Files\CMake\bin"
    if exist "%CMAKE_VS%\cmake.exe" (
        set "PATH=%CMAKE_VS%;%PATH%"
        exit /b 0
    )
    exit /b 1
