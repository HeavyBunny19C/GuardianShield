@echo off
setlocal EnableDelayedExpansion

set "PROJECT_ROOT=%~dp0"
cd /d "%PROJECT_ROOT%"

echo.
echo ============================================================
echo        GuardianShield Build Script
echo ============================================================
echo.

if not exist "%PROJECT_ROOT%build" mkdir "%PROJECT_ROOT%build"
cd /d "%PROJECT_ROOT%build"

call :setup_msvc_env
if %errorlevel% neq 0 (
    echo ERROR: Cannot find Visual Studio environment
    echo Please install Visual Studio with C++ Desktop workload.
    pause
    exit /b 1
)

if not exist "%PROJECT_ROOT%build\CMakeCache.txt" (
    echo Configuring project...
    cmake -G "Visual Studio 18 2026" -A x64 -DBUILD_TESTS=OFF ..
    if !errorlevel! neq 0 (
        echo Trying Visual Studio 17 2022...
        cmake -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTS=OFF ..
    )
    if !errorlevel! neq 0 (
        echo Trying Visual Studio 16 2019...
        cmake -G "Visual Studio 16 2019" -A x64 -DBUILD_TESTS=OFF ..
    )
    if !errorlevel! neq 0 (
        echo Configuration failed!
        pause
        exit /b 1
    )
    echo Configuration complete!
    echo.
)

echo Building Release mode...
cmake --build . --config Release -j %NUMBER_OF_PROCESSORS%

if %errorlevel% neq 0 (
    echo.
    echo BUILD FAILED!
    pause
    exit /b 1
)

echo.
echo ============================================================
echo                    BUILD SUCCESS!
echo ============================================================
echo.

echo Output files:
if exist "%PROJECT_ROOT%build\src\service\GuardianA\Release\svchost_core.exe" echo   [OK] svchost_core.exe (GuardianA)
if exist "%PROJECT_ROOT%build\src\service\GuardianB\Release\svchost_helper.exe" echo   [OK] svchost_helper.exe (GuardianB)
if exist "%PROJECT_ROOT%build\src\service\GuardianC\Release\winmon.exe" echo   [OK] winmon.exe (GuardianC)
if exist "%PROJECT_ROOT%build\bin\Release\guardian_ca.dll" echo   [OK] guardian_ca.dll (Installer CA)
echo.

pause
exit /b 0

:setup_msvc_env
:: VS 18 / 2026
if exist "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    exit /b 0
)
if exist "C:\Program Files\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    exit /b 0
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    exit /b 0
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    exit /b 0
)
:: VS 2022
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    exit /b 0
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    exit /b 0
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    exit /b 0
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    exit /b 0
)
:: VS 2019
if exist "C:\Program Files\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    exit /b 0
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    exit /b 0
)
exit /b 1
