@echo off
setlocal EnableDelayedExpansion

set "PROJECT_ROOT=%~dp0"
set "CSPROJ=%PROJECT_ROOT%src\tools\GuardianConfigManager\GuardianConfigManager.csproj"
set "OUTPUT=%PROJECT_ROOT%build\tools\GuardianConfigManager"

echo.
echo ============================================================
echo    GuardianShield ConfigManager Build Script
echo ============================================================
echo.

where dotnet >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: dotnet SDK not found in PATH
    echo Please install .NET 8 SDK: https://dotnet.microsoft.com/download
    pause
    exit /b 1
)

echo Project : %CSPROJ%
echo Output  : %OUTPUT%
echo.

echo Building Release...
dotnet publish "%CSPROJ%" -c Release -o "%OUTPUT%"

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
echo Output: %OUTPUT%\GuardianConfigManager.exe
echo.

pause
exit /b 0
