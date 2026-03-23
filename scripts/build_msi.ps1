<#
.SYNOPSIS
    Build GuardianShield MSI installer using WiX v3 toolchain
.DESCRIPTION
    Stages build artifacts into a single directory, then invokes candle.exe + light.exe
    to produce the final MSI. Bypasses CPack to avoid duplicate Product element conflicts.
.NOTES
    Prerequisites: cmake --build build --config Release
    WiX Toolset v3.x must be installed
#>

param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$buildRoot  = Join-Path $ProjectRoot "build"
$stagingDir = Join-Path $buildRoot "msi_staging"
$wxsMain    = Join-Path $ProjectRoot "src\installer\GuardianShield.wxs"
$wxsUI      = Join-Path $ProjectRoot "src\installer\InstallDlg.wxs"

$wixBin = "C:\Program Files (x86)\WiX Toolset v3.14\bin"
if (-not (Test-Path "$wixBin\candle.exe")) {
    $wixBin = (Get-Command candle.exe -ErrorAction SilentlyContinue).Source | Split-Path
    if (-not $wixBin) {
        Write-Error "WiX Toolset v3 not found. Install from https://wixtoolset.org/"
        exit 1
    }
}
$candle = Join-Path $wixBin "candle.exe"
$light  = Join-Path $wixBin "light.exe"

Write-Host "=== GuardianShield MSI Build ===" -ForegroundColor Cyan
Write-Host "Project: $ProjectRoot"
Write-Host "WiX:     $wixBin"
Write-Host ""

$artifacts = @(
    @{ Src = "src\service\GuardianA\$Configuration\svchost_core.exe";   Dst = "svchost_core.exe" },
    @{ Src = "src\service\GuardianB\$Configuration\svchost_helper.exe"; Dst = "svchost_helper.exe" },
    @{ Src = "src\service\GuardianC\$Configuration\winmon.exe";         Dst = "winmon.exe" },
    @{ Src = "bin\$Configuration\guardian_ca.dll";                      Dst = "guardian_ca.dll" }
)

$configFiles = @(
    @{ Src = "config\guardian_config.yaml"; Dst = "guardian_config.yaml" },
    @{ Src = "config\auth.list";           Dst = "auth.list" }
)

# Step 1: Stage files
Write-Host "[1/4] Staging build artifacts..." -ForegroundColor Yellow
if (Test-Path $stagingDir) { Remove-Item -Recurse -Force $stagingDir }
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

foreach ($a in $artifacts) {
    $src = Join-Path $buildRoot $a.Src
    if (-not (Test-Path $src)) {
        Write-Error "Missing build artifact: $src (run cmake --build build --config $Configuration first)"
        exit 1
    }
    Copy-Item $src (Join-Path $stagingDir $a.Dst)
    Write-Host "  Staged: $($a.Dst)" -ForegroundColor DarkGray
}

foreach ($c in $configFiles) {
    $src = Join-Path $ProjectRoot $c.Src
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $stagingDir $c.Dst)
        Write-Host "  Staged: $($c.Dst)" -ForegroundColor DarkGray
    } else {
        Write-Warning "Config file not found: $src (MSI install may prompt user)"
    }
}

# Step 2: Compile WXS -> WIXOBJ
Write-Host "[2/4] Compiling WiX sources (candle)..." -ForegroundColor Yellow
$objMain = Join-Path $buildRoot "GuardianShield.wixobj"
$objUI   = Join-Path $buildRoot "InstallDlg.wixobj"

& $candle -nologo -arch x64 `
    "-dBuildOutputDir=$stagingDir" `
    -out $objMain `
    -ext WixUtilExtension `
    $wxsMain
if ($LASTEXITCODE -ne 0) { Write-Error "candle failed on GuardianShield.wxs"; exit 1 }

& $candle -nologo -arch x64 `
    "-dBuildOutputDir=$stagingDir" `
    -out $objUI `
    -ext WixUtilExtension `
    $wxsUI
if ($LASTEXITCODE -ne 0) { Write-Error "candle failed on InstallDlg.wxs"; exit 1 }

# Step 3: Link WIXOBJ -> MSI
Write-Host "[3/4] Linking MSI (light)..." -ForegroundColor Yellow
$version = (Select-String -Path (Join-Path $ProjectRoot "CMakeLists.txt") -Pattern "VERSION\s+(\d+\.\d+\.\d+)" | ForEach-Object { $_.Matches[0].Groups[1].Value })
if (-not $version) { $version = "3.3.0" }
$msiPath = Join-Path $buildRoot "GuardianShield-$version-win64.msi"

& $light -nologo `
    -out $msiPath `
    -ext WixUIExtension -ext WixUtilExtension `
    -cultures:zh-CN `
    -sval `
    $objMain $objUI
if ($LASTEXITCODE -ne 0) { Write-Error "light failed"; exit 1 }

# Step 4: Verify
Write-Host "[4/4] Verifying MSI..." -ForegroundColor Yellow
if (Test-Path $msiPath) {
    $size = [math]::Round((Get-Item $msiPath).Length / 1024)
    Write-Host ""
    Write-Host "SUCCESS: $msiPath ($size KB)" -ForegroundColor Green
} else {
    Write-Error "MSI not found at $msiPath"
    exit 1
}
