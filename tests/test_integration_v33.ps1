<#
.SYNOPSIS
    GuardianShield v3.3.0 Integration Tests
.DESCRIPTION
    IT-1: Config rename threshold end-to-end (YAML -> cache v11 -> reload)
    IT-2: Cache v11 forward compatibility (old cache rejected -> defaults)
    IT-3: A/B HandleDriverEvent structural symmetry
.NOTES
    Prerequisite: cmake --build build --config Release
    Run: powershell -ExecutionPolicy Bypass -File tests\test_integration_v33.ps1
#>

param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Continue"
$script:PassCount = 0
$script:FailCount = 0

function Write-TestHeader($name) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  $name" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Test-Pass($msg) {
    Write-Host "  [PASS] $msg" -ForegroundColor Green
    $script:PassCount++
}

function Test-Fail($msg) {
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
    $script:FailCount++
}

function Test-Info($msg) {
    Write-Host "  [INFO] $msg" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "=== GuardianShield v3.3.0 Integration Tests ===" -ForegroundColor White
Write-Host "Time: $(Get-Date)" -ForegroundColor White
Write-Host "Project: $ProjectRoot" -ForegroundColor White
Write-Host ""

# ============================================================
# IT-1: Config rename threshold round-trip
# ============================================================
Write-TestHeader "IT-1: Config rename threshold (YAML -> cache v11 -> reload)"

$buildDir = Join-Path $ProjectRoot "build"

try {
    $output = & ctest --test-dir $buildDir -R "CacheV11RoundTrip_RenameThresholds" -C Release --output-on-failure 2>&1 | Out-String
    if ($output -match "1 test.*passed" -or $output -match "100% tests passed") {
        Test-Pass "CacheV11RoundTrip_RenameThresholds: YAML(rename=20) -> cache v11 -> reload = 20"
    } else {
        Test-Fail "CacheV11RoundTrip_RenameThresholds failed"
        Test-Info $output.Substring(0, [math]::Min(500, $output.Length))
    }
} catch {
    Test-Fail "ctest execution error: $_"
}

# ============================================================
# IT-2: Cache v11 forward compatibility
# ============================================================
Write-TestHeader "IT-2: Cache v11 forward compatibility (old version rejected)"

try {
    $output = & ctest --test-dir $buildDir -R "CacheOldVersionRejected" -C Release --output-on-failure 2>&1 | Out-String
    if ($output -match "1 test.*passed" -or $output -match "100% tests passed") {
        Test-Pass "CacheOldVersionRejected: old cache rejected, fallback to defaults"
    } else {
        Test-Fail "CacheOldVersionRejected failed"
        Test-Info $output.Substring(0, [math]::Min(500, $output.Length))
    }
} catch {
    Test-Fail "ctest execution error: $_"
}

$configCpp = Join-Path $ProjectRoot "src\service\common\src\config.cpp"
if (Test-Path $configCpp) {
    $content = Get-Content $configCpp -Raw
    if ($content -match 'version\s*[=!<>]+\s*11') {
        Test-Pass "config.cpp cache version constant is 11"
    } else {
        Test-Fail "config.cpp cache version constant is NOT 11"
    }
} else {
    Test-Fail "config.cpp not found at $configCpp"
}

# ============================================================
# IT-3: A/B HandleDriverEvent structural symmetry
# ============================================================
Write-TestHeader "IT-3: A/B HandleDriverEvent structural symmetry"

$srcA = Join-Path $ProjectRoot "src\service\GuardianA\src\guardian_a.cpp"
$srcB = Join-Path $ProjectRoot "src\service\GuardianB\src\guardian_b.cpp"

if (-not (Test-Path $srcA)) { Test-Fail "guardian_a.cpp not found"; exit 1 }
if (-not (Test-Path $srcB)) { Test-Fail "guardian_b.cpp not found"; exit 1 }

$contentA = Get-Content $srcA -Raw
$contentB = Get-Content $srcB -Raw

$patterns = @(
    @("filePath.empty", "Empty-path filter"),
    @("protPath", "Directory-level filter"),
    @("GetTopContributorPid", "Targeted termination"),
    @("ResponseActionCombinedToString", "Response action string"),
    @("file_rename_count", "Rename threshold assembly")
)

foreach ($item in $patterns) {
    $pat = $item[0]
    $desc = $item[1]
    $inA = $contentA.Contains($pat)
    $inB = $contentB.Contains($pat)
    if ($inA -and $inB) {
        Test-Pass "${desc}: '${pat}' present in both A and B"
    } elseif (-not $inA) {
        Test-Fail "${desc}: '${pat}' MISSING from guardian_a.cpp"
    } else {
        Test-Fail "${desc}: '${pat}' MISSING from guardian_b.cpp"
    }
}

# ============================================================
# Summary
# ============================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor White
Write-Host "  INTEGRATION TEST SUMMARY" -ForegroundColor White
Write-Host "========================================" -ForegroundColor White
Write-Host "  PASSED: $($script:PassCount)" -ForegroundColor Green

$failColor = "Green"
if ($script:FailCount -gt 0) { $failColor = "Red" }
Write-Host "  FAILED: $($script:FailCount)" -ForegroundColor $failColor
Write-Host "  TOTAL:  $($script:PassCount + $script:FailCount)" -ForegroundColor White
Write-Host ""

if ($script:FailCount -eq 0) {
    Write-Host "  RESULT: ALL INTEGRATION TESTS PASSED" -ForegroundColor Green
} else {
    Write-Host "  RESULT: $($script:FailCount) FAILURE(S)" -ForegroundColor Red
}

Write-Host ""
exit $script:FailCount
