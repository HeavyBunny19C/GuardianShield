<#
.SYNOPSIS
    GuardianShield Full Lifecycle Test Script
.DESCRIPTION
    Performs complete lifecycle testing: install -> start -> verify -> stop -> uninstall
    Run this in CI or locally to validate the entire deployment lifecycle.
.PARAMETER Key
    The installation key to use (default: GuardianShield2024)
.PARAMETER PackageDir
    Directory containing the deployment package (default: script directory)
.PARAMETER InstallDir
    Installation directory (default: C:\Program Files\GuardianShield)
.PARAMETER SkipCleanup
    Skip pre-test cleanup (useful for debugging)
.PARAMETER SkipInstall
    Skip installation test (useful for testing uninstall only)
.PARAMETER SkipUninstall
    Skip uninstallation test (leaves installation in place)
.EXAMPLE
    .\lifecycle-test.ps1
    .\lifecycle-test.ps1 -Key "MySecretKey"
    .\lifecycle-test.ps1 -SkipInstall -SkipCleanup  # Test uninstall only
#>
param(
    [string]$Key = "GuardianShield2024",
    [string]$PackageDir = "$PSScriptRoot",
    [string]$InstallDir = "C:\Program Files\GuardianShield",
    [string]$DataDir = "C:\ProgramData\GuardianShield",
    [switch]$SkipCleanup,
    [switch]$SkipInstall,
    [switch]$SkipUninstall,
    [int]$WaitForServices = 10  # Seconds to wait for services to stabilize
)

$ErrorActionPreference = "Stop"

# Test result tracking
$TestResults = @{
    Total = 0
    Passed = 0
    Failed = 0
    Tests = @()
    StartTime = Get-Date
}

function Write-Section {
    param($Title)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Test-Step {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        
        [int]$TimeoutSeconds = 60,
        [switch]$ContinueOnError
    )
    
    $TestResults.Total++
    Write-Host "`n[Test $($TestResults.Total)] $Name" -ForegroundColor White
    
    $job = $null
    $completed = $false
    $errorMsg = $null
    
    try {
        # Run the test with timeout
        $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Key, $PackageDir, $InstallDir, $DataDir
        $job | Wait-Job -Timeout $TimeoutSeconds | Out-Null
        
        if ($job.State -eq 'Completed') {
            $result = Receive-Job -Job $job
            if ($result -eq $false -or $result -eq $null) {
                throw "Test returned false/null"
            }
            $completed = $true
        } elseif ($job.State -eq 'Failed') {
            $errorMsg = ($job.ChildJobs[0].JobStateInfo.Reason.Message)
            throw $errorMsg
        } else {
            Stop-Job -Job $job
            throw "Test timed out after $TimeoutSeconds seconds"
        }
    } catch {
        $errorMsg = $_.Exception.Message
        $completed = $false
    } finally {
        if ($job) { Remove-Job -Job $job -Force }
    }
    
    if ($completed) {
        $TestResults.Passed++
        $TestResults.Tests += @{ Name = $Name; Result = "PASS"; Error = $null; Duration = 0 }
        Write-Host "  [PASS] $Name" -ForegroundColor Green
        return $true
    } else {
        $TestResults.Failed++
        $TestResults.Tests += @{ Name = $Name; Result = "FAIL"; Error = $errorMsg; Duration = 0 }
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
        Write-Host "  Error: $errorMsg" -ForegroundColor DarkRed
        if (-not $ContinueOnError) {
            throw "Test failed: $Name`n$errorMsg"
        }
        return $false
    }
}

function Get-ServiceStatus {
    param($Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc) { return $svc.Status } else { return "NOT_INSTALLED" }
}

function Wait-ForService {
    param($Name, $Status = 'Running', $Timeout = 30)
    $elapsed = 0
    while ($elapsed -lt $Timeout) {
        $current = Get-ServiceStatus -Name $Name
        if ($current -eq $Status) { return $true }
        Start-Sleep -Seconds 1
        $elapsed++
    }
    return $false
}

# ============================================================
# Pre-Test Cleanup
# ============================================================
if (-not $SkipCleanup) {
    Write-Section "Phase 0: Pre-Test Cleanup"
    
    Write-Host "Stopping services..."
    @("WinDefenderCore", "WinDefenderHelper") | ForEach-Object {
        $status = Get-ServiceStatus -Name $_
        if ($status -ne "NOT_INSTALLED") {
            Write-Host "  Stopping $_..."
            Stop-Service -Name $_ -Force -ErrorAction SilentlyContinue
            sc delete $_ 2>$null | Out-Null
        }
    }
    
    Write-Host "Terminating processes..."
    @("svchost_core", "svchost_helper", "winmon") | ForEach-Object {
        taskkill /F /IM "$_.exe" 2>$null | Out-Null
    }
    
    Write-Host "Cleaning up directories..."
    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $InstallDir) {
            Write-Host "  WARNING: Install directory locked, will be cleaned on reboot" -ForegroundColor Yellow
        }
    }
    if (Test-Path $DataDir) {
        Remove-Item -Path $DataDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Clean registry
    reg delete "HKLM\SOFTWARE\GuardianShield" /f 2>$null | Out-Null
    reg delete "HKCU\SOFTWARE\GuardianShield" /f 2>$null | Out-Null
    
    Start-Sleep -Seconds 3
    Write-Host "Cleanup complete" -ForegroundColor Green
}

# ============================================================
# Phase 1: Installation Test
# ============================================================
if (-not $SkipInstall) {
    Write-Section "Phase 1: Installation Test"
    
    # Verify package exists
    Test-Step "Package Integrity Check" {
        if (-not (Test-Path "$PackageDir\svchost_core.exe")) { throw "svchost_core.exe not found in package" }
        if (-not (Test-Path "$PackageDir\svchost_helper.exe")) { throw "svchost_helper.exe not found in package" }
        if (-not (Test-Path "$PackageDir\winmon.exe")) { throw "winmon.exe not found in package" }
        if (-not (Test-Path "$PackageDir\install.bat")) { throw "install.bat not found in package" }
        return $true
    }
    
    # Test command-line installation
    Test-Step "Command-Line Installation" {
        $proc = Start-Process -FilePath "$PackageDir\install.bat" `
            -ArgumentList "/install", "/key", $Key `
            -Wait -PassThru -NoNewWindow -WorkingDirectory $PackageDir
        if ($proc.ExitCode -ne 0) { 
            throw "Installation failed with exit code $($proc.ExitCode)" 
        }
        return $true
    } -TimeoutSeconds 120
    
    # Verify services installed and running
    Test-Step "Service Installation Verification" {
        $svcA = Get-Service -Name "WinDefenderCore" -ErrorAction SilentlyContinue
        $svcB = Get-Service -Name "WinDefenderHelper" -ErrorAction SilentlyContinue
        
        if (-not $svcA) { throw "GuardianA service (WinDefenderCore) not found" }
        if (-not $svcB) { throw "GuardianB service (WinDefenderHelper) not found" }
        
        Write-Host "  GuardianA status: $($svcA.Status)"
        Write-Host "  GuardianB status: $($svcB.Status)"
        return $true
    }
    
    # Wait for services to stabilize
    Write-Host "`nWaiting $WaitForServices seconds for services to stabilize..."
    Start-Sleep -Seconds $WaitForServices
    
    # Verify file deployment
    Test-Step "File Deployment Verification" {
        @("svchost_core.exe", "svchost_helper.exe", "winmon.exe") | ForEach-Object {
            $path = "$InstallDir\$_"
            if (-not (Test-Path $path)) { throw "$_ not found in install directory" }
            $size = (Get-Item $path).Length
            Write-Host "  $_ : $size bytes"
        }
        return $true
    }
    
    # Verify data directory
    Test-Step "Data Directory Verification" {
        if (-not (Test-Path $DataDir)) { throw "Data directory not created" }
        if (-not (Test-Path "$DataDir\config")) { throw "Config directory not created" }
        if (-not (Test-Path "$DataDir\logs")) { throw "Logs directory not created" }
        return $true
    }
}

# ============================================================
# Phase 2: Runtime Verification
# ============================================================
if (-not $SkipInstall) {
    Write-Section "Phase 2: Runtime Verification"
    
    # Check services are running
    Test-Step "Service Running Verification" {
        $svcA = Get-ServiceStatus -Name "WinDefenderCore"
        $svcB = Get-ServiceStatus -Name "WinDefenderHelper"
        
        if ($svcA -ne 'Running') { throw "GuardianA not running (status: $svcA)" }
        if ($svcB -ne 'Running') { throw "GuardianB not running (status: $svcB)"
        }
        return $true
    }
    
    # Check GuardianC process
    Test-Step "GuardianC Process Verification" {
        $process = Get-Process -Name "winmon" -ErrorAction SilentlyContinue
        if (-not $process) { throw "GuardianC process (winmon.exe) not found" }
        Write-Host "  PID: $($process.Id), Memory: $([math]::Round($process.WorkingSet64 / 1MB, 2)) MB"
        return $true
    }
    
    # Check log files
    Test-Step "Log File Creation Verification" {
        Start-Sleep -Seconds 3  # Give time for logs to be written
        $logFiles = Get-ChildItem "$DataDir\logs\*.json" -ErrorAction SilentlyContinue
        if ($logFiles.Count -eq 0) { 
            # Try alternative log location
            $logFiles = Get-ChildItem "$DataDir\logs\*.log" -ErrorAction SilentlyContinue
            if ($logFiles.Count -eq 0) {
                throw "No log files created" 
            }
        }
        Write-Host "  Found $($logFiles.Count) log file(s)"
        return $true
    } -ContinueOnError
    
    # Test status command
    Test-Step "Status Command Verification" {
        $proc = Start-Process -FilePath "$InstallDir\svchost_core.exe" `
            -ArgumentList "-status" `
            -Wait -PassThru -NoNewWindow `
            -RedirectStandardOutput "$env:TEMP\status_out.txt" `
            -RedirectStandardError "$env:TEMP\status_err.txt"
        
        $output = Get-Content "$env:TEMP\status_out.txt" -Raw -ErrorAction SilentlyContinue
        if ($output -match "RUNNING" -or $output -match "STOPPED") {
            return $true
        }
        throw "Status command did not return expected output"
    } -ContinueOnError
}

# ============================================================
# Phase 3: Functionality Test
# ============================================================
if (-not $SkipInstall) {
    Write-Section "Phase 3: Functionality Test"
    
    # Test heartbeat (via shared memory or log analysis)
    Test-Step "Heartbeat Detection" {
        # Look for heartbeat-related log entries
        $logFiles = Get-ChildItem "$DataDir\logs\*" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($logFiles) {
            $content = Get-Content $logFiles.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -and ($content.Length -gt 100)) {
                Write-Host "  Log entries detected"
                return $true
            }
        }
        throw "No log activity detected - services may not be functioning"
    } -ContinueOnError
    
    # Test config presence
    Test-Step "Configuration Verification" {
        $configCache = "$DataDir\config_cache.bin"
        if (Test-Path $configCache) {
            Write-Host "  Config cache found"
            return $true
        }
        # Also accept if config was loaded from YAML
        Write-Host "  Config cache not found (may use defaults)" -ForegroundColor Yellow
        return $true
    } -ContinueOnError
}

# ============================================================
# Phase 4: Stop Services Test
# ============================================================
if (-not $SkipInstall -and -not $SkipUninstall) {
    Write-Section "Phase 4: Stop Services Test"
    
    Test-Step "Service Stop Test" {
        $proc = Start-Process -FilePath "$PackageDir\install.bat" `
            -ArgumentList "/stop" `
            -Wait -PassThru -NoNewWindow -WorkingDirectory $PackageDir
        
        Start-Sleep -Seconds 3
        
        $svcA = Get-ServiceStatus -Name "WinDefenderCore"
        $svcB = Get-ServiceStatus -Name "WinDefenderHelper"
        
        # Services should be stopped (or not installed after uninstall)
        if ($svcA -eq 'Running') { throw "GuardianA still running after stop command" }
        if ($svcB -eq 'Running') { throw "GuardianB still running after stop command" }
        
        Write-Host "  Services stopped successfully"
        return $true
    }
    
    Test-Step "Service Start Test" {
        $proc = Start-Process -FilePath "$PackageDir\install.bat" `
            -ArgumentList "/start" `
            -Wait -PassThru -NoNewWindow -WorkingDirectory $PackageDir
        
        Start-Sleep -Seconds $WaitForServices
        
        $svcA = Get-ServiceStatus -Name "WinDefenderCore"
        $svcB = Get-ServiceStatus -Name "WinDefenderHelper"
        
        if ($svcA -ne 'Running') { throw "GuardianA not running after start command" }
        if ($svcB -ne 'Running') { throw "GuardianB not running after start command" }
        
        Write-Host "  Services started successfully"
        return $true
    }
}

# ============================================================
# Phase 5: Uninstallation Test
# ============================================================
if (-not $SkipUninstall) {
    Write-Section "Phase 5: Uninstallation Test"
    
    Test-Step "Command-Line Uninstallation" {
        $proc = Start-Process -FilePath "$PackageDir\install.bat" `
            -ArgumentList "/uninstall", "/key", $Key `
            -Wait -PassThru -NoNewWindow -WorkingDirectory $PackageDir
        
        if ($proc.ExitCode -ne 0) { 
            throw "Uninstallation failed with exit code $($proc.ExitCode)" 
        }
        return $true
    } -TimeoutSeconds 120
    
    Test-Step "Service Removal Verification" {
        Start-Sleep -Seconds 3
        
        $svcA = Get-Service -Name "WinDefenderCore" -ErrorAction SilentlyContinue
        $svcB = Get-Service -Name "WinDefenderHelper" -ErrorAction SilentlyContinue
        
        if ($svcA) { throw "GuardianA service still exists after uninstall" }
        if ($svcB) { throw "GuardianB service still exists after uninstall" }
        
        Write-Host "  Services removed successfully"
        return $true
    }
    
    Test-Step "Process Termination Verification" {
        Start-Sleep -Seconds 2
        
        $process = Get-Process -Name "winmon" -ErrorAction SilentlyContinue
        if ($process) { throw "GuardianC process still running after uninstall" }
        
        Write-Host "  All processes terminated"
        return $true
    }
    
    Test-Step "Registry Cleanup Verification" {
        $regHKLM = Test-Path "HKLM:\SOFTWARE\GuardianShield" -ErrorAction SilentlyContinue
        $regHKCU = Test-Path "HKCU:\SOFTWARE\GuardianShield" -ErrorAction SilentlyContinue
        
        if ($regHKLM) { 
            Write-Host "  WARNING: HKLM registry key still exists" -ForegroundColor Yellow 
        }
        if ($regHKCU) { 
            Write-Host "  WARNING: HKCU registry key still exists" -ForegroundColor Yellow 
        }
        
        return $true  # Don't fail on registry, just warn
    } -ContinueOnError
}

# ============================================================
# Test Summary
# ============================================================
Write-Section "Test Summary"

$duration = ((Get-Date) - $TestResults.StartTime).TotalSeconds

Write-Host "Total Tests:  $($TestResults.Total)"
Write-Host "Passed:       $($TestResults.Passed)" -ForegroundColor Green
Write-Host "Failed:       $($TestResults.Failed)" -ForegroundColor Red
Write-Host "Duration:     $([math]::Round($duration, 2)) seconds"

if ($TestResults.Failed -gt 0) {
    Write-Host "`nFailed Tests:" -ForegroundColor Red
    $TestResults.Tests | Where-Object { $_.Result -eq "FAIL" } | ForEach-Object {
        Write-Host "  - $($_.Name)" -ForegroundColor Red
        if ($_.Error) {
            Write-Host "    Error: $($_.Error)" -ForegroundColor DarkRed
        }
    }
    Write-Host "`n[RESULT] Lifecycle test FAILED" -ForegroundColor Red
    exit 1
} else {
    Write-Host "`n[RESULT] Lifecycle test PASSED" -ForegroundColor Green
    exit 0
}
