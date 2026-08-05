<#
.SYNOPSIS
    GuardianShield Security Verification Script
.DESCRIPTION
    Performs security checks to verify that security fixes are in place.
    Run this in CI or locally to validate security posture.
.PARAMETER FailOnWarning
    If set, warnings will also fail the check (strict mode)
.EXAMPLE
    .\security-scan.ps1
    .\security-scan.ps1 -FailOnWarning
#>
param(
    [switch]$FailOnWarning
)

$ErrorActionPreference = "Stop"
$script:FailedChecks = 0
$script:WarningChecks = 0

function Write-CheckHeader {
    param($Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Test-SecurityCheck {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        [scriptblock]$Test,
        
        [string]$FailMessage,
        [string]$PassMessage,
        [switch]$WarningOnly
    )
    
    Write-Host "`n[Check] $Name" -ForegroundColor White
    
    try {
        $result = & $Test
        if ($result -eq $true) {
            Write-Host "  [PASS] $PassMessage" -ForegroundColor Green
            return $true
        } else {
            if ($WarningOnly) {
                Write-Host "  [WARN] $FailMessage" -ForegroundColor Yellow
                $script:WarningChecks++
            } else {
                Write-Host "  [FAIL] $FailMessage" -ForegroundColor Red
                $script:FailedChecks++
            }
            return $false
        }
    } catch {
        if ($WarningOnly) {
            Write-Host "  [WARN] $FailMessage`n  Error: $_" -ForegroundColor Yellow
            $script:WarningChecks++
        } else {
            Write-Host "  [FAIL] $FailMessage`n  Error: $_" -ForegroundColor Red
            $script:FailedChecks++
        }
        return $false
    }
}

# Change to repo root
$repoRoot = Split-Path -Parent $PSScriptRoot | Split-Path -Parent
Push-Location $repoRoot

try {
    Write-CheckHeader "GuardianShield Security Verification"
    Write-Host "Repository: $repoRoot"
    Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    
    # Check 1: Hardcoded HMAC Key Removed
    Test-SecurityCheck `
        -Name "HMAC Hardcoded Key Removed" `
        -Test {
            $file = Get-Content "src/service/common/src/ipc.cpp" -Raw -ErrorAction Stop
            if ($file -match 'GuardianShield_IPC_v2') { return $false }
            return $true
        } `
        -PassMessage "Hardcoded HMAC key 'GuardianShield_IPC_v2' has been removed" `
        -FailMessage "Hardcoded HMAC key still present in ipc.cpp!"
    
    # Check 2: SHA256File Implementation
    Test-SecurityCheck `
        -Name "SHA256File BCrypt Implementation" `
        -Test {
            $file = Get-Content "src/service/common/src/security.cpp" -Raw -ErrorAction Stop
            return ($file -match 'BCryptCreateHash' -and $file -match 'SHA256File')
        } `
        -PassMessage "SHA256File uses BCryptCreateHash for SHA-256 hashing" `
        -FailMessage "SHA256File BCrypt implementation not found!"
    
    # Check 3: VerifyHash Implementation
    Test-SecurityCheck `
        -Name "VerifyHash Implementation" `
        -Test {
            $file = Get-Content "src/service/common/src/security.cpp" -Raw -ErrorAction Stop
            return ($file -match 'VerifyHash' -and $file -match 'SHA256File')
        } `
        -PassMessage "VerifyHash function implemented using SHA256File" `
        -FailMessage "VerifyHash implementation not found!"
    
    # Check 4: GuardianA Global Mutex (Split-brain protection)
    Test-SecurityCheck `
        -Name "GuardianA Split-brain Protection" `
        -Test {
            $file = Get-Content "src/service/GuardianA/src/guardian_a.cpp" -Raw -ErrorAction Stop
            return $file -match 'GuardianShield-Leader'
        } `
        -PassMessage "Global mutex 'GuardianShield-Leader' found in GuardianA" `
        -FailMessage "Split-brain protection mutex missing in GuardianA!"
    
    # Check 5: GuardianB Global Mutex (Split-brain protection)
    Test-SecurityCheck `
        -Name "GuardianB Split-brain Protection" `
        -Test {
            $file = Get-Content "src/service/GuardianB/src/guardian_b.cpp" -Raw -ErrorAction Stop
            return $file -match 'GuardianShield-Leader'
        } `
        -PassMessage "Global mutex 'GuardianShield-Leader' found in GuardianB" `
        -FailMessage "Split-brain protection mutex missing in GuardianB!"
    
    # Check 6: ETW Orphan Session Recovery
    Test-SecurityCheck `
        -Name "ETW Orphan Session Recovery" `
        -Test {
            $file = Get-Content "src/service/GuardianA/src/guardian_a.cpp" -Raw -ErrorAction Stop
            return ($file -match 'ERROR_ALREADY_EXISTS' -and $file -match 'EVENT_TRACE_CONTROL_STOP')
        } `
        -PassMessage "ETW orphan session recovery (ERROR_ALREADY_EXISTS handling) implemented" `
        -FailMessage "ETW orphan session recovery missing!"
    
    # Check 7: HMAC Zero Checksum Rejection
    Test-SecurityCheck `
        -Name "HMAC Zero Checksum Rejection" `
        -Test {
            $file = Get-Content "src/service/common/src/ipc.cpp" -Raw -ErrorAction Stop
            # Look for zero checksum validation logic
            return ($file -match 'zero' -and $file -match 'checksum') -or 
                   ($file -match 'memset.*0' -and $file -match 'HMAC')
        } `
        -PassMessage "HMAC zero checksum validation logic present" `
        -FailMessage "HMAC zero checksum rejection may be missing!" `
        -WarningOnly
    
    # Check 8: TCP ACL and Source Validation
    Test-SecurityCheck `
        -Name "TCP ACL and Source Validation" `
        -Test {
            $file = Get-Content "src/service/common/src/ipc.cpp" -Raw -ErrorAction Stop
            return ($file -match 'ACL' -or $file -match 'GetPeerName' -or $file -match 'loopback')
        } `
        -PassMessage "TCP access control or source validation implemented" `
        -FailMessage "TCP ACL validation may be missing!" `
        -WarningOnly
    
    # Check 9: Shared Memory Atomic Operations
    Test-SecurityCheck `
        -Name "Shared Memory Atomic Operations" `
        -Test {
            $file = Get-Content "src/service/common/src/ipc.cpp" -Raw -ErrorAction Stop
            return $file -match 'InterlockedExchange64'
        } `
        -PassMessage "InterlockedExchange64 used for shared memory atomic operations" `
        -FailMessage "Shared memory atomic operations may not be using Interlocked API!" `
        -WarningOnly
    
    # Check 10: No built-in install key
    Test-SecurityCheck `
        -Name "Plaintext Install Key" `
        -Test {
            $file = Get-Content "src/service/common/include/install_key.h" -Raw -ErrorAction Stop
            return ($file -notmatch 'GuardianShield20\d{2}')
        } `
        -PassMessage "No built-in install key found" `
        -FailMessage "A built-in install key is still present!"
    
    # Check 11: Install Key in Config Updated
    Test-SecurityCheck `
        -Name "Config Install Key Field" `
        -Test {
            $file = Get-Content "src/service/common/src/config.cpp" -Raw -ErrorAction Stop
            # Should reference the configured install_key field.
            return ($file -match 'install_key')
        } `
        -PassMessage "Config uses install_key field" `
        -FailMessage "Config is missing the install_key field!"
    
    # Check 12: No Hardcoded Secrets in Source
    Test-SecurityCheck `
        -Name "No Hardcoded Secrets" `
        -Test {
            $patterns = @(
                'password\s*=\s*[\x22\x27][^\x22\x27]+[\x22\x27]',
                'secret\s*=\s*[\x22\x27][^\x22\x27]+[\x22\x27]',
                'api[_-]?key\s*=\s*[\x22\x27][^\x22\x27]+[\x22\x27]'
            )
            $files = Get-ChildItem -Path "src/" -Recurse -Include "*.cpp","*.h","*.hpp"
            $found = $false
            foreach ($file in $files) {
                $content = Get-Content $file.FullName -Raw
                foreach ($pattern in $patterns) {
                    if ($content -match $pattern) {
                        # Exclude comments
                        if ($matches[0] -notmatch '//' -and
                            $matches[0] -notmatch '/\*') {
                            Write-Host "    Found in $($file.FullName): $($matches[0])" -ForegroundColor DarkYellow
                            $found = $true
                        }
                    }
                }
            }
            return -not $found
        } `
        -PassMessage "No suspicious hardcoded secrets found" `
        -FailMessage "Potential hardcoded secrets detected!" `
        -WarningOnly
    
    # Summary
    Write-CheckHeader "Security Check Summary"
    Write-Host "Total Checks: 12"
    Write-Host "Passed: $((12 - $script:FailedChecks - $script:WarningChecks))" -ForegroundColor Green
    if ($script:WarningChecks -gt 0) {
        Write-Host "Warnings: $($script:WarningChecks)" -ForegroundColor Yellow
    }
    if ($script:FailedChecks -gt 0) {
        Write-Host "Failed: $($script:FailedChecks)" -ForegroundColor Red
    }
    
    if ($script:FailedChecks -gt 0 -or ($FailOnWarning -and $script:WarningChecks -gt 0)) {
        Write-Host "`n[RESULT] Security verification FAILED" -ForegroundColor Red
        exit 1
    } else {
        Write-Host "`n[RESULT] Security verification PASSED" -ForegroundColor Green
        exit 0
    }
    
} finally {
    Pop-Location
}
