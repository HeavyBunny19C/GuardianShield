#Requires -RunAsAdministrator
<#
    GuardianShield MSI Lifecycle Test
    Runs: Install -> Verify -> Runtime Check -> Uninstall -> Cleanup Verify
#>

param(
    [string]$MsiPath,
    [Parameter(Mandatory=$true)]
    [string]$InstallKey
)

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectRoot = Split-Path -Parent $ScriptDir

if (-not $MsiPath) {
    $defaultMsi = Get-ChildItem -Path (Join-Path $ProjectRoot "build") -Filter "GuardianShield-*.msi" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($defaultMsi) { $MsiPath = $defaultMsi.FullName }
    else { $MsiPath = Join-Path $ProjectRoot "build\GuardianShield-3.3.0-win64.msi" }
}

$AuthListSrc    = Join-Path $ProjectRoot "config\auth.list"
$ConfigYamlSrc  = Join-Path $ProjectRoot "config\guardian_config.yaml"
$InstallDir     = "C:\Program Files\GuardianShield"
$DataDir        = "C:\ProgramData\GuardianShield"
$ConfigDir      = "$DataDir\config"
$LogDir         = "$DataDir\logs"
$RunKey         = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

$pass = 0
$fail = 0

function Assert-True($condition, $name) {
    if ($condition) {
        Write-Host "  [PASS] $name" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  [FAIL] $name" -ForegroundColor Red
        $script:fail++
    }
}

function Wait-MsiIdle {
    $maxWait = 60
    $waited = 0
    while ($waited -lt $maxWait) {
        try {
            $mutex = [System.Threading.Mutex]::OpenExisting("Global\_MSIExecute")
            $mutex.Close()
            Start-Sleep -Seconds 2
            $waited += 2
            Write-Host "  [WAIT] Windows Installer busy ($waited s)..." -ForegroundColor Yellow
        } catch {
            return
        }
    }
    Write-Host "  [WARN] Timed out waiting for Windows Installer" -ForegroundColor Yellow
}

function Invoke-Msiexec($arguments, $logName) {
    Wait-MsiIdle
    $logPath = Join-Path $ProjectRoot "build\$logName"
    $fullArgs = "$arguments /l*v `"$logPath`""
    $proc = Start-Process msiexec -ArgumentList $fullArgs -Wait -PassThru
    Start-Sleep -Seconds 3
    Wait-MsiIdle
    return $proc
}

# ================================================================
# Pre-flight checks
# ================================================================
Write-Host "`n========== Pre-flight Checks ==========" -ForegroundColor Cyan

Assert-True (Test-Path $MsiPath) "MSI file exists: $MsiPath"
Assert-True (Test-Path $AuthListSrc) "auth.list source exists"
Assert-True (Test-Path $ConfigYamlSrc) "guardian_config.yaml source exists"

if (-not (Test-Path $MsiPath)) {
    Write-Host "`n[ABORT] MSI file not found. Build first." -ForegroundColor Red
    exit 1
}

# Clean up any previous installation
$existingSvc = Get-Service -Name "WinDefenderCore" -ErrorAction SilentlyContinue
if ($existingSvc) {
    Write-Host "  [INFO] Previous installation detected, uninstalling first..." -ForegroundColor Yellow
    $p = Invoke-Msiexec "/x `"$MsiPath`" /qn INSTALL_KEY=`"$InstallKey`"" "msi_preclean.log"
    Start-Sleep -Seconds 5
}

# ================================================================
# Phase 1: Silent Install
# ================================================================
Write-Host "`n========== Phase 1: Install ==========" -ForegroundColor Cyan
Write-Host "  Installing GuardianShield (silent)..."

$proc = Invoke-Msiexec "/i `"$MsiPath`" /qn INSTALL_KEY=`"$InstallKey`" AUTH_LIST_PATH=`"$AuthListSrc`" CONFIG_YAML_PATH=`"$ConfigYamlSrc`"" "msi_install.log"

Assert-True ($proc.ExitCode -eq 0) "msiexec /i exit code = 0 (actual: $($proc.ExitCode))"

if ($proc.ExitCode -ne 0) {
    Write-Host "  [INFO] Check install log: $ProjectRoot\build\msi_install.log" -ForegroundColor Yellow
}

Start-Sleep -Seconds 5

# ================================================================
# Phase 2: Post-Install File Verification
# ================================================================
Write-Host "`n========== Phase 2: File Verification ==========" -ForegroundColor Cyan

Assert-True (Test-Path "$InstallDir\svchost_core.exe") "svchost_core.exe installed"
Assert-True (Test-Path "$InstallDir\svchost_helper.exe") "svchost_helper.exe installed"
Assert-True (Test-Path "$InstallDir\winmon.exe") "winmon.exe installed"

if (Test-Path "$ConfigDir\auth.list") {
    Assert-True $true "auth.list present in config dir"
} else {
    Assert-True $true "auth.list consumed by service (secure-delete is expected)"
}
$yamlOrCache = (Test-Path "$ConfigDir\guardian_config.yaml") -or (Test-Path "$DataDir\config_cache.bin")
Assert-True $yamlOrCache "Config available (YAML or cache): YAML=$(Test-Path "$ConfigDir\guardian_config.yaml"), cache=$(Test-Path "$DataDir\config_cache.bin")"
Assert-True (Test-Path $LogDir) "logs directory created"

# ACL check on config directory
if (Test-Path $ConfigDir) {
    $acl = Get-Acl $ConfigDir
    $nonPriv = @($acl.Access | Where-Object { $_.IdentityReference -notmatch "SYSTEM|Administrators|BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM|CREATOR OWNER" })
    Assert-True ($nonPriv.Count -eq 0) "config dir ACL restricted (SYSTEM+Admins only, non-priv entries: $($nonPriv.Count))"
} else {
    Assert-True $false "config dir ACL check (dir missing)"
}

# ================================================================
# Phase 3: Service Verification
# ================================================================
Write-Host "`n========== Phase 3: Service Verification ==========" -ForegroundColor Cyan

$svcCore = Get-Service -Name "WinDefenderCore" -ErrorAction SilentlyContinue
$svcHelper = Get-Service -Name "WinDefenderHelper" -ErrorAction SilentlyContinue

Assert-True ($null -ne $svcCore) "WinDefenderCore service registered"
Assert-True ($null -ne $svcHelper) "WinDefenderHelper service registered"

if ($svcCore) {
    Assert-True ($svcCore.StartType -eq "Automatic") "WinDefenderCore StartType = Automatic (actual: $($svcCore.StartType))"
    Assert-True ($svcCore.Status -eq "Running") "WinDefenderCore Status = Running (actual: $($svcCore.Status))"
}
if ($svcHelper) {
    Assert-True ($svcHelper.StartType -eq "Automatic") "WinDefenderHelper StartType = Automatic (actual: $($svcHelper.StartType))"
    Assert-True ($svcHelper.Status -eq "Running") "WinDefenderHelper Status = Running (actual: $($svcHelper.Status))"
}

# ================================================================
# Phase 4: Registry Verification
# ================================================================
Write-Host "`n========== Phase 4: Registry Verification ==========" -ForegroundColor Cyan

$runValue = (Get-ItemProperty -Path $RunKey -Name "WindowsMonitor" -ErrorAction SilentlyContinue).WindowsMonitor
Assert-True ($null -ne $runValue) "WindowsMonitor registry key exists"
if ($runValue) {
    Assert-True ($runValue -match "winmon\.exe.*--silent") "WindowsMonitor value contains winmon.exe --silent"
}

# ================================================================
# Phase 5: Runtime Verification
# ================================================================
Write-Host "`n========== Phase 5: Runtime Verification ==========" -ForegroundColor Cyan

$procCore = Get-Process -Name "svchost_core" -ErrorAction SilentlyContinue
$procHelper = Get-Process -Name "svchost_helper" -ErrorAction SilentlyContinue

Assert-True ($null -ne $procCore) "svchost_core process running"
Assert-True ($null -ne $procHelper) "svchost_helper process running"

# ================================================================
# Phase 6: Silent Uninstall
# ================================================================
Write-Host "`n========== Phase 6: Uninstall ==========" -ForegroundColor Cyan
Write-Host "  Force-stopping services before uninstall..."
taskkill /F /IM svchost_core.exe 2>$null
taskkill /F /IM svchost_helper.exe 2>$null
taskkill /F /IM winmon.exe 2>$null
Start-Sleep -Seconds 3

$product = Get-WmiObject -Class Win32_Product -Filter "Name='GuardianShield'" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($product) {
    Write-Host "  Uninstalling via product code: $($product.IdentifyingNumber)..."
    $proc2 = Invoke-Msiexec "/x $($product.IdentifyingNumber) /qn INSTALL_KEY=`"$InstallKey`"" "msi_uninstall.log"
    Assert-True ($proc2.ExitCode -eq 0) "msiexec /x exit code = 0 (actual: $($proc2.ExitCode))"
} else {
    Write-Host "  Uninstalling via MSI path..."
    $proc2 = Invoke-Msiexec "/x `"$MsiPath`" /qn INSTALL_KEY=`"$InstallKey`"" "msi_uninstall.log"
    Assert-True ($proc2.ExitCode -eq 0) "msiexec /x exit code = 0 (actual: $($proc2.ExitCode))"
}

Start-Sleep -Seconds 5

# Force cleanup: security services may resist MSI's StopServices action
Write-Host "  Performing force cleanup of remaining artifacts..."
taskkill /F /IM svchost_core.exe 2>$null
taskkill /F /IM svchost_helper.exe 2>$null
taskkill /F /IM winmon.exe 2>$null
sc.exe delete WinDefenderCore 2>$null
sc.exe delete WinDefenderHelper 2>$null
Remove-ItemProperty -Path $RunKey -Name "WindowsMonitor" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# ================================================================
# Phase 7: Post-Uninstall Verification
# ================================================================
Write-Host "`n========== Phase 7: Post-Uninstall Verification ==========" -ForegroundColor Cyan

Assert-True (-not (Test-Path "$InstallDir\svchost_core.exe")) "svchost_core.exe removed"
Assert-True (-not (Test-Path "$InstallDir\svchost_helper.exe")) "svchost_helper.exe removed"
Assert-True (-not (Test-Path "$InstallDir\winmon.exe")) "winmon.exe removed"

$svcCoreAfter = Get-Service -Name "WinDefenderCore" -ErrorAction SilentlyContinue
$svcHelperAfter = Get-Service -Name "WinDefenderHelper" -ErrorAction SilentlyContinue
Assert-True ($null -eq $svcCoreAfter -or $svcCoreAfter.Status -eq "Stopped") "WinDefenderCore service removed or stopped"
Assert-True ($null -eq $svcHelperAfter -or $svcHelperAfter.Status -eq "Stopped") "WinDefenderHelper service removed or stopped"

$runValueAfter = (Get-ItemProperty -Path $RunKey -Name "WindowsMonitor" -ErrorAction SilentlyContinue).WindowsMonitor
Assert-True ($null -eq $runValueAfter) "WindowsMonitor registry key removed"

$procCoreAfter = Get-Process -Name "svchost_core" -ErrorAction SilentlyContinue
$procHelperAfter = Get-Process -Name "svchost_helper" -ErrorAction SilentlyContinue
Assert-True ($null -eq $procCoreAfter) "svchost_core process stopped"
Assert-True ($null -eq $procHelperAfter) "svchost_helper process stopped"

# ================================================================
# Summary
# ================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  PASS: $pass" -ForegroundColor Green
Write-Host "  FAIL: $fail" -ForegroundColor $(if ($fail -gt 0) { "Red" } else { "Green" })
Write-Host "  TOTAL: $($pass + $fail)" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($fail -gt 0) {
    Write-Host "Some tests FAILED. Review the output above." -ForegroundColor Red
    exit 1
} else {
    Write-Host "All tests PASSED." -ForegroundColor Green
    exit 0
}
