# GuardianShield 云端全生命周期测试计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 在 GitHub Actions 云端环境中执行 GuardianShield 的完整生命周期测试，覆盖构建、单元测试、安全验证、安装/卸载流程验证。

**Architecture:** 采用多阶段 CI/CD 工作流，将测试分为编译阶段、单元测试阶段、集成测试阶段、生命周期验证阶段。利用 GitHub Actions Windows runner 模拟真实 Windows 环境进行服务安装/卸载测试。

**Tech Stack:** GitHub Actions, Windows Server 2022, CMake, Google Test, PowerShell, CMD

---

## 文件结构映射

| 文件 | 责任 |
|------|------|
| `.github/workflows/lifecycle-test.yml` | 主 CI 工作流定义，编排全生命周期测试 |
| `.github/workflows/nightly-test.yml` | 夜间回归测试（全量测试） |
| `scripts/ci/install-test.ps1` | 安装流程验证脚本 |
| `scripts/ci/uninstall-test.ps1` | 卸载流程验证脚本 |
| `scripts/ci/lifecycle-test.ps1` | 完整生命周期测试脚本 |
| `scripts/ci/security-scan.ps1` | 安全扫描和验证脚本 |
| `test/CMakeLists.txt` | 测试可执行文件构建配置（已存在） |
| `test/integration/` | 集成测试代码目录（需创建） |

---

## 测试阶段设计

### Phase 1: 编译与构建验证 (Build Verification)
**目标:** 验证代码在干净环境中可编译，零警告

**触发条件:**
- 每次 push 到 master/main 分支
- 每次 pull request
- 手动触发 (workflow_dispatch)

**步骤:**
1. 检出代码
2. 配置 CMake (Release + Debug)
3. 编译所有目标
4. 验证 `/W4` 零警告
5. 生成构建产物

---

### Phase 2: 单元测试 (Unit Test)
**目标:** 运行所有 Google Test 单元测试，验证核心功能

**测试套件:**
- `test_common.cpp` - 通用工具函数
- `test_config.cpp` - 配置管理
- `test_security.cpp` - 安全功能 (SHA256, HMAC)
- `test_ipc.cpp` - 进程间通信
- `test_emergency.cpp` - 紧急协议状态机
- `test_state_sync.cpp` - 状态同步和脑裂防护
- `test_etw_pipeline.cpp` - ETW 管道
- `test_event_logging.cpp` - 事件日志
- `test_file_encryptor.cpp` - 文件加密
- `test_file_wiper.cpp` - 文件擦除
- `test_threat_evaluator.cpp` - 威胁评估
- `test_heartbeat.cpp` - 心跳机制
- `test_event_response_config.cpp` - 事件响应配置
- `test_driver_client.cpp` - 驱动客户端
- `test_file_monitor.cpp` - 文件监控
- `test_monitor_logger.cpp` - 监控日志
- `test_system_logger.cpp` - 系统日志

**成功标准:**
- 所有测试 PASS
- 无内存泄漏 (通过 AddressSanitizer 或 Valgrind)
- 测试覆盖率 > 80%

---

### Phase 3: 安全验证 (Security Verification)
**目标:** 验证安全修复已正确实施

**检查清单:**
- [ ] **HMAC 硬编码密钥已移除**
  - 验证 `ipc.cpp` 中无 `GuardianShield_IPC_v2` 硬编码密钥
  - 验证使用 DPAPI 派生密钥
  
- [ ] **零校验 HMAC 被拒绝**
  - 验证全零 HMAC 校验被拒绝
  
- [ ] **脑裂防护已实施**
  - 验证 GuardianA 有 `GuardianShield-Leader` 全局互斥体
  - 验证 GuardianB 有 `GuardianShield-Leader` 全局互斥体
  
- [ ] **SHA256File 已实现**
  - 验证 `security.cpp` 有 `BCryptCreateHash` 调用
  
- [ ] **ETW 孤儿会话恢复**
  - 验证 `guardian_a.cpp` 处理 `ERROR_ALREADY_EXISTS`
  
- [ ] **安装密钥为明文**
  - 验证不再使用 SHA256 哈希比较
  - 验证默认密钥为 `GuardianShield2024`

---

### Phase 4: 安装流程验证 (Installation Test)
**目标:** 验证 install.bat 和服务安装流程

**测试步骤:**
1. **前置条件检查**
   - 检查管理员权限
   - 检查系统要求 (Windows 10/11, 64-bit)
   - 清理之前的安装残留

2. **交互式安装测试**
   - 运行 `install.bat` (无参数，进入交互模式)
   - 验证菜单显示正确
   - 选择选项 1 (安装)
   - 输入测试密钥
   - 验证安装成功

3. **命令行安装测试**
   - 运行 `install.bat /install /key GuardianShield2024`
   - 验证退出代码为 0
   - 验证服务已注册:
     - `WinDefenderCore` (GuardianA)
     - `WinDefenderHelper` (GuardianB)
   - 验证可执行文件已复制到 `C:\Program Files\GuardianShield`
   - 验证配置目录已创建 `C:\ProgramData\GuardianShield\config`

4. **错误处理测试**
   - 无效密钥测试 (应失败，退出代码 5)
   - 缺少参数测试 (应失败，退出代码 3)
   - 非管理员权限测试 (应失败，退出代码 2)

---

### Phase 5: 运行时验证 (Runtime Verification)
**目标:** 验证服务启动和基本功能

**测试步骤:**
1. **服务启动测试**
   - 运行 `install.bat /start`
   - 验证服务状态为 RUNNING
   - 验证 GuardianC 进程存在

2. **心跳测试**
   - 验证 GuardianA/B 之间的心跳通信
   - 验证共享内存状态更新

3. **配置加载测试**
   - 验证 YAML 配置被正确读取
   - 验证配置缓存被创建

4. **日志记录测试**
   - 验证日志文件被创建
   - 验证日志格式正确 (JSON)

---

### Phase 6: 功能集成测试 (Integration Test)
**目标:** 验证各组件协同工作

**测试场景:**
1. **文件监控场景**
   - 在保护目录创建测试文件
   - 验证 ETW 事件被捕获
   - 验证威胁评估正确
   - 验证响应动作执行

2. **紧急协议场景**
   - 模拟批量删除操作
   - 验证 Tier-1 保护协议触发
   - 验证文件被加密

3. **故障转移场景**
   - 停止 GuardianA
   - 验证 GuardianB 接管主控
   - 验证脑裂防护生效

---

### Phase 7: 卸载流程验证 (Uninstallation Test)
**目标:** 验证完全卸载和清理

**测试步骤:**
1. **交互式卸载测试**
   - 运行 `install.bat` (交互模式)
   - 选择选项 2 (卸载)
   - 输入密钥
   - 验证卸载成功

2. **命令行卸载测试**
   - 运行 `install.bat /uninstall /key GuardianShield2024`
   - 验证退出代码为 0
   - 验证服务已删除
   - 验证进程已终止
   - 验证安装目录已删除 (或标记为重启后删除)

3. **清理验证**
   - 验证注册表项已清理
   - 验证启动项已移除
   - 验证临时文件已清理

---

### Phase 8: 回归测试 (Regression Test)
**目标:** 验证新变更未破坏现有功能

**测试矩阵:**
| 测试项 | 预期结果 |
|--------|----------|
| 安装→启动→停止→卸载 | 完整流程成功 |
| 重复安装（已安装） | 优雅处理，不崩溃 |
| 卸载后重新安装 | 成功 |
| 无效密钥安装 | 拒绝安装，退出代码 5 |
| 配置热加载 | 配置变更生效 |

---

## CI 工作流设计

### 主工作流: lifecycle-test.yml

```yaml
name: GuardianShield Lifecycle Test

on:
  push:
    branches: [ master, main ]
  pull_request:
    branches: [ master, main ]
  workflow_dispatch:
    inputs:
      test_level:
        description: 'Test level'
        required: true
        default: 'full'
        type: choice
        options:
          - quick      # 仅编译 + 单元测试
          - standard   # 编译 + 单元测试 + 安全验证
          - full       # 完整生命周期测试

jobs:
  # Job 1: 编译验证
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Configure CMake
        run: cmake -B build -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTS=ON
      - name: Build
        run: cmake --build build --config Release
      - name: Check Warnings
        run: |
          cmake --build build --config Release 2>&1 | Tee-Object build.log
          if (Select-String -Path build.log -Pattern "warning C") { exit 1 }
      - name: Upload Build Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: build-artifacts
          path: build/src/service/**/Release/*.exe

  # Job 2: 单元测试
  unit-test:
    needs: build
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Download Build Artifacts
        uses: actions/download-artifact@v4
        with:
          name: build-artifacts
          path: build/
      - name: Run Tests
        run: ctest --test-dir build -C Release --output-on-failure

  # Job 3: 安全验证
  security-check:
    needs: build
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Security Scan
        run: ./scripts/ci/security-scan.ps1

  # Job 4: 生命周期测试 (仅在 full 模式下运行)
  lifecycle-test:
    needs: [build, unit-test]
    if: github.event.inputs.test_level == 'full' || github.event_name == 'schedule'
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Download Build Artifacts
        uses: actions/download-artifact@v4
        with:
          name: build-artifacts
          path: deploy-package/
      - name: Copy Install Scripts
        run: |
          Copy-Item install.bat deploy-package/
          Copy-Item config/guardian_config.yaml deploy-package/
          Copy-Item config/auth.list deploy-package/
      - name: Run Lifecycle Test
        run: ./scripts/ci/lifecycle-test.ps1 -Key "GuardianShield2024"

  # Job 5: 生成测试报告
  report:
    needs: [unit-test, security-check, lifecycle-test]
    if: always()
    runs-on: ubuntu-latest
    steps:
      - name: Generate Test Report
        uses: dorny/test-reporter@v1
        with:
          name: GuardianShield Test Results
          path: '**/test-results.xml'
          reporter: jest-junit
```

---

## PowerShell 测试脚本设计

### scripts/ci/lifecycle-test.ps1

```powershell
<#
.SYNOPSIS
    GuardianShield 完整生命周期测试脚本
.DESCRIPTION
    执行安装→启动→验证→停止→卸载的完整流程测试
.PARAMETER Key
    安装/卸载使用的密钥
.PARAMETER InstallDir
    安装目录 (默认: C:\Program Files\GuardianShield)
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$Key,
    
    [string]$InstallDir = "C:\Program Files\GuardianShield",
    [string]$PackageDir = "$PSScriptRoot\..\..\deploy-package"
)

$ErrorActionPreference = "Stop"
$TestResults = @{
    Total = 0
    Passed = 0
    Failed = 0
    Tests = @()
}

function Test-Step {
    param($Name, $ScriptBlock)
    $TestResults.Total++
    Write-Host "`n[Test] $Name" -ForegroundColor Cyan
    try {
        & $ScriptBlock
        $TestResults.Passed++
        $TestResults.Tests += @{ Name = $Name; Result = "PASS"; Error = $null }
        Write-Host "[PASS] $Name" -ForegroundColor Green
        return $true
    } catch {
        $TestResults.Failed++
        $TestResults.Tests += @{ Name = $Name; Result = "FAIL"; Error = $_.Exception.Message }
        Write-Host "[FAIL] $Name : $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ==================== 前置清理 ====================
Test-Step "Pre-test Cleanup" {
    # 停止并卸载之前的服务
    @("WinDefenderCore", "WinDefenderHelper") | ForEach-Object {
        sc stop $_ 2>$null
        sc delete $_ 2>$null
    }
    # 终止进程
    @("svchost_core", "svchost_helper", "winmon") | ForEach-Object {
        taskkill /F /IM "$_.exe" 2>$null
    }
    # 删除目录
    Remove-Item -Path $InstallDir -Recurse -Force 2>$null
    Remove-Item -Path "C:\ProgramData\GuardianShield" -Recurse -Force 2>$null
    Start-Sleep -Seconds 2
}

# ==================== 安装测试 ====================
Test-Step "Installation" {
    $proc = Start-Process -FilePath "$PackageDir\install.bat" `
        -ArgumentList "/install", "/key", $Key `
        -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) { throw "Install failed with exit code $($proc.ExitCode)" }
}

Test-Step "Service Registration Check" {
    $svcA = Get-Service -Name "WinDefenderCore" -ErrorAction Stop
    $svcB = Get-Service -Name "WinDefenderHelper" -ErrorAction Stop
    if ($svcA.Status -ne 'Running') { throw "GuardianA not running" }
    if ($svcB.Status -ne 'Running') { throw "GuardianB not running" }
}

Test-Step "File Deployment Check" {
    @("svchost_core.exe", "svchost_helper.exe", "winmon.exe") | ForEach-Object {
        if (-not (Test-Path "$InstallDir\$_")) { throw "$_ not found in install dir" }
    }
}

# ==================== 运行时测试 ====================
Test-Step "Heartbeat Verification" {
    # 检查共享内存或日志文件确认心跳
    Start-Sleep -Seconds 5
    $logFile = Get-ChildItem "C:\ProgramData\GuardianShield\logs\*.json" | Select-Object -First 1
    if (-not $logFile) { throw "No log files created" }
}

# ==================== 卸载测试 ====================
Test-Step "Uninstallation" {
    $proc = Start-Process -FilePath "$PackageDir\install.bat" `
        -ArgumentList "/uninstall", "/key", $Key `
        -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) { throw "Uninstall failed with exit code $($proc.ExitCode)" }
}

Test-Step "Service Removal Check" {
    $svcA = Get-Service -Name "WinDefenderCore" -ErrorAction SilentlyContinue
    $svcB = Get-Service -Name "WinDefenderHelper" -ErrorAction SilentlyContinue
    if ($svcA -or $svcB) { throw "Services still exist after uninstall" }
}

# ==================== 报告 ====================
Write-Host "`n=============================" -ForegroundColor Yellow
Write-Host "Test Summary" -ForegroundColor Yellow
Write-Host "=============================" -ForegroundColor Yellow
Write-Host "Total:  $($TestResults.Total)"
Write-Host "Passed: $($TestResults.Passed)" -ForegroundColor Green
Write-Host "Failed: $($TestResults.Failed)" -ForegroundColor Red

if ($TestResults.Failed -gt 0) {
    Write-Host "`nFailed Tests:" -ForegroundColor Red
    $TestResults.Tests | Where-Object { $_.Result -eq "FAIL" } | ForEach-Object {
        Write-Host "  - $($_.Name): $($_.Error)" -ForegroundColor Red
    }
    exit 1
}

exit 0
```

---

## 执行路线图

### 第一阶段: 基础设施 (2-3 小时)
- [ ] 创建 `.github/workflows/lifecycle-test.yml`
- [ ] 创建 `scripts/ci/security-scan.ps1`
- [ ] 创建 `scripts/ci/lifecycle-test.ps1`
- [ ] 更新现有 `.github/workflows/build-test.yml` 以支持产物传递

### 第二阶段: 单元测试增强 (3-4 小时)
- [ ] 确保所有现有测试在 CI 环境通过
- [ ] 添加测试覆盖率报告
- [ ] 创建测试报告聚合

### 第三阶段: 集成测试 (4-5 小时)
- [ ] 创建集成测试框架
- [ ] 实现文件监控集成测试
- [ ] 实现紧急协议集成测试
- [ ] 实现故障转移集成测试

### 第四阶段: 生命周期自动化 (3-4 小时)
- [ ] 完善 install/uninstall 测试脚本
- [ ] 添加错误场景测试
- [ ] 添加并发/压力测试

### 第五阶段: 报告与优化 (2-3 小时)
- [ ] 创建测试仪表板
- [ ] 添加性能基准测试
- [ ] 添加回归检测
- [ ] 文档完善

---

## 成功标准

| 指标 | 目标 |
|------|------|
| 单元测试通过率 | 100% |
| 集成测试通过率 | 100% |
| 生命周期测试通过率 | 100% |
| 代码覆盖率 | > 80% |
| 编译警告 | 0 |
| CI 执行时间 | < 30 分钟 |
| 安全扫描 | 100% 通过 |

---

## 风险评估

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| GitHub Actions Windows runner 限制 | 高 | 使用 self-hosted runner 或缩短测试时间 |
| 服务安装需要管理员权限 | 中 | CI runner 默认以管理员运行 |
| 测试间状态污染 | 中 | 每个测试前执行完整清理 |
| 时间敏感测试不稳定 | 低 | 增加重试机制，使用宽松超时 |

---

## 下一步行动

1. **立即执行**: 创建基础 CI 工作流文件
2. **并行开发**: 创建 PowerShell 测试脚本
3. **逐步验证**: 分阶段测试每个组件
4. **持续优化**: 根据 CI 执行情况调整

**预计总工作量:** 14-19 小时
**建议团队规模:** 2-3 人并行
