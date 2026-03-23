# GuardianShield 管理员操作手册

**版本**: 3.3.0  
**日期**: 2026-03-18  
**适用对象**: 系统管理员 / 安全运维人员

---

## 目录

- [1. 概述](#1-概述)
- [2. 环境要求](#2-环境要求)
- [3. 部署前准备](#3-部署前准备)
  - [3.1 生成 SHA-256 密码哈希](#31-生成-sha-256-密码哈希)
  - [3.2 编辑 guardian_config.yaml](#32-编辑-guardian_configyaml)
  - [3.3 编辑 auth.list](#33-编辑-authlist)
- [4. 安装部署](#4-安装部署)
  - [4.1 方式一：MSI 安装包](#41-方式一msi-安装包)
  - [4.2 方式二：run.bat 一键部署](#42-方式二runbat-一键部署)
  - [4.3 方式三：手动逐步安装](#43-方式三手动逐步安装)
  - [4.4 安装验证](#44-安装验证)
- [5. 日常运维](#5-日常运维)
  - [5.1 服务状态查看](#51-服务状态查看)
  - [5.2 日志查看](#52-日志查看)
  - [5.3 配置更新（"钥匙"机制）](#53-配置更新钥匙机制)
- [6. 安全事件处置](#6-安全事件处置)
  - [6.1 威胁等级说明](#61-威胁等级说明)
  - [6.2 锁屏窗口解锁](#62-锁屏窗口解锁)
  - [6.3 紧急协议触发后的恢复](#63-紧急协议触发后的恢复)
- [7. 卸载](#7-卸载)
  - [7.1 方式一：一键卸载脚本](#71-方式一一键卸载脚本)
  - [7.2 方式二：MSI 卸载](#72-方式二msi-卸载)
  - [7.3 方式三：手动卸载](#73-方式三手动卸载)
  - [7.4 残留清理](#74-残留清理)
- [8. 故障排除](#8-故障排除)
- [9. v2.1.0 变更说明](#9-v210-变更说明)
- [10. v2.5.0 变更说明](#10-v250-变更说明)
- [11. 附录](#11-附录)
  - [11.1 SHA-256 哈希生成方法](#111-sha-256-哈希生成方法)
  - [11.2 默认路径一览表](#112-默认路径一览表)
  - [11.3 guardian_config.yaml 完整字段参考](#113-guardian_configyaml-完整字段参考)

---

## 1. 概述

GuardianShield 是一套企业级源代码防泄漏系统，采用五层纵深防御架构，核心由三个组件组成：

| 组件 | 进程名 | 服务名 | 运行方式 | 核心职责 |
|------|--------|--------|---------|---------|
| GuardianA | svchost_core.exe | WinDefenderCore | Windows 服务 (SYSTEM) | 威胁评估、ETW 事件采集、紧急协议触发、内核驱动通信、决策中枢 |
| GuardianB | svchost_helper.exe | WinDefenderHelper | Windows 服务 (SYSTEM) | 监控 A 的健康状态，A 失效时自动接管主控，A 恢复后退回 |
| GuardianC | winmon.exe | — | 用户态程序（开机自启） | 心跳监控、系统托盘图标、用户通知弹窗、全屏锁屏窗口、密码解锁、文件管理面板、一键解锁 |

辅助组件：

| 组件 | 说明 |
|------|------|
| GuardFilter.sys | minifilter 文件系统监控驱动（需 WDK 编译） |
| GuardMonitor.sys | 进程/映像通知驱动，含 ObRegisterCallbacks 进程保护（需 WDK 编译） |
| guardian_ca.dll | WiX MSI 安装自定义动作 DLL |
| uninstall.bat | 一键卸载脚本 |

### 工作原理

```
┌─────────────────────────────────────────────────────────────┐
│                      五层纵深防御                             │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: 物理隔离   — IP/MAC 地址绑定验证                     │
│ Layer 2: 内核监控   — GuardFilter.sys + GuardMonitor.sys     │
│ Layer 3: 进程守护   — GuardianA + GuardianB + GuardianC      │
│ Layer 4: 紧急熔断   — 加密 → 擦除 → 锁定                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 环境要求

### 目标机器

| 项目 | 要求 |
|------|------|
| 操作系统 | Windows 10/11 (x64) |
| 权限 | 安装、卸载、配置更新均需管理员权限 |
| 磁盘空间 | ≥ 50 MB（安装目录 + 运行时数据 + 日志） |
| 网络 | 用于 IP/MAC 环境校验（如部署在离线环境请确保 auth.list 正确） |

### 编译环境（仅源码部署方式需要）

| 工具 | 版本 |
|------|------|
| Visual Studio 2022 | 含 C++ 桌面开发工作负载 |
| Windows SDK | 10.0.19041.0 或更高 |
| CMake | 3.20+ |
| WDK 11 | 仅编译内核驱动需要 |

---

## 3. 部署前准备

### 3.1 生成 SHA-256 密码哈希

GuardianShield 使用 SHA-256 哈希值存储密码，不存储明文。管理员需要为以下两个密码生成哈希：

1. **管理员密码** (`admin.password_hash`) — 用于锁屏解锁
2. **安装/卸载密钥** (`admin.install_key_hash`) — 用于安装和卸载操作

**PowerShell 生成命令：**

```powershell
# 将 '你的密码' 替换为实际密码
[System.BitConverter]::ToString(
  [System.Security.Cryptography.SHA256]::Create().ComputeHash(
    [System.Text.Encoding]::UTF8.GetBytes('你的密码')
  )
).Replace('-','').ToLower()
```

**示例：**

```powershell
PS> [System.BitConverter]::ToString(
>>   [System.Security.Cryptography.SHA256]::Create().ComputeHash(
>>     [System.Text.Encoding]::UTF8.GetBytes('MySecurePassword123')
>>   )
>> ).Replace('-','').ToLower()

# 输出: ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
```

> **重要**：请牢记设置的密码原文。如果忘记管理员密码，锁屏后需通过安全模式恢复（见 [6.3 节](#63-紧急协议触发后的恢复)）。

### 3.2 编辑 guardian_config.yaml

配置文件模板位于 `config/guardian_config.yaml`。以下是必须关注的关键配置项：

#### 管理员密码（必须修改）

```yaml
admin:
  # 管理员密码的 SHA-256 哈希（锁屏解锁用）
  password_hash: "在此粘贴 3.1 节生成的哈希值"

  # 安装/卸载密钥的 SHA-256 哈希
  # 留空则使用默认密钥 GuardianShield2026!
  install_key_hash: "在此粘贴 3.1 节生成的哈希值"
```

#### 保护目录（根据实际情况修改）

```yaml
protection:
  directories:
    - path: "D:\\Projects\\SourceCode"     # 保护的源码目录
      recursive: true                       # 递归保护子目录
      priority: HIGH
    - path: "E:\\ConfidentialDocs"
      recursive: true
      priority: MEDIUM
```

#### 检测阈值（按需调整）

```yaml
detection:
  alert_timeout_seconds: 30          # ALERT 阶段等待管理员取消的超时时间
  thresholds:
    tier1:                           # 保护协议阈值（加密+锁定，可恢复）
      file_write_count: 10           # 5 秒内写入 ≥10 个文件触发保护协议
      file_write_window_seconds: 5
      file_delete_count: 5
      file_delete_window_seconds: 5
      file_compress_count: 50
    tier2:                           # 紧急协议阈值（加密+擦除，不可逆）
      file_write_count: 50
      file_write_window_seconds: 10
      file_delete_count: 20
      file_delete_window_seconds: 10
      file_compress_count: 250
```

#### 白名单进程（允许操作保护文件的工具）

```yaml
whitelist:
  processes:
    - name: "devenv.exe"             # Visual Studio
      permissions: [READ, WRITE]
    - name: "code.exe"               # VS Code
      permissions: [READ, WRITE]
    - name: "Notepad.exe"            # 记事本（经典版 + UWP 版均匹配）
      permissions: [READ, WRITE]
```

> **v2.1 UWP 支持**：Windows 11 的 UWP 应用（如新版记事本）其 ETW 路径为类似 `WindowsApps\microsoft.windowsnotepad_...\Notepad\Notepad.exe` 的格式。系统已内置 UWP 回退逻辑——当 ETW 路径无法直接提取 `.exe` 名时，自动通过 `QueryFullProcessImageNameW` 获取真实进程名再匹配白名单。只需填写 `"Notepad.exe"` 即可同时覆盖经典版和 UWP 版。
>
> 完整字段参考见 [10.3 节](#103-guardian_configyaml-完整字段参考)。

### 3.3 编辑 auth.list

授权清单文件位于 `config/auth.list`，定义了允许运行 GuardianShield 的设备。

**格式：** 每行一条记录，`IP地址,MAC地址,备注`

```
# GuardianShield 授权清单
# 格式: IP地址,MAC地址,备注
192.168.1.100,AA:BB:CC:DD:EE:FF,研发一组-张三
192.168.1.101,11:22:33:44:55:66,研发一组-李四
192.168.1.102,A1:B2:C3:D4:E5:F6,测试机
```

**获取本机信息：**

```powershell
# 查看本机 IP 和 MAC 地址
Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress, InterfaceAlias
Get-NetAdapter | Select-Object Name, MacAddress
```

> **注意**：MAC 地址格式为 `XX:XX:XX:XX:XX:XX`（冒号分隔）。系统会自动处理大小写和格式差异。
>
> auth.list 在服务启动后会被自动删除，授权信息纳入受 ACL 保护的二进制缓存。下次更新授权清单时，将新文件放入配置目录重启服务即可。

---

## 4. 安装部署

### 4.1 方式一：MSI 安装包

MSI 安装包适用于已编译好的部署场景。

**操作步骤：**

1. 双击 `GuardianShield.msi` 启动安装向导
2. **输入安装密钥** — 输入管理员设定的安装密钥（明文）
3. **选择配置文件** — 浏览并选择准备好的 `auth.list` 和 `guardian_config.yaml`
4. **确认安装** — 安装程序自动完成以下操作：
   - 复制可执行文件至 `C:\Program Files\GuardianShield\`
   - 复制配置文件至 `C:\ProgramData\GuardianShield\config\`
   - 设置配置文件 ACL 权限（仅 SYSTEM + Administrators 可访问）
   - 注册 Windows 服务（WinDefenderCore、WinDefenderHelper）
   - 添加 GuardianC 开机自启
5. 安装完成后服务自动启动

### 4.2 方式二：run.bat 一键部署

适用于从源码编译并部署的场景。

**操作步骤：**

1. 确保已完成 [第 3 节](#3-部署前准备) 的准备工作
2. 右键 `run.bat` → "以管理员身份运行"
3. 选择 `[1] One-Click Build + Install + Start`
4. 按提示输入安装密钥
5. 等待自动完成：编译 → 安装服务 → 启动

```
============================================================
      GuardianShield Control Panel  v2.0.0
============================================================

  [1]  One-Click Build + Install + Start  (Full Deploy)
  [2]  Build Only
  [3]  Install Services  (requires Admin)
  [4]  Start Services    (requires Admin)
  [5]  Stop Services     (requires Admin)
  [6]  Check Status
  [7]  Uninstall All     (requires Admin)
  [8]  Clean Build
  [0]  Exit

============================================================
```

### 4.3 方式三：手动逐步安装

以管理员身份打开命令提示符：

```cmd
:: 步骤 1：编译（如使用预编译版本可跳过）
build.bat

:: 步骤 2：复制文件到安装目录
mkdir "C:\Program Files\GuardianShield"
copy build\src\service\GuardianA\Release\svchost_core.exe   "C:\Program Files\GuardianShield\"
copy build\src\service\GuardianB\Release\svchost_helper.exe "C:\Program Files\GuardianShield\"
copy build\src\service\GuardianC\Release\winmon.exe         "C:\Program Files\GuardianShield\"

:: 步骤 3：复制配置文件
mkdir "C:\ProgramData\GuardianShield\config"
copy config\guardian_config.yaml "C:\ProgramData\GuardianShield\config\"
copy config\auth.list            "C:\ProgramData\GuardianShield\config\"

:: 步骤 4：安装服务（需输入安装密钥）
cd "C:\Program Files\GuardianShield"
svchost_core.exe -install -key 你的安装密钥
svchost_helper.exe -install -key 你的安装密钥
winmon.exe --install -key 你的安装密钥

:: 步骤 5：启动服务
svchost_core.exe -start
svchost_helper.exe -start
start winmon.exe --silent
```

### 4.4 安装验证

安装完成后，使用以下方法验证系统是否正常运行：

**方法一：命令行查看**

```cmd
sc query WinDefenderCore
sc query WinDefenderHelper
tasklist | findstr winmon
```

预期输出：两个服务状态均为 `RUNNING`，`winmon.exe` 进程存在。

**方法二：使用 run.bat**

运行 `run.bat` 选择 `[6] Check Status`。

**方法三：查看日志**

```powershell
# 查看最新日志
Get-ChildItem "C:\ProgramData\GuardianShield\logs\" | Sort-Object LastWriteTime -Descending | Select-Object -First 5
```

日志目录下应生成当天的日志文件 `guardian_YYYY-MM-DD.json`。

**验证配置"钥匙"机制：**

```powershell
# YAML 配置应已被自动删除
Test-Path "C:\ProgramData\GuardianShield\config\guardian_config.yaml"
# 预期: False

# 二进制缓存应已生成
Test-Path "C:\ProgramData\GuardianShield\config_cache.bin"
# 预期: True

# auth.list 应已被自动删除
Test-Path "C:\ProgramData\GuardianShield\config\auth.list"
# 预期: False
```

---

## 5. 日常运维

### 5.1 服务状态查看

| 方式 | 命令 |
|------|------|
| run.bat | 运行 `run.bat` → 选择 `[6]` |
| sc 命令 | `sc query WinDefenderCore` / `sc query WinDefenderHelper` |
| 服务程序自带 | `svchost_core.exe -status` / `svchost_helper.exe -status` |
| 服务管理器 | 打开 `services.msc` → 查找 WinDefenderCore / WinDefenderHelper |
| GuardianC | `winmon.exe --status`（查看自启动状态） |
| 任务管理器 | 查找 `winmon.exe` 进程 |

**正常状态：**
- WinDefenderCore：运行中
- WinDefenderHelper：运行中
- winmon.exe：进程存在

### 5.2 日志查看

**日志位置：** `C:\ProgramData\GuardianShield\logs\`

**日志文件格式：**

| 文件名 | 内容 |
|--------|------|
| `guardian_YYYY-MM-DD.json` | 系统运行日志（威胁检测、紧急事件、配置变更等） |
| `monitor_YYYY-MM-DD.json` | 文件监控事件日志（文件操作记录） |

**日志轮转：** 每天生成新文件，默认保留 7 天（可通过 `logging.retention_days` 配置）。

**查看日志示例：**

```powershell
# 查看今天的系统日志
Get-Content "C:\ProgramData\GuardianShield\logs\guardian_2026-03-02.json" | ConvertFrom-Json | Format-Table

# 查看最近 20 条日志
Get-Content "C:\ProgramData\GuardianShield\logs\guardian_2026-03-02.json" -Tail 20

# 筛选告警以上级别
Get-Content "C:\ProgramData\GuardianShield\logs\guardian_2026-03-02.json" | Select-String "WARN|ERROR|CRITICAL"
```

### 5.3 配置更新（"钥匙"机制）

GuardianShield 使用"配置即钥匙"机制：配置文件在读取后自动删除，仅保留受 ACL 保护的二进制缓存。更新配置的完整流程如下：

```
管理员编辑 YAML → 放入配置目录 → 重启服务 → 自动读取 → YAML 自动删除
```

**操作步骤：**

1. **编辑配置文件** — 在安全的位置编辑 `guardian_config.yaml`（勿在公共目录操作）

2. **放入配置目录** — 将文件复制到运行时配置目录：
   ```cmd
   copy guardian_config.yaml "C:\ProgramData\GuardianShield\config\"
   ```

3. **重启服务** — 服务将自动检测新的 YAML 文件：
   ```cmd
   sc stop WinDefenderCore && sc start WinDefenderCore
   sc stop WinDefenderHelper && sc start WinDefenderHelper
   ```
   或使用 `run.bat`：停止 `[5]` → 启动 `[4]`

4. **验证** — 确认 YAML 已被读取并删除：
   ```powershell
   # 应返回 False（表示已被自动删除）
   Test-Path "C:\ProgramData\GuardianShield\config\guardian_config.yaml"
   ```

> **注意**：如果只需更新授权清单，将新的 `auth.list` 放入配置目录后重启服务即可，auth.list 同样会被自动读取并删除。

---

## 6. 安全事件处置

### 6.1 威胁等级说明

| 等级 | 名称 | 触发示例 | 系统响应 |
|------|------|---------|---------|
| LEVEL_0 | Normal | 文件读取、创建、进程终止、驱动加载/卸载 | 仅记录日志 |
| LEVEL_1 | Suspicious | 文件修改、删除、移动、压缩 | 日志 + 告警（可配置） |
| LEVEL_2 | Dangerous | 进程注入、调试器附加 | 日志 + 告警 + 阻止操作 + 终止进程 |
| LEVEL_3 | Critical | 网络外传、批量操作超阈值、环境校验失败 | **触发紧急协议：加密 → 擦除 → 系统锁定** |

> **v2.1 变更**：进程终止（PROCESS_TERMINATE）和驱动加载/卸载事件从 LEVEL_1 降级为 LEVEL_0，仅记录日志不再弹窗。Tier-2 紧急协议中的 TERMINATE 动作改为精准终止事件贡献最多的单个进程 PID，`explorer.exe`、`dwm.exe` 等核心系统进程受保护不会被终止。

### 6.2 锁屏窗口解锁

当系统触发 LEVEL_3 紧急协议并完成加密/擦除后，GuardianC 会在用户桌面显示一个 **全屏锁定窗口**。

**锁屏窗口特征：**
- 全屏覆盖整个桌面（包括任务栏）
- 始终保持在最顶层，每秒强制置顶
- 无关闭按钮，Alt+F4 和 Esc 均被拦截
- 显示红色 "系统已锁定" 标题和警告信息
- 底部提供密码输入框和"解锁"按钮

**解锁操作：**

1. 在密码输入框中输入管理员密码（即 `admin.password_hash` 对应的明文密码）
2. 点击"解锁"按钮或按 Enter 键
3. 密码验证通过后：
   - 锁屏窗口自动关闭
   - GuardianC 通过 IPC 广播 `UNLOCK_RESPONSE` 消息
   - GuardianA/B 接收后解锁文件并取消紧急状态
4. 系统恢复正常运行

> **如果输入错误密码**：窗口会提示"密码错误，请重试"，不会关闭。没有错误次数限制。

### 6.3 紧急协议触发后的恢复

紧急协议执行后，保护目录中的文件已被加密为 `.gs` 格式并安全擦除原件。解锁后的恢复步骤：

**正常恢复：**

在锁屏窗口输入密码解锁后，系统自动完成以下操作：
1. 加密的 `.gs` 文件可通过以下方式恢复：
   - **GuardianC 托盘右键 → 文件管理 → 输入管理员密码 → 一键解锁**（v2.5 新增，推荐）
   - 使用独立解密工具手动恢复
3. 取消紧急状态，系统回到 NORMAL

**忘记密码时的紧急恢复：**

1. 重启计算机进入 **Windows 安全模式**
2. 以管理员身份打开命令提示符
3. 停止所有服务：
   ```cmd
   sc stop WinDefenderCore
   sc stop WinDefenderHelper
   taskkill /f /im winmon.exe
   ```
4. 删除缓存配置：
   ```cmd
   del "C:\ProgramData\GuardianShield\config_cache.bin"
   ```
5. 准备新的配置文件（包含新密码的哈希值）：
   ```cmd
   copy guardian_config.yaml "C:\ProgramData\GuardianShield\config\"
   ```
6. 正常重启 Windows，服务将使用新配置启动

> **警告**：紧急协议执行的安全擦除操作（DOD 5220.22-M 7 次覆写）是不可逆的。擦除后的原始文件无法恢复，仅加密的 `.gs` 备份可解密还原。

---

## 7. 卸载

所有卸载方式都需要管理员权限和正确的卸载密钥。

### 7.1 方式一：一键卸载脚本

最推荐的卸载方式，自动完成全部清理工作。

**操作步骤：**

1. 右键 `scripts\uninstall.bat` → "以管理员身份运行"
2. 输入管理员卸载密钥（明文）
3. 脚本自动执行以下操作：
   - 停止 WinDefenderCore 和 WinDefenderHelper 服务
   - 终止 winmon.exe 进程
   - 验证密钥并卸载各组件
   - 删除服务注册
   - 清理注册表自启动项
   - 删除 `C:\ProgramData\GuardianShield\` 运行时数据
   - 删除 `C:\Program Files\GuardianShield\` 安装目录
4. 卸载完成后显示结果

```
============================================================
      GuardianShield 一键卸载工具
============================================================

  请输入管理员卸载密钥: ********
  [1/6] 停止服务和进程...       [OK]
  [2/6] 验证密钥并卸载服务...   [OK]
  [3/6] 清理服务注册...         [OK]
  [4/6] 清理注册表...           [OK]
  [5/6] 清理运行时数据...       [OK]
  [6/6] 清理安装目录...         [OK]

============================================================
  GuardianShield 已成功卸载！
============================================================
```

### 7.2 方式二：MSI 卸载

如果通过 MSI 安装，可以使用以下方式卸载：

1. 打开 **控制面板** → **程序和功能**
2. 找到 GuardianShield → 点击 **卸载**
3. 输入管理员卸载密钥
4. 确认卸载

或直接运行 MSI 安装包，选择卸载选项。

### 7.3 方式三：手动卸载

以管理员身份打开命令提示符，逐步执行：

```cmd
:: 1. 停止服务和进程
sc stop WinDefenderCore
sc stop WinDefenderHelper
taskkill /f /im winmon.exe
timeout /t 2 /nobreak >nul

:: 2. 卸载服务（需密钥）
svchost_core.exe -uninstall -key 你的密钥
svchost_helper.exe -uninstall -key 你的密钥
winmon.exe --uninstall -key 你的密钥

:: 3. 删除服务注册（兜底）
sc delete WinDefenderCore
sc delete WinDefenderHelper

:: 4. 清理注册表自启动
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v WindowsMonitor /f

:: 5. 删除运行时数据和安装目录
rmdir /s /q "C:\ProgramData\GuardianShield"
rmdir /s /q "C:\Program Files\GuardianShield"
```

### 7.4 残留清理

如果卸载后仍有残留（文件被占用等），重启计算机后手动删除：

```cmd
rmdir /s /q "C:\ProgramData\GuardianShield"
rmdir /s /q "C:\Program Files\GuardianShield"
```

确认以下注册表项已清理：

```cmd
:: 检查服务注册
sc query WinDefenderCore
sc query WinDefenderHelper
:: 预期: "指定的服务未安装"

:: 检查自启动
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v WindowsMonitor
:: 预期: 错误（项不存在）
```

---

## 8. 故障排除

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| 安装时提示"拒绝访问" | 未以管理员权限运行 | 右键"以管理员身份运行" |
| 安装时提示"密钥错误" | 输入的密钥不正确 | 确认密钥原文与 `admin.install_key_hash` 对应。默认密钥为 `GuardianShield2026!` |
| 服务启动后立即停止 | 配置文件缺失或格式错误 | 检查 `C:\ProgramData\GuardianShield\` 下是否有 `config_cache.bin` 或新的 YAML 文件（YAML 可放在 config\ 子目录）。查看日志获取错误详情 |
| 服务无法启动（错误 1053） | 服务启动超时 | 检查日志；可能由于配置加载耗时过长或依赖服务未就绪 |
| winmon.exe 不在进程列表中 | GuardianC 未启动或已崩溃 | 手动运行 `winmon.exe --silent`；检查注册表自启动项是否正确 |
| 锁屏窗口出现但未进行违规操作 | 可能是 auth.list 配置不正确导致环境校验失败 | 进入安全模式，更新 auth.list 和配置。参见 [6.3 节](#63-紧急协议触发后的恢复) |
| 忘记管理员密码 | — | 安全模式下删除 `C:\ProgramData\GuardianShield\config_cache.bin`，放入包含新密码哈希的 YAML，重启服务。参见 [6.3 节](#63-紧急协议触发后的恢复) |
| 日志目录为空 | 日志路径不存在或无写入权限 | 检查 `system.log_path` 配置的目录是否存在，服务账户（SYSTEM）是否有写入权限 |
| 构建时 Google Test 下载失败 | 网络问题 | 设置代理：`$env:HTTP_PROXY = "http://proxy:port"` 或使用 `-DBUILD_TESTS=OFF` 跳过 |
| 构建报 C4819 编码警告 | 源文件编码问题 | CMakeLists.txt 已包含 `/utf-8` 标志，确保 VS2022 为最新版本 |
| 内核驱动无法加载 | 未启用测试签名 | 执行 `bcdedit /set testsigning on` 并重启 |
| 卸载脚本提示密钥错误 | 密钥不匹配 | 使用安装时设定的密钥。如果使用了统一管理员密钥（YAML 中配置），使用该密钥 |
| 解锁后文件仍无法访问 | 权限问题 | 管理员手动执行 `icacls "文件路径" /reset` 恢复继承权限 |
| 通知弹窗过多（v2.0） | 进程终止事件触发大量 ALERT | **已在 v2.1 修复**：进程事件降级为 LEVEL_0/LOG，不再弹窗 |
| explorer.exe 被终止导致桌面消失（v2.0） | Tier-2 紧急协议无差别终止 | **已在 v2.1 修复**：explorer.exe 加入终止保护名单，TERMINATE 改为精准终止 |
| 服务重启后文件操作无告警 | ETW 会话孤儿/阻塞导致事件采集停滞 | **已在 v2.5 修复**：ETW 活性守护（60 秒无事件自动重启）+ 自动恢复循环。若仍出现，检查日志中 "ETW stall detected" 相关条目 |
| 告警通知不弹出（服务正常运行） | IPC 管道连接超时或 GuardianC 未就绪 | **已在 v2.5 优化**：tryConnect 超时从 3x1000ms 降至 1x300ms，失败时 MessageBeep 音效回退。检查日志中 "ALERT_NOTIFICATION sent/FAILED" |
| 加密的 .gs 文件需要恢复 | 紧急协议执行后文件被加密 | 通过 GuardianC 托盘右键 → 文件管理 → 输入管理员密码 → 一键解锁恢复 |

---

## 9. v2.1.0 变更说明

v2.1.0 基于深层根因分析修复了 v2.0.0 在实际部署中发现的 **8 个关键 Bug**，核心改动涉及 12 项结构性修复：

### 9.1 问题根因：放大级联链

v2.0.0 的核心缺陷是一条 **事件放大级联链**，由三个独立缺陷叠加而成：

1. **ETW EventId 11 + 17 双重计数**：一次文件删除同时产生 NameDelete (EventId 11) 和 SetDelete (EventId 17) 两条 ETW 事件，均映射为 `FILE_DELETE`，导致删除计数翻倍
2. **IPC A→B→A 乒乓回弹**：GuardianB 收到非主控事件后将其转回 GuardianA，造成每条 ETW 事件被 GuardianA 处理两次
3. **叠加放大**：上述两项缺陷叠加后，实际事件数被放大 2~4 倍，使得 Tier-1 阈值（5 次删除）仅需 2 次真实删除即可触发

这条级联链的末端效应是：
- ALERT 倒计时的 30 秒内 `m_protocolActive=false`，所有文件事件继续被处理为 LEVEL_3 + TERMINATE
- `explorer.exe` 在保护目录生成 `desktop.ini` 时被终止，导致桌面/任务栏消失
- ~~FileLocker ACL 问题~~ （v3.0 已移除 FileLocker，不再存在此问题）

### 9.2 修复清单

| # | 修复项 | 影响范围 | 说明 |
|---|--------|---------|------|
| 1 | IPC 乒乓消除 | GuardianB | 非主控节点收到事件后直接丢弃，不再回传 |
| 2 | EventId 11 不再映射为 FILE_DELETE | GuardianA | EventId 11 仅清除缓存，不计入删除计数 |
| 3 | 进程事件降级 | GuardianA/B | PROC_TERMINATE/DRIVER_LOAD/UNLOAD → LEVEL_0/LOG |
| 4 | ~~FileLocker ACL 恢复~~ | — | v3.0 已移除 FileLocker，由加密替代 |
| 5 | 倒计时暂停事件处理 | GuardianA/B | 进入 ALERT 即设置 `m_protocolActive=true` |
| 6 | 扩展终止保护名单 | GuardianA/B | 新增 explorer.exe/dwm.exe 等 11 个系统进程 + desktop.ini/Thumbs.db 硬过滤 |
| 7 | 精准终止 | GuardianA | Tier-2 仅终止事件贡献最多的 PID，非批量 kill |
| 8 | 文件类型过滤诊断 | 公共模块 | 启动时输出 exclude/include 列表内容，便于排查 YAML 加载问题 |
| 9 | UWP 白名单回退 | GuardianA/B | ETW 路径提取失败时自动 QueryFullProcessImageNameW |
| 10 | 事件队列上限 | GuardianA/B | 队列上限 10000，溢出丢弃最旧事件 |
| 11 | IPC DRIVER_EVENT 去重 | GuardianA | IPC 通道复用 ETW 去重逻辑 |
| 12 | PID ≤ 4 跳过 | GuardianA/B | System/System Idle Process 的事件不再处理 |

### 9.3 升级指引

1. 使用新版 MSI 安装包覆盖安装（自动替换可执行文件和服务注册）
2. 如需更新配置：将新版 `guardian_config.yaml`（版本号已更新为 2.1.0）放入 `C:\ProgramData\GuardianShield\config\` 后重启服务
3. 白名单中的 UWP 应用无需特殊配置，只需填写标准 `.exe` 名即可
4. 建议将 `system.log_level` 临时设为 `DEBUG`，运行 24 小时确认无误报后恢复为 `INFO`

### 9.4 已知限制

- `detection.rules` 配置节已废弃，由 `detection.event_responses` 取代（v3.0+）
- `emergency.encrypt_timeout_seconds` 和 `emergency.recovery_wait_seconds` 仍为保留字段
- `communication.*` 和 `keys.*` 配置节当前版本代码未解析，IPC 参数和加密算法为硬编码
- 文件类型过滤依赖 YAML 正确加载至 `config_cache.bin`；如过滤异常，检查日志中的启动诊断输出

---

## 10. v2.5.0 变更说明

v2.5.0 基于交互式验证测试和深层根因分析，修复了 ETW 事件采集的核心生命周期缺陷，并增强了 IPC 通知可靠性和用户体验。

### 10.1 ETW 生命周期修复（5 项）

服务重启后 ETW 事件采集线程可能因孤儿会话导致 `ProcessTrace` 永久阻塞（CPU=0），全链路事件处理停滞。

| # | 修复项 | 说明 |
|---|--------|------|
| 1 | 防御性清理 | `InitializeEtw()` 开头调用 `ShutdownEtw()`，确保旧会话和旧线程被正确清理 |
| 2 | 原子句柄 | `m_traceHandle` 改为 `std::atomic<TRACEHANDLE>`，消除跨线程竞争 |
| 3 | ETW 活性守护 | `HeartbeatThread` 监控 `m_eventsProcessed`，60 秒无新事件自动重启 ETW |
| 4 | 自动恢复 | `EtwCollectionThread` 改为循环结构，`ProcessTrace` 返回后自动重试 |
| 5 | IPC 超时优化 | `SendToNode` 的 `tryConnect` 从 3x1000ms 降至 1x300ms，减少回调阻塞 |

### 10.2 IPC 通知可靠性修复

| # | 修复项 | 说明 |
|---|--------|------|
| 1 | SendToNode 线程安全 | `m_sendMutex` 保护 `m_pipeClients` 并发访问 |
| 2 | 诊断日志 | 通知发送成功/失败均有明确日志记录 |
| 3 | 音效回退 | IPC 通知失败时使用 `MessageBeep` 提供听觉反馈 |

### 10.3 用户体验增强

| # | 新增功能 | 说明 |
|---|---------|------|
| 1 | 托盘退出隐藏 | 右键菜单不再显示退出按钮，防止用户误退出 GuardianC |
| 2 | 文件管理面板 | 托盘右键 → 文件管理，ListView 展示保护目录中的 `.gs` 加密文件 |
| 3 | 一键解锁 | 输入管理员密码后批量解密 `.gs` 文件并恢复 ACL，通过 IPC 路由到主控节点执行 |

### 10.4 升级指引

1. 使用新版 MSI 安装包覆盖安装
2. 如需更新配置：将 `guardian_config.yaml`（版本号 2.5.0）放入 `C:\ProgramData\GuardianShield\config\` 后重启服务
3. 建议升级后将 `system.log_level` 临时设为 `DEBUG`，运行 24 小时确认 ETW 事件正常采集后恢复为 `INFO`

---

## 11. 附录

### 11.1 SHA-256 哈希生成方法

**方法一：PowerShell（推荐）**

```powershell
[System.BitConverter]::ToString(
  [System.Security.Cryptography.SHA256]::Create().ComputeHash(
    [System.Text.Encoding]::UTF8.GetBytes('你的密码')
  )
).Replace('-','').ToLower()
```

**方法二：PowerShell 简洁版**

```powershell
$bytes = [System.Text.Encoding]::UTF8.GetBytes('你的密码')
$hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
-join ($hash | ForEach-Object { $_.ToString('x2') })
```

**方法三：certutil（Windows 自带）**

```cmd
echo|set /p="你的密码" > temp_pwd.txt
certutil -hashfile temp_pwd.txt SHA256
del temp_pwd.txt
```

> 注意 certutil 方法可能因文件末尾换行符导致结果不同，建议使用 PowerShell 方法。

### 11.2 默认路径一览表

| 用途 | 路径 |
|------|------|
| 安装目录 | `C:\Program Files\GuardianShield\` |
| 运行时数据目录 | `C:\ProgramData\GuardianShield\` |
| 配置目录 | `C:\ProgramData\GuardianShield\config\` |
| 二进制配置缓存 | `C:\ProgramData\GuardianShield\config_cache.bin` |
| 日志目录 | `C:\ProgramData\GuardianShield\logs\` |
| 系统日志 | `C:\ProgramData\GuardianShield\logs\guardian_YYYY-MM-DD.json` |
| 监控日志 | `C:\ProgramData\GuardianShield\logs\monitor_YYYY-MM-DD.json` |
| 卸载脚本 | `scripts\uninstall.bat`（项目目录）或 `C:\Program Files\GuardianShield\scripts\uninstall.bat` |
| 注册表自启动 | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsMonitor` |
| 服务注册 - A | `HKLM\SYSTEM\CurrentControlSet\Services\WinDefenderCore` |
| 服务注册 - B | `HKLM\SYSTEM\CurrentControlSet\Services\WinDefenderHelper` |

### 11.3 guardian_config.yaml 完整字段参考

| 字段路径 | 类型 | 默认值 | 说明 |
|---------|------|--------|------|
| **系统基础** | | | |
| `system.version` | string | "3.3.0" | 配置版本号（语义化版本） |
| `system.config_version` | int | 1 | 配置递增版本号，每次修改应递增 |
| `system.log_level` | string | "INFO" | 日志级别：DEBUG / INFO / WARN / ERROR |
| `system.log_path` | string | "C:\ProgramData\GuardianShield\logs" | 日志存储目录 |
| **检测规则** | | | |
| **检测阈值** | | | |
| `detection.alert_timeout_seconds` | int | 300 | ALERT 阶段等待管理员取消的超时时间（秒），YAML 默认 300 |
| `detection.thresholds.tier1.file_write_count` | int | 10 | Tier 1 批量文件写入数阈值 |
| `detection.thresholds.tier1.file_write_window_seconds` | int | 5 | Tier 1 文件写入检测时间窗口（秒） |
| `detection.thresholds.tier1.file_delete_count` | int | 5 | Tier 1 批量文件删除数阈值 |
| `detection.thresholds.tier1.file_compress_count` | int | 50 | Tier 1 批量压缩文件数阈值 |
| `detection.thresholds.tier2.file_write_count` | int | 50 | Tier 2 批量文件写入数阈值 |
| `detection.thresholds.tier2.file_delete_count` | int | 20 | Tier 2 批量文件删除数阈值 |
| `detection.thresholds.tier2.file_compress_count` | int | 250 | Tier 2 批量压缩文件数阈值 |
| **保护目录** | | | |
| `protection.directories[].path` | string | — | 保护目录绝对路径 |
| `protection.directories[].recursive` | bool | true | 是否递归保护子目录 |
| `protection.directories[].priority` | string | "HIGH" | 优先级：HIGH / MEDIUM / LOW |
| `protection.file_types.include` | list | — | 保护的文件扩展名（如 `*.cpp`） |
| `protection.file_types.exclude` | list | — | 排除的文件扩展名（如 `*.log`） |
| **环境授权** | | | |
| `authorization.list_path` | string | "C:\ProgramData\GuardianShield\config\auth.list" | auth.list 路径 |
| `authorization.check_on_boot` | bool | true | 启动时是否校验环境 |
| `authorization.strict_mode` | bool | true | 严格模式：未授权直接触发紧急协议 |
| **日志** | | | |
| `logging.path` | string | "C:\ProgramData\GuardianShield\logs" | 日志目录 |
| `logging.format` | string | "json" | 日志格式：json / text |
| `logging.retention_days` | int | 7 | 日志保留天数 |
| `logging.daily_rotation` | bool | true | 是否按天轮转 |
| **管理员** | | | |
| `admin.password_hash` | string | "" | 管理员密码的 SHA-256 哈希（锁屏解锁用） |
| `admin.install_key_hash` | string | "" | 安装/卸载密钥的 SHA-256 哈希 |
| `admin.unlock_timeout_seconds` | int | 30 | 解锁等待超时时间（秒） |
| **白名单** | | | |
| `whitelist.processes[].name` | string | — | 进程可执行文件名 |
| `whitelist.processes[].description` | string | — | 进程描述（仅注释） |
| `whitelist.processes[].permissions` | list | — | 允许操作：READ / WRITE |
| `whitelist.processes[].conditions` | list | — | 附加条件（如限定用户组） |
| **紧急协议** | | | |
| `emergency.encrypt_timeout_seconds` | int | 30 | 触发后等待时间（秒） |
| `emergency.recovery_wait_seconds` | int | 30 | 加密后恢复等待时间（秒） |
| `emergency.wipe_method` | string | "DOD_5220" | 擦除标准：DOD_5220 / GUTMANN / SIMPLE |
| `emergency.notifications[].type` | string | — | 通知类型：EMAIL / WEBHOOK |
| `emergency.notifications[].recipients` | list | — | 邮件接收地址列表 |
| `emergency.notifications[].url` | string | — | Webhook 回调地址 |
| **通信** | | | |
| `communication.named_pipe.enabled` | bool | true | 命名管道通信 |
| `communication.named_pipe.timeout_ms` | int | 5000 | 管道超时（ms） |
| `communication.shared_memory.enabled` | bool | true | 共享内存通信 |
| `communication.shared_memory.size_kb` | int | 4 | 共享内存大小（KB） |
| `communication.tcp.enabled` | bool | true | TCP 通信 |
| `communication.tcp.port_base` | int | 17500 | TCP 端口基址 |
| `communication.tcp.tls` | bool | false | TLS 加密（**当前版本未实现**，代码强制明文） |
| **密钥** | | | |
| `keys.tpm.enabled` | bool | true | 是否启用 TPM |
| `keys.tpm.pcr_indices` | list | [0-7] | TPM PCR 索引 |
| `keys.encryption.algorithm` | string | "AES-256-GCM" | 加密算法 |
| `keys.encryption.key_rotation_days` | int | 30 | 密钥轮换周期（天） |

---

*GuardianShield v3.3.0 — 企业级源代码防泄漏系统*
