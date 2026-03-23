# GuardianShield - 源代码防护系统

企业级源代码防泄漏系统，采用五层纵深防御架构 + 进程守护三角 + 内核级文件系统监控。

---

## 目录

- [项目状态](#项目状态)
- [系统架构](#系统架构)
- [快速开始](#快速开始)
- [环境要求](#环境要求)
- [构建指南](#构建指南)
- [一键运行脚本](#一键运行脚本)
- [部署指南](#部署指南)
- [配置说明](#配置说明)
- [使用手册](#使用手册)
- [测试指南](#测试指南)
- [项目结构](#项目结构)
- [安全特性](#安全特性)
- [故障排除](#故障排除)
- [卸载方法](#卸载方法)

---

## 项目状态

**版本: 3.3.0** | **构建状态: Release 通过** | **日期: 2026-03-18**

| 模块 | 状态 | 产物 | 说明 |
|------|------|------|------|
| Common 共享库 | 已完成 | GuardianCommon.lib | 14 模块: common_types, config, logger, ipc, windows_service, file_locker, file_encryptor, file_wiper, security, environment_validator, notification_manager, driver_client |
| GuardianA 主控服务 | 已完成 | svchost_core.exe (248 KB) | 威胁评估、紧急协议、批量检测、心跳、IPC、CLI 管理 |
| GuardianB 备控服务 | 已完成 | svchost_helper.exe (251 KB) | 心跳监控、故障接管/退回、事件转发、紧急协议 |
| GuardianC 用户监控 | 已完成 | winmon.exe (158 KB) | ETW 事件收集、心跳监控、全屏锁屏窗口、系统托盘状态、注册表自启 |
| GuardFilter.sys | 骨架完成 | 需 WDK 编译 | minifilter 文件系统回调、通信端口、事件缓冲区 |
| GuardMonitor.sys | 骨架完成 | 需 WDK 编译 | 进程/映像通知、ObRegisterCallbacks 进程保护、DeviceIoControl |
| guardian_ca.dll | 已完成 | guardian_ca.dll (24 KB) | WiX MSI 自定义动作：安装密钥验证、配置文件复制 |
| MSI 安装包 | 已完成 | WiX 源文件 | 统一安装包：密钥验证 + 配置文件选择 + 服务注册 |
| 一键卸载脚本 | 已完成 | uninstall.bat | 密钥验证 + 服务停止/删除 + 注册表/文件清理 |
| 测试套件 | 已完成 | GuardianTests.exe | 12 文件, ~167 用例, Google Test 框架 |

---

## 系统架构

### 五层纵深防御

```
Layer 0: 数据原生加密（源码场景不适用）
Layer 1: 物理隔离层 — IP/MAC 地址绑定验证
Layer 2: 内核级监控 — GuardFilter.sys + GuardMonitor.sys
Layer 3: 进程守护三角 — GuardianA + GuardianB + GuardianC
Layer 4: 紧急熔断机制 — 加密 → 擦除 → 锁定
```

### 进程守护三角

```
          GuardianA (主控服务, SYSTEM)
           ╱        ╲
     心跳/命令    心跳/警报
         ╱            ╲
  GuardianB ◄────────► GuardianC
  (备控服务, SYSTEM)    (用户监控程序)
```

| 节点 | 运行环境 | 核心职责 |
|------|---------|---------|
| GuardianA | Windows 服务 (SYSTEM) | 威胁评估、紧急协议触发、内核驱动通信、决策中枢 |
| GuardianB | Windows 服务 (SYSTEM) | 监控 A 的健康状态，故障时自动接管主控角色，A 恢复后自动退回 |
| GuardianC | 用户态程序 | ETW 事件收集、全屏锁屏窗口（密码解锁）、心跳监控、注册表自启 |

### 三层响应架构

```
单事件 → LOG / ALERT / BLOCK / TERMINATE / ENCRYPT（绝不执行破坏性操作）

保护协议 (Tier 1): NORMAL → ALERT → ENCRYPTING → LOCKED（可恢复）
紧急协议 (Tier 2): NORMAL → ALERT → ENCRYPTING → WIPING → DELETING → LOCKED（不可逆）
未授权设备:         NORMAL → ENCRYPTING → WIPING → DELETING → LOCKED（跳过 ALERT）

ALERT 阶段管理员可取消 → 恢复 NORMAL
LOCKED 阶段管理员输入密码 → 恢复 NORMAL
```

---

## 快速开始

### 方式一：MSI 安装包（推荐）

运行 MSI 安装包，按向导操作：输入安装密钥 → 选择 `auth.list` 和 `guardian_config.yaml` → 确认安装。安装完成后服务自动启动。

### 方式二：run.bat 一键部署

```
步骤 1. 双击 run.bat（右键 → 以管理员身份运行）
步骤 2. 输入 1 回车
步骤 3. 等待自动完成：构建 → 安装服务 → 启动
```

### 方式三：手动部署

```cmd
build.bat                            :: 步骤 1: 编译
svchost_core.exe -install -key 密码  :: 步骤 2: 安装 (管理员, 需密钥)
svchost_core.exe -start              :: 步骤 3: 启动 (管理员)
```

> 详细操作步骤请参阅 `docs/ADMIN_MANUAL.md` 管理员操作手册。

---

## 环境要求

### 开发/编译环境（必需）

| 工具 | 版本要求 | 说明 |
|------|----------|------|
| Visual Studio 2022 | Community / Professional / Enterprise | 含 C++ 桌面开发工作负载 |
| Windows SDK | 10.0.19041.0 或更高 | VS2022 安装时勾选 |
| CMake | 3.20+ | VS2022 自带，无需单独安装 |
| Git | 任意版本 | 用于下载 Google Test 依赖 |

### 内核驱动开发（可选）

| 工具 | 说明 |
|------|------|
| Windows Driver Kit (WDK) 11 | 编译 .sys 驱动所需 |
| 测试签名证书 | 驱动加载需要签名 |
| 测试模式 Windows | `bcdedit /set testsigning on` |

### 运行环境

| 要求 | 说明 |
|------|------|
| Windows 10/11 (x64) | 目标操作系统 |
| 管理员权限 | 安装/启动 Windows 服务需要 |

---

## 构建指南

### 方法一：使用 run.bat（推荐）

右键 `run.bat` → 以管理员身份运行 → 选择 `[2] Build Only`。

### 方法二：使用 build.bat

双击 `build.bat`，脚本会自动检测 VS 环境、配置 CMake、编译 Release 版本。

### 方法三：手动 CMake 构建

```powershell
cd C:\Users\lb\Desktop\GuardianShield
mkdir build && cd build

# 配置（不含驱动）
cmake -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTS=OFF ..

# 编译 Release
cmake --build . --config Release

# 编译 Debug（含调试信息）
cmake --build . --config Debug
```

### 方法四：含内核驱动构建（需 WDK）

```powershell
cmake -G "Visual Studio 17 2022" -A x64 -DBUILD_DRIVERS=ON ..
cmake --build . --config Release
```

### 构建选项

| CMake 选项 | 默认值 | 说明 |
|-----------|--------|------|
| `BUILD_DRIVERS` | OFF | 编译内核驱动（需 WDK） |
| `BUILD_TESTS` | ON | 编译测试套件 |
| `BUILD_TOOLS` | ON | 编译工具程序 |
| `ENABLE_DEBUG_OUTPUT` | ON | 启用调试输出 |

### 构建产物

```
build/src/service/common/Release/GuardianCommon.lib          — 共享静态库
build/src/service/GuardianA/Release/svchost_core.exe         — 主控服务 (伪装名)
build/src/service/GuardianB/Release/svchost_helper.exe       — 备控服务 (伪装名)
build/src/service/GuardianC/Release/winmon.exe               — 用户监控 (伪装名)
build/bin/Release/guardian_ca.dll                             — WiX 安装自定义动作 DLL
build/test/Release/GuardianTests.exe                         — 测试程序
```

### 生成 MSI 安装包

默认构建**不会**生成 MSI 安装程序。需要单独执行以下任一方式生成 `GuardianShield.msi`：

- **run.bat**：选择 `[9] Build MSI Installer`（需已安装 WiX Toolset 3.x）
- **命令行**：在项目根目录执行 `build_msi.bat`

**前置条件**：已先完成一次普通构建（run.bat [2] 或 build.bat），且本机已安装 [WiX Toolset v3.14](https://github.com/wixtoolset/wix3/releases)（默认路径：`C:\Program Files (x86)\WiX Toolset v3.14\bin`）。

**产物路径**：`build\bin\Release\GuardianShield.msi`

---

## 一键运行脚本

项目根目录提供 `run.bat` 交互式控制面板，涵盖全部生命周期操作：

```
============================================================
      GuardianShield Control Panel  v1.0.0
============================================================

  [1]  One-Click Build + Install + Start  (Full Deploy)
  [2]  Build Only
  [3]  Install Services  (requires Admin)
  [4]  Start Services    (requires Admin)
  [5]  Stop Services     (requires Admin)
  [6]  Check Status
  [7]  Uninstall All     (requires Admin)
  [8]  Clean Build
  [9]  Build MSI Installer  (requires WiX 3.x)
  [0]  Exit

============================================================
```

| 选项 | 功能 | 需要管理员 |
|------|------|-----------|
| **[1] Full Deploy** | 自动完成 构建→安装→启动 全流程 | 是 |
| [2] Build Only | 仅编译 Release 版本 | 否 |
| [3] Install | 注册 A/B 为 Windows 服务，C 加入注册表自启 | 是 |
| [4] Start | 启动三个 Guardian 节点 | 是 |
| [5] Stop | 停止三个 Guardian 节点 | 是 |
| [6] Status | 显示各服务当前运行状态 | 否 |
| [7] Uninstall | 停止并卸载所有服务和自启 | 是 |
| [8] Clean | 删除 build 目录，下次从头编译 | 否 |
| [9] Build MSI | 生成 MSI 安装包（需 WiX 3.x） | 否 |

**使用方式：** 右键 `run.bat` → "以管理员身份运行"。

---

## 部署指南

### 第一步：构建

双击 `run.bat` 选择 [2] 或直接运行 `build.bat`。

### 第二步：复制文件

将以下文件复制到目标机器的安装目录（例如 `C:\Program Files\GuardianShield\`）：

```
svchost_core.exe     （主控服务 GuardianA）
svchost_helper.exe   （备控服务 GuardianB）
winmon.exe           （用户监控 GuardianC）
config\              （整个配置文件夹）
```

### 第三步：修改配置

编辑 `config\guardian_config.yaml`（详细注释见文件内部）：

```yaml
system:
  log_level: "INFO"
  log_path: "C:\\ProgramData\\GuardianShield\\logs"

protection:
  directories:
    - path: "C:\\Users\\lb\\Documents\\GUARD_Test"
      recursive: true
      priority: HIGH

emergency:
  encrypt_timeout_seconds: 30
  wipe_method: "DOD_5220"
```

编辑 `config\auth.list`，设置授权机器：

```
# 格式: IP地址,MAC地址,备注
192.168.1.100,AA:BB:CC:DD:EE:FF,张三工位
192.168.1.101,11:22:33:44:55:66,李四工位
```

> **配置"钥匙"机制**：服务读取 `guardian_config.yaml` 后会自动删除该文件，仅保留受 ACL 保护的二进制缓存。管理员更新策略时，将新的 YAML 文件放入配置目录，重启服务即可生效。

### 第四步：安装并启动

以管理员身份运行：

```cmd
:: 安装并启动全部（推荐用 run.bat 选项 [1]）
svchost_core.exe -install -key 密码 && svchost_core.exe -start
svchost_helper.exe -install -key 密码 && svchost_helper.exe -start
winmon.exe --install -key 密码
start winmon.exe --silent
```

### 第五步：安装内核驱动（可选）

```cmd
:: 开启测试签名（需重启）
bcdedit /set testsigning on

:: 安装驱动
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 GuardFilter.inf
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 GuardMonitor.inf

:: 启动驱动
sc start GuardFilter
sc start GuardMonitor
```

---

## 配置说明

### 配置文件结构

```
config/
  guardian_config.yaml   — 唯一策略配置文件（"钥匙"，读取后自动删除）
  auth.list              — IP/MAC 授权清单
```

运行时缓存（位于 `C:\ProgramData\GuardianShield\`）：

```
config_cache.bin         — 二进制策略缓存（ACL 保护，仅 SYSTEM + Admin 可读）
```

### guardian_config.yaml 关键字段

| 字段路径 | 类型 | 默认值 | 说明 |
|---------|------|--------|------|
| `system.version` | string | "3.3.0" | 配置版本号 |
| `system.log_level` | string | "INFO" | 日志级别: DEBUG/INFO/WARN/ERROR |
| `system.log_path` | string | — | 日志文件存储路径 |
| `detection.alert_timeout_seconds` | int | 30 | ALERT 阶段等待管理员取消的超时时间（秒） |
| `detection.thresholds.tier1.file_write_count` | int | 10 | Tier 1 批量文件写入数阈值 |
| `detection.thresholds.tier1.file_delete_count` | int | 5 | Tier 1 批量文件删除数阈值 |
| `detection.thresholds.tier2.file_write_count` | int | 50 | Tier 2 批量文件写入数阈值 |
| `detection.thresholds.tier2.file_delete_count` | int | 20 | Tier 2 批量文件删除数阈值 |
| `protection.directories[].path` | string | — | 保护目录路径 |
| `protection.directories[].recursive` | bool | true | 是否递归保护子目录 |
| `protection.directories[].priority` | string | "HIGH" | 优先级: HIGH/MEDIUM/LOW |
| `protection.file_types.include` | list | — | 保护的文件扩展名 |
| `whitelist.processes[].name` | string | — | 白名单进程名 |
| `whitelist.processes[].permissions` | list | — | 允许的操作: READ/WRITE |
| `emergency.encrypt_timeout_seconds` | int | 30 | 紧急加密等待时间（秒） |
| `emergency.wipe_method` | string | "DOD_5220" | 擦除标准 |
| `admin.password_hash` | string | "" | 管理员密码 SHA-256 哈希 |
| `authorization.strict_mode` | bool | true | 未授权设备触发紧急协议 |

> 完整字段说明请参阅 `config/guardian_config.yaml` 内的详细中文注释，或 `docs/FUNCTIONAL_SPEC.md`。

---

## 使用手册

### 服务管理命令

#### GuardianA / GuardianB（Windows 服务）

```
svchost_core.exe -install -key 密码      安装为 Windows 服务（自动启动，需密钥）
svchost_core.exe -uninstall -key 密码    卸载服务（需密钥）
svchost_core.exe -start                  启动服务
svchost_core.exe -stop                   停止服务
svchost_core.exe -status                 查看服务状态
svchost_core.exe -help                   显示帮助信息
```

GuardianB 命令参数完全相同，将 `svchost_core` 替换为 `svchost_helper` 即可。

#### GuardianC（用户程序）

```
winmon.exe               直接运行（前台）
winmon.exe --silent      静默运行（后台，有系统托盘图标）
winmon.exe --install     添加到注册表自启动（当前用户，需密钥）
winmon.exe --uninstall   从注册表移除自启动（需密钥）
winmon.exe --status      查看自启动状态
winmon.exe --help        显示帮助信息
```

#### run.bat 控制面板

```
run.bat                     双击启动交互式控制面板
                            选项 [1] = 一键 构建+安装+启动
                            选项 [6] = 查看全部服务状态
```

### 系统托盘操作（GuardianC）

GuardianC 运行后会在系统托盘显示图标：

| 图标颜色 | 含义 |
|---------|------|
| 绿色 | 系统正常运行 |
| 黄色 | 检测到可疑活动 |
| 红色 | 紧急模式已触发 |

右键托盘图标菜单：
- **查看状态** — 显示 GuardianA/B 连接状态和当前威胁级别
- **查看日志** — 打开日志文件目录
- **退出** — 退出程序（需确认）

### 单事件威胁等级

| 等级 | 名称 | 触发条件示例 | 响应动作 |
|------|------|------------|---------|
| LEVEL_0 | Normal | 文件创建、读取 | LOG |
| LEVEL_1 | Suspicious | 文件修改、网络连接 | LOG + ALERT_USER |
| LEVEL_2 | Dangerous | 文件重命名/移动、进程注入、调试器附加 | LOG + ALERT_USER + BLOCK / TERMINATE / ENCRYPT |

**关键原则**: 单事件绝不执行 WIPE / LOCKDOWN。BLOCK 为内核级 I/O 拦截（需 GuardFilter 驱动），驱动未加载时跳过（不降级为 TERMINATE）。

### 批量操作检测（两级阈值）

| 超过阈值 | 触发协议 | 响应 | 可恢复性 |
|----------|----------|------|----------|
| tier1 | 保护协议 | ALERT → ENCRYPT → LOCK | 可恢复 |
| tier2 | 紧急协议 | ALERT → ENCRYPT → WIPE → DELETE → LOCK | 不可逆 |
| 未授权设备 | 紧急协议 | ENCRYPT → WIPE → DELETE → LOCK（跳过 ALERT） | 不可逆 |

### 紧急协议流程

| 阶段 | 操作 | 说明 |
|------|------|------|
| 1. ALERT | IPC 告警 + 倒计时 | 通知 GuardianC 弹出桌面告警，等待管理员取消 |
| 2. ENCRYPTING | AES-256-CBC 加密 | 保护目录文件加密为 `.gs` 格式 |
| 3. WIPING | DOD 5220.22-M 擦除 | 7 次覆写原始文件（仅 Tier 2） |
| 4. DELETING | 清理系统痕迹 | 清除临时文件、剪贴板、最近文档列表（仅 Tier 2） |
| 5. LOCKED | 锁定系统 | GuardianC 弹出全屏锁屏窗口，管理员输入密码解锁 |

### 故障转移机制

```
GuardianB 每 500ms 发送心跳 → GuardianA 响应
    │
    ├─ 正常响应 → 继续备控角色
    │
    └─ 连续 3 次超时 (1.5s) → 自动接管主控
                                    │
                                    └─ GuardianA 恢复 → 自动退回备控
```

整个切换过程对用户透明，不影响保护功能。

---

## 测试指南

### 运行全部测试

```powershell
cd build
cmake --build . --config Release --target GuardianTests
.\test\Release\GuardianTests.exe
```

### 运行特定测试

```powershell
.\test\Release\GuardianTests.exe --gtest_filter="FileLockerTest.*"
.\test\Release\GuardianTests.exe --gtest_filter="*Emergency*"
.\test\Release\GuardianTests.exe --gtest_filter="*Encrypt*"
```

### 测试覆盖

| 测试文件 | 覆盖模块 | 用例数 |
|---------|----------|-------|
| test_common.cpp | MessageHeader, HeartbeatPayload, 常量, 枚举 | ~15 |
| test_driver_client.cpp | DriverClient 连接、断开、IOCTL 方法 | ~17 |
| test_file_locker.cpp | 独占锁定、多文件、线程安全 | ~14 |
| test_file_encryptor.cpp | AES-256 加解密、格式验证、错误密码 | ~13 |
| test_file_wiper.cpp | DOD 5220 覆写、目录擦除、进度回调 | ~13 |
| test_ipc.cpp | Named Pipe、Shared Memory、消息序列化 | ~12 |
| test_threat_evaluator.cpp | 威胁分级、批量检测、响应动作 | ~20 |
| test_event_response_config.cpp | BLOCK 解析、威胁等级映射、降级逻辑、缓存持久化 | ~31 |
| test_emergency.cpp | 状态机推进、取消、线程安全 | ~15 |
| test_file_monitor.cpp | DriverEvent、组件集成 | ~7 |
| test_system_logger.cpp | Logger 公共 API、日志写入 | ~5 |
| test_monitor_logger.cpp | Logger 事件记录 | ~5 |

---

## 项目结构

```
GuardianShield/
├── src/
│   ├── driver/                           # 内核驱动
│   │   ├── shared/
│   │   │   └── guardian_ioctl.h          # 内核/用户共享 IOCTL + 结构体
│   │   ├── GuardFilter/                  # 文件系统微过滤驱动
│   │   │   ├── include/guard_filter.h
│   │   │   ├── src/
│   │   │   │   ├── guard_filter.c       # DriverEntry, Unload, InstanceSetup
│   │   │   │   ├── filter_callbacks.c   # PreCreate/Write/SetInfo/Cleanup
│   │   │   │   └── communication.c      # 通信端口消息处理
│   │   │   ├── GuardFilter.inf
│   │   │   └── CMakeLists.txt
│   │   └── GuardMonitor/                 # 进程监控驱动
│   │       ├── include/guard_monitor.h
│   │       ├── src/
│   │       │   ├── guard_monitor.c      # DriverEntry, 设备对象
│   │       │   ├── process_notify.c     # 进程创建/终止回调
│   │       │   ├── image_notify.c       # DLL/驱动加载回调
│   │       │   └── communication.c      # DeviceIoControl 分发
│   │       ├── GuardMonitor.inf
│   │       └── CMakeLists.txt
│   └── service/                          # 用户态服务
│       ├── common/                       # 共享库 (14 模块)
│       │   ├── include/                  # 公共头文件
│       │   │   ├── common_types.h       # 枚举、消息结构、配置结构
│       │   │   ├── config.h             # YAML 配置管理
│       │   │   ├── logger.h             # 线程安全日志
│       │   │   ├── ipc.h               # Named Pipe + Shared Memory
│       │   │   ├── windows_service.h    # 服务基类 + 安装器
│       │   │   ├── file_locker.h        # 文件独占锁定
│       │   │   ├── file_encryptor.h     # AES-256-CBC 加密
│       │   │   ├── file_wiper.h         # DOD 5220 安全擦除
│       │   │   ├── driver_client.h      # 内核驱动通信客户端
│       │   │   ├── environment_validator.h  # IP/MAC 环境校验
│       │   │   ├── notification_manager.h   # 通知管理
│       │   │   └── security.h           # 安全工具
│       │   ├── src/                      # 对应实现文件
│       │   └── CMakeLists.txt
│       ├── GuardianA/                    # 主控服务
│       │   ├── include/
│       │   │   ├── guardian_a.h
│       │   │   └── threat_evaluator.h
│       │   ├── src/
│       │   └── CMakeLists.txt
│       ├── GuardianB/                    # 备控服务
│       │   ├── include/guardian_b.h
│       │   ├── src/
│       │   └── CMakeLists.txt
│       └── GuardianC/                    # 用户监控程序
│           ├── include/guardian_c.h
│           ├── src/
│           └── CMakeLists.txt
├── src/installer/                        # MSI 安装包
│   ├── GuardianShield.wxs               # WiX 主安装定义
│   ├── InstallDlg.wxs                   # 自定义安装界面
│   ├── guardian_ca/                      # WiX 自定义动作 DLL
│   │   ├── guardian_ca.cpp              # 密钥验证 + 配置文件复制
│   │   ├── guardian_ca.def
│   │   └── CMakeLists.txt
│   └── CMakeLists.txt
├── scripts/                              # 部署与管理脚本
│   └── uninstall.bat                    # 一键卸载脚本
├── test/                                 # 测试套件 (12 文件)
│   ├── test_common.cpp
│   ├── test_driver_client.cpp
│   ├── test_file_locker.cpp
│   ├── test_file_encryptor.cpp
│   ├── test_file_wiper.cpp
│   ├── test_file_monitor.cpp
│   ├── test_ipc.cpp
│   ├── test_threat_evaluator.cpp
│   ├── test_event_response_config.cpp  # BLOCK 响应动作测试
│   ├── test_emergency.cpp
│   ├── test_system_logger.cpp
│   ├── test_monitor_logger.cpp
│   └── CMakeLists.txt
├── config/                               # 配置文件模板
│   ├── guardian_config.yaml             # 唯一策略配置（"钥匙"）
│   └── auth.list                        # IP/MAC 授权清单
├── docs/                                 # 设计与功能文档
│   ├── ADMIN_MANUAL.md                  # 管理员操作手册
│   ├── FUNCTIONAL_SPEC.md               # 功能说明书（需求对照）
│   ├── PROTECTION_SPEC.md
│   └── PROtection_system_design.md
├── run.bat                               # 一键运行控制面板
├── build.bat                             # 构建脚本
├── CMakeLists.txt                        # CMake 根配置
└── README.md                             # 本文件
```

---

## 安全特性

| 特性 | 技术实现 | 说明 |
|------|---------|------|
| 文件加密 | AES-256-CBC, Windows CNG BCrypt | SHA-256(password+salt) 密钥派生 |
| 加密格式 | `GSENCR01` + 16B salt + 16B IV + ciphertext | 自定义二进制格式 |
| 安全擦除 | DOD 5220.22-M, 7 次覆写 | BCryptGenRandom 随机源 + FILE_FLAG_WRITE_THROUGH |
| 文件锁定 | CreateFileW 独占模式 | dwShareMode=0, 线程安全管理 |
| 全屏锁屏窗口 | WS_EX_TOPMOST + WS_POPUP + 定时器置顶 | 覆盖全部显示器，无关闭按钮，密码输入解锁 |
| 三重 IPC | Named Pipe + Shared Memory + TCP Loopback | 任一通道断开不影响其余 |
| IPC 消息完整性 | HMAC-SHA256 校验 (12 字节截断) | 防止 IPC 消息篡改 |
| 心跳监控 | 500ms 间隔, 3 次超时 | 1.5 秒内完成故障转移 |
| 环境绑定 | IP/MAC 白名单 | auth.list 读后自动删除，数据纳入二进制缓存 |
| 内核级文件拦截 | GuardFilter.sys minifilter BLOCK 策略 | IRP_MJ_SET_INFORMATION 拦截文件重命名/移动，返回 STATUS_ACCESS_DENIED |
| 内核进程保护 | ObRegisterCallbacks | 阻止外部进程终止 Guardian 服务（需 WDK） |
| 服务恢复 | 自动重启策略 | 5s → 30s → 60s 递增延迟 |
| 统一安装密钥 | YAML admin.install_key_hash | 管理员可在配置文件中统一管理，无需重新编译 |
| MSI 安装包 | WiX + guardian_ca.dll | 密钥验证 + 配置文件选择 + 服务自动注册 |

---

## 故障排除

### 常见问题

**Q: 服务安装失败，提示"拒绝访问"**
A: 以管理员身份运行。右键 `run.bat` → "以管理员身份运行" → 选择 [3]。

**Q: GuardianC 是否有托盘图标？**
A: 是。GuardianC（winmon.exe）运行后会在系统托盘显示图标，用于查看状态和右键菜单（查看状态、查看日志、退出）。在任务管理器中也可确认 `winmon.exe` 进程是否运行。

**Q: 系统被锁定（出现全屏锁定窗口），如何解锁？**
A: 在锁定窗口的密码输入框中输入管理员密码（`admin.password_hash` 对应的原文密码），点击"解锁"按钮。忘记密码时：
1. 安全模式启动 Windows
2. 停止服务：`sc stop WinDefenderCore` `sc stop WinDefenderHelper`
3. 终止进程：`taskkill /f /im winmon.exe`
4. 删除缓存 `C:\ProgramData\GuardianShield\config_cache.bin`
5. 将包含新密码哈希的 `guardian_config.yaml` 放入配置目录
6. 重启服务（YAML 会被自动读取并删除）

**Q: 构建时 Google Test 下载失败**
A: 网络问题。方案一：配置代理

```powershell
$env:HTTP_PROXY = "http://proxy:port"
$env:HTTPS_PROXY = "http://proxy:port"
```

方案二：跳过测试编译

```powershell
cmake -DBUILD_TESTS=OFF ..
```

**Q: 内核驱动无法加载**
A: 确保：(1) 开启测试签名 `bcdedit /set testsigning on` 并重启，(2) 以管理员权限安装。

**Q: 构建报 C4819 编码警告**
A: 已在 CMakeLists.txt 中添加 `/utf-8` 编译标志。如仍出现，检查 VS2022 是否为最新版本。

### 日志位置

```
C:\ProgramData\GuardianShield\logs\
  guardian_YYYY-MM-DD.json      — 系统日志（每日轮转）
  monitor_YYYY-MM-DD.json       — 监控事件日志
```

日志格式为 JSON，可用 `jq` 或任何 JSON 查看器分析。

### 查看服务状态

```cmd
:: 方法一：run.bat
run.bat  →  选择 [6]

:: 方法二：命令行
svchost_core.exe -status
svchost_helper.exe -status
winmon.exe --status

:: 方法三：Windows 服务管理器
services.msc  →  查找 WinDefenderCore / WinDefenderHelper
```

---

## 卸载方法

### 方法一：一键卸载脚本（推荐）

右键 `scripts\uninstall.bat` → 以管理员身份运行 → 输入卸载密钥 → 自动完成全部清理。

### 方法二：run.bat 控制面板

右键 `run.bat` → 以管理员身份运行 → 选择 `[7] Uninstall All` → 输入密钥。

### 方法三：MSI 卸载

通过控制面板"程序和功能"卸载，或运行 MSI 安装包选择卸载，需输入管理员密钥。

### 方法四：手动卸载

```cmd
:: 停止服务
svchost_core.exe -stop
svchost_helper.exe -stop
taskkill /f /im winmon.exe

:: 卸载服务（需密钥）
svchost_core.exe -uninstall -key 密码
svchost_helper.exe -uninstall -key 密码
winmon.exe --uninstall -key 密码

:: 删除服务注册（兜底）
sc delete WinDefenderCore
sc delete WinDefenderHelper

:: 清理注册表自启动
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v WindowsMonitor /f

:: 卸载内核驱动（如已安装）
sc stop GuardFilter && sc stop GuardMonitor
sc delete GuardFilter && sc delete GuardMonitor

:: 删除文件
rmdir /s /q "C:\Program Files\GuardianShield"
rmdir /s /q "C:\ProgramData\GuardianShield"
```

> 详细卸载操作请参阅 `docs/ADMIN_MANUAL.md` 管理员操作手册。

---

## 版本历史

### v3.3.0 (2026-03-18) — FILE_MOVE 实现 + 响应动作审计 + 文档同步

- **FILE_MOVE 跨卷移动检测**：通过 CREATE+DELETE 事件关联实现（5 秒关联窗口），YAML 默认启用 `[LOG, ALERT_USER, BLOCK]`
- **7 类型显式注释**：FILE_READ、FILE_SET_INFO、PROCESS_INJECT、PROCESS_DEBUG、NETWORK_CONNECT、NETWORK_SEND、NETWORK_RECV 标记为预留（当前版本不实装）
- **ResponseAction 全面审计**：确认 LOG/ALERT_USER/TERMINATE/ENCRYPT/BLOCK 真实实现；WIPE/LOCKDOWN 仅 Tier 2 触发
- **新增 12 个 ActionAudit 单元测试**，总计 192/192 全部通过
- **文档全面同步**：版本号统一至 3.3.0，BLOCK 行为描述修正为"驱动未加载时跳过（不降级为 TERMINATE）"

### v3.2.0 (2026-03-10) — BLOCK 响应动作

- **新增 BLOCK 内核级 I/O 拦截**：通过 GuardFilter.sys minifilter 驱动在 `IRP_MJ_SET_INFORMATION` 层面拦截文件重命名/移动操作，返回 `STATUS_ACCESS_DENIED`
- **BLOCK 策略管理**：用户态服务通过 `IOCTL_GUARDIAN_SET_BLOCK_POLICY` 向驱动下发策略位掩码（BLOCK_FLAG_RENAME / BLOCK_FLAG_DELETE / BLOCK_FLAG_WRITE）
- **驱动白名单同步**：Guardian 自身进程和 YAML 配置的白名单进程自动同步到驱动侧，防止自我拦截
- **降级保护**：BLOCK + TERMINATE 并存时自动移除 TERMINATE，避免双重惩罚；驱动未加载时 BLOCK 跳过（不降级为 TERMINATE）
- **驱动重连状态恢复**：DriverReadThread 重连后自动重发白名单 + BLOCK 策略 + 保护路径
- **5 项新增单元测试**：BLOCK 解析、LEVEL_2 映射、BLOCK+TERMINATE 降级、缓存持久化、过滤一致性

### v3.1.0 (2026-03-09) — 威胁检测架构修复

- 移除 EmergencyExecutor 死代码，紧急协议由 guardian_a.cpp 直接实现
- 修复多项威胁检测架构缺陷

### v2.5.0 (2026-03-06) — ETW 迁移与 IPC 增强

- ETW 事件采集迁移至 GuardianA（SYSTEM 服务）
- IPC 通知可靠性 v2：互斥锁 + tryConnect 优化 + MessageBeep 回退
- GuardianC 文件管理面板 + 一键解锁功能

### v2.0.0 (2026-03-02) — 基础架构完成

- 五层纵深防御 + 进程守护三角 + 内核驱动骨架
- 全屏锁屏窗口 + HMAC-SHA256 IPC + MSI 安装包

---

## 许可证

企业内部使用，保密。
