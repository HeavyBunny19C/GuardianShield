<p align="center">
  <h1 align="center">🛡️ GuardianShield</h1>
</p>

<p align="center">
  <strong>把源代码保护、事件监控和应急响应，放进一套 Windows 守护系统里。</strong>
</p>

<p align="center">
  <a href="./README.md">中文完整文档</a> · <a href="#english-overview">English</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows-0078D6?style=flat-square&logo=windows" alt="Windows" />
  <img src="https://img.shields.io/badge/C%2B%2B-17-00599C?style=flat-square&logo=cplusplus" alt="C++17" />
  <img src="https://img.shields.io/badge/CMake-%3E%3D3.20-064F8C?style=flat-square&logo=cmake" alt="CMake 3.20+" />
  <img src="https://img.shields.io/badge/version-3.3.0-orange?style=flat-square" alt="Version 3.3.0" />
</p>

## 🤔 这是什么？

你可能不想等到源码被批量改写、删除或搬走之后，才开始翻日志。

GuardianShield 监控配置的保护目录，根据文件、进程和批量操作评估风险，再按策略记录日志、发送告警、终止进程或加密文件。需要内核拦截时，可以额外编译并加载 WDK 驱动。

它不是一个把所有东西藏在后台的单进程脚本，而是由三个 Guardian 节点共同完成监控、决策和用户侧响应：

- 🧠 **GuardianA**：主控服务，负责事件采集、威胁评估、策略执行、IPC 和紧急状态机。
- 🛟 **GuardianB**：备控服务，监控 GuardianA，并在心跳超时后接管主控角色。
- 🖥️ **GuardianC**：用户态监控程序，提供通知、托盘状态、锁屏界面和用户会话集成。

## 🏗️ 工作方式

```text
事件采集 -> 策略评估 -> 日志 / 告警 / 阻断 / 终止 / 加密
                         |
             批量阈值 -> 保护协议或紧急协议
```

紧急状态机是显式的：

```text
NORMAL -> ALERT -> ENCRYPTING -> WIPING -> DELETING -> LOCKED
```

⚠️ Tier 2 处置可能包含擦除和删除，具有不可逆风险。请只在隔离环境和可丢弃数据上测试。

## 🚀 快速开始

### 环境要求

- Windows 10/11 x64
- Visual Studio 2022，包含 C++ 桌面开发工作负载
- Windows SDK 10.0.19041.0 或更高版本
- CMake 3.20+
- 安装、启动、停止、配置部署和卸载需要管理员权限
- 仅在编译内核驱动时需要 WDK 11

### 源码构建

```bat
build.bat
```

快速构建路径默认关闭测试和驱动。需要显式配置测试时：

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DBUILD_TESTS=ON -DBUILD_DRIVERS=OFF
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

### 部署运行

以管理员身份运行 `run.bat`，可选择构建、安装、启动、停止、查看状态、卸载和生成 MSI。预编译部署包可使用：

```bat
install.bat /install /key <安装密钥>
install.bat /status
install.bat /stop
install.bat /uninstall /key <安装密钥>
```

配置模板为 `config/guardian_config.yaml`，授权清单为 `config/auth.list`。配置成功读取后，输入文件会被删除，活动策略保存在受保护的二进制缓存中。

## ⚠️ 先看边界

- 内核驱动是可选组件，默认构建不包含驱动。
- `BLOCK` 依赖 `GuardFilter.sys`；驱动未加载时不会自动降级为进程终止。
- TCP 通道尚未初始化，TLS 尚未实现。
- 部分事件类型仍是预留项，详见 [`docs/FUNCTIONAL_SPEC.md`](docs/FUNCTIONAL_SPEC.md)。
- 项目采用 MIT License，详见仓库根目录的 `LICENSE` 文件。

## 📚 中文文档

- [中文完整说明](README.md)
- [管理员操作手册](docs/ADMIN_MANUAL.md)
- [功能说明书](docs/FUNCTIONAL_SPEC.md)
- [保护方案](docs/PROTECTION_SPEC.md)

---

## English Overview

**A Windows-native source-code protection system built around event monitoring, configurable response policies, and a three-node guardian architecture.**

[中文完整文档 / Chinese documentation](README.md)

## What It Does

GuardianShield monitors configured protection directories and evaluates file and process activity against configurable policies. Depending on the event and threshold, the system can log activity, notify the user, terminate a process, encrypt files, or use the optional kernel filter for I/O blocking.

The project is designed for controlled Windows deployments where administrators need an auditable response workflow rather than a single background process:

- **GuardianA** is the primary Windows service. It coordinates event collection, threat evaluation, policy execution, IPC, and emergency-state transitions.
- **GuardianB** is the backup Windows service. It monitors GuardianA and can take over the primary role after a heartbeat timeout.
- **GuardianC** is the user-session monitor. It provides notifications, tray status, emergency lock-screen UI, and user-session integration.
- **GuardFilter.sys** and **GuardMonitor.sys** are optional WDK-based kernel components. They are not built by default.

## Architecture

```text
                 GuardianA (primary service)
                   /                  \
          heartbeat / commands      alerts / heartbeat
                 /                    \
 GuardianB (backup service) <----> GuardianC (user monitor)

 Events -> policy evaluation -> logging / alert / block / terminate / encrypt
 Batch thresholds -> protection or emergency state machine
```

The emergency state machine is explicit and stateful:

```text
NORMAL -> ALERT -> ENCRYPTING -> WIPING -> DELETING -> LOCKED
```

Tier 1 protection is intended to remain recoverable after encryption. Tier 2 emergency handling can include wiping, deletion, and lock-down, and should be treated as potentially irreversible. Test it only in an isolated environment with disposable data.

## Current Scope

| Area | Current implementation |
| --- | --- |
| Platform | Windows 10/11 x64 |
| Language | C++17 with Win32 and Windows CNG APIs |
| Build | CMake 3.20+ and Visual Studio 2022 |
| Services | GuardianA and GuardianB run as Windows services; GuardianC runs in the user session |
| Configuration | YAML policy template plus an IP/MAC authorization list |
| IPC | Named Pipe and Shared Memory paths are used; TCP/TLS is not enabled |
| Drivers | Optional; WDK is required and `BUILD_DRIVERS` defaults to `OFF` |
| Tests | GoogleTest target with 17 test source files registered in `test/CMakeLists.txt` |

## Quick Start

### Requirements

- Windows 10/11 x64
- Visual Studio 2022 with the C++ Desktop workload
- Windows SDK 10.0.19041.0 or later
- CMake 3.20 or later
- Administrator privileges for service installation, start/stop, configuration deployment, and uninstallation
- WDK 11 only when building the optional kernel drivers

### Build From Source

The repository includes a Windows build script:

```bat
build.bat
```

The script configures a Release build and disables tests and drivers for the fast deployment path. For an explicit CMake build:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DBUILD_TESTS=OFF -DBUILD_DRIVERS=OFF
cmake --build build --config Release
```

To configure the complete test target, enable `BUILD_TESTS=ON`. To attempt kernel-driver builds, enable `BUILD_DRIVERS=ON` on a machine with WDK installed.

### Deploy and Run

For a source checkout, run `run.bat` as Administrator and choose:

```text
[1] Build + Install + Start
[2] Build Only
[3] Install Services
[4] Start Services
[5] Stop Services
[6] Check Status
[7] Uninstall
[8] Clean Build
[9] Build MSI Installer
```

For a pre-built deployment bundle, use:

```bat
install.bat /install /key <installation-key>
install.bat /status
install.bat /stop
install.bat /uninstall /key <installation-key>
```

Installation places binaries under `C:\Program Files\GuardianShield` and runtime data under `C:\ProgramData\GuardianShield`.

### Configure

Start with:

- [`config/guardian_config.yaml`](config/guardian_config.yaml): detection thresholds, protection paths, response actions, logging, and emergency policy.
- [`config/auth.list`](config/auth.list): authorized IP/MAC entries.

The runtime configuration uses a key-like workflow: after a successful load, the YAML and authorization-list inputs are removed and the active policy is kept in a protected binary cache. Read the configuration comments and the administrator manual before deploying this behavior.

## Tests and CI

Configure and build the test target, then run it with CTest:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DBUILD_TESTS=ON -DBUILD_DRIVERS=OFF
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

If GoogleTest is not already available, CMake fetches GoogleTest 1.14.0 during configuration. The repository also contains Windows GitHub Actions workflows for build/test checks, security checks, lifecycle verification, and deployment artifacts.

## Documentation

- [中文完整说明](README.md)
- [Administrator Manual](docs/ADMIN_MANUAL.md)
- [Functional Specification](docs/FUNCTIONAL_SPEC.md)
- [Protection Specification](docs/PROTECTION_SPEC.md)
- [Configuration template](config/guardian_config.yaml)

## Important Limitations

- Kernel drivers are optional and require WDK; the normal build path does not include them.
- `BLOCK` depends on `GuardFilter.sys`. If the driver is not loaded, the configured block action is skipped rather than silently converted to process termination.
- Several event types remain reserved for future event sources. See the functional specification for the implemented/reserved matrix.
- TCP transport is defined in parts of the codebase but is not initialized, and TLS is not implemented.
- Tier 2 wiping and deletion are destructive operations. Do not enable them against irreplaceable data without an independent backup and an isolated recovery test.
- This project is released under the MIT License. See the repository root `LICENSE` file.

## Project Status

The current project version is **3.3.0**. This repository is a Windows-focused engineering project with source code, build scripts, configuration templates, tests, CI workflows, and administrator documentation. It is not presented as a drop-in endpoint security product or a substitute for a security review of the deployment environment.

## 中文简介

GuardianShield 是一个面向 Windows 的源代码保护系统，围绕事件监控、可配置响应策略和三节点守护架构工作。项目包含主控服务 GuardianA、备控服务 GuardianB、用户态监控 GuardianC，以及需要 WDK 才能构建的可选内核驱动。

项目支持源码构建、脚本部署、配置文件管理、GoogleTest 测试和 GitHub Actions 生命周期验证。完整的中文部署、配置、测试、故障排除和卸载说明请查看 [README.md](README.md)。
