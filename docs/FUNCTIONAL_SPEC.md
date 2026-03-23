# GuardianShield 功能说明书

**版本**: 3.3.0  
**日期**: 2026-03-18  
**状态**: 与《保护方案》需求 100% 对照

---

## 目录

- [1. 需求对照表](#1-需求对照表)
- [2. 事件类型与威胁等级映射](#2-事件类型与威胁等级映射)
- [3. 响应动作说明](#3-响应动作说明)
- [4. 紧急协议流程](#4-紧急协议流程)
- [5. 进程守护三角](#5-进程守护三角)
- [6. 配置文件说明](#6-配置文件说明)
- [7. 安全特性](#7-安全特性)
- [8. v2.0.0 新增特性](#8-v200-新增特性)
- [9. v3.2.0 新增特性 — BLOCK 响应动作](#9-v320-新增特性--block-响应动作)
- [10. 已知限制与后续规划](#10-已知限制与后续规划)

---

## 1. 需求对照表

下表逐项列出《保护方案》（H:\保护方案11.md）中的全部需求条目，以及 GuardianShield 的对应实现方式和源文件位置。

| 序号 | 需求描述 | 实现状态 | 实现方式 | 关键源文件 |
|------|---------|---------|---------|-----------|
| 1 | 文件被读取时仅记录 | 已实现 | `FILE_READ` → `LEVEL_0` / `LOG` | `threat_evaluator.cpp` |
| 2 | 文件被增加时仅记录 | 已实现 | `FILE_CREATE` → `LEVEL_0` / `LOG` | `threat_evaluator.cpp` |
| 3 | 文件被删除时仅记录 | 已实现 | `FILE_DELETE` → `LEVEL_1` / `LOG + ALERT_USER` | `threat_evaluator.cpp` |
| 4 | 文件被修改时仅记录 | 已实现 | `FILE_WRITE` → `LEVEL_1` / `LOG + ALERT_USER` | `threat_evaluator.cpp` |
| 5 | 文件被移动时告警 | 已实现 | `FILE_MOVE` → `LOG + ALERT_USER + BLOCK`（可配置）。v3.3 通过 GuardianA ETW 回调中 CREATE+DELETE 事件关联检测跨卷移动 | `guardian_a.cpp`, `config.cpp`, `common_types.h` |
| 6 | 文件被压缩时锁定文件 | 已实现 | 批量压缩检测（阈值内）→ `LEVEL_3` 触发紧急协议 | `threat_evaluator.cpp`, `guardian_a.cpp` |
| 7 | 网络传输时加密删除文件，不可复原 | 已实现 | `LEVEL_3` → AES-256 双模式加密（≤100MB: GCM; >100MB: CBC+HMAC 流式）→ DOD 5220.22-M 7次覆写擦除。密钥派生: PBKDF2-SHA256 (100,000 iterations) | `file_encryptor.cpp`, `file_wiper.cpp` |
| 8 | 开机自启 + 自动建立运行日志 | 已实现 | A/B: `SERVICE_AUTO_START` 服务; C: 注册表 `HKCU\...\Run`; Logger 按日期自动创建 | `windows_service.cpp`, `logger.cpp` |
| 9 | 阈值可配置（秒/数量/MB） | 已实现 | `guardian_config.yaml` → `detection.thresholds` 节，含时间窗口和计数 | `config.cpp`, `guardian_config.yaml` |
| 10 | 文件类型过滤和进程白名单 | 已实现 | `protection.file_types.include/exclude` + `whitelist.processes[]` | `guardian_config.yaml`, `config.cpp` |
| 11 | 区分正常操作与恶意窃取 | 已实现 | `ThreatEvaluator` 综合事件类型+频率+白名单+批量检测 | `threat_evaluator.cpp` |
| 12 | 锁定后管理员输入密码解锁 | 已实现 | GuardianA/B 通过 IPC 触发 GuardianC 全屏锁屏窗口，密码 SHA-256 验证后广播 UNLOCK_RESPONSE 解锁 | `guardian_c.cpp`, `guardian_a.cpp` |
| 13 | 配置文件"钥匙"机制 | 已实现 | 读取成功后 `DeleteConfigFile()` 删除 YAML，缓存设 ACL 保护 | `config.cpp` |
| 14 | IP/MAC 绑定环境校验 | 已实现 | `EnvironmentValidator` 启动时核对 `auth.list`，不匹配触发 `LEVEL_3` | `environment_validator.cpp` |
| 15 | 授权清单"钥匙"方式管理 | 已实现 | YAML 配置读后删除；auth.list 读取后自动删除，数据纳入二进制缓存 | `config.cpp`, `environment_validator.cpp` |
| 16 | 卸载需输入密码 | 已实现 | `VerifyInstallKey()` 校验 SHA-256 哈希，`-uninstall` 时必须提供 `-key` | `install_key.h`, `main.cpp` |
| 17 | 安装需输入密码 | 已实现 | 同上，`-install` 时必须提供 `-key` | `install_key.h`, `main.cpp` |
| 18 | 每天建立新日志文件，保留7天 | 已实现 | `daily_rotation: true`, `retention_days: 7` | `logger.cpp`, `guardian_config.yaml` |
| 19 | 开机自启无窗口 | 已实现 | `wWinMain` 入口 + `WIN32_EXECUTABLE ON`，进程名伪装 | `main.cpp`, `CMakeLists.txt` |
| 20 | Windows 11 系统兼容 | 已实现 | 目标 Windows 10/11 x64，使用标准 Win32 API | 全局 |
| 21 | 管理员后门（中止/卸载/解锁/恢复） | 已实现 | 密码解锁 + 加密文件可解密恢复 + CLI 管理命令 | `guardian_a.cpp`, `file_encryptor.cpp` |
| 22 | 紧急协议五阶段流程 | 已实现 | NORMAL→ALERT→ENCRYPTING→WIPING→DELETING→LOCKED | `guardian_a.cpp` |
| 23 | 响应动作体系（7种） | 已实现 | LOG/ALERT_USER/BLOCK/TERMINATE/ENCRYPT/WIPE/LOCKDOWN（BLOCK 在 v3.2 重新引入为内核级 I/O 拦截；LOCK_FILE 在 v3.0 移除） | `common_types.h`, `guardian_a.cpp` |

---

## 2. 事件类型与威胁等级映射

### 2.1 单事件映射（仅在保护目录内触发）

**v3.3.0 实现状态**: 标注 `[已实现]` 的事件类型有 ETW/驱动事件源，`[预留/当前版本不实装]` 的类型在当前版本无事件源。

| 事件类型 | 枚举值 | 威胁等级 | 响应动作 | 说明 | 状态 |
|---------|--------|---------|---------|------|------|
| FILE_CREATE | `DriverEvent::FILE_CREATE` | LEVEL_0 | LOG | 文件创建，仅记录 | [已实现] ETW opcode 0 |
| FILE_WRITE | `DriverEvent::FILE_WRITE` | LEVEL_1 | LOG + ALERT_USER | 文件修改 | [已实现] ETW opcode 32 |
| FILE_RENAME | `DriverEvent::FILE_RENAME` | LEVEL_2 | LOG + ALERT_USER + BLOCK | 文件重命名/同卷移动 | [已实现] ETW opcode 36 |
| FILE_DELETE | `DriverEvent::FILE_DELETE` | LEVEL_1 | LOG + ALERT_USER | 文件删除监控 | [已实现] ETW opcode 35 |
| FILE_COMPRESS | `DriverEvent::FILE_COMPRESS` | LEVEL_1 | LOG + ALERT_USER | 文件压缩（启发式） | [已实现] 进程名匹配 |
| FILE_NETWORK_TRANSFER | `DriverEvent::FILE_NETWORK_TRANSFER` | LEVEL_1 | LOG + ALERT_USER | 网络传输（启发式） | [已实现] 进程名匹配 |
| PROCESS_CREATE | `DriverEvent::PROCESS_CREATE` | LEVEL_0 | LOG | 进程创建，仅记录 | [已实现] |
| PROC_TERMINATE | `DriverEvent::PROC_TERMINATE` | LEVEL_0 | LOG | 进程终止（v2.1 降级） | [已实现] |
| DRIVER_LOAD | `DriverEvent::DRIVER_LOAD` | LEVEL_0 | LOG | 驱动加载（v2.1 降级） | [已实现] |
| DRIVER_UNLOAD | `DriverEvent::DRIVER_UNLOAD` | LEVEL_0 | LOG | 驱动卸载（v2.1 降级） | [已实现] |
| FILE_READ | `DriverEvent::FILE_READ` | LEVEL_0 | LOG | 文件读取 | [预留/当前版本不实装] |
| FILE_SET_INFO | `DriverEvent::FILE_SET_INFO` | LEVEL_1 | LOG + ALERT_USER | 文件属性修改 | [预留/当前版本不实装] |
| FILE_MOVE | `DriverEvent::FILE_MOVE` | LEVEL_2 | LOG + ALERT_USER + BLOCK | 文件移动 | [已实现 v3.3] 通过 CREATE+DELETE 事件关联检测跨卷移动 |
| PROCESS_INJECT | `DriverEvent::PROCESS_INJECT` | LEVEL_2 | LOG + ALERT_USER + TERMINATE | 进程注入攻击 | [预留/当前版本不实装] |
| PROCESS_DEBUG | `DriverEvent::PROCESS_DEBUG` | LEVEL_2 | LOG + ALERT_USER + TERMINATE | 调试器附加 | [预留/当前版本不实装] |
| NETWORK_CONNECT | `DriverEvent::NETWORK_CONNECT` | LEVEL_1 | LOG + ALERT_USER | 网络连接 | [预留/当前版本不实装] |
| NETWORK_SEND | `DriverEvent::NETWORK_SEND` | LEVEL_1 | LOG + ALERT_USER | 网络发送 | [预留/当前版本不实装] |
| NETWORK_RECV | `DriverEvent::NETWORK_RECV` | LEVEL_1 | LOG + ALERT_USER | 网络接收 | [预留/当前版本不实装] |

**重要设计原则（ADR-001）**：单事件响应动作由 `guardian_config.yaml` 的 `detection.event_responses` 节驱动（可配置 LOG/ALERT_USER/BLOCK/TERMINATE/ENCRYPT）。WIPE 和 LOCKDOWN 仅由批量协议触发，单事件配置中自动过滤。BLOCK 为内核级 I/O 拦截，需 GuardFilter 驱动加载。

### 2.2 两级批量操作检测

批量操作检测使用两级阈值系统（Tier 1 / Tier 2），取代旧的单一 LEVEL_3 触发。

| 协议 | 触发条件 | 动作 | 可恢复性 |
|------|---------|------|---------|
| Tier 1（保护协议） | 任一检测项超过 tier1 阈值 | ALERT 倒计时 → 全目录加密 | 可恢复（管理员可解密） |
| Tier 2（紧急协议） | 任一检测项超过 tier2 阈值 / 未授权设备 | ALERT 倒计时 → 加密 + 擦除 + 删除 + 锁定 | 不可逆 |

**检测项与默认阈值**：

| 检测项 | Tier 1 阈值 | Tier 1 窗口 | Tier 2 阈值 | Tier 2 窗口 |
|--------|-----------|-----------|-----------|-----------|
| file_write_count | 10 | 5秒 | 50 | 10秒 |
| file_compress_count | 50 | 5秒 | 250 | 10秒 |
| file_delete_count | 5 | 5秒 | 20 | 10秒 |
| file_create_count | 15 | 5秒 | 50 | 10秒 |
| file_rename_count | 10 | 5秒 | 50 | 10秒 |
| file_move_count | 10 | 5秒 | 50 | 10秒 |
| file_network_transfer_count | 10 | 5秒 | 40 | 10秒 |
| data_transfer_mb | 1 MB | 5秒 | 10 MB | 10秒 |
| process_termination_count | 50 | 5秒 | 200 | 5秒 |

**留空规则**：阈值为 0 表示不限制（跳过该项检测）。所有阈值可在 `guardian_config.yaml` 的 `detection.thresholds.tier1` / `detection.thresholds.tier2` 中自定义。

---

## 3. 响应动作说明

| 响应动作 | 代码 | 执行内容 | 实现位置 |
|---------|------|---------|---------|
| LOG | 0x01 | 记录事件到日志文件（JSON 格式） | `logger.cpp` |
| ALERT_USER | 0x02 | 通过 IPC 发送 `ALERT_NOTIFICATION` 至 GuardianC，由其在用户桌面弹出通知 | `guardian_a.cpp`, `guardian_c.cpp` |
| TERMINATE | 0x08 | 终止可疑进程（`TerminateProcess`） | `guardian_a.cpp` |
| BLOCK | 0x10 | 内核级 I/O 拦截：GuardFilter.sys 在 minifilter 回调中返回 `STATUS_ACCESS_DENIED`，阻止文件重命名/移动/删除/写入（按策略位掩码）。驱动未加载时跳过（不降级为 TERMINATE，仅记录警告日志） | `filter_callbacks.c`, `guardian_a.cpp` |
| ENCRYPT | 0x20 | AES-256 双模式加密（≤100MB: GCM/GSENCR01; >100MB: CBC+HMAC/GSENCR02），密钥派生 PBKDF2-SHA256。单文件或批量 | `file_encryptor.cpp` |
| WIPE | 0x40 | DOD 5220.22-M 标准安全擦除（7次覆写），仅批量协议 | `file_wiper.cpp` |
| LOCKDOWN | 0x80 | 系统锁定，GuardianC 显示全屏置顶锁屏窗口，仅批量协议 | `guardian_a.cpp`, `guardian_c.cpp` |

> **v3.2 变更**: `BLOCK` (0x10) 重新引入为内核级 I/O 拦截动作，通过 GuardFilter.sys minifilter 驱动实现。`LOCK_FILE` 在 v3.0 已移除。BLOCK + TERMINATE 并存时自动移除 TERMINATE（防止双重惩罚）。

---

## 4. 紧急协议流程

### 4.1 触发条件

- 批量操作检测达到 LEVEL_3 阈值
- 环境校验失败（IP/MAC 不在授权清单中）
- 手动触发（管理员通过 IPC 命令）

### 4.2 五阶段执行流程

```
阶段 1: NORMAL → ALERT
  ├── 增强监控模式
  ├── 记录所有操作到日志
  ├── 发送警报通知（跨 Session）
  └── 广播紧急消息至 GuardianB/C

阶段 2: ALERT → ENCRYPTING
  ├── 遍历所有保护目录
  ├── 使用 AES-256 双模式加密每个文件
  │   ├── 密钥派生: PBKDF2-SHA256(password + random_salt, 100000 iterations)
  │   ├── ≤100MB: AES-256-GCM，格式 [GSENCR01 8B][SALT 16B][IV 12B][TAG 16B][密文...]
  │   ├── >100MB: AES-256-CBC+HMAC-SHA256 流式，格式 [GSENCR02 8B][SALT 16B][IV 16B][HMAC 32B][密文...]
  │   └── 加密后原文件替换为 .gs 文件（原子写入: .gs.tmp → rename）
  └── 密码来源: admin.password_hash 或内置默认密码

阶段 3: ENCRYPTING → WIPING
  ├── 对保护目录执行安全擦除
  ├── DOD 5220.22-M 标准 7 次覆写
  │   ├── Pass 1: 全 0x00
  │   ├── Pass 2: 全 0xFF
  │   ├── Pass 3: BCryptGenRandom 随机数据
  │   ├── Pass 4: 全 0x00
  │   ├── Pass 5: 全 0xFF
  │   ├── Pass 6: BCryptGenRandom 随机数据
  │   └── Pass 7: 全 0x00
  └── FILE_FLAG_WRITE_THROUGH 确保直写磁盘

阶段 4: WIPING → DELETING
  ├── 清除 %TEMP% 下的 GuardianShield 临时文件
  ├── 清理最近文档记录 (SHAddToRecentDocs)
  └── 清除剪贴板 (OpenClipboard + EmptyClipboard)

阶段 5: DELETING → LOCKED
  ├── GuardianA/B 发送 EMERGENCY_TRIGGER IPC 消息到 GuardianC
  ├── GuardianC 创建全屏置顶窗口 (WS_EX_TOPMOST + WS_POPUP)
  │   ├── 覆盖全部显示器，无关闭按钮，拦截 Alt+F4/Esc
  │   ├── 定时器每秒强制置顶 (SetWindowPos + SetForegroundWindow)
  │   └── 提供密码输入框和解锁按钮
  ├── 管理员输入密码 → SHA-256 校验 → 通过后广播 UNLOCK_RESPONSE
  └── GuardianA/B 收到 UNLOCK_RESPONSE → CancelEmergency() + 自动解密 .gs 文件
```

### 4.3 管理员恢复流程

1. 在锁定界面输入管理员密码
2. 密码验证通过后系统解锁
3. 加密的 `.gs` 文件可使用相同密码通过 `FileEncryptor::DecryptFile()` 解密恢复
4. 安全模式下也可通过停止服务 + 手动解密恢复数据

---

## 5. 进程守护三角

### 5.1 三节点架构

| 节点 | 类型 | 进程名 | 服务名 | 职责 |
|------|------|--------|--------|------|
| GuardianA | Windows 服务 (SYSTEM) | svchost_core.exe | WinDefenderCore | 主控：威胁评估、ETW 事件采集、紧急协议、内核驱动通信 |
| GuardianB | Windows 服务 (SYSTEM) | svchost_helper.exe | WinDefenderHelper | 备控：监控 A 健康、故障接管/退回、事件转发 |
| GuardianC | 用户态程序 | winmon.exe | — | 监控：心跳监控、系统托盘状态与通知、文件管理面板、一键解锁 |

### 5.2 心跳与故障转移

- 心跳间隔：500ms
- 超时判定：连续 3 次无响应（1.5 秒）
- GuardianA 失效 → GuardianB 自动接管主控角色
- GuardianA 恢复 → GuardianB 自动退回备控角色
- 切换过程对用户透明

### 5.3 通信机制

| 通道 | 说明 |
|------|------|
| Named Pipe | `\\.\pipe\GuardianIPC_A/B/C`，事件传递和命令通信。`SendToNode` 使用 `m_sendMutex` 保护并发访问，`tryConnect` 超时 1x300ms |
| Shared Memory | `Global\GuardianState`，心跳状态高速同步（使用 `Global\` 命名空间实现跨会话通信） |
| TCP Loopback | 端口 17500+，明文通信（**TLS 尚未实现**，代码强制 `m_useTLS = false`），远程管理预留 |

> **v2.5 IPC 增强**：通知发送失败时自动使用 `MessageBeep` 音效回退；新增 `DECRYPT_REQUEST` / `DECRYPT_RESPONSE` 消息类型支持一键解锁功能。

---

## 6. 配置文件说明

### 6.1 配置文件结构

系统使用单一配置文件 `guardian_config.yaml`，采用"钥匙"机制管理：

```
C:\ProgramData\GuardianShield\
  ├── config\
  │   ├── guardian_config.yaml   ← 管理员放入，服务读取后自动删除
  │   └── auth.list              ← IP/MAC 授权清单
  └── config_cache.bin           ← 二进制缓存（ACL 保护，普通用户不可读，由 Config::GetCachePath() 写入）
```

### 6.2 配置"钥匙"运行时流程

1. 服务启动 → 检查 `guardian_config.yaml` 是否存在
2. **存在** → 读取 YAML → 保存到 `C:\ProgramData\GuardianShield\config_cache.bin` → 删除 YAML → 设置缓存 ACL → 按最新策略运行
3. **不存在** → 加载 `C:\ProgramData\GuardianShield\config_cache.bin` → 按缓存策略运行
4. **缓存也不存在** → 使用内置默认策略

管理员更新策略：将新的 `guardian_config.yaml` 放入配置目录 → 重启服务 → 自动读取生效 → YAML 自动删除。

### 6.3 关键配置字段

#### 系统基础

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `system.version` | string | "3.3.0" | 配置版本号 |
| `system.log_level` | string | "INFO" | 日志级别：DEBUG/INFO/WARN/ERROR |
| `system.log_path` | string | — | 日志存储目录 |

#### 检测阈值

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `detection.alert_timeout_seconds` | int | 300 | ALERT 阶段等待管理员取消的超时时间（秒），YAML 默认配置为 300 |
| `detection.thresholds.tier1.file_write_count` | int | 10 | Tier 1 批量文件写入数阈值 |
| `detection.thresholds.tier1.file_write_window_seconds` | int | 5 | Tier 1 文件写入检测时间窗口（秒） |
| `detection.thresholds.tier1.file_delete_count` | int | 5 | Tier 1 批量文件删除数阈值 |
| `detection.thresholds.tier1.file_compress_count` | int | 50 | Tier 1 批量压缩文件数阈值 |
| `detection.thresholds.tier2.file_write_count` | int | 50 | Tier 2 批量文件写入数阈值 |
| `detection.thresholds.tier2.file_delete_count` | int | 20 | Tier 2 批量文件删除数阈值 |
| `detection.thresholds.tier2.file_compress_count` | int | 250 | Tier 2 批量压缩文件数阈值 |

#### 保护目录

| 字段 | 类型 | 说明 |
|------|------|------|
| `protection.directories[].path` | string | 保护目录绝对路径 |
| `protection.directories[].recursive` | bool | 是否递归保护子目录 |
| `protection.directories[].priority` | string | 优先级：HIGH/MEDIUM/LOW |
| `protection.file_types.include` | list | 保护的文件扩展名（如 `*.cpp`） |
| `protection.file_types.exclude` | list | 排除的文件扩展名（如 `*.log`） |

#### 进程白名单

| 字段 | 类型 | 说明 |
|------|------|------|
| `whitelist.processes[].name` | string | 进程名（如 `devenv.exe`） |
| `whitelist.processes[].permissions` | list | 允许的操作：READ/WRITE |
| `whitelist.processes[].conditions` | list | 附加条件（如限定用户组） |

#### 紧急协议

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `emergency.encrypt_timeout_seconds` | int | 30 | **保留字段**（当前版本已解析但未使用，ALERT 等待由 `detection.alert_timeout_seconds` 控制） |
| `emergency.recovery_wait_seconds` | int | 30 | **保留字段**（当前版本未使用，加密后直接进入 WIPING） |
| `emergency.wipe_method` | string | "DOD_5220" | 擦除标准：DOD_5220/GUTMANN/SIMPLE |

#### 管理员

| 字段 | 类型 | 说明 |
|------|------|------|
| `admin.password_hash` | string | 管理员密码的 SHA-256 哈希值（64位十六进制） |
| `admin.unlock_timeout_seconds` | int | 解锁等待超时时间（秒） |

#### 授权清单

| 字段 | 类型 | 说明 |
|------|------|------|
| `authorization.list_path` | string | auth.list 文件路径 |
| `authorization.check_on_boot` | bool | 启动时是否校验环境 |
| `authorization.strict_mode` | bool | 严格模式：未授权直接触发紧急协议 |

### 6.4 授权清单格式 (auth.list)

```
# 格式: IP地址,MAC地址,备注
192.168.110.148,6C:24:08:23:3A:1B,本机测试
192.168.110.124,14:18:C3:E3:A1:75,测试机
```

- MAC 地址格式：`XX:XX:XX:XX:XX:XX`
- 系统启动时自动获取本机 IP 和 MAC 进行比对
- 不在清单中的设备将触发最高等级处置（LEVEL_3 紧急协议）

---

## 7. 安全特性

### 7.1 文件加密

| 项目 | 说明 |
|------|------|
| 算法 | AES-256 双模式（Windows CNG BCrypt API）：≤100MB 使用 **AES-256-GCM**（认证加密）；>100MB 使用 **AES-256-CBC + HMAC-SHA256**（流式加密） |
| 密钥派生 | **PBKDF2-SHA256**（100,000 iterations）→ 32 字节 AES 密钥 |
| 随机数 | BCryptGenRandom（密码学安全） |
| 文件格式 | 小文件 GCM: `[GSENCR01 8B][SALT 16B][IV 12B][TAG 16B][密文...]`；大文件 CBC: `[GSENCR02 8B][SALT 16B][IV 16B][HMAC 32B][密文...]` |
| 阈值 | `STREAM_THRESHOLD = 100 MB`（`file_encryptor.h`） |
| 扩展名 | 加密后文件扩展名为 `.gs` |

### 7.2 安全擦除

| 项目 | 说明 |
|------|------|
| 标准 | DOD 5220.22-M（7 次覆写） |
| 随机源 | BCryptGenRandom |
| 磁盘直写 | `FILE_FLAG_WRITE_THROUGH` 确保不经过缓存 |
| 覆写序列 | 0x00 → 0xFF → 随机 → 0x00 → 0xFF → 随机 → 0x00 |

### 7.3 服务隐蔽性

| 特性 | 实现方式 |
|------|---------|
| 无控制台窗口 | `wWinMain` + `WIN32_EXECUTABLE ON` |
| 进程名伪装 | `svchost_core.exe` / `svchost_helper.exe` / `winmon.exe` |
| 服务名伪装 | `WinDefenderCore` / `WinDefenderHelper` |
| 防止终止 | DACL 限制：仅 SYSTEM + Administrators 有控制权限 |
| 托盘图标 | GuardianC 在用户会话中显示系统托盘图标（状态指示与右键菜单） |
| 故障自恢复 | 服务失败自动重启（5s → 30s → 60s） |

### 7.4 安装/卸载保护

| 特性 | 实现方式 |
|------|---------|
| 安装密钥 | `-install -key <密码>` 校验 SHA-256 哈希 |
| 卸载密钥 | `-uninstall -key <密码>` 同上 |
| MSI 安装密钥 | `guardian_ca.dll` 自定义动作验证 |
| 哈希算法 | Windows BCrypt SHA-256 |
| 统一密钥管理 | `admin.install_key_hash` 可在 YAML 中配置，无需重新编译 |
| 一键卸载脚本 | `scripts/uninstall.bat` 含密钥验证，完整清理 |

### 7.5 配置保护

| 特性 | 实现方式 |
|------|---------|
| YAML 读后删除 | `Config::DeleteConfigFile()` |
| 缓存 ACL 保护 | `D:P(A;;FA;;;SY)(A;;FA;;;BA)` — 仅 SYSTEM + Administrators 可访问 |
| 普通用户不可读 | 缓存文件中的密码哈希等敏感信息受 DACL 保护 |

---

## 8. v2.0.0 新增特性

### 8.1 全屏锁屏窗口

| 项目 | 说明 |
|------|------|
| 触发方式 | GuardianA/B 通过 IPC 发送 `EMERGENCY_TRIGGER` 至 GuardianC |
| 窗口特性 | 全屏覆盖、`WS_EX_TOPMOST` 置顶、无标题栏、无关闭按钮 |
| 防绕过 | 拦截 `WM_CLOSE`/`WM_SYSCOMMAND`/`Alt+F4`/`Esc`，定时器每秒强制置顶 |
| 解锁方式 | 管理员在窗口内输入密码，SHA-256 校验通过后广播 `UNLOCK_RESPONSE` |
| 实现文件 | `src/service/GuardianC/src/guardian_c.cpp` |

### 8.2 IPC 消息 HMAC-SHA256 校验

| 项目 | 说明 |
|------|------|
| 算法 | HMAC-SHA256，截断至 12 字节 |
| 校验范围 | 所有 IPC 消息（Named Pipe / Shared Memory / TCP） |
| 密钥来源 | 基于机器 SID 或 MachineGuid 注册表值结合固定盐值派生，非硬编码 |
| 安全增强 | VerifyChecksum 显式拒绝全零校验和；TCP 仅监听 127.0.0.1 并通过 getpeername 验证对端 |
| 部署状态 | IpcManager 仅启用 Named Pipe 和 Shared Memory；TCP 通道已定义但未初始化；TLS 推迟至 V2 |
| 实现文件 | `src/service/common/src/ipc.cpp` |

### 8.3 ObRegisterCallbacks 内核级进程保护

| 项目 | 说明 |
|------|------|
| 功能 | 通过内核回调拦截外部进程对 Guardian 服务的终止操作 |
| 保护对象 | `svchost_core.exe`, `svchost_helper.exe`, `winmon.exe` |
| 实现 | GuardMonitor.sys 中注册 `ObRegisterCallbacks`，移除 `PROCESS_TERMINATE` 权限 |
| 实现文件 | `src/driver/GuardMonitor/src/process_notify.c` |

### 8.4 统一 MSI 安装包

| 项目 | 说明 |
|------|------|
| 安装流程 | 输入安装密钥 → 选择 auth.list 和 guardian_config.yaml → 自动复制配置 → 注册服务 |
| 自定义动作 DLL | `guardian_ca.dll` 实现密钥 SHA-256 验证和配置文件安全复制 |
| 卸载密钥 | 卸载时同样需要输入管理员密钥 |
| 实现文件 | `src/installer/GuardianShield.wxs`, `src/installer/guardian_ca/guardian_ca.cpp` |

### 8.5 一键卸载脚本

| 项目 | 说明 |
|------|------|
| 文件 | `scripts/uninstall.bat` |
| 功能 | 密钥验证 → 停止服务/进程 → 卸载服务 → 清理注册表 → 删除所有文件 |
| 使用 | 右键以管理员身份运行，输入卸载密钥 |

### 8.6 统一管理员密钥

| 项目 | 说明 |
|------|------|
| 机制 | `admin.install_key_hash` 写入 YAML，服务启动时读取并缓存 |
| 优势 | 管理员可在配置文件中统一管理，无需重新编译 |
| auth.list | 读取后自动删除，授权信息纳入二进制缓存 |

### 8.7 v2.5 新增特性

| 项目 | 说明 |
|------|------|
| ETW 迁移至 GuardianA | ETW 事件采集由 SYSTEM 权限服务完成，解决权限不足问题 |
| ETW 生命周期管理 | 防御性清理、原子句柄、60 秒活性守护、ProcessTrace 自动恢复 |
| IPC 通知可靠性 v2 | SendToNode 互斥锁、tryConnect 优化、MessageBeep 音效回退 |
| 托盘退出隐藏 | 右键菜单不再暴露退出按钮，防止用户误操作 |
| 文件管理面板 | GuardianC 托盘右键 → 文件管理，ListView 展示 `.gs` 加密文件 |
| 一键解锁 | 输入管理员密码后批量解密 `.gs` 文件，通过 DECRYPT_REQUEST/RESPONSE IPC 路由到主控节点 |

---

## 9. v3.2.0 新增特性 — BLOCK 响应动作

### 9.1 内核级文件操作拦截

| 项目 | 说明 |
|------|------|
| 驱动 | GuardFilter.sys minifilter 驱动 |
| 拦截层面 | `IRP_MJ_SET_INFORMATION`（`FileRenameInformation` / `FileDispositionInformation`）、`IRP_MJ_CREATE`（DELETE 权限）、`IRP_MJ_WRITE` |
| 拦截方式 | Pre-operation 回调返回 `FLT_PREOP_COMPLETE` + `STATUS_ACCESS_DENIED` |
| 策略位掩码 | `BLOCK_FLAG_RENAME` (0x01) / `BLOCK_FLAG_DELETE` (0x02) / `BLOCK_FLAG_WRITE` (0x04) |
| IOCTL | `IOCTL_GUARDIAN_SET_BLOCK_POLICY` / `IOCTL_GUARDIAN_GET_BLOCK_POLICY` |

### 9.2 BLOCK 行为规则

| 规则 | 说明 |
|------|------|
| 威胁等级 | BLOCK 映射为 `LEVEL_2`（与 TERMINATE、ENCRYPT 同级） |
| 降级逻辑 | BLOCK + TERMINATE 并存 → 自动移除 TERMINATE，避免双重惩罚 |
| 回退机制 | 驱动未加载时 BLOCK 跳过（不降级为 TERMINATE），仅记录 WARNING 日志 |
| 白名单豁免 | Guardian 自身进程 + YAML whitelist.processes 自动同步至驱动侧 |
| 驱动重连 | DriverReadThread 断线重连后自动重发白名单 + BLOCK 策略 + 保护路径 |
| 跨卷移动 | Windows 将跨卷移动拆分为 Copy + Delete，BLOCK 仅拦截 Delete 阶段，目标位置可能残留副本 |

### 9.3 默认事件映射

| 事件类型 | 默认动作 |
|---------|---------|
| FILE_RENAME | LOG + ALERT_USER + BLOCK |
| FILE_MOVE | LOG + ALERT_USER + BLOCK |

### 9.4 审计修复项

v3.2 发布前通过深度审计发现并修复了以下问题：

| 编号 | 类型 | 修复内容 |
|------|------|---------|
| F1 | 预存在BUG | GuardianB `ConnectDrivers()` 使用错误的驱动端口名 |
| F2 | 预存在BUG | GuardianB `LoadProtectedPaths()` 未同步保护路径到驱动 |
| F3 | 白名单 | Guardian 自身进程 + YAML 白名单未同步到驱动侧 |
| F4 | 重连 | 驱动断线重连后未重发白名单/策略/保护路径 |
| F5 | 日志 | `ResponseActionCombinedToString()` 缺失 BLOCK/ENCRYPT |
| F6 | 威胁等级 | BLOCK 未映射到 LEVEL_2 |
| F7 | 回退 | GuardianB `ExecuteResponse()` 缺失 BLOCK 分支 |
| F8 | 文档 | ~~FILE_MOVE 事件源尚未实现~~ 已在 v3.3 通过 CREATE+DELETE 事件关联实现 |

---

## 10. 已知限制与后续规划

### 10.1 已知限制

| 编号 | 描述 | 影响范围 | 优先级 |
|------|------|---------|--------|
| ~~L1~~ | ~~EmergencyExecutor 死代码~~ | **已删除 (v3.1)**: EmergencyExecutor 全是 TODO 桩代码，紧急协议由 guardian_a.cpp 直接实现，已从项目中移除 | 已解决 |
| L2 | 内核驱动需 WDK 编译 | GuardFilter.sys / GuardMonitor.sys 骨架已完成，需安装 WDK 后编译 | 中 |
| L3 | ~~ETW 权限问题~~ | **已在 v2.5 解决**：ETW 由 GuardianA（SYSTEM 服务）采集，权限已满足；若采集异常可检查 ETW 活性守护与自动恢复日志 | 已解决 |

### 10.2 后续规划

| 编号 | 计划项 | 说明 |
|------|--------|------|
| ~~P1~~ | ~~auth.list "钥匙"化~~ | ~~已在 v2.0.0 中实现~~ |
| ~~P2~~ | ~~IPC HMAC 校验~~ | ~~已在 v2.0.0 中实现~~ |
| P3 | 内核驱动编译与部署 | 配置 WDK 环境，编译并签名 GuardFilter.sys / GuardMonitor.sys |
| ~~P4~~ | ~~ObRegisterCallbacks 进程保护~~ | ~~已在 v2.0.0 中实现~~ |
| ~~P5~~ | ~~统一安装程序~~ | ~~已在 v2.0.0 中实现（WiX MSI）~~ |
| P6 | 多显示器锁屏测试 | 验证锁屏窗口在多显示器环境的覆盖效果 |
| P7 | TPM 密钥保护 | 利用 TPM 硬件模块保护加密密钥 |

---

*GuardianShield v3.3.0 — 企业级源代码防泄漏系统*
