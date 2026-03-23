> ⚠️ **归档文档** — 本文档部分内容可能与 v3.3.0 代码不一致，以源代码和 guardian_config.yaml 为准。
# GuardianShield 源代码防护系统 - 完整方案文档

> **⚠ 历史文档**: 本文档为早期设计方案，部分内容已过时。以 `FUNCTIONAL_SPEC.md` 和 `guardian_config.yaml` 为准。

## 一、系统概述

GuardianShield 是一套源代码防护系统，通过监控文件操作行为，识别正常操作与恶意盗取行为，保护敏感文件安全。

### 组件架构

| 组件 | 类型 | 运行方式 | 职责 |
|------|------|----------|------|
| svchost_core.exe | Windows 服务 | 自动启动（SYSTEM权限） | 主控制器：威胁评估、ETW 事件采集、决策、触发紧急协议 |
| svchost_helper.exe | Windows 服务 | 自动启动（SYSTEM权限） | 备份控制器：监控 GuardianA、文件监控 |
| winmon.exe | 用户程序 | 开机自启（后台运行） | 监控节点：系统托盘、用户通知、文件管理面板、一键解锁 |

---

## 二、文件操作行为与响应

### 2.1 单文件操作响应（以方案文字描述为准）

| 操作行为 | 响应动作 | 说明 |
|----------|----------|------|
| 文件读取 | LOG | 仅记录到日志 |
| 文件创建 | LOG | 仅记录到日志 |
| 文件修改 | LOG | 仅记录到日志 |
| 文件删除 | LOG | 仅记录到日志 |
| 文件重命名 | LOG | 仅记录到日志 |
| 文件移动 | **LOG + ALERT_USER** | 记录+告警（可配置） [已实现 v3.3] 通过 CREATE+DELETE 事件关联检测跨卷移动 |
| 文件删除 | **LOG + ALERT_USER** | 记录+告警（可配置） |
| 文件压缩 | **LOG + ALERT_USER** | 记录+告警（可配置） |
| 文件网络传输 | **LOG + ALERT_USER** | 记录+告警（可配置） |

### 2.2 批量操作响应（两级阈值）

| 触发条件 | 协议类型 | 响应动作 | 可恢复性 |
|----------|----------|----------|----------|
| 批量操作超过 tier1 阈值 | 保护协议 | ALERT → ENCRYPT → LOCK | 可恢复 |
| 批量操作超过 tier2 阈值 | 紧急协议 | ALERT → ENCRYPT → WIPE → DELETE → LOCK | 不可逆 |
| 未授权设备启动 | 紧急协议 | ENCRYPT → WIPE → DELETE → LOCK（跳过 ALERT） | 不可逆 |

### 2.3 进程行为响应

| 事件类型 | 威胁等级 | 响应动作 | 说明 |
|----------|----------|----------|------|
| PROCESS_CREATE | LEVEL_0 | LOG | 进程创建 |
| PROCESS_TERMINATE | LEVEL_0 | LOG | 进程终止（v2.1 降级） |
| PROCESS_INJECT | LEVEL_2 | LOG + ALERT_USER + TERMINATE | 进程注入攻击 [预留/未实装] |
| PROCESS_DEBUG | LEVEL_2 | LOG + ALERT + TERMINATE | 调试器附加 [预留/未实装] |

### 2.4 驱动与网络响应

| 事件类型 | 威胁等级 | 响应动作 | 说明 |
|----------|----------|----------|------|
| DRIVER_LOAD | LEVEL_0 | LOG | 驱动加载（v2.1 降级） |
| DRIVER_UNLOAD | LEVEL_0 | LOG | 驱动卸载（v2.1 降级） |
| NETWORK_CONNECT | LEVEL_1 | LOG + ALERT_USER | 网络连接 [预留/未实装] |
| NETWORK_SEND | LEVEL_1 | LOG + ALERT_USER | 网络发送 [预留/未实装] |
| NETWORK_RECV | LEVEL_1 | LOG + ALERT_USER | 网络接收 [预留/未实装] |

---

## 三、响应动作定义

| 响应动作 | 代码 | 执行内容 |
|----------|------|----------|
| LOG | 0x01 | 记录事件到日志文件（JSON格式） |
| ALERT_USER | 0x02 | Windows系统通知/系统托盘警告 |
| TERMINATE | 0x08 | 终止可疑进程 |
| BLOCK | 0x10 | 内核级 I/O 拦截（v3.2 引入，需 GuardFilter 驱动） |
| ENCRYPT | 0x20 | 加密保护文件（AES-256 双模式: ≤100MB GCM; >100MB CBC+HMAC。密钥: PBKDF2-SHA256） |
| WIPE | 0x40 | 安全擦除文件（DOD_5220标准，7次覆写） |
| LOCKDOWN | 0x80 | 系统锁定，禁止所有操作，需管理员密码解锁 |

---

## 四、紧急协议执行流程

```
LEVEL_3 触发后的响应流程:

┌─────────────────────────────────────────────────────────┐
│ 1. NORMAL → ALERT                                       │
│    • 增强监控模式                                        │
│    • 记录所有操作到审计日志                              │
│    • 发送警报通知（Windows窗口）                         │
│    • 等待时间：即时                                      │
├─────────────────────────────────────────────────────────┤
│ 2. ALERT → ENCRYPTING (批量操作超阈值触发)               │
│    • 加密保护目录下的所有敏感文件                        │
│    • 使用 AES-256-GCM 加密                              │
│    • 密码由管理员设置                                    │
│    • 超时时间：30秒（由 alert_timeout_seconds 控制）     │
│    • v2.1: 倒计时期间暂停所有事件处理                   │
├─────────────────────────────────────────────────────────┤
│ 3. ENCRYPTING → WIPING                                   │
│    • 安全擦除原文件（DOD_5220标准，7次覆写）             │
│    • 防止数据恢复                                        │
│    • 记录擦除日志                                        │
├─────────────────────────────────────────────────────────┤
│ 4. WIPING → DELETING                                    │
│    • 删除临时文件和缓存                                  │
│    • 清理系统痕迹                                        │
├─────────────────────────────────────────────────────────┤
│ 5. DELETING → LOCKED                                    │
│    • 系统锁定                                            │
│    • 禁止所有文件操作                                    │
│    • 等待管理员输入密码解锁                              │
│    • 恢复等待时间：30秒                                  │
└─────────────────────────────────────────────────────────┘
```

**v2.1+ 紧急协议增强**：
- **精准终止**：Tier-2 紧急协议中 TERMINATE 动作仅终止事件贡献最多的单个进程 PID（`GetTopContributorPid()`），explorer.exe/dwm.exe 等 11 个核心系统进程受保护不会被终止
- **一键解锁**：v2.5 新增 GuardianC 文件管理面板，管理员可通过托盘右键→文件管理→输入密码批量解密 `.gs` 文件

---

## 五、阈值配置参数

### 5.1 配置文件格式 (guardian_config.yaml)

```yaml
detection:
  alert_timeout_seconds: 30        # ALERT 阶段等待时间（秒）
  thresholds:
    tier1:                         # 保护协议阈值（加密+锁定，可恢复）
      file_write_count: 10         # 批量文件写入阈值
      file_write_window_seconds: 5 # 时间窗口（秒）
      file_delete_count: 5
      file_delete_window_seconds: 5
      file_compress_count: 50      # 批量压缩阈值
      file_compress_window_seconds: 5
      file_network_transfer_count: 10
      file_network_transfer_window_seconds: 5
      data_transfer_mb: 1          # 数据传输阈值（MB）
    
    # 进程行为阈值
    process_termination_count: 2  # 进程终止次数阈值

# 管理员密码（加密存储）
admin:
  password_hash: ""  # SHA-256 哈希值
  unlock_timeout_seconds: 30

# 日志配置
logging:
  path: "C:\\ProgramData\\GuardianShield\\logs"
  format: "json"
  retention_days: 7
  daily_rotation: true

# 保护路径
protection:
  directories:
    - path: "D:\\Projects\\CoreProject"
      recursive: true
      priority: HIGH
    - path: "D:\\Projects\\SharedLibs"
      recursive: true
      priority: MEDIUM

# 白名单进程
whitelist:
  processes:
    - name: "devenv.exe"
      description: "Visual Studio"
      permissions: [READ, WRITE]
    - name: "code.exe"
      description: "VS Code"
      permissions: [READ, WRITE]
```

### 5.2 外部配置文件机制

- 配置文件作为"钥匙"，每次开机后读取
- 如果未读取到外部配置，使用首次读取到的策略
- 配置文件一般不放在本机，由管理员携带（U盘/网络共享）

---

## 六、日志记录规范

### 6.1 日志格式 (JSON)

```json
{
  "timestamp": "2026-03-02T12:34:56.789Z",
  "event_type": "FILE_DELETE",
  "threat_level": "LEVEL_0",
  "response_action": "LOG",
  "file_path": "D:\\Projects\\CoreProject\\main.cpp",
  "process_name": "explorer.exe",
  "process_id": 1234,
  "user": "DOMAIN\\username",
  "details": {
    "operation": "delete",
    "file_size": 1024,
    "file_hash": "sha256:abc123..."
  }
}
```

### 6.2 日志文件命名

```
C:\ProgramData\GuardianShield\logs\
├── guardian_2026-03-01.json
├── guardian_2026-03-02.json
└── guardian_2026-03-03.json
```

### 6.3 日志保留策略

- 每天生成一个新日志文件
- 保留最近 7 天的日志
- 超过 7 天的日志自动清理

---

## 七、系统解锁机制

### 7.1 解锁流程

1. 系统锁定后，显示解锁对话框
2. 管理员输入密码
3. 密码验证通过后，系统恢复正常状态
4. 记录解锁事件到日志

### 7.2 密码存储

- 密码以 SHA-256 哈希形式存储
- 首次运行时设置管理员密码
- 密码存储在配置文件中

---

## 八、开机自启配置

### 8.1 GuardianA/B (Windows 服务)

- 服务启动类型：`SERVICE_AUTO_START`
- 系统启动后自动运行

### 8.2 GuardianC (用户程序)

- 添加到注册表 Run 键：`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- 用户登录后自动运行，无窗口，后台运行

---

## 九、卸载方案

### 9.1 卸载步骤

1. 停止所有 Guardian 进程
2. 删除 Windows 服务
3. 删除注册表启动项
4. 删除安装文件
5. 可选：删除配置和日志文件

### 9.2 卸载脚本

```powershell
# 停止并删除服务
sc stop WinDefenderCore; sc delete WinDefenderCore
sc stop WinDefenderHelper; sc delete WinDefenderHelper
taskkill /F /IM winmon.exe

# 删除注册表启动项
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "GuardianC" -ErrorAction SilentlyContinue

# 删除安装文件
Remove-Item -Path "C:\Program Files\GuardianShield" -Recurse -Force

# 可选：删除配置和日志
Remove-Item -Path "C:\ProgramData\GuardianShield" -Recurse -Force
```

---

## 十、版本历史

| 版本 | 日期 | 说明 |
|------|------|------|
| 1.0.0 | 2026-03-02 | 初始版本，基础保护功能 |
| 2.0.0 | 2026-03-03 | 两级阈值、IPC 告警路由、全屏锁屏、MSI 安装包 |
| 2.1.0 | 2026-03-05 | 12 项结构性修复：EventId 11 降级、IPC 乒乓消除、进程事件降级、精准终止 |
| 2.5.0 | 2026-03-06 | ETW 生命周期修复（5 项）、IPC 通知可靠性 v2、文件管理面板、一键解锁 |
| 3.0.0 | 2026-03-09 | 移除 FileLocker（BLOCK/LOCK_FILE），事件响应可配置化（event_responses YAML 节） |
| 3.1.0 | 2026-03-10 | 14 项功能正确性缺陷修复 |
| 3.2.0 | 2026-03-10 | BLOCK 响应动作 — 内核级文件操作拦截 |
| 3.3.0 | 2026-03-18 | FILE_MOVE 实现 + 7 类型注释 + 响应动作审计 (192 测试) |
