> ⚠️ **归档文档** — 本文档为早期设计文档，部分内容与 v3.3.0 实现不一致。
# GuardianShield 源代码保护系统设计文档

> **⚠ 历史文档**: 本文档为早期系统设计文档，部分内容已过时。以 `FUNCTIONAL_SPEC.md` 和 `guardian_config.yaml` 为准。

**版本**: 3.3.0  
**最后更新**: 2026-03-18

---

## 一、系统架构

### 1.1 组件概述

| 组件 | 类型 | 运行方式 | 职责 |
|------|------|----------|------|
| GuardianA | Windows 服务 | 自动启动（SYSTEM权限） | 主控制器：威胁评估、ETW 事件采集、决策、触发紧急协议 |
| GuardianB | Windows 服务 | 自动启动（SYSTEM权限） | 备份控制器：监控 GuardianA、文件监控 |
| GuardianC | 用户程序 | 开机自启（后台运行） | 监控节点：系统托盘、用户通知、文件管理面板、一键解锁 |

---

## 二、文件操作行为与响应

### 2.1 单文件操作响应

| 操作行为 | 响应动作 | 说明 |
|----------|----------|------|
| 文件读取 | LOG | 仅记录到日志 |
| 文件增加 | LOG | 仅记录到日志 |
| 文件修改 | LOG + ALERT_USER | 记录+告警（可配置） |
| 文件重命名 | LOG + ALERT_USER + BLOCK | 记录+告警+内核拦截（v3.2，可配置） |
| 文件移动 | LOG + ALERT_USER + BLOCK | 记录+告警+内核拦截（v3.3 已实现，通过 CREATE+DELETE 事件关联检测跨卷移动） |
| 文件删除 | LOG + ALERT_USER | 记录+告警（可配置） |
| 文件压缩 | LOG + ALERT_USER | 记录+告警（可配置） |
| 文件网络传输 | LOG + ALERT_USER | 记录+告警（可配置） |

### 2.2 批量操作响应（两级阈值）

| 触发条件 | 协议类型 | 响应动作 | 可恢复性 |
|----------|----------|----------|----------|
| 批量操作超过 tier1 阈值 | 保护协议 | ALERT -> ENCRYPTING -> LOCKED | 可恢复 |
| 批量操作超过 tier2 阈值 | 紧急协议 | ALERT → ENCRYPT → WIPE → DELETE → LOCK | 不可逆 |
| 未授权设备启动 | 紧急协议 | ENCRYPT → WIPE → DELETE → LOCK（跳过 ALERT） | 不可逆 |

### 2.3 其他事件响应

| 事件类型 | 威胁等级 | 响应动作 | 说明 |
|----------|----------|----------|------|
| FILE_SET_INFO | LEVEL_1 | LOG + ALERT_USER | 文件属性修改 [预留/未实装] |
| PROCESS_CREATE | LEVEL_0 | LOG | 进程创建 |
| PROCESS_TERMINATE | LEVEL_0 | LOG | 进程终止（v2.1 降级） |
| PROCESS_INJECT | LEVEL_2 | LOG + ALERT_USER + TERMINATE | 进程注入攻击 [预留/未实装] |
| PROCESS_DEBUG | LEVEL_2 | LOG + ALERT + TERMINATE | 调试器附加 [预留/未实装] |
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
| BLOCK | 0x10 | 内核级 I/O 拦截：GuardFilter.sys minifilter 回调返回 STATUS_ACCESS_DENIED，阻止文件重命名/移动/删除/写入（按策略位掩码）。驱动未加载时跳过（不降级为 TERMINATE） |
| ENCRYPT | 0x20 | 加密保护文件（AES-256 双模式: ≤100MB GCM; >100MB CBC+HMAC。密钥: PBKDF2-SHA256） |
| WIPE | 0x40 | 安全擦除文件（DOD_5220标准，7次覆写） |
| LOCKDOWN | 0x80 | 系统锁定，禁止所有操作，需管理员密码解锁 |

---

## 四、紧急协议执行流程

### 4.1 文件移动/压缩触发（单事件响应）

```
检测到文件移动/压缩
    ↓
记录日志 + 告警通知
    ↓
（如配置了 ENCRYPT）加密触发文件
```

> **v3.0+ 变更**: 单事件响应动作由 `guardian_config.yaml` 的 `detection.event_responses` 节配置。默认为 LOG + ALERT_USER，可配置添加 BLOCK（v3.2 内核级拦截）、TERMINATE 或 ENCRYPT。

### 4.2 网络传输触发（ENCRYPT + WIPE）

```
检测到网络传输
    ↓
加密保护目录下所有敏感文件（AES-256 双模式: ≤100MB GCM; >100MB CBC+HMAC）
    ↓
安全擦除原文件（DOD_5220标准）
    ↓
删除临时文件和缓存
    ↓
系统锁定
    ↓
等待管理员密码解锁
```

### 4.3 批量操作触发

```
检测到批量操作（复制/压缩/传输）
    ↓
增强监控模式
    ↓
记录所有操作到审计日志
    ↓
发送警报通知（Windows窗口）
    ↓
根据操作类型执行相应响应：
  - 批量复制/压缩：ENCRYPT（保护协议）
  - 批量网络传输：ENCRYPT + WIPE（紧急协议）
```

---

## 五、阈值配置参数

### 5.1 配置文件位置

配置文件使用"钥匙"机制，管理员将 `guardian_config.yaml` 放入配置目录后重启服务，系统读取后自动删除。
默认路径: `C:\ProgramData\GuardianShield\config\guardian_config.yaml`

### 5.2 配置文件格式

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

# 管理员密码（SHA-256 哈希）
admin:
  password_hash: ""  # 密码哈希值

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

---

## 六、日志系统

### 6.1 日志配置

- 存储位置：`C:\ProgramData\GuardianShield\logs`
- 日志格式：JSON
- 保留天数：7 天
- 按天分割：每天生成一个新日志文件
- 文件命名：`guardian_YYYYMMDD.json`

### 6.2 日志内容

```json
{
  "timestamp": "2026-03-02T12:00:00.000Z",
  "event_type": "FILE_DELETE",
  "threat_level": "LEVEL_1",
  "response_action": "LOG",
  "file_path": "D:\\Projects\\CoreProject\\test.cpp",
  "process_id": 1234,
  "process_name": "explorer.exe",
  "user": "DOMAIN\\user",
  "details": "File deleted by user"
}
```

---

## 七、系统解锁机制

### 7.1 解锁流程

1. 系统锁定后显示解锁对话框
2. 管理员输入密码
3. 密码验证通过
4. 系统恢复正常状态
5. 记录解锁事件到日志

### 7.2 密码管理

- 密码以 SHA-256 哈希形式存储
- 首次运行时设置管理员密码
- 密码存储在配置文件中

---

## 八、开机自启配置

### 8.1 GuardianA/B (Windows 服务)

- 服务启动类型：`SERVICE_AUTO_START`
- 系统启动后自动运行

### 8.2 GuardianC (用户程序)

- MSI 安装时注册表启动项：`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsMonitor`
- 手动安装时：`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\GuardianC`
- 值：`"C:\Program Files\GuardianShield\winmon.exe" --silent`
- 用户登录后自动运行
- 无窗口，后台运行

---

## 九、卸载方案

### 9.1 卸载步骤

1. 停止所有 Guardian 进程
2. 删除 Windows 服务
3. 删除注册表启动项
4. 删除安装文件
5. 可选：删除配置和日志文件

### 9.2 卸载命令

```powershell
# 停止并删除服务
sc stop WinDefenderCore; sc delete WinDefenderCore
sc stop WinDefenderHelper; sc delete WinDefenderHelper
taskkill /F /IM winmon.exe

# 删除注册表启动项（MSI 安装）
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsMonitor" -ErrorAction SilentlyContinue
# 删除注册表启动项（手动安装）
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "GuardianC" -ErrorAction SilentlyContinue

# 删除安装文件
Remove-Item -Path "C:\Program Files\GuardianShield" -Recurse -Force

# 可选：删除配置和日志
Remove-Item -Path "C:\ProgramData\GuardianShield" -Recurse -Force
```

---

## 十、开发任务清单

### 10.1 代码修改

| 任务 | 文件 | 优先级 |
|------|------|--------|
| 添加新事件类型 | common_types.h | 高 |
| 修改威胁评估逻辑 | threat_evaluator.cpp | 高 |
| 实现文件压缩检测 | threat_evaluator.cpp | 高 |
| 实现网络传输检测 | threat_evaluator.cpp | 高 |
| 实现日志按天分割 | logger.cpp | 中 |
| 实现日志7天保留 | logger.cpp | 中 |
| ~~实现管理员密码解锁~~ | ~~emergency_executor.cpp~~ → guardian_a.cpp (已实现) | ~~高~~ 已完成 |
| 实现外部配置文件读取 | config.cpp | 中 |
| GuardianC 开机自启 | 安装脚本 | 中 |

---

## 十一、版本历史

| 版本 | 日期 | 说明 |
|------|------|------|
| 3.2.0 | 2026-03-10 | BLOCK 响应动作 — 内核级文件操作拦截 |
| 3.3.0 | 2026-03-18 | FILE_MOVE 实现 (CREATE+DELETE 关联) + 7 类型注释 + 响应动作审计 + 192 测试 |

---

**文档完成，准备开始代码实现。**
