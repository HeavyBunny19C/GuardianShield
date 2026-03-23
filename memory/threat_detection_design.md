# 威胁检测设计文档 (Threat Detection Design)

GuardianShield v3.3.0 的威胁检测系统完整规格说明。

**当前版本检测范围**: 7 种文件操作 — 写入 (FILE_WRITE)、压缩 (FILE_COMPRESS)、删除 (FILE_DELETE)、创建 (FILE_CREATE)、重命名/同卷移动 (FILE_RENAME)、跨卷移动 (FILE_MOVE，已实现 v3.3 via CREATE+DELETE 事件关联)、复制 (FILE_CREATE+FILE_WRITE 组合)。以下 7 种类型当前未实现：FILE_READ、FILE_SET_INFO、PROCESS_INJECT、PROCESS_DEBUG、NETWORK_CONNECT、NETWORK_SEND、NETWORK_RECV。

**GuardianA/B 对称性**: v3.3.0 起 GuardianB 的 HandleDriverEvent 与 GuardianA 行为对齐 — 空路径过滤、目录级过滤、批量触发不短路（先日志+响应再协议）、精准终止 (GetTopContributorPid)、ResponseActionCombinedToString 日志。

---

## 1. 系统概览

### 事件管道数据流

```
内核驱动 (GuardFilter)        ETW (Microsoft-Windows-Kernel-File)
         |                                    |
         v                                    v
    DriverClient              GuardianA (EtwEventCallback)  ← v2.1: ETW 采集移至 GuardianA
         |                              |
         |    +----- QueueEvent() ------+
         |    |
         v    v
    GuardianA (m_eventQueue)
              |
              v
    EventProcessingThread
         |         |
         |    IPC → GuardianB (DRIVER_EVENT)  ← v2.1: 从 ETW 回调移到此处
         |         |
         |         v
         |    ThreatEvaluator.CheckBatchThresholds
         |         |          |          |
         |       NONE       TIER_1     TIER_2
         |         |          |          |
         |         v          v          v
         |     继续      Protection   Emergency
         |     单事件     Protocol     Protocol
         |     评估
         v
    AssessThreat -> ExecuteResponse
    (由 event_responses 配置驱动: LOG/ALERT_USER/TERMINATE/ENCRYPT/BLOCK)
```

### 事件来源

| 来源 | 方式 | 内容 |
|------|------|------|
| GuardFilter 内核驱动 | DriverClient (m_driverThread) | 文件系统操作事件 (FILE_CREATE, FILE_WRITE, FILE_DELETE 等) |
| ETW 提供器 | GuardianA 自身 (EtwEventCallback → QueueEvent) | 用户态文件事件 + 启发式分类（v2.1 起 ETW 采集由 GuardianA 直接执行，不再经 GuardianC 转发） |

---

## 2. 三层响应架构

### 第一层: 单事件响应

每个事件独立评估，只执行非破坏性动作。

| 事件类型 | 威胁等级 | 响应动作 | 说明 |
|---------|---------|---------|------|
| FILE_READ | LEVEL_0 | LOG | 正常读取 [预留] |
| FILE_CREATE | LEVEL_0 | LOG | 正常创建 |
| PROCESS_CREATE | LEVEL_0 | LOG | 正常进程启动 |
| FILE_WRITE | LEVEL_1 | LOG + ALERT_USER | 文件修改监控 |
| FILE_RENAME | LEVEL_1 | LOG + ALERT_USER | 文件重命名监控 |
| FILE_SET_INFO | LEVEL_1 | LOG + ALERT_USER | 文件属性修改 [预留] |
| NETWORK_CONNECT | LEVEL_1 | LOG + ALERT_USER | 网络连接监控 [预留] |
| NETWORK_SEND | LEVEL_1 | LOG + ALERT_USER | 网络发送监控 [预留] |
| NETWORK_RECV | LEVEL_1 | LOG + ALERT_USER | 网络接收监控 [预留] |
| PROC_TERMINATE | LEVEL_0 | LOG | 进程终止（v2.1 降级，避免噪声） |
| DRIVER_LOAD | LEVEL_0 | LOG | 驱动加载（v2.1 降级） |
| DRIVER_UNLOAD | LEVEL_0 | LOG | 驱动卸载（v2.1 降级） |
| FILE_MOVE | LEVEL_1 | LOG + ALERT_USER | 文件移动监控 [已实现 v3.3] |
| FILE_DELETE | LEVEL_1 | LOG + ALERT_USER | 文件删除监控 |
| FILE_COMPRESS | LEVEL_1 | LOG + ALERT_USER | 文件压缩监控 |
| FILE_NETWORK_TRANSFER | LEVEL_1 | LOG + ALERT_USER | 网络传输监控 |
| PROCESS_INJECT | LEVEL_2 | LOG + ALERT_USER + TERMINATE | 注入攻击，终止进程 [预留] |
| PROCESS_DEBUG | LEVEL_2 | LOG + ALERT_USER + TERMINATE | 调试器，终止进程 [预留] |

**关键原则**: 单事件响应动作由 `guardian_config.yaml` 的 `detection.event_responses` 节驱动（可配置 LOG/ALERT_USER/TERMINATE/ENCRYPT/BLOCK）。WIPE 和 LOCKDOWN 仅由批量协议触发，单事件配置中自动过滤。BLOCK 需 GuardFilter 驱动，驱动未加载时跳过（不降级为 TERMINATE）。

### 第二层: 保护协议 (Tier 1)

当批量操作超过 Tier 1 阈值时触发。

**状态流转**:
```
NORMAL -> ALERT -> (等待 alert_timeout_seconds) -> ENCRYPTING -> LOCKED
                      |
                      v (管理员取消)
                   NORMAL
```

**动作序列**:
1. 进入 ALERT 状态，通过 IPC 发送告警到 GuardianC
2. 等待 `alert_timeout_seconds` 秒（默认 30 秒），每秒检查管理员是否取消
3. 如果未取消：加密所有保护目录中的文件
4. 进入 LOCKED 状态

**特点**: 可恢复。不执行擦除和删除。管理员可通过锁屏输入密码解锁并自动解密。

### 第三层: 紧急协议 (Tier 2)

当批量操作超过 Tier 2 阈值或未授权设备启动时触发。

**状态流转**:
```
NORMAL -> ALERT -> (等待) -> ENCRYPTING -> WIPING -> DELETING -> LOCKED
             |
             v (管理员取消)
          NORMAL

未授权设备:
NORMAL -> ENCRYPTING -> WIPING -> DELETING -> LOCKED  (跳过 ALERT)
```

**动作序列**:
1. 进入 ALERT 状态（未授权设备跳过此步）
2. 等待 `alert_timeout_seconds` 秒，管理员可取消（未授权设备不等待）
3. 加密所有保护目录中的文件
4. DOD 5220.22-M 7-pass 安全擦除
5. 清理系统痕迹（剪贴板、最近文档、临时文件）
6. 锁定系统

**特点**: 不可逆。数据被加密后擦除再删除。

---

## 3. 两级阈值配置

### Tier 1 阈值（保护协议）

| 指标 | 默认值 | 时间窗口 |
|------|--------|---------|
| file_write_count | 10 | 5 秒 |
| file_compress_count | 50 | 5 秒 |
| file_delete_count | 5 | 5 秒 |
| file_create_count | 15 | 5 秒 |
| file_rename_count | 10 | 5 秒 |
| file_move_count | 10 | 5 秒 |
| file_network_transfer_count | 10 | 5 秒 |
| data_transfer_mb | 1 MB | 5 秒 |
| process_termination_count | 50 | 5 秒 |

### Tier 2 阈值（紧急协议）

| 指标 | 默认值 | 时间窗口 |
|------|--------|---------|
| file_write_count | 50 | 10 秒 |
| file_compress_count | 250 | 10 秒 |
| file_delete_count | 20 | 10 秒 |
| file_create_count | 50 | 10 秒 |
| file_rename_count | 50 | 10 秒 |
| file_move_count | 50 | 10 秒 |
| file_network_transfer_count | 40 | 10 秒 |
| data_transfer_mb | 10 MB | 10 秒 |
| process_termination_count | 200 | 10 秒 |

### 其他参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| alert_timeout_seconds | 300 | ALERT 阶段等待管理员取消的超时时间（YAML 默认 300 秒，代码内置默认 30 秒） |

---

## 4. ETW 事件采集与分类

### ETW 生命周期管理 (v2.1)

ETW 采集由 GuardianA 服务直接执行（SYSTEM 权限），不再通过 GuardianC 转发。生命周期防护措施：

| # | 措施 | 实现 |
|---|------|------|
| 1 | 防御性清理 | `InitializeEtw()` 开头调用 `ShutdownEtw()`，清理可能的孤儿会话 |
| 2 | 原子句柄 | `m_traceHandle` 为 `std::atomic<TRACEHANDLE>`，线程安全访问 |
| 3 | 活性守护 | `HeartbeatThread` 监控 `m_eventsProcessed`，60 秒无事件自动重启 ETW |
| 4 | 自动恢复 | `EtwCollectionThread` 内 `while(m_etwRunning)` 循环，`ProcessTrace` 异常退出后 2 秒延迟重试 |

### 诊断计数器

ETW 回调中维护以下诊断数据：
- `s_diagCounts` — 回调被调用的总次数
- `s_diagDropped` — 被过滤/丢弃的事件总数
- `s_diagDroppedById[64]` — 按 EventId 分桶的丢弃计数

### opcode 映射 (Microsoft-Windows-Kernel-File)

| opcode | 映射事件类型 |
|--------|-------------|
| 0 | FILE_CREATE |
| 32 | FILE_WRITE |
| 35 | FILE_DELETE |
| 36 | FILE_RENAME |
| 其他 | FILE_READ (默认，当前未实现 [预留]) |

### 启发式进程名重分类

对所有文件事件，通过 `QueryFullProcessImageNameW()` 查询进程名后重分类：

**压缩工具 -> FILE_COMPRESS**:
- `7z`, `WinRAR`, `winrar`, `zip`, `tar`

**网络传输工具 -> FILE_NETWORK_TRANSFER**:
- `scp`, `sftp`, `curl`, `wget`, `rclone`, `OneDrive`, `Dropbox`

匹配方式：进程完整路径中包含上述关键字 (`wstring::find`)。

---

## 5. 告警通知路径

```
GuardianA (Session 0)                    GuardianC (User Session)
     |                                        |
     |  SendAlert()                           |
     |    构建 AlertNotification 结构体         |
     |    IPC SendToNode(GUARDIAN_C,           |
     |        ALERT_NOTIFICATION, ...)         |
     |  ---------------------------------->   |
     |                                  HandleGuardianMessage()
     |                                    解析 AlertNotification
     |                                    ShowBalloonNotification()
     |                                    -> 气球通知显示在桌面
     |                                    -> MessageBeep 音频回退
```

### IPC 通信优化 (v2.1)

- `SendToNode` 使用 `m_sendMutex[3]` 按目标节点加锁（非全局锁）
- `m_sequence` 改为 `std::atomic<uint32_t>` 确保线程安全
- `tryConnect` 单次连接 300ms 超时，避免阻塞
- 心跳顺序：先发 GuardianC，后发 GuardianB（GuardianC 负责用户通知，优先保障）

### 通知可靠性 (v2.1)

- `ShowBalloonNotification` 检查 `Shell_NotifyIconW` 返回值并记录日志
- 无论视觉通知成功与否，均调用 `MessageBeep(MB_ICONWARNING/MB_ICONERROR)` 提供音频回退
- 首次收到 GuardianA/GuardianB 心跳时记录诊断日志

**AlertNotification 结构体**:
- `level` (uint8_t): 威胁等级
- `reserved` (uint8_t[3]): 对齐填充
- `process_id` (uint32_t): 触发事件的进程 ID
- `message` (char[256]): 告警消息 (UTF-8)
- `file_path` (wchar_t[MAX_PATH_LENGTH]): 相关文件路径

---

## 6. 管理员取消机制

### 保护协议取消
- 在 ALERT 阶段，`StartProtectionCountdown()` 每秒检查 `m_emergencyMode` 标志
- 管理员通过锁屏界面输入密码后，系统设置 `m_emergencyMode = false`
- 下一秒循环检测到标志变化，取消协议，恢复 NORMAL 状态

### 紧急协议取消
- 同样的机制，在 `StartEmergencyCountdown()` 中检查
- 一旦进入 ENCRYPTING 阶段，即不可取消

### 未授权设备
- `skipAlert = true`，完全跳过 ALERT 阶段
- 直接进入 ENCRYPTING，不给取消机会

---

## 7. GuardianB 故障转移行为

### Backup 模式 (GuardianA 健康)
- 接收到的 DRIVER_EVENT 直接转发给 GuardianA
- 不进行威胁评估
- 只做心跳监控

### Primary 模式 (GuardianA 失效)
- 当连续 3 次心跳超时 (3 x 500ms = 1.5s)，GuardianB 提升为 Primary
- 使用相同的 ThreatEvaluator 类和两级阈值逻辑
- 独立执行保护协议和紧急协议
- 当 GuardianA 恢复心跳，GuardianB 降级回 Backup

---

## 8. 代码定位

| 功能 | 文件 | 函数 |
|------|------|------|
| 事件管道入口 (IPC) | guardian_a.cpp | Initialize() 中的 lambda |
| 事件管道入口 (驱动) | guardian_a.cpp | DriverReadThread() |
| 事件队列 | guardian_a.cpp | QueueEvent() |
| 事件处理线程 | guardian_a.cpp | EventProcessingThread() |
| 事件分发 | guardian_a.cpp | HandleDriverEvent() |
| 两级阈值检查 | threat_evaluator.cpp | CheckBatchThresholds() |
| 单事件评估 | guardian_a.cpp | AssessThreat() |
| 响应执行 | guardian_a.cpp | ExecuteResponse() |
| 保护协议 | guardian_a.cpp | TriggerProtectionProtocol() + StartProtectionCountdown() |
| 紧急协议 | guardian_a.cpp | TriggerEmergencyProtocol() + StartEmergencyCountdown() |
| 告警发送 | guardian_a.cpp | SendAlert() |
| ETW 采集初始化 | guardian_a.cpp | InitializeEtw() (含防御性 ShutdownEtw) |
| ETW 采集线程 | guardian_a.cpp | EtwCollectionThread() (while 循环 + 自动恢复) |
| ETW 回调 | guardian_a.cpp | EtwEventCallback() (含 s_diagCounts/s_diagDropped) |
| ETW 活性守护 | guardian_a.cpp | HeartbeatThread() 中的 etwStallTicks 监控 |
| 告警接收 | guardian_c.cpp | HandleGuardianMessage() ALERT_NOTIFICATION case |
| 通知显示 | guardian_c.cpp | ShowBalloonNotification() + MessageBeep 回退 |
| 阈值配置 (yaml-cpp) | config.cpp | LoadYaml() detection.thresholds 解析 |
| 阈值配置 (简易解析) | config.cpp | LoadSimple() 含 excludeFileTypes/includeFileTypes/whitelist 解析 |
| 事件记录 | threat_evaluator.cpp | RecordEvent() |
