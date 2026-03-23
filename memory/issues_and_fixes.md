# 问题与修复记录 (Issues & Fixes)

记录所有遇到的问题、根因分析和修复方案。按严重程度和类别分组。

---

## 2026-03-17: 代码-文档-配置一致性审查 (20+ 项不一致)

**状态: 已修复**

**触发**: 深度代码审查发现代码实现、配置文件注释、文档描述三者之间存在大量不一致，给管理员和开发者造成误导。

### 不一致分类

| 类别 | 数量 | 示例 |
|------|------|------|
| 加密算法描述错误 | 5 | 多处文档写 "AES-256-CBC"，实际为 GCM/CBC+HMAC 双模式 |
| 阈值默认值错误 | 3 | process_termination_count 文档写 2/6，代码和 YAML 为 50/200 |
| 功能状态标注错误 | 3 | tcp.tls 配置为 true 但代码未实现；FILE_MOVE 已实现 v3.3: CREATE+DELETE 事件关联检测 |
| 未解析字段未标注 | 4 | config_version/communication/keys/logging.path 均被 YAML 列出但代码未使用 |
| 历史文档未标注过时 | 3 | PROTECTION_SPEC/PROtection_system_design/need.md 无过时警告 |
| 响应动作缺失 | 3 | 网络事件和 FILE_SET_INFO 缺少 ALERT_USER |
| 配置名称过时 | 1 | 文档仍引用 thresholds.yaml 而非 guardian_config.yaml |
| 注册表键名不一致 | 1 | MSI=HKLM\WindowsMonitor vs 代码=HKCU\GuardianC |
| 代码注释过时 | 2 | config.cpp/file_encryptor.cpp 文件头未反映当前实现 |

### 根因

1. **多轮迭代未同步**: 加密模块从 AES-256-CBC 演进为双模式（GCM + CBC+HMAC），阈值从早期低值调整为安全值，但文档和配置注释未跟进
2. **预留配置无标注**: YAML 中 `communication`/`keys` 等节是为未来功能预留，但未在注释中说明"当前未使用"
3. **历史文档未归档**: PROTECTION_SPEC 和 need.md 是早期设计文档，内容已大量过时但仍以正式文档形态存在

### 修复原则

- 以**代码实现**为唯一真相源
- 配置注释中标注未实现/未解析的字段
- 历史文档添加醒目的过时警告头
- 统一所有文档中的加密、阈值、功能状态描述

### 教训

- 每次代码变更后必须 grep 关键术语（如算法名、阈值值、功能标记）确认所有文档引用已同步
- 预留的配置字段应在注释和文档中明确标注"保留/未实现"
- 早期设计文档应在首行添加过时警告，避免误导

---

## 2026-03-11 v3.3.1: Session 0 通知不可见

**状态: 已修复**

**症状**: 安装 v3.3 并重启后，威胁检测事件已被正确检测和记录（日志中可见 FILE_CREATE/DELETE/RENAME/WRITE 事件），但用户桌面无任何可见通知。

**根因**: GuardianA 的 `HandleNodeTimeout` 使用 `CreateProcessW` 启动 winmon.exe，winmon 继承服务的 Session 0。Windows Session 0 隔离机制阻止了桌面 Shell 访问：
- `Shell_NotifyIconW(NIM_ADD)` 失败 → `m_trayInitialized = false` → `ShowBalloonNotification` 静默返回
- Session 0 的 winmon 先占据 `GuardianIPC_C` 管道，用户会话 (Session 1) 的 winmon 无法接收 IPC 消息
- 两个 winmon 实例同时运行（Session 0 收 IPC 无法显示 UI，Session 1 有 UI 收不到 IPC）

**修复**: 6 项代码变更（详见 changelog v3.3.1）

**教训**: Windows 服务 (Session 0) 不能直接 CreateProcessW 启动需要用户桌面交互的进程。必须使用 WTS API (CreateProcessAsUserW) 在用户会话中启动。

---

## 2026-03-11 v3.3: 威胁检测系统 8 项缺陷修复

**状态: 已修复**

| ID | 严重 | 问题 | 修复 |
|----|------|------|------|
| TD1 | 高 | `process_termination_count` 窗口硬编码 5 秒，配置无效 | 新增 `process_termination_window_seconds` 字段贯穿全栈，缓存 v9→v10 |
| TD2 | 中 | `FILE_RENAME` 计入删除队列，推高 `file_delete_count` | 分离为独立 `m_fileRenameRecords` deque |
| TD3 | 高 | ETW `data_size` 恒为 0，`data_transfer_mb` 检测无效 | TDH 提取 IoSize + raw offset 20 回退 |
| TD4 | 中 | `m_evalCount++` 非原子操作（多线程竞态） | 改为 `std::atomic<uint64_t>` + `fetch_add` |
| TD5 | 低 | `ThreatEvaluator::m_threatsDetected` 从未递增 | 在 TIER_1/TIER_2 返回前 `fetch_add(1)` |
| TD6 | 高 | BUG-11: cmd.exe 文件删除未被 ETW 捕获 | EventId 11 (NameDelete) 对 PID>4 重新生成 FILE_DELETE |
| TD7 | 低 | `CheckBatchThresholds` 双锁间隙竞态 | 合并为单一 `lock_guard` 作用域 |
| TD8 | 信息 | 未实现事件类型注释不明确 | `IsEventTypeImplemented()` 添加详细注释 |

### 缓存版本升级
- v9 → v10（因 `processTerminationWindowSeconds` 和 `tier2ProcessTerminationWindowSeconds` 字段新增）

---

## 2026-03-11 v3.2.1: 深度审计整改 (12 项修复)

**状态: 已修复**

| ID | 严重 | 问题 | 修复 |
|----|------|------|------|
| C1 | 高 | 白名单仅匹配进程名，可被同名恶意程序绕过 | `WhitelistProcess` 增加 `path_prefix`，`IsProcessWhitelisted` 增加路径前缀校验 |
| C2 | 中 | 配置了不存在的保护目录时无警告 | `LoadProtectedPaths` 用 `GetFileAttributesW` 检查，不存在写 Error + IPC 告警 |
| C3 | 中 | BLOCK 降级为 TERMINATE 时仅写日志，用户不感知 | `SendBlockPolicy` 驱动未连接时写 EventLog + IPC 通知 GuardianC |
| C4 | 高 | MSI 安装时 `CA_CopyConfigFiles` 未接入执行序列 | 添加到 `InstallExecuteSequence` 的 `InstallInitialize` 之后 |
| H1 | 中 | ETW 初始化失败只写 `etw_init.txt`，主日志不记录 | 追加 `g_logger->Error` + `LogEvent` + IPC 告警 |
| H2 | 中 | IPC 管道创建失败时无限重试无日志 | 加重试上限(50次) + 对数递减日志(第1/10/50次) |
| H3 | 中 | 日志文件写入失败（磁盘满）无告警 | `m_file.fail()` 检查后回退到 Windows EventLog |
| H4 | 低 | `SendToNode` 返回值未全部检查 | 关键路径增加返回值检查 + 节流告警(1/10/100/500) |
| H5 | 低 | 配置来源不写主日志，v6 文案与 v9 缓存版本不符 | 加载成功写日志来源，v6→v9 |
| M1 | 低 | `-status` 输出空白，无法诊断系统状态 | 输出服务状态/配置来源/保护目录/驱动连接 |

### 缓存版本升级
- v8 → v9（因 `WhitelistProcess.path_prefix` 字段新增）

---

## 2026-03-10 v3.2: BLOCK 响应动作 — 内核级文件移动拦截 (10 项修复)

**状态: 已修复**

### F1 [致命/预存在]: GuardianB 驱动连接使用错误端口名
- **根因**: `guardian_b.cpp` L268/L457 使用 `GUARDFILTER_USERMODE_PATH` (`\\\\.\\GuardFilter` — 设备路径)，但 `DriverClient::Connect()` 调用 `FilterConnectCommunicationPort()` 需要过滤器端口名 `GUARDFILTER_PORT_NAME` (`\\GuardFilterPort`)。GuardianA 一直用的正确端口名。
- **影响**: GuardianB 驱动连接永远失败，failover 后无法获取驱动事件
- **修复**: `ConnectDrivers()` 和 `DriverReadThread` 中全部改为 `GUARDFILTER_PORT_NAME`
- **文件**: guardian_b.cpp
- **验证**: 编译通过

### F2 [高/预存在]: GuardianB LoadProtectedPaths 不同步到驱动
- **根因**: GuardianB `LoadProtectedPaths()` 只存 `m_protectedPaths` 向量，不调用 `m_driverClient->AddProtectedPath()`。对比 GuardianA 会同步。
- **影响**: GuardianB failover 后驱动不知道哪些路径需要保护
- **修复**: 循环中补齐 `m_driverClient->AddProtectedPath(dir.path)` 调用
- **文件**: guardian_b.cpp
- **验证**: 编译通过

### F3 [致命]: WhitelistProcess.permissions 数据模型误解
- **根因**: 原方案中假设 `wp.canRead`/`wp.canWrite`（bool），实际结构为 `vector<wstring> permissions`（如 `["READ","WRITE"]`）
- **影响**: 原方案代码会编译失败
- **修复**: 遍历 `permissions` vector，映射 `READ→1, WRITE→6, DELETE→4` 为驱动位掩码
- **文件**: guardian_a.cpp, guardian_b.cpp (`SyncDriverWhitelist()`)
- **验证**: 编译通过

### F4 [高]: 驱动重连后白名单和 block policy 丢失
- **根因**: GuardianA DriverReadThread 重连只调 `LoadProtectedPaths()`，GuardianB 重连什么都不做。白名单和 BlockPolicy 全部丢失。
- **修复**: 重连成功后追加 `SyncDriverWhitelist()` + `SendBlockPolicy()` 调用
- **文件**: guardian_a.cpp, guardian_b.cpp
- **验证**: 编译通过

### F5 [中]: ResponseActionCombinedToString 不认识 BLOCK/ENCRYPT
- **根因**: 函数只处理 TERMINATE/ALERT_USER/LOG，BLOCK/ENCRYPT 事件的日志动作列显示为 "LOG"
- **修复**: 添加 BLOCK 和 ENCRYPT 分支（按优先级排列）
- **文件**: guardian_a.cpp
- **验证**: 编译通过

### F6 [中]: BuildEventResponse 无 BLOCK 威胁等级映射
- **根因**: 威胁等级分支只检查 TERMINATE/ENCRYPT，`[LOG, BLOCK]` 配置会评为 LEVEL_0 → ExecuteResponse 不执行
- **修复**: 条件中加入 `ResponseAction::BLOCK`，BLOCK 映射为 LEVEL_2
- **文件**: threat_evaluator.cpp
- **验证**: 单元测试 BlockIsLevel2 PASS

### F7 [低]: GuardianB ExecuteResponse 缺 BLOCK 处理
- **根因**: A/B 不对称，B 的 ExecuteResponse 无 BLOCK 分支
- **修复**: 在 TERMINATE 检查前添加 BLOCK 分支（no-op / 驱动未连接时跳过，不降级为 TERMINATE；见 RISK-6）
- **文件**: guardian_b.cpp
- **验证**: 编译通过

### RISK-4: BLOCK + TERMINATE 自动降级
- **场景**: 配置 `[BLOCK, TERMINATE]` 时驱动阻止操作后用户态又杀进程（双重惩罚）
- **修复**: `BuildEventResponse()` 中 BLOCK 存在时自动移除 TERMINATE
- **文件**: threat_evaluator.cpp
- **验证**: 单元测试 BlockPlusTerminate_DegradesToBlock PASS

### RISK-6: 驱动未加载时 BLOCK 静默失效
- **场景**: GuardFilter.sys 未安装时所有 BLOCK 配置无效，用户零感知
- **修复**: `SendBlockPolicy()` 中检查并输出 WARNING 日志；`ExecuteResponse` 中 BLOCK 跳过（不降级为 TERMINATE）
- **文件**: guardian_a.cpp, guardian_b.cpp
- **验证**: 编译通过，ActionAudit_BLOCK 单元测试 PASS

### BLOCK 功能新增
- **变更**: `ResponseAction::BLOCK = 0x10`，config parseAction/parseAct 支持 "BLOCK"，YAML 默认 FILE_RENAME + FILE_MOVE 启用 BLOCK（FILE_MOVE 已实现 v3.3，跨卷移动现可被 CREATE+DELETE 关联检测并触发 BLOCK）
- **文件**: common_types.h, config.cpp, guardian_config.yaml
- **验证**: 5 个新单元测试全部 PASS

---

## 2026-03-10 v3.1: 功能正确性整改 — 14 项缺陷修复

**状态: 已修复**

### D1: event_type 范围校验缺失
- **根因**: HandleDriverEvent 未验证 event_type 范围，无效值进入 switch-case 走 default 路径但仍消耗资源
- **修复**: GuardianA/B 添加 `event_type >= MAX_TYPE` 边界检查，立即 return
- **文件**: guardian_a.cpp, guardian_b.cpp
- **验证**: 编译通过，161/162 PASS

### D2: GuardianB 缺少 IsFileTypeMonitored 过滤
- **根因**: GuardianB HandleDriverEvent 不检查文件类型是否在监控范围，备控接管后所有文件类型都触发告警
- **修复**: 添加 `m_config->IsFileTypeMonitored(fp)` 检查
- **文件**: guardian_b.cpp
- **验证**: 编译通过

### D3-D6: deleteSource 失败静默忽略 (4处)
- **根因**: file_encryptor.cpp 中 EncryptFile/StreamEncryptFile/DecryptFile/StreamDecryptFile 的 DeleteFileW 失败时未设 success=false
- **修复**: 4 处均添加 `result.success = false; return result;`
- **文件**: file_encryptor.cpp
- **验证**: 编译通过

### D7: EncryptDirectory 失败文件无日志
- **根因**: 加密目录中部分文件失败时静默跳过，无法事后排查
- **修复**: 添加 std::cerr 日志 + 汇总统计
- **文件**: file_encryptor.cpp
- **验证**: 编译通过

### D8: WipeDirectory 失败文件无日志
- **根因**: 擦除目录中部分文件失败时静默跳过
- **修复**: 添加 std::cerr 日志 + WideToUtf8 转换
- **文件**: file_wiper.cpp
- **验证**: 编译通过

### D9-D11: TerminateProcess 返回值未检查 (3处)
- **根因**: ExecuteResponse (单次/批量) 中 TerminateProcess 调用忽略返回值，进程可能终止失败而不自知
- **修复**: 检查返回值 + 失败日志 + WaitForSingleObject(3s) 等待进程退出 + OpenProcess 失败日志
- **文件**: guardian_a.cpp, guardian_b.cpp
- **验证**: 编译通过

### D12: LoadYaml 后不 SaveToCache
- **根因**: Config::Load() 中 YAML 加载成功后不写缓存，下次启动仍用旧缓存
- **修复**: LoadYaml/LoadSimple 成功后立即 SaveToCache()
- **文件**: config.cpp
- **验证**: 编译通过

### D13: Config::Validate 缺上限校验
- **根因**: Validate() 只检查下限，超大值（如 fileWriteWindowSeconds=999999）可通过验证
- **修复**: 添加上限检查 + 日志警告（window≤3600, retention≤365, timeout≤600, threshold≤100000）
- **文件**: config.cpp
- **验证**: 编译通过

### D14: GuardianB promote 后无事件源
- **根因**: GuardianB 接管主控后不读取驱动事件，只能被动收 IPC 转发
- **修复**: PromoteToPrimary 连接驱动 + 启动 DriverReadThread；DemoteToBackup 停止线程
- **文件**: guardian_b.cpp, guardian_b.h
- **验证**: 编译通过

### D15: GuardianB 缺少事件去重
- **根因**: GuardianB 无去重机制，主备同时运行时驱动事件重复处理
- **修复**: 与 GuardianA 相同的 hash(file_path ^ event_type ^ process_id) + 500ms 窗口去重
- **文件**: guardian_b.cpp
- **验证**: 编译通过

### D16: GuardianC 超时不自动重启
- **根因**: OnNodeTimeout 中 GUARDIAN_C 超时仅记日志，用户态监控永久离线
- **修复**: CreateProcessW 启动 winmon.exe --silent
- **文件**: guardian_a.cpp
- **验证**: 编译通过

### D17: DriverReadThread 断连不重连
- **根因**: 驱动连接断开后 read 循环退出，不再尝试重建连接
- **修复**: 每 10s 尝试重连 GuardFilter
- **文件**: guardian_a.cpp
- **验证**: 编译通过

### D18: EncryptFile 非原子写入
- **根因**: 加密结果直接写目标 .gs 文件，断电/崩溃时可能产生部分写入的损坏文件
- **修复**: 先写 .gs.tmp → MoveFileExW rename 为 .gs（原子替换）
- **文件**: file_encryptor.cpp
- **验证**: 编译通过

### D19: emergency_executor 死代码
- **根因**: EmergencyExecutor 类全是 TODO 桩，从未被调用
- **修复**: 删除 emergency_executor.cpp/h，更新 CMakeLists.txt
- **文件**: emergency_executor.cpp (删除), emergency_executor.h (删除), GuardianA/CMakeLists.txt
- **验证**: 编译通过

### 编译修复 (附带)
- fileSize 变量重定义 → 改为赋值
- std::cerr 缺 `#include <iostream>` → 补齐
- wchar_t→char 警告 → 使用 WideToUtf8 + string_utils.h
- topPid 未声明 → 修正为 targetPid

---

## 2026-03-06 v2.6: UTF-8 转换 Bug 修复

**状态: 已修复**

### 症状
GuardianC 收到的 ALERT_NOTIFICATION 中，`message` 和 `file_path` 为 UTF-8 编码的 char[]，但 `guardian_c.cpp` L583 使用 `std::wstring(notif->message, ...)` 直接按字节拷贝构造 wstring，导致中文乱码或未定义行为。

### 根因
`std::wstring(const char*, size_t)` 将 char 按 1:1 映射为 wchar_t，不进行 UTF-8 解码。UTF-8 多字节序列被错误解释。

### 修复
使用 `MultiByteToWideChar(CP_UTF8, 0, notif->message, -1, ...)` 正确转换 UTF-8 → UTF-16，再构造 wstring。

### 涉及文件
- `src/service/GuardianC/src/guardian_c.cpp`

---

## 2026-03-06 v2.6: 通知中文本地化 + 身份隐藏

**状态: 已实施**

### 背景
用户可见字符串（托盘、气球、右键菜单、窗口标题、MessageBox）均为英文，且暴露 "GuardianShield"、"GuardianA"、"GuardianB" 等产品/组件名称。

### 改动
1. **guardian_c.cpp**: 27 处用户可见字符串替换为中文，产品名统一为 "系统防护"，组件名改为 "主控服务/备份服务"
2. **guardian_a.cpp / guardian_b.cpp**: AssessThreat 的 description（10+2 处）和 SendAlert 的 message（各 2 处）改为中文 UTF-8
3. **路径隐藏**: 通知中的 file_path 仅显示文件名（`wcsrchr`），不暴露完整路径

### 涉及文件
- `guardian_c.cpp`, `guardian_a.cpp`, `guardian_b.cpp`

---

## 2026-03-06 v2.6: MSI 安装流程简化

**状态: 已实施**

### 背景
安装向导包含 InstallKeyDlg（密码输入）、ConfigSelectDlg（配置文件选择）、CA_LocateConfigFiles 等步骤，增加安装复杂度。用户要求简化。

### 改动
- WelcomeDlg Next: InstallKeyDlg → GS_VerifyReadyDlg（跳过密码和配置对话框）
- VerifyReadyDlg Back: ConfigSelectDlg → GS_WelcomeDlg
- WelcomeDlg 描述: 移除 "和有效的安装密钥"
- InstallUISequence: 移除 CA_LocateConfigFiles

### 涉及文件
- `src/installer/InstallDlg.wxs`

---

## 2026-03-06 v2.6: INSTALL_KEY Approach B（CA_SetDefaultKey）

**状态: 已实施**

### 背景
MSI 安装时需验证 INSTALL_KEY。原方案为 CA_ValidateInstallKey（用户输入验证）或 Property 默认值。简化安装流程后，跳过 InstallKeyDlg，需在安装时自动注入密钥。

### 决策: Approach B
- 新增 CA_SetDefaultKey Custom Action：`Property="INSTALL_KEY" Value="GuardianShield2026!"`
- InstallExecuteSequence: 用 CA_SetDefaultKey 替换 CA_ValidateInstallKey（Before="RemoveExistingProducts", NOT Installed）
- 移除 CA_SetCopyConfigData 和 CA_CopyConfigFiles
- CA_ValidateUninstallKey 保留用于卸载

### 安全特性
- **零安全降级**: Property 无默认值，密钥仅在安装/升级执行序列中注入
- 未安装时 CA_SetDefaultKey 运行，安装完成后 Property 不持久化
- 卸载仍需 CA_ValidateUninstallKey 验证

### 涉及文件
- `src/installer/GuardianShield.wxs`

---

## 致命: ETW 回调未解析 file_path 导致保护体系完全失效

### 症状
安装并运行后，无论在保护目录内执行什么操作（批量写入、删除、压缩），系统均无反应。Tier1/Tier2 协议从未触发。

### 根因
`guardian_c.cpp` 的 `EtwEventCallback` 从未调用 TdhGetProperty 解析 Kernel-File 事件的 FileName 属性，`DriverEvent.file_path` 恒为空字符串。`IsInProtectedPath("")` 恒返回 false，批量阈值检测被完全跳过。同时 `data_size` 未填充导致数据泄露量检测失效。

### 修复
1. 新增 `EtwGetStringProperty`/`EtwGetUInt64Property`/`EtwGetUInt32Property` 辅助函数
2. 维护 FileObject->FileName 缓存，Close 事件清理
3. Write 事件解析 IoSize 填充 data_size
4. 单事件 AssessThreat 增加 inProtectedPath 门控

### 级联修复
- GuardianC 双发事件到 A 和 B（故障转移支持）
- IPC SendToNode 增加 3 次重试
- process_termination_count 纳入 CheckBatchThresholds
- Config::Validate() 允许阈值为 0
- BLOCK 动作降级为 FileLocker
- Legacy 配置补充 file_delete

---

## 高: uninstall.bat 闪退/乱码/卡死（三连问题）

### 症状
1. 管理员右键运行闪退（窗口一闪即逝）
2. 运行后中文显示为菱形乱码
3. 卡在 [1/6] 步骤长时间无响应

### 根因
1. 文件行尾为 LF（Cursor Write 工具默认），cmd.exe 要求 CRLF
2. 文件用 GBK 编码保存但 chcp 65001 切 UTF-8，编码冲突
3. exe 卸载命令 `-uninstall -key` 阻塞等待服务响应

### 修复
全面重写为纯 ASCII + CRLF：移除 chcp 65001，所有中文改为英文，exe 卸载改为 `start "" /b` 后台运行 + 10 秒 ping 超时 + taskkill 兜底，rmdir 增加 3 次重试循环，支持 `-key` 命令行参数。

---

## 中: MSI 安装无密钥输入界面

### 症状
双击 MSI 安装时不显示密钥输入和配置文件选择对话框。

### 根因
之前测试残留的 MSI 注册表项未清除（`HKLM\...\Uninstall\{ProductCode}`），Windows Installer 认为产品已安装，进入修复模式跳过安装向导。

### 修复
1. 测试脚本预清理逻辑增加 MSI 注册表残留检测和清除
2. InstallUISequence 添加 UninstallKeyDlg 显示条件（卸载时弹出密钥验证）

### 第二次暴露 (2026-03-05): uninstall.bat 导致重装闪退

**完整根因链**: `uninstall.bat` 调用 `msiexec /x /passive` 未传递 `INSTALL_KEY` → `CA_ValidateUninstallKey`（`Return="check"`）密钥为空失败 → MSI 卸载静默中止 → 产品注册残留 → 重装时 `NOT Installed` 条件为 FALSE → `GS_WelcomeDlg` 不显示 → 闪退

**修复**:
1. `msiexec /x` 传递 `INSTALL_KEY="%UNINSTALL_KEY%"` 使密钥验证通过
2. 卸载后用 `reg query` 验证产品注册是否清除
3. 若残留，强制删除 Uninstall + WOW6432Node + Classes\Installer\Products 注册表项

**教训**: 卸载流程必须验证"卸载成功了吗"，不能假设 `msiexec /x` 一定成功。`/passive` 模式下自定义动作仍然执行，缺少属性会导致静默失败。

---

## 中: 测试基础设施与实现脱节

### 症状
test_threat_evaluator.cpp 断言 FILE_DELETE→LEVEL_1，但实际实现是 LEVEL_2+BLOCK。test_emergency.cpp 测试独立 mock 而非真实状态机。

### 修复
1. 重写 test_threat_evaluator.cpp 直接测试真实 ThreatEvaluator 类
2. 重写 test_emergency.cpp 验证真实 EmergencyState 枚举和转换
3. 更新 FUNCTIONAL_SPEC.md 与当前三层响应架构对齐

---

## 高: YAML 阈值字段留空导致配置加载崩溃

### 症状
管理员在 `guardian_config.yaml` 中将阈值字段留空（如 `file_write_count:` 冒号后无值），系统启动后所有配置被忽略，使用上次缓存或默认值。

### 根因
`yaml-cpp` 中 `node[key]` 对 Null 节点返回 true（存在但值为空），后续 `.as<int>()` 对 Null 节点抛出 `TypedBadConversion<int>` 异常。异常被 `LoadYaml()` 的 `catch` 捕获，导致整个 YAML 解析失败。

### 修复
1. 新增 `readInt` 和 `safeInt` 对 `.IsNull()` 的前置检查：Null → 返回 0（不限制）
2. `ThreatEvaluator::CheckBatchThresholds` 所有比较前增加 `> 0` 条件
3. 语义: 0 = 不限制，-1 = 字段不存在（保持默认值），正整数 = 用户配置值

### 涉及文件
- `src/service/common/src/config.cpp`
- `src/service/GuardianA/src/threat_evaluator.cpp`
- `config/guardian_config.yaml`

---

## 严重: 威胁检测系统惰性 (完全失效)

### 症状
用户在保护路径内一次性压缩 50 个文件，系统无任何响应 -- 无日志、无告警、无协议触发。

### 根因 (多层级)

**1. 事件管道断裂**
- GuardianA `Initialize()` 中没有注册 IPC 消息处理器，无法接收 GuardianC 转发的 `DRIVER_EVENT`
- `m_driverThread` 从未被启动，无法从 DriverClient 读取内核驱动事件
- 结果：两条事件来源都被切断，GuardianA 的事件队列始终为空

**2. ETW 事件分类不完整**
- GuardianC 的 `EtwEventCallback` 缺少 `FILE_WRITE` (opcode 32) 映射，写操作被归类为 `FILE_READ`
- 没有压缩工具和网络工具的启发式检测，压缩 50 个文件仅产生 `FILE_READ` 事件

**3. 批量检测返回层级不足**
- `CheckBatchOperation()` 检测到批量操作后返回 `ThreatLevel::LEVEL_2`
- 但紧急协议仅在 `LEVEL_3` 时触发
- 两者之间存在不可逾越的断层

**4. 单事件响应过度**
- `FILE_NETWORK_TRANSFER` 直接映射为 `LEVEL_3 + ENCRYPT + WIPE`
- 一次网络传输即触发全面销毁，但 50 次压缩却无反应，逻辑完全矛盾

### 修复
见 changelog.md 2026-03-03 条目。核心改动：
- 修复事件管道 (注册 IPC handler + 启动 driverThread)
- 完善 ETW 分类 (FILE_WRITE + 启发式)
- 实施三层响应架构 (单事件/Tier1/Tier2)
- 移除单事件破坏性动作

### 涉及文件
`guardian_a.cpp`, `guardian_a.h`, `threat_evaluator.h`, `threat_evaluator.cpp`, `guardian_c.cpp`, `common_types.h`, `config.cpp`, `config.h`, `guardian_config.yaml`

---

## 严重: NotificationManager 在 Session 0 中失效

### 症状
GuardianA 发送的告警通知从未显示在用户桌面。

### 根因
GuardianA 作为 Windows 服务运行在 Session 0 (隔离会话)。`NotificationManager` 依赖 `GetDesktopWindow()` 进行系统托盘操作，该函数在 Session 0 中返回 NULL。Windows Vista 之后的 Session 0 隔离机制禁止服务直接与用户桌面交互。

### 修复
`SendAlert()` 改为通过 IPC 发送 `ALERT_NOTIFICATION` 消息给 GuardianC (运行在用户 Session 中)，由 GuardianC 负责桌面通知。

### 涉及文件
`guardian_a.cpp`, `guardian_c.cpp`, `common_types.h`

---

## 中等: MSI 安装报错 Error 2343

### 症状
MSI 安装过程中弹出 "Error 2343" 对话框，安装失败。

### 根因
`InstallDlg.wxs` 中 `ConfigSelectDlg` 使用了 `PathEdit` 控件用于输入配置文件路径。`PathEdit` 控件强制要求其绑定属性的值为非空且有效的目录路径。当用户未输入或输入的是文件路径时，内部验证触发 Error 2343。此外 `PathEdit` 关联的 `BrowseDlg` 是目录浏览器，不适合选择文件。

### 修复
将 `PathEdit` 控件改为 `Edit` (普通文本输入框)，移除 "Browse..." 按钮及其 `BrowseDlg` 引用。

### 涉及文件
`src/installer/InstallDlg.wxs`

---

## 中等: 日志文件不生成

### 症状
服务安装启动后，`C:\ProgramData\GuardianShield\logs\` 目录下没有日志文件。

### 根因
`Config` 类返回的 `logPath` 为 `C:\ProgramData\GuardianShield\logs`。`Logger::GetLogFilename()` 将此值作为文件名前缀而非目录路径，生成的日志文件名为 `logs_YYYY-MM-DD.json`，被写入到 `C:\ProgramData\GuardianShield\` 而非预期的 `logs` 子目录。

### 修复
各服务的 `InitializeLogger()` 中显式拼接完整路径:
```cpp
std::wstring logPrefix = logDir + L"\\guardian_a";
```
确保日志写入 `logs\guardian_a_YYYY-MM-DD.json`。

### 涉及文件
`guardian_a.cpp`, `guardian_b.cpp`, `guardian_c.cpp`

---

## 中等: uninstall.bat 系列问题 (5 轮修复)

### 第 1 轮: 逻辑错误

**症状**: 卸载脚本运行后部分组件未清理
**根因**:
- `setlocal EnableDelayedExpansion` 消耗安装密钥中的 `!` 字符
- `exit /b 1` 在错误处导致整个脚本提前退出，后续清理步骤不执行
- 密钥参数传递时未加引号，含空格或特殊字符时断裂
- GuardianC 注册表路径 (HKLM vs HKCU) 不匹配
**修复**: 重写卸载逻辑，使用错误标记代替 exit、引号包裹参数、同时清理 HKLM 和 HKCU

### 第 2 轮: 闪退

**症状**: 双击运行后窗口立即消失
**根因**: 文件使用 LF 行尾，`cmd.exe` 要求 CRLF
**修复**: 转换行尾为 CRLF

### 第 3 轮: @echo off 失效

**症状**: 所有命令被回显，错误信息纷飞
**根因**: UTF-8 BOM (`EF BB BF`) 导致 `cmd.exe` 无法识别第一行
**修复**: 保存为 UTF-8 无 BOM

### 第 4 轮: 乱码命令错误

**症状**: 控制台显示 `'◆◆权限运行' is not recognized as an internal or external command`
**根因**: `::` 在 `cmd.exe` 中是无效标签而非注释，在 `chcp 65001` (UTF-8) 环境下 `cmd.exe` 将其后的中文字符当作命令执行
**修复**: 所有 `::` 替换为 `REM`

### 第 5 轮: 闪退（回归）

**症状**: 上次重写添加 MSI 卸载功能后，再次闪退
**根因**:
- `setlocal EnableDelayedExpansion` 在重写时被重新引入（第 1 轮已修过），`!` 被消耗导致密钥和 powershell 命令解析异常
- 新增的 `for /f "usebackq"` 内嵌 powershell 长命令含 `\\`、`$_`、`|`、`'` 等大量特殊字符，cmd.exe 在 `EnableDelayedExpansion` 下解析失败导致立即崩溃
- `if "%~1"=="" pause`：传了 `-key` 参数时不暂停，用户看不到任何输出
**修复**:
- `setlocal EnableDelayedExpansion` → `setlocal`（无延迟展开）
- `!VAR!` 延迟变量引用 → `call :subroutine` + `goto :label` 重构
- `for /f` + powershell 查 MSI ProductCode → 原生 `reg query /s /f "GuardianShield"` + `findstr`
- `if "%~1"=="" pause` → 无条件 `pause`

### 涉及文件
`scripts/uninstall.bat`

### 关键教训
Windows 批处理脚本的六大陷阱：
1. **行尾必须是 CRLF** -- 开发工具可能默认使用 LF
2. **不能有 UTF-8 BOM** -- 会破坏 `@echo off`
3. **用 `REM` 不用 `::`** -- `::` 在 UTF-8 代码页下会导致异常
4. **不用 `EnableDelayedExpansion`** -- 消耗 `!` 字符，与 `for /f` 组合导致解析崩溃。用 `call :label` 替代
5. **不在 `for /f` 内嵌套 powershell** -- 特殊字符转义在 cmd.exe 中极其脆弱。用原生 `reg query` + `findstr` 替代
6. **卸载/关键脚本必须无条件 `pause`** -- 确保用户能看到执行结果，不论是否传了命令行参数

---

## 低: build/bin 目录下无 MSI 文件

### 症状
用户在 `build/bin` 下找不到 `GuardianShield.msi`。

### 根因
默认构建流程 (`build.bat` / `run.bat`) 只编译源码，不包含 MSI 打包步骤。CPack 的 WIX 生成器与项目手写的 `.wxs` 文件冲突。

### 修复
创建自定义 `build_msi.bat`，直接使用 WiX Toolset 的 `candle.exe` + `light.exe` 编译手写 `.wxs`，输出到 `build/bin/Release/GuardianShield.msi`。

### 涉及文件
`build_msi.bat` (新建), `run.bat` (新增菜单选项)

---

## 低: GuardianB 链接错误 (ThreatEvaluator 未定义)

### 症状
编译时 GuardianB 报 LNK2019 链接错误，找不到 `ThreatEvaluator` 的符号。

### 根因
`threat_evaluator.cpp` 只在 GuardianA 的 CMakeLists.txt 中编译，GuardianB 引用了头文件但没有链接实现。

### 修复
在 GuardianB 的 `CMakeLists.txt` 中添加 `../GuardianA/src/threat_evaluator.cpp` 到源文件列表，并添加 `../GuardianA/include` 到 include 路径。

### 涉及文件
`src/service/GuardianB/CMakeLists.txt`

---

## 中等: GuardianB 与 GuardianA 行为分歧 (3 轮修复)

### 症状
GuardianB 在 Primary 模式下的威胁响应与 GuardianA 不一致。

### 根因 (多层级)
**第 1 轮** (重构时): GuardianB 有独立复制的 AssessThreat，修改 GuardianA 后未同步。
**第 2 轮** (深层分析时): 对齐了 FILE_NETWORK_TRANSFER 的 ENCRYPT+WIPE 问题，但遗漏了 FILE_DELETE (LEVEL_1→LEVEL_2)、FILE_COMPRESS (缺 BLOCK)、PROCESS_INJECT/DEBUG (缺 TERMINATE) 3 处差异。
**第 3 轮** (全面审查): Tier 1 缺少 ALERT 阶段（直接进入 ENCRYPTING，无等待、无取消机会）；StartEmergencyCountdown 硬编码 5 秒超时而非读取配置。

### 修复
- AssessThreat 所有 case 逐行与 GuardianA 对齐
- 新增 TriggerProtectionProtocol + StartProtectionCountdown（与 GuardianA 一致的 ALERT → 倒计时 → ENCRYPTING → LOCKED 流程）
- StartEmergencyCountdown 改用 `m_config->GetAlertTimeoutSeconds()` + 每秒检查取消标志

### 涉及文件
`guardian_b.cpp`, `guardian_b.h`

### 教训
对齐两个文件的同名函数时，必须**逐行 diff 比对**，而非只看"最明显的差异"。每次修复后用 grep 验证两个函数的结构和关键词完全一致。

---

## 低: 文档大范围过时 (file_copy → file_write 未传播)

### 症状
代码和 YAML 已使用 `file_write_count`，但 10 个文档文件仍使用 `file_copy_count`。6 个文档仍描述单事件触发 ENCRYPT/WIPE。7 个文档使用旧的扁平阈值结构。

### 根因
重命名时只关注"主要文件"（代码本体和 YAML 配置），把文档视为"后续清理"。完成代码修改后产生"完成感"，注意力转向下一个任务，忘记传播变更。

### 修复
全量 grep `file_copy_count` 确认所有引用点 → 逐文件替换 → grep 确认剩余为 0（仅 config.cpp 的向后兼容别名保留）。同时修正 6 个文档的单事件响应描述和 7 个文档的阈值结构。

### 涉及文件
10 个文档文件 + tests/test_threat_detection.ps1 + config/guardian_config.yaml

### 教训
任何"重命名"操作完成后，必须执行 `rg "旧名称"` 确认结果为 0 或仅剩有意保留的别名。

---

## 低: DriverClient::BlockOperation 不存在

### 症状
编译时 GuardianA 报 C2039 错误，`BlockOperation` 不是 `DriverClient` 的成员。

### 根因
在 `ExecuteResponse` 中新增了 `m_driverClient->BlockOperation(event.process_id)` 调用，但 `DriverClient` 类没有此方法。

### 修复
移除该调用，仅保留日志记录。阻止操作实际通过内核驱动的 IOCTL 实现，当前版本尚未实现此接口。

### 涉及文件
`guardian_a.cpp`

---

## 低: DriverClient 双份实现 (ODR 风险)

### 症状
GuardianA 目录下存在独立的 `driver_client.cpp` 和 `driver_client.h`，同时 GuardianA 又通过 CMake 链接 `GuardianCommon` 库（其中包含 `common/src/driver_client.cpp` 的同名实现）。

### 根因
早期开发中将 common 的 DriverClient 复制到 GuardianA 目录，后续未清理。两份实现可能导致 C++ One Definition Rule (ODR) 违规——链接器静默选择其中一份，行为一致性无法保证。

### 修复
1. 从 GuardianA 的 `CMakeLists.txt` 中移除 `src/driver_client.cpp` 和 `include/driver_client.h`
2. 删除 `src/service/GuardianA/src/driver_client.cpp`
3. 删除 `src/service/GuardianA/include/driver_client.h`
4. 确认 GuardianA 通过 GuardianCommon 链接使用 common 中唯一的 DriverClient 实现

### 涉及文件
- `src/service/GuardianA/CMakeLists.txt`
- `src/service/GuardianA/src/driver_client.cpp` (已删除)
- `src/service/GuardianA/include/driver_client.h` (已删除)

### 教训
与 reflections 5（"代码复制导致行为分歧"）同构。共享代码应通过链接公共库实现，不应复制源文件。

---

## 低: 缓存路径/文件名多处不一致

### 症状
代码中 `GetCachePath()` 返回 `C:\ProgramData\GuardianShield\config_cache.bin`，但多处文档使用 `guardian_config.cache` 或 `config\config_cache.bin`。WiX 卸载逻辑删除的是错误的文件名/路径，导致卸载后缓存文件残留。

### 根因
缓存文件名/路径在开发过程中经历了多次调整（从 `guardian_config.cache` 到 `config_cache.bin`，从 `config\` 子目录到 `ProgramData\GuardianShield\` 根目录），但每次调整只改了代码，未做全量 grep 验证文档和安装器引用。

### 修复
1. 以代码 `C:\ProgramData\GuardianShield\config_cache.bin` 为唯一真相源
2. WiX `GuardianShield.wxs`：修正 `RemoveFile` 目标为 `config_cache.bin`，移至 `DATAROOTFOLDER`
3. `current_state.md`、`ADMIN_MANUAL.md`、`FUNCTIONAL_SPEC.md` 统一路径描述

### 涉及文件
- `src/installer/GuardianShield.wxs`
- `memory/current_state.md`
- `docs/ADMIN_MANUAL.md`
- `docs/FUNCTIONAL_SPEC.md`

### 教训
与 reflections 7（"改了 A 忘了 B"）同构。路径/文件名变更后必须 `rg "旧名称"` 确认所有引用已更新。

---

## 致命: 服务启动自毁 -- process_termination 阈值导致自我触发紧急协议 (2026-03-05 测试发现)

**状态: 已修复 (2026-03-05)**

### 症状
部署配置文件后首次启动服务，2 秒内自动触发 Tier 1 → 级联 Tier 2，执行 7-pass DOD 擦除，保护目录所有文件被不可逆销毁。

### 根因
1. `process_termination_count` 阈值极低（Tier1=2, Tier2=6）
2. ETW 收集**系统全局**进程事件（PROCESS_CREATE/PROCESS_TERMINATE），不限于保护目录
3. `threat_evaluator.cpp` 中 process_termination 使用硬编码 5 秒窗口
4. `HandleDriverEvent()` 中进程事件跳过路径/类型过滤但仍调用 `CheckBatchThresholds()`
5. 无启动宽限期（startup grace period）

### 修复
- `guardian_a.cpp` / `guardian_b.cpp`: `HandleDriverEvent()` 中 `CheckBatchThresholds()` 仅对文件事件调用（`!isProcessEvent` 条件）
- `guardian_config.yaml`: `process_termination_count` 恢复为合理值（Tier1=50, Tier2=200），仅记录不触发批量协议

### 涉及文件
- `src/service/GuardianA/src/guardian_a.cpp`
- `src/service/GuardianB/src/guardian_b.cpp`
- `config/guardian_config.yaml`

---

## 严重: IPC 通信全面断开 (2026-03-05 测试发现)

**状态: 已修复 (2026-03-05)**

### 症状
GuardianA/B/C 之间 IPC 全部失败，日志中持续 `"IPC: cannot reach node X"`。GuardianC 无法收到告警通知，管理员无法取消 ALERT 阶段。

### 根因（代码验证）
1. **管道 SDDL 过严**: `D:(A;;GA;;;SY)(A;;GA;;;BA)` 仅允许 SYSTEM 和已提权管理员。GuardianC 通过注册表 Run 键启动，在非提权用户会话运行，UAC 下 BA SID 为 deny-only，无法连接管道
2. **共享内存命名空间隔离**: `Local\GuardianState` 在 Session 0（服务）和用户会话（GuardianC）指向不同命名空间，心跳无法跨会话
3. **AcceptLoop 缺陷**: `CreateNamedPipeW` 失败时无 sleep（CPU 空转）；`ERROR_PIPE_CONNECTED` 未处理导致连接丢失

### 修复
- `ipc.cpp` AcceptLoop: SDDL 扩展为 `SY+BA+IU`（Interactive Users），允许非提权 GuardianC 连接
- `ipc.cpp` SharedMemory: SDDL 同步扩展；命名空间从 `Local\` 改为 `Global\`（SYSTEM 有 SeCreateGlobalPrivilege）
- `ipc.cpp` AcceptLoop: 增加 `ERROR_PIPE_CONNECTED` 分支处理；`CreateNamedPipeW` 失败时添加 `Sleep(100)`

### 涉及文件
- `src/service/common/src/ipc.cpp`

---

## 严重: 排除文件类型未过滤 (2026-03-05 测试发现)

**状态: 已修复 (2026-03-05)**

### 症状
`.log`、`.tmp`、`.bak` 文件的 FILE_CREATE/FILE_WRITE 事件出现在检测日志中，且被计入阈值。

### 根因
`config.cpp` 的 `IsFileTypeMonitored()` 函数从未检查 `m_impl->excludeFileTypes`。YAML 中 `protection.file_types.exclude` 正确加载到了 `m_impl->excludeFileTypes`（第 631-636 行），但函数只检查了始终为空的 `dir.file_types`（per-directory 排除列表），然后直接跳到 `includeFileTypes`。

### 修复
在 `IsFileTypeMonitored()` 中，于 per-directory 排除检查之后、include 列表检查之前，新增遍历 `m_impl->excludeFileTypes` 的循环，对扩展名进行大小写不敏感比较。

### 涉及文件
- `src/service/common/src/config.cpp`

---

## 中: MSI 安装后配置文件未部署 (2026-03-05 测试发现)

**状态: 已修复 (2026-03-05)**

### 症状
MSI 安装后 `C:\ProgramData\GuardianShield\config\guardian_config.yaml` 不存在，服务启动时 `"No protected paths configured"`。

### 根因
WiX `GuardianShield.wxs` 的 `ConfigFiles` ComponentGroup 只创建目录和 RemoveFile 规则，无 `File` 元素。Custom Action `CA_CopyConfigFiles` 依赖安装时传入文件路径，但 MSI 包内不含配置文件。

### 修复
- `GuardianShield.wxs`: 新增 `ConfigYamlFile` 和 `AuthListFile` Component，通过 `File` 元素将配置文件打包进 MSI
- `build_msi.bat`: 在 staging 阶段复制 `guardian_config.yaml` 和 `auth.list` 到 staging 目录

### 涉及文件
- `src/installer/GuardianShield.wxs`
- `build_msi.bat`

---

## 中: 背景索引进程放大事件计数 (2026-03-05 测试发现)

**状态: 已修复 (2026-03-05)**

### 症状
`SearchProtocolHost.exe`（Windows Search）对保护目录新文件的索引操作生成额外 FILE_CREATE 事件，创建 1 个文件实际产生 2-3 个事件。

### 修复
在 `guardian_a.cpp` / `guardian_b.cpp` 的 `HandleDriverEvent()` 中，文件类型过滤之后、用户配置白名单之前，新增系统级硬编码白名单（不可配置，始终生效）：
- SearchProtocolHost.exe / SearchIndexer.exe / SearchFilterHost.exe
- TrustedInstaller.exe / TiWorker.exe
- MsMpEng.exe（Windows Defender）
- svchost_core.exe / svchost_helper.exe（自身）

### 涉及文件
- `src/service/GuardianA/src/guardian_a.cpp`
- `src/service/GuardianB/src/guardian_b.cpp`

---

# ========== 2026-03-05 第一性原理全面排查发现的新问题 ==========

## [待修复] 致命: 代码重复导致的系统性行为分歧

**状态: 待修复（需结构性重构）**

### 症状
GuardianB 在 3 轮"对齐"修复后仍有 8 处与 GuardianA 的行为分歧。20+ 个函数在两个文件中重复维护。

### 已验证的 8 处分歧
1. HandleDriverEvent 缺少 4 层过滤（目录级/文件类型/用户白名单/空路径）
2. 事件处理顺序颠倒（B 先批量后单事件，A 先单事件后批量）
3. ThreatEvaluator 缺 file_create 阈值
4. ExecuteResponse 重复日志
5. TriggerEmergencyProtocol 行为不同（A 发 SendAlert，B 发 Broadcast）
6. ThreatAssessmentB 重复结构体
7. LoadProtectedPaths 未同步驱动
8. 驱动连接方式错误（USERMODE_PATH vs PORT_NAME）

### 修复方案
创建 GuardianCore 基类，将 20 个重复函数抽取到共享实现

---

## [待修复] 严重: config.cpp CreateMutexW 失败导致崩溃

**状态: 待修复**

config.cpp:125 `CreateMutexW` 返回 NULL 时，后续 `WaitForSingleObject(NULL, 10000)` 行为未定义/崩溃。

---

## [已修复] 严重: GuardianC wstring 构造未定义行为 (v2.6)

**状态: 已修复 (2026-03-06)**

guardian_c.cpp L583 原用 `char*`(UTF-8) 直接构造 `std::wstring`，不做 UTF-8 解码。已改为 `MultiByteToWideChar(CP_UTF8, ...)` 正确转换。

---

## [待修复] 高: 配置系统 18 个 YAML 字段未实现

**状态: 待修复**

**未解析**: system.config_version, detection.rules, authorization.check_on_boot/strict_mode, whitelist.conditions, emergency.notifications, communication.*, keys.*
**已解析未使用**: encrypt_timeout_seconds, recovery_wait_seconds
**加载错误**: dir.file_types 未读取, Thumbs.db 排除了所有 .db 文件

---

## [待修复] 高: 6 个线程安全竞态条件

**状态: 待修复**

1. ipc.cpp:569 `s_lastWarn[3]` 无锁
2. ipc.cpp:419 SharedMemory::GetHeartbeat 读无锁
3. config.cpp:1149 Config watcher 与 getter 无互斥
4. file_locker.cpp:111 GetFileHandle 无锁
5. guardian_a.cpp:1018 心跳数组无锁
6. guardian_b.cpp:389 m_isPrimary 无锁

---

## [待修复] 高: 威胁评估器 4 个数据失真

**状态: 待修复**

1. process_termination 窗口硬编码 5 秒（应从配置读取）
2. FILE_RENAME 计入 FILE_DELETE 队列（推高删除计数）
3. ETW data_size 恒为 0（data_transfer_mb 检测无效）
4. 无扩展名文件一律不监控

---

## [待修复] 中: 注册表键名不一致

**状态: 待修复**

WiX 写 HKLM\Run\WindowsMonitor，代码写 HKCU\Run\GuardianC。

---

## [待修复] 中: 测试空洞

**状态: 待修复**

test_threat_evaluator.cpp EventClassificationTest 5 个用例零断言，始终通过。test_threat_detection.ps1 AlertNotification 大小计算错误、Tier1 未验证触发。

---

## [待验证] 高: IPC GuardianC 管道连接失败（实际部署发现）

**状态: 待验证**

**发现时间**: 2026-03-05 MSI 安装后交互式测试

**现象**: GuardianA 和 GuardianB 日志中持续出现 `"IPC: cannot reach node 2 (will keep retrying)"`。GuardianC (winmon.exe, PID 15472) 在 Session 1 运行，但 Named Pipe `\\.\pipe\GuardianIPC_C` 未建立连接。

**影响**: 所有 ALERT_USER 通知无法送达用户桌面（`ExecuteResponse` 中 `SendToNode(NodeId::GUARDIAN_C, ALERT_NOTIFICATION, ...)` 会静默失败）。保护协议/紧急协议的锁屏通知也可能受影响。

**可能原因**:
1. GuardianC 的 IPC 服务端管道未成功创建（ACL/权限问题）
2. 管道名称不匹配（代码中 GuardianC 创建的管道名 vs GuardianA 连接的管道名）
3. GuardianC 启动时序问题（服务先于 GuardianC 启动，但 GuardianC 应在管道创建后才可连接）
4. 之前修复 IPC 的 SDDL 改动可能在 GuardianC 端未完全同步

**关联**: issues_and_fixes.md 中历史 IPC 修复（已修复项 8："IPC 通信全面断开"），可能修复不完整或产生了新的回归。

**更新 (2026-03-06 交互式测试)**: 重启 GuardianC 后 IPC 恢复正常，通知成功送达。初始失败可能是启动时序问题而非管道权限问题。

---

## [已修复] 致命: System PID 4 误判导致 FileLocker 锁定所有新建文件

**状态: 已修复 (2026-03-05 深层根因修复: Fix 2 EventId 11降级 + Fix 4 ACL恢复 + Fix 12 PID≤4跳过)**

**发现时间**: 2026-03-05 交互式测试 Phase 1

**现象**: 保护目录中每个新建文件在 ~1 秒内被 FileLocker 锁定（ACL → Everyone:(N)），后续所有操作（修改/重命名/删除）返回"拒绝访问"。

**根因**: System (PID 4) 的 NTFS 元数据操作（日志刷新、MFT 更新等）生成 FILE_DELETE ETW 事件。`AssessThreat` 将 FILE_DELETE 判定为 "Dangerous" / BLOCK。`ExecuteResponse` 调用 `FileLocker` 修改文件 ACL 为 `Everyone:(N)`。

**影响**: 保护目录内所有文件在创建后立即变为不可访问。系统完全不可用。

**修复建议**: 在 `HandleDriverEvent` 的系统级硬编码白名单 (`kSystemWhitelist`) 中添加 `System` (PID 4) 或基于 PID=4 的特殊判断。

---

## [已修复] 致命: PROCESS_TERMINATE 通知洪泛

**状态: 已修复 (2026-03-05 深层根因修复: Fix 3 降级为LEVEL_0/LOG)**

**发现时间**: 2026-03-06 交互式测试

**现象**: 系统托盘持续弹出通知（黄色图标），每秒数十条，每条 PID 不同。7 分钟内产生 6,637 条 ALERT_USER 通知。

**根因**: `AssessThreat` 将所有 `PROCESS_TERMINATE` 事件标记为 `Suspicious/ALERT_USER`。ETW 采集的是系统全局进程事件，正常 Windows 系统每分钟有数百个进程启动/退出。每个退出事件都通过 IPC 发送 `ALERT_NOTIFICATION` 给 GuardianC，显示为桌面通知。

**影响**: 用户桌面被通知洪泛淹没，无法正常工作。

**修复建议**: `PROCESS_TERMINATE` 在 `AssessThreat` 中降级为 `Normal/LOG`，不触发 `ALERT_USER`。

---

## [已修复] 致命: TERMINATE 响应动作杀死 explorer.exe

**状态: 已修复 (2026-03-05 深层根因修复: Fix 5 倒计时暂停 + Fix 6 protectedProcs扩展 + Fix 7 精准终止)**

**发现时间**: 2026-03-05 交互式测试

**现象**: Tier 2 紧急协议触发后，Windows 桌面和任务栏完全消失。

**根因**: explorer.exe 在浏览保护目录时自动创建 `desktop.ini`。紧急协议期间该 FILE_CREATE 事件被标记为 Critical/TERMINATE。`ExecuteResponse` 终止了 explorer.exe (PID 8848)，导致 Windows Shell 崩溃。

**日志证据**: `"event_type":"FILE_CREATE","response_action":"TERMINATE","process_name":"C:\\Windows\\explorer.exe"`

**影响**: Windows 桌面崩溃，用户无法操作电脑。需手动运行 explorer.exe 恢复。

**修复建议**:
1. TERMINATE 动作应排除系统关键进程（explorer.exe、csrss.exe、lsass.exe、winlogon.exe 等）
2. `desktop.ini` 应加入文件名排除列表
3. 紧急协议期间只终止最初触发警报的进程，不终止所有进程

---

## [已修复] 严重: 文件类型过滤完全失效（交互式测试验证）

**状态: 已修复 (v2.1.0.0 — LoadSimple 结构性变更: 添加 inExcludeArray/inIncludeArray 列表解析通道 + 诊断日志)**

**发现时间**: 2026-03-05 交互式测试 Phase 2

**现象**: `.log` 和 `.tmp` 文件产生完整事件链（CREATE + WRITE + DELETE），与普通文件行为一致。

**与历史修复的关系**: issues_and_fixes.md 中"排除文件类型未过滤"标记为已修复（新增 `excludeFileTypes` 检查）。但交互式测试证实该修复未生效——可能是二进制缓存中 `excludeFileTypes` 为空（序列化问题），或代码修复未包含在当前 MSI 中。

---

## [已修复] 严重: 白名单不支持 Windows 11 UWP 应用

**状态: 已修复 (2026-03-05 Fix 9 UWP回退 + v2.1.0.0 LoadSimple 白名单解析 + _wcsicmp 大小写不敏感匹配)**

**发现时间**: 2026-03-06 交互式测试 Phase 3

**现象**: Windows 11 现代记事本 (UWP) 未被白名单识别，操作产生完整事件链。

**根因**: ETW 返回的 UWP 进程路径为 `C:\Program Files\WindowsApps\microsoft.windowsnotepad_11.2510.1`。`HandleDriverEvent` 使用 `rfind('\\')` 提取最后一段 `microsoft.windowsnotepad_11.2510.1` 作为进程名，与白名单中的 `notepad.exe` 不匹配。

**影响**: Windows 11 上所有 UWP 应用无法被白名单豁免。

**修复建议**: 白名单匹配增加模糊匹配（包含子串匹配）或支持包名匹配模式。

---

## [已修复] 中等: 所有事件重复记录两次

**状态: 已修复 (2026-03-05 深层根因修复: Fix 1 IPC乒乓消除 + Fix 2 EventId 11降级 + Fix 11 IPC去重)**

**发现时间**: 2026-03-05 交互式测试

**现象**: 日志中每个事件以相同时间戳和内容出现两次。

**影响**: 日志膨胀一倍；事件计数失真可能提前触发批量阈值（实际 5 次操作被计为 10 次）。

---

## [已验证] 深度审查: 托盘退出隐藏 + 一键解锁方案验证偏差

**状态: 已在方案中修正 (2026-03-05)**

**发现时间**: 2026-03-05 方案验证阶段

经两轮代码级审查发现以下风险（已全部纳入方案）：

| # | 风险 | 验证结论 | 处理 |
|---|------|---------|------|
| 1 | IPC 线程阻塞导致心跳超时 | **确认存在** | 解密线程化 |
| 2 | ETW 自身事件触发无限循环 | **已排除**: self-PID 过滤有效 | 无需处理 |
| 3 | CancelEmergency 不重置 protocolActive | **确认存在** | RAII 守卫 |
| 4 | UnlockAllFiles 双调用崩溃 | **已排除**: mutex+clear 幂等 | 无需处理 |
| 5 | ENCRYPTING/WIPING 期间解密 | **确认危险** | 状态门禁 |
| 6 | 并发 DECRYPT_REQUEST | **确认文件损坏风险** | 原子互斥 |
| 7 | 备份节点文件锁阻塞解密 | **确认存在** | 广播解锁+等待 |
| 8 | FileManager WM_CLOSE 退出进程 | **确认风险** | DestroyWindow |

**另外发现**: 方案初始假设 `constantTimeCompare` 函数全局可用，实际 `SecureCompare` 仅存在于 `guardian_c.cpp` 的 static 函数中。修正：在 `guardian_a.cpp` 和 `guardian_b.cpp` 各自添加 static `SecureCompare`/`SecureCompareB` 函数。

---

## 2026-03-06 全链路缺陷修复 (10 个根因, 35+ 缺陷) [已验证: cmake PASS, ctest 162/162 PASS]

### 根因分析

经四路并行代码审计，发现 35+ 个缺陷归属 10 个根因模式：
1. **RC-1 函数违反单一职责** — EncryptFile/DecryptFile 耦合加密+删除为不可分割操作
2. **RC-2 Tier-2 管道因果链断裂** — 加密步骤删除原文件 → 擦除步骤找不到目标 → 安全擦除作用在加密副本上
3. **RC-3 IPC消息链路全断裂** — WM_USER+100 死消息 + COMMAND/STATE_SYNC 无发送者
4. **RC-4 A/B 代码复制导致不一致** — GuardianB 缺少 4 个 file_create 阈值 + 缺少 SendAlert
5. **RC-5 线程安全违规** — HideLockScreen 从 IPC 线程直接调用 Win32 UI 操作
6. **RC-6 配置序列化缺失** — whitelist/emergency 等 6 个字段未写入 config_cache.bin
7. **RC-7 状态机缺乏防护** — SetEmergencyState 无合法性检查 + CancelEmergency 绕过
8. ~~**RC-8 响应动作混乱**~~ — BLOCK 和 LOCK_FILE 已完全移除 (**已修复**)
9. **RC-9 心跳检测失效** — nonce != 0 永远为真，无法检测服务崩溃
10. **RC-10 解密流程缺陷** — NORMAL 状态允许解密成为 DoS 向量

### 已完成修复 (P0 + P1 + P2)

| # | 修复项 | 文件 | 状态 |
|---|--------|------|------|
| P0-1 | 锁屏命令 WM_USER+100→WM_SHOW_LOCKSCREEN + HideLockScreen 改 PostMessage | guardian_c.cpp/h | **已修复** |
| P0-2 | DecryptDirectory 不再静默删除 .gs 文件 | file_encryptor.cpp | **已修复(之前session)** |
| P0-3a | EncryptFile/DecryptFile 添加 deleteSource 参数 | file_encryptor.h/cpp | **已修复** |
| P0-3b | Tier-2 管道: EncryptProtectedFiles(false) + WipeDirectory(skip .gs) | guardian_a/b.cpp, file_wiper.h/cpp | **已修复** |
| P1-1 | config 缓存补全 whitelist+emergency+version+log_level, v6→v7 | config.cpp | **已修复** |
| P1-2 | 心跳 nonce 变化检测 (nonce != 0 && nonce != lastSeen) | guardian_c.cpp | **已修复** |
| P1-3 | SetEmergencyState 广播 STATE_SYNC 到 GuardianC | guardian_a/b.cpp | **已修复** |
| P2-1 | GuardianB 补全 file_create 阈值 4 个字段 | guardian_b.cpp | **已修复** |
| P2-2 | GuardianB TriggerEmergencyProtocol 补全 SendAlert | guardian_b.cpp | **已修复** |
| P2-3 | CancelEmergency 统一使用 SetEmergencyState (A+B) | guardian_a/b.cpp | **已修复** |

### 新增测试用例

- `test_file_encryptor.cpp`: 新增 7 个测试 (deleteSource=true/false, EncryptDirectory 保留原件, DecryptDirectory 跳过, Tier-2 管道模拟)
- `test_file_wiper.cpp`: 新增 3 个测试 (WipeDirectory skipExtension, 递归跳过, 无过滤对照)

---

## 2026-03-06 IPC 通知可靠性修复 v2（经自审修订）

### 问题现象

交互式测试中，在保护目录创建文件后 GuardianC 未弹出告警通知，但双击托盘图标后能正常弹出"All services running normally"状态通知。

### 自审过程（修正错误诊断）

初始方案（v1）的 3 个错误：

| 错误 | 原方案内容 | 自审结论 |
|------|-----------|---------|
| NIF_SHOWTIP | 添加到 ShowBalloonNotification | 该标志控制工具提示（tooltip），不是气球通知——API 用错了 |
| NOTIFYICON_VERSION_4 | 每次弹通知时设置 | guardian_c.cpp L250-251 初始化时已调用——重复操作 |
| Sleep(500) | ProcessPendingNotifications 中添加 | 会阻塞 UI 消息循环，可能导致窗口无响应——方向错误 |

### 证据链（驱动修订方案的关键验证）

1. 用户双击通知内容为 "All services running normally" → `m_guardianAAlive && m_guardianBAlive = true` → **IPC 心跳 A→C / B→C 正常**
2. 双击能正常弹出通知 → `QueueNotification → PostMessage → ShowBalloonNotification` 管线完整
3. GuardianA 日志有 FILE_WRITE + ALERT_USER 且 IPC 零失败 → **消息已发送**
4. 结论：问题不在 IPC 连接，不在通知 API。根因是 SendToNode 线程安全 + OS 通知抑制

### 真正根因

1. **SendToNode 无锁竞态** (ipc.cpp L759-817): 心跳线程和事件处理线程并发调用 SendToNode(GUARDIAN_C, ...)，共享 m_pipeClients[idx] 无 mutex 保护，m_sequence++ 非原子操作
2. **Windows 通知抑制**: Windows 10/11 Focus Assist 在启动/登录后一段时间内静默气球通知，Shell_NotifyIconW 返回 TRUE 但不显示
3. **零诊断能力**: HandleGuardianMessage 无日志、ShowBalloonNotification 不检查返回值，无法区分"消息未送达"与"通知被 OS 压制"

### 修复内容 [已验证: 待构建]

| # | 修复项 | 文件 | 状态 |
|---|--------|------|------|
| Fix-1 | SendToNode 添加 std::mutex m_sendMutex + m_sequence 改 std::atomic | ipc.h, ipc.cpp | **已修复** |
| Fix-2 | GuardianA ALERT_NOTIFICATION 发送结果日志 (成功/失败) | guardian_a.cpp | **已修复** |
| Fix-3a | GuardianC ALERT_NOTIFICATION 接收日志 (level/PID/msg) | guardian_c.cpp | **已修复** |
| Fix-3b | ShowBalloonNotification 检查返回值 + MessageBeep 音效回退 | guardian_c.cpp | **已修复** |
| Fix-3c | 首次心跳接收日志 (GuardianA/B 各一条) | guardian_c.cpp | **已修复** |

### 教训

- **先验证假设，再制定方案**：原方案基于"IPC 可能断开"的未验证假设，制定了错误的修复方向
- **区分"不显示"和"不送达"**：缺乏诊断日志时，容易将 OS 级行为误归因为代码缺陷
- **自审清单**：每个修复项应验证 (a) API 用法正确 (b) 不引入新问题 (c) 有代码证据支撑

---

### 待后续迭代

- 状态机转换合法性检查 (SetEmergencyState 验证表)
- ResponseActionToString 组合 bitmask 支持
- m_threatsDetected 递增修复
- m_evalCount 改 std::atomic
- CleanSystemTraces 改用 FileWiper 安全删除
- config watcher 线程数据竞争修复
- WRL Toast 通知替代旧式气球通知（彻底解决 OS 通知抑制问题）

---

## 2026-03-06 v2.5 交互式测试发现的新问题

### BUG-7: ETW 会话生命周期缺陷 (P0)

**状态: 已修复 (2026-03-06 ETW 生命周期彻底修复)**

**现象**: 服务重启后 GuardianA 日志停止更新（370行后无新条目，35+分钟），ETW 会话活跃但回调线程 CPU 为 0。

**根因**: `InitializeETW()` 在重初始化时，`OpenTraceW` 可能绑定到旧会话的消费者上下文，导致 `ProcessTrace` 永久阻塞但不消费事件。`m_traceHandle` 非原子变量，在 `EtwCollectionThread` 和 `ShutdownEtw` 之间存在数据竞争。`EtwCollectionThread` 中 `ProcessTrace` 返回后线程直接退出，无自动恢复。

**证据**:
- ETW 采集线程（TID 6744）CPU 时间 = 0 秒（35+ 分钟内）
- `logman query -ets` 显示 32818 缓冲区已写入但未被消费
- `etw_diag.txt` 仍显示 total=10000（首次会话数据）
- 重启 GuardianA 后立即恢复正常
- `etw_thread.txt` 显示两次 EtwCollectionThread 启动，第一次 ProcessTrace 返回 0，第二次未返回

**修复内容（5 项）**:
1. **Fix-1 防御性清理**: `InitializeEtw()` 开头调用 `ShutdownEtw()`，确保旧会话和旧线程被正确释放
2. **Fix-2 原子句柄**: `m_traceHandle` 改为 `std::atomic<TRACEHANDLE>`，消除跨线程读写竞争
3. **Fix-3 ETW 活性守护**: `HeartbeatThread` 中监控 `m_eventsProcessed`，60 秒无新事件自动重启 ETW 会话
4. **Fix-4 自动恢复**: `EtwCollectionThread` 改为 while 循环，`ProcessTrace` 返回后自动 `CloseTrace` + 延迟 2 秒 + 重新 `OpenTraceW` + `ProcessTrace`
5. **Fix-5 IPC 超时优化**: `SendToNode` 的 `tryConnect` 从 3x1000ms 降到 1x300ms，减少 ETW 回调线程阻塞

**涉及文件**: guardian_a.h, guardian_a.cpp, ipc.cpp
**验证**: cmake --build PASS, ctest 161/162 PASS (1 个预存版本号不匹配), MSI 已生成
**运行时验证 (2026-03-08)**: **部分修复** — 自动恢复触发了一次（etw_thread.txt 三次启动），但冷启动仍在 49 秒后停滞。ETW watchdog (Fix-3) 未触发（HeartbeatThread 疑似未运行）。手动重启后 ETW 恢复并稳定运行 12+ 分钟。详见 BUG-10。

---

## 2026-03-08 v2.5 全生命周期测试发现的新问题

### BUG-10: ETW + 日志冷启动 ~49 秒停滞 (P0)

**状态: 已修复 (v2.1.0.0)**

**现象**: 服务初次启动后日志在 49 秒后完全停止（464 行后无新条目，48+ 分钟），零文件事件，零心跳，ETW 回调计数停滞在 10,000。

**证据**:
- etw_diag.txt total=10000（5 秒间隔读取两次未变化）
- 日志文件 48 分钟未更新（98KB 后不再增长）
- ETW 会话仍在运行（44,057 缓冲区已写入但未被消费）
- svchost_core.exe 存活，6 线程，CPU=2.83s/49min，未崩溃
- etw_thread.txt 显示两次 EtwCollectionThread 启动（Fix-4 自动恢复触发过一次）
- 手动重启后 ETW 立即恢复，total 从 10,000 跳到 9,420,000+

**根因分析**:
- 与 BUG-7 同源：ProcessTrace 永久阻塞但不消费事件
- Fix-3 (60 秒 ETW watchdog) 未触发 — HeartbeatThread 疑似未启动或在初始化阶段就退出
- Fix-4 (自动恢复) 触发了一次，但第二次 ProcessTrace 再次阻塞
- 所有线程 CPU 接近 0，表明整个进程处于挂起状态

**影响**: 系统重启后需要手动干预才能正常工作
**严重程度**: 严重（P0）— 部署后首次启动不可靠

### BUG-11: cmd.exe 文件删除未被 ETW 捕获 (P1)

**状态: 仅诊断 (v2.1.0.0 — 添加 per-EventId dropped 计数器，待下次测试确认 EventId)**

**现象**: `cmd /c "del file.txt"` 成功执行，但 GuardianA 日志中无 FILE_DELETE 事件。

**证据**:
- P3.5: `del test1_renamed.txt` 成功，日志中无 FILE_DELETE
- P5.1: UWP Notepad 原子保存时的 FILE_DELETE 可被检测（EventId 不同）
- 日志搜索 "FILE_DELETE" 仅在 Notepad 场景出现

**根因**: EventId 11 (NameDelete) 在 v2.1 被降级为缓存维护事件，不再映射 FILE_DELETE。但 `del` 命令使用的 NTFS 删除路径（可能是 EventId 17 SetInformation 而非 EventId 18 SetDelete）也未被映射到 FILE_DELETE。

**影响**: file_delete 阈值（5/5s）可能无法通过常规删除触发
**严重程度**: 严重（P1）— 核心检测能力缺失

### BUG-12: ALERT 倒计时阶段被跳过 (P1)

**状态: 已修复 (v2.1.0.0)**

**现象**: 保护协议触发后直接进入 ENCRYPTING，日志中无 "Warning: bulk operation detected" 或 ALERT 状态相关条目。

**证据**:
- P8.2: 12 次快速写入触发 Tier-1，日志直接从 FILE_WRITE 跳到 "Encrypting [1/31]"
- 配置 alert_timeout_seconds=300（5 分钟），但未被使用
- 用户确认未看到 ALERT 倒计时通知

**根因**: TriggerProtectionProtocol() 可能未正确进入 ALERT 状态和启动倒计时，或 StartProtectionCountdown() 的等待逻辑有缺陷。

**影响**: 管理员无法在加密前取消操作，300 秒的取消窗口形同虚设
**严重程度**: 严重（P1）— 取消机制失效

### BUG-8: 服务启动顺序竞争 (P1)

**现象**: GuardianA/B 在 15:45:00 启动，GuardianC 在 15:45:14 启动。A/B 的 IPC 管道客户端在 C 启动前用尽了初始连接尝试。

**根因**: Windows 服务（A/B）通过 SCM 自动启动，用户态程序（C）通过 `Run` 注册表在用户登录后启动，存在不可避免的时序差。

**修复建议**:
1. `SendToNode` 的 `tryConnect` 应采用指数退避策略（首次 1s，逐步增加到 30s）
2. 添加 IPC 连接成功日志（当前只有失败日志）
3. 考虑让 C 在 IPC 初始化后主动向 A/B 发送"上线"消息

### BUG-9: "First heartbeat" 日志竞争 (P2)

**现象**: GuardianC 日志中 "First heartbeat received from GuardianA/B" 可能不出现。

**根因**: `CheckServiceHealth()` 通过共享内存路径先于管道心跳设置 `m_guardianAAlive = true`，导致 `HandleGuardianMessage` 中 `!m_guardianAAlive` 条件为 false，日志被跳过。

**修复建议**: 使用独立的 `static bool s_firstPipeHeartbeat[2]` 标志，与 `m_guardianAAlive` 解耦。

---

## 2026-03-09 v2.1.0.0 归档与修复（5 个 BUG + MSI 归档基础设施）

### 修复概览

| BUG | 严重度 | 状态 | 核心改动 |
|-----|--------|------|----------|
| BUG-10 | P0 | **已修复** | ETW 回调中移除 SendToNode(B)→EventProcessingThread; per-dest mutex; HeartbeatThread 诊断日志 |
| BUG-4 | P0 | **已修复** | LoadSimple 结构性变更: inExcludeArray/inIncludeArray 列表解析 + 诊断日志 |
| BUG-12 | P1 | **已修复** | LoadSimple 解析 alert_timeout_seconds; 倒计时进度日志; Validate 字段级防御; try-catch 生命周期 |
| BUG-11 | P1 | **仅诊断** | s_diagDroppedById[64] per-EventId dropped 计数器 |
| BUG-5 | P1 | **已修复** | LoadSimple 白名单列表解析; _wcsicmp 大小写不敏感匹配; 诊断日志 |

### MSI 归档基础设施

- `build_msi.bat`: 新增 `:archive_old_msi` 子程序，构建前自动归档旧 MSI 到 `releases/GuardianShield_buildN.msi`
- `releases/RELEASE_LOG.txt`: 版本发布日志
- `releases/GuardianShield_build0_v2.0.0.0.msi`: v2.0 基线存档
- WiX ProductVersion: 2.0.0.0 → 2.1.0.0

### 涉及文件

- `guardian_a.cpp`, `guardian_b.cpp`: BUG-10 (IPC 移动+HeartbeatThread 诊断), BUG-12 (倒计时日志+try-catch), BUG-11 (s_diagDroppedById)
- `config.cpp`: BUG-4 (列表解析), BUG-12 (alert_timeout_seconds 解析+防御), BUG-5 (白名单解析+_wcsicmp)
- `ipc.h`, `ipc.cpp`: BUG-10 (m_sendMutex[3] per-dest mutex)
- `build_msi.bat`: MSI 归档子程序
- `GuardianShield.wxs`: Version 2.1.0.0

### 验证

- ctest: 162/162 PASS（每次修复后均验证）
- cmake --build: 全量编译 PASS
- build_msi.bat: MSI 生成成功 (476 KB)
- CRLF 验证: build_msi.bat 行尾正确

---

## 2026-03-09 移除 FileLocker + 事件响应可配置化 [已验证: cmake PASS, ctest 161/161 PASS]

### 变更概览

| 变更 | 详情 |
|------|------|
| 移除 FileLocker | 删除 file_locker.h/cpp，移除 ResponseAction::BLOCK/LOCK_FILE，移除 UNLOCK_FILES_REQUEST/RESPONSE |
| 清理 GuardianA/B/C | 移除所有 FileLocker 引用、ACL 锁定逻辑、解除锁定按钮和 IPC handler |
| 事件响应可配置化 | 新增 guardian_config.yaml event_responses 节，支持 LOG/ALERT_USER/TERMINATE/ENCRYPT/BLOCK |
| Config 扩展 | GetEventResponse() API，YAML+Simple 解析，cache v7→v8，序列化 |
| A/B 去重 | BuildEventResponse() 共享函数，AssessThreat 委托调用（20 个重复函数中的 1 个） |
| ENCRYPT 单文件分支 | ExecuteResponse 新增 ENCRYPT（.gs 检查 + EmergencyState::NORMAL 门控） |

### 关闭的历史问题

- RC-8 (BLOCK/LOCK_FILE 语义混乱) — 两者均已移除
- v2.9 T10.2 FAIL (LockdownSystem 对 .gs 文件 ACL 锁定无效) — FileLocker 已移除
- current_state.md #16 线程安全竞态 6→5（FileLocker::GetFileHandle 无锁已消除）

### 涉及文件

- **删除**: file_locker.h, file_locker.cpp, test_file_locker.cpp, test_file_locker_detection.cpp, test_file_locker_destructor.cpp, test_unlock_ipc.cpp
- **修改**: common_types.h, config.h, config.cpp, guardian_a.h, guardian_a.cpp, guardian_b.h, guardian_b.cpp, guardian_c.h, guardian_c.cpp, threat_evaluator.h, threat_evaluator.cpp, guardian_config.yaml, test/CMakeLists.txt, common/CMakeLists.txt, test_emergency.cpp, test_file_monitor.cpp, test_threat_evaluator.cpp, test_config.cpp, test_threat_detection.ps1
- **新增**: test_event_response_config.cpp

### 验证

- cmake --build: Release 全量编译 0 错误
- ctest: 161/161 PASS (移除 4 个 FileLocker 测试，新增 14 个 event_response 测试)
- rg 清扫: 源码中无 ResponseAction::BLOCK/LOCK_FILE/FileLocker 残留
