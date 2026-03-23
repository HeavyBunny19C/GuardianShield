# 当前状态 (Current State)

**最后更新**: 2026-03-18 (v3.3.0 威胁检测聚焦版本)

### v3.3.0 威胁检测聚焦版本变更
- **[P0] 默认值安全加固**: `DetectionThresholds::process_termination_count` 从 2 改为 50，消除配置加载失败时的秒级自毁风险
- **[P0] FILE_RENAME 批量检测**: 新增 `file_rename_count`/`file_rename_window_seconds` 阈值 (Tier1=10/5s, Tier2=50/10s)，补齐勒索软件批量重命名检测
- **[P1] GuardianB 行为对齐**: 空路径过滤、目录级过滤、批量触发不短路、精准终止、ResponseActionCombinedToString 日志
- **[P1] 清理纸面事件类型**: 在 enum、config 解析、默认响应、driver header、文档中注释掉 7 个未实现类型 (FILE_READ/SET_INFO/PROCESS_INJECT/DEBUG/NETWORK_CONNECT/SEND/RECV)；FILE_MOVE 已实现 (v3.3)  via CREATE+DELETE 事件关联
- **[P2] 死代码清理**: 移除 m_tieredMode、ThreatEvaluation 结构体；标注 7 个 CheckBatch*() 为 test-only
- **[P2] 测试加固**: 填充 4 个空体 EventClassificationTest；修复 BuildEventResponse_TerminateIsLevel2 测试；新增 5 个 FILE_RENAME 批量测试
- **缓存版本**: v10 → v11 (新增 file_rename 字段)
- **192/192 单元测试全部通过**（含 12 个新增动作审计测试）

## 最新验证结果 (v2.5 全生命周期测试 2026-03-08)

| 阶段 | 测试项 | 结果 | 关键发现 |
|------|--------|------|---------|
| Phase 0 | 环境健康检查 (4项) | 4/4 PASS | 三组件运行 + 托盘绿色 + config_cache.bin |
| Phase 1 | ETW+IPC 首次启动 (5项) | 3/5 PASS | **BUG-10**: 冷启动 49 秒后 ETW 停滞，手动重启后恢复 |
| Phase 2 | 通知系统 (3项) | 3/3 PASS | 气球通知+状态通知+无洪泛 |
| Phase 3 | 单文件事件 (6项) | 5/6 PASS | **BUG-11**: FILE_DELETE (cmd del) 未被捕获 |
| Phase 4 | 文件类型过滤 (3项) | 1/3 PASS | BUG-4 仍未修复: .log/.tmp 未排除 |
| Phase 5 | 进程白名单 (3项) | 2/3 PASS | BUG-5 仍未修复: UWP Notepad 白名单失效 |
| Phase 6 | 路径过滤 (2项) | 2/2 PASS | 目录内/外/子目录正确 |
| Phase 7 | ETW 稳定性 (2项) | 2/2 PASS | 重启后 12+ 分钟持续稳定 |
| Phase 8 | 批量阈值+紧急协议 (5项) | 4/5 PASS | **BUG-12**: ALERT 倒计时跳过 |
| Phase 9 | 文件管理+一键解锁 (4项) | 4/4 PASS | 29 文件解密还原+ACL 恢复 |
| Phase 10 | 故障转移+韧性 (3项) | 2.5/3 PASS | ~1-2s 崩溃检测，恢复正常 |

### 上轮 Bug 回归验证 (4/8 已修复)

- ~~BUG-1 [致命] System PID 4 误判~~ → **已修复**
- ~~BUG-2 [致命] 通知洪泛~~ → **已修复**
- ~~BUG-3 [致命] explorer 被终止~~ → **已修复**
- ~~BUG-7 [中] 事件重复~~ → **已修复**
- BUG-4 [严重] 文件类型过滤 → **仍未修复**
- BUG-5 [严重] UWP 白名单 → **仍未修复**
- BUG-6 [严重] ETW 启动时序 → **部分修复** (BUG-10)
- ~~BUG-8 [中] 服务名混淆~~ → **已修复**

### v2.1.0.0 已修复问题

1. ~~**BUG-10 [严重]: ETW 冷启动 ~49 秒停滞**~~ → **已修复 (v2.1)**: ETW 回调中移除 SendToNode(B)，改到 EventProcessingThread；per-dest mutex 隔离；HeartbeatThread 诊断日志；C 优先发送
2. **BUG-11 [严重]: cmd.exe 文件删除未被 ETW 捕获** — 仅添加 per-EventId dropped 诊断计数，待下次测试确认 EventId 后决定检测逻辑
3. ~~**BUG-12 [严重]: ALERT 倒计时阶段被跳过**~~ → **已修复 (v2.1)**: LoadSimple 解析 alert_timeout_seconds；倒计时每 10 秒输出进度日志；Validate() 字段级防御；m_protocolActive try-catch 生命周期管理。**注意**: ALERT 从默认 30s 变为配置的 300s
4. ~~**BUG-4 [严重]: 文件类型过滤失效**~~ → **已修复 (v2.1)**: LoadSimple 结构性变更，添加 inExcludeArray/inIncludeArray 列表解析通道
5. ~~**BUG-5 [严重]: UWP 白名单失效**~~ → **已修复 (v2.1)**: LoadSimple 添加白名单列表解析；IsProcessWhitelisted 改用 _wcsicmp 大小写不敏感匹配
6. **BUG-8: 启动顺序竞争** — A/B 比 C 先启动 ~14 秒，IPC 管道连接延迟（未修复）
7. **BUG-9: "First heartbeat" 日志竞争** — 共享内存路径抢先设置 m_guardianAAlive（未修复）

---

## 项目版本

- WiX ProductVersion: 2.1.0.0
- 配置文件版本: 3.3.0
- CMake 项目名: GuardianShield
- 内部开发代号: v2.5
- MSI 归档: releases/GuardianShield_build0_v2.0.0.0.msi (baseline), releases/GuardianShield_build1.msi (v2.1 pre-fixes)

---

## 构建状态

| 组件 | 输出文件 | 大小 | 状态 |
|------|---------|------|------|
| GuardianA | `build/src/service/GuardianA/Release/svchost_core.exe` | ~245 KB | v3.1 编译通过 |
| GuardianB | `build/src/service/GuardianB/Release/svchost_helper.exe` | ~243 KB | v3.1 编译通过 |
| GuardianC | `build/src/service/GuardianC/Release/winmon.exe` | ~158 KB | 编译通过 |
| CustomAction | `build/bin/Release/guardian_ca.dll` | ~23 KB | 编译通过 |
| MSI Installer | `build/bin/Release/GuardianShield.msi` | ~480 KB | v3.1 打包成功 |
| Tests | `build/test/Release/GuardianTests.exe` | — | 192/192 PASS |
| ConfigManager | `build/tools/GuardianConfigManager/GuardianConfigManager.exe` | 148.5 KB | 编译通过 (.NET 8 WPF) |

**部署状态**: MSI 已安装，三组件均在运行（手动重启后恢复）
**配置状态**: config_cache.bin 已重新生成，YAML/auth.list 已自动删除，保护路径 `C:\Users\Administrator\Documents\test`
**IPC 状态**: 服务恢复正常后需重新验证
**密码**: 紧急解锁 `GuardianShield_Emergency` (password_hash)，安装密钥 `GuardianShield2026!` (install_key_hash)。注: YAML 默认密码注释为 `GuardianShield2026!`，MSI 也注入此值为 INSTALL_KEY
**交互式测试**: 19 项测试完成，9 PASS / 5 FAIL / 3 BLOCKED，发现 8 个 Bug（3 致命/3 严重/2 中等）→ `tests/TEST_REPORT_interactive_2026-03-05.md`

### v2.7 MajorUpgrade 配置保护修复 (2026-03-09)

**根因**: MajorUpgrade 卸载旧版时 RemoveFile/RemoveFolder 摧毁 config_cache.bin → 新版部署默认 auth.list（开发环境 IP/MAC）→ 开机时网络未就绪 → 授权检查失败 → Tier-2 紧急协议 → 文件加密+心跳停止

**修复内容**:
1. `config/auth.list` 改为仅含注释的空列表（新安装进入安全模式而非紧急协议）
2. `guardian_ca.cpp` 新增 `BackupConfigCache`/`RestoreConfigCache` 导出函数
3. `GuardianShield.wxs` 新增 `CA_BackupConfigCache`（Before RemoveExistingProducts）和 `CA_RestoreConfigCache`（After RemoveExistingProducts）自定义动作
4. 紧急恢复：停止服务 → 删除旧 config_cache.bin → 重新部署配置 → 重启服务

### v2.8 冷启动三层防御修复 (2026-03-09)

**根因**: `GetAllNetworkInterfaces()` L248 跳过 IP="0.0.0.0" 的接口。冷启动时 DHCP 未完成，所有接口 IP 都是 "0.0.0.0"，函数返回空列表。`IsAuthorized()` 要求 IP+MAC 同时匹配，空列表 → 无任何接口可匹配 → 授权失败 → Tier-2 紧急协议。v2.7 的 Sleep(2000) 单次重试不够。

**三层防御**:
1. **Layer 1 (根本修复)**: `environment_validator.cpp` — 移除 "0.0.0.0" 跳过逻辑，让 MAC 始终可用；`IsAuthorized()` 在 IP 为 "0.0.0.0" 时视为通配符，仅靠 MAC 匹配
2. **Layer 2 (安全网)**: `guardian_a.cpp` / `guardian_b.cpp` — `ValidateEnvironment()` 改为 10 次 × 3 秒智能重试，区分"有真实 IP 但不匹配"（立即失败=未授权）和"无真实 IP"（继续等=网络未就绪）
3. **Layer 3 (安装器层)**: `GuardianShield.wxs` — 两个 ServiceInstall 添加 `<ServiceDependency Id="Tcpip" />`，让 SCM 在 TCP/IP 协议栈就绪后才启动服务

### v2.9 UX改善 + 状态管理 + 安全强化 (2026-03-09)

**Phase 1: 纯 UI 展示改动**
1. **弹窗通知引导文字**: `guardian_c.cpp` — 安全警报弹窗追加 "→ 右键托盘 → 文件管理" 引导文字
2. ~~**文件管理面板双状态显示**~~ → **已简化**: PopulateFileList() 仅扫描 .gs 加密文件（FileLocker 已移除，ACL 检测逻辑已删除）
3. ~~**新增单元测试**: `test/test_file_locker_detection.cpp`~~ → **已删除** (FileLocker 移除)

**Phase 2: 状态管理 + 安全强化**
1. **ALERT 自动恢复（双端同步）**: GuardianA/B `StartProtectionCountdown` 取消时和 `CancelEmergency()` 中广播 `STATE_SYNC(NORMAL)`；GuardianC `STATE_SYNC` 处理增加 NORMAL 分支（托盘从黄变绿）；120 秒时间兜底（`m_lastAlertTimeMs` 原子变量）
2. ~~**UNLOCK_FILES IPC 消息**~~ → **已移除**: UNLOCK_FILES_REQUEST/RESPONSE 随 FileLocker 一并删除
3. ~~**解除锁定按钮**~~ → **已移除**: FileLocker 移除后无需 ACL 解锁按钮
4. ~~**GuardianA UNLOCK_FILES_REQUEST 处理**~~ → **已移除**: 整条 handler 已删除
5. ~~**FileLocker 条件析构**~~ → **已移除**: file_locker.h/cpp 已删除
6. ~~**新增单元测试**: `test_file_locker_destructor.cpp`/`test_unlock_ipc.cpp`~~ → **已删除** (FileLocker 移除)

**测试结果**: 169/169 全部 PASS (含新增 7 个测试)，MSI 构建成功 (491KB)

### v3.1 功能正确性整改 (2026-03-10)

**触发**: 深度架构缺陷分析 → 逐一验证 → 14 项真实功能缺陷修复

**修复内容**:
1. event_type 范围校验 (A+B HandleDriverEvent)
2. GuardianB 补齐 IsFileTypeMonitored
3. deleteSource 失败返回 false (4处)
4. EncryptDirectory/WipeDirectory 失败日志
5. TerminateProcess 返回值验证 + WaitForSingleObject (3处)
6. LoadYaml 后 SaveToCache
7. Config::Validate 上限校验
8. GuardianB DriverReadThread (promote failover 事件源)
9. GuardianB 事件去重
10. GuardianC 超时自动重启 (OnNodeTimeout)
11. DriverReadThread 断连重连
12. EncryptFile 原子写入 (.gs.tmp → rename)
13. emergency_executor 死代码删除
14. CMakeLists.txt 更新

**验证的误报 (7项)**: m_encryptedFiles mutex / heartbeat mutex / s_dropCount atomic / Tier1→Tier2 cancelCb / LockdownSystem 超时 / StreamEncryptFile / 去重含 process_id — 均已在之前版本中修复

**测试结果**: 161/162 PASS (1 个预存在的 EventResponseConfig 测试失败), MSI 构建成功

### v3.2 BLOCK 响应动作 (2026-03-10)

**触发**: 用户要求阻止保护目录中文件被移动/重命名 → 需要内核级 BLOCK

**修复内容**:
1. [F1] GuardianB 驱动连接端口名修正 (GUARDFILTER_USERMODE_PATH → GUARDFILTER_PORT_NAME)
2. [F2] GuardianB LoadProtectedPaths 补齐驱动同步
3. [F3/RISK-1/2] 启动时白名单同步到驱动 (Guardian 进程 + YAML 配置)
4. [F4] 驱动重连后恢复白名单 + block policy + 保护路径
5. [F5] ResponseActionCombinedToString 补齐 BLOCK/ENCRYPT
6. [F6] BLOCK 映射为 LEVEL_2 威胁等级
7. [F7] GuardianB ExecuteResponse 补齐 BLOCK 分支
8. ResponseAction::BLOCK = 0x10 + config 解析 + YAML 配置
9. BLOCK+TERMINATE 自动降级 (RISK-4)
10. 驱动未连接时 BLOCK 跳过（不降级为 TERMINATE）+ WARNING 日志 (RISK-6)

**测试结果**: 166/167 PASS (同一个预存在的失败), 5 个新 BLOCK 测试全部通过, 驱动编译成功

**编译环境**: Visual Studio 2022 Community, Windows SDK 10.0.22621.0, C++17
**WiX Toolset**: v3.14 (位于 `C:\Program Files (x86)\WiX Toolset v3.14\bin`)
**已知 warnings**: `wchar_t -> char` 隐式转换 (C4244), `WIN32_LEAN_AND_MEAN` 重定义 (C4005) -- 均为预存问题

---

## 已完成的功能

### 核心功能
- [x] 三层响应架构 (单事件/Tier1 保护协议/Tier2 紧急协议)
- [x] BLOCK 响应动作: 内核级文件操作拦截 (FILE_RENAME 默认启用)
- [x] 两级批量操作检测阈值 (tier1 + tier2)
- [x] ETW 事件采集由 GuardianA 直接执行 (FILE_CREATE, FILE_WRITE, FILE_DELETE, FILE_RENAME, PROCESS_CREATE, PROC_TERMINATE)
- [x] ETW 生命周期防护: 防御性清理 + 原子句柄 + 60s 活性守护 + ProcessTrace 自动恢复
- [x] ETW file_path 解析 (TdhGetProperty + FileObject 缓存)
- [x] ETW data_size 解析 (IoSize)
- [x] ETW 诊断计数器 (s_diagCounts / s_diagDropped / s_diagDroppedById[64])
- [x] 压缩/网络工具启发式分类
- [x] 单事件 inProtectedPath 门控（防止告警洪泛）
- [x] process_termination_count 批量检测
- [x] IPC per-dest mutex (m_sendMutex[3]) + atomic 序列号 + 300ms 单次超时
- [x] 文件加密 (AES-256 双模式: ≤100MB GCM/GSENCR01; >100MB CBC+HMAC/GSENCR02, 密钥 PBKDF2-SHA256)
- [x] 文件安全擦除 (DOD 5220.22-M 7-pass, FileWiper)
- [x] 环境验证 (IP/MAC 授权, EnvironmentValidator)
- [x] IPC 通信 (Named Pipes, Shared Memory)
- [x] 心跳监控和故障转移 (GuardianA -> GuardianB)
- [x] 告警通知通过 IPC 路由到 GuardianC 桌面（v2.6: 全部中文本地化，产品名统一为「系统防护」，路径仅显示文件名）
- [x] 托盘右键菜单退出按钮已隐藏（防止用户误退出 GuardianC）
- [x] 文件管理面板（GuardianC 托盘右键→文件管理，ListView 展示 .gs 加密文件）
- [x] 一键解密（ACL 恢复 + .gs 解密，密码验证，IPC 路由到主控节点执行）
- [x] 文件管理面板显示加密文件（.gs 加密文件列表）
- [x] 弹窗通知引导文字（"→ 右键托盘 → 文件管理"）
- [x] ALERT 自动恢复（STATE_SYNC NORMAL 双端广播 + 120s 时间兜底）
- [x] DecryptDirectory 批量解密（含原始文件存在性检查，跳过已恢复文件）
- [x] DECRYPT_REQUEST/DECRYPT_RESPONSE IPC 消息类型
- [x] 解密线程化执行（不阻塞 IPC 心跳，防止备份节点误接管）
- [x] RAII ProtocolGuard 确保 m_protocolActive 在解密后必恢复
- [x] 状态门禁：ENCRYPTING/WIPING/DELETING/ALERT 状态拒绝解密请求
- [x] 原子互斥标志 m_decryptInProgress 防止并发解密
- [x] event_type 范围校验 (MAX_TYPE 哨兵, GuardianA + GuardianB)
- [x] GuardianB 文件类型过滤对齐 (IsFileTypeMonitored)
- [x] GuardianB 事件去重 (hash + 500ms 窗口, 与 GuardianA 一致)
- [x] GuardianB failover DriverReadThread (promote 时启动, demote 时停止)
- [x] GuardianC 超时自动重启 (OnNodeTimeout → CreateProcessW winmon.exe)
- [x] DriverReadThread 断连重连 (10s 间隔)
- [x] EncryptFile 原子写入 (.gs.tmp → MoveFileExW → .gs)
- [x] deleteSource 失败正确返回 false (4处)
- [x] TerminateProcess 返回值验证 + WaitForSingleObject (3处)
- [x] Config::Validate 上限校验 (window/retention/timeout/threshold)
- [x] LoadYaml 后自动 SaveToCache

### 安装与运维
- [x] MSI 安装包 (自定义 WiX .wxs)
- [x] 自定义安装对话框 (v2.6: 流程简化 — Welcome → VerifyReady，跳过密码/配置对话框；INSTALL_KEY 采用 Approach B 自动注入)
- [x] 卸载脚本 (scripts/uninstall.bat, 支持 -key 参数, 后台超时卸载, 无条件 pause, 无 EnableDelayedExpansion, 无 powershell 依赖)
- [x] MSI 卸载清理 ProgramData + HKCU 注册表
- [x] MSI 交互式卸载密钥对话框 (UninstallKeyDlg)
- [x] SHA-256 哈希工具 (tools/hash_tool.py + hash_tool.bat)
- [x] 日志系统 (JSON 格式, 每日轮转)

### 配置与管理
- [x] YAML 配置文件 (guardian_config.yaml)
- [x] 配置读取后自动删除 (防泄露)
- [x] 二进制缓存 + ACL 保护（v8 格式，含 event_responses 序列化）
- [x] 锁屏界面 (管理员密码解锁)
- [x] 事件响应可配置化 (detection.event_responses YAML 节，支持 LOG/ALERT_USER/TERMINATE/ENCRYPT/BLOCK)

---

## 已知限制与潜在改进

### 已知限制
1. ~~**BLOCK 操作已降级实现**~~ → **已移除 (v3.0)**: FileLocker 及 BLOCK/LOCK_FILE 动作已完全移除，事件响应改为 YAML 可配置
2. **启发式检测覆盖有限**: 只匹配固定进程名列表，无法识别改名工具或浏览器上传
3. **编译 warnings 未清理**: `wchar_t -> char` 隐式转换散布在多处（应使用 WideCharToMultiByte）
4. **内核驱动未构建**: `BUILD_DRIVERS=OFF`，GuardFilter 迷你过滤器未编译（需要 WDK）
5. **测试覆盖**: `tests/test_file_protection.ps1` + `tests/TEST_REPORT_2026-03-05.md` (自动化) + `tests/TEST_REPORT_interactive_2026-03-05.md` (交互式)。交互式测试: 19 项，9 PASS / 5 FAIL / 3 BLOCKED。发现 8 个新 Bug（含 3 个致命）
6. **emergency.encrypt_timeout_seconds 未参与加密阶段**: 该配置项已从 YAML 读取并由 `Config::Validate()` 校验，但 GuardianA/GuardianB 的 `EncryptProtectedFiles()` 目前未使用超时控制；ALERT 阶段倒计时由 `detection.alert_timeout_seconds` 控制
7. ~~**[致命] process_termination 导致启动自毁**~~ → **已修复**: 进程事件不再参与文件保护批量阈值检查
8. ~~**[严重] IPC 通信全面断开**~~ → **已修复**: 管道 SDDL 增加 IU；共享内存改 Global 命名空间；AcceptLoop 增加边界处理
9. ~~**[严重] 排除文件类型未过滤**~~ → **已修复**: IsFileTypeMonitored() 新增 excludeFileTypes 检查
10. ~~**[中] MSI 未部署 config 文件**~~ → **已修复**: WiX 新增 File 元素打包 config 文件
11. ~~**[中] SearchProtocolHost.exe 放大事件计数**~~ → **已修复**: 新增系统级硬编码白名单

12. **[待修复] GuardianA/B 代码重复**: 20+ 个函数中 AssessThreat 已通过 BuildEventResponse 共享函数去重（1/20），其余待 GuardianCore 基类。
13. **[待修复] config.cpp CreateMutexW 崩溃**: 返回 NULL 时 WaitForSingleObject(NULL) 行为未定义
14. ~~**[待修复] GuardianC wstring 构造**~~ → **已修复 (v2.6)**: MultiByteToWideChar(CP_UTF8) 正确转换
15. **[待修复] 配置系统 18 字段未实现**: YAML 字段给管理员虚假安全感
16. **[待修复] 5 个线程安全竞态**: Config watcher/SharedMemory/SendToNode/心跳/m_isPrimary（FileLocker 竞态已消除）
17. **[待修复] 威胁评估 4 个数据失真**: 硬编码窗口/RENAME 计入删除/ETW data_size=0/无扩展名不监控
18. **[待修复] 注册表键名不一致**: WiX=WindowsMonitor vs 代码=GuardianC
19. **[待修复] 测试空洞**: EventClassificationTest 零断言

### 潜在改进
1. 实现 DriverClient 的 `BlockOperation` 和 `BlockProcess` IOCTL 接口
2. 扩展启发式规则为可配置的进程名列表 (在 YAML 中定义)
3. 添加 WRL (Windows Runtime Library) 的 Toast 通知替代旧式气球通知
4. ~~添加服务运行时的集成测试~~ → 已实现 `tests/test_file_protection.ps1`（4 层 34 项）
5. 清理 wchar_t -> char 转换 warnings
6. 启用 `emergency.encrypt_timeout_seconds` 在加密阶段生效（当前仅 `detection.alert_timeout_seconds` 用于 ALERT 倒计时；encrypt_timeout 已读取、未使用）
7. **创建 GuardianCore 基类消除 A/B 代码重复（最高优先级结构性改进）**
8. **创建 verify.ps1 自动化验证脚本**
9. **清理 YAML 中未实现的配置字段**
10. **WRL Toast 通知替代旧式气球通知**（彻底解决 Windows 10/11 Focus Assist 通知抑制问题）

---

## 项目目录结构

```
GuardianShield/
├── build/                      # CMake 构建输出
├── cmake/                      # CMake 模块
├── config/                     # 配置文件模板
│   └── guardian_config.yaml    # 主配置文件
├── docs/                       # 文档
├── memory/                     # 项目记忆库 (本文件夹)
├── scripts/                    # 运维脚本
│   └── uninstall.bat
├── src/
│   ├── driver/                 # 内核驱动 (GuardFilter)
│   ├── installer/              # WiX 安装器定义
│   │   ├── GuardianShield.wxs
│   │   └── InstallDlg.wxs
│   ├── tools/
│   │   └── GuardianConfigManager/  # C# WPF 配置管理工具
│   └── service/
│       ├── common/             # 公共库 (GuardianCommon.lib)
│       ├── GuardianA/          # 主控服务
│       ├── GuardianB/          # 备份服务
│       └── GuardianC/          # 用户态监控
├── tests/                      # 测试脚本
│   ├── test_file_protection.ps1    # 文件防护完整测试 (4层34项)
│   ├── test_threat_detection.ps1   # 威胁检测冒烟测试 (旧)
│   └── test_full_lifecycle.ps1     # 全生命周期测试 (旧)
├── tools/                      # 工具
│   ├── hash_tool.py
│   └── hash_tool.bat
├── build.bat                   # 编译脚本
├── build_msi.bat               # MSI 打包脚本
├── run.bat                     # 主控制台菜单
└── CMakeLists.txt              # 根 CMake 文件
```

---

## 关键文件路径 (快速参考)

| 用途 | 路径 |
|------|------|
| GuardianA 主逻辑 | `src/service/GuardianA/src/guardian_a.cpp` |
| GuardianA 头文件 | `src/service/GuardianA/include/guardian_a.h` |
| 威胁评估器 | `src/service/GuardianA/src/threat_evaluator.cpp` |
| 威胁评估器头文件 | `src/service/GuardianA/include/threat_evaluator.h` |
| GuardianB 主逻辑 | `src/service/GuardianB/src/guardian_b.cpp` |
| GuardianC 主逻辑 | `src/service/GuardianC/src/guardian_c.cpp` |
| 公共类型定义 | `src/service/common/include/common_types.h` |
| 配置解析 | `src/service/common/src/config.cpp` |
| 配置头文件 | `src/service/common/include/config.h` |
| YAML 配置 | `config/guardian_config.yaml` |
| WiX 主文件 | `src/installer/GuardianShield.wxs` |
| 安装对话框 | `src/installer/InstallDlg.wxs` |
| 卸载脚本 | `scripts/uninstall.bat` |
| MSI 打包脚本 | `build_msi.bat` |

---

## 安装路径 (运行时)

| 内容 | 路径 |
|------|------|
| 服务可执行文件 | `C:\Program Files\GuardianShield\` |
| 配置文件 (一次性) | `C:\ProgramData\GuardianShield\config\guardian_config.yaml` |
| 配置缓存 (二进制) | `C:\ProgramData\GuardianShield\config_cache.bin` |
| 日志目录 | `C:\ProgramData\GuardianShield\logs\` |
| 授权列表 | `C:\ProgramData\GuardianShield\config\auth.list` |
| GuardianC 自启动 | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
