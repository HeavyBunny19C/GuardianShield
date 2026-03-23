# 架构决策记录 (Architecture Decision Records)

记录 GuardianShield 开发过程中做出的关键设计决策，以及选择的理由。

---

## ADR-001: 三层响应架构

**日期**: 2026-03-03
**状态**: 已实施
**背景**: 原始设计中，单个 `FILE_NETWORK_TRANSFER` 事件即触发 `LEVEL_3 + ENCRYPT + WIPE`，这意味着一个误判就会导致不可逆的数据销毁。批量操作检测仅返回 `LEVEL_2`，无法触发 `LEVEL_3` 的紧急协议。用户在保护路径内压缩 50 个文件后未触发任何响应。

**决策**: 实施三层响应架构：

| 层级 | 触发条件 | 动作 | 可恢复性 |
|------|---------|------|---------|
| 单事件层 | 每个文件操作事件 | LOG, ALERT_USER, TERMINATE, ENCRYPT, BLOCK (可配置) | 无破坏 |
| Tier 1 (保护协议) | 批量操作超过 tier1 阈值 | 全目录加密 | 可恢复 |
| Tier 2 (紧急协议) | 批量操作超过 tier2 阈值 / 未授权设备 | 加密 + 擦除 + 删除 + 锁定系统 | 不可逆 |

**理由**:
- 单事件绝不执行破坏性操作，避免误判导致数据丢失
- 两级阈值提供缓冲：Tier 1 是可恢复的保护措施，Tier 2 才是最终手段
- 未授权设备启动直接跳到 Tier 2 (skipAlert=true)，因为此时已确认威胁

**替代方案被否决**:
- 单一阈值方案：无法区分轻度和重度威胁，要么过于激进要么过于保守
- 单事件触发加密：用户明确反对，一个操作不应毁掉所有数据

---

## ADR-002: 告警通知通过 IPC 路由到 GuardianC

**日期**: 2026-03-03
**状态**: 已实施
**背景**: GuardianA 作为 Windows 服务运行在 Session 0，无法访问用户桌面。`NotificationManager` 依赖 `GetDesktopWindow()` 获取系统托盘句柄，在 Session 0 中始终失败，导致告警通知无法显示。

**决策**: GuardianA 将告警信息封装为 `AlertNotification` 结构体，通过 IPC (`MessageType::ALERT_NOTIFICATION`) 发送给 GuardianC。GuardianC 运行在用户的交互式 Session 中，收到后调用 `QueueNotification()` 弹出气球通知。

**理由**:
- GuardianC 已有完整的系统托盘和通知机制
- IPC 通道已经存在且可靠
- 遵循 Windows 服务架构的最佳实践：服务层不直接与用户桌面交互

**AlertNotification 结构体**:
```
struct AlertNotification {
    uint8_t     level;              // ThreatLevel
    uint8_t     reserved[3];
    uint32_t    process_id;
    char        message[256];       // UTF-8
    wchar_t     file_path[MAX_PATH_LENGTH];
};
```

---

## ADR-003: GuardianB 简化为转发器 + ThreatEvaluator 复用

**日期**: 2026-03-03
**状态**: 已实施
**背景**: GuardianB 原本有自己独立的 `AssessThreat()` 和 `ExecuteResponse()` 实现，与 GuardianA 的逻辑不同步。在 GuardianA 重新设计后，GuardianB 的行为与 GuardianA 完全不一致。

**决策**:
- **Backup 模式**: GuardianB 只转发收到的事件给 GuardianA，不做任何威胁评估
- **Primary 模式** (GuardianA 故障后): GuardianB 复用相同的 `ThreatEvaluator` 类和两级阈值逻辑

**理由**:
- 一份逻辑、两处使用，消除行为分歧
- 通过 `CMakeLists.txt` 直接引入 `threat_evaluator.cpp` 源文件实现共享
- GuardianB 的 `ExecuteResponse` 也同步移除了单事件 ENCRYPT/WIPE 分支

---

## ADR-004: ETW 事件分类 + 启发式进程识别

**日期**: 2026-03-03
**状态**: 已实施
**背景**: GuardianC 的 ETW 回调只映射了 `FILE_CREATE`(opcode 0)、`FILE_DELETE`(opcode 35)、`FILE_RENAME`(opcode 36)，所有其他文件操作都默认为 `FILE_READ`。缺少 `FILE_WRITE` 映射，也无法识别压缩或网络传输行为。

**决策**:
1. 新增 opcode 32 -> `FILE_WRITE` 映射
2. 对所有文件事件，通过 `QueryFullProcessImageNameW()` 获取进程镜像名
3. 根据进程名匹配已知工具进行启发式重分类:
   - `7z`, `WinRAR`, `winrar`, `zip`, `tar` -> `FILE_COMPRESS`
   - `scp`, `sftp`, `curl`, `wget`, `rclone`, `OneDrive`, `Dropbox` -> `FILE_NETWORK_TRANSFER`

**理由**:
- Microsoft-Windows-Kernel-File ETW 提供器不直接区分"压缩"和"网络传输"
- 进程名启发式是实现成本最低且覆盖面够用的方案
- 后续可通过配置文件扩展匹配规则

**局限性**:
- 无法识别通过浏览器上传文件的行为
- 自定义或改名的工具不会被识别
- 进程查询有微小的性能开销

---

## ADR-005: 配置文件两级阈值结构

**日期**: 2026-03-03
**状态**: 已实施
**背景**: 原始配置文件使用扁平结构定义单一阈值，无法区分保护协议和紧急协议。

**决策**: 阈值配置拆分为 `tier1` 和 `tier2` 两个子节点，保留旧格式的兼容性回退：

```yaml
detection:
  alert_timeout_seconds: 30
  thresholds:
    tier1:
      file_write_count: 10
      file_delete_count: 5
      ...
    tier2:
      file_write_count: 50
      file_delete_count: 20
      ...
```

**理由**:
- 清晰地表达两级语义
- `config.cpp` 先检测 `tier1` 子节点是否存在，不存在则回退到旧的扁平格式
- 新增 `file_delete_count` / `file_delete_window_seconds` 填补之前缺失的删除检测
- `alert_timeout_seconds` 控制 ALERT 阶段的等待时间，给管理员取消的窗口

---

## ADR-006: MSI 打包使用自定义 WiX 脚本

**日期**: 2026-03-01
**状态**: 已实施
**背景**: 项目已有手写的 `GuardianShield.wxs` 和 `InstallDlg.wxs`，但 CMake 的 CPack/WIX 生成器与这些自定义 `.wxs` 冲突。

**决策**: 创建独立的 `build_msi.bat`，直接调用 WiX Toolset 的 `candle.exe` 和 `light.exe` 编译手写 `.wxs` 文件。

**理由**:
- 完全控制安装界面和自定义操作
- 不依赖 CPack 的 WIX 生成逻辑
- 输出位置固定为 `build/bin/Release/GuardianShield.msi`

---

## ADR-007: 阈值字段留空/0 表示不限制

**日期**: 2026-03-03
**状态**: 已实施
**背景**: YAML 阈值字段留空时 `yaml-cpp` 的 `.as<int>()` 抛出异常，导致整个配置加载失败。

**决策**: 用 0 表示"不限制"：留空/null → 0 → 跳过检测；字段缺失 → 保持默认值。

**理由**:
- 管理员可以通过留空某一类阈值来选择性放行某类文件操作
- 向后兼容：已有正整数配置不受影响
- 0 作为 uint32_t 的天然下界，语义清晰

---

## ADR-008: 安装器自动定位配置文件 + 浏览按钮

**日期**: 2026-03-03
**状态**: 已实施
**背景**: MSI 安装器的配置文件选择对话框只有空白 Edit 控件，管理员需要手动输入完整路径。

**决策**: 新增 `LocateConfigFiles` Custom Action 自动搜索 MSI 同目录和 ProgramData 下的配置文件，并添加"浏览"按钮调用 `GetOpenFileNameW`。

**理由**:
- 降低安装出错概率
- 保留手动输入能力作为回退
- Custom Action DLL 已存在，新增导出函数成本低

---

## ADR-009: C# WPF 图形化配置管理工具

**日期**: 2026-03-03
**状态**: 已实施
**背景**: 管理员只能通过手动编辑 YAML 文件来配置系统，容易出错且不直观。

**决策**: 创建独立的 C# WPF 应用 `GuardianConfigManager`，使用 YamlDotNet 库进行 YAML 序列化/反序列化，MVVM 架构。

**理由**:
- WPF 提供丰富的 UI 控件（DataGrid、ComboBox 等），适合复杂表单编辑
- YamlDotNet 是 .NET 生态中最成熟的 YAML 库
- 独立于 C++ 主项目，无交叉编译依赖
- 内置 SHA-256 哈希生成，降低管理员使用门槛

---

## ADR-010: ETW 会话生命周期管理

**日期**: 2026-03-06
**状态**: 已实施
**背景**: 服务重启后，前一个进程可能遗留孤儿 ETW 会话（`GuardianFileTrace`）。新进程尝试 `ControlTraceW(STOP)` + `StartTraceW` 时，竞态条件或无效句柄状态导致 `ProcessTrace` 永久阻塞（CPU=0），全链路事件处理停滞。`m_traceHandle` 为普通变量，跨线程访问存在数据竞争。

**决策**: 实施四项防御措施：

| # | 措施 | 实现 |
|---|------|------|
| 1 | 防御性清理 | `InitializeEtw()` 开头调用 `ShutdownEtw()`，确保旧会话和旧线程被正确清理 |
| 2 | 原子句柄 | `m_traceHandle` 改为 `std::atomic<TRACEHANDLE>`，使用 `.load()` / `.store()` 操作 |
| 3 | 活性守护 | `HeartbeatThread` 中监控 `m_eventsProcessed`，连续 60 秒无新事件自动触发 `ShutdownEtw()` + `InitializeEtw()` 重启 |
| 4 | 自动恢复 | `EtwCollectionThread` 改为 `while(m_etwRunning)` 循环，`ProcessTrace` 返回后 `CloseTrace` + 2 秒延迟 + 重试 |

**理由**:
- 孤儿会话问题在服务重启/崩溃恢复场景下必然发生，防御性清理是最低成本的可靠方案
- `std::atomic` 消除了 `ShutdownEtw`（主线程/心跳线程）与 `EtwCollectionThread` 之间的数据竞争
- 活性守护覆盖了 `ProcessTrace` 静默阻塞（无返回值、无错误码）的场景
- 自动恢复循环使 ETW 采集线程具备自愈能力，无需外部干预

**替代方案被否决**:
- 仅依赖 `ControlTraceW(STOP)` 清理旧会话：不够可靠，STOP 调用本身可能失败
- 使用进程级互斥锁（Mutex）保护 ETW 会话：增加复杂度且无法处理进程崩溃后遗留的 Mutex

---

## ADR-011: IPC SendToNode 按目标节点加锁

**日期**: 2026-03-06
**状态**: 已实施
**背景**: `IpcManager::SendToNode` 使用单一 `m_sendMutex` 保护所有发送操作。当 `HeartbeatThread` 同时向 GuardianB 和 GuardianC 发送心跳，而 `EventProcessingThread` 向 GuardianB 转发事件时，全局锁造成不必要的串行化，尤其当某个管道连接超时时会阻塞其他目标节点的发送。

**决策**:
- `m_sendMutex` 从单一互斥锁改为 `m_sendMutex[3]` 数组，每个目标节点一把锁
- `m_sequence` 改为 `std::atomic<uint32_t>`，无需锁保护
- `tryConnect` 改为单次连接尝试 + 300ms 超时，替代原来的多次重试

**理由**:
- 消除跨目标节点的锁竞争，向 GuardianC 发送通知不会被向 GuardianB 转发事件阻塞
- `std::atomic` 保证序列号递增的原子性，比在锁内递增更高效
- 300ms 单次超时避免了长时间阻塞调用线程（ETW 回调中的阻塞是 BUG-10 的直接原因）

---

## ADR-012: MSI 版本归档基础设施

**日期**: 2026-03-09
**状态**: 已实施
**背景**: 每次 `build_msi.bat` 生成新 MSI 时，旧 MSI 被静默覆盖，无法回滚到上一版本。用户明确要求保留历史版本以便比较和回滚。

**决策**:
- `build_msi.bat` 在生成新 MSI 前，自动将旧 MSI 归档到 `releases/GuardianShield_buildN.msi`（N 自增）
- `releases/RELEASE_LOG.txt` 记录每个版本的构建时间、版本号和变更摘要
- WiX `Product Version` 在每次发布时手动递增（遵循 `Major.Minor.Patch.0` 格式）
- WiX `MajorUpgrade` 元素确保新版覆盖旧版安装

**理由**:
- 归档逻辑作为 `build_msi.bat` 的子程序 (`:archive_old_msi`)，对构建流程零侵入
- 动态命名避免覆盖：循环查找下一个可用的 buildN 编号
- `RELEASE_LOG.txt` 提供人类可读的版本历史，无需 git
- 使用 `setlocal`（不含 `EnableDelayedExpansion`）遵循批处理最佳实践

---

## ADR-013: 配置文件简易解析增强（LoadSimple 结构化列表解析）

**日期**: 2026-03-09
**状态**: 已实施
**背景**: `Config::LoadSimple()` 的 YAML 简易解析器无法正确解析嵌套列表结构（`protection.file_types.exclude/include`、`whitelist.processes`），导致文件类型过滤和进程白名单在无 yaml-cpp 环境下完全失效（BUG-4、BUG-5）。

**决策**:
- 引入节区栈状态变量（`inExcludeArray`、`inIncludeArray`、`inWhitelistArray`）追踪当前解析位置
- 列表项以 `- ` 前缀识别，根据当前节区追加到对应容器
- `WhitelistProcess` 支持嵌套键值对解析（`name:`、`package_prefix:`）
- 解析结束时刷新最后一个 `WhitelistProcess` 条目
- `alert_timeout_seconds` 在 `LoadSimple` 中增加解析逻辑
- `Config::Load()` 中增加字段级防御：`alertTimeoutSeconds <= 0` 时默认 30

**理由**:
- 保持 `LoadSimple` 不依赖 yaml-cpp 的设计意图，同时支持实际配置结构
- 显式状态变量比正则表达式更可预测，便于调试
- 字段级防御消除"配置文件拼写错误导致 0 值"的隐患

---

## ADR-014: 进程白名单大小写不敏感匹配

**日期**: 2026-03-09
**状态**: 已实施
**背景**: `Config::IsProcessWhitelisted()` 使用 `==` 比较进程名，而 Windows 文件系统大小写不敏感——同一进程的名称可能是 `notepad.exe` 或 `Notepad.EXE`，导致白名单匹配失败（BUG-5 的一部分）。

**决策**: 将进程名比较从 `==` 改为 `_wcsicmp()`（Windows CRT 提供的大小写不敏感宽字符比较）。

**理由**:
- Windows 路径天然大小写不敏感，使用 `==` 是设计缺陷而非实现缺陷
- `_wcsicmp` 是 MSVC CRT 标准函数，无需额外依赖
- UWP 应用的 `package_prefix` 比较保持 `find` 不变（包名大小写有固定约定）

---

## ADR-015: 通知中文本地化与身份隐藏策略

**日期**: 2026-03-06
**状态**: 已实施
**背景**: 用户可见字符串（托盘、气球、右键菜单、窗口标题、MessageBox）均为英文，且暴露 "GuardianShield"、"GuardianA"、"GuardianB" 等产品/组件名称，不利于本地化与低调部署。

**决策**:
1. **中文本地化**: 所有 27 处 GuardianC 用户可见字符串 + GuardianA/B 的 AssessThreat description 与 SendAlert message 改为中文
2. **产品名统一**: "GuardianShield" → "系统防护"
3. **组件名隐藏**: "GuardianA/GuardianB" → "主控服务/备份服务"
4. **路径隐藏**: 通知中的 file_path 仅显示文件名（`wcsrchr` 提取），不暴露完整路径

**理由**:
- 提升中文用户可读性
- 降低产品指纹识别度，便于低调部署
- 路径隐藏减少敏感信息泄露

**涉及文件**: guardian_c.cpp, guardian_a.cpp, guardian_b.cpp

---

## ADR-016: INSTALL_KEY Approach B — CA_SetDefaultKey 替代 Property 默认值

**日期**: 2026-03-06
**状态**: 已实施
**背景**: MSI 安装流程简化后跳过 InstallKeyDlg，需在安装时自动注入 INSTALL_KEY。可选方案：(A) 在 WiX Property 中设置默认值；(B) 通过 Custom Action 在安装执行序列中注入。

**决策**: 采用 Approach B — 新增 CA_SetDefaultKey，在 InstallExecuteSequence 中（Before="RemoveExistingProducts", NOT Installed）设置 `INSTALL_KEY="GuardianShield2026!"`。Property 本身无默认值。

**理由**:
- **零安全降级**: Property 无默认值，密钥不会出现在 MSI 数据库的静态定义中
- 密钥仅在安装/升级执行时注入，安装完成后不持久化
- CA_ValidateUninstallKey 保留，卸载仍需验证
- 移除 CA_SetCopyConfigData 和 CA_CopyConfigFiles，简化执行序列

**替代方案被否决**:
- Approach A (Property 默认值): 密钥会写入 MSI 数据库，可被提取，存在安全风险

**涉及文件**: GuardianShield.wxs
