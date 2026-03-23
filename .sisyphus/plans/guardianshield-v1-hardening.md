# GuardianShield V1 安全审计 + ETW 端到端闭环 + 测试加固

## TL;DR

> **Quick Summary**: 对 GuardianShield V1（ETW 监控版）进行安全审计级代码审查，修复 6 个 CRITICAL/HIGH 安全漏洞，确保 ETW 事件检测→威胁评估→响应动作端到端闭环可工作，补充约 120+ 缺失测试用例并在目标 Windows 机器上验证。
> 
> **Deliverables**:
> - 安全漏洞修复（HMAC 硬编码密钥、脑裂防护、零校验绕过、安全 stub 实现）
> - ETW 管道端到端验证与修复
> - ~120 新增测试用例覆盖关键缺失领域
> - 目标机构建验证 + 集成测试通过
> 
> **Estimated Effort**: Large
> **Parallel Execution**: YES - 4 waves
> **Critical Path**: Wave 1 (测试基座) → Wave 2 (安全修复) → Wave 3 (管道修复) → Wave FINAL (远程验证)

---

## Context

### Original Request
审查代码，实现文件检测与防护功能，测试功能完整性与稳定性。

### Interview Summary
**Key Discussions**:
- 文件检测范围: ETW 检测端到端闭环（非内核驱动）
- 审查深度: 安全审计级（最深）
- 测试策略: 编写测试代码 + 远程 Windows 机器验证
- 交付物: 工作计划（规划后交由执行者落地）

**Research Findings** (3 parallel explore agents):
- **GuardianA Core**: ETW 实现 95%，批量检测 100%，紧急协议 90%，5 个 FIX 注释待处理
- **GuardianB/C + Common**: 3 CRITICAL（HMAC 硬编码、脑裂风险、事件丢弃）、5 HIGH（安全 stub、TLS 缺失）
- **Test Suite**: ~265 用例，ZERO 覆盖紧急协议状态机/HMAC 验证/Failover/ETW 处理

### Metis Review
**Identified Gaps** (addressed):
- HMAC 零校验绕过（BCrypt 不可用时所有消息通过验证）→ 显式拒绝全零校验
- Tier 2 不可逆操作无假阳性停止机制 → 添加紧急协议取消测试
- Config 自删除与 failover 交互未验证 → 添加 config cache 验证
- ETW 会话名冲突（崩溃后 ERROR_ALREADY_EXISTS）→ 添加孤儿会话清理
- 共享内存 torn read 风险 → 使用 InterlockedExchange64
- HMAC 密钥迁移需协调重启 → 计划包含迁移策略

---

## Work Objectives

### Core Objective
修复 GuardianShield V1 的安全漏洞，确保 ETW 文件检测→威胁评估→紧急响应的端到端管道可靠工作，并通过全面测试验证功能完整性与稳定性。

### Concrete Deliverables
- 修复 `ipc.cpp` HMAC 硬编码密钥 + 零校验绕过
- 实现 `security.cpp` 中 `SHA256File()` 和 `VerifyHash()` stub
- 添加 GuardianB 脑裂防护（Global 命名互斥体）
- 非主控 Guardian 事件持久化（文件记录替代丢弃）
- TCP fallback 限制为 loopback + ACL
- ETW 孤儿会话清理
- ~120 新测试用例
- 目标 Windows 机器全量构建 + 测试通过

### Definition of Done
- [ ] `ctest --test-dir build --config Release --output-on-failure` 全部通过
- [ ] `/W4` 编译零警告
- [ ] 所有 CRITICAL/HIGH 安全问题已修复并有对应测试
- [ ] ETW 事件管道端到端集成测试通过

### Must Have
- HMAC 密钥替换为 DPAPI/机器级密钥派生
- 零校验 HMAC 显式拒绝
- 脑裂防护机制
- 紧急协议状态机测试（含取消/无效转换）
- SHA256File + VerifyHash 实现
- ETW 孤儿会话恢复
- 目标机构建验证

### Must NOT Have (Guardrails)
- ❌ 不实现 TLS — 改为 TCP loopback + ACL 限制
- ❌ 不实现 anti-debug stub（CheckPEBDebugPort, HasRemoteThread 等）— V2
- ❌ 不重构 config.cpp（83,635 行）— 仅允许精确行修改
- ❌ 不添加跨进程事件转发 — 仅本地文件记录
- ❌ 不做测试跨平台兼容 — Windows 专属
- ❌ 不新增 ResponseAction 枚举值
- ❌ 紧急协议修复和安全修复不在同一 commit 中混合

---

## Verification Strategy

> **ZERO HUMAN INTERVENTION** — ALL verification is agent-executed. No exceptions.
> **唯一例外**: Task 16 目标机构建验证需主人在 Windows 机器上执行 agent 生成的验证脚本。

### Test Decision
- **Infrastructure exists**: YES (Google Test v1.14.0, FetchContent 自动获取)
- **Automated tests**: YES (TDD — 先写测试再修复)
- **Framework**: Google Test (`TEST_F` fixture 模式)
- **TDD 模式**: 每个修复对应的测试先写出（期望 FAIL），修复后变 PASS

### QA Policy
每个任务必须包含 agent-executed QA scenarios。
Evidence 保存至 `.sisyphus/evidence/task-{N}-{scenario-slug}.{ext}`。

- **编译验证**: Bash (`cmake --build`)
- **测试验证**: Bash (`ctest --test-dir build --config Release -R "TestName"`)
- **集成验证**: Bash (PowerShell 脚本模拟文件操作)

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (Start Immediately — 测试基座，写所有新测试文件):
├── Task 1: test_security.cpp — SHA256File/VerifyHash 测试向量 [quick]
├── Task 2: test_ipc.cpp 扩展 — HMAC 边界测试 [quick]
├── Task 3: test_emergency.cpp 扩展 — 状态机转换测试 [deep]
├── Task 4: test_state_sync.cpp 扩展 — Failover 测试 [deep]
├── Task 5: test_etw_pipeline.cpp (NEW) — ETW 管道模拟测试 [deep]
└── Task 6: test_event_logging.cpp (NEW) — 非主控事件记录测试 [quick]

Wave 2 (After Wave 1 — 安全修复，逐项修复 + 测试变绿):
├── Task 7: 实现 SHA256File() (depends: 1) [quick]
├── Task 8: 实现 VerifyHash() (depends: 1, 7) [quick]
├── Task 9: HMAC 零校验拒绝 + 密钥派生 (depends: 2) [deep]
├── Task 10: 脑裂防护 — Global 命名互斥体 (depends: 4) [deep]
├── Task 11: 非主控事件文件记录 (depends: 6) [unspecified-high]
└── Task 12: TCP loopback + ACL 限制 (depends: 2) [quick]

Wave 3 (After Wave 2 — ETW 管道修复 + 集成):
├── Task 13: ETW 孤儿会话恢复 (depends: 5) [unspecified-high]
├── Task 14: ETW 降级日志修正 (depends: 5) [quick]
├── Task 15: 共享内存原子读写修复 (depends: 4) [quick]
└── Task 16: 目标机远程构建 + 全量测试 (depends: ALL) [deep]

Wave FINAL (After ALL — 4 parallel reviews, then user okay):
├── Task F1: Plan compliance audit (oracle)
├── Task F2: Code quality review (unspecified-high)
├── Task F3: Real manual QA (unspecified-high)
└── Task F4: Scope fidelity check (deep)
-> Present results -> Get explicit user okay
```

### Dependency Matrix

| Task | Depends On | Blocks | Wave |
|------|-----------|--------|------|
| 1 | — | 7, 8 | 1 |
| 2 | — | 9, 12 | 1 |
| 3 | — | — | 1 |
| 4 | — | 10, 15 | 1 |
| 5 | — | 13, 14 | 1 |
| 6 | — | 11 | 1 |
| 7 | 1 | 8 | 2 |
| 8 | 1, 7 | — | 2 |
| 9 | 2 | — | 2 |
| 10 | 4 | — | 2 |
| 11 | 6 | — | 2 |
| 12 | 2 | — | 2 |
| 13 | 5 | 16 | 3 |
| 14 | 5 | 16 | 3 |
| 15 | 4 | 16 | 3 |
| 16 | ALL | F1-F4 | 3 |

### Agent Dispatch Summary

- **Wave 1**: **6 tasks** — T1 → `quick`, T2 → `quick`, T3 → `deep`, T4 → `deep`, T5 → `deep`, T6 → `quick`
- **Wave 2**: **6 tasks** — T7 → `quick`, T8 → `quick`, T9 → `deep`, T10 → `deep`, T11 → `unspecified-high`, T12 → `quick`
- **Wave 3**: **4 tasks** — T13 → `unspecified-high`, T14 → `quick`, T15 → `quick`, T16 → `deep`
- **Wave FINAL**: **4 tasks** — F1 → `oracle`, F2 → `unspecified-high`, F3 → `unspecified-high`, F4 → `deep`

---

## TODOs

- [x] 1. test_security.cpp — SHA256File / VerifyHash 测试向量

  **What to do**:
  - 创建 `test/test_security.cpp`，包含 `SecurityHashTest` fixture
  - 测试 `SHA256File()`：已知内容文件 → 对比 NIST SHA-256 测试向量
  - 测试 `SHA256File()`：空文件 → 对比空内容标准哈希 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
  - 测试 `SHA256File()`：不存在的文件 → 返回 false（不崩溃）
  - 测试 `VerifyHash()`：正确哈希 → true
  - 测试 `VerifyHash()`：错误哈希 → false
  - 测试 `VerifyHash()`：不可访问文件 → false
  - 在 `test/CMakeLists.txt` 中添加 `test_security.cpp`
  - **测试先写，当前 stub 实现会导致测试 FAIL — 这是预期的 TDD 行为**

  **Must NOT do**:
  - 不修改 security.cpp 源码（仅写测试）
  - 不实现 anti-debug 相关测试

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: 单文件测试编写，模式清晰
  - **Skills**: []
    - 无需额外技能

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 2-6)
  - **Blocks**: Tasks 7, 8
  - **Blocked By**: None

  **References**:

  **Pattern References**:
  - `test/test_file_encryptor.cpp` - SetUp/TearDown 临时目录模式（遵循此 fixture 结构）
  - `test/CMakeLists.txt` - 测试文件注册方式

  **API/Type References**:
  - `src/service/common/include/security.h` - SHA256File 和 VerifyHash 函数签名
  - `src/service/common/src/security.cpp:108-110` - SHA256File stub（当前返回 false）
  - `src/service/common/src/security.cpp:160-162` - VerifyHash stub（当前返回 false）

  **External References**:
  - NIST SHA-256 测试向量: `"abc"` → `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`

  **WHY Each Reference Matters**:
  - test_file_encryptor.cpp 展示了如何用 SetUp 创建临时目录、TearDown 清理，新测试必须遵循此模式
  - security.h 包含精确的函数签名 `bool SHA256File(const std::wstring&, uint8_t[32])` — 测试必须匹配

  **Acceptance Criteria**:

  **TDD:**
  - [ ] 测试文件 `test/test_security.cpp` 已创建
  - [ ] CMakeLists.txt 已更新包含 test_security.cpp
  - [ ] `cmake --build build --config Release --target GuardianTests` 编译成功
  - [ ] `ctest -R SecurityHash` 运行（当前预期 FAIL，因为 stub 返回 false）

  **QA Scenarios:**

  ```
  Scenario: SHA256File 测试向量验证（预期 FAIL — TDD RED phase）
    Tool: Bash
    Preconditions: 项目已构建，test_security.cpp 已添加到 CMakeLists
    Steps:
      1. cmake --build build --config Release --target GuardianTests
      2. ctest --test-dir build --config Release -R "SecurityHash" --output-on-failure
    Expected Result: 编译成功，测试运行但 FAIL（因 stub 返回 false）
    Failure Indicators: 编译失败或链接错误
    Evidence: .sisyphus/evidence/task-1-sha256-test-red.txt

  Scenario: 测试文件结构验证
    Tool: Bash
    Preconditions: test_security.cpp 已创建
    Steps:
      1. grep -c "TEST_F" test/test_security.cpp
    Expected Result: 至少 7 个 TEST_F 声明
    Evidence: .sisyphus/evidence/task-1-test-count.txt
  ```

  **Commit**: YES
  - Message: `test(security): add SHA256File and VerifyHash test vectors`
  - Files: `test/test_security.cpp`, `test/CMakeLists.txt`
  - Pre-commit: `cmake --build build --config Release`

- [x] 2. test_ipc.cpp 扩展 — HMAC 边界测试（零校验绕过、篡改、错误密钥）

  **What to do**:
  - 在 `test/test_ipc.cpp` 中添加 `HMACSecurityTest` fixture
  - 测试 `CalculateChecksum()` + `VerifyChecksum()` 正常流程
  - 测试零校验绕过：构造全零 checksum → `VerifyChecksum` 必须拒绝
  - 测试消息篡改：修改 payload 中一个字节 → 校验失败
  - 测试错误密钥场景（如果可注入）
  - 测试 `CalculateChecksum` BCrypt 失败场景 → 校验不应通过
  - **注意**：当前零校验会通过验证 — 测试应捕获此 BUG

  **Must NOT do**:
  - 不修改 ipc.cpp 源码
  - 不实现 TLS

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: 扩展现有测试文件
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1, 3-6)
  - **Blocks**: Tasks 9, 12
  - **Blocked By**: None

  **References**:

  **Pattern References**:
  - `test/test_ipc.cpp` - 现有 IPC 测试结构（序列化、Named Pipe 测试模式）
  - `test/test_file_encryptor.cpp` - fixture 模式参考

  **API/Type References**:
  - `src/service/common/src/ipc.cpp:83` - 硬编码 HMAC 密钥 `"GuardianShield_IPC_v2"`
  - `src/service/common/src/ipc.cpp:86-106` - CalculateChecksum 实现
  - `src/service/common/src/ipc.cpp:108-117` - VerifyChecksum 实现（含 constant-time 比较）
  - `src/service/common/src/ipc.cpp:103-105` - BCrypt 失败时 memset(0) 行为
  - `src/service/common/include/common_types.h` - CHECKSUM_SIZE 定义（12 字节）

  **WHY Each Reference Matters**:
  - ipc.cpp:103-105 是零校验绕过的根因 — 测试必须直接验证此路径
  - CHECKSUM_SIZE=12 意味着 HMAC-SHA256 被截断，测试应验证截断后的行为

  **Acceptance Criteria**:

  **TDD:**
  - [ ] test_ipc.cpp 已添加至少 5 个新 HMAC 测试
  - [ ] 编译成功
  - [ ] 零校验绕过测试当前预期 FAIL（揭示 BUG）

  **QA Scenarios:**

  ```
  Scenario: HMAC 零校验绕过检测（预期 FAIL — 揭示安全 BUG）
    Tool: Bash
    Preconditions: 项目已构建
    Steps:
      1. cmake --build build --config Release --target GuardianTests
      2. ctest --test-dir build --config Release -R "HMACSecurityTest" --output-on-failure
    Expected Result: 编译成功，零校验拒绝测试 FAIL（确认 BUG 存在）
    Failure Indicators: 编译错误
    Evidence: .sisyphus/evidence/task-2-hmac-test-red.txt

  Scenario: HMAC 消息完整性验证
    Tool: Bash
    Preconditions: 项目已构建
    Steps:
      1. grep -c "TEST_F.*HMACSecurityTest" test/test_ipc.cpp
    Expected Result: 至少 5 个 HMAC 安全测试
    Evidence: .sisyphus/evidence/task-2-hmac-count.txt
  ```

  **Commit**: YES
  - Message: `test(ipc): add HMAC zero-checksum bypass and tamper tests`
  - Files: `test/test_ipc.cpp`
  - Pre-commit: `cmake --build build --config Release`

- [x] 3. test_emergency.cpp 扩展 — 紧急协议状态机转换测试

  **What to do**:
  - 在 `test/test_emergency.cpp` 中添加 `EmergencyStateMachineTest` fixture
  - **实现路径**: 将紧急协议状态机逻辑从 `guardian_a.cpp` 提取为独立类 `EmergencyStateMachine`，放入 `src/service/common/include/emergency_state_machine.h` 和 `src/service/common/src/emergency_state_machine.cpp`
  - 该类封装状态转换验证逻辑（哪些转换合法、取消逻辑、并发保护）
  - `guardian_a.cpp` 修改为使用提取后的 `EmergencyStateMachine` 类
  - 测试直接链接 GuardianCommon（已包含 common 模块），无需编译 guardian_a.cpp
  - 测试用例：
    - 完整 Tier 1 序列：NORMAL → ALERT → ENCRYPTING → LOCKED
    - 完整 Tier 2 序列：NORMAL → ALERT → ENCRYPTING → WIPING → DELETING → LOCKED
    - 无效跳跃转换：NORMAL → WIPING（应被拒绝）
    - 反向转换：LOCKED → NORMAL（仅通过管理员解锁）
    - ALERT 阶段取消 → 恢复 NORMAL
    - ENCRYPTING 阶段取消 → 应被拒绝（不可逆）
    - 并发触发 → 仅一个成功（atomic guard）

  **Must NOT do**:
  - 不修改紧急协议的业务行为（仅提取为可测试单元）

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 需要理解状态机逻辑并设计覆盖所有转换路径的测试
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1, 2, 4-6)
  - **Blocks**: None (Wave 2 修复不直接依赖此任务)
  - **Blocked By**: None

  **References**:

  **Pattern References**:
  - `test/test_emergency.cpp` - 现有紧急协议测试（仅枚举/原子操作）
  - `test/test_threat_evaluator.cpp` - EventClassificationTestFixture 模式

  **API/Type References**:
  - `src/service/common/include/common_types.h:141-148` - EmergencyState 枚举定义
  - `src/service/GuardianA/src/guardian_a.cpp:1932-2007` - TriggerEmergencyProtocol 实现
  - `src/service/GuardianA/include/guardian_a.h` - GuardianA 类定义和紧急协议方法声明

  **WHY Each Reference Matters**:
  - common_types.h 定义了所有合法状态，测试需要验证每个转换组合的合法性
  - guardian_a.cpp:1932+ 是实际状态机逻辑，测试必须覆盖其所有分支

  **Acceptance Criteria**:

  **TDD:**
  - [ ] test_emergency.cpp 新增至少 8 个状态机测试
  - [ ] 编译成功
  - [ ] 部分测试 PASS（有效转换），部分可能 FAIL（如果状态机缺少验证）

  **QA Scenarios:**

  ```
  Scenario: 紧急协议状态机转换覆盖
    Tool: Bash
    Preconditions: 项目已构建
    Steps:
      1. cmake --build build --config Release --target GuardianTests
      2. ctest --test-dir build --config Release -R "EmergencyStateMachine" --output-on-failure
    Expected Result: 编译成功，状态机测试运行
    Failure Indicators: 编译错误或链接错误
    Evidence: .sisyphus/evidence/task-3-emergency-statemachine.txt

  Scenario: 取消逻辑验证
    Tool: Bash
    Steps:
      1. grep -c "Cancel" test/test_emergency.cpp
    Expected Result: 至少 2 个取消相关测试（ALERT 阶段 + ENCRYPTING 阶段）
    Evidence: .sisyphus/evidence/task-3-cancel-tests.txt
  ```

  **Commit**: YES
  - Message: `refactor(emergency): extract state machine + add transition tests`
  - Files: `test/test_emergency.cpp`, `src/service/common/include/emergency_state_machine.h`, `src/service/common/src/emergency_state_machine.cpp`, `src/service/common/CMakeLists.txt`, `src/service/GuardianA/src/guardian_a.cpp`
  - Pre-commit: `cmake --build build --config Release`

- [x] 4. test_state_sync.cpp 扩展 — Failover / 脑裂测试

  **What to do**:
  - 在 `test/test_state_sync.cpp` 中添加 `FailoverTest` fixture
  - 测试 A 崩溃 → B 在 3 次心跳缺失（1.5s）内提升为 Primary
  - 测试 A 恢复 → B 降级回 Backup
  - 测试同时启动 → 仅一个成为 Primary（通过 Global 命名互斥体验证）
  - 测试共享内存损坏 → 确定性决议（不是双 Primary）
  - 测试心跳 nonce 验证（stale heartbeat 检测）
  - **注意**: `test/CMakeLists.txt` 不含 `guardian_b.cpp` — Failover 测试需通过模拟心跳状态和互斥体行为测试，而非直接调用 GuardianB 服务类。测试应：
    (a) 使用 SharedMemory API 模拟心跳写入/超时
    (b) 使用 CreateMutexW 验证互斥体获取/释放行为
    (c) 不需要完整的 GuardianB 服务实例

  **Must NOT do**:
  - 不修改 guardian_b.cpp 源码
  - 不引入外部依赖

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 需要模拟分布式系统场景，测试设计复杂
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1-3, 5-6)
  - **Blocks**: Tasks 10, 15
  - **Blocked By**: None

  **References**:

  **Pattern References**:
  - `test/test_state_sync.cpp` - 现有状态同步测试
  - `test/test_ipc.cpp` - IPC 相关测试模式

  **API/Type References**:
  - `src/service/GuardianB/src/guardian_b.cpp:442-458` - Failover 逻辑
  - `src/service/GuardianB/src/guardian_b.cpp:492-506` - DemoteToBackup 逻辑
  - `src/service/GuardianB/src/guardian_b.cpp:175` - MAX_MISSED_HEARTBEATS = 3
  - `src/service/GuardianC/src/guardian_c.cpp:478-496` - Nonce 心跳验证

  **WHY Each Reference Matters**:
  - guardian_b.cpp:442-458 是脑裂风险的根因 — 测试必须直接覆盖此代码路径
  - MAX_MISSED_HEARTBEATS=3 定义了 failover 窗口 — 测试需要验证精确计时

  **Acceptance Criteria**:

  **TDD:**
  - [ ] test_state_sync.cpp 新增至少 5 个 failover 测试
  - [ ] 编译成功

  **QA Scenarios:**

  ```
  Scenario: Failover 测试编译验证
    Tool: Bash
    Steps:
      1. cmake --build build --config Release --target GuardianTests
      2. ctest --test-dir build --config Release -R "FailoverTest" --output-on-failure
    Expected Result: 编译成功，测试运行
    Evidence: .sisyphus/evidence/task-4-failover-tests.txt
  ```

  **Commit**: YES
  - Message: `test(failover): add split-brain and heartbeat timeout tests`
  - Files: `test/test_state_sync.cpp`
  - Pre-commit: `cmake --build build --config Release`

- [x] 5. test_etw_pipeline.cpp (NEW) — ETW 管道模拟测试

  **What to do**:
  - 创建 `test/test_etw_pipeline.cpp`，包含 `ETWPipelineTest` fixture
  - 模拟 `DriverEvent` 注入 → 验证 `ThreatEvaluator` 分类正确
  - 测试 FILE_CREATE/FILE_WRITE/FILE_DELETE/FILE_RENAME 事件处理
  - 测试 FILE_COMPRESS（通过进程名匹配 7z.exe/WinRAR 等）
  - 测试 FILE_NETWORK_TRANSFER（通过进程名匹配 curl.exe/wget.exe 等）
  - 测试 FILE_MOVE 关联逻辑（CREATE+DELETE 5 秒窗口）
  - 测试超过 Tier 1/Tier 2 阈值 → 正确触发协议
  - 测试响应动作映射（LOG → ALERT_USER → TERMINATE → ENCRYPT）
  - 在 `test/CMakeLists.txt` 中注册

  **Must NOT do**:
  - 不直接调用 ETW API（无需 Admin 权限）
  - 不修改 guardian_a.cpp 或 threat_evaluator.cpp

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 需要理解事件管道全流程并构造模拟事件
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1-4, 6)
  - **Blocks**: Tasks 13, 14
  - **Blocked By**: None

  **References**:

  **Pattern References**:
  - `test/test_threat_evaluator.cpp` - EventClassificationTestFixture 模式（最佳参考）
  - `test/test_event_response_config.cpp` - 事件响应配置测试

  **API/Type References**:
  - `src/service/common/include/common_types.h` - DriverEvent、EventType、MonitoredEvent 结构定义
  - `src/service/GuardianA/src/threat_evaluator.cpp:368-388` - IsEventTypeImplemented
  - `src/service/GuardianA/src/threat_evaluator.cpp:180-310` - CheckBatchThresholds
  - `src/service/GuardianA/src/threat_evaluator.cpp:390-429` - BuildEventResponse

  **WHY Each Reference Matters**:
  - test_threat_evaluator.cpp 已有事件分类测试的 fixture 模式 — 新测试应扩展此模式
  - IsEventTypeImplemented 定义了哪些事件类型真正工作 — 测试必须覆盖每个 implemented 类型

  **Acceptance Criteria**:

  **TDD:**
  - [ ] test_etw_pipeline.cpp 已创建并注册到 CMakeLists
  - [ ] 至少 10 个事件管道测试
  - [ ] 编译成功

  **QA Scenarios:**

  ```
  Scenario: ETW 管道测试编译运行
    Tool: Bash
    Steps:
      1. cmake --build build --config Release --target GuardianTests
      2. ctest --test-dir build --config Release -R "ETWPipeline" --output-on-failure
    Expected Result: 编译成功，事件管道测试运行
    Evidence: .sisyphus/evidence/task-5-etw-pipeline.txt
  ```

  **Commit**: YES
  - Message: `test(etw): add ETW pipeline mock event injection tests`
  - Files: `test/test_etw_pipeline.cpp`, `test/CMakeLists.txt`
  - Pre-commit: `cmake --build build --config Release`

- [x] 6. test_event_logging.cpp (NEW) — 非主控事件记录测试

  **What to do**:
  - 创建 `test/test_event_logging.cpp`，包含 `EventLoggingTest` fixture
  - 测试非主控 Guardian 接收事件时写入本地日志文件（而非丢弃）
  - 测试日志文件格式（JSON 行格式）
  - 测试日志文件轮转/大小限制
  - 测试日志可被后续主控恢复时读取
  - 在 `test/CMakeLists.txt` 中注册
  - **注意**: `guardian_b.cpp` 不在测试编译目标中 — 事件日志测试应直接测试 Logger API 写入 JSON Lines 格式文件，验证格式和轮转，而非测试 GuardianB 服务逻辑本身

  **Must NOT do**:
  - 不实现跨进程事件转发
  - 不修改 guardian_b.cpp 源码

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: 相对简单的日志测试
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1-5)
  - **Blocks**: Task 11
  - **Blocked By**: None

  **References**:

  **Pattern References**:
  - `test/test_system_logger.cpp` - 日志测试模式
  - `test/test_monitor_logger.cpp` - 事件日志测试

  **API/Type References**:
  - `src/service/GuardianB/src/guardian_b.cpp:525-527` - 当前事件丢弃行为（参考，非编译目标）
  - `src/service/common/include/logger.h` - Logger API（测试直接使用此 API）

  **WHY Each Reference Matters**:
  - guardian_b.cpp:525-527 是事件丢弃的根因 — Task 11 将修复此处，本任务写测试

  **Acceptance Criteria**:

  **TDD:**
  - [ ] test_event_logging.cpp 已创建
  - [ ] 至少 4 个事件日志测试
  - [ ] 编译成功

  **QA Scenarios:**

  ```
  Scenario: 事件日志测试编译
    Tool: Bash
    Steps:
      1. cmake --build build --config Release --target GuardianTests
      2. ctest --test-dir build --config Release -R "EventLogging" --output-on-failure
    Expected Result: 编译成功
    Evidence: .sisyphus/evidence/task-6-event-logging.txt
  ```

  **Commit**: YES
  - Message: `test(events): add non-primary event logging tests`
  - Files: `test/test_event_logging.cpp`, `test/CMakeLists.txt`
  - Pre-commit: `cmake --build build --config Release`

- [x] 7. 实现 SHA256File() — BCrypt SHA-256 文件哈希

  **What to do**:
  - 在 `src/service/common/src/security.cpp:108-110` 实现 `SHA256File()`
  - 使用 Windows BCrypt API（`BCryptOpenAlgorithmProvider` + `BCRYPT_SHA256_ALGORITHM`）
  - 流式读取文件（分块 hash，支持大文件）
  - 返回 32 字节 SHA-256 哈希到输出参数
  - 文件不存在/不可读时返回 false
  - 实现后运行 Task 1 的测试 → 期望 SHA256File 相关测试 PASS

  **Must NOT do**:
  - 不修改函数签名 `bool SHA256File(const std::wstring&, uint8_t[32])`
  - 不引入第三方库（仅用 Windows CNG BCrypt）
  - 不修改其他 stub 函数

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: 单函数实现，BCrypt 模式已在 file_encryptor.cpp 中有参考
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with Tasks 9-12)
  - **Parallel Group**: Wave 2
  - **Blocks**: Task 8
  - **Blocked By**: Task 1

  **References**:

  **Pattern References**:
  - `src/service/common/src/file_encryptor.cpp:84-141` - BCrypt API 使用模式（BCryptOpenAlgorithmProvider、BCryptCreateHash 等）

  **API/Type References**:
  - `src/service/common/src/security.cpp:108-110` - 当前 stub 位置
  - `src/service/common/include/security.h` - Hash 命名空间声明

  **WHY Each Reference Matters**:
  - file_encryptor.cpp 已有完整的 BCrypt 初始化和清理模式 — 直接复用

  **Acceptance Criteria**:

  - [ ] SHA256File 使用 BCrypt 实现完成
  - [ ] `ctest -R "SecurityHash.*SHA256"` 全部 PASS
  - [ ] 空文件、大文件、不存在文件场景均通过

  **QA Scenarios:**

  ```
  Scenario: SHA256File 测试从 RED 转 GREEN
    Tool: Bash
    Steps:
      1. cmake --build build --config Release --target GuardianTests
      2. ctest --test-dir build --config Release -R "SecurityHash" --output-on-failure
    Expected Result: 所有 SHA256File 相关测试 PASS
    Failure Indicators: 测试仍然 FAIL
    Evidence: .sisyphus/evidence/task-7-sha256-green.txt
  ```

  **Commit**: YES
  - Message: `fix(security): implement SHA256File with BCrypt SHA-256`
  - Files: `src/service/common/src/security.cpp`
  - Pre-commit: `ctest -R SecurityHash`

- [x] 8. 实现 VerifyHash() — 进程完整性校验

  **What to do**:
  - 在 `src/service/common/src/security.cpp:160-162` 实现 `VerifyHash()`
  - 调用 `SHA256File()` 获取文件哈希
  - 使用 constant-time 比较与期望哈希对比（防时序攻击）
  - 文件不可访问时返回 false
  - 实现后运行 Task 1 的测试 → 期望 VerifyHash 相关测试 PASS

  **Must NOT do**:
  - 不修改函数签名
  - 不修改其他函数

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: 依赖 Task 7 的 SHA256File，仅需 constant-time compare
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with Tasks 9-12)
  - **Parallel Group**: Wave 2
  - **Blocks**: None
  - **Blocked By**: Tasks 1, 7

  **References**:

  **Pattern References**:
  - `src/service/common/src/ipc.cpp:112-117` - constant-time 比较模式（已有实现）

  **API/Type References**:
  - `src/service/common/src/security.cpp:160-162` - 当前 stub
  - `src/service/common/include/security.h` - ProcessIntegrity 命名空间

  **WHY Each Reference Matters**:
  - ipc.cpp 的 constant-time compare 模式直接复用，防止时序攻击

  **Acceptance Criteria**:

  - [ ] VerifyHash 实现完成
  - [ ] `ctest -R "SecurityHash.*Verify"` 全部 PASS

  **QA Scenarios:**

  ```
  Scenario: VerifyHash 测试 GREEN
    Tool: Bash
    Steps:
      1. cmake --build build --config Release
      2. ctest --test-dir build --config Release -R "SecurityHash" --output-on-failure
    Expected Result: 全部 SecurityHash 测试 PASS
    Evidence: .sisyphus/evidence/task-8-verifyhash-green.txt
  ```

  **Commit**: YES
  - Message: `fix(security): implement VerifyHash for process integrity`
  - Files: `src/service/common/src/security.cpp`
  - Pre-commit: `ctest -R SecurityHash`

- [x] 9. HMAC 零校验拒绝 + 密钥派生

  **What to do**:
  - 修改 `src/service/common/src/ipc.cpp:103-105`：BCrypt 失败时不再 memset(0)，而是返回 false
  - 修改 `src/service/common/src/ipc.cpp:108-117` VerifyChecksum：显式拒绝全零校验
  - 替换 `ipc.cpp:83` 硬编码密钥 `"GuardianShield_IPC_v2"` → 使用 DPAPI（`CryptProtectData`）或基于机器 SID 的密钥派生
  - **密钥迁移策略**：新版本使用派生密钥 + 拒绝全零，所有三个服务必须协调重启
  - 实现后运行 Task 2 的测试 → HMAC 测试全部 PASS

  **Must NOT do**:
  - 不修改 HMAC-SHA256 算法本身
  - 不修改 CHECKSUM_SIZE（保持 12 字节）
  - 不实现 TLS

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 密钥派生涉及 DPAPI/机器级安全，需谨慎实现
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with Tasks 7, 8, 10-12)
  - **Parallel Group**: Wave 2
  - **Blocks**: None
  - **Blocked By**: Task 2

  **References**:

  **Pattern References**:
  - `src/service/common/src/file_encryptor.cpp:74-79` - PBKDF2 密钥派生模式

  **API/Type References**:
  - `src/service/common/src/ipc.cpp:83` - 硬编码密钥（替换目标）
  - `src/service/common/src/ipc.cpp:86-117` - CalculateChecksum + VerifyChecksum
  - `src/service/common/src/ipc.cpp:103-105` - BCrypt 失败时 memset(0) 行为（零校验绕过根因）

  **External References**:
  - DPAPI `CryptProtectData/CryptUnprotectData` — MSDN LocalMachine scope

  **WHY Each Reference Matters**:
  - ipc.cpp:103-105 是零校验绕过的根因 — 此行必须改为返回 false 而非写零
  - file_encryptor.cpp 的 PBKDF2 展示了正确的密钥派生模式

  **Acceptance Criteria**:

  - [ ] 硬编码密钥已移除
  - [ ] BCrypt 失败不再产生全零校验
  - [ ] VerifyChecksum 显式拒绝全零校验
  - [ ] `ctest -R "HMACSecurityTest"` 全部 PASS
  - [ ] 所有现有 IPC 测试仍然 PASS

  **QA Scenarios:**

  ```
  Scenario: HMAC 安全测试 GREEN
    Tool: Bash
    Steps:
      1. cmake --build build --config Release
      2. ctest --test-dir build --config Release -R "IPC" --output-on-failure
    Expected Result: 所有 IPC 测试（含新 HMAC 安全测试）PASS
    Failure Indicators: 任何 IPC 测试 FAIL
    Evidence: .sisyphus/evidence/task-9-hmac-green.txt

  Scenario: 硬编码密钥移除验证
    Tool: Bash
    Steps:
      1. grep -n "GuardianShield_IPC_v2" src/service/common/src/ipc.cpp
    Expected Result: 无匹配行（硬编码密钥已移除）
    Evidence: .sisyphus/evidence/task-9-no-hardcoded-key.txt
  ```

  **Commit**: YES
  - Message: `fix(ipc): reject zero-checksum HMAC + derive key from DPAPI`
  - Files: `src/service/common/src/ipc.cpp`
  - Pre-commit: `ctest -R IPC`

- [x] 10. 脑裂防护 — Global 命名互斥体 Leader Election

  **What to do**:
  - 在 `src/service/GuardianB/src/guardian_b.cpp` 的 PromoteToPrimary 方法中添加 Global 命名互斥体获取
  - 在 `src/service/GuardianA/src/guardian_a.cpp` 的 OnStart/Initialize 阶段获取同一互斥体作为 Primary 标识
  - 互斥体名称：`Global\\GuardianShield-Leader`
  - **GuardianA（首选 Primary）**：启动时 CreateMutexW 获取互斥体 → 成功则持有 Primary 角色
  - **GuardianB（备选）**：PromoteToPrimary 时尝试 WaitForSingleObject(0ms) 获取互斥体 → 成功才提升
  - 获取失败（已被 A 持有）→ 保持 Backup
  - 处理 `WAIT_ABANDONED`（A 崩溃未释放）→ B 获得互斥体 → 提升
  - A 恢复时获取同一互斥体 → B 检测到心跳恢复 → 释放互斥体 → 降级
  - 无需引入新依赖（Windows 原生 Mutex API）

  **Must NOT do**:
  - 不引入第三方共识库
  - 不修改心跳间隔

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 分布式系统 leader election 需要精确实现
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with Tasks 7-9, 11-12)
  - **Parallel Group**: Wave 2
  - **Blocks**: None
  - **Blocked By**: Task 4

  **References**:

  **API/Type References**:
  - `src/service/GuardianB/src/guardian_b.cpp:442-458` - 当前 failover 逻辑
  - `src/service/GuardianB/src/guardian_b.cpp:454-458` - PromoteToPrimary 调用点
  - `src/service/GuardianB/src/guardian_b.cpp:492-506` - DemoteToBackup
  - `src/service/GuardianA/src/guardian_a.cpp` - OnStart/Initialize 阶段（需添加互斥体获取）
  - `src/service/GuardianA/include/guardian_a.h` - 添加 HANDLE m_leaderMutex 成员

  **External References**:
  - Windows `CreateMutexW` / `WaitForSingleObject` / `ReleaseMutex` — MSDN

  **WHY Each Reference Matters**:
  - 442-458 是脑裂根因 — 互斥体检查必须插入此处的 promote 路径

  **Acceptance Criteria**:

  - [ ] Global 命名互斥体用于 leader election
  - [ ] 同时启动 A+B → 仅一个为 Primary
  - [ ] A 崩溃 → B 获取 abandoned mutex → 提升
  - [ ] `ctest -R "FailoverTest"` 全部 PASS

  **QA Scenarios:**

  ```
  Scenario: 脑裂防护验证
    Tool: Bash
    Steps:
      1. cmake --build build --config Release
      2. ctest --test-dir build --config Release -R "FailoverTest" --output-on-failure
    Expected Result: Failover 测试 PASS
    Evidence: .sisyphus/evidence/task-10-splitbrain-fix.txt
  ```

  **Commit**: YES
  - Message: `fix(failover): add Global mutex leader election for split-brain`
  - Files: `src/service/GuardianB/src/guardian_b.cpp`, `src/service/GuardianA/src/guardian_a.cpp`, `src/service/GuardianA/include/guardian_a.h`
  - Pre-commit: `ctest -R StateSync`

- [x] 11. 非主控事件文件记录

  **What to do**:
  - 修改 `src/service/GuardianB/src/guardian_b.cpp:525-527`：当 `m_isPrimary == false` 时，将事件写入本地日志文件而非丢弃
  - 日志路径：`C:\ProgramData\GuardianShield\logs\backup_events_YYYY-MM-DD.json`
  - 格式：JSON Lines（每行一个事件 JSON）
  - 包含时间戳、事件类型、源进程、文件路径
  - 日志文件大小限制：50MB 轮转
  - A 恢复后可读取此日志了解 B 接管期间的事件

  **Must NOT do**:
  - 不实现跨进程事件转发（仅写本地文件）
  - 不修改 IPC 通信协议

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: 需要实现日志写入、轮转、格式化
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with Tasks 7-10, 12)
  - **Parallel Group**: Wave 2
  - **Blocks**: None
  - **Blocked By**: Task 6

  **References**:

  **Pattern References**:
  - `src/service/common/src/logger.cpp` - Logger 写入模式
  - `src/service/common/include/logger.h` - Logger API

  **API/Type References**:
  - `src/service/GuardianB/src/guardian_b.cpp:525-527` - 当前事件丢弃代码

  **WHY Each Reference Matters**:
  - logger.cpp 已有 JSON 日志写入和日轮转模式 — 复用此模式

  **Acceptance Criteria**:

  - [ ] 非主控事件写入日志文件
  - [ ] JSON Lines 格式
  - [ ] `ctest -R "EventLogging"` PASS

  **QA Scenarios:**

  ```
  Scenario: 事件日志测试 GREEN
    Tool: Bash
    Steps:
      1. cmake --build build --config Release
      2. ctest --test-dir build --config Release -R "EventLogging" --output-on-failure
    Expected Result: 事件日志测试 PASS
    Evidence: .sisyphus/evidence/task-11-event-logging-green.txt
  ```

  **Commit**: YES
  - Message: `fix(events): log events to file when non-primary`
  - Files: `src/service/GuardianB/src/guardian_b.cpp`
  - Pre-commit: `ctest -R EventLog`

- [x] 12. TCP accept 端 ACL + 连接源验证

  **What to do**:
  - TCP 绑定已使用 `INADDR_LOOPBACK`（ipc.cpp:520-523），无需修改绑定地址
  - 在 TCP accept 后添加 `getpeername` 连接源验证：仅接受来自 127.0.0.1 的连接，拒绝其他来源并关闭 socket
  - 在代码注释中标记 TLS 为 V2 范围（替代当前的 "TLS not implemented" 注释）
  - 实现后运行 Task 2 的 IPC 测试验证无回归

  **Must NOT do**:
  - 不实现 TLS
  - 不移除 TCP 通道
  - 不使用 `SetSecurityInfo`（不适用于 Winsock SOCKET）

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: 安全加固级修改
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with Tasks 7-11)
  - **Parallel Group**: Wave 2
  - **Blocks**: None
  - **Blocked By**: Task 2

  **References**:

  **API/Type References**:
  - `src/service/common/src/ipc.cpp:520-523` - TCP 绑定代码（已为 INADDR_LOOPBACK）
  - `src/service/common/src/ipc.cpp:502-503` - TLS 降级日志（需修改注释）

  **External References**:
  - MSDN `getpeername` — 获取连接源地址进行验证

  **WHY Each Reference Matters**:
  - ipc.cpp:520-523 已是 loopback 绑定 — 本任务重点是 accept 端验证和 ACL

  **Acceptance Criteria**:

  - [ ] Accept 后使用 getpeername 验证连接源为 127.0.0.1
  - [ ] 非 loopback 连接被拒绝并关闭
  - [ ] `ctest -R "IPC"` 全部 PASS

  **QA Scenarios:**

  ```
  Scenario: TCP 连接源验证
    Tool: Bash
    Steps:
      1. grep -n "getpeername\|INADDR_LOOPBACK" src/service/common/src/ipc.cpp
    Expected Result: 至少 2 行匹配（loopback 绑定 + accept 验证）
    Evidence: .sisyphus/evidence/task-12-tcp-acl.txt
  ```

  **Commit**: YES
  - Message: `fix(ipc): add TCP accept ACL and source validation`
  - Files: `src/service/common/src/ipc.cpp`
  - Pre-commit: `ctest -R IPC`

- [x] 13. ETW 孤儿会话恢复

  **What to do**:
  - 修改 `src/service/GuardianA/src/guardian_a.cpp` ETW 初始化代码
  - 当 `StartTraceW()` 返回 `ERROR_ALREADY_EXISTS` 时：
    1. 调用 `ControlTraceW(..., EVENT_TRACE_CONTROL_STOP)` 停止孤儿会话
    2. 重新调用 `StartTraceW()` 创建新会话
    3. 记录 WARNING 日志
  - 如果二次创建仍失败 → 降级为无 ETW 模式（已有逻辑）

  **Must NOT do**:
  - 不修改 ETW 会话名称（保持 `L"GuardianShieldETW"`）
  - 不修改事件回调逻辑

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: 涉及 ETW 系统 API 的错误处理
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with Tasks 14, 15)
  - **Parallel Group**: Wave 3
  - **Blocks**: Task 16
  - **Blocked By**: Task 5

  **References**:

  **API/Type References**:
  - `src/service/GuardianA/src/guardian_a.cpp:606-618` - ETW 启动失败处理
  - `src/service/GuardianA/src/guardian_a.cpp:579-658` - ETW 初始化全流程

  **External References**:
  - MSDN `ControlTraceW` EVENT_TRACE_CONTROL_STOP

  **WHY Each Reference Matters**:
  - 606-618 是 ETW 失败处理点 — 在此处插入孤儿会话清理逻辑

  **Acceptance Criteria**:

  - [ ] ERROR_ALREADY_EXISTS 得到处理
  - [ ] 孤儿会话被清理后重建
  - [ ] `ctest -R "ETWPipeline"` PASS

  **QA Scenarios:**

  ```
  Scenario: ETW 初始化代码审查
    Tool: Bash
    Steps:
      1. grep -n "ERROR_ALREADY_EXISTS\|EVENT_TRACE_CONTROL_STOP" src/service/GuardianA/src/guardian_a.cpp
    Expected Result: 至少 2 行匹配（错误检测 + 会话停止）
    Evidence: .sisyphus/evidence/task-13-etw-orphan.txt
  ```

  **Commit**: YES
  - Message: `fix(etw): handle orphan session recovery on startup`
  - Files: `src/service/GuardianA/src/guardian_a.cpp`
  - Pre-commit: `ctest -R ETW`

- [x] 14. ETW 降级日志修正

  **What to do**:
  - 修复 `src/service/GuardianA/src/guardian_a.cpp:313`（或 FIX-10 标注位置）
  - ETW 启动失败时日志级别从 WARN 升级为 ERROR
  - 确保降级通知发送到 GuardianC（已有逻辑，验证是否工作）

  **Must NOT do**:
  - 不改变降级行为（仍继续运行）

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: 单行日志级别修改
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with Tasks 13, 15)
  - **Parallel Group**: Wave 3
  - **Blocks**: Task 16
  - **Blocked By**: Task 5

  **References**:

  **API/Type References**:
  - `src/service/GuardianA/src/guardian_a.cpp:313` - FIX-10 标注
  - `src/service/GuardianA/src/guardian_a.cpp:383-386` - 无授权数据日志级别

  **Acceptance Criteria**:

  - [ ] ETW 降级使用 ERROR 级别日志
  - [ ] 编译通过，无新警告

  **QA Scenarios:**

  ```
  Scenario: 日志级别验证
    Tool: Bash
    Steps:
      1. grep -n "FIX-10" src/service/GuardianA/src/guardian_a.cpp
    Expected Result: FIX-10 注释已移除或标记为 FIXED
    Evidence: .sisyphus/evidence/task-14-log-level.txt
  ```

  **Commit**: YES
  - Message: `fix(etw): correct degradation log level to ERROR`
  - Files: `src/service/GuardianA/src/guardian_a.cpp`
  - Pre-commit: `cmake --build build --config Release`

- [x] 15. 共享内存原子读写修复

  **What to do**:
  - 修改 `src/service/common/src/ipc.cpp` 中 SharedStateBlock 的读写
  - 64 位时间戳使用 `InterlockedExchange64` / `InterlockedCompareExchange64` 替代直接赋值
  - 防止 32 位对齐的 torn read（虽然 x64 上 64 位读写天然原子，但显式使用 Interlocked 更安全）
  - Nonce 字段同样使用原子操作

  **Must NOT do**:
  - 不改变共享内存布局
  - 不修改心跳间隔

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: 局部 API 替换
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with Tasks 13, 14)
  - **Parallel Group**: Wave 3
  - **Blocks**: Task 16
  - **Blocked By**: Task 4

  **References**:

  **API/Type References**:
  - `src/service/common/src/ipc.cpp:365-477` - SharedMemory 实现
  - `src/service/GuardianC/src/guardian_c.cpp:478-496` - 心跳 nonce 读取

  **Acceptance Criteria**:

  - [ ] 共享内存时间戳使用 InterlockedExchange64
  - [ ] `ctest -R "Heartbeat"` PASS

  **QA Scenarios:**

  ```
  Scenario: 原子操作验证
    Tool: Bash
    Steps:
      1. grep -n "InterlockedExchange64\|InterlockedCompareExchange64" src/service/common/src/ipc.cpp
    Expected Result: 至少 2 行使用 Interlocked API
    Evidence: .sisyphus/evidence/task-15-atomic-shm.txt
  ```

  **Commit**: YES
  - Message: `fix(heartbeat): use InterlockedExchange64 for shared memory`
  - Files: `src/service/common/src/ipc.cpp`
  - Pre-commit: `ctest -R Heartbeat`

- [x] 16. 目标机远程构建 + 全量测试验证（人工辅助步骤）

  > **注意**: 此任务是唯一需要人工参与的步骤。当前开发环境为 macOS，无法编译 Windows 服务。
  > 主人需要在目标 Windows 机器上手动执行以下构建和测试命令。
  > Agent 负责生成构建脚本和验证清单，主人负责在目标机执行。

  **What to do**:
  - Agent 生成 `scripts/verify_build.bat` 一键验证脚本，包含以下步骤
  - 主人在目标 Windows 机器上执行该脚本
  - `cmake -B build -G "Visual Studio 17 2022" -A x64`
  - `cmake --build build --config Release`
  - `ctest --test-dir build --config Release --output-on-failure`
  - 验证 `/W4` 编译零警告
  - 验证所有测试 PASS（baseline + 新增）
  - 保存 build.log 和 test.log 作为证据
  - 如有失败 → 记录具体错误并修复

  **Must NOT do**:
  - 不在非目标环境（macOS）上运行构建验证
  - 不跳过任何测试

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 需要处理构建环境问题和测试失败排查
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Sequential (after Wave 3)
  - **Blocks**: F1-F4
  - **Blocked By**: Tasks 13, 14, 15 (ALL Wave 3)

  **References**:

  **Pattern References**:
  - `build.bat` - 现有构建脚本
  - `CMakeLists.txt` - CMake 配置

  **Acceptance Criteria**:

  - [ ] `cmake --build` 零错误、零 `/W4` 警告
  - [ ] `ctest --output-on-failure` 100% 测试通过
  - [ ] build.log 和 test.log 已保存

  **QA Scenarios:**

  ```
  Scenario: 全量构建验证
    Tool: Bash (on target Windows machine)
    Steps:
      1. cmake -B build -G "Visual Studio 17 2022" -A x64
      2. cmake --build build --config Release 2>&1 | tee build.log
      3. ctest --test-dir build --config Release --output-on-failure 2>&1 | tee test.log
    Expected Result: build.log 含 "Build succeeded"、0 errors; test.log 含 "100% tests passed"
    Failure Indicators: 编译错误、测试 FAIL
    Evidence: .sisyphus/evidence/task-16-full-build.txt, .sisyphus/evidence/task-16-test-results.txt

  Scenario: 零警告验证
    Tool: Bash
    Steps:
      1. grep -c "warning" build.log
    Expected Result: 0 或仅 CMake info warnings（非 /W4 代码警告）
    Evidence: .sisyphus/evidence/task-16-zero-warnings.txt
  ```

  **Commit**: NO (验证任务，无代码变更)

---

## Final Verification Wave (MANDATORY — after ALL implementation tasks)

> 4 review agents run in PARALLEL. ALL must APPROVE. Present consolidated results to user and get explicit "okay" before completing.

- [ ] F1. **Plan Compliance Audit** — `oracle`
  Read the plan end-to-end. For each "Must Have": verify implementation exists (read file, run command). For each "Must NOT Have": search codebase for forbidden patterns — reject with file:line if found. Check evidence files exist in .sisyphus/evidence/. Compare deliverables against plan.
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Tasks [N/N] | VERDICT: APPROVE/REJECT`

  **QA Scenarios:**

  ```
  Scenario: Must Have 逐项验证
    Tool: Bash
    Steps:
      1. grep -rn "DPAPI\|CryptProtectData\|CryptUnprotectData" src/service/common/src/ipc.cpp — HMAC 密钥派生
      2. grep -n "GuardianShield_IPC_v2" src/service/common/src/ipc.cpp — 应无匹配（硬编码已移除）
      3. grep -rn "GuardianShield-Leader\|CreateMutexW" src/service/GuardianB/src/guardian_b.cpp — 脑裂防护
      4. grep -rn "SHA256File\|BCryptCreateHash" src/service/common/src/security.cpp — SHA256 实现
      5. grep -rn "backup_events\|EventLog" src/service/GuardianB/src/guardian_b.cpp — 事件记录
      6. grep -rn "ERROR_ALREADY_EXISTS\|EVENT_TRACE_CONTROL_STOP" src/service/GuardianA/src/guardian_a.cpp — ETW 恢复
      7. ls .sisyphus/evidence/ — 至少 16 个 evidence 文件
    Expected Result: 步骤 1,3-6 有匹配；步骤 2 无匹配；步骤 7 显示 evidence 文件
    Evidence: .sisyphus/evidence/F1-compliance-audit.txt

  Scenario: Must NOT Have 验证
    Tool: Bash
    Steps:
      1. grep -rn "TLS\|SSL_CTX\|mbedtls" src/service/ — 不应有 TLS 实现
      2. grep -rn "CheckPEBDebugPort\|HasRemoteThread" src/service/common/src/security.cpp — 应仍为 stub
      3. git diff --stat HEAD~15..HEAD -- src/service/common/src/config.cpp — config.cpp 改动应 ≤5 行
    Expected Result: 步骤 1 无匹配；步骤 2 中函数体仍为 return false；步骤 3 极少改动
    Evidence: .sisyphus/evidence/F1-must-not-have.txt
  ```

- [ ] F2. **Code Quality Review** — `unspecified-high`
  Run `cmake --build build --config Release` + ctest. Review all changed files for: hardcoded secrets, empty catches, commented-out code, unused includes. Check AI slop: excessive comments, over-abstraction.
  Output: `Build [PASS/FAIL] | Tests [N pass/N fail] | Files [N clean/N issues] | VERDICT`

  **QA Scenarios:**

  ```
  Scenario: 构建 + 测试全量验证
    Tool: Bash
    Steps:
      1. cmake --build build --config Release 2>&1 | tee .sisyphus/evidence/F2-build.log
      2. ctest --test-dir build --config Release --output-on-failure 2>&1 | tee .sisyphus/evidence/F2-test.log
      3. grep -c "warning C" .sisyphus/evidence/F2-build.log — 编译警告计数
      4. grep "tests passed" .sisyphus/evidence/F2-test.log — 测试通过率
    Expected Result: 0 errors, 0 warnings at /W4; "100% tests passed"
    Evidence: .sisyphus/evidence/F2-build.log, .sisyphus/evidence/F2-test.log

  Scenario: 硬编码秘密扫描
    Tool: Bash
    Steps:
      1. grep -rn "password\|secret\|key.*=.*\"" src/service/ --include="*.cpp" --include="*.h" | grep -iv "//\|hash\|Password_hash\|install_key"
    Expected Result: 无新增硬编码秘密（除注释和已知常量外）
    Evidence: .sisyphus/evidence/F2-secret-scan.txt
  ```

- [ ] F3. **Real Manual QA** — `unspecified-high`
  Start from clean state on target Windows machine. Execute EVERY QA scenario from EVERY task. Test cross-task integration. Save to `.sisyphus/evidence/final-qa/`.
  Output: `Scenarios [N/N pass] | Integration [N/N] | VERDICT`

  **QA Scenarios:**

  ```
  Scenario: 全量 QA 场景回放
    Tool: Bash (on target Windows machine)
    Steps:
      1. cmake -B build -G "Visual Studio 17 2022" -A x64
      2. cmake --build build --config Release
      3. ctest --test-dir build --config Release -R "SecurityHash" --output-on-failure
      4. ctest --test-dir build --config Release -R "HMACSecurityTest" --output-on-failure
      5. ctest --test-dir build --config Release -R "EmergencyStateMachine" --output-on-failure
      6. ctest --test-dir build --config Release -R "FailoverTest" --output-on-failure
      7. ctest --test-dir build --config Release -R "ETWPipeline" --output-on-failure
      8. ctest --test-dir build --config Release -R "EventLogging" --output-on-failure
    Expected Result: 全部 PASS
    Failure Indicators: 任何一项 FAIL
    Evidence: .sisyphus/evidence/final-qa/F3-full-qa.txt

  Scenario: 跨任务集成验证
    Tool: Bash
    Steps:
      1. ctest --test-dir build --config Release --output-on-failure 2>&1 | tee .sisyphus/evidence/final-qa/F3-integration.txt
      2. grep "tests passed" .sisyphus/evidence/final-qa/F3-integration.txt
    Expected Result: 总测试数 ≥ 350，100% 通过
    Evidence: .sisyphus/evidence/final-qa/F3-integration.txt
  ```

- [ ] F4. **Scope Fidelity Check** — `deep`
  For each task: read "What to do", read actual diff. Verify 1:1 — everything in spec was built, nothing beyond spec. Check "Must NOT do" compliance. Flag unaccounted changes.
  Output: `Tasks [N/N compliant] | Unaccounted [CLEAN/N files] | VERDICT`

  **QA Scenarios:**

  ```
  Scenario: 变更范围审计
    Tool: Bash
    Steps:
      1. git diff --stat HEAD~15..HEAD -- src/ test/ — 变更文件清单
      2. git diff --stat HEAD~15..HEAD -- src/service/common/src/config.cpp — config.cpp 应无改动或 ≤5 行
      3. git diff HEAD~15..HEAD -- src/ | grep "^+.*TLS\|^+.*SSL\|^+.*mbedtls" — 不应有 TLS 代码
      4. git log --oneline HEAD~15..HEAD — 提交消息审计
    Expected Result: 变更文件仅限计划中列出的文件；config.cpp 无显著改动；无 TLS 代码；16 个 commit
    Failure Indicators: 未计划的文件被修改；出现禁止的代码模式
    Evidence: .sisyphus/evidence/F4-scope-audit.txt

  Scenario: Commit 策略合规
    Tool: Bash
    Steps:
      1. git log --oneline HEAD~15..HEAD | wc -l
      2. git log --oneline HEAD~15..HEAD | grep -c "^.*test\|^.*fix\|^.*chore"
    Expected Result: 15 个 commit，全部遵循 type(scope) 格式
    Evidence: .sisyphus/evidence/F4-commit-audit.txt
  ```

---

## Commit Strategy

| Commit | Type | Scope | Message | Files | Pre-commit |
|--------|------|-------|---------|-------|------------|
| 1 | test | security | `test(security): add SHA256File and VerifyHash test vectors` | test/test_security.cpp, test/CMakeLists.txt | cmake --build + ctest -R Security |
| 2 | test | ipc | `test(ipc): add HMAC zero-checksum bypass and tamper tests` | test/test_ipc.cpp | ctest -R IPC |
| 3 | refactor+test | emergency | `refactor(emergency): extract state machine + add transition tests` | test/test_emergency.cpp, src/service/common/include/emergency_state_machine.h, src/service/common/src/emergency_state_machine.cpp, src/service/common/CMakeLists.txt, src/service/GuardianA/src/guardian_a.cpp | ctest -R Emergency |
| 4 | test | failover | `test(failover): add split-brain and heartbeat timeout tests` | test/test_state_sync.cpp | ctest -R StateSync |
| 5 | test | etw | `test(etw): add ETW pipeline mock event injection tests` | test/test_etw_pipeline.cpp, test/CMakeLists.txt | ctest -R ETW |
| 6 | test | events | `test(events): add non-primary event logging tests` | test/test_event_logging.cpp, test/CMakeLists.txt | ctest -R EventLog |
| 7 | fix | security | `fix(security): implement SHA256File with BCrypt SHA-256` | src/service/common/src/security.cpp | ctest -R Security |
| 8 | fix | security | `fix(security): implement VerifyHash for process integrity` | src/service/common/src/security.cpp | ctest -R Security |
| 9 | fix | ipc | `fix(ipc): reject zero-checksum HMAC + derive key from DPAPI` | src/service/common/src/ipc.cpp | ctest -R IPC |
| 10 | fix | failover | `fix(failover): add Global mutex leader election for split-brain` | src/service/GuardianB/src/guardian_b.cpp, src/service/GuardianA/src/guardian_a.cpp, src/service/GuardianA/include/guardian_a.h | ctest -R StateSync |
| 11 | fix | events | `fix(events): log events to file when non-primary` | src/service/GuardianB/src/guardian_b.cpp | ctest -R EventLog |
| 12 | fix | ipc | `fix(ipc): add TCP accept ACL and source validation` | src/service/common/src/ipc.cpp | ctest -R IPC |
| 13 | fix | etw | `fix(etw): handle orphan session recovery on startup` | src/service/GuardianA/src/guardian_a.cpp | ctest -R ETW |
| 14 | fix | etw | `fix(etw): correct degradation log level to ERROR` | src/service/GuardianA/src/guardian_a.cpp | ctest |
| 15 | fix | heartbeat | `fix(heartbeat): use InterlockedExchange64 for shared memory` | src/service/common/src/ipc.cpp | ctest -R Heartbeat |

---

## Success Criteria

### Verification Commands
```bash
cmake -B build -G "Visual Studio 17 2022" -A x64  # Expected: Configure success
cmake --build build --config Release               # Expected: 0 errors, 0 warnings at /W4
ctest --test-dir build --config Release --output-on-failure  # Expected: 100% tests passed
```

### Final Checklist
- [ ] All "Must Have" present (HMAC fix, zero-checksum reject, split-brain, SHA256, VerifyHash, ETW recovery, event logging)
- [ ] All "Must NOT Have" absent (no TLS, no anti-debug, no config.cpp refactor, no event forwarding, no cross-platform)
- [ ] All tests pass (baseline ~265 + ~120 new = ~385 total)
- [ ] Zero `/W4` warnings
- [ ] All 15 commits follow TDD pattern (test first → fix → verify)
