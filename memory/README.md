# GuardianShield Memory (项目记忆库)

本文件夹记录了 GuardianShield 项目的开发历程、架构决策、问题修复和反思教训。
作为 AI 辅助开发的持续上下文，帮助在后续对话中快速恢复项目认知。

**项目**: GuardianShield v3.3.0 (配置版本 3.3.0)
**创建时间**: 2026-03-03
**最后更新**: 2026-03-18

---

## 文件索引

| 文件 | 说明 |
|------|------|
| [changelog.md](changelog.md) | 变更日志 -- 按时间线记录所有重要修改 |
| [architecture_decisions.md](architecture_decisions.md) | 架构决策记录 -- 关键设计选择及其理由 |
| [issues_and_fixes.md](issues_and_fixes.md) | 问题与修复 -- 所有遇到的 bug、根因分析和解决方案 |
| [reflections.md](reflections.md) | 反思与教训 -- 从错误中总结的经验和改进思路 |
| [current_state.md](current_state.md) | 当前状态 -- 项目现状、已完成功能和待办事项 |
| [threat_detection_design.md](threat_detection_design.md) | 威胁检测设计 -- 三层响应架构的完整规格说明 |

---

## 项目概述

GuardianShield 是一个 Windows 文件保护系统，由三个核心组件组成：

- **GuardianA** (`svchost_core.exe` / 服务名 `WinDefenderCore`) -- 主控服务，运行在 Session 0，负责 ETW 事件采集、威胁评估和响应执行
- **GuardianB** (`svchost_helper.exe` / 服务名 `WinDefenderHelper`) -- 备份服务，监控 GuardianA 健康状态，故障时接管主控
- **GuardianC** (`winmon.exe` / 注册表 `WindowsMonitor`) -- 用户态进程，运行在用户 Session，负责桌面通知（含 MessageBeep 音频回退）、文件管理面板、一键解锁

辅助组件：
- **GuardFilter** -- 内核迷你过滤器驱动，拦截文件系统操作
- **guardian_ca.dll** -- MSI 安装器的自定义操作 DLL

---

## 如何使用

在新的 AI 对话开始时，读取本文件夹中的相关文档可以快速恢复上下文：
1. 先读 `current_state.md` 了解当前状态
2. 遇到问题时查 `issues_and_fixes.md` 看是否有先例
3. 做设计决策前查 `architecture_decisions.md` 了解已有的设计原则
4. 需要理解威胁检测行为时查 `threat_detection_design.md`
5. 编写任何批处理脚本前查 `reflections.md` 中的批处理相关条目

**组件名称映射（快速参考）**:

| 内部代号 | 服务名 | 显示名 | 可执行文件 |
|---------|--------|--------|-----------|
| GuardianA | `WinDefenderCore` | Windows Defender Core Service | `svchost_core.exe` |
| GuardianB | `WinDefenderHelper` | Windows Defender Helper Service | `svchost_helper.exe` |
| GuardianC | _(无服务名)_ | `WindowsMonitor` (注册表 Run) | `winmon.exe` |

**MSI 版本归档**: 每次构建自动归档上一版 MSI 到 `releases/` 目录，命名为 `GuardianShield_buildN.msi`，详见 `releases/RELEASE_LOG.txt`。
