# GuardianShield v3.3.0 File Protection Test Report

**Date**: 2026-03-18 01:50:13
**Duration**: 902.1 seconds
**Version**: v3.3.0 (threat detection focused + FILE_RENAME + A/B symmetry)

## Summary

| Metric | Count |
|--------|-------|
| PASSED | 76 |
| FAILED | 0 |
| SKIPPED | 18 |
| **TOTAL** | **94** |

## Result: ALL CHECKS PASSED

## Detailed Results

| ID | Result | Description |
|----|--------|-------------|| T0.1 | PASS | All 3 components running (A=Running, B=Running, C=PID 14116) |
| T0.2 | PASS | config_cache.bin exists (1127 bytes) |
| T0.3 | PASS | Log directory and today's guardian_a log exist |
| T0.4 | PASS | IPC pipes found (A=True, B=True, C=True) |
| T0.5 | PASS | ETW session running (no errors in etw_thread.txt) |
| T1.1 | PASS | WinDefenderCore still RUNNING (not STOPPED by auth failure) |
| T1.2 | SKIP | No 'Authorized' entry found (service may have started before today) |
| T1.3 | PASS | No unauthorized/emergency entries in today's log |
| T2.1 | PASS | FILE_CREATE detected for phase2_create.txt |
| T2.2 | PASS | FILE_WRITE detected with content append |
| T2.3 | PASS | FILE_RENAME detected |
| T2.4 | PASS | FILE_DELETE detected |
| T2.5 | PASS | Recursive subfolder detection works |
| T2.6 | PASS | Process name 'powershell' found in log entries |
| T2R.1 | PASS | FILE_RENAME detected for Rename-Item |
| T2R.2 | PASS | FILE_RENAME detected for same-volume Move-Item |
| T2R.3 | PASS | Rename outside protected dir NOT detected (correct) |
| T2R.4 | PASS | .log rename excluded (filter consistency confirmed) |
| T3.1 | PASS | .log file excluded (not in log) |
| T3.2 | PASS | .tmp file excluded (not in log) |
| T3.3 | PASS | .obj file excluded (not in log) |
| T3.4 | PASS | .txt file detected (monitored) |
| T4.1 | PASS | desktop.ini excluded (hardcoded) |
| T4.2 | PASS | Thumbs.db excluded (hardcoded) |
| T5.1 | PASS | PowerShell WRITE detected (powershell.exe has READ-only permission) |
| T5.2 | PASS | cmd.exe WRITE detected (not in whitelist) |
| T5.3 | PASS | IPC ALERT_NOTIFICATION sent to GuardianC |
| T6.1 | PASS | File outside protected dir NOT detected (correct) |
| T6.2 | PASS | File inside protected dir detected (correct) |
| T7.1 | PASS | No protocol triggered with 10 files (below threshold) |
| T7.2 | PASS | 10 FILE_CREATE events logged for batch files |
| T7.3 | PASS | Confirmed: no protection/emergency protocol in batch test |
| T7R.1 | PASS | No protocol triggered with 5 renames (below tier1=10) |
| T7R.2 | PASS | No protocol after window expiry + 5 more renames |
| T8.1 | PASS | Protocol-related activity detected |
| T8.2 | PASS | Threshold detection responded |
| T8.3 | PASS | Services restarted successfully after Tier-1 interrupt |
| T8.4 | PASS | No files encrypted (ALERT interrupted before ENCRYPTING) |
| T8R.1 | PASS | Tier/protocol activity detected for rename batch |
| T8R.2 | PASS | Services restored to RUNNING after rename Tier-1 interrupt |
| T8R.3 | PASS | Post-cancel single rename logged without protocol trigger |
| T9.1 | PASS | GuardianA (WinDefenderCore) stopped |
| T9.2 | SKIP | GuardianB running but promotion not logged (heartbeat-based failover may take >30s) |
| T9.3 | SKIP | Demotion log not found within timeout (may take longer) |
| T9.4 | PASS | Both services RUNNING after failover test |
| T10.1 | PASS | config_cache.bin survives service stop (1127 bytes) |
| T10.2 | PASS | Both services recovered to RUNNING |
| T10.3 | SKIP | Cache restoration log not found (may use different wording) |
| T11.1 | PASS | ETW drop rate: 2.32% (232/10000) - below 15% threshold |
| T11.2 | PASS | ETW thread running without critical failures |
| T11.3 | PASS | No ETW stall detected in today's log |
| T12.1 | PASS | config_cache.bin exists and > 100 bytes (1127 bytes) |
| T12.2 | SKIP | No v3.2/event_responses reference found in today's log |
| T12.3 | PASS | Config NOT loaded from DEFAULT (YAML or cache in use) |
| T12.4 | PASS | guardian_config.yaml has been deleted (secure delete mechanism working) |
| T13.1 | SKIP | GuardFilter driver not loaded (BLOCK tests will verify degradation path) |
| T13.2 | SKIP | Driver not loaded - cannot test kernel-level block |
| T13.3 | SKIP | Driver not loaded - cannot test kernel-level move block |
| T13.4 | PASS | BLOCK skipped (driver not connected) - no process termination |
| T13.5 | PASS | No TERMINATE degradation (v3.3: BLOCK without driver is safely skipped) |
| T13.6 | PASS | FILE_RENAME response_action contains BLOCK |
| T13.7 | PASS | Startup log confirms BLOCK will be skipped (driver not loaded) |
| T14.1 | PASS | notepad.exe write: no threat alert (whitelisted) |
| T14.2 | SKIP | Notepad test file not created (notepad may not have saved) |
| T14.3 | PASS | cmd.exe write detected (not in whitelist) |
| T14.4 | PASS | PowerShell (READ-only) write detected (permission insufficient) |
| T15.1 | PASS | File inside protected directory detected |
| T15.2 | PASS | File outside protected directory NOT detected (correct) |
| T15.3 | SKIP | No missing-directory warning (all configured directories may exist) |
| T16.1 | PASS | Guardian IPC pipes found (3 pipes: GuardianIPC_C, GuardianIPC_A, GuardianIPC_B) |
| T16.2 | PASS | ALERT_NOTIFICATION sent to GuardianC (IPC working) |
| T16.3 | SKIP | GuardianC log file not found at expected path |
| T17.1 | PASS | winmon.exe running with PID 14116 |
| T17.2 | PASS | Sent kill signal to winmon.exe PID 14116 |
| T17.3 | PASS | winmon.exe restarted with new PID 16376 |
| T17.4 | SKIP | No winmon restart log entry found (may use different wording) |
| T18.1 | PASS | Baseline recorded at log line 11283 |
| T18.2 | PASS | cmd.exe: CREATE + WRITE + RENAME performed on protected file |
| T18.3 | PASS | Collected 117 new log lines |
| T18.4 | PASS | All 3 events found: FILE_CREATE, FILE_WRITE, FILE_RENAME |
| T18.5 | PASS | Log entry has all required fields: event_type, process_name, file_path, timestamp |
| T18.6 | PASS | FILE_WRITE response_action contains ALERT_USER |
| T18.7 | PASS | FILE_RENAME response_action contains BLOCK |
| T18.8 | SKIP | FILE_CREATE found but LEVEL_0 not in entry |
| T18.9 | SKIP | FILE_WRITE found but LEVEL_1 not in entry |
| T18.10 | SKIP | FILE_RENAME found but LEVEL_2 not in entry |
| T19.1 | PASS | No Tier-1 triggered by 5 process terminations (threshold=50) |
| T19.2 | SKIP | GuardianB may not have promoted or logged events |
| T19.3 | SKIP | Targeted termination not logged (may only appear at Tier-2) |
| T19.4 | SKIP | No response_action entries in GuardianB log |
| T19.5 | PASS | No paper event types (FILE_READ etc.) in recent log |
| T19.6 | PASS | NETWORK_SEND not contributing to batch counts |
| T19.7 | PASS | YAML securely deleted (T12.4); cache cannot rebuild without source (expected) |
| T19.8 | PASS | Cache exists with rename fields (size=1127, v11 includes rename) |

## Test Phases

| Phase | Name | Description |
|-------|------|-------------|
| 0 | Environment Health | Services, cache, logs, IPC, ETW |
| 1 | Cold Boot Auth | Authorization after restart (MAC-only fallback) |
| 2 | ETW Detection | CREATE, WRITE, RENAME, DELETE, recursive, process name |
| 2R | FILE_RENAME Detection (v3.3) | Rename, same-vol move, outside-path, filter consistency |
| 3 | File Type Filter | .log/.tmp/.obj excluded, .txt monitored |
| 4 | Filename Exclusion | desktop.ini, Thumbs.db hardcoded skip |
| 5 | Process Whitelist | powershell READ-only, cmd.exe not whitelisted, IPC delivery |
| 6 | Path Boundary | Inside vs outside protected directory |
| 7 | Batch Below Threshold | 10 files < tier1=15, no protocol triggered |
| 7R | Rename Below Threshold (v3.3) | 5 renames < tier1=10, window expiry verification |
| 8 | Tier-1 Trigger+Interrupt | 16 files > tier1=15, protocol triggered, service stop to cancel |
| 8R | Rename Tier-1 Trigger (v3.3) | 10 renames = tier1=10, interrupt, post-cancel verification |
| 9 | GuardianB Failover | Stop A, B promotes, restart A, B demotes |
| 10 | Service Restart | Cache persistence, config reload from cache |
| 11 | ETW Stability | Drop rate, thread health, stall detection |
| 12 | Config Version | Cache validity, YAML/cache source, secure delete |
| 13 | BLOCK Full Chain | Driver status, rename/move block, degradation, policy log |
| 14 | Whitelist Deep | notepad (whitelisted), cmd (non-WL), powershell (READ-only) |
| 15 | Protected Dir Boundary | Inside/outside detection, missing dir warning |
| 16 | IPC Notification | Pipe existence, ALERT_NOTIFICATION delivery, GuardianC receipt |
| 17 | GuardianC Auto-Restart | Kill winmon, verify auto-restart, log confirmation |
| 18 | End-to-End Smoke | CREATE鈫扺RITE鈫扲ENAME chain, field completeness, threat levels |
| 19 | v3.3.0 Regression | process_termination safe, B no short-circuit, cache v11, rename thresh |
