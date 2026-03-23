> ⚠️ **归档文档** — 本文档为需求分析文档，部分枚举值与当前代码不一致。
触发保护系统的行为（完整版）

> **⚠ 原始需求文档**: 本文档为项目最初需求草稿，其中的响应动作位码和威胁等级已在后续开发中调整。以 `FUNCTIONAL_SPEC.md` 和 `guardian_config.yaml` 为准。
对指定路径下的文件进行保护与监视（指定路径需可配置）
该软件功能要求如下
1.当该文件夹里文件被读取时仅记录；
2.当该文件夹下文件被增加时仅记录；
3.当该文件夹下文件被删除时仅记录；
4.当该文件夹下文件被修改时仅记录；
5.当该文件夹下文件被移动时锁定文件；
6.当该文件夹下文件被压缩时即锁定文件；
7.当该文件夹下文件被网络传输时阻止操作并告警（批量超阈值时触发协议）；
8.该软件开机自启，自动建立本机的软件运行日志
9.系统应具备对阈值的配置，例如5秒内对文件压缩数量超过10个、5秒内该文件被复制/网络传输超过10个、数据传输超过1MB等可量化的结果需要管理员可以自行在配置文件里配置，写到guardian_config.yaml里。
配置文件里要有文件类型过滤和进程白名单。
10.核心是该软件能够区别正常操作与恶意被盗走。
11.该文件夹被锁定后，任何人不能操作，需要管理员输入密码进行解锁。
12.该阈值配置文件每次开机后就会进行读取，如果未读取到就按照第一次读取到的策略来执行，如果读取到了就会按照最新的策略来执行，相当于是一个钥匙，该文件一般不放在本机内，只存在于人工管理员。
| 事件类型 | 威胁等级 | 响应动作 | 说明 |
|----------|----------|----------|------|
| FILE_READ | LEVEL_0 | LOG | 文件读取（仅记录） [预留] |
| FILE_CREATE | LEVEL_0 | LOG | 文件创建 （仅记录）|
| FILE_WRITE | LEVEL_1 | LOG + ALERT_USER | 文件修改 （仅记录）|
| FILE_DELETE | LEVEL_2 | LOG + ALERT_USER + BLOCK | 文件删除（阻止） |
| FILE_RENAME | LEVEL_1 | LOG + ALERT_USER | 文件重命名 |
| FILE_SET_INFO | LEVEL_1 | LOG + ALERT_USER | 文件属性修改 [预留] |
| FILE_MOVE | LEVEL_1 | LOG + ALERT_USER + LOCK_FILE | 文件移动（锁定） [已实现] 通过 CREATE+DELETE 事件关联检测跨卷移动 |
| FILE_COMPRESS | LEVEL_2 | LOG + ALERT_USER + BLOCK + LOCK_FILE | 文件压缩（阻止+锁定） |
| FILE_NETWORK_TRANSFER | LEVEL_2 | LOG + ALERT_USER + BLOCK | 网络传输（阻止） |
| PROCESS_CREATE | LEVEL_0 | LOG | 进程创建 |
| PROCESS_TERMINATE | LEVEL_1 | LOG + ALERT_USER | 进程终止 |
| PROCESS_INJECT | LEVEL_2 | LOG + ALERT_USER + BLOCK + TERMINATE | 进程注入（阻止+终止） [预留] |
| PROCESS_DEBUG | LEVEL_2 | LOG + ALERT_USER + BLOCK + TERMINATE | 调试器附加（阻止+终止） [预留] |
| DRIVER_LOAD | LEVEL_1 | LOG + ALERT_USER | 驱动加载 |
| DRIVER_UNLOAD | LEVEL_1 | LOG + ALERT_USER | 驱动卸载 |
| NETWORK_CONNECT | LEVEL_1 | LOG + ALERT_USER | 网络连接 [预留] |
| NETWORK_SEND | LEVEL_1 | LOG + ALERT_USER | 网络发送 [预留] |
| NETWORK_RECV | LEVEL_1 | LOG + ALERT_USER | 网络接收 [预留] |
| 批量操作超 tier1 | — | 保护协议 (ENCRYPT+LOCK) | 可恢复 |
| 批量操作超 tier2 | — | 紧急协议 (ENCRYPT+WIPE+DELETE) | 不可逆 |
| 未授权设备启动 | — | 紧急协议 (跳过 ALERT) | 不可逆 |
---
响应动作说明
| 响应动作 | 代码 | 执行内容 |
|----------|------|----------|
| LOG | 0x01 | 记录事件到日志文件 |
| ALERT_USER | 0x02 | 弹出用户通知/系统托盘警告 |
| BLOCK | 0x10 | 阻止操作执行 |
| TERMINATE | 0x08 | 终止可疑进程 |
| LOCKDOWN | 0x80 | 锁定文件，禁止访问 |
| ENCRYPT | 0x20 | 加密保护文件 |
| WIPE | 0x40 | 安全擦除文件（DOD_5220标准） |
| LOCKDOWN | 0x80 | 系统锁定，禁止所有操作 |
---
紧急协议执行流程（细化）
LEVEL_3 触发后的响应流程:
┌─────────────────────────────────────────────────────────┐
│ 1. NORMAL → ALERT                                       │
│    • 增强监控模式                                        │
│    • 记录所有操作到日志                              │
│    • 发送警报通知（Windows窗口）                        │
│    • 等待时间：即时                                      │
├─────────────────────────────────────────────────────────┤
│ 2. ALERT → ENCRYPTING                                   │
│    • 加密保护目录下的所有敏感文件                        │
│    • 使用密码保护，密码由管理员设置                          │
│                                         │
├─────────────────────────────────────────────────────────┤
│ 3. ENCRYPTING → WIPING                                  │
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
│    • 等待管理员输入密码解锁                                      │
│                                      
└─────────────────────────────────────────────────────────┘
---
配置文件阈值参数（仅作参考，自行调整，可增加）
detection:
  alert_timeout_seconds: 30        # ALERT 阶段等待时间（秒）
  thresholds:
    tier1:                         # 保护协议阈值（加密+锁定，可恢复）
      file_write_count: 10         # 5 秒内写入 ≥10 个文件
      file_write_window_seconds: 5
      file_delete_count: 5
      file_delete_window_seconds: 5
      file_compress_count: 50
    tier2:                         # 紧急协议阈值（加密+擦除，不可逆）
      file_write_count: 50
      file_write_window_seconds: 10
      file_delete_count: 20
      file_delete_window_seconds: 10
      file_compress_count: 250
配置文件阈值参数的格式看起来不够清晰，部分没有单位，也没有时间，很不合理，应该能让人一眼就看出如何修改。例如批量压缩阈值就会有两个配置项，多少时间内（单位为秒），压缩多少文件。

工程文件在内部的使用方式存在虚拟机和系统级镜像两种方式，所以如果有人将虚拟机或装有该工程文件的镜像系统非法获取，会造成该工程文件的流失，所以需要增加对运行环境的检测与确认，目前可以为每台运行该工程文件的虚拟机或电脑配置唯一的IP地址，当前考虑将该IP地址与终端计算机的MAC地址作为校验确认信息。开机启动时会自动核对运行环境的IP地址，如果该IP地址与MAC地址在默认的清单列表中，则操作正常。若不在则执行最高等级的处置流程。清单列表也是钥匙的方式，存放地址与格式都有明确要求，当需要补充或删除某个清单时，由管理员拷贝到某个具体的计算机进行修改，完毕后会删除该清单。
卸载需要输入密码

每天建立新日志文件（系统运行日志+保护路径下的监控日志
），保留天数7天
3. 系统开机自启方案：
系统开机后自启，开启后无窗口，直接跑在进程里
硬件环境全是windows11系统。
   
为管理员留后门，进行系统的中止和卸载，预留数据解锁和恢复后门