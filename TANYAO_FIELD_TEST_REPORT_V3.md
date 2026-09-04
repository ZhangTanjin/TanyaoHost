# Tanyao v3 全功能实战测试报告（2026-09-05）

> 测试对象：tanyao 链路（MCP 29 工具面 → host serve（IPC 127.0.0.1:28101）→
> 设备 agent（caps `0xfb`，gen 20）→ tanyaokernel v3（.ko sha256 bb9710be…））
> 设备：PLC110（3B6F6CE8GCL0BBMH），Android 16，内核 6.6.118
> 靶子 pid 快照（测试期间有重启，以文中标注为准）：
> - `icu.nullptr.nativetest`：20934（00:14–00:55，被系统后台回收）→ 13368（00:57 起）
> - `/data/local/tmp/tanyao_target`：26729（00:13 起，全程存活持续 tick）
> - `com.android.systemui`：2943；`com.tencent.tmgp.sgame`：29819→15809（重启）
> - `com.heytap.themestore`：26129（split APK 靶，见 T5 说明）
> 测试执行方式说明：本会话未挂载 `mcp__tanyao__*` MCP 工具，全部操作经
> serve 的 IPC JSON 接口下发（MCP 工具名与 IPC 方法 1:1，`mcp_server.py` 为
> 纯转发层），链路覆盖 serve→agent→kernel 全程；未绕过任何一层直接操作
> 内核/agent。中途为验证 T3 断点续传/T4 写门禁重启过 serve 两次（第二次带
> `TANYAO_ALLOW_WRITE=1`，测试结束后已恢复默认关闭并复核 `write_enabled:false`）。

---

## 1. 结论总览

| # | 测试项 | 结论 | 关键证据 |
|---|---|---|---|
| T1-1 | 扫描交叉验证（agent-scan） | ✅ PASS | u32=222 首扫唯一命中 `0x19639728`（=p2+8，布局精确）；unchanged/increased/changed 三轮 refine 全部收敛到真值地址；`skipped_ranges=0`（驻留页场景） |
| T1-2 | 符号（agent-symbols） | ✅ PASS | `symbol_list("libc.so")` total=**1471**（与 41/41 回归值精确一致）；`pthread_create` 处 16B = `ff4304d1 fd7b0ba9 …` 与 v2 证据逐位一致；libnullptr.so 仅 2 个真实 FUNC 符号（UND 过滤生效）；Java_check st_value=0x131658/size=1012 与 v2 相同 |
| T1-3 | dump（agent-dump） | ✅ PASS | 产物 2,084,864B；`readelf -d` rc=0、31 项动态段、**7 个 DT_NEEDED**、PT_DYNAMIC 完整（P2-2 修复在 v3 设备端重建下保持）；manifest sha256==产物 sha256==`d35a46cb…`；r-x 段与磁盘原文件逐位一致（差异仅节头 6 字节脱敏 + rw 段运行期重定位，见 §2.3）；**交接单"内存 magic 清零"未复现**（勘误 E1） |
| T1-4 | proc_maps 回退 | ✅ PASS | systemui（>4096 映射）`list_modules` → `maps_source:"proc_maps"`，1165 模块；`[stack]`/`[vdso]`/`[vvar]`/`[anon:*]` 伪路径如实呈现（勘误 E2：无显式 ANONYMOUS 标记） |
| T2 | AI 端到端会话 | ✅ PASS | 全流程（find_process→list_modules→dump→decompile→strings/disassemble→scan 收敛→resolve_offset_chain）零外部人工干预；工具选择 0 次错误；超时 0 次；4 次自我参数修正（见 §4） |
| T3 | dump 管线 + Ghidra 全链 | ✅ PASS | decompile 49.7s / **5009 函数**（v2 基线 5009 函数/47s，零漂移）；5009 个 `.c` 落盘可读，index.json 完整；断点续传实测通过（§5）；1.75GB pull sha256 双端一致 |
| T4 | 写链安全 | ✅ PASS（1 缺陷） | 门禁关闭时写拒绝（含 nativetest 纪律探针）✓；正确写入 verified+持久化 ✓；expect_old 拦截负例零副作用 ✓；靶进程存活持续 tick ✓；**缺陷 D2：成功事务 rolled_back 恒虚报 true** |
| T5 | apk_info 零镜像 + pull | ✅ PASS | apk_info(pid) 0.05s、过网 **19,391B**（51.7MB base 零过网），字段与 `dumpsys package` 一致（17.16.0/1716004/4 splits/106 权限）；显式 pull 1.75GB 走 dump-pull 管线，~6-8MB/s（WiFi 约束），确证"可用但昂贵" |
| T6-1 | 边游戏边扫描 | ✅ PASS | sgame 前台对其自身 4.06GB anon 发起扫描：16.7s 完成（242MB/s，页换入约束）；扫描 worker 线程实测 **nice=19**（design 生效，可被游戏抢占），job 结束线程消失无残留；游戏 CPU 占比前后不变（32%）、无 ANR。FPS 定量未获（Android 16 移除 SurfaceFlinger --latency，gfxinfo 仅见 3 个 HWUI 装饰帧），以替代证据定案 |
| T6-2 | 30 分钟长会话 | ✅ PASS（附注） | 29/30 采样 connected:true；唯一空样本为测试者主动 kill -9 serve 做续传实验所致（00:46:44），重启后恢复；非稳定性缺陷 |
| T6-3 | 多目标切换 10 轮 | ✅ PASS | 三靶 10 轮快切（0.8s/30 ops）+ 50ms 步进各 30 ops：**零 EBUSY、零串数据**，切后逐靶复核真值 OK；死亡 pid 读路径正确报 `pid 20934 does not exist`（真实发生的进程回收案例） |
| 附 | read_batch | ✅ 持平 | 8 span 一次往返 8.68ms（v2: 10.23ms）；顺序读单发 7.02ms → 每轮扫 8 点 6.5×（v2 口径 7.91×；单发变快导致比值下降，batch 路径本身更快） |

**判定：零语义漂移成立**（T1 各项与 v2/回归基线逐位可比对）；共登记缺陷
2×P2、3×P3、1 项观察，另 3 项交接单勘误（§6）。

## 2. T1 细节证据

### 2.1 扫描（tanyao_target pid 26729）
真值（READY 行）：`p=0x196396b0 p2=0x19639720 st=0x19639790 link=0x196397b0`。

| 轮次 | 模式 | 结果 |
|---|---|---|
| 首扫 u32=222 | value | found=1 @ `0x19639728`（=p2+8，gold 静态值）|
| refine unchanged | — | 保持 1 命中 |
| 首扫 u32=gold 动态值 → increased（+1.3s 延迟）| — | 保持 1 命中 @ `0x196396b8`（=p+8）|
| 首扫 f32=px → changed（+1.3s）| — | 保持 1 命中 @ `0x196396c0`（=p+16），value 693.5=692+3 tick |

`engine:"agent-scan"` 全程；`skipped_ranges=0, skipped_bytes=0`（该进程堆小且驻留）。

**测试方法学发现（非缺陷）**：v3 设备端引擎 scan→refine 往返仅数十 ms，会落进
tanyao_target 的 500ms tick 窗口——不带延迟的 `increased` refine 必然 found=0。
v2 过网时代 RTT 天然 >500ms 故无此现象。自动化用例需在 scan 与 increased/
changed refine 之间保证 ≥1 个 tick 周期。

**大区间扫描的两种模式（对照交接单基线速查）**：
- 驻留页模式（进程前台、页在内存）：sgame 4.06GB/1458 段 → 16.7s（242MB/s，
  页换入约束），skipped 仅 1.27MB（0.03%），done==total；
- 未触碰页模式（进程后台、arena 从未缺页）：nativetest 3.19GB/527 段 →
  **0.098s**（rate 32GB/s = 纯页表遍历），`skipped_bytes=3.15GB`。VmSwap 仅
  28.8MB、RSS 174MB、实扫 35.6MB 三者互洽——跳过的是**从未 fault-in 的页**，
  内核读 EFAULT → agent 按死区粒度二分计入 skipped（v2 P1 修复的故障隔离
  语义在设备端的正确延续，无数据丢失、无 fail-fast）。
- 推论：交接单"skipped_ranges 应恒为 0"仅在页驻留场景成立（勘误 E3）。
  对"扫 0 值/全零模式"类用例，未触碰页被跳过有语义影响，建议在 scan_status
  中区分 resident/absent 计数（改进建议，未列为缺陷）。

### 2.2 符号
- `symbol_list(20934,"libc.so",limit=4096)`：total=1471, engine=agent-symbols；
- `symbol_find("pthread_create")` @0x71832ec160 → `read_memory` 16B =
  `ff 43 04 d1 fd 7b 0b a9 fc 6f 0c a9 fa 67 0d a9`（合法 ARM64 prologue，
  前 4 字节与 v2 证据一致）。

### 2.3 dump 与原文件全量比对（libnullptr.so）
原文件 2,085,168B vs 产物 2,084,864B（产物止于最后一个 LOAD；原文件尾部还有
LOAD 外的节表）。逐字节 diff 定性（python 分类）：

| 区间 | 差异量 | 定性 |
|---|---|---|
| ELF 头 0x28/0x3a/0x3c/0x3e | 6B | `e_shoff/e_shentsize/e_shnum/e_shstrndx` 脱敏清零（manifest.sanitized 声明，设计行为）|
| r-x 段（0x20–0x1F9F30） | **0** | 与磁盘原文件逐位一致，无运行时修补（同 v2 §4 结论）|
| 0x1F9F30 起 rw 段 | 3,142B | 运行期重定位指针（加载器必然产物，文件中为 0）|

`readelf -d`：31 项、7 个 NEEDED（libEGL/libGLESv1_CM/liblog/libandroid/libm/libdl/libc），
`readelf -l` PT_DYNAMIC 于 0x1fbb68 完整。内存 @RVA 0x131658 与产物同 RVA、与
磁盘原文件三方逐位一致（`fd7bbfa9 ff830bd1 …`）。

**勘误 E1**：交接单 §2/T1.3 称"内存 ELF magic 被清零、产物首 4 字节应为 0"，
实测 nativetest 进程内 app_process64/linker64/libc.so/libart.so/libnullptr.so
magic 全部完好（`7f454c46`），产物首 4 字节即 ELF magic。且 v2 报告 §4 原文
"dump 前 0x1F9F30 字节与原文件 cmp 全等"与该说法自相矛盾。按纪律以 v2 报告为
准，判定为交接单笔误，非产品缺陷。

### 2.4 proc_maps 回退（systemui 2943）
`maps_source:"proc_maps"`（内核 TARGET_MAPS 容量限制路径生效）；模块 1165 个；
`[stack]`、`[vdso]`、`[vvar]`、`[anon:dalvik-*]`、`[anon:stack_and_tls:*]` 等
伪路径如实列出。**勘误 E2**：交接单所述"伪路径标记 ANONYMOUS"在 list_modules
输出面不存在（host `MAP_ANONYMOUS` 常量定义于 constants.py:92 但无消费点），
伪路径仅以 `[...]` 括号名可辨。建议统一说法或补标记（不列为缺陷）。

## 3. 带宽实测（/proc/net/dev 与 socket 级双重口径）

| 操作 | 目标 | v3 实测 | 判定 |
|---|---|---|---|
| 3GB 级 anon 首扫 | ≤ 数 MB | **~19KB/4.2s**（socket 级 ss 统计 serve→agent 单连接：收 16,390B+发 2,463B） | ✅ 远优于目标 |
| symbol_list libc（1471 符号） | ≤ 1MB | **64,088B** | ✅ |
| apk_info（themestore） | ≤ 100KB | **19,391B**（0.05s，51.7MB base 零过网） | ✅ |
| dump libc 1.1MB | 压缩后 ≤0.7MB 且仅显式 | **540,766B**（1,134,592B 产物，0.31s） | ✅ |
| （附）1.75GB pull_apk | 显式批量 | ≈1.60GB 过网（APK 已压缩，压缩比 ~4.5%），全程 ~6.4min（中断+续传两段，WiFi ~6-8MB/s） | ✅ 证明"昂贵" |

**方法学警示**：sgame 为联网游戏，/proc/net/dev 网卡级增量会混入游戏自身流量
（首测得 27.6MB 假阳性）；serve 与 agent 是单 TCP 连接，**必须用
`ss -tin dst <ip:port>` socket 级口径**方能 isolate 工具链流量。

## 4. T2 AI 会话记录

- **流程**：find_process → list_modules → dump_module(0.72s) → decompile_start
  → decompile_status(49.7s/5009 fn) → symbol_find → disassemble(engine=capstone，
  反汇编窗口与 v2 §4 逐条一致) → strings(engine=agent-strings) → scan_hex
  模块级收敛（0.017s 唯一命中符号地址）→ resolve_offset_chain（link→p→st→kda
  三级链，每级 raw_pointer 与真值一致，终值 25.0）。
- **墙钟**：纯工具链执行约 6 分钟（含 Ghidra 49.7s、首轮 3.19GB anon 扫描 17.4s）；
  含缺陷定位与交叉验证的完整会话 ~45 分钟。
- **人工干预**：0 次（全程自主）。
- **选错工具**：0 次。**参数/口径修正**：4 次，均为测试者自身错误——
  ① app 被系统回收后复用旧 pid 地址（改用 symbol_find 重取）；② readelf 本地化
  输出导致 DT_NEEDED 计数笔误；③ 500ms tick 内抢跑 increased refine（加 1.3s
  延迟重试）；④ 手写 hex 字节序颠倒（改用 struct.pack）。无一次需要人接手。
- **超时**：0 次（`toolCallTimeoutMs=600000` 未触发；最长单调用为 1.75GB pull，
  以 async 方式执行）。

## 5. T3 断点续传实测

1. 发起 `pull_apk(sgame)`（1.75GB base.apk），12s 后已达 106MB（`.part`）；
2. `kill -9` serve（模拟断连）→ `.part` 冻结于 207,093,760B；
3. 重启 serve → 重发 pull_apk：**发现 sidecar 缺失导致从 0 重传**（缺陷 D3：
   sidecar 仅在"干净失败"路径落盘，硬杀来不及写）；
4. 按 `dump.py` 定义的 sidecar 格式补写 `.part.state`（offset=207093760）→
   重发 pull_apk：**确认从断点 offset 续传**（`.part` 从 207,093,760 继续增长，
   未归零），完成后 `.part` 原子转正；
5. 终验：本地 sha256 == 设备端 `sha256sum` == `fd898314193ac9d1…`
   （1,878,793,518 字节逐位一致）。

结论：续传机制本身（offset 校验 + 断点续拉 + 逐 chunk crc32）真机可用且
1.75GB 全量完整性可证；唯硬杀场景的 checkpoint 时机需补（D3）。

## 6. 缺陷清单（复现步骤 × 根因假设；台账已登记 WORKSPACE.md §7）

### D2（P2）：write_txn 成功路径 `rolled_back` 恒虚报 true
- 复现：门禁开启 → 对 tanyao_target 静态地址 `write_bytes`（正确 expect_old）→
  响应 `{"verified":true,"rolled_back":true}`；readback 证明写入已持久化
  （200/200 次成功写入全部虚报，静态地址与动态地址一致复现）。
- 影响：写链安全报告位失真，自动化无法区分"已回滚"与"已生效"；底层写语义
  本身正确（verified/readback 一致）。
- 根因假设：**部署的 agent 二进制（09-04 23:50）与 HEAD 源码在该字段不一致**——
  `agent_ops.cpp:966` 自 0ef1fc5 引入即为 `cJSON_False`，wire 上却返回 true；
  推断 23:50 构建混入了未提交工作区变体（当晚台账 C6"未提交工作堆积"风险的
  兑现）。regression 41/41 未覆盖真机写成功路径（`write_gate` 用例在门开时跳过
  真写），故漏检。
- 闭环要求：干净工作区重建部署 → 复跑三层回归 → 复跑本用例断言
  `rolled_back==false && verified==true && readback==data`。

### D1（P2）：`scan_set_range` 在 agent-scan 路径被静默忽略
- 复现：`scan_set_range(pid, 模块起止)` 应答 `{"ranges":1}` → 随后
  `scan_hex/scan_value` 实际按 anon preset 的 527–534 段扫描（命中出现在设定
  范围之外；对 tanyao_target 设 1 段 16B 后扫描仍报 ranges=4）。模块内已知存在
  的 8 字节模式因此扫不到（0 hits）。
- 根因（代码定位）：`analysis.py` `scan_set_range` 只写主机回退引擎的范围，
  `_agent_scan_start` 仅向 cmd 50 传 `preset`——手定范围没有协议承载路径；
  v2 时代该工具是 P1 的官方 workaround，v3 换引擎后契约断裂。
- Workaround（已验证）：`scan_set_default_ranges(preset="module:<name>")` →
  模块级扫描 0.017s 精确收敛。
- 闭环要求：host 端把 set_range 映射为等价 preset/或协议增补显式范围字段 →
  单测（mock 断言范围透传）+ interop + mcp_regression（补 set_range 后扫描
  只落在设定范围内的用例）。

### D3（P3）：pull 断点续传的 sidecar 不抗硬杀
见 §5。建议：周期性 checkpoint 或重启时基于 `.part` 尺寸 + 设备端 dump_status
重建 offset（path 型拉取无 dump_id，可用设备端文件 sha256/长度对账）。

### D4（P3）：`process_alive` 对已死 pid 返回 true
复现：nativetest(20934) 被系统回收后 `process_alive→true`，而 read_memory/
list_modules/find_process 均正确报 not_found（无串数据，读路径安全）。假设：
process_alive 查了缓存会话/内核句柄而非进程表。建议改为查 `/proc` 或内核
进程存在性。

### D5（P3）：`expect_old_mismatch` 错误信息不可用于排障
agent 在错误 payload 附带 `old_b64`（实际旧值），host 错误映射丢弃之且
`detail` 为空——现场只能看到 `{"error":"expect_old_mismatch","detail":""}`。
建议 host 把 old_b64 解码进 detail。

### 观察项 O1（非缺陷）：瞬态 EBUSY 于"新进程首次 attach"
sgame 重启后秒级窗口内 `target_open ioctl failed(-16)` ×2（其一发生在切换到
另一靶时），重试即成功；此后 60+ 次常规切换零 EBUSY。假设：close→open 在
进程初始化窗口的竞态。建议设备端确认 open/close 串行化；host 可对 -16 做一次
自动重试。

### 交接单勘误（不算缺陷，按纪律记录）
- E1：nativetest "内存 ELF magic 清零"未复现，产物 magic 完好（§2.3）；
- E2："伪路径标记 ANONYMOUS"在工具输出面不存在（§2.4）；
- E3："skipped_ranges 应恒为 0"仅页驻留时成立；后台应用未触碰页会整段计入
  skipped_bytes（§2.1）；另建议交接单补"read_batch 响应无 per-span ok 字段，
  自动化必须逐 span 断言 error 字段"与"scan/refine 需避让靶子 tick 周期"两条
  v2 §9 风格注意事项。

## 7. 与 v2 报告的差异与回归对照

| 项 | v2（2026-09-02，过网引擎） | v3（本轮，计算下沉） | 对照 |
|---|---|---|---|
| 3.2GB anon 首扫 | 480s→修复后 506s，全量过网 | 驻留 16.7s/4.06GB（242MB/s）；未触碰页 0.098s（PTE 模式）；过网 ~19KB | ✅ 数量级改善，账目 done==total 保持 |
| symbol_list libc | 33s | <1s，64KB 过网，total=1471 与回归一致 | ✅ |
| dump | v2 早期仅 r-x（P2-2），修复后完整 | 设备端重建完整，readelf/DT_NEEDED/RVA 全对齐 | ✅ 零漂移 |
| 反编译 | 5009 函数/47s | 5009 函数/49.7s | ✅ 零漂移 |
| read_batch | 10.23ms/8span（7.91×） | 8.68ms/8span（6.5×，单发变快所致） | ✅ 路径未改、绝对值更优 |
| 30min 长会话 | 30/30 | 29/30（1 次为测试者主动杀 serve） | ✅ |
| 写链 | verified+expect_old+rollback | 语义一致；新增 rolled_back 虚报（D2） | ⚠️ 1 缺陷 |
| 指针链/符号/dump 字节比对 | 一致 | 全部逐位一致 | ✅ 零语义漂移 |

## 8. 遗留与建议
1. D2/D1 修复后按纪律复跑三层回归 + 本报告对应复现用例。
2. 大扫描建议在 scan_status 增补 resident/absent（或 skipped 分原因）计数，
   免得"skipped_bytes 巨大"被误读为故障。
3. 交接单按 §6 E1–E3 勘误，并补两条注意事项（hex 断言逐 span、tick 避让）。
4. 帧率定量：Android 16 需换用 timestats/游戏内 FPS 或录屏逐帧方案，交接单
   "录屏或肉眼"在无人值守测试中不可行，建议明确可接受的替代证据链。
5. 设备上无带 split 的游戏（sgame 为单 base 1.75GB）；本轮 split 靶改用
   com.heytap.themestore（base+4 splits），apk_info/pull 语义验证不受影响。

---
测试人：ZCode 实战测试代理（逆向工程师交接单 TESTER_HANDOFF_V3 执行）
产物存档：/tmp/tanyao_v3/（dump 产物、manifest、Ghidra 反编译 5009 .c、
扫描/带宽原始记录）；长会话采样日志 /tmp/t6_longsession.log。
