# Tanyao v3 全功能实战测试 — 逆向工程师交接单

> 交接时间：2026-09-05 ｜ 前置状态：v1.2 已定版（真机 mcp_regression 41/41），
> 内核 v3 证据链闭环（VALIDATION_LOG §0V3）
> 目标设备：PLC110（3B6F6CE8GCL0BBMH），Android 16，内核 6.6.118，
> tanyaokernel v3 Live（.ko `bb9710be…`）
> 上一轮报告：`TANYAO_FIELD_TEST_REPORT.md`（v2，2026-09-02，8 项 7 PASS
> + 1 定位根因，P1/P2/P3 已全部修复）——本轮与其同靶对比。

---

## 1. 环境速查（开工前 3 分钟）

| 组件 | 状态 | 操作 |
|---|---|---|
| 设备 agent | `192.168.1.34:52730`，v1.2 版（caps `0xfb`） | 掉线重启见下方命令 |
| 主机核心 | `tanyao.serve` 常驻，IPC `127.0.0.1:28101` | 重启：`/home/tanjin/phone/tanyao-host/scripts/start-serve.sh` |
| MCP | DeepSeek Harness（`mcp__tanyao__*`，29 工具） | 新会话生效 |
| 健康检查 | `curl -s -X POST http://127.0.0.1:28101/ -H 'Content-Type: application/json' -d '{"method":"get_status","params":{}}'` | `connected:true` 且 `agent_capabilities:"0xfb"` 即就绪 |
| 诊断 | get_status 的 `skipped_caps` | 列出的能力 = 设备 agent 未声明，host 自动走回退 |

agent 掉线/升级重启（两条分开执行；旧版 adb shell 里 `pid=x pidof y` 会踩
mksh 赋值坑，务必用 `$(...)`）：

```bash
adb shell "su -M -c 'p=\$(pidof tanyao-agent); [ -n \"\$p\" ] && kill -TERM \$p'"
adb shell "su -M -c 'nohup /data/local/tmp/tanyao-agent --bind 192.168.1.34 --port 52730 --token-file /data/local/tmp/.tanyao-token >/dev/null 2>&1 &'"
```

## 2. 测试靶子

| 靶 | 用途 | 备注 |
|---|---|---|
| `icu.nullptr.nativetest`（每次重启 pid 变化） | T1/T3/T6 主靶：反 dump 硬化（内存 ELF magic 被清零）、自带 root 检测、60fps NativeActivity | 与 v2 同靶，保证可比 |
| `/data/local/tmp/tanyao_target`（自有进程） | T1 写链/T4 指针链：三级指针 `link→p→stats→kda`，源码 `tests/tanyao_target.c` | **唯一允许写入的靶** |
| 一款带 split APK 的已安装游戏 | T5 apk_info/pull | 测试者自选，报告记录包名 |
| `surfaceflinger` / `systemui` | T1 模块枚举 / proc_maps 回退路径（>4096 映射） | 只读 |
| `libc.so`（任意进程内） | T2 符号/strings/扫描基准 | 只读 |

## 3. 测试项

### T1 正确性交叉验证（最高优先级——引擎换位后的语义证明）

v3 把扫描/符号/dump 从主机引擎搬到设备引擎（工具输出 `engine` 字段应显示
`agent-*`）。对**同一目标**验证结果与地面真值/历史结果一致：

1. **扫描**：对 `tanyao_target` 已知布局做 `scan_value`（u32 已知值）→
   命中地址与 `tests/tanyao_target.c` 的布局对照；再 `scan_refine`
   increased/changed 各一轮。`skipped_ranges` 应恒为 0（内核已排除 PFNMAP）。
2. **符号**：`symbol_list("libc.so")` → 总数与 41/41 回归值（1471）同量级；
   `symbol_find("pthread_create")` 地址处 `read_memory` 读回应为合法 ARM64
   prologue（v2 证据：`ff 43 04 d1`）。对nativetest 再做一次（重型 dynsym）。
3. **dump**：`dump_module` nativetest 主 so → 产物 `readelf -d` 可解析、
   PT_DYNAMIC 完整、manifest 与产物 sha256 一致；**内存 magic 清零目标**
   产物首 4 字节应为 0（反 dump 硬化特征，Ghidra 导入需手动补 magic——
   v2 已知行为，验证设备端重建未改变它）。
4. **proc_maps 回退**：对 `systemui` 做 `list_modules`，`maps_source` 应为
   `proc_maps`，伪路径（[heap]/[stack] 等）标记 ANONYMOUS。

判定：零语义漂移；任何不一致记 P1。

### T2 AI 端到端会话（v2 未覆盖的新维度）

在 MCP 会话里**只给目标不给步骤**，让 AI 自主完成一次完整逆向：
find_process → list_modules → dump_module → decompile（Ghidra）→
strings/disassemble 定位关键函数 → scan 收敛一个已知值 → resolve_offset_chain。

度量：墙钟时间、人工纠错次数、AI 选错工具/参数的次数、超时工具
（`toolCallTimeoutMs=600000`）触发次数。判定：全流程 ≤ 2 次人工干预。

### T3 dump 管线 + Ghidra 全链（v3 新路径）

`dump_module`（设备端落盘）→ `decompile_start/decompile_status`
（Ghidra headless，/opt/ghidra + JDK 21）。关注：拉取产物 sha256 与
manifest 一致、Ghidra 符号恢复数量与 v2 同靶记录可比（v2：反编译 5009
函数/47s 量级）、`.c` 产物可读。另测一次**显式中断后续传**：dump_pull
中途断开 serve→重启→再 dump，确认从断点 offset 续传且最终 sha256 一致。

### T4 写链安全（纪律靶）

仅对 `tanyao_target`：expect-old 拦截负例 → 正确写入 → verify → 故意
verify 失败 → rollback。确认：门禁默认关闭时 `write_bytes` 拒绝；
任何情况下 surfaceflinger/libc 等活体目标零改动（回归已内置该断言，
实战再肉眼复核一次）。

### T5 apk_info 零镜像 + pull 链

对带 split APK 的游戏：`apk_info(pid)` → 返回 package/version/permissions/
split_apks，全程不产生整包传输（用 §4 的字节计数证明）；字段与
`aapt dump badging`（如有）或应用设置页交叉核对。再显式 `pull_apk` 一次
（已知是百 MB 级），记录耗时——验证"显式批量"路径可用但确实昂贵。

### T6 稳定性与资源

1. **边游戏边扫描**：游戏前台运行时对 3GB 级 anon 区发起 `scan_start`，
   观察游戏帧率（录屏或肉眼）+ `top` 里 agent 的 CPU 占比（SCHED_IDLE/nice
   生效应表现为可被游戏抢占）。
2. **30 分钟长会话**：watch 循环 + 周期 get_status，30/30 采样
   `connected:true`（对照 v2 基线）。
3. **多目标切换**：tanyao_target ↔ nativetest ↔ systemui 轮切 10 轮，
   无 EBUSY、无 handle 泄漏（切换后对旧 pid 的读应报错而非串数据）。

## 4. 带宽实测方法（本轮新增硬指标）

对三个头条操作分别采样网口字节增量（操作前后各读一次，取差值）：

```bash
IF=$(ip route get 192.168.1.34 | grep -o 'dev [a-z0-9]*' | awk '{print $2}')
grep -E "$IF" /proc/net/dev    # 记录 recv bytes
# ……执行操作……
grep -E "$IF" /proc/net/dev    # 再记，差值即过网字节
```

| 操作 | 过网字节目标 |
|---|---|
| 3.21GB anon 首扫（T6-1 同款） | ≤ 数 MB（仅命中与进度） |
| symbol_list libc（1471 符号） | ≤ 1MB |
| apk_info（游戏） | ≤ 100KB（零镜像） |
| dump libc 1.1MB | 压缩后 ≤ 0.7MB，且仅显式发起 |

## 5. 纪律（违反即测试无效）

1. 写操作**只允许**打 `tanyao_target`；任何情况不改活体目标进程。
2. 不绕过 MCP 直接操作内核/agent（测的就是整链）。
3. 发现缺陷：登记 `/home/tanjin/phone/WORKSPACE.md` §7 台账（编号沿用
   P1/P2/P3 分级）→ 交对应工程师修复 → **复跑三层回归**（单测/interop/
   mcp_regression）+ 复现用例通过才算闭环。
4. 对照基线以 `TANYAO_FIELD_TEST_REPORT.md`（v2）和
   `TanyaoKernel/docs/VALIDATION_LOG.md` §0V3 为准，不凭印象。

## 6. 已知事项（先声明，不算缺陷）

- `disassemble` 走主机 capstone 路径（读字节过网，全 ISA 覆盖不受影响）；
  设备端 capstone 是可选增强（bit8 未声明）。
- agent hello `version` 仍为 `"1.1.0"`（协议已 v1.2 定版；host 按能力位
  分派不看版本号，纯记账项）。
- 设备端扫描单 job 槽、`scan_start` 同 pid 自动 cancel 旧 job——属设计。
- 冷页换入成本仍存在（v2 实测 350s 慢段的根因），但走 UFS 速率而非网络
  速率；大扫描 elapsed 里若出现无进度段，先查 page-in 再报缺陷。
- vvar 已从 TARGET_MAPS 消失（内核 v3）；`[vdso]` 仍上报但可读——均为
  VALIDATION_LOG §0V3 实证过的设计行为。

## 7. 报告模板（回填 `TANYAO_FIELD_TEST_REPORT_V3.md`）

```markdown
# Tanyao v3 全功能实战测试报告（日期）
> 测试对象/设备/靶子 pid 快照
## 1. 结论总览
| # | 测试项 | 结论 | 关键证据 |
## 2. 带宽实测
| 操作 | v2 基线 | v3 实测 | 过网字节 |
## 3. 缺陷清单（P1/P2/P3 × 复现步骤 × 根因假设）
## 4. AI 会话记录（T2：时间线 + 干预点）
## 5. 与 v2 报告的差异与回归对照
```

基线对照速查：3.21GB 首扫 v2=480s（过网，P1 修复后 506s）→ v3 已实测
2.747s；symbol_list libc v2=33s → 回归秒级；read_batch 7.91×（v3 未改此
路径，应持平）；30min 长会话 v2=30/30。
