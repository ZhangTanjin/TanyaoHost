# Tanyao 全功能实战测试报告（2026-09-02）

> **修复复验闭环（同日）**：P1/P2-1/P2-2/P3 全部真机复验 PASS——
> P1 同目标 3.21GB/547 段扫描 `done`，5537 hits，skipped_ranges=1/skipped_bytes=8192（恰为 [vvar] 段），506s，账目精确（done+skipped=total）；
> P2-1 `[good,bad,good]→[data,read_failed,data]`；P2-2 dump v2 `readelf -d` rc=0 + 7 个 DT_NEEDED + PT_DYNAMIC 段在位；
> P3 scan_value 内联 results ✓ / symbol_list 仅剩 2 个真实符号（92 个 UND 消失）✓ / scan_clear 保留范围 ✓。
> 复验脚本沉淀：`tanyao-host/tests/verify_fixes.py`。写入门禁已按批准重新开启并在新代码下回归通过。
> 内核侧唯一遗留建议维持：排除 PFNMAP VMA（届时 skipped 概念整体消失）。

> 测试对象：tanyao 链路（MCP 22 工具 → host serve → 设备 agent gen=9 → tanyaokernel）
> 设备：PLC110（3B6F6CE8GCL0BBMH），Android 16，内核 6.6.118-android15-8
> 真实目标：`icu.nullptr.nativetest`（pid 6545，前台 60fps NativeActivity，自带 root 检测逻辑）
> 靶进程：`/data/local/tmp/tanyao_target`（pid 15277，root 自有进程，三级指针链布局）

---

## 1. 结论总览

| # | 测试项 | 结论 | 关键证据 |
|---|---|---|---|
| 1 | 真实应用全流程（侦察→dump→符号→字节比对） | ✅ PASS | 内存代码与磁盘文件逐位一致（48B×3 窗口 + 2MB 全段比对） |
| 2 | typed 扫描收敛链（u32/f32+epsilon） | ✅ PASS | gold/px 双链各 3 轮 increased 收敛到唯一正确地址 |
| 3 | read_batch 效率 | ✅ PASS | **7.91×**（8 span，10.23ms vs 80.95ms/轮）；附带发现批次污染语义（见 P2） |
| 4 | watch / changes_only | ✅ PASS | +7 递增序列捕获、无变化路径只回 index 0 |
| 5 | 写入完整安全链 + rollback 失败路径 | ✅ PASS | expect_old 拦截无副作用、EFAULT 拒绝、写后 verified、程序存活继续 tick |
| 6 | 3 级真实指针链 | ✅ PASS | link→p→stats→kda = 25.0，每级 raw/normalized 正确 |
| 7 | 30 分钟长会话稳定性 | ✅ PASS | 30/30 采样 connected=true gen=9，断连 0 次（见 §6） |
| 8 | dump 产物 RVA 对准度 | ⚠️ 有条件 PASS | r-xp 段 RVA=文件偏移精确；**PT_DYNAMIC 截断**（见 P2-2） |
| 附 | 全匿名区大扫描（真实应用 3.2GB） | ❌ **P1 bug** | 首扫 99.7% 处 EFAULT 全损；复扫结论见 §5 |

## 2. 域矩阵（写入能力，实测更新）

| 写入方向 | 结果 | 证据 |
|---|---|---|
| root agent → 自有 root 进程（15277） | ✅ 正常 | gold 写入 + verified + 程序存活 |
| root agent → untrusted_app（6545） | ✅ **正常（新发现）** | 32B 写入 @0x7bf0bff000 verified=true |
| root agent → system 进程 | ❌ EFAULT | 交接单已载，本轮未重复踩 |

交接单的"写入务必选对目标"可以放宽为：**除 system 域外均可写**；untrusted_app 写入可用。

## 3. 问题清单（按严重度）

### P1：全匿名区大扫描 fail-fast，99.7% 处全损（根因已定位）
- 现象：6545 anon preset（547 段 3,210,780,672 B）异步扫描，两次独立运行均在
  **完全相同的累计偏移 3,202,273,280**（99.7%）失败：
  `AgentError: backend_error (errno=-14): mem_read failed at offset 0 (0/8192 bytes)`，
  8.5 分钟 / 3.2GB 进度全部丢弃，结果不交付。
- **根因（已实证）**：内核 target_maps 把 `[vvar]`（0x7e053ba000-0x7e053bc000，4KB，
  VM_PFNMAP 特殊映射）当作可读匿名段纳入扫描范围。8KB 块读 vvar 首页 → GUP 不支持
  PFNMAP → EFAULT → 引擎 fail-fast。位置在范围列表尾部 ≈ 99.7% 处，与确定性失败偏移吻合。
  对照实验：64MiB 修正后失败偏移精确落在 [vvar] 段内偏移 0x0，直接探针复现 EFAULT。
- 附带澄清：此前 124 个 `[anon:.bss]` 段起点探针失败为伪影（探针未按段截断读 8192 越过
  4KB 段尾撞未映射空洞；引擎本身 `take=min(chunk, end-pos)` 按段截断正确）。
- **建议**：① 内核 target_maps 排除 VM_PFNMAP|VM_IO VMA（vvar/vdso）；
  ② host 引擎 per-chunk EFAULT 容错（skip + skipped 计数，不 fail-fast，保留已完成命中）；
  ③ 应急 workaround：`scan_set_range` 手动指定范围可绕开尾部特殊页。

### P2-1：read_batch 坏 span 污染同批次后续所有 span
- 现象：批次中任意 span EFAULT 后，**其后的所有合法 span 也返回 `"error": "read_failed"`**，
  且调用级 `ok:true`——坏 span 之前的正常。坏 span 放尾部则前面全部正常。
- 复现：`spans=[good, bad, good]` → `[ok, failed, failed]`；`spans=[good, good, bad]` → `[ok, ok, failed]`
- 影响：自动化脚本易把污染数据当真。建议：逐 span 独立错误隔离（mem_readv 本身按 iov 返回）。

### P2-2：dump_module 只写 r-xp 映射，PT_DYNAMIC 截断
- 现象：libnullptr.so dump 2,072,576 B 仅含 r-xp 段（manifest 1 mapping）；原文件 PT_DYNAMIC
  位于 rw 段（file offset 0x1f9f30），dump 文件在 0x1FA120 处截断，
  `readelf -d` 报 "the dynamic segment offset + size exceeds the size of the file"。
- 影响：Ghidra/IDA 导入后**无 dynsym/imports**，只能纯反汇编（反汇编本身可用，见 §4）。
- 建议：把 file-backed 的 r--p/rw-p 映射一并写入（原始文件内容即可），恢复完整 ELF 语义。

### P3（cosmetic/文档）
1. `scan_value` 响应不含内联 `results`（`scan_hex` 有）——不一致。
2. `symbol_list` 列出全部 94 个 dynsym 含 92 个 UND 导入符号，st_value=0 全部显示为模块基址——建议过滤 UND。
3. `scan_clear` 连同范围配置一起清空：clear 后 scan_next 报 "no scan ranges set"，重扫必须重设范围——交接单未载。
4. 边界行为本身精确：0x37fe6ff8 EFAULT / 0x37fe7000 OK（heap 起点分毫不差）——fault 语义可信。

## 4. 反汇编 / RVA 验证（测试 8 细节）

- `symbol_find("Java_icu_nullptr_nativetest_NTRZygotePreload_check")` = 0x7bf0b31658，
  = load_bias(0x7bf0a00000) + st_value(0x131658)，size=1012 与 readelf 一致。
- 内存 48B @0x7bf0b31658 与文件 `fd7bbfa9ff830bd1...` 逐位一致；
  ANativeActivity_onCreate @0x7bf0bed2f0 同样一致。
- dump 前 0x1F9F30 字节与原文件 cmp 全等（代码段无运行时修补）。
- 反汇编窗口（objdump + 手册比对）：`stp x29,x30,[sp,#-16]!; sub sp,#0x2e0; mov x8,#0x3b9aca00...`
  与内存/文件三方一致。
- **结论：r-xp 段的 RVA 对准度完全可信，可直接 Ghidra flat 加载 base=0；恢复 imports 需先修 P2-2。**

## 5. 全匿名区大扫描（已闭环）

- 首扫 job `b77b7b1b9aa1`：失败 @99.7%（偏移 3202273280）。
- 纯净复扫 job `8c46d77f9bde`（零交叉操作）：失败 @**同一偏移** 3202273280 —— 确定性证明。
- 根因定位：`[vvar]` VM_PFNMAP 特殊页被含入 anon 范围（见 P1，含修正偏移与探针证据）。
- 稳定速率 ~6.2 MB/s（WiFi 链路）；单次全扫耗时 ~8.4 分钟。

## 6. 长会话稳定性（测试 7）

- 采样器：60s 间隔 get_status，30 分钟窗口。
- 结果：30/30 `connected=true gen=9`，断连 0，generation 不变。
- 期间负载：serve 重启一次（门禁开启，MCP 自动重连 ~2s 恢复）、3.2GB 大扫描、
  60 次跨 pid 交替读（0 错误，108.9 ms/op，host 单活动 target 切换全透明）、
  写入链、指针链、watch——全部无残留故障。

## 7. 性能速查

| 操作 | 实测 |
|---|---|
| 单次 8B 读（IPC→agent→内核→WiFi 往返） | ~10 ms |
| read_batch 8 span（一次往返） | 10.23 ms/轮（7.91×） |
| HTTP IPC 裸开销 | 0.34 ms |
| 模块内扫描（2MB） | 0.47 s（6.2 MB/s 同量级） |
| 交替 pid 操作 | 108.9 ms/op，0 错误 |

## 8. 靶进程资产（复用）

- 源码：`tanyao-host/tests/tanyao_target.c`（hp 衰减/gold+7/px 漂移/kda 恒定/三级链 link[3]）
- 设备：`/data/local/tmp/tanyao_target`（aarch64 静态，root 启动）
- 基准脚本：`tanyao-host/tests/bench_read_batch.py`

## 9. 交接单勘误建议

1. 写入域矩阵补充：untrusted_app 可写。
2. read_batch 注意事项补：批次污染语义 + 自动化必须断言每个 span 无 "error" 字段。
3. 扫描注意补：scan_clear 连带清范围；大扫描中途结果不保留（待 P1 定位后更新）。
4. dump 用法补：当前 dump 仅含可执行段，Ghidra 无 imports；反汇编可用。
