# Tanyao 全功能实战测试 — 逆向工程师交接单

> 交接时间：2026-09-02 | 链路状态已验证：MCP 回归 32/32，单测 41/41
> 目标设备：PLC110（3B6F6CE8GCL0BBMH），Android 16，内核 6.6.118-android15-8，tanyaokernel Live

---

## 1. 环境速查（开工前 3 分钟）

| 组件 | 状态 | 操作 |
|---|---|---|
| 设备 agent | 运行中 `192.168.1.34:52730`（gen=9） | 掉线重启：`adb shell "su -M -c '/data/local/tmp/tanyao-agent --bind 192.168.1.34 --port 52730 --token-file /data/local/tmp/.tanyao-token'"` |
| 主机核心 | `tanyao.serve` 常驻，IPC `127.0.0.1:28101` | 重启：`/home/tanjin/phone/tanyao-host/scripts/start-serve.sh` |
| MCP | 已挂 DeepSeek Harness（`mcp__tanyao__*`，29 工具） | 新会话生效；重启 serve 后 MCP 子进程自动重连 |
| 健康检查 | `curl -s -X POST http://127.0.0.1:28101/ -H "Content-Type: application/json" -d '{"method":"get_status","params":{}}'` | `connected:true` 即链路通 |

日志：`/tmp/tanyao-serve.log`（主机侧）。

## 2. 工具面（29 个，AI 会话内以 `mcp__tanyao__<名>` 调用）

- **侦察**：`get_status` `find_process` `list_processes` `list_modules` `resolve_module` `address_resolve`
- **内存**：`read_memory`（原始/typed 数组）`write_bytes` `read_batch`
- **扫描**：`scan_set_default_ranges`（preset: anon/stack/module:X/all_readable）`scan_value` `scan_hex` `scan_start`+`scan_status`（异步）`scan_next` `scan_results` `scan_cancel` `scan_clear`
- **分析**：`resolve_offset_chain`（PAC 剥离）`symbol_list` `symbol_find` `dump_module`（ELF 文件布局重建+manifest，PT_DYNAMIC 完整可解析）`watch`
- **原生分析**（2026-09-02 新增）：`disassemble`（**capstone 主引擎**全 ISA 覆盖，无 capstone 时自动降级内置子集解码器）`strings`（模块分块容错 / 任意窗口，正则过滤）`pull_apk`（按 pid 拉取 base.apk 到主机）`apk_info`（AXML 解析：包名/版本/Activity/入口/权限）
- **反编译**（Ghidra headless，2026-09-02 新增）：`decompile_start`（dump→导入→自动分析→全函数 C 反编译，异步 job）+ `decompile_status`（状态/函数清单/.c 文件落盘 out_dir）

**环境依赖**：capstone（`apt install python3-capstone`）；Ghidra 12.1.3（`/opt/ghidra`，含 sha256 校验下载）+ **JDK 21**（`apt install openjdk-21-jdk-headless`——Ghidra 必须 JDK，纯 JRE 会报 "Unable to prompt user for JDK path"）。

## 3. 实战注意事项（踩过的坑，按重要性排序）

1. **写入三重门禁**：`TANYAO_ALLOW_WRITE=1`（serve 环境）+ host 强制 expect-old→write→verify + 工具 `expect_old_hex` 参数。当前门禁**关闭**。实测写 system_server 等系统进程会 EFAULT（SELinux 域隔离），写自有 root 进程正常——写入目标请选自有进程或已确认可写的进程。
2. **单活动 target**：内核一会话只允许一个打开的 target。host 已自动处理（切 pid 前先释放），但**多工具并发交叉操作两个 pid 时**如遇 EBUSY(-16)，重试即可（host 有 close-all+重试兜底）。
3. **大进程扫描**：全匿名区首扫是分钟级（WiFi 带宽约束），用 `scan_set_default_ranges(preset="module:XXX")` 或 `scan_set_range` 限定范围；>64MB 自动转异步，`scan_start` → `scan_status` 轮询。
4. **符号解析 33s 量级**（libc 1483 符号，WiFi 逐条读）：建议先 `dump_module` 拉回主机本地解析（后续版本优化），或直接用 `symbol_find`（带 module 参数可省全模块搜索）。
5. **scan_next 前必须有首扫**；`scan_clear` 后 next 会报错（属正常）。
6. **PID 复用防护**：内核 start_cookie 自动校验，目标进程重启后第一次访问会报错，重试自动重开。

## 4. 测试建议清单（供参考，自由发挥）

- [ ] 真实游戏/应用进程全流程：找进程→模块→dump→Ghidra→符号回查→scan 定位内存值→指针链
- [ ] typed 扫描实战：f32 血量/坐标 + epsilon、u32 货币、增量收敛链
- [ ] `read_batch` 一次拉对象多字段 vs 逐字段读的效率对比
- [ ] `watch`/`changes_only` 观察内存变化定位写入时机
- [ ] `write_bytes` 门禁开启后的完整安全链（expect-old 校验 + 回读 + 故意失败的 rollback 路径）
- [ ] `resolve_offset_chain` 真实多级指针（3+ 级）+ PAC 场景
- [ ] 长会话稳定性：连续操作 30 分钟，观察 gen/断连/恢复
- [ ] dump 产物在 Ghidra/IDA 的可用性（manifest 的 RVA 字段对准度）

## 5. 反馈通道

问题按此格式反馈（会直接进入修复流程）：

```
工具名：mcp__tanyao__XXX
参数：{...}
期望：...
实际：...（完整错误文本）
```

已知边界（不算 bug）：反汇编不在工具面（dump 后用主机 Ghidra/capstone）；无注入/Hook（设计排除）；无硬件断点（P2 排期，内核能力待扩展）。

---

## 6. 2026-09-02 实战测试补充结论（新一轮实测后追加）

完整报告：`/home/tanjin/guihua/TANYAO_FIELD_TEST_REPORT.md`。8 项测试 7 项 PASS，1 项定位到根因。

### 对第 3 节注意事项的修正与补充

1. **写入域矩阵更新**：root agent 对 **untrusted_app 也可写**（实测 32B 写入 verified）。"选对目标"放宽为：只有 system 域 EFAULT。
2. **read_batch 批次污染**（新坑）：批次中一个坏 span 后，**其后的所有 span 静默 `read_failed`**（调用级仍 ok:true，坏 span 之前的正常）。自动化必须逐 span 断言无 "error" 字段。
3. **大扫描纪律（根因已定位）**：全匿名区扫描必死——`[vvar]`（VM_PFNMAP 特殊页）被 anon preset 包含，8KB 块读它必 EFAULT，引擎 fail-fast 丢弃全部进度（实测 3.2GB/99.7% 两次确定性复现，~8.4 分钟/次）。**修复前用 `scan_set_range` 手动范围绕开**；引擎侧修复：排除 PFNMAP + per-chunk 容错。
4. **scan_clear 连带清空范围配置**：clear 后重扫必须重新 set_ranges/set_default_ranges。
5. dump 用法补：当前 dump 仅含可执行段（PT_DYNAMIC 截断），Ghidra 导入无 imports/dynsym，只能纯反汇编；r-xp 段 RVA 对准度已字节级验证可信。恢复符号需原文件或等 dump 修复（P2-2）。
6. 性能基准：单次 8B 读 ~10ms；read_batch(8 span) 10.23ms/轮 = **7.91×**；交替 pid 操作 108.9ms/op 零错误（host 切换全透明）；全匿名区 ~6.2MB/s。
7. 长会话：30 分钟 30/30 采样零断连 gen 恒定（期间含 serve 重启一次，MCP 自动重连 ~2s）。

### 复测资产

- 靶进程：`tanyao-host/tests/tanyao_target.c`（hp 衰减/gold+7/px 漂移/恒定 kda/三级链），设备 `/data/local/tmp/tanyao_target`（root 启动，新日志用 `tt2.log` 避免旧日志权限坑）
- 基准：`tanyao-host/tests/bench_read_batch.py`
- 产物：`/home/tanjin/guihua/dumps/`（libnullptr 原始+dump+manifest、nativetest-base.apk、nativetest-pulled.apk）

### 工具链扩展（2026-09-02 同日，22→28 工具，含外接集成修正）

- **架构修正**（工程师复盘）：反汇编曾走自写子集解码器，实测真机覆盖率 94% 后纠正为**外接开源工具路线**——capstone 为主引擎（100% 覆盖），自写解码器降级为无 capstone 时的 fallback；Ghidra headless 反编译集成。
- **新增**：`disassemble`（capstone）/ `strings` / `pull_apk` / `apk_info` / `decompile_start` / `decompile_status`（零第三方硬依赖原则保持：capstone 缺席自动降级，pyproject 可选依赖模式与 pyelftools 先例一致）。
- **真机 e2e 闭环**：`Java_..._check` 函数（1012 字节）capstone 逐条解码与 objdump 一致；Ghidra 47s 反编译 5009 函数，导出符号 `Java_..._check`/`ANativeActivity_onCreate` 以真名产出 C 伪代码。
- **重要工具链发现（dump 工具 P2-2 后续）**：内存 dump 的 ELF 头携带悬空 e_shoff（指向未捕获的磁盘节表），Ghidra 导入器因此**静默跳过 dynsym 符号加载**（31758 符号无一命名）。修复：`dump_module` 输出时清零 e_shoff/e_shentsize/e_shnum/e_shstrndx（manifest `sanitized` 字段记录），清零后 Ghidra 恢复全部导出符号命名。
- 验证状态：单测 61/61；MCP 回归 35/35（28 工具）；环境：capstone 4.0.2（apt）、Ghidra 12.1.3（/opt/ghidra，sha256 校验）、JDK 21.0.12。

架构资料：`/home/tanjin/phone/tanyao-host/tanyao-ai-re-architecture.md`（架构+全部实施记录）、`/home/tanjin/phone/tanyao-host/docs/PROTOCOL.md`（协议唯一真相源）。
