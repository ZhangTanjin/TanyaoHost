# Tanyao v3 真实目标逆向落地测试 — LOLM（英雄联盟手游）（2026-09-05）

> 前置：`TANYAO_FIELD_TEST_REPORT_V3.md`（同日，T1–T6 全项）。本轮为该报告的
> 真实目标延伸，目标 `com.tencent.lolm` v7.2.0.2458（7245864），pid 16821，
> 前台 `.lgame`，RSS 1.3GB。全程**只读侦察**（写纪律不变：写操作仅限
> tanyao_target，本轮对 lolm 零写入）。测试会话未挂载 MCP 工具面，经 serve
> IPC 下发（与 v3 报告同口径）。
> **执行环境**：设备端 agent 为 R2 构建（hello 实测 `caps=0x2fb` 含 bit9、
> `build=agent-v1.2.0-1-g95cddf8-dirty`、gen 30）；备案中"R2 clean 重建"在
> 本会话前未执行，产物归因以 build 字段为准；`绘梨衣内部*.sh` 看门狗清理项
> 仍待运维处理（非本会话范围）。

## 1. 结论总览

| # | 环节 | 结论 | 关键证据 |
|---|---|---|---|
| 1 | 进程发现 | ✅（带观察） | `find_process("com.tencent.lolm")` 命中；短名 "lolm" 不匹配（观察 O4：find_process 为子串/全名匹配，短包名尾部段不命中）|
| 2 | apk_info 零镜像 | ✅ | 0.05s，过网 **5,910B**；package/version/min,target sdk/entry/54 权限/45 activity/无 split 全字段 |
| 3 | 模块清单 | ✅ | 1217 模块，`maps_source:"proc_maps"`（>4096 映射自动回退）；识别 **libil2cpp.so（198MB）/libunity.so（26MB）**（Unity IL2CPP 确认）与反作弊 **libtersafe.so/libtprt.so** |
| 4 | 198MB 巨库 dump | ✅ | 207,822,848B 产物 ~90s 完成；**过网仅 65.2MB（3.2× 压缩）**；6 个 PT_LOAD 与原文件**逐项一致**（含 0x4000/0x8000/0x260000… 多段异构 bias 的自定义布局）；仅缺文件尾 1,184B 节表（设计脱敏+未映射尾） |
| 5 | 符号面 | ⚠️ D8 | 标准布局模块正常（tersafe 72 / gcloud 1984 / FEProj 8040 符号）；**libil2cpp/libunity 失败**（"no dynamic segment in module"/not_found）——见 D8，已用 dump+映射表法现场绕行 |
| 6 | 离线符号→活体定位 | ✅ | 从 dump/原文件取 `il2cpp_init`（st_value 0x3eba158，252 个 il2cpp_* 导出之一）→ 按映射表平移到运行时 `0x70070ef158` → **活体 44B 与文件逐位一致** → capstone 反汇编出标准序言+调用序列 |
| 7 | 扫描收敛 | ✅ | `scan_hex("696c326370705f69")`（"il2cpp_i"）模块级扫描：**28 命中**（12 个在 r-x 文件映射 = strtab 正主，16 个在堆/bss 副本）；抽验活体字节 `il2cpp_init\0` 正确 |
| 8 | 目标加固侦察 | ✅（结论） | 9.4GB 全可读空间扫 IL2CPP metadata magic `0xFAB11BAF`：**0 命中**——CN 版元数据加密/魔数改写，不以内明文形态驻留内存（预期保护行为，非工具缺陷） |
| 9 | 反作弊库 dump | ✅ | libtersafe.so 6,287,360B dump，`readelf -d` 4 个 NEEDED，结构有效（只读操作） |
| 10 | 稳定性 | ✅ | 全程（~20min 重负载：198MB dump+拉取、5.3GB+9.4GB 两轮大扫描、跨模块读写）无断连、无 EBUSY、agent 存活 |

## 2. 新缺陷与观察（已登记 WORKSPACE.md §7；编号沿用台账，D8/O3/O4 为本轮新增）

### D8（P2）：符号引擎在"自定义多 bias 映射"模块上失败（libil2cpp/libunity）
- 现象：`symbol_list("libunity.so")` → `"no dynamic segment in module"`；
  `symbol_find("il2cpp_init")`（全局）→ not_found。而文件/dump 的 dynsym 完整
  （2743 项、252 个 il2cpp_* 导出），内存 dynsym 内容与文件逐位一致。
  **R2 构建（caps 0x2fb）上复核仍复现**；同进程标准布局模块全部正常
  （libtersafe 72 / libgcloud 1984 / libFEProj 8040）——缺陷边界精确锁定在
  自定义映射布局的巨型库，且恰为 IL2CPP 游戏最高价值目标。
- 根因（已实证）：这两库由自定义 loader 按**非 PT_LOAD 线性**的方式分段映射
  （manifest：file_off 0x0/0x56f4000/0xbb80000/0xbefe000/0xc61c000/0xc620000 对应
  六段 vaddr，bias 各异 0x0/0x4000/0x8000/0x260000/0x264000/0x268000）。符号引擎
  按 ELF phdr 做 vaddr+bias 平移会把 DT_SYMTAB（vaddr 0xc889c20）算到未映射地址；
  **映射表法**（file_off→所在 mapping→runtime）实测精确命中
  （0xc621c20 → 0x700fabec20，与文件字节 MATCH）。
- 修复方向：设备端符号引擎改用映射表（file_offset）平移——dump 管线
  （dump_builder）已用同款逻辑且被本轮实证正确，可作为实现参照。
- Workaround（本轮验证）：dump → 离线读 dynsym → 映射表平移 → 活体 read_memory
  校验。对 IL2CPP 游戏的完整工作流可用。

### O3（P3/易用性）：已完成扫描 job 的 id 快速失效
`scan_status(job_id)` 在 job 完成后很快返回 `"unknown (or expired)"`（detail
还存在格式小瑕疵 `job: 8b47…`），而 `scan_results` 仍可取回结果。轮询方需要
改为"完成即取结果"或延长完成后 job 的可查询窗口。

### O4（P3/易用性）：`find_process("lolm")` 不命中（全名可命中）
包名尾段短名不参与匹配；对 AI 会话是一次选参摩擦。建议 process_find 同样匹配
包名末段。

### 目标侧结论（非缺陷）
- LOLM CN 的 IL2CPP 元数据不以明文 magic 驻留（anon 5.28GB + 全可读 9.4GB 两轮
  扫描均 0 命中 FAB11BAF）；审计面留在 libtersafe/libtprt 与加密 metadata 的
  运行期解密路径，超出本轮工具链验证范围。
- DT_NEEDED 显示 **libil2cpp.so 直接依赖 libtprt.so**——反作弊与引擎库静态织入，
  单独卸载/绕过不可行（只读确认）。

## 3. 与 v3 报告基线的衔接

| 项 | v3 报告基线（nativetest/themestore/sgame） | LOLM 实测 |
|---|---|---|
| apk_info 过网 | 19,391B | **5,910B**（更瘦，无 split）|
| 大库 dump | libnullptr 2MB/0.72s | **198MB/~90s，压缩 3.2×（65.2MB 过网）** |
| proc_maps 回退 | systemui 1165 模块 | 1217 模块，同路径 |
| 扫描引擎双模式 | 32GB/s PTE 模式 + 242MB/s 驻留模式 | 9.4GB 全可读 ~208MB/s 混合模式，账目 done==total 保持 |
| 符号引擎 | libc 1471/libnullptr 2（标准布局） | 标准布局正常；**自定义映射布局失败（D8，新发现）** |
| 断点续传/D1 workaround | module: preset | 本轮 module: preset 再次稳定工作 |

## 4. 产物存档（/tmp/tanyao_v3/lolm/）
- `libil2cpp_dump.so`（207,822,848B）+ manifest；`libil2cpp_orig.so`（对账真值）
- `libtersafe_dump.so`（6,287,360B）+ manifest
- `il2cpp_init_rt.txt`（运行时地址 0x70070ef158）
- socket 级带宽采样 ss_before/mid/after

---
测试人：ZCode 实战测试代理（TESTER_HANDOFF_V3 延伸任务：真实目标 lolm）
纪律复核：对 lolm 全程零写入；写门禁保持默认关闭。
