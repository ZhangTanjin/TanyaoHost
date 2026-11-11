# Tanyao lolm 适配二轮审查报告（2026-09-05，R4 输入）

> 审查对象：v1.2.1 定版后链路（agent build `agent-v1.2.0-5-g6e2b4e6`，caps
> `0x2fb`）。目标 `com.tencent.lolm`（pid 5555 会话）+ 自有靶 tanyao_target。
> 纪律：全程只读零写入；三仓库工作树保持干净。

## 1. 基线（全绿）

interop 20/20；mcp_regression 44/44；单测 127/127。真实适配验证：
libil2cpp 2461 / libunity 438 符号；`il2cpp_init` @ `0x700991c158`（新会话
新地址）44B 内存读取 + capstone 反汇编；apk_info（7.2.0.2458 /
7245864 / `.lgame`）；dump 207,822,848B / 8 映射 / PT_DYNAMIC 可解析 /
sha256 对账；tanyao_target agent-scan 命中坐标字段、watch 观察、
resolve_offset_chain（hp=77 / kda=25.0）。

## 2. 缺陷

### D9（P2，主机端）多 bias 模块的 rva/load_bias/BSS 元数据错误

- `symbol_find("il2cpp_init")` 返回真实地址 `0x700991c158`（正确文件偏移
  `0x3eba158`），但 `address_resolve` / `disassemble` 对该地址给出
  `rva=0x1888b9158`（> dump 产物 207,822,848B）——单 bias 减法产物。
- `resolve_module("libil2cpp.so")` 给出的 BSS 终点 `0x6e8d8e8c30` 经
  `address_resolve` 归属到 **libunity.so**。
- 根因（代码级）：`analysis.py:163 resolve_module` / `:189
  address_resolve` / `:759 disassemble` 仍用单 bias 平移；设备端符号与
  dump 已用映射表法（故符号地址正确），错误集中在主机展示/标注层。
- 影响：AI 拿到错误 RVA 会把 Ghidra/手工分析引向错误偏移。

### D10（P2，主机端）大模块 strings 无异步 MCP 入口

`strings(pid, module="libil2cpp.so")` → `bad_request: sync range exceeds
threshold`（设备端 >256MiB 拒绝同步，符合协议），但 MCP schema 无
`async` 参数（mcp_server.py:283）、facade 只走同步（analysis.py:816）。
现只能手工切 ≤16MiB 窗口或绕过 MCP。设备端 cmd 62 本就支持
`async:true` job 路径。

### D11（P3，协议裁定 + 双端）symbol bind 字段悬空

工具描述承诺 `bind`，实测恒空：analysis.py:653/667 写死；设备端
SymbolRecord 未保存 binding（symbol_layout.hpp:39）。影响 GLOBAL/WEAK/
导入/本地 区分的逆向流程。

### D12（P3，运维/主机端）ADB forward 丢失时 serve 状态失真

设备在线、agent 进程在，但 adb forward 52730 消失 → MCP 首调
`agent_unavailable: connection refused`；serve 进程活着且不自愈。手工
`adb forward tcp:52730 tcp:52730` 后立即恢复。

## 3. 目标加固结论（lolm）

延续一轮结论：全可读空间无明文 IL2CPP metadata；本轮进一步确认
apk_info/符号/dump/反汇编/指针链在 TP 反作弊活体上稳定可用。

## 4. 修复优先级建议（tester 提出，分诊采纳）

1. 抽取 dump/symbol 已用的映射表地址转换为公共 helper，统一修复
   resolve_module / address_resolve / disassemble。
2. 多 bias 断言：`rva < dump_size`；BSS 地址不得落入其他模块。
3. strings 增加 `async` + job 轮询（协议已支持，补 MCP/facade）。
4. `bind` 协议决策二选一（架构师裁定：JSON 增列，见分诊）。
5. start-serve.sh 增加 ADB forward 检查/自动建立 + 端到端健康检查。
6. 主机单测加入 lolm 六段 mapping fixture。
