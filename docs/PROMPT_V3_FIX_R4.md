# 主机端工程师修复任务提示词：R4——D9 / D10 / D12 + D11 host 半

> 把本文整段交给负责 tanyao-host 仓库的工程师（人或 AI 编码代理）即可。
> 背景：lolm 适配二轮审查（`TANYAO_FIELD_TEST_REPORT_LOLM_R2.md`，已入库）
> 发现主机侧地址元数据层缺陷。分诊与修复设计定稿：
> `/home/tanjin/phone/WORKSPACE.md` §7「架构师分诊 R3」之后的 R4 段。
> 协议依据：`docs/PROTOCOL_V1.2.md` §3.1 v1.2.2 附录（binds 列）。

## 任务 1：D9（P2）地址元数据统一到映射表平移

`analysis.py` 三处单 bias 残留（:163 resolve_module / :189
address_resolve / :759 disassemble）统一改造：

1. 抽公共 helper：`runtime→(module, file_offset)` 与
   `file_offset→runtime`，语义与 dump_builder/symbol 引擎同源（逐映射
   `runtime = m.start + (F − m.file_offset)`）。
2. `resolve_module`：模块边界以**映射路径包含优先**（地址落在谁的映射
   归谁），BSS/算术边界不得越过本模块映射范围（实测病态：BSS 终点
   `0x6e8d8e8c30` 被归到 libunity.so）。
3. `address_resolve`：对返回地址同时给出 `file_offset` 与按映射表计算的
   `rva`，并附 `module`。
4. `disassemble`：RVA 标注同 helper。
5. **断言（验收硬指标）**：lolm libil2cpp `il2cpp_init`（symbol_find 实测
   地址）→ `rva == 0x3eba158` 且 < dump size；BSS 地址不再归 libunity。
6. 单测：lolm 六段 mapping fixture（bias
   0x0/0x4000/0x8000/0x260000/0x264000/0x268000，非 PT_LOAD 线性）覆盖
   上述全部路径。

## 任务 2：D10（P2）strings 异步入口

- MCP `strings` schema 增加 `"async": {"type": "boolean"}`（默认 false）；
  facade async=true 时走 cmd 62 `async:true`，返回 `job_id`，轮询复用
  scan_status/scan_results（kind=strings，结果元素 `{address,value}`）。
- 同步超阈值（设备端 >256MiB 拒绝）的 bad_request 保持原样，detail 追加
  "use async=true" 指引。**不做静默自动转异步**（显式优于惊喜）。
- 回归：async strings job 全轮询链（mock + 真机各一）。

## 任务 3：D11 host 半（binds 透传）

- `symbol_batch` json 解码新增 `binds` 列（缺失容忍——旧 agent 无该列时
  置空串，不报错）；MCP symbol_list/symbol_find 输出透传 binds；工具
  描述自本轮起承诺成立。
- 协议依据：`PROTOCOL_V1.2.md` §3.1 v1.2.2 附录（仅 json 路径；packed
  维持 20B 不动）。

## 任务 4：D12（P3）start-serve.sh 端到端化

1. `TANYAO_AGENT` 指向 127.0.0.1/localhost 且 `adb` 可用 → 自动执行幂等
   `adb forward tcp:PORT tcp:PORT`（PORT 取自 TANYAO_AGENT）。
2. 启动尾置端到端健康检查：IPC get_status 必须 `connected:true` 才报
   ready；失败时按症状给出 remediation（forward 丢失 / agent 未起 /
   token 不匹配 / 设备离线，四种各自一条提示）。
3. 可选：get_status 增加 `transport` 字段（"adb-forward"/"direct-tcp"，
   由 TANYAO_AGENT 地址推断）。

## 纪律与 DoD

- 每任务一个 commit（引用 D9/D10/D11/D12）；协议正文不得改动（v1.2.2
  附录已由架构师定稿）。
- DoD：单测全绿（含六段 fixture 与 binds 缺失容忍例）→ 与设备端协调
  （其交付 binds 编码后）真机 `mcp_regression.py` 全绿 + lolm 实测
  `address_resolve(il2cpp_init).rva == 0x3eba158` → WORKSPACE.md §7
  回填关闭。
