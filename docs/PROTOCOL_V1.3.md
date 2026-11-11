# Tanyao Agent 线协议 v1.3（模糊 find / packed bind / 多值指针扫描，定版）

> 状态：**已定版（2026-09-12）**——双端实现完成（设备 bit8/10/11/12 四提交、
> 主机五提交），真机联合回归 **51/51**（caps 0x1ffb 全能力位在位；v1.3 三
> 用例：substring 模糊 find、pointers_to values[] exact-u64 单往返、多目标
> 单往返 scans==1）。勘误：初稿两处 “cmd 44” 为笔误，process_find 实为
> **cmd 40**（实现按 cmd 40 mode 字段落地）。与 `PROTOCOL.md`（v1/v1.1）+
> `PROTOCOL_V1.2.md` 共同构成现行规范。
> 遗留记账：agent hello `version` 升 "1.3.0" 随下次设备端发版；bit2
> MODULE_STREAM 位维持永久弃用。
> 基线：v1.2（`PROTOCOL_V1.2.md`）+ 附录 v1.2.1/2/3。全部为纯增量，v1.2
> 语义不变；新能力位协商，旧组合行为不变。

## 0. 出身处（每项都有实战编号）

| 项 | 出处 |
| --- | --- |
| 模糊 find | lolm 实战 O4：短名（"lolm"）不命中须全包名，AI 选参摩擦 |
| packed bind | R4 D11 裁定遗留：json 有 binds、packed 20B 无 |
| 多值指针扫描 | 12 轮审查 U2：host `pointers_to` 现为 N 次单值扫描的展开 |

## 1. 能力位（hello.capabilities 续）

| bit | 名称 | 含义 |
| --- | --- | --- |
| 10 | FUZZY_FIND | cmd 40 支持子串匹配（§2.1） |
| 11 | SCAN_VALUES | cmd 50 支持 `values[]` 多值扫描（§2.3） |
| 12 | PACKED_BIND | cmd 61 packed entry 携带 bind（§2.2） |

cmd 67（bit8）与本草案无关，随 capstone vendor 独立启用。

## 2. 新语义

### 2.1 cmd 40 process_find 模糊匹配（bit10）

- 请求新增可选 `"mode":"exact|substring"`（默认 exact，现状语义）。
- `substring`：agent 以 root 读 `/proc/<pid>/cmdline`（NUL 截断到首段），
  **大小写敏感子串**匹配；多命中返回首个 + `"matches":n`（>1 时提示
  调用方收窄）；零命中 `not_found`（现状）。
- 内核 legacy op 不动（F18 长名边界维持现状）——模糊匹配完全在 agent
  用户态实现。上限：遍历 /proc 全量 pid，单次调用预算 2s。

### 2.2 cmd 61 packed bind（bit12）

- packed entry **20B → 24B**：`addr u64 | size u32 | name_off u32 |
  module_off u32 | bind u8 | rsv u8 | rsv2 u16`（大端）。
- `bind` 枚举：0=OTHER 1=LOCAL 2=GLOBAL 3=WEAK 4=GNU_UNIQUE（与 json
  `binds` 字符串一一对应）。
- 头部第 5 个 u32 `entry_size` 加在 module_blob_size 之后（=24），解析方
  以 entry_size 分派 20B/24B——旧 agent 无该字段按 20B，向前兼容由
  **bit12 声明**双保险。
- json 路径不变。

### 2.3 cmd 50 多值扫描（bit11）

- `kind:"value"` 请求新增可选 `"values":[...]`（与单 `value` 互斥，≤64
  个；元素类型仍由 `type` 统一）。
- 语义：一次遍历，命中任意成员即记录；结果 `hits[]` 元素增加
  `"value_index":<i>`（命中的 values 下标）。typed/ptr 语义、对齐、
  epsilon、死区二分、MAX_HITS 全部沿用单值规则。
- 用途：`pointers_to(addresses[])` 的单次往返化（现在 host 展开 N 次）。

## 3. host 侧映射（实现参考，非 wire 语义）

- `find_process` 新增可选 `mode` 透传；MCP 描述更新"短名用
  mode=substring"。
- `pointers_to` 在 bit11 声明时改发 `values[]` 单次扫描，未声明维持
  现状展开。
- packed 解码器按 entry_size 分派；mock_agent 同步实现三项（参考实现）。

## 4. 验收

- interop 条件项：bit10 子串命中/多命中计数；bit11 双值扫描 value_index
  正确；bit12 packed 24B 解码与 json binds 一致。
- mcp_regression：find_process(mode=substring) 用例；pointers_to 多目标
  单往返用例（engine=agent-scan，ranges 仍 1 次扫描的账目）。
- 真机带宽对照：pointers_to 8 目标，values[] 单次 vs 展开 8 次，字节数
  与时延记录回台账。
