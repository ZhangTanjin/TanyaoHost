# Tanyao Agent 线协议 v1.2 草案（计算下沉）

> 状态：**草案**——设备端（TanyaoCli）与主机端（tanyao-host）评审通过、双端实现
> 并互通后，正式并入 `PROTOCOL.md` 取代本文。
> 上游依据：`tanyao-host/tanyao-ai-re-architecture.md` §11（v3 架构，2026-09-04 定稿）。
> 本文在 v1（`PROTOCOL.md`）+ v1.1（`TanyaoCli/docs/AGENT_PROTOCOL_EXTENSIONS.md`）
> 之上做**纯增量**：新增能力位、新增 cmd、帧 flags 新增一位；v1/v1.1 全部语义不变。

## 0. 基线与勘误

- v1 基线：`PROTOCOL.md` 全文（20B 大端帧头、JSON payload、鉴权、单槽位、代际）。
- v1.1 基座（本文将其正式定版）：cmd 50–55 扫描引擎、cmd 60 write_txn、
  hello `capabilities` 字段。勘误：v1.1 文本 §1 写 "cmd 50–56"，实现与 op 清单
  均为 50–55，以 50–55 为准。
- hello `version` 自 v1.2 起统一为 `"1.2.0"`（v1.1 草案与 agent 实际发送的
  `"1.0.0"` 不一致问题一并闭环）。

## 1. 能力位（hello.capabilities，agent 层命名空间）

| bit | 名称 | 含义 | 引入 |
| --- | --- | --- | --- |
| 0 | AGENT_SCAN | cmd 50–55（agent 本地扫描引擎） | v1.1 |
| 1 | WRITE_TXN | cmd 60（单地址写入事务） | v1.1 |
| 2 | ~~MODULE_STREAM~~ | **撤销预留，永久不用**：其语义由 bit6 dump 管线取代。实现不得占用该位 | v1.1→v1.2 |
| 3 | SYMBOL_BATCH | cmd 61（设备端 dynsym 批量解析） | v1.2 |
| 4 | BINARY_FRAMES | 帧 flags bit2 PAYLOAD_BINARY（§2） | v1.2 |
| 5 | STRINGS | cmd 62（设备端 strings 扫描） | v1.2 |
| 6 | DUMP_PIPELINE | cmd 63/64/65/68（设备端 dump 落盘 + 分块拉取 + 清理） | v1.2 |
| 7 | APK_INFO | cmd 66（设备端 apk 元信息，零镜像过网） | v1.2 |
| 8 | DISASSEMBLE | cmd 67（设备端 capstone 反汇编，可选实现） | v1.2 |

规则沿用 v1.1：host 从 hello 读 `capabilities`；对未声明能力的 cmd 一律得到
`unsupported_cmd` ERROR（不断开）。所有新 op 均要求已认证，无匿名面。

## 2. 帧格式扩展：二进制载荷帧（bit4 BINARY_FRAMES）

帧头 20B 布局不变。flags 新增：

```text
flags bit2 = PAYLOAD_BINARY
```

- 置位时 payload 为**原始字节**（非 UTF-8 JSON）；未置位行为与 v1 完全一致。
- 该位**只允许出现在 agent→host 响应帧**上；host 请求一律 JSON 帧。agent 收到
  带 bit2 的请求帧视为协议错误，立即断开。
- 一问一答规则不变：每个请求恰好一个响应（响应可为 JSON 帧或二进制帧，由 op
  定义声明）；`MAX_PAYLOAD = 16 MiB` 对二进制 payload 同样生效。
- 声明二进制响应的 op：`dump_pull`（65，固定）与 `symbol_batch`（61，仅
  `format:"packed"` 时）。

## 3. 新命令规范

JSON 约定沿用 v1 §4：u64 一律小写 `"0x..."` hex 字符串；`pid`、count、
`min_sdk` 等为十进制数字；二进制仅出现在二进制帧或 `*_b64` 字段。
`pid` 的 target 生命周期语义沿用 v1.1 `scan_start`：请求 pid 与会话当前
target 不同时，agent 自动 close 旧 target 再 open（响应无需特殊字段）。

### 3.1 cmd 61 symbol_batch（bit3）

请求：

```json
{"pid":1234,"module":"libc.so","filter":"^pthread_","format":"json",
 "max_symbols":65536,"include_undef":false}
```

- `module`：可省略（=全部可执行模块）。basename 精确匹配（与扫描 preset
  `module:<basename>`、dump 的 module 参数同一语义，大小写敏感）；无匹配
  回 `not_found`。省略时覆盖目标全部 file-backed 可执行映射，**按基址升序
  迭代**（确定性顺序，截断结果可复现）。
- `filter`：可省略（=全部）。ECMAScript 正则（`std::regex`），对符号名做
  `regex_search`；非法正则回 `bad_request` + detail。**服务端过滤先于
  `max_symbols` 计数**——全模块精确查找不会因靠前模块符号多而被截断。
- `format`：`json`（默认）| `packed`（响应为二进制帧，要求同时声明 bit4）。
- `max_symbols`：返回符号数上限，默认 65536；超出置 `truncated`（不报错）。
- `include_undef`：默认 false——排除 `st_shndx==SHN_UNDEF` 导入符号（对齐
  host P3 修复语义，消除 st_value=0 噪声）。

语义：agent 在设备端从目标内存解析 `PT_DYNAMIC` → `DT_SYMTAB/DT_STRTAB/
DT_HASH/GNU_HASH`（兼容 bionic 的 raw/absolute 两种地址形态，与 host
`symbols.py` 同源语义）。模块归属按映射路径 basename 分组，同一 so 的多个
映射段（r-x/-w-/r--）归同一模块。**只回传符号表，不回传内存。**

响应（`format:"json"`，列式数组，下标一一对应）：

```json
{"count":1483,"truncated":false,
 "modules":["libc.so"],"module_indexes":[0,0,...],
 "names":["pthread_create",...],"addresses":["0x7dd2ef1160",...],
 "sizes":[64,...],"types":["FUNC",...]}
```

- `modules`：本次结果涉及的模块 basename 表（去重，按首次出现序）；
  `module_indexes[i]` 是第 i 个符号对 `modules` 的下标。两字段**恒在**
  （单模块请求时 `modules` 长度为 1），解析方无需分形态处理。

响应（`format:"packed"`，二进制帧 payload，**大端**）：

```text
0   4   count            u32
4   4   module_count     u32
8   4   name_blob_size   u32
12  4   module_blob_size u32
16  20×count  entry：addr u64 | size u32 | name_off u32 | module_idx u32
...     name_blob：'\0' 结尾字符串连续拼接（name_off 相对起点）
...     module_blob：'\0' 结尾字符串连续拼接（module_idx 相对起点）
```

错误：`not_found`（模块未命中/无动态段/无可执行映射）、`backend_error`
（内存读失败，带 errno）、`bad_request`。

> **MCP 映射（2026-09-04 裁决）**：`symbol_list(module,filter)` 直传
> `module`/`filter`；`symbol_find(name)` 用省略 `module` 的全模块请求 +
> 锚定 filter（服务端过滤后结果集小，无截断风险），输出中的模块归属由
> `modules`/`module_indexes` 填充。工具层兼容细则由
> `DESIGN_V3_HOST.md` §3.1 承载，wire 协议不感知 MCP 签名。

### 3.2 cmd 62 strings_scan（bit5）

请求：

```json
{"pid":1234,"preset":"module:libc.so","min_len":4,"max_len":256,
 "regex":"root|magisk","max_results":1024,"async":false}
```

- `preset`：与 v1.1 `scan_start` 同表（`anon` / `stack` / `module:<basename>` /
  `all_readable`）；亦可用显式 `"addr":"0x..","size":"0x.."` 二元组替代。
- `min_len` 默认 4，`max_len` 默认 256（单串截断上限）；只提取可打印 ASCII
  连续序列（`\t` 允许；UTF-8 多字节按无效字节截断，不做解码）。
- `regex`：设备端过滤（ECMAScript，`regex_search`），可省略。
- `async:false`（默认）：同步执行，响应即结果。范围必须有限——对 `all_readable`
  与超大范围，agent 可直接回 `bad_request`（detail 建议限 preset），实现必须在
  文档化阈值（默认 256 MiB）内二选一：执行或拒绝，不得无限阻塞。
- `async:true`：行为同 `scan_start` 返回 `{"job_id":..}`；`scan_status`（51）
  响应增加 `"kind":"strings"`；结果经 `scan_results`（53）分页取回，`hits`
  元素为 `{"address":"0x..","value":"<字符串>"}`（无 value_hex）。

同步响应：

```json
{"count":87,"truncated":false,"scanned_bytes":"0x1f0000",
 "skipped_bytes":"0x2000","elapsed_sec":1.2,
 "results":[{"address":"0x7dd2ef0a40","length":21,
             "value":"ro.build.fingerprint"}]}
```

- `length`（2026-09-04 增补）：字符串原始字节长度（截断前），host 工具层
  `{offset,length,value}` 输出形状所需；async 路径的 `scan_results` hits
  元素同样携带 `{"address","length","value"}`（仍无 value_hex）。

容错读复用扫描引擎的分区读 + 死区二分（§v1.1 语义对齐清单全部适用）。

### 3.3 cmd 63 dump_start（bit6）

请求：

```json
{"pid":1234,"module":"libdemo.so","include_anonymous":false,"out_name":"libdemo"}
```

agent 本地完成 v2 时代 host `dump.py` 的全部工作：取映射快照（语义同 cmd 22，
含 procfs 回退与 `maps_source`）→ **文件布局重建**（file-backed 按原
file_offset 落盘，含无读权限映射位置占位，不可读段跳过并记录）→ 节表清洗
（`e_shoff/e_shnum/e_shstrndx` 清零，manifest 记 `sanitized:true`）→ 产出
manifest JSON。落盘位置固定：

```text
/data/local/tmp/tanyao-dump/<dump_id>.so
/data/local/tmp/tanyao-dump/<dump_id>.so.manifest.json
```

`dump_id = <out_name>-<4hex>`（冲突自动重生成）。目录权限 0700，文件 0600。
`out_name` 仅允许 `[A-Za-z0-9._-]`，非法回 `bad_request`。目录总大小预算
默认 512 MiB，超预算回 `disk_budget`（host 应先 cleanup）。

响应：

```json
{"dump_id":"libdemo-a1b2","path":"/data/local/tmp/tanyao-dump/libdemo-a1b2.so",
 "size":"0x1fc000","sha256":"<64hex>","manifest_path":"...",
 "mappings":3,"sanitized":true,"maps_source":"target_maps",
 "skipped":[{"start":"0x..","end":"0x..","reason":"unreadable"}],
 "manifest":{"pid":1234,"module":"libdemo.so","total_size":"0x1fc000",
             "maps_source":"target_maps","mappings":[...],"skipped":[...],
             "sanitized":["e_shoff","e_shentsize","e_shnum","e_shstrndx"]}}
```

- `manifest`（2026-09-04 增补）：完整 manifest 对象，字段与 host `dump.py`
  `DumpManifest.to_dict()` 同构（`mappings` 为映射条目数组，u64 用 hex
  字符串），host 据此原样落盘 `<out>.manifest.json`，工具层形状不变。

### 3.4 cmd 64 dump_status（bit6）

- `{"dump_id":"libdemo-a1b2"}` → `{"exists":true,"size":"0x1fc000",
  "sha256":"<64hex>","age_sec":12}`；不存在 → `{"exists":false}`（非错误）。
- `{"list":true}` → `{"dumps":[{"dump_id":"..","size":"0x..","age_sec":..},...]}`。

### 3.5 cmd 65 dump_pull（bit6；响应为二进制帧，要求 bit4）

请求：

```json
{"dump_id":"libdemo-a1b2","offset":"0x0","chunk":"0x40000","compress":true}
```

响应二进制帧 payload（**大端**，24B 子头 + 数据）：

```text
0   8   offset     u64  实际起始偏移（回带请求值）
8   4   data_len   u32  数据字节数（压缩后）
12  4   raw_len    u32  解压后字节数
16  1   flags      u8   bit0=deflate bit1=last（本响应已到 EOF）
17  3   reserved   =0
20  4   crc32      u32  对 data 原始字节（压缩态）的 CRC-32（IEEE）
24  N   data
```

- `offset >= size`：正常回 `data_len=0, flags.last=1`（幂等，不报错）。
- `compress:true` 而 agent 无 deflate（libz 不可用）时按未压缩回
  （flags.bit0=0），host 以 flags 为准，不得假设。
- 分块上限受 `MAX_PAYLOAD`：`24 + data_len <= 16 MiB`。host 逐块推进 offset
  并以 crc32/size 校验，支持任意 offset 重发实现断点续传。
- 错误：`not_found`（dump_id 不存在）、`bad_request`（chunk 越界等）。

### 3.6 cmd 66 apk_info（bit7）

请求：`{"pid":1234}`

agent 从目标映射提取 base.apk 路径（`/data/app/.../<pkg>/base.apk`），本地打开
zip 解析中央目录 + `AndroidManifest.xml` AXML（输出字段与 host 既有
`apk_info` 工具对齐）。**零镜像过网。**

响应：

```json
{"apk_path":"/data/app/~~x/pkg/base.apk","package":"com.example",
 "version_name":"1.2.3","version_code":123,"min_sdk":24,"target_sdk":34,
 "entry_activity":"com.example.MainActivity","permissions":["..."],
 "activities":["com.example.MainActivity",...],
 "launcher_activities":["com.example.MainActivity",...],
 "split_apks":["/data/app/~~x/pkg/split_config.arm64_v8a.apk"]}
```

- `activities` / `launcher_activities`（2026-09-04 增补）：对齐 host
  `apk_info` 既有字段（DESIGN_V3_HOST §3.4 规则 4 "输出形状统一"），设备端
  AXML 解析本就产出，零额外成本。

错误：`not_found`（映射中无 apk）、`internal` + detail（AXML 解析失败）。
APK 文件本体拉取复用 dump 管线语义（`dump_start` 的 `module` 换 `apk_path`
入参不在本期范围——host 仅在用户显式要求 `pull_apk` 时用 cmd 65 拉
`apk_path` 指向文件，请求新增可选字段 `path`（绝对路径，仅接受
`/data/app/` 前缀），与 `dump_id` 二选一。

> **语义澄清（2026-09-04）**：cmd 66 只回答"**目标进程**的 APK 是什么"
> （入参 pid，设备端从 maps 定位）。主机本地 APK 文件解析（MCP
> `apk_info(apk_path)`）仍在 host 层，不经本 cmd。MCP 工具层的双路径路由
> 规则见 `DESIGN_V3_HOST.md` §3.4，wire 协议不为此改动。

### 3.7 cmd 67 disassemble（bit8，可选实现）

请求：`{"pid":1234,"addr":"0x..","count":64}`（`count` 或 `"size":"0x.."`
二选一；上限 4096 条 / 64 KiB）。

agent 链接 capstone（仅 ARM64 后端），本地读内存（语义同 mem_read）后反汇编。
响应对齐 host `native.py` 输出形状：

```json
{"engine":"capstone","count":64,
 "instructions":[{"address":"0x..","bytes_hex":"ff4304d1",
                  "mnemonic":"stp","op_str":"x31, x30, [sp, #-64]!"}]}
```

- 读内存失败 → `backend_error` + errno（不返回部分反汇编）。
- 构建未带 capstone → `unsupported`（host 回退自带子集解码器，行为同现状）。

## 4. 资源与生命周期约束（新 op 通用）

1. **单 job 槽**：扫描（50–55）与 strings 异步 job 共用一个 job；同 pid 新 job
   自动 cancel 旧 job（响应带 `cancelled_old:true`），沿用 v1.1。
2. **低优先级**：扫描/strings/dump worker 线程以 `SCHED_IDLE` 或 nice 19 运行；
   提供启动参数 `--scan-pacing-ms <0..100>`（默认 0）做分块间让步，避免与游戏
   抢 CPU/IO。
3. **断连回收**：连接终止时 cancel 属连接的 job、close 属连接 target、不做
   静默 dump 清理（cleanup 是 host 的显式职责，可审计）。
4. **磁盘预算**：dump 目录超预算时 `dump_start` 回 `disk_budget`；`dump_status
   {"list":true}` 供 host 决策。
5. **鉴权**：全部新 op 在认证之后可用；loopback 客户端（TanyaoMB）同样必须
   携带 token，见 `TanyaoMB/docs/DESIGN_V3_MB.md`。

## 5. 错误 slug 增补

| slug | 含义 | 引入 |
| --- | --- | --- |
| `expect_old_mismatch` / `verify_failed` | write_txn 失败路径 | v1.1 |
| `disk_budget` | dump 目录超预算 | v1.2 |
| `unsupported` | 能力存在但可选组件缺失（如 capstone 未编译） | v1.2 |

`not_found` 扩展用于 dump_id / apk 未命中（v1 已定义，语义不冲突）。

## 6. 兼容矩阵

| agent | host（v1.2） | 行为 |
| --- | --- | --- |
| v1.0 | — | 全部走 host 本地引擎与旧 dump/symbol 路径（现状回归必须保持绿） |
| v1.1 | — | 扫描/write_txn 走设备，其余 host 本地 |
| v1.2 | — | 声明了的能力全部下沉设备；仅未声明项回退 host |

host 侧选择逻辑只看 hello.capabilities，不做版本号判断。

## 7. 验收

- `tests/mock_agent.py` 实现全部 v1.2 op（作为参考实现），含二进制帧与 packed
  符号表金样本；host 单测覆盖帧编解码、CRC 校验失败注入、断点续传。
- `interop.py` 按能力位条件化：声明了才检查，未声明跳过并记录 `skipped_caps`。
- 带宽验收指标（真机）见各项目设计文档 `DESIGN_V3_*.md` 的里程碑表。
