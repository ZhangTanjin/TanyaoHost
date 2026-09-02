# Tanyao Agent 线协议 v1（唯一真相源）

双端（主机 `tanyao-host` / 设备 `tanyao-agent`）以本文为唯一协议依据。
任何修改必须先改本文并同步双方 + 互通测试。

设计原则：agent 只做"帧 ↔ ioctl"翻译，不含任何业务逻辑；
所有 u64 值走 JSON 十六进制字符串，避免 JS/Python 浮点精度丢失；
二进制数据走 base64；帧头定长二进制负责分帧与版本协商。

## 1. 传输

- TCP。默认端口 **52730**。
- agent 监听绑定：优先 rndis0 接口地址；允许 WiFi 局域网地址；**禁止 0.0.0.0 无鉴权**（鉴权是强制的，此条指不绑定通配地址）。
- 同一时刻**只允许一条已认证连接**。新连接在已认证连接存在时应发送错误帧并立即关闭（busy）。
- 字节序：帧头多字节字段一律**大端（网络序）**。

## 2. 帧格式

```text
偏移  大小  字段
0     4    magic     u32 = 0x54594F31 ("TYO1" 的 ASCII)
4     1    version   u8  = 0x01
5     1    flags     u8    bit0=RESPONSE bit1=ERROR
6     2    reserved  u16 = 0
8     4    seq       u32  请求序号；响应必须原样回带
12    4    cmd       u32  操作码；响应必须原样回带
16    4    length    u32  payload 字节数
20    N    payload   JSON（UTF-8，单对象）；N==0 视为 {}
```

- `MAX_PAYLOAD = 16 MiB`。`length > MAX_PAYLOAD` 视为协议错误，**立即断开**。
- `version != 0x01` 视为协议错误，立即断开。
- 除 Hello 外严格一问一答：请求（flags 无 RESPONSE 位）→ 响应（RESPONSE 位，
  seq/cmd 回带）。禁止 agent 主动推送除 Hello 外的帧。
- 错误响应：`flags = RESPONSE|ERROR`，payload 见 §5。

## 3. 操作码（cmd）

| cmd | 名称 | 方向 | 对应内核接口 |
| --- | --- | --- | --- |
| 0 | hello | agent→host（连接后第一条，主动推送） | — |
| 1 | auth | host→agent / agent 回响应 | — |
| 2 | ping | host→agent | — |
| 3 | shutdown | host→agent（agent 回响应后退出进程） | — |
| 10 | backend_info | host→agent | `TANYAO_IOC_BACKEND_INFO` |
| 11 | session_info | host→agent | `TANYAO_IOC_SESSION_INFO` |
| 20 | target_open | host→agent | `TANYAO_IOC_TARGET_OPEN` |
| 21 | target_close | host→agent | `TANYAO_IOC_TARGET_CLOSE` |
| 22 | target_maps | host→agent | `TANYAO_IOC_TARGET_MAPS` |
| 30 | mem_read | host→agent | `TANYAO_IOC_MEM_READ` |
| 31 | mem_readv | host→agent | `TANYAO_IOC_MEM_READV` |
| 32 | mem_write | host→agent | `TANYAO_IOC_MEM_WRITE` |
| 40 | process_find | host→agent | legacy `OP_FIND_PROCESS` |
| 41 | process_list | host→agent | legacy `OP_LIST_PROC` |
| 42 | process_alive | host→agent | legacy `OP_ALIVE` |
| 43 | module_base | host→agent | legacy `OP_MODULE_BASE` |

未识别的 cmd：回 `ERROR` 帧（error=`unsupported_cmd`），**不断开**。

## 4. JSON 约定

- u64 一律 `"0x..."` 十六进制字符串（地址、size、handle、cookie、base、
  start/end/file_offset、capabilities、max_transfer_size 等）。
- `pid`、`abi_major/minor`、`entry_count`、`page_size`、`pointer_bits`、
  `max_iov`、`flags(u32 位图)`、`status`、`errno`：JSON 十进制数字。
- 二进制：`"data_b64"`（标准 base64）。
- 大小写：hex 字符串小写，无前导零（除 `"0x0"`）。

### 4.0 hello（agent 主动推送，seq=0）

```json
{"agent":"tanyao-agent","version":"1.0.0","generation":7,
 "challenge":"<64个小写hex，随机每次连接>"}
```

### 4.1 auth

请求：`{"proof":"<64个小写hex>"}`，其中
`proof = hex( SHA256( UTF8(token) || ASCII(challenge字符串) ) )`
（token 为主机环境变量配置的共享密钥；challenge 为 hello 中的原字符串）。

响应成功：`{"ok":true,"backend_name":"..."}`（可省略 backend_name）。
失败：ERROR 帧 `{"ok":false,"error":"auth_failed"}` 并**立即关闭连接**。
认证完成前收到任何其他 cmd：回 `auth_required` ERROR 帧并关闭。

### 4.2 ping / shutdown

`ping {}` → `{"ok":true,"uptime_sec":<数字>}`。
`shutdown {}` → `{"ok":true}` 然后进程退出。

### 4.3 backend_info

`{}` → `{"abi_major":1,"abi_minor":0,"capabilities":"0x3f","page_size":4096,
"pointer_bits":64,"max_transfer_size":"0x100000","max_iov":64,
"backend_flags":"0x7","name":"tanyao"}`

### 4.4 session_info

`{}` → `{"session_id":"0x...","capabilities":"0x..."}`

### 4.5 target_open

请求：`{"pid":4321,"expected_cookie":"0x0"}`（expected_cookie 可省略=0）。
响应：`{"handle":"0x...","start_cookie":"0x..."}`。
失败回 ERROR（errno 为内核返回的负值，如 pid 不存在 `-3`）。

**单槽位语义（重要）**：内核会话同一时刻只允许一个已打开 target
（`transport_anon.c`：`session->target` 非空即 EBUSY）。因此：

1. agent 必须维护**每连接 target 列表**，连接终止（任何原因）时对余量
   补发 TARGET_CLOSE（agent 侧已实现，TanyaoCli `57f5891`）；
2. host 端策略为**单活动 target**：打开新 pid 前先关闭旧 target，
   target_open 收到 EBUSY(-16) 时做一次"close 全部 + 重试"；
3. 待办（agent）：TARGET_OPEN 对"会话中已锁定的同一 pid"应返回既有
   handle/cookie（幂等打开），消除 serve 重启后缓存丢失导致的残留 EBUSY。

### 4.6 target_close

`{"handle":"0x..."}` → `{}`

### 4.7 target_maps

请求：`{"handle":"0x...","capacity":4096}`（capacity ≤ 4096）。
响应：`{"status":0,"entry_count":3,"total_count":3,"target_cookie":"0x...",
"maps_source":"target_maps",
"entries":[{"start":"0x...","end":"0x...","file_offset":"0x...",
"flags":5,"path":"/system/lib64/libdemo.so"}]}`
（flags 位图：READ=1 WRITE=2 EXEC=4 PRIVATE=8 SHARED=16 ANONYMOUS=32；
无路径或 `[` 开头的伪路径（[heap]/[stack]/[anon:*]/[vdso]/[vvar]）置 ANONYMOUS
且 path 原样保留）
status 非 0（如 -ENOSPC 快照截断）仍按 ERROR 帧回，host 侧负责以更大
capacity 重试（agent 不做重试逻辑）。

**ENOSPC 回退与 maps_source（标准字段，自 agent a81d824）**：当内核快照返回
-ENOSPC 且 total_count > 4096（TANYAO_MAX_MAP_ENTRIES）时，agent 读
`/proc/<pid>/maps` 解析为同结构 entries 返回，`maps_source` 置
`"proc_maps"`；内核路径返回的快照 `maps_source` 为 `"target_maps"`。
host 端必须将该字段透传为映射来源标记，不得假设其一。

### 4.8 mem_read

请求：`{"handle":"0x...","addr":"0x...","size":"0x10"}`。
响应：`{"status":0,"result_size":"0x10","data_b64":"..."}`。
语义与 ABI 相同：`status==0` 表示完整成功；status 非 0 时 `data_b64`
携带已读到的部分（可能为空），result_size 为部分长度。host 负责分块
（单请求 size 不得超过 backend_info.max_transfer_size）。

### 4.9 mem_readv

请求：`{"handle":"0x...","iov":[{"addr":"0x...","size":"0x10"},...]}`（≤ max_iov）。
响应：`{"status":0,"completed_iov":2,"total_completed":"0x20",
"spans":[{"status":0,"result_size":"0x10","data_b64":"..."},...]}`

### 4.10 mem_write

请求：`{"handle":"0x...","addr":"0x...","data_b64":"..."}`。
响应：`{"status":0,"result_size":"0x8"}`。
agent 不做 expect/verify/rollback——这些全部由 host 用 read+write 组合实现。

### 4.11 legacy 进程/模块 op

- `process_find {"name":"com.demo.game"}` → `{"pid":4321}`；
  无匹配回 ERROR `{"ok":false,"error":"not_found"}`。
- `process_list {"bytes":8192}` → `{"pids":[123,456,...]}`
- `process_alive {"pid":4321}` → `{"alive":true}`
- `module_base {"pid":4321,"name":"libdemo.so"}` → `{"base":"0x..."}`；
  无匹配 `not_found`。

## 5. 错误语义

ERROR 帧 payload：

```json
{"ok":false,"error":"<slug>","errno":-14,"detail":"人类可读补充，可省略"}
```

| slug | 含义 | 典型 errno |
| --- | --- | --- |
| `bad_request` | payload 缺字段/类型错/越界 | 0 |
| `auth_required` / `auth_failed` | 未认证 / 校验失败（后者的帧之后必须断开） | 0 |
| `busy` | 已有已认证连接 | 0 |
| `unsupported_cmd` | 未知 cmd | 0 |
| `backend_error` | ioctl 失败 | 内核 errno（负数原样带出） |
| `not_found` | 进程/模块无匹配 | 0 |
| `internal` | agent 内部错误 | 0 |

规则：内核 ioctl 返回 -1/负 status 时用 `backend_error` + `errno`；
`status` 字段（如 mem_read 部分 读）不是 ioctl 失败，按 §4.8 正常响应帧带出。

## 6. 鉴权与生命周期

1. TCP 建立后 agent 立即发 hello（含随机 challenge 与 generation）。
2. host 发 auth；agent 校验 proof。失败→ERROR+断开。
3. 认证后正常一问一答。host 空闲保活用 ping（建议 10s 间隔，超时 30s 判死）。
4. generation：agent 启动时递增并持久化（如计数文件，跨重启单调，不重置）；
   host 以"generation 变化"为唯一重启信号——agent 自身重启与 host 重连都会
   表现为变化，处理方式相同（清空全部 handle/cookie 缓存，按需重建会话）。
5. TCP 断开：agent 必须对本连接打开的全部 target 补发 TARGET_CLOSE
   （per-connection target 列表，见 §4.5 单槽位语义）；host 同时丢弃 handle 缓存。
6. SIGTERM/SIGINT：agent 尽量回 shutdown 响应后干净退出；退出前 close 全部
   target（内核侧也会随 fd 自动清理，这是兜底）。
