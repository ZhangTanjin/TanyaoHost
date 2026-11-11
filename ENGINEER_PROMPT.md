# TanyaoCli 工程师任务提示词：实现 tanyao-agent（设备端）

> **⚠️ 存档（2026-09-04）**：本文是 v2 阶段的任务提示词，所述任务已完成
> （agent 已交付并真机验收，见 `tanyao-ai-re-architecture.md` §10）。
> v3 阶段的任务提示词是 `/home/tanjin/phone/TanyaoCli/docs/PROMPT_V3_AGENT.md`，
> 请勿再按本文派工。另：文中 `/home/tanjin/...` 旧主机路径已全部废弃，
> 现工作区为 `/home/tanjin/phone/`，仅供历史对照。

> 把本文整段交给负责 `/home/tanjin/TanyaoCli` 的工程师（人或 AI 编码代理）即可。
> 文中协议与主机端 `tanyao-host`（由架构师维护）逐字对齐；
> 权威协议文档：`/home/tanjin/guihua/tanyao-host/docs/PROTOCOL.md`；
> 互通自测工具：`/home/tanjin/guihua/tanyao-host/tanyao/interop.py`。

---

## 角色与任务

你负责在 **TanyaoCli 仓库**内新增一个设备端可执行程序 **`tanyao-agent`**：
Android arm64 常驻 TCP 服务，作为电脑端（tanyao-host）与 TanyaoKernel 内核模块之间的
**纯转发器**。它把主机发来的协议帧逐条翻译成对内核匿名 fd 的 `ioctl()` 调用并回帧。

**硬性边界**：agent 不含任何业务逻辑——不做扫描、不做 ELF 解析、不做文本/JSON
格式化、不做落盘。它只有：鉴权、帧解析、ioctl 翻译、错误回帧。
所有逆向逻辑都在电脑端，你不需要也不应该"补全"它们。

## 背景材料（动手前必读）

1. 内核 ABI：`/home/tanjin/TanyaoKernel/include/uapi/tanyao_abi.h`
   —— 全部 ioctl 号、结构体、能力位。agent 是这些结构的唯一翻译层。
2. 连接内核的现成代码：`/home/tanjin/TanyaoCli/src/main.cpp` 中
   `BackendClient::connect()`（magic reboot syscall → kprobe → task_work 安装匿名 fd）
   与各 `ioctl` 封装。直接复用或照抄这段；**不要发明新的连接方式**。
3. 权威协议：`/home/tanjin/guihua/tanyao-host/docs/PROTOCOL.md`（下文已内嵌要点，
   冲突时以该文件为准）。
4. 参考实现：`/home/tanjin/guihua/tanyao-host/tests/mock_agent.py`
   （Python 写的逐字模拟，语义以此为准；C++ 实现行为必须与它一致）。

## 交付物

```text
TanyaoCli/
  src/agent/agent_main.cpp      入口、参数、鉴权、帧循环
  src/agent/agent_ops.cpp       op ↔ ioctl 翻译（每个 CMD_* 一个函数）
  src/agent/agent.hpp          内部头
  third_party/agent/cJSON.*     或 jsmn（JSON 解析，vendor 进来）
  third_party/agent/sha256.*    公有领域 SHA-256 实现（auth 用）
  CMakeLists.txt                新增 target: tanyao-agent（不影响 tanyao-cli）
  scripts/build-agent.sh        NDK 交叉编译脚本（可复用 build-wsl.sh 的环境探测）
产物: out/android-arm64-release/tanyao-agent
```

`src/main.cpp` 与 `tanyao-cli` 本体**一行都不改**。`tanyao_abi.h` 继续通过
`../TanyaoKernel/include/uapi` 引用。

## 协议规范（逐字实现）

### 帧格式

TCP；默认端口 **52730**；帧头 20 字节定长 + JSON payload；多字节字段**大端**：

```text
偏移 大小 字段
0   4   magic     u32 = 0x54594F31 ("TYO1")
4   1   version   u8  = 0x01（其他值 → 立即断开）
5   1   flags     u8    bit0=RESPONSE bit1=ERROR
6   2   reserved  u16 = 0
8   4   seq       u32  请求序号，响应原样回带
12  4   cmd       u32  操作码，响应原样回带
16  4   length    u32  payload 字节数（>16MiB → 立即断开）
20  N   payload   JSON 对象（UTF-8）；N==0 视为 {}
```

严格一问一答。agent 主动推送的帧只有一条：连接后的 hello。
除 hello 外收到非请求帧（flags 带 RESPONSE 位）→ 协议错误，断开。

### 生命周期与鉴权

1. TCP accept 后立即发 hello（seq=0，flags=0）：
   `{"agent":"tanyao-agent","version":"<你的版本>","generation":<进程启动序号>,"challenge":"<32字节随机数的64位小写hex>"}`
2. 等待 `cmd=1 auth`：`{"proof":"<64 hex>"}`。
   校验：`proof == hex(SHA256( UTF8(token) || ASCII(challenge字符串) ))`。
   - 通过：回 `{"ok":true}`（RESPONSE 位）。
   - 失败：回 ERROR 帧 `{"ok":false,"error":"auth_failed"}` 并**关闭连接**。
3. 认证前收到任何其他 cmd：回 `{"ok":false,"error":"auth_required"}` ERROR 帧并关闭。
4. **单连接**：已有已认证连接时，新连接直接回 ERROR 帧 `{"ok":false,"error":"busy"}`
   并关闭（不必发 hello）。
5. `cmd=3 shutdown`：回 `{"ok":true}` 后干净退出（close 全部 target handle 与 fd）。
6. generation：agent 进程内从 1 开始每次启动 +1；用于主机检测 agent 重启。

### op 表（cmd → 内核调用 → 字段）

JSON 约定：**u64 一律小写 "0x..." 字符串**（addr/size/handle/cookie/base/capabilities/
max_transfer_size/start/end/file_offset）；pid、计数、flags 位图、status、errno 用十进制
数字；二进制用 base64 字段 `data_b64`。

| cmd | 请求 → 响应 | 内核调用 |
| --- | --- | --- |
| 2 ping | `{}` → `{"ok":true,"uptime_sec":N}` | — |
| 3 shutdown | `{}` → `{"ok":true}` 后退出 | — |
| 10 backend_info | `{}` → `{"abi_major","abi_minor","capabilities":"0x..","page_size","pointer_bits","max_transfer_size":"0x..","max_iov","backend_flags":"0x..","name"}` | `TANYAO_IOC_BACKEND_INFO`（字段原样搬运） |
| 11 session_info | `{}` → `{"session_id":"0x..","capabilities":"0x.."}` | `TANYAO_IOC_SESSION_INFO` |
| 20 target_open | `{"pid":N,"expected_cookie":"0x.."}`（可省略） → `{"handle":"0x..","start_cookie":"0x.."}` | `TANYAO_IOC_TARGET_OPEN` |
| 21 target_close | `{"handle":"0x.."}` → `{}` | `TANYAO_IOC_TARGET_CLOSE` |
| 22 target_maps | `{"handle":"0x..","capacity":N≤4096}` → `{"status","entry_count","total_count","target_cookie":"0x..","entries":[{"start","end","file_offset","flags","path"}]}`（flags 位图：R=1 W=2 X=4 P=8 S=16 ANON=32；path 为空串表示匿名） | `TANYAO_IOC_TARGET_MAPS`（status 非 0 也按 ERROR 帧回，带 errno=status，主机负责重试） |
| 30 mem_read | `{"handle","addr","size"}` → `{"status":0,"result_size":"0x..","data_b64":".."}`（status≠0 时 data_b64 带已读部分，可为空；**这不是 ERROR 帧**） | `TANYAO_IOC_MEM_READ` |
| 31 mem_readv | `{"handle","iov":[{"addr","size"},..≤max_iov]}` → `{"status","completed_iov","total_completed":"0x..","spans":[{"status","result_size","data_b64"},..]}` | `TANYAO_IOC_MEM_READV` |
| 32 mem_write | `{"handle","addr","data_b64"}` → `{"status":0,"result_size":"0x.."}`；短写按 ERROR 帧 `backend_error` + errno + detail | `TANYAO_IOC_MEM_WRITE` |
| 40 process_find | `{"name":".."}` → `{"pid":N}`；无匹配 ERROR `not_found` | legacy ioctl `OP_FIND_PROCESS`（260 字节定长名） |
| 41 process_list | `{"bytes":N}` → `{"pids":[..]}` | legacy `OP_LIST_PROC`（bitmap 逐位展开） |
| 42 process_alive | `{"pid":N}` → `{"alive":bool}` | legacy `OP_ALIVE` |
| 43 module_base | `{"pid":N,"name":".."}` → `{"base":"0x.."}`；无匹配 `not_found` | legacy `OP_MODULE_BASE` |

未知 cmd：回 ERROR `{"ok":false,"error":"unsupported_cmd"}`，**不断开**。

### 错误帧

```json
{"ok":false,"error":"<slug>","errno":-14,"detail":"可选补充"}
```

slug：`bad_request`（缺字段/类型错/越界，errno=0）、`auth_required`、`auth_failed`、
`busy`、`unsupported_cmd`、`backend_error`（ioctl 返回 -1 或负 status，errno=内核
负值原样带出）、`not_found`、`internal`。
注意区分：**ioctl 调用本身失败 → ERROR 帧**；**调用成功但业务 status 非 0
（如 mem_read 部分读）→ 正常 RESPONSE 帧，status 字段带出**。

## 实现要求

1. **复用** `main.cpp` 的 `BackendClient`（提取到共享头或复制进 src/agent/）。
   连接内核 = `syscall(SYS_reboot, 0x53A91C7D, 0xB4E26019, 0, &fd)`。
2. 线程模型建议：主线程 accept；每连接单线程顺序处理（一问一答，无需并发）；
   已认证连接存在时拒绝新连接。
3. JSON：vendor cJSON（MIT，单文件）或 jsmn；不要引 Boost/nlohmann 等重依赖。
4. SHA-256：vendor 公有领域实现（约 200 行），仅用于 auth。
5. 参数：`--bind <ip>`（默认 rndis0 地址；找不到时拒绝启动并提示）、`--port`（默认 52730）、
   `--token-file <path>`（推荐）或 `--token <str>`（仅调试）。**禁止**在日志中打印
   token 或 proof。
6. 启动预检：`geteuid()==0` 否则报错退出；内核模块未加载（connect 失败）时给出明确
   错误信息后退出。
7. 日志走 stderr，一行一事件，安静模式默认开。禁止落盘、禁止上传、禁止改
   /data/local/tmp 之外的文件系统。
8. 信号：SIGTERM/SIGINT → 回 shutdown 响应（若有在途连接）→ 干净退出。
9. 退出码：0 正常 / 2 参数错 / 3 权限或后端不可用。
10. 构建：NDK r27、API ≥ 21，CMake target `tanyao-agent`，产物
    `out/android-arm64-release/tanyao-agent`；沿用 `build-wsl.sh` 的环境探测方式。
11. 部署：push 到 `/data/local/tmp/tanyao-agent`，`chmod 0755`（不要 0700，SELinux
    Enforcing 下 0700 会拒绝执行，这是 tanyao-cli 的已知经验）；启动：
    `su -M -c '/data/local/tmp/tanyao-agent --token-file /data/local/tmp/.tanyao-token'`。

## 明确禁止

- 不得在 agent 内实现扫描、ELF 解析、指针链、文本命令、JSON 美化等业务逻辑；
- 不得绕过 token 鉴权（哪怕对本机回环）；
- 不得绑定 0.0.0.0 同时无鉴权；
- 不得修改 tanyao-cli 与 TanyaoKernel 仓库任何文件；
- 不得记录或回显 token/proof/challenge。

## 验收标准（Definition of Done）

1. `python3 /home/tanjin/guihua/tanyao-host/tanyao/interop.py --host <设备IP> --port 52730
   --token-file <token文件> --pid <存活进程pid>` **全项 PASS，退出码 0**
   （工具会依次验证 auth 正误、busy、ping、backend_info、session_info、target_open、
   target_maps、mem_read、mem_readv、（`--allow-write` 时）write+readback、
   target_close、未知 cmd 错误处理）。
2. 真机对照：同一 PID 下 `tanyao-cli status` 与 agent `backend_info` 的 abi/capabilities
   一致；`mem_read` 首读 16 字节与 `tanyao-cli memory read --size 16` 输出一致。
3. agent 进程重启后 generation 变化；重启期间主机能感知断连并在 agent 回来后恢复。
4. 错误 token、认证前发 op、双连接、未知 cmd、超长 payload（>16MiB）行为与规范一致。
5. `tanyao-cli` 构建不受影响（CI/本地 `build-wsl.sh release` 仍通过）。

## 建议的实现顺序

1. 帧收发 + hello/auth（对 interop 的 auth 两项）
2. ping/shutdown/backend_info/session_info（interop 基础项）
3. target_open/close/maps + mem_read（interop 内存项）
4. mem_readv/mem_write + legacy 四项（interop 全绿）
5. 信号、busy、异常路径加固（interop 边界项）

有任何协议疑问：以 `PROTOCOL.md` 为准；文档未覆盖处，先在 PR 描述里提出，
与主机端架构师确认后再实现——**不要自行发挥字段语义**。
