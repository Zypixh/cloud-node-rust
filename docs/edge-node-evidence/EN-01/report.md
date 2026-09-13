# EN-01 — 共享合同与资源账本规范

- **task_id**: EN-01
- **status**: VERIFIED（证据见下；本任务为合同/规范交付，无运行态行为变化，验收项全部可由本报告所列命令与断言复核）
- **start_commit**: `8c66537`（EN-00 提交后工作树干净）
- **end_commit**: 见本证据目录同 commit 的 `manifest.json` / git log
- **working_tree_dirty**: 提交前包含本任务新增文件；提交后干净
- **patch_digest**: `src/contracts.rs`（新）、`crates/cloud-node-xdp-common/src/lib.rs`（合同段）、`src/lib.rs`（模块导出）
- **contract_versions**: `XDP_ABI_VERSION = 1`（首次显式编号；本次未改任何既有 map 布局）

## 交付内容

### eBPF 共享合同（cloud-node-xdp-common，固定 repr(C) ABI）

| 合同 | 类型 | 尺寸 | 说明 |
|---|---|---|---|
| FlowKey | `XdpFlowKey` | 48 B | security_domain + family + proto + client/service tuple + service_id；服务 tuple = 节点侧 VIP；共享端口下 service_id 携带 listener 身份，不伪造 tenant（I06/I11） |
| FlowRecord | `XdpFlowRecord` | 64 B | created / absolute_deadline / idle_deadline / flow_incarnation / owner_epoch / policy_generation / state / owner_kind / validation；absolute_deadline 重传不续期（I02/I03），idle 只随当前 incarnation+owner 的包推进 |
| FlowEvent | `XdpFlowEvent` | 88 B | key + incarnation + owner_epoch + seq + kind + reason；旧事件不得覆盖 tuple 复用后的新状态，按 (incarnation, epoch, seq) 排序 |
| PathBinding | `XdpPathBinding` | 32 B | KERNEL=0 / AFXDP=1 / NAT=2 + queue_id + backend tuple；一条流生命周期内唯一所有者（I04） |
| BudgetConfig | `XdpBudgetConfig` | 48 B | unverified_pps / new_flow_per_sec / xsk_redirect_pps / challenge_pps / window_ns / flags；**聚合**上限，与源地址旋转无关（I03）；flags=0 全禁用 |
| PendingCap | `XdpPendingCap` | 16 B | 半开并发上限单槽值，dataplane 免二次查表 |
| DecisionReason | `XDP_DECISION_*` | u8 常量 | PASS/ACL_BLOCK/RATE_SOURCE/MALFORMED/FRAGMENT/NO_FLOW/BUDGET/NO_XSK/FLOW_TABLE_FULL/TCP_FLAG；append-only，禁止重编号（I10） |
| ParseClass | `XDP_CLASS_*` | u8 常量 | SUPPORTED/MALFORMED/UNSUPPORTED/FRAGMENTED/CONTROL；取代单一 Err→PASS 桶 |
| 状态机 | `XDP_FLOW_*` / `XDP_OWNER_*` / `XDP_VALIDATION_*` | u8 常量 | ABSENT→PENDING→VALIDATED→CLOSING→EXPIRED；validation: NONE/STATELESS/OWNER |
| ABI 版本 | `XDP_ABI_VERSION` | u32 | 任何 key/value 布局、map 语义或 dispatch 槽位合同变化必须 bump；`drop_stale_pinned_maps` 的 spec 表随布局断言同步更新 |

所有新类型加入 `unsafe_impl_aya_pod!` 列表；既有类型（Counters/CT/SNAT/Policy/RateBucket/Scratch）一并钉上编译期尺寸断言，共 13 条。

### 用户态合同（src/contracts.rs）

- `ServiceIdentity`：service_id + domain + listen tuple + protocol；接入方：config compile（EN-07 服务作用域）、flow 归属与计费（EN-09/EN-12）。
- `PathProfile`：arch/kernel/driver/attachMode/xskMode/queues/mtu/protocols/snat/fallback/**evidenceId**；支持矩阵行必须挂证据 id，无证据 = 假设不是支持（EN-30..33 / EN-00 已按此产出）。
- `NodeGeneration`：单调发布代次，`INITIAL`/`next()`；接入方：代次发布与 LKG 回滚（EN-25..29）、dataplane 每包代次标记。
- `BudgetSnapshot` + `FullBehavior`（Reject/Fallback/Evict/FailStart）：每个有界资源一行，满额行为是合同的一部分（I01/I10）；metric 标签 = `resource` 字段名，append-only。
- `XdpBudgetBreakdown` + `compute_xdp_budget(proxy_queues, frame_size, cpu_count)`：map 最坏占用（hash ≈ key+value+96B/条目，per-CPU 按 cpu 数放大）、UMEM（4096 帧×frame_size + 4×2048 描述符环，与 `xdp.rs` attach 处现有投影公式一致）、每队列一个 reactor task；输出每资源 BudgetSnapshot 行。
- 容量单位规则：entries/bytes/pps/conns/tasks 五种，记录在 `BudgetSnapshot.unit`。
- 端序规则：ABI 中所有端口字段 `*_be` 为网络序；地址为原始字节；u64 计数/时间为 host 序（eBPF 与 userspace 同机同端序，跨机序列化走 serde 文本）。

### 序列化兼容样例（测试固化）

- `PathProfile` 字段名固化为 camelCase（attachMode/xskMode/evidenceId），缺省字段反序列化兼容旧 payload。
- `BudgetSnapshot.fullBehavior` 序列化为 `reject` 等枚举串。
- `XdpBudgetConfig.flags == 0` 语义 = 全禁用，即使 rate 字段非零。

## I01～I15 责任模块映射

| 不变量 | 责任模块 | 本任务合同抓手 |
|---|---|---|
| I01 资源上限+满额行为 | `memory_governor` + `contracts::BudgetSnapshot` | FullBehavior 四类枚举，逐资源行 |
| I02 未验证不获身份 | `xdp` 准入层（EN-09） | XDP_FLOW_*/XDP_VALIDATION_* 状态机 |
| I03 聚合预算先行 | `xdp` 聚合桶（EN-07/08） | `XdpBudgetConfig` 聚合速率字段 |
| I04 单一流所有者 | `xdp` 路径选择（EN-09/10/12） | `XdpPathBinding` + owner_epoch |
| I05 代次协议 | `config_apply`/`compiled`（EN-25..29） | `NodeGeneration` + FlowRecord.policy_generation |
| I06 租户边界 | `routing`/`http_proxy_manager`（EN-18） | `ServiceIdentity.service_id` |
| I07 purge 语义 | `cache_hybrid`/`purge_barrier`（EN-23） | —（G3 合同沿用本代次机制） |
| I08 控制面断连用 LKG | `config_apply`（EN-26） | `NodeGeneration` LKG 标记 |
| I09 预算不重复发放 | `memory_governor` + `contracts::compute_xdp_budget` | 总预算纯函数，CPU/队列数显式入参 |
| I10 决策可观测 | `xdp` counters + `pipeline_metrics`（EN-03） | `XDP_DECISION_*` append-only 码 |
| I11 身份信任分级 | `client_ip`/`toa`/`ssl`（EN-18） | FlowRecord.validation 分级 |
| I12 恢复正确性 | `cache` 持久化（EN-24） | FlowEvent incarnation/epoch 防旧事件复活 |
| I13 后台工作有界 | `memory_governor`/`logging`（EN-16/17） | BudgetSnapshot 覆盖 tasks/bytes |
| I14 能力声明一致 | `runtime_mode` + PathProfile（EN-01/33） | PathProfile.protocols 显式列表 |
| I15 组合身份可追踪 | `xdp` pin/spec + `compiled`（EN-29） | `XDP_ABI_VERSION` + spec 表 + evidenceId |

## 兼容性

- 本次**未修改任何既有 map 布局**：XdpCounters、CT、SNAT、Fwd、Rate 等全部只加断言，尺寸未变 → pinned map 复用语义不变。
- 新增合同类型当前无 map 引用——它们是 EN-05..EN-10 落地时的 ABI；先固化布局再消费，避免"边写边改"。
- `XDP_ABI_VERSION = 1` 编号从本提交起生效；后续 EN-03（counters→per-CPU）等布局变化需 bump 并扩 spec 表。

## 验证命令与结果

| 命令 | 结果 |
|---|---|
| `cargo check`（crates/cloud-node-xdp-common，default + --all-features） | PASS，0 error；13 条静态尺寸断言全部成立 |
| `cargo check --lib`（主 crate） | PASS，7 个存量 dead-code 警告，无新增 |
| `cargo test --lib contracts::` | 6/6 PASS |
| `cargo test --features aya`（common crate） | 7/7 PASS |

未运行项与原因：eBPF 编译无需重跑——本次未改 `crates/cloud-node-xdp-ebpf`；netns 冒烟无行为变化可验证。

## 遗留与边界

- `compute_xdp_budget` 的 map 字节数是带余量的**估计值**（96B/条目开销），用于预算比较，不是内核精确记账；精确 memlock 占用仍以 `bpf map` 工具实测为准。
- spec 表（`xdp.rs::drop_stale_pinned_maps`）与 `compute_xdp_budget` 的容量常量是两处手工同步——EN-04 拆分时建议收敛为单一来源。
- rate-limit map 的满额行为当前如实记录为 `Fallback`（fail-open + 计数）；EN-05/06/07 将其收紧为聚合 Reject。
