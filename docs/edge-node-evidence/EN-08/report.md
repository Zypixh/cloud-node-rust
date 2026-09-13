# EN-08 — 源地址公平性与有界状态维护

状态：**VERIFIED（veth/netns + 全节点进程）**。基线 commit `ca30b32`（EN-07）。

## 交付

### eBPF（ABI v7）

- `XdpRateLimitConfig` 扩展为 32B：`udp_pps` / `tcp_syn_pps` / `window_ns` + `v4_prefix_len` / `v6_prefix_len`（新增两字段，size assertion 锁定布局）。
- 前缀公平性：`rate_limited_v4` 在查桶前按 `v4_prefix_len` 掩码源地址（`0` 或 `>=32` = 每地址；移位严格界内，无 UB）；`rate_limited_v6` 按字（u64×2）掩码，`hi_keep=min(len,64)`/`lo_keep=saturating_sub(64)`，无 shift-by-64、无变长字节循环。
- `rate_limited_v6` 压回 5 寄存器签名（src_hi/src_lo/meta/now），消除 r11 栈传参——`llvm-objdump` 零 r11 引用。
- 满表回退：`rate_bucket_hit_*` insert 失败 → `ratelimitMapFull` 计数 + 不视为超限——该包已由更早的聚合 unverified 预算兜底，不会 fail-open 也不会静默丢包。

### 用户态

- `xdp.rateLimit` 新字段：`prefixV4Len`（0=per-IP，1..=32 前缀共享桶）、`prefixV6Len`（0=per-IP/128）、`gcAfterWindows`（默认 8）。
- `scaled_rate_limit_config()`（纯函数，可测）：`windowMs → window_ns` saturating 换算；前缀长度 clamp 到 32/128；压力缩放（High÷2/Critical÷4）对非零基数保底 1。
- `sweep_rate_buckets()`（挂 5s rule-sweeper tick）：`linux::sweep_rate_maps` 回收空闲超过 `windowMs × gcAfterWindows` 的桶；**每表每趟最多删 8192 项**，剩余下趟继续；扫描上界=map 容量（262144），保证进度。
- `CLOUD_NODE_XDP_TEST_PRESSURE`：debug-only 压力注入钩子，仅影响 XDP 限流缩放路径；release 构建不可达。

## 验证

| 证据 | 结果 |
|---|---|
| verifier / 回归矩阵 | T01 28/28、T02 4/4、T03 3/3、T04 2/2（kernel 7.0 接受全部 11 程序） |
| Rust 单测 | xdp 模块 77 过；新增 `scaled_rate_limit_config_window_prefix_and_floor` |
| 前缀公平（probe A） | 3000 包随机源同 /24 → 仅 **1 个桶**，`pass=213, rateLimited=2787` |
| 每地址（probe B） | 5 源×600 包 → **5 个桶**，`pass=1000, rateLimited=2000` |
| 有界 GC（probe C） | 12005 项 → 首趟恰好回收 **8192** → 3813 → 次趟 0；churn 不永久占表 |
| GC 后正常流量（C2） | `pass=6, drop=0` |
| 满表回退（probe D） | 280k 独立源 → map 精确停在 **262144**，`ratelimitMapFull=17856`，聚合预算兜底全过 |
| 满表后新源（D2） | 10 包 → `ratelimitMapFull=10, pass=10`，逐包落到显式计数器 |

e2e 工具：`scripts/edge/en08_rate_probe.py`（netns 拓扑 + 全节点 + AF_PACKET 随机源 + bpftool 按 id 读 map 计数）。

## 与验收对照

- 随机源 churn 不导致永久失去限制 ✓（GC 时间线 12005→3813→0）
- 源桶满时聚合预算继续 ✓（D/D2：map-full 计数 + 聚合路径裁决）
- NAT 出口合法样本不误伤 ✓（T03/T04 全过；C2 legit 通过）
- windowMs 正确换算 ✓（单测 `×1e6` saturating + e2e 窗口语义生效）
- 前缀掩码无非法移位 ✓（eBPF 界内 clamp + 单测 clamp 断言）
- 无无界 map 迭代 ✓（删除 8192/趟封顶；扫描受 map 容量上界约束）
- 不把近似计数描述成精确配额 ✓（configuration.md 明确标注"近似"）

## 限制（如实记录）

- per-source 限制器在 Normal 压力下整体关闭（既有语义：聚合预算提供基线保护，见 EN-07）。
- 固定窗口限流是近似语义：窗口边界有突刺容忍；精确配额由聚合预算承担。
- GC 扫描上界是 map 容量（262k），单趟删除封顶 8192——极大表完全排空需多趟 sweep，属有界而非无界。
- `CLOUD_NODE_XDP_TEST_PRESSURE` 仅 debug 构建生效，release 不编译该分支。
