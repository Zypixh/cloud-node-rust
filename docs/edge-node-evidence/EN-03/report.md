# EN-03 — 正确低成本的基础观测

## 范围与改动

| 层 | 改动 |
|---|---|
| eBPF (`crates/cloud-node-xdp-ebpf/src/main.rs`) | `XDP_COUNTERS` 由 `Array<XdpCounters>` 改为 `PerCpuArray<XdpCounters>`；新增 `counter_tx()`/`counter_acl_blocked()`；`count_action` 对 `XDP_TX` 记 `tx`（不再漏记、也不再误记为 PASS）；`block_action` 命中 ACL 阻断时记 `acl_blocked` |
| 共享 ABI (`crates/cloud-node-xdp-common/src/lib.rs`) | `XdpCounters` 增加 `tx`、`acl_blocked` 字段（144B）；`XDP_ABI_VERSION` 1→2；静态尺寸断言同步 |
| 用户态 (`src/xdp.rs`) | `read_counters`/`read_pinned_counters`/`zero_counters` 改为 `PerCpuArray` API；新增 `sum_percpu_counters` 逐 CPU saturating 聚合；`drop_stale_pinned_maps` spec 表改为 `MapType::PerCpuArray`；`XdpStatusSnapshot`/`status`/`dump-maps` 输出新增 `tx`、`aclBlocked` |

## 不变量核对

- 多 CPU 并发 RX 不再共享单一槽位做读-改-写：每 CPU 写自己的槽，丢计数在结构上被消除（原 `Array` 的多核 `saturating_add` RMW 竞态修复）。
- 动作计数语义：`packets`（尝试数）与 `pass/drop/redirect/tx`（终结动作）分字段；`redirect` 是 XSK 投递**尝试**，`xsk_drops` 是投递**失败**，两者继续分列，不混淆为交付数。
- tail-call 终结计数：所有 7 个入口（`cloud_node_xdp` + 6 个 NAT dispatch）均自行 `count_action`，tail-call 后父程序不再执行的路径已有覆盖，本次未改变该结构，仅让 `XDP_TX` 有了独立桶。
- ACL 阻断（`acl_blocked`）与 rate-limit（`rate_limited`）、内部 drop 可区分（I10：DROP 原因可观测）。

## 旧 pin 处理（回退语义）

`XDP_COUNTERS` 仅含遥测计数、不含连接状态。spec 表改为 `PerCpuArray` 后，旧版 `Array` pin 在 attach 时被 spec 校验判为不匹配 → **显式 unlink 并重建**，旧计数器不迁移（接受丢失——计数器是易失遥测）；连接 map（CT/SNAT/限流桶）完全不受影响，满足"不通过清空连接 map 迁移计数器"。新代码读取旧 ABI map 会因类型不符被 `PerCpuArray::try_from` 拒绝，无静默兼容。

## 验证证据

环境：x86-build OrbStack VM（x86_64 Linux），eBPF 在 build-node（aarch64）以 `bpfel-unknown-none` release 构建，object sha256 `1532610c4574abb9f66b553f7ddb9bbee53bfe6bdb3f40ee5d8c6fc6345bb20f`。

| 验证 | 命令/方法 | 结果 |
|---|---|---|
| 用户态编译 | `cargo check --lib`（x86-build） | PASS |
| 单测 | `cargo test --lib xdp` / `percpu` | 95/2 pass；新增 `percpu_counter_aggregation_sums_all_cpu_slots`、`..._saturates_instead_of_wrapping` 覆盖多槽聚合与饱和语义 |
| common ABI | `cargo test -p cloud-node-xdp-common` | 7 pass（含 144B 尺寸断言、ABI v2） |
| 真实 eBPF attach | `xdp raw-smoke` on veth-en03 + netns en03 | attach 成功，`/sys/fs/bpf/cloud-node-xdp/XDP_COUNTERS` 以 PerCpuArray 创建（spec 校验通过） |
| 跨进程读 pin | 流量注入后 `xdp dump-maps` | packets=7、redirect=6、pass=1 与发送（6×UDP:443 + 1×UDP:9999）精确一致；`tx`/`aclBlocked` 字段导出 |

多 CPU 不丢计数的结构保证来自 PerCpuArray 本身；并发注入下的差值对比留待 EN-31 容量测试做定量证据。

## 成本基线

- 单槽 → per-CPU 槽：写路径仍是单次 `get_ptr_mut` + 一次 saturating_add，无额外查找；内存从 144B 增至 144B×CPU 数（VM 4 CPU ≈ 576B），可忽略。
- 用户态聚合每次读遍历 nr_cpus 个槽（status 刷新周期 10s），纳秒级开销。

## 遗留

- T16（观测成本基线）定量数据：建议并入 EN-31 长跑容量测试。
- kernel 6.1 verifier 复测：本次仅新增两个字段写入，程序复杂度未上升，风险低，但未在 6.1 实测。
