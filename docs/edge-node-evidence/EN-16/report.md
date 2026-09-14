# EN-16: 扩展统一资源治理 — kernel-BPF map 账本与压力迟滞（首个已验证切片）

Base commit: `20f8615` (EN-09)
eBPF object: `data/cloud-node-xdp-ebpf.o` sha256 `00f0e34ee5350401152ae20381220f07520b6fa9d6db6cfb0d494b1b21056618`（本切片未改 eBPF，对象不变）
环境: OrbStack x86 VM, kernel 7.0.14-orbstack, cgroup v2, veth 拓扑 (en2-a/en2-b)

EN-16 是 L 规模条目。本切片交付并验证了其中两个具体缺口：**eBPF map 常驻内核内存账本** 与 **利用率驱动压力等级的迟滞**。剩余缺口如实列于文末。

## 问题

XDP 对象 pin 住 31 个 eBPF map，实测 memlock 约 365 MB（FLOW_ACCT 独占 ~130 MB）。这是预分配、不可回收的内核内存，此前不进入任何预算：

- attach 前的容量校验只覆盖条目数/单 map 尺寸，不覆盖聚合内核内存；
- AF_XDP UMEM 预算与 BPF map 各自合法但联合可能超出节点内存包络；
- spec 表（`bpf_map_specs`）若与 `#[map]` 声明漂移，账本静默漏计。

同时 `current_pressure_level()` 是纯函数：连接利用率在 85% 边界抖动会让 Elevated/High 每次快照翻转，保护行为（超时、阈值、worker 数）随之震荡。

## 实现

### kernel-BPF 账本（`src/xdp/linux.rs`、`src/memory_governor.rs`）

- `GovernorSnapshot.kernel_bpf_budget_bytes = state_budget`（8% 节点内存，cgroup 感知）。
- `bpf_map_specs()` 提取为唯一 map 真源（31 map，与全部 `#[map]` 声明逐一核对一致）。
- `projected_bpf_map_bytes()`：按 map 类型计费最坏情况 pin 内存——hash +64B/entry、per-CPU map ×nr_cpus、LPM trie 惰性分配但按最坏值计、array/prog-array/xsk +8B/entry。在 kernel 7.0 上与实测 memlock 偏差 ~5%（投影 382,756,816 vs 实测 ~365 MB，模型偏保守）。
- `ensure_bpf_map_budget()`：在 `loader.load_*` **之前**校验投影 ≤ 预算；超预算显式 `Err`，拒绝 attach，不静默 pin 未入账内存。
- `audit_loaded_map_specs()`：load 后逐一核对对象实际声明的 map（名称+类型+key/value/max_entries 经 `MapInfo` 内核查询）必须命中 spec 表；漂移即显式失败——账本无法被静默绕过。
- `xdp dump-maps` 透出 `kernelBpfBudget.{projectedBytes,budgetBytes}`。

### 压力迟滞（`src/l4_defense.rs`）

- `utilization_pressure_level_hysteretic()`：进入带 70/85/95（与 `level_from_pct` 一致），退出带 60/75/90。升级立即生效；降级须跌破退出阈值。
- 迟滞只作用于利用率标量通道（connection/fd/quic pct 的 max）；memory level、aggregate surge、syn-defense 通道保持即时（各自有独立动态）。
- `pressure_level_from_utilization_pct*` 纯函数不变，供测试与无状态合成使用；迟滞状态仅存于 `current_pressure_level*` 查询路径。

## 验证

探针 `scripts/edge/en16_bpf_budget_probe.py`（原始输出 `probe.json`）：

| 阶段 | 结果 |
|---|---|
| A 账本可观测 | `projectedBytes=382756816 ≤ budgetBytes=412300738`，非零且落在预算内 |
| B 正向 attach | 正常预算下 XDP 成功 attach |
| C 预算拒绝 | cgroup `memory.max=4GiB` → 预算缩至 ~341 MiB < 投影；节点退出，日志显式报 `eBPF map projected memory 382756816 exceeds kernel-bpf budget 342530457`；无 link pin |

回归：EN-09 pending 探针在带新门禁的 attach 路径上重跑 5/5 通过；本地 `xdp` 78 + `l4_defense` 38 单测全过；x86-build lib 编译干净。

既有验收项核对（审计结论，非本切片新代码）：

- 取消/超时释放 permit：全部准入 permit（`AdmissionPermit`/`ZeroCopyRelayPermit`/`UdpQueueBytePermit`/`ActiveIpPermit`）为 RAII `Drop`，Tokio 取消路径同样释放。
- 多队列不独占整机预算：AF_XDP UMEM 投影对**所有**队列求和后比对单一节点预算（`src/xdp/linux.rs` attach 前校验）。
- 控制面预留：`ConfigSyncBudget.commit_reserve_bytes` 保留 config commit 容量。
- 物理观测与逻辑账目不双算：准入账本只记逻辑估计值；RSS/cgroup 仅作观测与预算推导输入，不再二次计费。

## 剩余缺口（如实声明，EN-16 未整体完成）

1. **listener/tenant 配额池未实施**：`ServiceIdentity` 合同存在且 `service_id` 已随 `XdpUdpFwdRule` 携带，但所有 `try_admit` 都是节点级；未知租户流量没有 listener 级隔离池。
2. **投影是校准模型而非精确内核计数**：LPM trie 惰性分配按最坏值计费；attach 后可用 bpftool memlock 复核。
3. **无 disk/spool 账本**：本地日志/缓存盘写入沿用各自配置上限，未纳入 governor。
4. memory/aggregate/syn 压力通道无迟滞（利用率通道已有）。

回退方式：账本纯增量——移除 `ensure_bpf_map_budget`/`audit_loaded_map_specs` 调用即回到旧 attach 行为；迟滞移除即回到无状态即时等级。两者都不放松任何既有硬上限。
