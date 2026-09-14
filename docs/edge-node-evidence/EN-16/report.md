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

## 第二切片（本提交）：listener 配额池 + disk/spool 账本

### listener 配额池

未识别租户流量现在落在 listener 级隔离池上：`MemoryGovernor::try_admit_listener(key, class)` 在节点级 class permit 之外要求一个 per-(listener, class) 槽位：

- cap = `ceil(class_limit / 活跃 listener 数)`，下限 `LISTENER_POOL_FLOOR=16`——新 listener 永不被饿死，单一 listener 独占时可达整机预算；池只约束**新准入**，不抢占在途连接。
- map 有界（4096 条 (listener,class) 项，满时先回收空闲池，仍满则显式拒绝并计数）。
- RAII `ListenerPoolPermit`，释放即归还槽位并删除空池。
- 接入全部 6 个准入点：HTTP kernel accept、HTTP AF_XDP、TCP kernel accept、TCP AF_XDP bypass（reactor 传 `session.flow.local_addr`）、H3、UDP session。拒绝路径记录 L4 事件（`phase=listener_pool`）+ `listener_pool_rejects` 计数。
- 透出：`GovernorSnapshot.listener_pool_{active,tracked,rejects}`；perf monitor `PerfSample` 带 `listener_pool_active`/`listener_pool_rejects`。

### disk/spool 账本

governor 新增统一磁盘账本，reserved（在途预约，RAII）与 committed（持久占用，绝对上报）分开，杜绝物理观测与逻辑预约双算：

- `try_reserve_disk(class, bytes)`：逐类 cap（注册值或默认）+ 聚合包络（全部类预算之和）双校验，拒绝显式计数。
- `DiskPermit::commit()`：预约转持久占用；未 commit 的 drop 释放预约。
- 类预算注册：cache `sharedMaxBytes`/`maxDiskBytes` → `CacheL2`；Mace cache+pool+checkpoint 容量 → `MetricsDb`；默认 `ConfigArtifacts=2GiB`、`NodeState=256MiB`。
- 写入点：IP 库 artifact 下载前预约、安装成功后上报 committed；`atomic_write` 状态文件在写期间持 `NodeState` 预约（拒绝返回 `QuotaExceeded` io 错误，不静默）。
- 透出：`disk_{budget,reserved,committed}_bytes` + `disk_rejects`；perf monitor 同步透出。

### 第二切片验证

- 单测 5 项：flood listener 隔离（新 listener 保公平份额）、RAII 释放即删池、map 有界、reserve/commit/release 与类 cap、committed 绝对上报。
- 全量 667 lib 测试 + 18 集成测试通过；EN-10 流接管探针在带 listener 池的数据面上重跑仍全绿（x86-build）。

## 剩余缺口（如实声明，EN-16 未整体完成）

1. **投影是校准模型而非精确内核计数**：LPM trie 惰性分配按最坏值计费；attach 后可用 bpftool memlock 复核。
2. memory/aggregate/syn 压力通道无迟滞（利用率通道已有）。
3. listener 池的 e2e 证据为单测 + 探针回归；真实 listener 配置下的洪泛隔离尚需带业务 server 的环境验证。
4. tenant 级配额未实施——本仓库无 tenant 概念，listener 池是当前的隔离粒度。

回退方式：账本与池均为纯增量——移除 `ensure_bpf_map_budget`/`audit_loaded_map_specs`/`try_admit_listener`/`try_reserve_disk` 调用即回到旧行为；迟滞移除即回到无状态即时等级。不放松任何既有硬上限。
