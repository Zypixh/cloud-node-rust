# Implementation Plan: AnyTLS SNI Relay Upload Stability

## Overview

修复 AnyTLS 经 cloud-node-rust SNI passthrough 上传时的断流和长时间停顿。现有证据表明，外层 TCP 线路存在真实丢包/乱序，但 relay 的压力下单方向 idle timeout 会把正常的上传等待、TCP 重传和源站无响应误判为断流；metrics 初始化路径还存在 DashMap 重入死锁，可能把 relay 卡在流量统计位置。

目标是先保证已建立的双向 tunnel 不因单方向暂时无应用数据而被关闭，再修复统计死锁，最后用 mihomo、双链路抓包和 close reason 日志验证线路问题不会再被 relay 放大。

## Architecture Decisions

- 已建立 TCP/SNI relay 不使用 2/5/15/30 秒的单方向压力超时。连接 admission、TLS/SNI 握手超时和 L4 攻击防御继续保留，用于防止未建立连接和明显攻击路径耗尽资源。
- 如果业务确实需要清理长期空闲 established tunnel，必须使用双向共享活动状态、显著更长的宽限时间和明确的可观测 close reason，不能分别对 `ClientToBackend` 与 `BackendToClient` 调用 `reader.read()` 计时。
- `ServerMetrics::new()` 保持为不访问 `METRICS.servers` 的纯构造过程；需要的 server 数量在进入 `DashMap::entry()` 之前计算，避免在 entry 写锁内重入同一张表。
- SNI/AnyTLS 的 benign drain 先保持有界，但将上传方向的窗口与 tunnel 选项隔离，避免普通 TCP 和跨地域 AnyTLS 共用不合适的固定值。
- 默认保持 `relay.zeroCopy: false` 作为首轮稳定性基线。zero-copy 只在 copy relay 修复并验证后单独做 A/B。

## Task List

### Phase 1: Establish the Baseline

#### Task 1: Add incident observability and a reproducible relay fixture

**Description:** 在 relay 测试和运行日志中明确记录方向、阶段、累计上行/下行字节、pressure timeout、benign drain 和 L4 drain。建立一个模拟“客户端持续上传、源站暂时不返回应用数据”的双向 socket fixture，避免只依赖公网测速复现。

**Acceptance criteria:**

- [ ] 测试可以注入 memory/FD pressure，并让 backend 在上传期间保持响应方向静默。
- [ ] relay 结束时可以区分 `PressureIdleTimeout`、`BenignIo`、`DrainTimeoutAfterBenign`、`L4Drain` 和 `Clean`。
- [ ] 日志或测试结果能同时给出 `bytes_received` 和 `bytes_sent`，不暴露 AnyTLS 密钥或完整 payload。

**Verification:**

- [ ] 运行新增的定向 relay 测试并检查 close reason 与字节计数。
- [ ] 在节点日志中搜索 `relay idle timeout under pressure`、`TcpPressureIdleClose` 和 `drained_connections`。

**Dependencies:** None

**Files likely touched:**

- `src/tcp_proxy.rs`
- `src/l4_defense.rs`

**Estimated scope:** Small

#### Task 2: Capture a two-leg production baseline

**Description:** 在不改行为的情况下，用 mihomo 固定 AnyTLS 配置重复执行 8 MiB、64 MiB 上传，并在节点同时抓取客户端到 8443 以及节点到 SNI backend 的两条 TCP 流，记录内存/FD pressure 和 relay close reason。

**Acceptance criteria:**

- [ ] 至少有一次慢上传和一次正常上传样本。
- [ ] 每个样本都能关联外层连接、backend 连接、开始/结束时间和最终 close reason。
- [ ] 能区分线路重传造成的慢速与 relay 主动关闭造成的截断。

**Verification:**

- [ ] 外层抓包统计 retransmission、SACK、RST、FIN、zero window 和最大应用数据间隔。
- [ ] 节点日志与抓包时间线能够对齐。

**Dependencies:** Task 1

**Files likely touched:**

- None; temporary capture/config files only

**Estimated scope:** Small

### Checkpoint: Baseline

- [ ] 已保存慢/快上传对照结果。
- [ ] 已确认生产是否启用 `relay.zeroCopy`。
- [ ] 已确认 incident 时是否出现 `PressureIdleTimeout` 或 `TcpPressureIdleClose`。

### Phase 2: Fix Established Relay Lifecycle

#### Task 3: Remove the per-direction pressure timeout from established relays

**Description:** 修改 relay 生命周期，使压力治理不再因为一个方向暂时没有应用层数据而结束整个双向 tunnel。首选方案是 established TCP/SNI relay 不启用该 timeout；保留连接 admission、握手/首字节 timeout 和 L4 防御。若必须保留 established 清理，则引入 `RelayOptions` 明确控制，并只使用双向共享活动时间和长宽限期。

**Acceptance criteria:**

- [ ] 客户端持续上传、backend 响应方向静默超过原 2/5/15/30 秒时，relay 不会提前结束。
- [ ] 客户端真正关闭、backend EOF、hard I/O error 和 L4 cancel 仍能正确结束连接。
- [ ] `relay.zeroCopy: true` 与 async-copy 两条路径具有相同的超时语义。
- [ ] `PressureIdleTimeout` 不再作为正常 established 上传的默认关闭原因。

**Verification:**

- [ ] 添加并运行持续上传/静默响应测试。
- [ ] 运行 half-close、cancel、hard-error 和 large-payload 测试。
- [ ] `cargo check --all-targets` 通过。

**Dependencies:** Task 1

**Files likely touched:**

- `src/tcp_proxy.rs`
- `src/memory_governor.rs` only if the timeout API needs to be narrowed

**Estimated scope:** Medium

#### Task 4: Fix metrics DashMap re-entry deadlock

**Description:** 重构 `RuntimeDistinctIpTracker::new()` 和 `record::get_or_create()` 的构造顺序。`ServerMetrics::new()` 不得在 `DashMap::entry().or_insert_with()` 闭包内读取 `METRICS.servers`；将 server 数量或预算作为已计算参数传入，或者使用不依赖 map cardinality 的独立预算快照。

**Acceptance criteria:**

- [ ] 空 metrics 表上首次 `get_or_create(missing_server_id)` 在有界时间内返回。
- [ ] 并发创建多个不同 server id 不死锁、不 panic，tracker capacity 仍有上限。
- [ ] relay 在累计 1 MiB、EOF 和 hard error 统计时不会卡在 metrics 初始化。

**Verification:**

- [ ] 增加 `tokio::time::timeout` 包围的首次创建回归测试。
- [ ] 运行 `cargo test memory_governor::tests -- --nocapture`。
- [ ] 运行 TCP/SNI relay 全部定向测试，确认不再出现超过测试上限的挂起。

**Dependencies:** Task 1

**Files likely touched:**

- `src/metrics.rs`
- `src/tcp_proxy.rs` tests if a relay regression test is needed

**Estimated scope:** Small

### Checkpoint: Core Fixes

- [ ] pressure 静默响应测试通过。
- [ ] metrics 首次创建和 relay 统计测试通过。
- [ ] `cargo check --all-targets` 通过。
- [ ] 没有新增持锁跨 `.await`、未绑定 task 或无界 buffer。

### Phase 3: Harden Shutdown and Rollout

#### Task 5: Revisit benign drain and SNI half-close behavior

**Description:** 在 pressure timeout 修复后，单独处理 backend benign close 的上传尾部窗口。将 SNI/AnyTLS 的 upload drain 设置为独立策略，基于跨地域 RTT 和重传观察选择 10-15 秒的初始窗口；保留明确上限，避免 backend 已断开时无限保留连接。

**Acceptance criteria:**

- [ ] backend 响应方向 benign close 后，延迟到达的上传尾部在窗口内完整转发。
- [ ] 超过窗口后连接以 `DrainTimeoutAfterBenign` 结束，字节计数和方向信息正确。
- [ ] backend clean EOF 仍不会在上传未结束时向 AnyTLS 客户端过早发送 FIN。

**Verification:**

- [ ] 增加 2 秒以上延迟、backend reset、client half-close 和 clean EOF 测试。
- [ ] 运行 SNI passthrough half-close regression test。

**Dependencies:** Tasks 3 and 4

**Files likely touched:**

- `src/tcp_proxy.rs`
- `src/http_proxy_manager.rs` only for close reason/access-log handling

**Estimated scope:** Small

#### Task 6: Make pressure/L4 close reasons operationally actionable

**Description:** 确保 `PressureIdleTimeout`、L4 drain 和 hard relay error 在 access log、metrics 和节点日志中不会都表现为成功 200。成功转发后的 benign close 可以保持非源站失败，但压力主动关闭需要单独计数和告警维度。

**Acceptance criteria:**

- [ ] 可以按 server、peer、方向和 close reason 聚合断流数量。
- [ ] `L4 drain` 日志能够显示受影响的协议和连接数。
- [ ] 不会因为一次正常 AnyTLS 收尾把源站健康状态标记为失败。

**Verification:**

- [ ] 使用模拟 close reason 检查 access log 和 metrics。
- [ ] 检查现有 SNI/HTTP/TCP 统计兼容性。

**Dependencies:** Tasks 3 and 4

**Files likely touched:**

- `src/tcp_proxy.rs`
- `src/http_proxy_manager.rs`
- `src/l4_defense.rs`
- `src/metrics.rs`

**Estimated scope:** Medium

#### Task 7: Run live mihomo A/B and staged rollout

**Description:** 使用固定 AnyTLS 配置做修复前后对照。首轮固定 `relay.zeroCopy=false`，只验证 async-copy；确认稳定后再单独测试 zero-copy。部署时按小范围节点逐步放量，保留旧二进制和抓包/日志回滚条件。

**Acceptance criteria:**

- [ ] 8 MiB 和 64 MiB 上传均能完整返回，不能出现 relay 主动提前 FIN/RST。
- [ ] `PressureIdleTimeout`/`TcpPressureIdleClose` 在正常上传中为零或显著下降。
- [ ] 线路重传仍可能存在，但不再导致应用层截断；慢速程度与直接 TCP 基线接近。
- [ ] zero-copy A/B 不引入新的 close reason、死锁或数据计数不一致。

**Verification:**

- [ ] `cargo check --all-targets`。
- [ ] `cargo test memory_governor::tests -- --nocapture`。
- [ ] TCP/SNI relay 定向测试和完整测试集。
- [ ] mihomo 重复上传测试、双链路抓包、节点 close reason 对齐。

**Dependencies:** Tasks 5 and 6

**Files likely touched:**

- None beyond already reviewed implementation and test files

**Estimated scope:** Medium

### Checkpoint: Complete

- [ ] 所有 acceptance criteria 完成。
- [ ] 慢上传样本可以解释为线路重传，而不是 relay 截断。
- [ ] 没有 metrics 死锁或测试挂起。
- [ ] 已保留部署回滚方案和修复前后指标对照。

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| 去掉 established pressure timeout 后慢连接占用资源 | High | 保留 admission/握手防御；对真正双向长期空闲连接使用更长且可观测的清理策略；监控 active relay 和 FD 使用量 |
| 修复 metrics 构造顺序导致预算计算变化 | Medium | 保持 tracker capacity 上限；增加并发创建和 capacity 测试 |
| 延长 benign upload drain 增加连接保留时间 | Medium | 只对 SNI/AnyTLS 生效，设置硬上限并记录 drain duration |
| 线路仍有丢包，误判修复失败 | Medium | 同时比较 retransmission、relay close reason 和完整 payload；不要只看吞吐 |
| zero-copy 与 async-copy 行为不一致 | Medium | 首轮固定关闭 zero-copy；后续单独做同一 fixture 的 A/B |

## Open Questions

- 生产 incident 时是否能看到 `PressureIdleTimeout` 或 `TcpPressureIdleClose`？
- 当前节点的 `memory_pressure_level`、FD pressure 和 connection admission utilization 是否达到 80%/90% 阈值？
- 生产是否显式开启了 `relay.zeroCopy`？
- 是否可以在节点上同时抓取客户端到 8443 和节点到 SNI backend 两条 TCP 流？

