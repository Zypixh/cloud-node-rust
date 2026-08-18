# Implementation Plan: Process-Live but All Connections Reset

## Overview

修复 cloud-node-rust 运行一段时间后进程仍在、但新连接普遍被重置，只有 `cloud-node restart` 后恢复的问题。当前只完成静态分析，因此不能把某一条链路称为已证实根因；计划先建立故障阶段和资源证据，再按“会被 restart 清空的共享状态”优先修复。

TOA 未开启时，`src/toa.rs` 的 `connect_with_toa` 会直接走普通 `TcpStream::connect`，因此 TOA 端口池耗尽不是本次 `isOn=false` incident 的直接解释。但 TOA 的 enabled 分支仍存在超时、TLS 失败、取消和内核删除失败时的租约清理缺口，必须作为独立的资源生命周期缺陷修复。

## Static Evidence and Priority

| Priority | Hypothesis | Static evidence | Why restart appears to help | First proof |
| --- | --- | --- | --- | --- |
| P0 | 源站状态全部被标记 down | 每个源站累计 5 次失败后进入 down；TCP 选路会排除 down 源站；只有成功连接或 60 秒清理任务才能恢复 | restart 清空 `ORIGIN_STATE_MANAGER` 的内存状态 | 日志中的 `marked down`、`No healthy backends`、源站状态与时间线 |
| P0 | FD/连接资源耗尽或 stale relay 持有资源 | accept 对 `EMFILE/ENFILE` 无限重试；FD 快照有缓存；普通 TCP relay 没有默认 established idle timeout | restart 关闭所有 socket/task，释放 FD 和准入计数 | `/proc/<pid>/fd`、`EMFILE/ENFILE`、active relay、FD pressure |
| P1 | L4 防御误封或 fail-closed | 每个 accept 都可能记录 churn；精确计数容量饱和时高置信事件 fail-closed；还会按 IP/prefix block 并 drain | restart 清空本地防御状态；若未落到外部防火墙，表现与恢复一致 | `defense status`、block/prefix/saturation/drain counters |
| P1 | listener worker 失管 | accept worker 是 detached task；子 worker 失败只记日志，未由 supervisor 重启 | restart 重建 listener 和 worker 集合 | listener ready/worker heartbeat、fatal accept 日志 |
| P1 | XDP/AF_XDP 数据面卡死 | XDP 路径可把流量 redirect 到 userspace bridge；运行时需要显式确认 redirect 和 bridge 状态 | restart 重新 attach/detach 并清理 runtime state | XDP status、redirect/drop/map-miss、bridge heartbeat |
| P2 | relay/metrics 取消路径或热路径阻塞 | relay 在多个 await 后才释放业务资源；metrics 记录在 relay 内；当前 `get_or_create` 已先计算 map 长度，再进入 `entry`，历史 DashMap 重入死锁不是当前首要证据 | restart 清空挂起 task 和运行时 map | relay close reason、task/registry count、metrics creation latency |
| P2 | TOA lease leak | enabled 分支的 allocation/cleanup 不完全 RAII | restart 重置 allocator 并刷新内核映射 | 仅在有效配置 `isOn=true` 时检查 TOA pool/DEL 错误 |

## Architecture Decisions

- 将“新连接失败”拆成 `accepted -> defense -> admission -> protocol handshake -> route -> origin connect -> relay` 阶段；任何阶段都必须有计数和可关联的 close reason。
- 源站熔断使用有界的 `down -> half-open probe -> up/down` 状态机。不能因为瞬时故障把所有源站永久排除，也不能把本地资源错误当成源站错误。
- FD 保护同时使用真实 FD 快照和应用层估算预算，并预留 listener、日志、控制面和诊断 FD 的硬余量。
- established relay 的清理使用双向共享活动时间或明确的最大生命周期；不使用一个方向的短读超时去关闭仍在合法上传的 tunnel。
- 所有会计资源使用 RAII/drop 语义；清理失败不能阻止进程侧租约、permit 或 registry 计数归还，并通过后台重试/对账处理外部状态。
- L4 防御的 fail-closed 行为必须按事件置信度、作用域和计数容量显式配置；任何 prefix block 或 connection drain 都要记录范围、持续时间和数量。
- XDP 只有在 redirect map、AF_XDP queue 和 userspace bridge 都 ready 后才允许 redirect；bridge 失活必须自动回退 PASS 或按配置 fail-start。
- listener worker 必须由 supervisor 持有句柄、记录状态并按 generation 重启；不能只依赖一个 detached task 的日志。
- 首轮上线固定关闭 zero-copy 和 XDP（若业务允许），先验证普通 async-copy TCP/HTTP/TLS 路径；TOA 也保持关闭，之后单独做功能验证。

## Task List

### Phase 0: Incident Classification and Observability

#### Task 1: Add connection-stage and close-reason telemetry

**Description:** 在 HTTP、TLS、TCP/SNI 和 upstream path 增加稳定的 connection id，记录每个连接最后完成的阶段、reject/error 分类、server/origin id、协议、字节数和 close reason。日志必须限流，不能记录 payload、token、证书私钥或完整 header。

**Acceptance criteria:**

- [ ] 能分别统计 accept、L4 block/drain、per-IP limit、memory/FD admission reject、TLS/SNI failure、route/no-backend、origin connect timeout/error、relay start/end。
- [ ] relay 结束能区分 `Clean`、`BenignIo`、`PressureIdleTimeout`、`L4Drain`、`DrainTimeoutAfterBenign` 和 hard I/O error，并带方向、phase、raw errno。
- [ ] 每条诊断记录能通过 connection id 关联 downstream 与 backend；高基数字段使用采样或聚合。
- [ ] `cloud-node defense status` 或等效本地诊断可以显示 FD、准入、registry、origin down、L4 和 listener 状态。

**Verification:**

- [ ] 为每个阶段增加无网络依赖的计数/格式化单元测试。
- [ ] 检查正常连接和拒绝连接日志不会输出敏感数据或形成每请求 warn 风暴。
- [ ] 在 incident runbook 中确认可用关键词：`EMFILE`、`ENFILE`、`No healthy backends`、`marked down`、`TcpAdmissionReject`、`TcpPressureIdleClose`、`exact counter capacity saturated`、`proxy_redirect_enabled`。

**Dependencies:** None

**Files likely touched:**

- `src/tcp_proxy.rs`
- `src/http_proxy_manager.rs`
- `src/memory_governor.rs`
- `src/l4_defense.rs`
- `src/metrics.rs`

**Estimated scope:** Medium

#### Task 2: Build deterministic failure fixtures and incident runbook

**Description:** 建立本地可重复 fixture，分别模拟 backend 全部拒绝、backend TLS 失败、慢连接/长 idle、FD admission pressure、L4 threshold/prefix block、listener accept error 和取消。形成 restart 前必须采集的只读命令清单。

**Acceptance criteria:**

- [ ] 每个 fixture 都能让测试唯一落到一个阶段和 close reason，而不是只断言客户端看到 reset。
- [ ] fixture 能验证“进程仍在但新连接不可用”与“listener 已死”是两种不同故障。
- [ ] runbook 要求 restart 前保存 PID、FD limit/usage、socket summary、defense status、origin status、listener/XDP status 和相关日志。

**Verification:**

- [ ] 运行定向测试时使用有界 `tokio::time::timeout`，不能留下后台 task。
- [ ] 检查每个 fixture 的资源计数在测试结束后回到基线。

**Dependencies:** Task 1

**Files likely touched:**

- `src/origin_state.rs`
- `src/l4_defense.rs`
- `src/net_bind.rs`
- `src/tcp_proxy.rs`

**Estimated scope:** Medium

### Checkpoint: Evidence Baseline

- [ ] 能用指标判断故障发生在 accept、defense、admission、route、origin connect 还是 relay。
- [ ] 能在不 restart 的情况下判断是 FD 耗尽、源站全 down、L4 block、listener worker 失活还是 XDP redirect。
- [ ] 现有 `tasks/plan.md` 和 `tasks/todo.md` 未被覆盖，新增计划与原 AnyTLS 工作隔离。

### Phase 1: Fix Restart-Cleared Shared State

#### Task 3: Replace origin all-down behavior with half-open probing

**Description:** 重构 `src/origin_state.rs` 的五次失败 down、60 秒自动恢复逻辑，并让 TCP route path 能在所有 origin 被标记 down 时执行受控 half-open probe。失败分类要区分 origin failure、client cancellation、local resource failure、defense reject 和 config/no-route。

**Acceptance criteria:**

- [ ] 五次真实 origin connect/TLS failure 后可以进入 down，但客户端取消、本地 `EMFILE/ENFILE`、memory admission reject、L4 drain 和 config lookup failure 不会污染 origin failure counter。
- [ ] down 状态到期后只允许有限的 half-open probe；probe 成功立即恢复，失败按 backoff/jitter 延长下一次探测，不能把所有 origin 永久排除。
- [ ] 多 origin 场景不会在同一时间无界地对所有 down origin 重试；全部 down 时仍有可解释的 `origin_all_down` 结果和告警。
- [ ] 配置热更新、origin id 变化和进程 shutdown 不会留下与新配置不匹配的状态。

**Verification:**

- [ ] 测试 5 次失败、down、到期 probe、probe 成功恢复和 probe 失败 backoff。
- [ ] 测试所有 origin down 时新连接不会静默 reset，而是留下明确 route/backend failure 记录。
- [ ] 测试不同 origin 并发失败不会因为 DashMap 状态竞争丢失成功恢复。

**Dependencies:** Tasks 1 and 2

**Files likely touched:**

- `src/origin_state.rs`
- `src/tcp_proxy.rs`
- `src/lb_factory.rs`
- `src/metrics.rs`

**Estimated scope:** Medium

#### Task 4: Make L4 defense scope and fail-closed behavior bounded

**Description:** 审核 accept churn、active limit、TLS failure、exact counter saturation、aggregate drop、IP/prefix block 和 registry drain 的组合行为。保持明确的高置信攻击防护，但避免一个容量饱和或误计数把共享 listener 变成全局不可用。

**Acceptance criteria:**

- [ ] 每次 block/drain 都可见 `scope=ip|prefix|cluster`、kind、threshold、count、TTL、drained count 和 source stage。
- [ ] 低置信事件在 exact counter 饱和时不触发 fail-closed block；高置信事件的 fail-closed 策略可配置并有明确的容量/恢复边界。
- [ ] prefix block 必须有最大范围、TTL、白名单检查和回滚/清理路径；不会把无关连接全部 drain。
- [ ] defense reject、block 和 drain 只影响匹配 IP/prefix，不修改全局 listener 或全局 origin 状态。

**Verification:**

- [ ] 测试 policy disabled、单 IP block、prefix block、exact counter saturation、whitelist 和 TTL recovery。
- [ ] 测试被 drain 的 relay 释放 connection permit、active-IP permit、registry guard、backend socket 和 TOA lease。
- [ ] 测试同时来自不同 IP 的连接不会因单 IP 事件全部被拒绝。

**Dependencies:** Tasks 1 and 2

**Files likely touched:**

- `src/l4_defense.rs`
- `src/l4_connection_registry.rs`
- `src/tcp_proxy.rs`
- `src/http_proxy_manager.rs`

**Estimated scope:** Medium; implement counter policy and drain lifecycle as separate commits

#### Task 5: Add listener worker supervision and ready-state recovery

**Description:** 将 TCP/HTTP listener 的 worker 从 detached-only 模型改为可观察的 supervisor 模型。每个 bind address 使用 generation/worker handle，worker 异常退出时限速重启；关闭或热更新时只关闭对应 generation，避免旧 task 删除新 listener 状态。

**Acceptance criteria:**

- [ ] 任一 accept worker 异常退出会被记录并在有界 backoff 后重启；所有 worker 失活时端口 readiness 变为 false。
- [ ] `handled_ports` 不会因为旧 worker 的 late cleanup 删除新 generation 的 listener entry。
- [ ] listener bind、accept、worker count、restart count 和最后 heartbeat 可查询。
- [ ] `EMFILE/ENFILE` 不再只以 100ms 无限循环；有 spare-fd/退避/限频策略，并为诊断和控制面保留 FD 余量。

**Verification:**

- [ ] 单测覆盖 transient accept error 判定和 backoff。
- [ ] 集成测试模拟 worker 返回错误、重启、热更新和 shutdown，确认没有重复 bind 或 zombie listener。
- [ ] 测试 FD pressure 下 listener 不 busy-loop，恢复 FD 后可继续 accept。

**Dependencies:** Tasks 1 and 2

**Files likely touched:**

- `src/net_bind.rs`
- `src/tcp_proxy.rs`
- `src/http_proxy_manager.rs`
- `src/memory_governor.rs`

**Estimated scope:** Medium

### Checkpoint: Shared-State Recovery

- [ ] 源站全 down、L4 block、worker death 和 FD pressure 都有独立测试及可观察状态。
- [ ] 所有新增后台 task 有 owner、错误观察、shutdown 和测试回收路径。
- [ ] 没有使用 broad `unwrap/expect` 把可恢复的网络/资源错误升级为不可诊断的 task panic。

### Phase 2: Resource and Connection Lifecycle Hardening

#### Task 6: Enforce real FD budget and reap stale connections safely

**Description:** 将 `MemoryGovernor` 的 FD 等价估算与真实 `/proc` FD 快照、listener/outbound socket 预留和连接 class 绑定。为 raw TCP/SNI established relay 增加明确的共享活动策略、最大生命周期或可配置 idle policy，同时保留首字节、TLS handshake 和 upstream connect timeout。

**Acceptance criteria:**

- [ ] accept 前和 origin connect 前都能在 FD 达到硬余量时拒绝/降级，并产生 class、fd_used、fd_limit、reserved_fd 的结构化原因。
- [ ] FD snapshot 读取失败时不会把旧值无限当作真实值；有 TTL、保守 fallback 和告警。
- [ ] established relay 的 idle 判定基于双向共享活动或明确的业务策略，不因单方向短时间无数据关闭合法上传。
- [ ] keepalive、TCP user timeout、最大连接时长和 relay queue/buffer budget 在 HTTP/HTTPS/TCP/SNI 路径中语义一致且可配置。
- [ ] permit、active-IP counter、registry guard 和 socket 在 normal return、timeout、cancel、panic/JoinError 路径均回收。

**Verification:**

- [ ] 测试连续慢上传、单方向静默、双向 idle、client half-close、backend EOF、RST、cancel 和 max-lifetime。
- [ ] 测试人为降低 FD budget 后 admission 进入可恢复 pressure，释放 socket 后新连接恢复。
- [ ] 资源 fixture 结束后比较 FD、governor counters 和 registry snapshot 与基线。

**Dependencies:** Tasks 3, 4 and 5

**Files likely touched:**

- `src/memory_governor.rs`
- `src/resource_budget.rs`
- `src/tcp_proxy.rs`
- `src/http_proxy_manager.rs`
- `src/net_bind.rs`

**Estimated scope:** Medium; implement FD admission and relay policy as separate changes

#### Task 7: Make TOA allocation an RAII lease with reconciliation

**Description:** 在 TOA enabled 分支引入 lease guard，覆盖 allocation 后的 bind、connect timeout、PROXY header、upstream TLS、relay、L4 cancel 和 task cancellation。将进程 allocator 的释放与内核 `DEL` 成功解耦，失败进入有界 retry/reconciliation 队列。

**Acceptance criteria:**

- [ ] `isOn=false` 仍只执行普通 connect，不分配 TOA 端口、不加载模块、不产生 TOA 释放日志。
- [ ] `isOn=true` 时任何 early return 都最终释放进程侧 lease；内核删除失败不会永久占用 allocator slot。
- [ ] connect timeout、bind failure、PROXY write failure、upstream TLS failure、relay error、L4 drain 和 cancellation 都有覆盖测试。
- [ ] pool size、allocated、released、kernel DEL failure、retry pending 和 exhausted counters 可查询；重试有上限和退避。
- [ ] 配置的 min/max port 合法性在加载时校验，默认 120-port pool 的容量和运行负载有明确告警阈值。

**Verification:**

- [ ] 运行 TOA 单元测试和 Linux-only integration test；macOS 只验证 disabled branch。
- [ ] 通过模拟 kernel add/del failure 验证 allocator 不被永久锁死。
- [ ] `cargo test` 结束后确认没有 pending reconciliation task 或 leaked lease。

**Dependencies:** Task 6

**Files likely touched:**

- `src/toa.rs`
- `src/tcp_proxy.rs`
- `src/config_models.rs`

**Estimated scope:** Medium

#### Task 8: Make upstream failures explicit and non-poisoning

**Description:** 统一 TCP/SNI/HTTP upstream connect、PROXY header、TLS handshake、route lookup 和 no-backend 的错误分类。当前 TCP path 在这些错误后直接结束 downstream，客户端看到 reset 但日志只在 debug，必须让运维能区分源站失败与本地拒绝，并避免错误污染 circuit breaker。

**Acceptance criteria:**

- [ ] 每次 upstream failure 都包含 server id、origin id/address、stage、timeout/errno、是否已向 client 写入数据和最终 close mode。
- [ ] local admission/FD/L4/cancel 错误不计入 origin failure；连接拒绝、connect timeout、origin TLS failure 才计入相应 origin class。
- [ ] HTTP 已完成协议握手时返回稳定的 502/503 语义；raw TCP/SNI 保留协议边界，但关闭原因和 downstream reset/FIN 行为可解释。
- [ ] upstream failure rate、all-down duration 和 recovery probe 结果进入 metrics/告警。

**Verification:**

- [ ] 测试 no LB、no backend、connect refused、connect timeout、PROXY write error、origin TLS error、client cancel 和 successful recovery。
- [ ] 验证失败连接不会把 `active_connections`、origin permit 或 metrics counters 留在非零状态。

**Dependencies:** Tasks 3 and 6

**Files likely touched:**

- `src/tcp_proxy.rs`
- `src/http_proxy_manager.rs`
- `src/proxy.rs`
- `src/origin_state.rs`

**Estimated scope:** Medium

### Checkpoint: Lifecycle and Resource Correctness

- [ ] 同一组 fixture 在 async-copy、zero-copy fallback 和 L4 cancel 下资源均归还。
- [ ] TOA disabled path 无额外副作用，TOA enabled path 无租约泄漏。
- [ ] FD、origin state、L4 state 和 listener state 都能在不重启进程的情况下恢复。

### Phase 3: Conditional XDP and Runtime Safety

#### Task 9: Enforce XDP fail-safe and bridge supervision

**Description:** 仅对实际启用 XDP 的节点实施。把 eBPF attach、redirect map、AF_XDP queue、userspace bridge 和 fallback 视为一个可检查的状态机；bridge 退出或队列不 ready 时关闭 redirect 或按配置 fail-start。

**Acceptance criteria:**

- [ ] `xdp.enabled=false` 时状态明确显示 detached、`proxy_redirect_enabled=false`，不会残留 redirect map 导流。
- [ ] redirect 只有在所有必要 queue ready 且 userspace bridge heartbeat 有效后才开启。
- [ ] bridge/queue/map sync 失败有明确 fallback reason、drop/redirect/map-miss counters 和自动恢复/关闭路径。
- [ ] runtime status 能把“XDP disabled”“XDP attached but pass”“proxy redirect active”“bridge unhealthy”区分开。

**Verification:**

- [ ] 运行 disabled、attach failure、partial queue、bridge stop、map sync failure 和 recovery 测试。
- [ ] Linux 节点通过 XDP smoke test 检查非空流量、redirect/pass/drop 计数及真实连接成功率。

**Dependencies:** Tasks 1 and 5

**Files likely touched:**

- `src/xdp.rs`
- `src/main.rs`
- `src/xdp_auto_config.rs`
- `configs/runtime.yaml`

**Estimated scope:** Medium; Linux-only implementation and verification

#### Task 10: Add bounded background-task and metrics health checks

**Description:** 对 origin cleanup、pressure updater、metrics worker、cache worker、listener supervisor、TOA reconciler 和 XDP bridge 建立统一的 task health snapshot。指标构造保持无阻塞、无 await 持锁；当前 `metrics::record::get_or_create` 的 map length 已在 `entry` 前读取，补回归测试而不是重复改造不存在的重入死锁。

**Acceptance criteria:**

- [ ] 每个关键后台 task 有 started、last progress、last error、restart count 和 shutdown state。
- [ ] task panic/JoinError 不会静默吞掉；关键 task 失败会触发 readiness 降级或受控 supervisor restart。
- [ ] metrics first-server creation、并发 server creation 和 persistence iteration 有有界测试。
- [ ] 热路径 metrics 记录不持有 DashMap/Mutex guard 跨 await，不因诊断日志阻塞网络 worker。

**Verification:**

- [ ] 使用 `tokio::time::timeout` 测试 task health 和 metrics creation。
- [ ] 检查所有新增 `tokio::spawn` 都有错误观察和 owner。

**Dependencies:** Tasks 1, 3, 5 and 7

**Files likely touched:**

- `src/metrics.rs`
- `src/main.rs`
- `src/origin_state.rs`
- `src/tcp_proxy.rs`
- `src/xdp.rs`

**Estimated scope:** Medium

### Checkpoint: Runtime Safety

- [ ] 关闭/重启/热更新不会留下旧 generation listener、旧 origin state 或未回收 permit。
- [ ] 关键 task 失败能在诊断中看到，不需要依赖“所有连接 reset”这一间接症状。
- [ ] XDP/TOA 关闭时没有隐藏的 Linux 外部状态副作用。

### Phase 4: Verification and Staged Rollout

#### Task 11: Run the verification matrix

**Description:** 按风险执行 Rust 编译、定向测试、Linux-only 测试和压力/故障注入。静态分析阶段不启动生产服务；实现阶段必须在 Linux 环境完成 socket/TOA/XDP 验证。

**Acceptance criteria:**

- [ ] `cargo check --all-targets` 通过。
- [ ] `cargo test` 的定向集合覆盖 origin state、net bind、memory governor、L4 defense、connection registry、TCP relay、TOA disabled/enabled 和 listener supervisor。
- [ ] unsafe/FFI/socket/TLS 改动完成额外 invariant review；每个新增 unsafe block 有局部 `SAFETY` 说明。
- [ ] Linux pressure test 能重复“资源到阈值 -> 新连接降级 -> 释放资源 -> 自动恢复”，无需进程 restart。

**Verification:**

- [ ] 先跑 touched module targeted tests，再跑 `cargo check --all-targets` 和完整测试集。
- [ ] 对 zero-copy 与 async-copy 做相同 fixture A/B；首轮 rollout 固定 `zeroCopy=false`。
- [ ] 记录测试环境的 Linux kernel、FD limit、worker count、XDP/TOA flags 和配置快照。

**Dependencies:** Tasks 3-10

**Files likely touched:**

- Test files adjacent to the touched modules
- `Cargo.toml` only if a test-only dependency is genuinely required

**Estimated scope:** Medium

#### Task 12: Stage rollout with explicit rollback triggers

**Description:** 分阶段部署：先关闭 XDP/TOA/zero-copy 的复杂路径，验证普通 TCP/HTTP/TLS；再逐项开启并观察。保留旧 binary、旧配置和不依赖进程内状态的回滚方式。

**Acceptance criteria:**

- [ ] 小范围节点观察至少一个完整的源站故障恢复周期和高峰连接周期。
- [ ] `connection_reset`、`origin_all_down`、`fd_pressure`、`l4_block/drain`、`listener_restart`、`xdp_redirect_drop` 和 TOA pool metrics 有基线与阈值。
- [ ] 触发以下任一条件自动暂停放量：新连接 reset 持续升高、FD 使用接近硬上限、worker 无法恢复、all-origin-down 超过 cooldown、L4 block 范围异常扩大、XDP drop/map-miss 持续增长。
- [ ] 回滚不依赖当前进程成功接收新连接；可以由外部 supervisor 替换 binary/配置并重新启动。

**Verification:**

- [ ] 修复前后用同一 client/backend fixture 对比成功率、完整 payload、首字节延迟、reset/FIN/RST、FD usage 和 close reason。
- [ ] 记录一次不重启的自动恢复证据。

**Dependencies:** Task 11

**Files likely touched:**

- Deployment/runbook files outside the Rust source tree

**Estimated scope:** Medium

### Checkpoint: Complete

- [ ] 故障阶段可定位，且所有 P0/P1 假设都有对应的自动化测试或生产证据。
- [ ] 源站全 down、FD pressure、L4 false positive、listener worker failure、XDP bridge failure 和 TOA lease failure 均可在不依赖人工 restart 的情况下恢复或明确降级。
- [ ] 所有连接/permit/registry/lease/task 资源在 success、error、timeout、cancel、panic 和 shutdown 路径有一致生命周期。
- [ ] 旧 AnyTLS 计划文件保持原样，当前问题的实现任务已独立完成并通过 review。

## Risks and Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| 放宽源站熔断后把真实故障放大到源站 | High | half-open probe、指数退避、并发 probe 上限和明确 all-down 告警 |
| 放宽 L4 fail-closed 造成攻击面扩大 | High | 只对低置信饱和 fail-open；高置信策略可配置；保留 prefix 白名单、TTL 和计数器 |
| 增加 established relay 生命周期导致 FD 增长 | High | 真实 FD hard margin、连接 class budget、双向 idle/max-lifetime、active relay 监控 |
| EMFILE recovery 逻辑本身造成 accept 抖动 | Medium | spare-fd、限速日志、退避和 dedicated diagnostics FD 预算 |
| listener supervisor 重启造成端口重复 bind 或配置竞态 | Medium | generation token、单 owner、shutdown handshake 和有界 backoff |
| XDP/TOA 修复只在 Linux 可验证 | Medium | macOS 只测 disabled path；Linux CI/节点做 FFI/socket smoke test |
| 错误日志增加高基数和锁竞争 | Medium | 结构化字段、采样/聚合、不要在网络 worker 内做阻塞 I/O |

## Open Questions

- incident 发生时 `toa.isOn` 的有效 runtime config 是否确实为 `false`，而不是旧配置或单 server 配置被覆盖？
- incident 持续时间是否超过源站 `AUTO_RECOVER_SECONDS=60`，以及期间是否有 `origin ... marked down` 和 `No healthy backends`？
- 失败连接来自单一 NAT/IP、同一 prefix，还是不同公网 IP 全部失败？
- 生产节点的 FD soft limit、实际 FD 数、TCP states、TIME_WAIT/ESTABLISHED 数量和 listener backlog 是否接近上限？
- `empty_connection_flood` 是否开启，是否出现 exact counter saturation、prefix block 或大量 `TcpPressureIdleClose`？
- XDP 的有效状态是否为 disabled/pass，还是有 redirect/map/AF_XDP bridge 参与？
- 生产是否开启 `relay.zeroCopy`、upstream TLS、PROXY Protocol 或长连接/AnyTLS SNI passthrough？

## Suggested Implementation Order

1. Task 1 and Task 2: make the next incident classifiable.
2. Task 3 and Task 5: remove restart-cleared all-down and listener-worker black holes.
3. Task 4 and Task 6: bound L4 and FD/resource pressure.
4. Task 7 and Task 8: close all TOA and upstream error lifecycle gaps.
5. Task 9 and Task 10: harden conditional dataplanes and background tasks.
6. Task 11 and Task 12: verify on Linux and roll out gradually.

The first implementation checkpoint should be after Tasks 1-5. Do not combine origin circuit-breaker changes, L4 policy changes, FD policy changes and XDP changes into one deployment; otherwise a recovery after restart cannot be attributed to a fix.
