# EN-17: 用户态传输调度与拷贝优化（首个已验证切片 — AF_XDP TCP reactor 热路径）

Base: `baf752c`（R0–R4 验收基线）
eBPF object: `data/cloud-node-xdp-ebpf.o` sha256 `3b8549a9c1ea9c2107db834aeb76b627c03df10bca9b1ef53bee9660297423ba`（本切片未改 eBPF，对象不变）
环境: `.110` (ser790960344190) 构建+测试, Debian 12 / kernel 6.1.0-10-amd64 / 2c/2GiB。本机仅编辑+传输，未编译。

EN-17 是 L 规模条目。本切片交付并验证了 **AF_XDP TCP reactor 的事件驱动调度** 与
**桥接 RX/TX 路径上的每包分配消除**。剩余缺口如实列于文末。

## 问题

改动前的 `AfXdpTcpReactor::poll_at` 每轮对 `sessions` 全表扫描并逐一泵送，且：

- 未处理 ingress 包堆积在 `device.ingress` 无上限——RX 洪水下内存随包数增长；
- 会话泵送无任何唤醒通道：proxy 任务把响应字节写进 egress channel 后，只能等下一轮
  全表扫描才被送出，延迟与表大小耦合；
- `retain_live_sessions` 每轮做全表 idle 扫描（秒级超时的工作每微秒级轮询一次）；
- socket 收包路径 `recv_slice(rx_scratch)` + `Bytes::copy_from_slice` 双拷贝；
- bridge 每包 `interface.to_string()`（RX）与 `parse_proxy_frame` 内
  `AfXdpRouteMeta.interface: String`（每包一次堆分配）；TCP egress 每帧
  `tx_scratch.clone()`。

## 实现

### 热集调度（`src/xdp/af_xdp/tcp_reactor.rs`）

- `sessions` 仍持有全部会话，但每轮只泵送"热集"：
  - 新 ingress 包 → `mark_hot(flow)`（`session.hot` 标志去重，队列内至多一条）；
  - proxy 任务写 egress channel → 共享 `wake_set: Arc<DashMap<FlowKey, ()>>`
    脏标记——**硬有界**（≤ session_limit 活流 + drain 中瞬态 stale key），
    入队即去重（map key 语义），`insert` 无"满"路径故**无丢信号分支**；
    每轮至多 drain `AF_XDP_TCP_WAKE_DRAIN_BUDGET = 8192` 条 → `mark_hot`，
    未 drain 条目留在集内下轮继续（不丢）。
  - 热集每轮泵送上限 `AF_XDP_TCP_PUMP_BUDGET = 512`；泵完仍有工作
    （`session_still_active`：未启动 proxy / pending_ingress / pending_egress /
    closing / socket.can_recv）的会话重入热集，下一轮继续。
- **正确性兜底（分批）**：每 `AF_XDP_TCP_SWEEP_INTERVAL = 250ms` 起一个 sweep
  周期，周期内收集 key 集、游标 `sweep_pos` 每轮推进至多
  `AF_XDP_TCP_SWEEP_BATCH_BUDGET = 256` 条——大表不会单轮独占；已在热队列
  的会话跳过（其泵送经队列），周期中新建的会话天然带热标记。
  漏掉的信号只延迟到下一次 sweep，永不丢失。
- **回收**：`retain_live_sessions` 按同一 250ms cadence 门控
  （`last_retain` 独立时间戳）；可回收会话（closing+Closed/TimeWait）先被
  `session_still_active` 排除出热集，等门控 reaper 摘除——不再每轮全表扫。

### 有界 ingress

- `device.ingress` 上限 `AF_XDP_TCP_INGRESS_QUEUE_MAX = 4096`；超限返回显式
  `AfXdpTcpIngestStatus::IngressQueueFull`——计入 `ingressQueueDropped` 诊断，
  且 `AfXdpTcpAdmissionFailureTracker` 将其与 `RefusedAtCapacity` 同等视为拒绝
  事件参与连续失败熔断。TCP 重传是恢复路径；绝不静默增长。
- 每轮 ingress 处理上限 `AF_XDP_TCP_INGRESS_BUDGET = 512`——RX 洪水不能无限推迟
  会话泵送/TX/定时器。

### 拷贝消除

- socket 收包：`socket.recv(|data| (n, Bytes::copy_from_slice(&data[..n])))`——
  smoltcp 接收缓冲直接拷入 `Bytes`，删除 `rx_scratch` 字段及其往返。
- bridge RX：`poll_raw_once` 回调不再 `interface.to_string()`（队列句柄本来只产出
  本队列帧）；`AfXdpRouteMeta.interface: String → Arc<str>`，route clone 变为
  引用计数，`parse_proxy_frame(interface: impl Into<Arc<str>>)` 调用点不变。
- bridge TX：同接口 TCP egress 直接 `encode_ip_reply_frame` 进桥接自有
  `encode_scratch` 后 `send_raw_frame(&scratch)` 借用——删除每帧 `tx_scratch.clone()`；
  跨接口转发路径保留 owned frame（转发本来就需要所有权）。

### 诊断

新增计数（`af_xdp_tcp_diagnostics_json` 透出）：

- `ingressQueueDropped`——ingress 队列满拒绝的包数；
- `wakeSignals`——drain 到的 proxy→reactor 脏标记数。

既有 `accepted`/`refusedAtCapacity`/`ignoredUnknown`/`preProxyTimeout`/
`proxyStarted`/`socketRecvBytes`/`streamIngressBytes`/`streamEgressBytes`/
`egressFrames` 语义不变。

## 验证（.110，VPS-only）

| 项 | 结果 |
|---|---|
| `cargo check --lib` / `--all-targets` | 通过（仅既有 warning） |
| `cargo test --lib af_xdp`（定向） | 50 passed / 0 failed |
| `cargo test --lib`（全量） | **697 passed / 0 failed** |
| eBPF 对象 | 未重建需求；.110/.120 均为 `3b8549a9`（源码哈希经 manifest 校验一致） |

新增测试：

- `af_xdp_tcp_reactor_hot_set_dedups_and_drains`——SYN 建会话入热集；同流第二包
  不产生重复热条目；泵后无工作会话冷却（hot=0）。
- `af_xdp_tcp_stream_write_and_shutdown_signal_reactor_wake`——真实
  `channel_pair_with_wake` 路径：`write_all`/`shutdown` 各标记脏位；
  同流去重后 wake_set 恒为 1；poll drain 后归零。
- `af_xdp_tcp_reactor_ingress_queue_overflow_is_explicit_refusal`——填满
  4096 项后下一包返回 `IngressQueueFull`（显式拒绝，非增长）。
- `af_xdp_tcp_reactor_unstarted_sessions_stay_hot_until_swept`——无 manager 的
  会话经真实 wake 信号入热集；泵后因 `!proxy_started` 保持热（不被信号遗漏
  永久滞留）。
- `af_xdp_tcp_reactor_sweep_is_batched_not_unbounded`——会话数 > 单批预算时
  sweep 游标每轮恰推进一个批次，两完成周期。
- `af_xdp_tcp_reactor_stale_wake_mark_is_a_noop`——无会话流的脏标记 drain 后
  不产生会话/工作（tuple 重用、worker 退出安全）。
- `af_xdp_tcp_reactor_ingress_budget_leaves_backlog_bounded`——RX 洪泛下每轮
  恰好处理 ingress 预算额，余量下轮继续，不丢不越界。
- `af_xdp_tcp_wake_set_stays_bounded_under_write_storm`——32 次分块写风暴下
  wake set 恒为 1（入队去重），drain 后归零。

更新测试（语义随 cadence 门控变化，断言收紧而非放宽）：

- `af_xdp_tcp_reactor_resolves_egress_route_before_reaping_session`——原断言
  依赖"同轮回收"；改为 `poll_at_for_test` 越过 sweep 间隔，仍断言 routeless
  egress 帧先于回收解析到会话路由、且回收发生。

既有行为回归：SYN-ACK、未知流忽略、容量拒绝、idle/TimeWait 回收、半关闭、
背压/分块写、BrokenPipe、UDP 路由缓存等 46 项 af_xdp 测试全过。

## 遗留/限制（如实记录）

- `poll_egress` 仍由 smoltcp 内部逐 socket 推进（vendored 协议栈不改）——
  每轮 O(session_limit) 但每 socket 工作量小；为既有架构内界，列为记录项。
- 无信号的最坏推进延迟 = 250ms sweep 间隔（大表下周期本身随批次摊销；
  秒级 idle 超时尺度下可接受）。
- 每包 UMEM→`Vec` 拷贝（`frame.to_vec()`）保留：async demux 需要 owned 帧，
  无法在跨 `.await` 处持有 UMEM 引用——属架构内固有拷贝，非本切片范围。
- 未做真 NIC/多队列压测：2c2g VPS 无 AF_XDP 硬件路径，T05/T06/T07 的高会话/
  RX 洪水验收需要生产 NIC 证据——本切片只交付调度结构与单元级证明。
- "相关 bench" 交付项未做：无标准 bench 基线，后续在真机上补 T05/T06/T07。
