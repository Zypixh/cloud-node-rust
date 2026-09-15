# EN-19: T3 — smoltcp-edge 受控 fork + 外部传输控制器接线

Base: `1943c16`（T2 之后）
规范: `tasks/xdp-transport-next-steps-2026-09-15.md` v3 §8 T3
环境: `vps-110` 构建+测试。本机仅编辑+传输。
范围: `vendor/smoltcp-edge/`（新）、`Cargo.toml`（patch 段）、
`crates/cloud-node-transport`（`on_loss_undo` + Eifel 检查点 + `app_limited_now`）、
`src/xdp/af_xdp/tcp_reactor.rs`（accepted 会话装控制器 + /status 快照接线）。
未实现 EdgeCC 决策层（T5）；生产控制器保持 `CubicRef`。

## 交付

### Vendor fork

- `vendor/smoltcp-edge`：registry `smoltcp 0.14.0` 的受控副本，
  `[patch.crates-io]` 覆盖根清单两处声明（linux target deps +
  dev-deps）。fork 自持 `[workspace]` 声明，独立于根 workspace，
  上游测试经 `--manifest-path` / 目录内 `cargo test` 独立运行。
- `DIVERGENCE.md` 记录全部分歧；代码内标记 `smoltcp-edge (T3)`。
  不变量：**未装外部控制器时全部路径与上游逐字节一致**。

### transport_ext.rs（新模块，~700 行）

- 每段 `SentRecord` 记分板；`pipe` 对齐 Linux
  `tcp_packets_in_flight`（sacked/lost 出管，重传入管）。
- SACK 消费 + RFC 2883 DSACK（首块低于累积沿 → 重复到达证据）。
- 3-dupack 前沿标记（`tcp_mark_head_lost` 类比）+ RFC 8985 RACK
  时间标记，自适应 reo_wnd（min_rtt/4，1ms 下限，srtt 上限，
  DSACK 驱动乘数上限 8×）。
- TLP 探针（max(2·srtt,10ms)，封顶 RTO；无新数据时重传尾部记录）。
- Eifel 撤销：DSACK 或 TSecr-早于重传 tsval → `on_loss_undo`
  （transport crate 为此新增 trait 方法 + NewRenoRef/CubicRef
  pre-loss 检查点，级联响应保留最早检查点）。
- RTT：记分板 first-tx 计时（Karn 安全）+ TSecr RTTM 回退。
- Pacing 门 `next_send_due`：只管新数据段，重传/控制豁免。
- app-limited 标记（发送缓冲排空时）+ 空闲重启通知。
- 可观测计数：`dsack_events`、`rack_lost_bytes`。

### tcp.rs 钩子

- `congestion::Controller`/impls 与 `RttEstimator` 转 `pub`
  （reactor 保留内置 Cubic 作对照路径）。
- socket API：`set_transport_controller`、`has_transport_controller`、
  `transport_snapshot`（`CcSnapshot`）、`transport_pacing_rate`、
  `transport_next_send_due`、`set_rx_window_cap`（D-R1 动态接收窗
  上限，`scaled_window()` 在缩放前应用）。
- PAWS（RFC 7323 §5.3）：TS 协商后丢弃 serially-older TSval；
  **已知分歧**：未实现 24 天 TS.Recent 超时豁免。
- DSACK 生成：完全低于累积接收沿的数据段记入
  `last_rx_duplicate_range`，作为下一个 ACK 的首个 SACK 块。
- ACK 处理 ext 分支接管 dupack/cwnd 簿记；builtin 分支原样保留。
- 两处握手 MSS 学习点同步 `ext.cc.on_mss_update`；ACK 携带
  `ecn_echo` → `cc.on_ecn_ce`（经典 ECN，每 ACK 一次；AccECN=T7）。
- dispatch：ext.timer_checks（RACK/TLP 到期）；RTO →
  `mark_all_lost`（不回绕 remote_last_seq）；发送选择顺序
  scoreboard-lost（cwnd 门）→ 新数据（cwnd+pacing 门）→ TLP 尾探针。
- `poll_at` 合并 pacing/RACK/TLP 到期——定时器能唤醒 socket。
- wire 层：`TcpRepr.ecn_echo/cwr`、`Ipv4Repr.ecn`、`Ipv6Repr.ecn`、
  `IpRepr::ecn()` 贯通（不协商）。

### Reactor 接线（T3-8）

- `tcp_reactor.rs` accepted 会话创建处安装
  `CubicRef::new(536)`（注释明确内置 Cubic 仅为对照路径）——
  F8 语义保持：生产 TCP 不会静默跑 `NoControl`。
- `publish_session_snapshot` 改读 `socket.transport_snapshot()`：
  `/status` 现在输出真实 `ccAlgorithm`/`ccVersionPin`/`ccMode`/
  `reasonCode`/`cwndBytes`/`ssthreshBytes`/`minRttMicros`/
  `pacingRateBps` + EdgeCC 观测字段（belief/queue/p_rand/
  bw_sigma/envelope）；控制器不提供的字段保持 null，不伪造；
  `ccImpl` 区分 `smoltcp-edge` vs `smoltcp-0.14`。

## 验证（vps-110）

- `cargo test --lib`（fork 目录内）：**675 pass / 0 fail**
  （673 上游 + 2 新增 ext 端到端测试）。
- `cargo check --lib --tests`（根 crate）：通过，4 个既有警告
  （unused import / 可见性，与本任务无关）。
- `cargo test -p cloud-node-transport`：T2 阶段已全绿，本任务
  改动仅为新增 trait 方法与检查点字段。
- 新增 fork 测试覆盖：cwnd 门控在途量、ACK→slow-start 增长+
  RTT 采样、pacing 间隔（102400 B/s → 10ms/段）、3-dupack+SACK
  前沿标记→`on_loss_event`→cwnd 收缩。

## 遗留 / 设计限制

- PAWS 无 24 天 TS.Recent 超时豁免（DIVERGENCE.md 已记录）。
- 经典 ECN 只贯通不协商；AccECN=T7；共享瓶颈检测=T6；
  EdgeCC=T5。
- fork 内 `congestion::Controller`/`RttEstimator` 公开化带来的
  `private_interfaces` 类警告已清理（RttEstimator 转 pub）。
- veth 双栈协议矩阵与报文脚本回归属 T3-10，按指示"编译通过
  即止"推迟到后续规划；`CubicRef vs 上游 Cubic` 逐 ACK cwnd
  对照由 fork 端到端测试 + transport crate 参考测试分别覆盖。
- 真 NIC/zero-copy 验收仍需硬件环境。
