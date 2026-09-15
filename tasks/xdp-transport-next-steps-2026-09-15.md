# XDP 全协议接管的传输层下一步：双向拥塞控制 / AccECN / 用户态队列调度 —— 任务规划与 Devin 提示词

基线：HEAD `d13f77c`（仅在 `315af04` 上追加文档脱敏提交，代码与发布前静态审阅一致）。
上游输入：`tasks/xdp-final-static-review-2026-09-15.md`（F1–F8）与 `docs/xdp-transport-performance-design.md`（PROPOSED）。

本文只做静态阅读与依赖源码核对（`~/.cargo/registry` 中 Cargo.lock 锁定的 smoltcp 0.14.0、quinn-proto 0.11.17），未编译、未运行、未连接 VPS。所有编译/测试/压测仍按既有约束在授权 VPS .110/.120 执行。

## 范围声明（用户决策 2026-09-15）

1. 目标是 **XDP/AF_XDP 完全接管协议数据面**：客户端方向（被动打开）与回源方向（主动打开）都由 `smoltcp-edge` 在 AF_XDP 上承载。内核 TCP/UDP 不再参与业务数据面。
2. **非 XDP 模式（XDP 关闭的 socket 代理路径）不做任何传输改造**：内核拥有 TCP，6.1 上只有 BBRv1 谱系、无 AccECN、fq 只管内核 TX。它只在 T9 作为同环境对照基线存在。
3. 因此本文所有传输机制——RateSample、BBRv3、NewReno/Cubic、AccECN、pacing、时间轮调度、节点出口治理、AQM——只实现在我们拥有线格式的 AF_XDP 路径上，并且是**双向**的。
4. 控制面（配置、RPC、DNS 解析、健康检查、日志上报）保留内核 socket，不属于数据面接管范围。

## 0. 本次核对出的硬约束（决定架构的事实）

| # | 事实 | 证据 | 影响 |
|---|---|---|---|
| C1 | smoltcp 0.14.0 的 `Controller` trait 是 `pub(super)`，`on_ack(now, len, in_flight, rtt)` 没有 per-segment 发送时间、delivered 计数、app-limited、SACK 范围 | `smoltcp-0.14.0/src/socket/tcp/congestion.rs:14-37` | 任何 BBR 系（依赖 delivery-rate 采样）**不能以外部 Controller 注入**，必须受控 fork |
| C2 | RTT 估计一窗一样本（Karn 风格 `rtte.on_send` 仅在 `timestamp.is_none()` 时记录），socket 层不使用 TCP Timestamps 选项做 RTT；`RttEstimator` 精度 ms | `socket/tcp.rs:163-242`, `:2143` | BBR 的 min_rtt / 每 ACK 交付率采样质量不足 |
| C3 | 发送侧没有 SACK 记分板、RACK-TLP、PRR；丢失判定只有 3 dupack 与 RTO；SACK 仅用于接收端生成 SACK 块 | `socket/tcp.rs:512-523, 2106-2137, 1497-1525` | BBR 需要准确的 lost/delivered 记账；无 RACK 的 BBR 在乱序/尾丢包下表现错误 |
| C4 | socket 层不处理 ECN：`TcpRepr` 无 ECE/CWR/AE 字段，`Ipv4Repr` 无 ECN 字段（wire 层有 `ecn()/set_ecn()` 但未上提） | `wire/tcp.rs:856-869`, `wire/ipv4.rs:533-539` | 经典 ECN 与 AccECN 都要在 fork 里贯通 IP/TCP repr |
| C5 | 无 pacing 钩子：`cwnd_remaining = window - flight_size`，dispatch 允许多少就立刻发多少 | `socket/tcp.rs:1400-1405` | 发送节奏必须在 fork 的 dispatch 或 reactor 层加“最早发送时间”门 |
| C6 | reactor 用 `now_timestamp_millis()`（系统时间 + 偏移，ms）构造 `SmoltcpInstant` | `src/xdp/af_xdp/tcp_reactor.rs:668, 775` | 墙钟可跳变、ms 粒度：pacing/RTT/RateSample 前置必须换单调 µs 时钟 |
| C7 | bridge 对 reactor 产出的每个 egress 帧立即 `send_raw_frame`，无节奏、无队列选择；连续 256 次 TX backpressure 直接撤销队列 redirect 并 `return` | `src/xdp/af_xdp/bridge.rs:992-1073, 511` | 调度器接入点在这里；TX 背压退出与 F2 同类，需并入过载合同 |
| C8 | quinn-proto 0.11.17 `congestion::Controller` 为公开 trait，`on_ack(now, sent, bytes, app_limited, rtt)` / `on_sent` / `on_end_acks` / `on_congestion_event(lost_bytes=0 表示 ECN)` | `quinn-proto-0.11.17/src/congestion.rs:17-85` | QUIC 侧 BBRv3 可作为自定义 Controller **不 fork** 实现 |
| C9 | quinn 的 Pacer 是 `window/srtt` 令牌桶；Controller 的 `metrics().pacing_rate` 只进 qlog，不驱动 Pacer | `connection/pacing.rs`, `connection/paths.rs:198-278` | BBRv3 的 pacing_gain ≠ cwnd_gain 无法直接表达；是否 patch quinn 需测后决定 |
| C10 | quinn 内置 `Bbr` 是 quiche 派生的 BBRv1，源码标注 “Experimental! Use at your own risk” | `congestion/bbr/mod.rs:19-24` | 不得把它当 “BBR/BBRv3” 启用 |
| C11 | H3 共享 UDP 套接字丢弃 ECN：`try_send` 不传 `transmit.ecn`，`poll_recv` 填 `ecn: None` | `src/quic_udp_demux.rs:163-180, 717` | quinn 的 RFC 9000 ECN 验证必然失败并自禁；这是**已存在的静默降级**，先报告 |
| C12 | **AF_XDP reactor 只有被动打开**：`ensure_session_at` 对每个新流 `socket.listen(...)`；`src/xdp` 下没有 `connect`/active open。回源当前走内核 TCP（pingora/`tcp_proxy` 的 relay socket，`tcp_proxy.rs:1849-1863` 对其设置 `TCP_CONGESTION=bbr` 并忽略返回值） | `src/xdp/af_xdp/tcp_reactor.rs:779-840`；grep `src/xdp` 无 active open | 回源接管需要新增：smoltcp-edge 主动打开、源端口分配、邻居解析、出接口选择、eBPF 出向流表、内核 RST 防护 |
| C13 | AccECN 已成 RFC 9768；Linux 于 6.18/6.19 系列合入，7.0 默认启用（LWN 1058666）；目标内核 6.1 不具备 | 上游依据见文末 | 我们的 smoltcp-edge 双向都可实现 AccECN；对端（客户端/源站）是否支持取决于其内核版本，命中率要实测 |
| C14 | Linux 6.1 AF_XDP copy TX 走 `xsk_generic_xmit → __dev_direct_xmit`，绕过 netdev egress qdisc | 设计提案已引用 | fq/CAKE/FQ-PIE 对 AF_XDP 发包无效；队列设计必须在用户态 TX 路径实现 |
| C15 | eBPF `tcp_sanity` 只检查 `flags & 0x3f`，不触碰 ECE/CWR/AE；SYN-cookie challenge 路径 SYN-ACK 仅带 MSS（ADR-001） | `crates/cloud-node-xdp-ebpf/src/main.rs:1369-1390, 4940` | smoltcp 终止路径可协商 ECN/AccECN；challenge 路径当前无法协商，需显式限定 |
| C16 | `send_window=32MiB` 为每连接（源码注释写成 per-stream 不准确），`stream_receive_window=4MiB` 为每 stream | `src/quic_transport.rs:13-19` | 联合计费进 F3 预算；注释修正 |
| C17 | 内核对到达无监听端口的 SYN-ACK/数据会回 RST；XDP 程序 detach（reload prepare 窗口）期间入包会漏到内核栈 | Linux TCP 语义 | 回源 active open 的源端口范围必须让内核既不分配也不响应（`ip_local_reserved_ports` + netfilter DROP 守卫），否则一次 reload 就会让源站收到 RST |

上游版本钉住（后续所有实现与测试引用这两个标识，不写“BBRv3”泛称）：

- 算法参考实现：google/bbr 分支 `v3`，commit `90210de4b779d40496dee0b89081780eeddf2a60`（`net/ipv4/tcp_bbr.c`）。
- 规范文本：`draft-ietf-ccwg-bbr-06`（2026-07-06，Experimental）。两者冲突时以源码行为为准并记录差异。
- AccECN：RFC 9768。经典 ECN：RFC 3168。RACK-TLP：RFC 8985。PRR：RFC 6937。CUBIC：RFC 9438 + HyStart++ RFC 9406。NewReno：RFC 5681/6582。TCP TS：RFC 7323。

## 1. 目标架构

```mermaid
flowchart LR
    subgraph transport["crates/cloud-node-transport（纯算法，无 tokio，可确定性测试，双向共用）"]
        CLK[clock: 单调 µs TransportInstant]
        RS[rate_sample: 每段 TxRecord → RateSample]
        CC[cc: CongestionController trait<br/>NewReno / Cubic / Bbr3 / 策略叠加层]
        ECN[ecn: Off / Classic3168 / AccEcn9768<br/>被动方 + 主动方状态机, ACE/Option 编解码]
        REC[recovery: SACK 记分板 + RACK-TLP + PRR]
        PACE[pacer: 每连接 next_send_at + 有界突发]
        SCHED[sched: 最小堆参考 + 分层时间轮 + 业务分层 DRR + 节点出口租约]
        AQM[aqm: CoDel / PIE（仅转发队列，ECN 标记优先于丢弃）]
        SIM[sim: 确定性网络模拟器]
    end
    subgraph tcpfork["vendor/smoltcp-edge（受控 fork，[patch.crates-io]）"]
        SOCK[socket/tcp.rs: 段记录、TS RTT、SACK 记分板、ECN repr、发送时间门、可插拔 CC<br/>listen（客户端侧）+ connect（回源侧）]
        NEIGH[邻居/路由: 默认网关 ARP/NDP、出接口与本地 IP 选择、PMTU]
    end
    subgraph ebpf["eBPF"]
        INMAP[入向: 监听端口/流表 → XSK]
        OUTMAP[出向流表: 我们主动打开的 5 元组 → 归属 XSK<br/>ICMP 错误按内层 5 元组投递]
    end
    subgraph dp["src/xdp/af_xdp 数据面"]
        REACT[tcp_reactor: 两类会话（accepted / dialed），按调度器选择 dispatch]
        BRIDGE[bridge: min(cwnd,rwnd,pacer,租约,XSK slots) → TX]
        UPCONN[upstream connector: pingora 上游 L4 = 虚拟流（复用 virtual_l4_stream）]
    end
    subgraph quic["quinn 适配"]
        QCC[Bbr3 impl quinn_proto::congestion::Controller]
        QECN[quic_udp_demux ECN 贯通]
    end
    CLK --> RS --> CC --> PACE --> SCHED --> BRIDGE
    ECN --> CC
    REC --> RS
    SOCK --> RS
    SOCK --> ECN
    SOCK --> REC
    NEIGH --> SOCK
    REACT --> SOCK
    UPCONN --> REACT
    SCHED --> REACT
    AQM --> BRIDGE
    OUTMAP --> BRIDGE
    QCC --> CC
    QECN --> QCC
    SIM -.测试.- CC
    SIM -.测试.- SCHED
```

边界原则：

- 拥塞控制只输出 pacing rate / cwnd / 状态与原因，不分配应用队列，不越过 TX 资源额度。
- TCP 与 QUIC 各自保留序号、ACK、重传、加密、流控；共享的是 `RateSample → CongestionController` 接口与节点出口治理。
- 客户端侧会话与回源侧会话是同一个 reactor/调度器里的两类会话（`accepted` / `dialed`），共用 CC、pacer、预算与分层，只是打开方向与 ECN 协商角色不同。
- 业务优先级只在“已满足协议发送条件”的工作中选择。
- 应用层（pingora / tcp_proxy / udp_proxy）不得绑定 smoltcp 类型；上下游都通过虚拟 L4 流接入。

## 2. 拥塞控制模块设计

### 2.1 统一输入：RateSample（对齐 Linux `tcp_rate.c` 语义）

每个已发送段记录 `TxRecord { sent_at, delivered_at_send, delivered_snapshot, first_tx_at, is_app_limited, is_retransmit, size }`。每次 ACK/SACK 处理后生成：

```
RateSample {
  delivered: u64,          // 本次新确认字节（含 SACK）
  lost: u64,               // 本次新判丢字节（RACK/dupack/RTO）
  delivered_ce: u64,       // AccECN: ACE/CEB 增量；经典 ECN: 0/1 事件
  interval: Duration,      // max(send_elapsed, ack_elapsed)，RFC 语义
  rtt: Option<Duration>,   // 本次样本 RTT（TS 或段时间）
  is_app_limited: bool,
  prior_in_flight: u64,
  acked_sacked: u64,
  now: TransportInstant,
}
```

必须处理：ACK 压缩、延迟 ACK、重传段不产生 RTT 样本、app-limited 标记随段传递、`interval` 取发送/确认区间的较大者。不得用“本次 ACK 字节 / 两次 ACK 间隔”。

### 2.2 `CongestionController` trait（transport crate 公开）

```
trait CongestionController {
  fn on_sent(&mut self, now, bytes, in_flight, is_app_limited);
  fn on_rate_sample(&mut self, rs: &RateSample, in_flight, rtt: &RttState);
  fn on_loss_event(&mut self, now, lost_bytes, in_flight, persistent: bool);
  fn on_ecn_ce(&mut self, now, ce_bytes_or_events, delivered, in_flight);
  fn on_rto(&mut self, now, in_flight);
  fn on_idle_restart(&mut self, now, idle_for);
  fn on_mss_update(&mut self, mss);
  fn cwnd(&self) -> u64;
  fn pacing_rate(&self) -> Option<u64>;       // bytes/s；Reno/Cubic 也给出 cwnd/srtt 派生值
  fn state(&self) -> CcSnapshot;               // 算法名+版本钉、mode、bw_hi/lo、inflight_hi/lo、min_rtt、extra_acked、ecn_alpha、原因码
}
```

`CcSnapshot` 直接进 `/status` 与日志，F8 的“对已连接 socket 断言算法不为 None”落到这里，且对 accepted 与 dialed 两类会话都成立。

### 2.3 三个控制器 + 策略叠加层

| 控制器 | 角色 | 说明 |
|---|---|---|
| `NewReno`（RFC 5681/6582 + PRR 6937） | 基线、对照、最小依赖回退 | 也是模拟器与记账正确性的“金标准”；ECN 响应按 RFC 3168 每 RTT 一次减半并置 CWR |
| `Cubic`（RFC 9438 + HyStart++ 9406） | 阶段 0 即时对照 | 与 smoltcp 自带 `socket-tcp-cubic` 行为对比，验证 fork 记账没有改变已有语义 |
| `Bbr3`（pinned） | 主控制器（双向） | 先忠实复现：STARTUP（full-bw 三轮 1.25× 判定 + 基于丢包的提前退出）、DRAIN、ProbeBW 四态 DOWN/CRUISE/REFILL/UP、`bw_hi/bw_lo`、`inflight_hi/inflight_lo`、headroom、ProbeRTT（5s/200ms）、ack aggregation `extra_acked`、丢包响应 `inflight_lo = (1-beta)·inflight`、ECN 响应 `ecn_alpha` EWMA、`ecn_max_rtt_us` 门限。所有常数以 pinned `tcp_bbr.c` 的 `bbr_*` 为准，不在文档里抄写 |

**关于 “魔改 BBR”**：所有偏离都以“策略叠加层”实现，每项独立开关、默认关闭、默认行为 = 参考 BBRv3。每项策略必须声明：触发条件、期望效果、度量指标、回退条件。候选：

1. `path_prior`：同类路径（同 /24 或 /48 + 同接口 + TTL 60s + 置信度）为新连接提供有界 `bw_hi`/`min_rtt` 先验，缩短 STARTUP；不得据此跳过 STARTUP 的 full-bw 判定。回源方向对同一源站集群天然适用，先验命中率预期高于客户端方向。
2. `probe_up_policy`：在“额外注入确实带来额外交付”且节点 CPU/出口租约允许时，延长 ProbeBW_UP 或提高增益；必须有探测额度和结束条件。
3. `loss_tolerance`：仅在 RTT 未升、交付率未降、无 ECN CE、非 RTO 的多信号一致时，放宽 `loss_thresh` 一档；任一信号缺失即回参考值。**不是**“忽略丢包”。
4. `egress_plateau`：节点级观察 sum(delivery_rate) 平台期 + 与注入相关的丢弃，收紧节点出口租约；不把各连接 bw 估计相加当物理带宽。
5. `probe_stagger`：同节点连接的 ProbeBW_UP 错峰（哈希到 slot），仅在证明共享瓶颈（同接口出口）时启用。
6. `ecn_public_policy`：BBRv3 上游只在 `min_rtt ≤ ecn_max_rtt_us`（DC/L4S）响应 ECN；公网 RTT 上收到的 CE 来自经典 AQM。本策略决定：公网 CE 按 RFC 3168 语义（一次/RTT，作用于 `inflight_lo`）还是沿用上游忽略。默认沿用上游，开启需审批。
7. `path_loss_floor`：从路径质量表（第 6.5 节）取该路径的基线随机丢包率（置信度加权），把 BBRv3 的 `loss_thresh` 从固定 2% 改为 `max(2%, floor + margin)`，只把高于基线的丢包视为拥塞信号。守卫：交付率随 inflight 增长停滞、RTT 抬升或 CE 出现时立即回参考值；基线只能由无 RTT 抬升的丢包样本贡献。这是针对“高丢包但带宽充足”的国际链路的唯一 CC 侧调整，其余靠路径选择避开。

**Reno 的定位**：不是主控制器，而是（a）算法与记账正确性的对照；（b）`NoControl` 的最小替代；（c）短流/小响应在有先验时的候选。是否在业务上使用由 T9 实验决定。

### 2.4 ECN 响应与 AccECN 的关系（双向）

- 经典 ECN 只能每 RTT 反馈一次 CE，`delivered_ce` 只能是事件；BBRv3 的 `ecn_alpha` 需要 AccECN 的 ACE/CEB 精确计数才有意义。
- **客户端方向（我们是服务端/主要发送方）**：客户端请求 AccECN → 我们的响应数据以 ECT(0) 发送 → 路径 AQM 打 CE → 客户端 ACE 精确回报 → 我们的 `Bbr3.on_ecn_ce` 得到字节级比例。
- **回源方向（我们是客户端/主要接收方）**：我们在 SYN 请求 AccECN → 源站（Linux 7.0+ 默认支持）以 ECT(0) 发送 → 我们作为接收方精确回报 ACE/CEB → 源站的 CC 受益；我们向源站的上行（请求体/上传）由我们的 `Bbr3` 控制。
- 命中率取决于对端内核版本，T9 用真实客户端与源站分布测量，不预设收益。不做 L4S/ECT(1)/Prague。

## 3. AccECN（RFC 9768）双角色设计（smoltcp-edge 内）

### 3.1 被动方（客户端方向）

1. **协商**（SYN 的 AE,CWR,ECE）：`(1,1,1)` → AccECN；`(0,1,1)` → 经典 RFC 3168；其他 → 无 ECN。SYN-ACK 用 (AE,CWR,ECE) 回报收到 SYN 的 IP-ECN：`(0,1,0)` Not-ECT、`(0,1,1)` ECT(1)、`(1,0,0)` ECT(0)、`(1,1,0)` CE；经典 ECN 回 `(0,0,1)`。
2. challenge 路径（ADR-001 MSS-only SYN-ACK）无法协商 ECN，本轮显式限定 AccECN 仅对 smoltcp 终止路径生效；若未来需要，参考 Linux AccECN 系列对 `syncookies.c` 的做法把 ECN 模式编码进 cookie。

### 3.2 主动方（回源方向）

1. SYN 置 (AE,CWR,ECE)=(1,1,1)，可携带 AccECN 选项请求对方回带选项。
2. SYN-ACK `(0,1,0)/(0,1,1)/(1,0,0)/(1,1,0)` → AccECN 并据此得知 SYN 的 IP-ECN 是否被改写；`(1,0,1)`（保留“Nonce”组合）按 §3.1.3 视为 AccECN；`(0,0,1)` → 经典；`(0,0,0)` → 无 ECN。
3. SYN 超时重传按 §3.1.5 与 Linux `tcp_ecn_fallback` 语义退回 Not-ECN SYN，并记录原因码（这是规范行为，需可观测）。
4. 首个 ACK 携带 AccECN 选项回报 SYN-ACK 的 IP-ECN。

### 3.3 共同部分

1. **ACE 字段**：三比特 (AE,CWR,ECE) 作为收到 CE 报文计数 mod 8，初值 5；字节计数 `e0b/ceb/e1b` 初值 1。
2. **AccECN 选项**：Kind 172（AccECN0：EE0B, CEB, EE1B）/ Kind 174（AccECN1：EE1B, CEB, EE0B），24-bit 计数；发送策略按 §3.2.6（计数变化时携带 + 每 RTT 最少信标），与 SACK/TS 的选项空间裁剪有明确优先级。
3. **发送侧**：协商后数据段 IP-ECN 置 ECT(0)；纯 ACK 保持 Not-ECT；从 ACK 的 ACE/CEB 增量推 `delivered_ce`；ACE 回绕按 §3.2.2.5 的最小回绕假设，有选项时优先用 CEB。
4. **接收侧**：解析入包 IP-ECN，CE 递增 ACE 与 CEB；ECT(0)/ECT(1) 递增 EE0B/EE1B；反馈随每个 ACK。
5. **失效处理**（§3.2.x，属于规范要求的协议行为）：中间盒清零 AE、对端不再携带选项、ACE 不变但 CE 已知等，按规范转入经典 ECN 或关闭 ECN，并在 `CcSnapshot.ecn_mode` 与计数器中记录原因；不得伪装成正常状态。
6. **测试**：移植 Linux selftests `tcp_accecn_*.pkt` 的用例语义为 Rust 报文脚本测试，被动方与主动方各一组。

## 4. 用户态队列调度（AF_XDP TX 的 “fq / CAKE / FQ-PIE”）

C14 决定所有队列机制在 `bridge` 的 TX 提交前实现。回源接管后，同一个调度器同时管理客户端方向与回源方向的发送。

### 4.1 取自 fq：每流发送时间 + 时间结构

- 每条有待发数据的连接持有 `next_send_at`；由 `pacing_rate`、本次发送字节数和有界初始突发（类 fq `initial_quantum`/`quantum`：10×MSS 起步、稳态 2×MSS）更新。
- 时间结构：**参考实现**为 `BinaryHeap<(next_send_at, generation, flow)>` 惰性删除；**目标实现**为 3 层分层时间轮（示例：64µs×256 / 16ms×256 / 4s×256，粒度由基准决定）+ 溢出堆。每流至多一个有效条目，`generation` 防旧事件推进新连接。
- 线程等待 `min(时间轮最近到期, smoltcp poll_delay, RX 就绪)`；不为报文创建 tokio sleep；临近到期 ≤50µs 才允许短忙等，并纳入 CPU 预算。
- 长暂停后追赶：`next_send_at` 落后于 now 时只补发一个有界突发，不把暂停期间的额度一次性倾泻。

### 4.2 取自 CAKE：时间基整形、分层、开销补偿

- **节点/接口出口整形**：CAKE 式 deficit 整形（`time_next_packet += len·8/rate`，`overhead` 补偿以太/VLAN/QinQ 头，突发 ≤ 1ms×rate）。rate 来源优先级：显式配置的 vNIC 出口 → `egress_plateau` 策略测量值 → 无（不整形，只保留 XSK slot 约束）。**不**用各连接 BBR 带宽估计求和。
- **分层（tin）→ 业务优先级**，有界、工作保持、不均分：
  - T0 控制推进：ACK、握手、关闭、丢失恢复重传（两方向）；保证份额（如 ≤20%）但不能被饿死，也不能无限置顶。
  - T1 完成时间敏感：首字节、小响应、交互流；**有客户端等待的 cache-miss 回源请求**默认也在此层（是否保留由 T9 决定）。
  - T2 大流：客户端方向大响应与回源预取/大文件；消费剩余。
  - 已知剩余长度的响应可评估 SRPT；未知长度、透传流不伪造剩余量。
- **不采纳**：ack-filter、per-host 公平、固定哈希桶、GSO 拆分。

### 4.3 取自 CoDel/PIE：只用于我们真正“转发”的队列

- 适用对象：UDP/QUIC 透传队列、跨接口 `AfXdpForward` 通道、任何“我们不是端点”的排队点。
- 行为：以入队时间计算逗留时间；CoDel `target=5ms / interval=100ms` 或 PIE 15ms 周期概率更新；超阈值时 **ECT 报文打 CE**（合法转发跳），Not-ECT 报文丢弃并计数。二选一由基准决定，只交付一个。
- **不适用于我们终止的 TCP**：自己的负载不能丢。回源接管后背压机制变得直接：客户端方向发送缓冲逗留时间超 target → **收窄我们向源站通告的接收窗口**（同一 reactor 内的 dialed 会话 rwnd），源站按其 CC 自然减速；不再依赖内核 socket 的读取速率。
- 自适应每连接发送缓冲：`clamp(2×BDP_est, 32KiB, per_conn_cap)`，两方向会话都在 F3 全局字节预算内申请；预算不足时缩窗而不是拒绝已建连接。

### 4.4 合法发送条件（bridge 层单一裁决点）

```
send_bytes = min(cwnd_remaining, rwnd_remaining, pacer_allowance(now), worker_lease, xsk_tx_slots × frame)
```

- `worker_lease`：节点出口治理向每个 XSK worker 批量租用（如 250µs 的额度），租约耗尽才碰全局原子。
- 批量 TX 只聚合已到期且已获额度的报文；限制单批序列化时间。
- QUIC：quinn 自己 pace，公共层只叠加租约与分层选择，`poll_transmit` 的期限接入时间轮。

### 4.5 复杂度与 CPU 边界

- 堆 O(log N) 与时间轮平均 O(1) 必须用同一事件轨迹对比发送顺序一致。
- 回源接管使每个代理连接对应两个 smoltcp 会话；2c2g 上调度器自身开销（每包 ns、每轮 µs、P99）与会话数上限是验收指标。

## 5. QUIC 路径

1. `Bbr3` 实现 `quinn_proto::congestion::Controller` + `ControllerFactory`，映射 `on_sent/on_ack/on_end_acks/on_congestion_event` 到 RateSample。
2. Pacing：先接受 quinn `window/srtt` 令牌桶；T5 测量 ProbeBW_UP/DOWN 的实际发送速率偏差；若影响模型，再以 `[patch.crates-io]` 小 patch 让 `Pacer::delay` 读取 `metrics().pacing_rate`。需审批。
3. ECN：修 C11 —— `SharedQuinnUdpSocket::try_send` 把 `transmit.ecn` 传给 `UdpDownstreamSender` 并在 AF_XDP 编码路径写 IP TOS/TC；`poll_recv` 从 IP 头填 `RecvMeta.ecn`。只声称 ECT(0)。
4. 不启用 quinn 内置 `Bbr`（C10）。修正 `quic_transport.rs` 的 per-stream 注释（C16），把 `send_window` 计入 F3 预算。

## 6. 回源方向由 XDP 接管：active open 设计

### 6.1 smoltcp-edge 主动打开

- 增加 `dialed` 会话类型：`socket.connect(local, remote)`；客户端侧 TCP 选项：MSS、SACK-permitted、TS、窗口缩放、AccECN 请求（§3.2）。
- 本地端点：出接口上的本地 IP（配置或从接口地址表选择）+ 保留端口范围内分配的源端口（每 (local_ip, remote) 对做端口去重，回收有 TIME-WAIT 等价保护）。
- 邻居与路由：默认网关 IPv4/IPv6 由配置或运行时读取内核路由表得到；网关 MAC 由 smoltcp 自身 ARP/NDP（Ethernet medium 已启用）解析，首次解析期间的 SYN 排队而不是丢弃；可选以内核 `ip neigh` 结果作为预热。
- PMTU：eBPF 把内层 5 元组匹配我们出向流的 ICMP Frag-Needed / ICMPv6 PTB 投递到归属 XSK，smoltcp-edge 据此调整 MSS；未收到 ICMP 时使用接口 MTU 派生 MSS，不做黑洞探测以外的猜测。
- 复用现有 `virtual_l4_stream`：pingora 上游连接器与 `tcp_proxy` 后端连接改为通过 reactor 请求 dialed 会话并拿到虚拟 L4 流；TLS 到源站在该流上完成（已是 pingora 的 VirtualSocket 路径）。连接池复用、空闲超时、半关闭必须驱动 smoltcp 会话生命周期。
- UDP 回源：同理走 AF_XDP 出向流表，与现有 UDP 透传路由缓存合并。

### 6.2 eBPF 出向流表

- 用户态在发送 SYN 前把 (proto, local_ip, local_port, remote_ip, remote_port) → XSK 索引写入出向流表；eBPF 入向对匹配的返回报文 redirect 到该 XSK，优先级高于内核栈；关闭后删除。
- 多队列约束与 F7 同类：返回流量的 RSS 队列可能不是归属 XSK 的队列，必须复用 F7 的解决方案（先投递到当前 ingress 的有效 XSK，再有界用户态交接），不能跨队列 XSKMAP 直投。
- ICMP 错误报文按内层 5 元组查同一张表。

### 6.3 内核 RST 防护（C17）

- `net.ipv4.ip_local_reserved_ports` 预留我们的源端口范围，内核不再分配。
- netfilter 对入向目标端口在该范围内的 TCP/UDP 加 DROP（fail-closed 守卫），保证 XDP detach 窗口内漏到内核的报文不会引发 RST/ICMP port unreachable。这是安全策略意义上的 fail-closed，需记录、可观测、有回归测试。
- reload/prepare 期间 dialed 会话与 accepted 会话遵守同一 F1 生命周期合同。

### 6.4 分阶段接入

- 配置键 `xdp.upstream = kernel | afxdp`。开发与验收期间默认 `kernel` 仅为分阶段验证，**接管完成后默认 `afxdp`**，且 `kernel` 仅在 XDP 关闭模式下有意义。这不是降级开关，是迁移期开关，迁移完成后是否删除由用户决定。
- 每个 dialed 会话进 F3 三级预算；会话上限估算按“每代理连接两个会话”重算。

### 6.5 国际网络：路径多样性、质量测量与选择

前提事实：单条 TCP/QUIC 连接的拥塞控制只能适应它所在的那条路径，不能替我们换路。国际链路上同一目的地经不同出口 IP、不同地址族、不同 ECMP 哈希、不同源站/父节点到达，丢包与 RTT 可能相差一个数量级。因此“高丢包路径 vs 零丢包路径”是**路径选择问题**，第 2 节的 CC 只负责在被选中的路径上尽量高效。回源接管让我们在拨号时拥有全部选择权；客户端方向我们没有换路能力。

#### 我们实际拥有的杠杆（按成本与确定性排序）

| 杠杆 | 作用点 | 说明 |
|---|---|---|
| L1 源站候选选择 | dialed 会话的目的地址 | `primaryOrigins/backupOrigins` 的多个地址、A/AAAA 双栈、同一源站的多 IP：按测得路径质量选，而不只按 weight 轮询；Happy Eyeballs（RFC 8305）式有界竞速拨号，保留先完成/更优的一条，其余 RST |
| L2 源侧多样性 | dialed 会话的本地端点 | 多公网 IP / 多出接口时选择源 IP 与出接口；**源端口重掷**与 IPv6 flow label 变化以改变中转 AS 的 ECMP 哈希。只有探测证明存在哈希多样性（不同源端口的 RTT/丢包分布显著不同）时才启用，避免无意义的 SYN 放大 |
| L3 父节点中转 | 分级 CDN 的 node → parent 跳 | 仓库已有 `level` 与 `parentNodes`（`ParentNodeConfig { addrs, lnAddrs, weight, isBackup }`）；父节点按测得路径质量选择。node↔parent 两端都是我们的栈，是唯一可以启用 FEC/私有封装的受控隧道（设计提案的可行性边界） |
| L4 路径感知的 CC 参数 | 被选路径上的连接 | `path_prior`（暖启动 `bw_hi/min_rtt`，长 RTT 国际链路上 STARTUP 可省数秒）与 `path_loss_floor`（第 2.3 节第 7 项），都从路径表取值，都有守卫 |
| L5 传输中重选路 | 幂等 cache-fill | 当前连接交付率相对候选路径塌陷（如 <30% 且持续 ≥2 RTT 窗口）时，中止并以 Range 从另一候选续拉；只对幂等 GET、有 `Accept-Ranges`/强校验器的对象；计入重复字节成本；默认关闭 |
| L6 客户端方向 | 无换路能力 | 只能：(a) CC/恢复对观测路径鲁棒；(b) 按客户端前缀导出路径质量（丢包、RTT、交付率）给控制面，由 DNS/GSLB 决定把客户端调度到路径更好的节点；(c) QUIC 客户端迁移由 quinn 现有能力支持 |

#### 路径质量表（transport crate `path_table`）

- 键：dialed 侧 `(egress_iface, local_ip, af, dst_prefix /24 或 /48, dst_port_class)`；accepted 侧 `(ingress_iface, local_ip, af, client_prefix)`。父节点与源站条目共用同一结构。
- 值（全部 EWMA + 样本数 + 最后更新时间 + 置信度）：`connect_rtt`、`connect_fail_rate`、`min_rtt`、`srtt`、`jitter`、`bw_hi`、`loss_rate` 分成“伴随 RTT 抬升的丢包”与“无 RTT 抬升的丢包”两列（后者是随机丢包基线的依据）、`ce_rate`、`retrans_ratio`、`spurious_retrans_ratio`（DSACK/TS 判定，乱序指标）。
- 数据来源：**被动为主**，直接消费活跃连接的 RateSample 与 RttState（零额外流量）；**主动探测为辅**，只在候选 ≥2 且条目陈旧/缺失时，以真实服务端口的 TCP SYN（测握手 RTT 与成功率）按目的地限速探测，不依赖 ICMP。
- 衰减与恢复：时间衰减；ε-greedy 探索（默认 ≤5% 的新拨号走非最优候选）保证坏路径恢复后能被发现、好路径劣化后能被替换。
- 选择：按请求类别估算完成时间——小对象由 `connect_rtt + srtt` 主导，大对象由该路径的实测 `bw_hi` 与丢包/RTT 下的可达交付率主导；切换需迟滞（连续两个窗口优于当前 >20%）并对连接池友好（池键包含路径选择，避免复用到已判劣的路径）。
- 边界：不覆盖健康检查的“不可用”判定；不把所有路径的 `bw_hi` 相加当出口带宽；探测与探索有节点级额度。

#### 恢复机制对国际链路的补充（进入 T3）

- 乱序：RACK 的 `reo_wnd` 自适应 + DSACK（RFC 2883）识别伪重传 + 基于 TS 的 Eifel（RFC 3522）撤销错误的 cwnd 削减；否则 ECMP/LAG 乱序会被当成丢包。
- 尾丢包：TLP 必备；长 RTT 上 RTO 代价极高。
- 长 RTT 的 BDP：100Mbit × 300ms ≈ 3.75MB/连接，不能给每条连接无条件预留；按路径表的 BDP 估计与分层（T1 优先）在 F3 预算内分配，向源站通告的 rwnd 才能覆盖 BDP。

#### 明确不做

- 不在 smoltcp-edge 实现 MPTCP：客户端普遍不启用，收益不可预期。
- 不在通用 TCP/HTTP 上做 FEC/私有封装；只允许在 node↔parent 受控隧道评估（T10）。
- 不用 ICMP 结果作为路径选择依据。

## 7. 前置：时钟与字节记账

- `TransportInstant`：基于 `std::time::Instant` 的单调 µs 时钟，映射到 `SmoltcpInstant::from_micros`；reactor、pacer、RateSample、时间轮统一使用；测试可注入。替换 `tcp_reactor.rs:668/775` 的墙钟。
- F3 字节预算：每连接/每队列/节点三级许可随 `Bytes` 生命周期转移，覆盖 accepted 与 dialed 两类会话；RateSample 的 `in_flight` 与预算的 `queued` 分别暴露。
- F4 sweep 计时修正是调度器正确性的前提。

## 8. 验证策略

1. **确定性模拟器**（`cloud-node-transport::sim`）：事件驱动；链路 `{rate, delay, buffer_bytes, aqm: none|droptail|codel_ecn, policer, random_loss p, reorder}`；运行 NewReno/Cubic/Bbr3 并断言 STARTUP 退出时机、稳态排队 ≤1.5×BDP、丢包率上界、ProbeRTT 周期、ECN 响应；golden trace 回归。
2. **报文脚本测试**（smoltcp-edge）：被动/主动两角色的 AccECN 协商、经典 ECN、SACK/RACK/TLP、TS/PAWS、窗口缩放、选项裁剪、active open 三次握手/同时打开/SYN 重传回退。
3. **调度器等价测试**：同一事件轨迹下堆与时间轮发送顺序一致；generation；长暂停追赶有界。
3b. **路径选择测试**：模拟器双候选路径的选择收敛与互换后重新收敛；VPS 上源站经两条 veth 路径、不同 netem 的拨号分布、迟滞、恢复发现、SYN 竞速无泄漏。
4. **回源接管专项**（VPS veth/netns）：源站在另一 netns；验证 SYN 经 AF_XDP 发出、SYN-ACK 被 eBPF 出向流表捕获、内核 `ss` 无对应 socket、无 RST 外泄（tcpdump 断言）；XDP detach 窗口注入源站报文，断言 netfilter 守卫丢弃且计数增长；多队列限定声明。
5. **远程弱网矩阵**（netem 施加在报文真实经过的链路，确认 impairment 计数增长）：RTT {5,50,150,300}ms × 丢包 {0,0.1,1,3}% × 带宽 {10,100,1000}Mbit × 缓冲 {0.25,1,4}×BDP × policer 有/无 × 并发 {1,10,100}，客户端侧与回源侧分别施加。指标：成功业务字节/秒、完成时间、P99、重传字节比例、CPU/Gbit、RSS、出口队列时间、过载恢复时间、算法状态轨迹。对照组：XDP 关闭的 socket 代理路径（内核 TCP，不改造）。
6. 不以无损低 RTT echo 通过代替；缺乏基线不写提升百分比。

## 9. 分阶段任务与 Devin 提示词

通用约束（每个提示词都包含）：

- 遵守 `.cursor/rules/no-unapproved-degradation.mdc`：不得为让测试通过而静默禁用、旁路、吞错、缩短超时或改语义；发现已有降级先报告。
- 本机只编辑与静态阅读；编译/测试/eBPF 构建/压测在授权 VPS .110/.120 的隔离目录与 netns/veth，禁止清理生产 bpffs；不新增 B 组/TC 后端；不 tag/push/部署。
- 范围：只改造 XDP/AF_XDP 数据面；非 XDP 模式不做传输改造，只作 T9 基线。
- 引用固定版本：smoltcp 0.14.0、quinn-proto 0.11.17、google/bbr v3 `90210de4`、draft-ietf-ccwg-bbr-06、RFC 9768/8985/6937/9438/9406/7323/3168。
- 每个任务单独提交，证据（命令、SHA、内核/网卡/队列/copy 模式、结果、未测范围）写入 `docs/edge-node-evidence/` 与单一状态入口。
- 最终报告区分：已修复、仍存在、设计限制、经审批的降级。

### T0 · 前置闭合（沿用发布审阅顺序，不重复规划）

F6 → F5 → F4 → F2 → F8 止血（启用 `socket-tcp-cubic`，`set_congestion_control(Cubic)`，`/status` 暴露实际算法，断言不为 `None`）→ F3 → F1 → F7。T1 起的任务从 T0 落地后的提交分支。

总顺序：T1 时钟 → T2 transport crate → T3 fork 钩子 → T4 回源 active open → **T4b 路径质量表与拨号选择** → T5 BBRv3 → T6 AccECN → T7 调度器 → T8 AQM/背压 → T9 矩阵与决策 →（可选）T10 父节点隧道。T4b 放在 BBRv3 之前，是因为 `path_prior`/`path_loss_floor` 都依赖路径表，且路径选择本身不依赖具体拥塞算法。

### T1 · 单调传输时钟与传输可观测骨架

```
任务：为 AF_XDP TCP reactor 引入单调 µs 传输时钟，并建立传输层可观测骨架。
基线：<填写 T0 完成后的 commit>。先核对 HEAD，若已有并行修改逐条核销。
范围：只改造 XDP/AF_XDP 数据面；非 XDP 模式不做传输改造。
背景：src/xdp/af_xdp/tcp_reactor.rs:668 与 :775 用 crate::utils::time::now_timestamp_millis()（系统时间+偏移，ms）构造 SmoltcpInstant；pacing/RTT/交付率采样需要单调 µs 时钟。
要求：
1. 新增 TransportClock（基于 std::time::Instant 锚点，输出 µs，可在测试中注入/推进），reactor、bridge 的所有协议时间改用它；SmoltcpInstant 用 from_micros。
2. 保留 utils::time 的业务时间用途不变。
3. /status 与 tracing 增加每会话快照：会话方向（accepted/dialed，当前只有 accepted）、算法名与版本钉、cwnd、in_flight、srtt/min_rtt、pacing_rate、delivered/lost 累计、ecn_mode、队列字节；先填 smoltcp 现有可得字段，缺失标记 None 而不是伪造。
4. 测试：时钟单调性与注入推进；reactor 现有测试改为注入时钟后全部保持通过；F4 的 1ms 连续 poll 测试基于新时钟重跑。
验收：VPS release 构建 + 目标测试通过；提交 SHA 与命令记录到证据目录。不改变任何发送/接收语义。
```

### T2 · `crates/cloud-node-transport`：RateSample、CC trait、NewReno/Cubic、模拟器

```
任务：创建 crates/cloud-node-transport（纯算法 crate，不依赖 tokio/smoltcp/quinn），实现 RateSample、CongestionController trait、NewReno（RFC 5681/6582 + PRR RFC 6937）、Cubic（RFC 9438 + HyStart++ RFC 9406）与确定性网络模拟器。接口按双向（发送方/接收方角色无关）设计。
基线：T1 完成后的 commit。
设计输入：tasks/xdp-transport-next-steps-2026-09-15.md 第 2.1–2.3、8.1 节。
要求：
1. RateSample 对齐 Linux net/ipv4/tcp_rate.c 语义：每段 TxRecord（sent_at、delivered_at_send、delivered 快照、first_tx_at、is_app_limited、is_retransmit）；interval=max(send_elapsed, ack_elapsed)；重传段不产生 RTT 样本；app-limited 随段传递。
2. trait 接口按文档 2.2；CcSnapshot 含算法名+版本钉与原因码。
3. 模拟器：事件驱动，链路 {rate, delay, buffer_bytes, aqm none|droptail|codel_ecn, policer 令牌桶, random_loss, reorder}；发送端由 trait 驱动；输出 trace。
4. 测试：NewReno/Cubic 在 {RTT 10/100ms × bw 10/100Mbit × buffer 0.5/2×BDP × loss 0/1%} 的锯齿、PRR、HyStart++ 退出；golden trace 回归；RateSample 对 ACK 压缩、延迟 ACK、SACK 的单元用例。
5. 本 crate 加入 workspace；根 crate 暂不接入数据面（T3 做）。
验收：VPS 上 cargo test -p cloud-node-transport 通过；trace 文件与命令记录进证据目录。不修改 src/xdp。
```

### T3 · `vendor/smoltcp-edge`：受控 fork 与传输钩子（被动方）

```
任务：以 Cargo.lock 锁定的 smoltcp 0.14.0 建立受控 fork vendor/smoltcp-edge，通过 [patch.crates-io] 覆盖 Cargo.toml:90 与 :95 两处声明；在 socket/tcp.rs 增加传输钩子，并把 AF_XDP reactor 的 accepted 会话接到 cloud-node-transport 的 CongestionController。
基线：T2 完成后的 commit。
必须补齐（对照文档第 0 节 C1–C5）：
1. 每段 TxRecord 记录与 RateSample 生成（复用 transport crate），替换 pub(super) Controller 为 transport crate 的公开 trait；保留 smoltcp 自带 NoControl/Reno/Cubic 作为 feature 对照。
2. TCP Timestamps（RFC 7323）用于每 ACK RTT 样本与 PAWS；窗口缩放保持现有实现。
3. 发送侧 SACK 记分板 + RACK-TLP（RFC 8985，含 reo_wnd 自适应）+ PRR + DSACK（RFC 2883）伪重传识别 + 基于 TS 的 Eifel 撤销（RFC 3522）；保留 3-dupack/RTO 路径并在测试中对比。乱序场景（ECMP/LAG）必须有专门用例，断言不产生伪重传导致的 cwnd 削减。
4. IP/TCP repr 贯通 ECN 字段（Ipv4Repr/Ipv6Repr ecn、TcpRepr ae/cwr/ece），本任务只贯通不协商（协商在 T6）。
5. dispatch 增加“最早发送时间”门：socket 暴露 next_send_at 与 pacing_rate；poll_egress 只发已到期段（调度器在 T7 接管选择）。
6. 写 vendor/smoltcp-edge/DIVERGENCE.md 列出每处与上游 0.14.0 的差异与原因。
7. reactor：生产 socket 创建处显式选择控制器（默认 Cubic，保持 F8 止血行为），CcSnapshot 进 /status。
测试：smoltcp 自带 tcp 测试全部保留通过；新增报文脚本测试覆盖 SACK/RACK/TLP/TS/PAWS；同一 ACK 轨迹下 fork 的 Cubic 与上游 Cubic cwnd 曲线一致。
验收：VPS release 构建；veth 双栈协议矩阵重跑无回归；证据入库。禁止在此任务中改 BBR、ECN 协商或 active open。
```

### T4 · 回源方向由 AF_XDP 接管：active open、eBPF 出向流表、内核 RST 防护

```
任务：让回源连接（TCP 与 UDP）经 smoltcp-edge 在 AF_XDP 上主动打开，替代 pingora/tcp_proxy 的内核 socket；新增 eBPF 出向流表与内核 RST 防护。
基线：T3 完成后的 commit。
设计输入：文档第 6 节；C12、C17；F1/F3/F7 合同。
要求：
1. smoltcp-edge：dialed 会话（connect），客户端侧选项 MSS/SACK-permitted/TS/窗口缩放（AccECN 请求留 T6）；源端口从保留范围分配并按 (local_ip, remote) 去重回收；默认网关 ARP/NDP 由 smoltcp 解析，解析期间 SYN 排队；PMTU 由投递到 XSK 的 ICMP Frag-Needed/PTB 驱动，否则用接口 MTU 派生 MSS。
2. reactor：accepted/dialed 两类会话共用 pump/sweep/reaper/预算；dialed 会话通过 virtual_l4_stream 暴露给 pingora 上游连接器与 tcp_proxy 后端连接；连接池复用、空闲超时、半关闭驱动 smoltcp 生命周期；UDP 回源并入出向流表。
3. eBPF：出向流表 (proto, local_ip, local_port, remote_ip, remote_port) → XSK；返回报文与匹配内层 5 元组的 ICMP 错误 redirect 到归属 XSK；多队列下复用 F7 方案，不跨队列直投；关闭即删。
4. 内核守卫：启动时设置 net.ipv4.ip_local_reserved_ports 预留范围，并对入向目标端口在范围内的 TCP/UDP 加 netfilter DROP；两者失败为显式启动错误，不静默继续。守卫计数进 /status。
5. 配置键 xdp.upstream = kernel|afxdp；本任务默认 kernel 仅用于分阶段验收，报告中明确接管完成后默认 afxdp。
6. tcp_proxy.rs:1849-1863 对内核 relay socket 的 TCP_CONGESTION 设置在 afxdp 模式下不再执行；kernel 模式保持原样并在报告中列为“随接管退役”。
测试：报文脚本测试覆盖三次握手、SYN 重传、同时关闭、RST；VPS veth/netns：源站在另一 netns，断言 SYN 经 AF_XDP 发出、SYN-ACK 被出向流表捕获、`ss` 无内核 socket、tcpdump 无 RST 外泄；XDP detach 窗口注入源站报文，断言守卫丢弃且计数增长；HTTP/HTTPS/TCP/UDP 回源矩阵双栈通过；带活跃回源连接的 reload 遵守 F1。
验收：VPS release 构建 + 上述测试；证据记录实际内核、队列数、copy 模式、保留端口范围与守卫规则。
```

### T4b · 路径质量表与拨号路径选择（国际网络）

```
任务：在 cloud-node-transport 实现 path_table（路径质量表），并在 dialed 会话的拨号点实现候选选择：源站/父节点多地址、A/AAAA 双栈、源 IP/出接口、源端口重掷；被动测量为主、有界主动探测为辅。
基线：T4 完成后的 commit。
设计输入：文档第 6.5 节；ReverseProxyConfig.primaryOrigins/backupOrigins（config_models.rs:3013-3048）、OriginConfig（:3259）、ParentNodeConfig（:154）与 lb_factory.rs 的现有 LoadBalancer 结构。
要求：
1. path_table 键与值按 6.5 节；被动样本来自 accepted/dialed 会话的 RateSample/RttState（零额外流量）；丢包分“伴随 RTT 抬升”与“无 RTT 抬升”两列；DSACK/TS 判定的伪重传比例单列。
2. 主动探测只在候选 ≥2 且条目陈旧/缺失时进行：真实服务端口 TCP SYN 测握手 RTT 与成功率，按目的地限速，节点级额度；不用 ICMP。
3. 拨号选择：按请求类别估算完成时间（小对象 connect_rtt+srtt 主导，大对象实测 bw_hi 与丢包/RTT 下可达交付率主导）；Happy Eyeballs（RFC 8305）式有界竞速（最多 2 路），落选方 RST；ε-greedy 探索默认 ≤5%；迟滞：连续两个窗口优于当前 >20% 才切换；连接池键包含路径选择。
4. 源端口重掷/flow label 变化只在探测证明 ECMP 哈希多样性（不同源端口 RTT/丢包分布显著不同，给出统计判据）时启用，否则不放大 SYN。
5. 与现有 LoadBalancer/健康检查的关系：健康检查的“不可用”优先级最高；weight 作为先验，不再是唯一依据；lb_factory 中未使用的 level/parent_nodes 参数（:244-246）在本任务里接通到父节点候选。
6. 传输中重选路（L5）只建接口与计数，默认关闭，实现留 T9 实验后决定。
7. 按客户端前缀的路径质量导出：通过现有 rpc/stats 通道上报聚合值（丢包、RTT、交付率、样本数），供控制面 DNS/GSLB 调度；不在节点内做客户端换路。
8. /status 暴露每候选路径的质量条目、当前选择、探索比例、探测额度使用。
测试：transport crate 单元测试（EWMA/衰减/置信度/迟滞/探索比例）；模拟器中两条候选路径 {loss 3% + 低 RTT, loss 0% + 高 RTT} 与 {同 RTT, loss 5% vs 0%} 的选择收敛、路径质量互换后的重新收敛时间；VPS veth：源站 netns 经两条 veth 路径可达，netem 分别施加不同丢包，断言拨号分布、切换迟滞、坏路径恢复后的重新发现、SYN 竞速无泄漏 socket。
验收：VPS release 构建 + 上述测试 + 双向协议矩阵无回归；证据记录选择分布与探测流量占比。
```

### T5 · BBRv3 参考实现与 QUIC 适配

```
任务：在 cloud-node-transport 实现 Bbr3（参考 google/bbr v3 commit 90210de4b779d40496dee0b89081780eeddf2a60 的 net/ipv4/tcp_bbr.c，规范文本 draft-ietf-ccwg-bbr-06），并实现 quinn_proto::congestion::Controller 适配器；接入 accepted 与 dialed 两类会话（默认仍 Cubic）。
基线：T4 完成后的 commit。
要求：
1. 忠实复现：STARTUP/DRAIN/ProbeBW(DOWN/CRUISE/REFILL/UP)/ProbeRTT、bw_hi/bw_lo、inflight_hi/inflight_lo、headroom、extra_acked、丢包响应、ecn_alpha 与 ecn_max_rtt_us 门限、idle restart。常数从 pinned 源码取值并注明来源行号；与 draft 差异逐条注释。
2. CcSnapshot 暴露 mode、bw_hi/lo、inflight_hi/lo、min_rtt、extra_acked、ecn_alpha、full_bw_reached、原因码。
3. 模拟器验证：{RTT 10/50/150ms × bw 10/100/1000Mbit × buffer 0.25/1/4×BDP × loss 0/0.1/1% × policer 有/无}，断言 STARTUP 退出时机、稳态排队 ≤1.5×BDP、ProbeRTT 周期、丢包响应后 inflight_lo 行为；与 NewReno/Cubic 同轨迹对照。
4. quinn 适配：Bbr3 实现 Controller + ControllerFactory；不启用 quinn 内置 Bbr。测量 quinn window/srtt pacer 与 Bbr3 pacing_rate 的偏差并报告；是否 patch quinn Pacer 列为待审批决策，不在本任务实施。
5. 策略叠加层只建骨架（trait + 全部默认关闭），不实现任何策略。
验收：VPS cargo test 通过；模拟器 trace 入库。不把 Bbr3 设为生产默认，生产切换在 T9 依据实验决定。
```

### T6 · AccECN（RFC 9768）双角色 + 经典 ECN + QUIC ECN 贯通

```
任务：在 vendor/smoltcp-edge 实现 AccECN（RFC 9768）被动方（客户端方向）与主动方（回源方向）协商/反馈，以及经典 ECN（RFC 3168）；修复 H3 共享 UDP 套接字丢弃 ECN 的问题。
基线：T5 完成后的 commit。
设计输入：文档第 3 节；C11/C15。
要求：
1. 被动方：SYN (1,1,1)→AccECN，(0,1,1)→经典，其余无 ECN；SYN-ACK 按收到 SYN 的 IP-ECN 编码 (0,1,0)/(0,1,1)/(1,0,0)/(1,1,0)，经典回 (0,0,1)。
2. 主动方：SYN 置 (1,1,1) 并可带 AccECN 选项；SYN-ACK 四种 AccECN 编码与 (1,0,1) 按 §3.1.3 处理；(0,0,1) 经典；(0,0,0) 无 ECN；SYN 超时按 §3.1.5 退回 Not-ECN SYN 并记录原因码。
3. ACE 三比特计数（初值 5）、e0b/ceb/e1b（初值 1）、选项 Kind 172/174 编解码与发送策略、与 SACK/TS 的裁剪优先级。
4. 发送侧：协商后数据段 ECT(0)，纯 ACK Not-ECT；从 ACE/CEB 增量推 delivered_ce 进 RateSample；ACE 回绕按 §3.2.2.5。
5. 失效处理按 §3.2.x，模式变更写入 CcSnapshot.ecn_mode 与计数器并记录原因；不得伪装成正常状态。
6. 显式限定：eBPF challenge 路径（ADR-001）不协商 ECN，文档与 /status 标注。
7. QUIC：src/quic_udp_demux.rs 的 try_send 传递 transmit.ecn 到 UdpDownstreamSender 并在 AF_XDP 编码路径写 IP TOS/TC；poll_recv 填 RecvMeta.ecn。只声称 ECT(0)。
8. eBPF：核对 tcp_sanity 与任何头部改写不清零 AE 位；补 SYN (1,1,1) 变体测试（参照 src/xdp/tests.rs:1517）；出向流表对返回 SYN-ACK 的 AE 位不做归一化。
测试：移植 Linux selftests tcp_accecn_*.pkt 用例语义为 Rust 报文脚本测试（两角色）；经典 ECN CE→CWR 一次/RTT；veth 上源站 netns 以支持 AccECN 的内核（≥6.18，或用户态模拟）验证主动方协商；QUIC ECN 在 veth 上打 CE 验证 quinn 不再报 “ECN not acknowledged by peer”。
验收：VPS release 构建 + 上述测试 + 双向协议矩阵；证据记录两方向协商成功率与失效原因分布。默认是否开启 ECN 通告作为待审批项在报告中列出。
```

### T7 · 用户态出口调度器（fq/CAKE 派生）与节点出口治理

```
任务：在 cloud-node-transport 实现每连接发送时间调度（最小堆参考 + 分层时间轮）、有界业务分层选择、节点出口租约，并接入 src/xdp/af_xdp/bridge.rs 的 TX 提交与 tcp_reactor 的会话选择；同时管理 accepted 与 dialed 会话。
基线：T6 完成后的 commit。
设计输入：文档第 4.1、4.2、4.4、4.5 节；C7。
要求：
1. 参考调度器：BinaryHeap<(next_send_at, generation, flow)> 惰性删除；目标调度器：3 层时间轮 + 溢出堆；两者同一 trait，同一事件轨迹下发送顺序一致（测试断言）。
2. 合法发送条件在 bridge 单点裁决：min(cwnd_remaining, rwnd_remaining, pacer_allowance, worker_lease, xsk_tx_slots)。
3. 分层：T0 控制推进（保证份额、不可无限置顶）/T1 完成时间敏感（含有客户端等待的 cache-miss 回源请求）/T2 大流；工作保持；不均分。
4. 节点出口治理：rate 来源优先级 = 配置 vNIC 出口 → 无；worker 按 250µs 级租约批量领取；CAKE 式 time_next_packet 整形含 overhead 补偿；突发 ≤1ms×rate。
5. 线程等待 min(时间轮最近到期, smoltcp poll_delay, RX)；忙等窗口 ≤50µs；长暂停追赶有界。
6. AF_XDP_MAX_CONSECUTIVE_TX_FAILURES=256 的退出行为并入 F2 过载合同：TX 背压只背压、计数、继续处理存量，不退出线程。
7. QUIC：quinn poll_transmit 期限接入时间轮，不叠加第二个连接级整形器。
测试：等价性测试；generation；热桶/回绕/过期条目；CPU 微基准（每包 ns、每轮 µs、P99）；bridge 现有测试与双向协议矩阵无回归。
验收：VPS release 构建；单队列 veth 上 1/10/100 并发（每并发两方向会话）下发送节奏轨迹与 CPU 记录入库。无配置时不整形，只启用 pacing 与分层。
```

### T8 · 转发队列 AQM、终止 TCP 的 rwnd 背压与自适应缓冲

```
任务：为 UDP/QUIC 透传与跨接口转发队列实现 CoDel 或 PIE（ECN 标记优先于丢弃）；为我们终止的 TCP 实现基于逗留时间的接收窗口背压（客户端方向发送缓冲逗留 → 收窄向源站通告的 rwnd）与 F3 预算内的自适应发送缓冲。
基线：T7 完成后的 commit。
设计输入：文档第 4.3 节；F3。
要求：
1. AQM 只作用于我们不是端点的队列；ECT 报文置 CE，Not-ECT 丢弃并计数；CoDel(target 5ms, interval 100ms) 与 PIE(15ms 周期) 各实现一版做基准，只交付其一并写明理由。
2. 终止 TCP：accepted 会话发送缓冲逗留时间超 target → 收窄对应 dialed 会话通告的接收窗口（不丢自己负载）；反向（源站慢、客户端上传）对称处理。
3. 自适应发送缓冲 clamp(2×BDP_est, 32KiB, per_conn_cap)，两类会话都从 F3 三级预算申请；预算不足缩窗而不拒绝已建连接；关闭/取消/错误路径释放。
4. AF_XDP_TCP_SESSION_ESTIMATED_BYTES 与会话上限估算改为“每代理连接两个会话”的真实最坏保留量。
测试：模拟器中 AQM 的排队延迟与吞吐曲线；慢读/零窗口/慢源站下 TCP queued bytes、RSS、预算释放、rwnd 轨迹；透传 UDP 在拥塞下的 CE 标记与丢弃计数。
验收：VPS release 多连接慢读矩阵；资源回到可解释基线；证据入库。
```

### T9 · 弱网矩阵、策略实验与生产默认决策

```
任务：在 VPS 私有 netns/veth 与云 vNIC 上执行弱网矩阵，比较 Cubic / NewReno / Bbr3 / Bbr3+单项策略，客户端方向与回源方向分别施加损伤，形成生产默认算法、策略开关与 xdp.upstream 默认值的决策建议。
基线：T8 完成后的 commit。
要求：
1. netem/整形施加在报文真实经过的链路，先确认 impairment 计数增长；记录内核、网卡、队列数、copy 模式、二进制 SHA（release）。
2. 矩阵：RTT {5,50,150,300}ms × 丢包 {0,0.1,1,3}% × 带宽 {10,100,1000}Mbit × 缓冲 {0.25,1,4}×BDP × policer 有/无 × 并发 {1,10,100} × 方向 {客户端侧,回源侧,双侧}；每格记录成功业务字节/秒、完成时间、P99、重传字节比例、CPU/Gbit、RSS、出口队列时间、算法状态轨迹。
2b. 国际多路径矩阵：源站经 ≥2 条路径可达（不同出口 IP / v4 vs v6 / 不同父节点），路径质量组合 {3% 随机丢包+150ms vs 0%+250ms}、{5% vs 0% 同 RTT}、{乱序 1%/5ms 抖动 vs 无乱序}、{中途质量互换}、{一条路径间歇性黑洞 30s}；记录拨号选择分布、切换时延、完成时间、探测/探索流量占比、伪重传比例、path_loss_floor 开启前后的吞吐与丢包。
3. 策略逐项单独开启：path_prior、probe_up_policy、loss_tolerance、egress_plateau、probe_stagger、ecn_public_policy、path_loss_floor、传输中重选路（L5）；每项给出触发条件、效果、回退条件与是否建议保留。
4. 客户端与源站的 ECN/AccECN 支持比例用真实样本测量，不预设收益。
5. 对照组只用 XDP 关闭的 socket 代理路径（内核 TCP，不改造）。
6. 报告：不写提升百分比除非有同环境基线；发生器或 2c2g 达到极限如实标注；提出生产默认建议（含 xdp.upstream=afxdp）但不自行切换默认，等待审批。
```

### T10（可选，需单独审批）· node↔parent 受控隧道

```
任务：评估并实现 node → parent node 的受控传输隧道：两端都运行本项目栈，父节点按 path_table 选择；在隧道内评估 FEC 与 AccECN 双端启用对高丢包国际段的收益。
前提：T4b 完成；用户确认部署中存在多级节点（level>0 且 parentNodes 非空）且父节点可升级到同一版本。
要求：
1. 隧道承载现有 node→parent 回源语义（缓存穿透、Range、请求头透传、secretHash 鉴权）不变；不引入新的明文协议。
2. 传输：复用 smoltcp-edge dialed 会话 + Bbr3 + AccECN 主动方；或 QUIC（quinn + Bbr3 适配）——两者在同一矩阵对比后二选一。
3. FEC 只在隧道内、只对高丢包路径（path_table 基线随机丢包 ≥ 阈值）按需开启；记录冗余字节比例与 CPU；有效吞吐（去冗余后）必须优于无 FEC，否则不保留。
4. 父节点选择与 T4b 共用 path_table 与迟滞/探索规则；父节点全部劣化时回直连源站的条件与可观测性明确。
测试：两节点 netns 拓扑（node、parent、origin），netem 在 node↔parent 段施加 {1,3,5}% 随机丢包与 {150,250}ms RTT；对比直连 vs 经父节点、FEC 开/关的完成时间、有效吞吐、CPU、冗余比。
验收：只在 VPS 双节点验证；报告给出是否建议在生产启用的条件，不自行启用。
```

## 10. 需要用户明确审批的决策点

1. smoltcp 受控 fork（`vendor/smoltcp-edge` + `[patch.crates-io]`）作为长期方案，还是过渡后评估替换 TCP 栈。
2. 回源源端口保留范围与 netfilter DROP 守卫（内核配置变更，fail-closed）。
3. 默认网关 MAC 的来源：仅 smoltcp ARP/NDP，还是允许内核邻居表预热。
4. PMTU 策略：仅 ICMP 驱动 + 接口 MTU 派生，是否补黑洞探测。
5. 是否允许对 quinn-proto 打小 patch 让 Pacer 读取 `pacing_rate`（T5 报告偏差后决定）。
6. 默认是否在两方向通告 ECN/AccECN（RFC 3168 黑洞风险 vs 反馈质量）。
7. 节点出口整形 rate 的配置键与默认（无配置时不整形）。
8. `ecn_public_policy`：公网 RTT 下的 CE 是否作为 BBRv3 模型输入。
9. 转发队列 AQM 选 CoDel 还是 PIE（T8 基准后）。
10. eBPF challenge 路径是否要把 ECN 模式编码进 cookie 以支持 AccECN。
11. `xdp.upstream` 迁移期开关在接管完成后是否删除。
12. 路径选择的默认探索比例（ε）、迟滞阈值、主动探测节点级额度；SYN 竞速最大并行数。
13. 源端口重掷/flow label 变化是否允许（涉及对源站的 SYN 放大与安全设备误判风险）。
14. `path_loss_floor` 的 margin 与最大允许 `loss_thresh` 上限。
15. 传输中重选路（L5）是否实现，及允许的重复字节成本上限。
16. 是否启动 T10 node↔parent 受控隧道（含 FEC）评估。
17. 按客户端前缀导出路径质量给控制面的字段与上报频率。

## 11. 已发现的既有降级（按仓库规则先报告，不在未审批下扩展）

- `src/quic_udp_demux.rs:163-180, 717`：H3 共享 UDP 套接字静默丢弃 ECN，导致 quinn 自禁 ECN；无日志、无指标。
- `src/xdp/af_xdp/bridge.rs:511, 1042-1050`：TX 背压 256 次后退出 worker（与 F2 同类，属于用退出代替削减）。
- `Cargo.toml:90, 95`：未启用任何 smoltcp 拥塞控制 feature → `NoControl`（F8）。
- 现状记录，随回源接管退役而非修复：`src/tcp_proxy.rs:1855-1861` 对内核 relay socket 的 `TCP_CONGESTION=bbr` 忽略返回值；`src/kernel_tuning.rs:275-276` 的 `bbr`/`fq` 为 optional 且不核对运行中 qdisc。在 XDP 关闭模式下它们仍存在且不可观测，报告中如实列出。

## 12. 明确的非目标与设计限制

- 非 XDP 模式（XDP 关闭的 socket 代理路径）不做任何传输改造，只作对照基线。
- 不做跨流均分带宽或对其他算法的公平性优化。
- 不做 L4S/ECT(1)/TCP Prague；不做自定义 FEC 或私有封装。
- 不把 fq/CAKE/FQ-PIE 的 sysctl/tc 配置当作 AF_XDP 发包的队列管理。
- 不用 quinn 内置 `Bbr` 充当 BBR/BBRv3。
- 回源接管的多队列场景受 F7 同样约束；无硬件时显式限定支持范围。
- generic + AF_XDP copy 路径不据此宣称比 socket 代理更快；所有性能结论来自 T9 的同环境对照。

## 上游依据

- [google/bbr v3 分支（commit 90210de4）](https://github.com/google/bbr/tree/v3)
- [draft-ietf-ccwg-bbr-06](https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/06/)
- [RFC 9768 Accurate ECN](https://www.rfc-editor.org/rfc/rfc9768)
- [LWN: More accurate congestion notification for TCP（7.0 默认启用 AccECN）](https://lwn.net/Articles/1058666/)
- [Linux AccECN 协议系列合入（6.18/6.19）](https://github.com/gregkh/linux/commit/667539f6dce27aa7db0a711375f94e14e714a698)
- [RFC 8985 RACK-TLP](https://www.rfc-editor.org/rfc/rfc8985) · [RFC 6937 PRR](https://www.rfc-editor.org/rfc/rfc6937) · [RFC 9438 CUBIC](https://www.rfc-editor.org/rfc/rfc9438) · [RFC 9406 HyStart++](https://www.rfc-editor.org/rfc/rfc9406) · [RFC 7323 TCP Extensions](https://www.rfc-editor.org/rfc/rfc7323) · [RFC 3168 ECN](https://www.rfc-editor.org/rfc/rfc3168)
- [Linux AF_XDP 文档：XSKMAP 绑定约束](https://docs.kernel.org/networking/af_xdp.html)
- [Linux 6.1 AF_XDP copy TX](https://github.com/torvalds/linux/blob/v6.1/net/xdp/xsk.c#L514-L577)
- 本地依赖源码：`smoltcp-0.14.0/src/socket/tcp/congestion.rs`、`socket/tcp.rs`、`wire/{tcp,ipv4}.rs`；`quinn-proto-0.11.17/src/congestion.rs`、`congestion/bbr/mod.rs`、`connection/pacing.rs`
