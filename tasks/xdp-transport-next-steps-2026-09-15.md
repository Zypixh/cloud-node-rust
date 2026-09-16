# XDP 全协议接管的传输层：统一拥塞控制 EdgeCC / AccECN / 用户态队列调度 —— 规划 v3 与 Devin 提示词

规划基线：`d13f77c`（静态审阅基线 `315af04` + 文档脱敏）。
进度快照（2026-09-15 暂停时）：T0 各项与 T1 已提交（`8172ac6` F6、`b17a5d6` F5、`be75083` F2/F3/F4/F8、`1b742c0` F7、`da21e7a` T1 时钟）；T2 在工作区未提交：`crates/cloud-node-transport/`（RateSample、RttState、TransportInstant、`CongestionController` trait、NewReno+PRR、Cubic+HyStart++、确定性模拟器、三组测试）与 `Cargo.toml` workspace 声明。
上游输入：`tasks/xdp-final-static-review-2026-09-15.md`（F1–F8）与 `docs/xdp-transport-performance-design.md`（PROPOSED）。

本文只做静态阅读与依赖源码核对，未编译、未运行、未连接 VPS。所有编译/测试/压测仍按既有约束在授权 VPS 执行。

**开发/编译主机（2026-09-16 用户提供）**：`devin-build-90`（103.79.184.90，root，本机 `~/.ssh/config` 已配别名；已启用 PubkeyAuthentication + key 认证，密码认证仍开）。Debian 12 / kernel 6.1.0-41（与目标同代）/ 8c / 15GB / 56G 盘。已装：stable 1.98.1 + pinned `nightly-2026-09-13`（rust-src）、mold+clang 链接、mold+target-cpu=native（`~/.cargo/config.toml`）、nftables/iproute2/tcpdump 等。代码树在 `/root/cloud-node-rust`（含 .git 的完整 rsync；eBPF 用 `bpfel-unknown-none` + rust-lld，**不需要 bpf-linker**）。`cargo test -p cloud-node-transport` 已在此机全绿。此后"授权 VPS"含此机；vps-110/.120 仍可用于对照。.110 的 2GB 内存瓶颈由本机替代。

## 范围声明

1. 目标是 **XDP/AF_XDP 完全接管协议数据面**：客户端方向（被动打开）与回源方向（主动打开）都由 `smoltcp-edge` 在 AF_XDP 上承载。内核 TCP/UDP 不再参与业务数据面。
2. **非 XDP 模式不做任何传输改造**，只在 T10 作为同环境对照基线。
3. 拥塞控制交付物是 **一个控制器（工作名 EdgeCC）**，不是多个算法并列。Reno/Cubic/BBRv1/BBRv3 在本文里只以两种身份出现：(a) 被拆出来的**部件**（PRR、HyStart++、模型滤波器、`inflight_hi` 包络、`lt_bw` policer 判定等）；(b) 同一份代码钉死参数后得到的**校验模式**，用于证明记账正确、并作为同栈内对照。它们不是生产可选项。
4. 控制面（配置、RPC、DNS、健康检查、日志上报）保留内核 socket。

## v3 相对 v2 的改动

- 第 2 节整体重写：从"三个控制器 + 策略叠加层"改为统一控制器 EdgeCC 的分层设计（路径模型 → 多信号推断 → 决策 → 安全包络 → 聚合协调 → 接收侧控制）。
- 补入 v2 遗漏的 BBRv1（丢包盲响应、`lt_bw` policer 判定）以及 BBR 家族之外的机制来源：PCC-Vivace 的效用梯度、Copa/Swift 的时延目标控制、GCC 的时延梯度滤波、Veno 的队列占用判据、RFC 3124 Congestion Manager 与 RFC 8382 共享瓶颈检测、DCTCP/RFC 8257 的 alpha、接收窗口驱动控制。
- 路径质量表并入路径模型的长期存储；路径选择（原 T4b）与聚合协调合并为 T6。
- 任务 T2 之后全部重排；提供暂停后的"继续提示词"。

## 0. 硬约束（决定架构的事实，保留自 v2）

| # | 事实 | 证据 | 影响 |
|---|---|---|---|
| C1 | smoltcp 0.14.0 `Controller` 为 `pub(super)`，`on_ack(now, len, in_flight, rtt)` 无 per-segment 发送时间/delivered/app-limited/SACK | `smoltcp-0.14.0/src/socket/tcp/congestion.rs:14-37` | 交付率模型无法外部注入，必须受控 fork |
| C2 | RTT 一窗一样本，不用 TS 选项，ms 精度 | `socket/tcp.rs:163-242, :2143` | 需要 TS 每 ACK RTT 与 µs 时钟 |
| C3 | 发送侧无 SACK 记分板/RACK-TLP/PRR；丢失只靠 3 dupack 与 RTO | `socket/tcp.rs:512-523, 2106-2137` | 交付/丢失记账不可信，任何模型型 CC 都会被误导 |
| C4 | socket 层无 ECN；`TcpRepr`/`Ipv4Repr` 未上提 ECN 字段 | `wire/tcp.rs:856-869`, `wire/ipv4.rs:533-539` | 经典 ECN 与 AccECN 都要 fork 贯通 |
| C5 | 无 pacing 钩子：`cwnd_remaining = window - flight_size` | `socket/tcp.rs:1400-1405` | 发送时间门必须加在 dispatch |
| C6 | reactor 曾用墙钟 ms（T1 已改为单调 µs `TransportClock`） | `da21e7a` | 已闭合 |
| C7 | bridge 对每个 egress 帧立即 `send_raw_frame`；TX 背压 256 次退出 | `src/xdp/af_xdp/bridge.rs:992-1073, 511` | 调度器接入点；退出并入过载合同 |
| C8 | quinn-proto 0.11.17 `Controller` 公开：`on_ack(now, sent, bytes, app_limited, rtt)` 等 | `quinn-proto-0.11.17/src/congestion.rs:17-85` | QUIC 侧 EdgeCC 不 fork 即可接入 |
| C9 | quinn Pacer 为 `window/srtt` 令牌桶，忽略 `pacing_rate` | `connection/pacing.rs` | pacing_gain ≠ cwnd_gain 无法表达；是否 patch 按 D-C1 先度量 |
| C10 | quinn 内置 `Bbr` 为 quiche 派生 BBRv1，标注 Experimental | `congestion/bbr/mod.rs:19-24` | 不用；与我们的模型层不能共享状态 |
| C11 | H3 共享 UDP 套接字丢弃 ECN | `src/quic_udp_demux.rs:163-180, 717` | 既有静默降级，先报告 |
| C12 | AF_XDP reactor 只有被动打开；回源走内核 TCP | `tcp_reactor.rs:779-840`；`tcp_proxy.rs:1849-1863` | 回源接管需新增 active open、出向流表、RST 防护 |
| C13 | AccECN = RFC 9768；Linux 6.18/6.19 合入，7.0 默认开；目标内核 6.1 无 | LWN 1058666 | 只有我们的栈能双向实现；对端支持率要实测 |
| C14 | 6.1 AF_XDP copy TX 绕过 egress qdisc | `xsk.c` | fq/CAKE/FQ-PIE 必须在用户态 TX 路径重做 |
| C15 | eBPF `tcp_sanity` 不动 ECE/CWR/AE；challenge 路径 SYN-ACK 仅 MSS | `ebpf/main.rs:1369-1390, 4940` | challenge 路径不协商 ECN，显式限定 |
| C16 | quinn `send_window=32MiB` 为每连接 | `src/quic_transport.rs:13-19` | 进 F3 预算，修注释 |
| C17 | 内核对无监听端口的 SYN-ACK 回 RST；XDP detach 窗口漏包到内核 | Linux TCP 语义 | 回源源端口需 `ip_local_reserved_ports` + netfilter DROP 守卫 |

上游版本钉住：google/bbr `v3` @ `90210de4b779d40496dee0b89081780eeddf2a60`；`draft-ietf-ccwg-bbr-06`；RFC 9768（AccECN）、3168、8985（RACK-TLP）、6937（PRR）、9438（CUBIC）、9406（HyStart++）、7323（TS）、2883（DSACK）、3522（Eifel）、8257（DCTCP）、8382（共享瓶颈检测）、3124（Congestion Manager）、8305（Happy Eyeballs）。BBRv1 参考 Linux 6.1 `net/ipv4/tcp_bbr.c`（含 `lt_bw` 长期带宽/policer 判定）。PCC-Vivace（NSDI'18）、Copa（NSDI'18）、Swift（SIGCOMM'20）、GCC（RMCAT）、Veno（JSAC'03）为机制来源，不是实现对象。

## 1. 目标架构

```mermaid
flowchart LR
    subgraph transport["crates/cloud-node-transport（纯算法，无 tokio，确定性可测，双向共用）"]
        CLK[clock / RateSample / RttState（已存在）]
        PM[PathModel：bw 估计+不确定度、base_rtt、qdelay 与梯度、<br/>丢包过程（随机基线/拥塞证据/伪重传）、CE 比例、policer、ACK 聚合]
        INF[Inference：多信号 log-odds → congestion_belief、queue_estimate、p_rand]
        DEC[Decision：先验启动、不确定度驱动探测、时延目标/平台期双模、<br/>效用梯度微调、按 belief 比例响应]
        ENV[Envelope：inflight_hi 硬包络（强证据驱动，任何层不得越过）]
        AGG[Aggregate：共享瓶颈检测、按业务分层分配、探测协调、base_rtt 共享]
        RX[Receiver-side：rwnd 右尺寸、BDP 上限、与配对连接耦合]
        REC[Recovery：RACK-TLP + PRR + DSACK/Eifel]
        REF[Reference modes：Bbr3Ref / CubicRef / NewRenoRef / LossBlindRef（校验用）]
        SCHED[sched：时间轮 + 分层 + 节点出口租约]
        AQM[aqm：CoDel/PIE（仅转发队列）]
        SIM[sim：多流、共享瓶颈、抖动、路由切换、policer、ECN]
        PT[path_table：前缀级长期先验 + 拨号选择]
    end
    subgraph tcpfork["vendor/smoltcp-edge"]
        SOCK[段记录、TS、SACK 记分板、ECN repr、发送时间门、app-limited 标记、rwnd 钩子<br/>listen + connect]
    end
    subgraph dp["src/xdp/af_xdp"]
        REACT[tcp_reactor：accepted/dialed 会话]
        BRIDGE[bridge：min(cwnd,rwnd,pacer,租约,XSK) → TX]
        EBPF[eBPF：入向流表 + 出向流表 + ICMP]
    end
    QUIC[quinn：EdgeCC impl Controller；ECN 贯通]
    CLK --> PM --> INF --> DEC --> ENV --> SCHED --> BRIDGE
    AGG --> DEC
    PT --> DEC
    PT --> AGG
    RX --> SOCK
    REC --> PM
    SOCK --> PM
    REACT --> SOCK
    EBPF --> BRIDGE
    QUIC --> PM
    SIM -.测试.- DEC
    REF -.同一代码钉参数.- DEC
```

## 2. EdgeCC：统一拥塞控制设计

### 2.1 设计原则

1. **拥塞是路径的属性，不是连接的属性。** 模型与包络在瓶颈聚合上维护；连接是聚合额度的消费者。一个 CDN 节点对同一客户端前缀/同一源站常有几十条并发流，各自独立探测会把共享瓶颈超冲 N 倍——这是我们相对端点 CC 最大的结构性优势。
2. **用后验做决策，不用单个事件做决策。** 丢包、RTT、交付率平台期、CE、ACK 聚合都只是证据，更新一个连续的拥塞置信度；响应强度与置信度成比例，而不是"丢一个包就减半"或"完全无视丢包"。
3. **所有探索都在安全包络内。** 强证据（CE、伴随 RTT 抬升的丢包、RTO、policer）设定 `inflight_hi` 硬上限；推断错误最多导致包络内的次优，不会失控。
4. **目标函数显式。** 业务有效吞吐与完成时间为正项，自身排队时延与拥塞丢包为代价项，权重由业务分层给出；同一函数既用于探测决策也用于 T10 评估。
5. **用代理知道而端点不知道的一切：** 两侧速率、同路径的历史与并发流、业务优先级、我们是接收方时的窗口控制权。
6. **可审计。** 每次模式/包络/分配变化带原因码；同一事件轨迹可确定性重放；每个机制有消融开关（用于度量，不是生产可选项）。

### 2.2 路径模型（PathModel）

每个聚合一份，流级只保留 RateSample 累计与 app-limited 状态。

| 量 | 估计方法 | 来源 |
|---|---|---|
| `bw_max` | 交付率窗口最大值滤波（窗口 ≈ 2 个探测周期） | BBR |
| `bw_est`, `bw_sigma` | 非 app-limited 交付样本的 EWMA 与偏差 EWMA → 置信区间；样本年龄与数量进置信度 | 新增；不确定度驱动探测 |
| `bw_hi` / `bw_lo` | 剂量-响应试验（提升 inflight 后交付率是否随之增长）与响应事件更新 | BBRv3 概念，更新规则由 belief 驱动 |
| `base_rtt` | 长窗口最小值 + 漂移检测（全部流长期高于底线且 inflight 低 → 路由变化，允许底线上移） | BBR + 新增 |
| `qdelay`, `qdelay_grad` | `srtt − base_rtt`；梯度用 Kalman/EWMA 滤波 | Copa/Swift/GCC |
| `extra_acked` | ACK 聚合补偿 | BBRv3 |
| 丢包过程 | 两列丢包率（伴随 qdelay 抬升 / 无抬升）、突发长度、**因果检验**（丢包率是否在我们提速后上升）、伪重传比例（DSACK/Eifel） | Veno 队列占用判据 + 新增 |
| `p_rand` | 由"无 qdelay 抬升、无 CE、非提速期"的丢包样本估计的随机丢包基线，带置信度 | 新增；对高丢包国际链路关键 |
| `alpha` | CE 字节比例 EWMA（AccECN 精确；经典 ECN 为事件） | DCTCP/BBRv3 |
| `lt_bw` / policer | 持续丢包 + 交付率平坦 → 令牌桶 policer，长期带宽上限 | BBRv1 |
| `delay_signal_quality` | 低 inflight 时 RTT 方差；决定时延信号是否可用 | 新增 |

长期存储 `path_table`：按 `(egress_iface, local_ip, af, dst_prefix)` / `(ingress_iface, local_ip, af, client_prefix)` 保存聚合摘要（`bw_est`、`base_rtt`、`p_rand`、`alpha`、乱序度、connect_rtt、失败率），TTL 与置信度；供暖启动与拨号选择。

### 2.3 多信号推断（Inference）

- `congestion_belief ∈ [0,1]`：有界 log-odds 累加器，每 RTT 衰减。证据权重从强到弱：CE（AccECN 比例 > 经典事件）> `qdelay` 超出该分层预算且梯度为正 > 伴随 qdelay 抬升的丢包 > inflight 上升而交付率平台期 > 无抬升的丢包（权重为 `(loss_rate − p_rand)+`）；DSACK 判定的伪重传为负证据。
- `queue_estimate ≈ qdelay × bw_est`：我们在瓶颈里堆的字节。
- 共享瓶颈检测（RFC 8382 思路）：同候选聚合内各流的 qdelay 变化与丢包时刻相关性；相关则合并，去相关则拆分——防止错误分组造成的欠利用。
- 所有推断为每 ACK O(1) 的滤波器更新，不含在线学习。

### 2.4 决策（Decision，聚合级 → 流级）

- **工作点**：`inflight_target = bw_est × base_rtt + Q_budget(tier)`；`pacing = bw_est × g`。`Q_budget` 是我们接受的自排队量，由业务分层给出（完成时间敏感层小，大流层大）。
- **双模控制**：`delay_signal_quality` 高 → 时延目标控制（Copa/Swift 式：速率按 `(d_target − qdelay)/d_target` 的有界比例调整）；时延信号被抖动淹没 → 平台期驱动探测（BBR 式）。切换带迟滞并记录原因。
- **不确定度驱动探测**：探测触发 = `bw_sigma/bw_est` 高、或距上次剂量-响应试验超过与 RTT 成比例的随机化 horizon、或先验显示更高容量；探测幅度与不确定度成比例（有上下限），时长 ≥1 RTT；用交付率增量/inflight 增量判定接受或回退。**同一聚合同时只有一个流在探测**，其余保持。
- **效用梯度微调**（PCC-Vivace 思路，受限使用）：模型收敛后，在 `[0.9×target, envelope]` 内做成对小幅试验（±ε，一个监测区间），按效用 `U = goodput^a − b·(rate·qdelay_grad)+ − c·rate·loss_congestion` 的梯度方向有界步进。只对非 app-limited、寿命 ≥5 RTT 的流启用；作用是找到 policer/浅缓冲上"稍低速率换更低丢包"的点，而不是替代模型。
- **按置信度比例响应**：`inflight_lo = inflight × (1 − β·belief)`，`β_max` 取 BBRv3 值；PRR 平滑削减；CE 按 `alpha/2` 每 RTT 削减（DCTCP）；RTO 后从模型恢复而不是从 1 MSS 重来；`belief≈0` 的随机丢包不改模型，只由 RACK/TLP 修复——这就是 BBRv1 的丢包盲行为，但只在证据支持时出现。
- **启动**：有置信先验 → paced start：以约 0.5×先验带宽起步、cwnd = 先验 BDP × 1.5、立即做剂量-响应确认，不走指数增长；无先验 → 2.77 增益指数启动，退出条件为平台期（3 轮）、HyStart++ 式时延抬升（base_rtt 可来自聚合）、伴随抬升的丢包、CE。IW 由先验有界推导（无先验 10 MSS），在约半个 RTT 内 pace 发出。
- **base_rtt 刷新**：优先用聚合内其他流的低 inflight 样本与自然空闲期；仅当 horizon 内无新鲜样本时，聚合内**一个**流做 0.5×BDP 的短暂下探（BBRv3 参数），其余不动。
- **app-limited**：样本不下拉 `bw_est`，不触发探测；代理场景下客户端侧流在源站侧供给不足时必须被正确标记（第 2.7 节）。

### 2.5 安全包络（Envelope）

- `inflight_hi` 由强证据设定：一轮内伴随 qdelay 抬升的丢包 ≥ 阈值、CE 比例 ≥ 阈值、RTO、policer 判定 → `inflight_hi = 当时 inflight × (1 − headroom)`。
- 只有 belief 连续 K 轮低于阈值才允许 REFILL → 上探（BBRv3 语义）。
- 决策层与效用微调层输出一律 `min(·, inflight_hi)`；节点出口租约再叠一层。
- 包络的存在使"推断把拥塞丢包误判为随机丢包"的最坏后果被限制为包络内的次优，而不是 BBRv1 式的顶死队列。

### 2.6 聚合协调（Aggregate，RFC 3124 思路）

- 候选键 `(egress_iface, local_ip, af, dst_prefix, port_class)`；新流先加入候选，共享瓶颈检测确认后共享模型与包络，否则退化为单流聚合。
- 分配：聚合 `rate_total`/`inflight_total` 按业务分层权重分配（T0 控制推进与 T1 完成时间敏感有最低保证），工作保持，未用份额每 RTT 再分配。
- 协调：一次一个探测者、错峰；`base_rtt` 共享；Σ聚合 ≤ 节点出口治理上限。
- 收益预期：N 条同路径流从"N 次独立探测、N 倍超冲"变为"一次探测、按优先级分配"。这是 T10 必须单独度量的项。

### 2.7 接收侧控制与配对连接耦合（代理特有）

- 我们是接收方（源站→节点、客户端上传）时：`rwnd = clamp(consumer_drain_rate × (srtt + margin) + Q_budget_rx, min, F3 份额)`，且 `rwnd ≤ BDP_est(path) + Q_budget_rx`，防止源站的 CC 把源站→节点路径灌成 bufferbloat，也防止 F3 内存被单流占满。
- 配对耦合：客户端侧交付率是源站侧 rwnd 的上限（不拉得比推得快）；源站侧到达速率不足时客户端侧 RateSample 标记 app-limited，模型不被污染；cache 命中路径以缓存读取背压标记。
- ACK 策略默认不变（每 2 段或定时器），CPU 影响进 T10 度量。

### 2.8 恢复

RACK-TLP（`reo_wnd` 自适应）+ PRR + DSACK/Eifel 撤销；在 `p_rand` 高且乱序低的路径收紧 `reo_wnd` 加快修复；TLP 参数对长 RTT 调整。

### 2.9 校验模式（不是交付物）

同一份代码通过参数钉死得到：`Bbr3Ref`（belief 规则 = v3 loss/CE、无效用微调、无聚合、v3 探测周期）、`CubicRef`、`NewRenoRef`（现有实现）、`LossBlindRef`（belief 钉 0 → BBRv1 丢包盲）。用途：记账一致性回归；同栈内对照（EdgeCC 必须在 T10 同环境下优于 `Bbr3Ref`，否则不切默认）；随机丢包场景下 EdgeCC 应逼近 `LossBlindRef` 吞吐、真拥塞场景下应逼近 `Bbr3Ref` 的排队与重传。

### 2.10 明确不采用

- 数据面内在线学习/强化学习（Remy/Aurora/Orca 类）：不可审计、CPU 不可控。T10 数据允许离线参数拟合（D-G1），但任何拟合结果要进数据面仍需走 T10 同环境验证。
- L4S/ECT(1)/Prague；MPTCP；通用 TCP 上的 FEC。
- quinn 内置 `Bbr`。

### 2.11 风险（如实）

- EdgeCC 没有上游参考可"符合"，只能靠模拟器不变量 + 真实矩阵度量；校验模式是唯一的锚。
- 效用微调在 300ms RTT 上每步至少一个 RTT，收敛慢；因此它只做微调，工作点由模型给出。
- 共享瓶颈误分组会欠利用；拆分规则必须有测试。
- 每 ACK 增加滤波与 log-odds 更新；2c2g 上要度量每 ACK 纳秒级开销。

## 3. AccECN（RFC 9768）双角色设计

（保留 v2 内容）被动方：SYN (1,1,1)→AccECN，(0,1,1)→经典；SYN-ACK 按 SYN 的 IP-ECN 编码 (0,1,0)/(0,1,1)/(1,0,0)/(1,1,0)。主动方：SYN 置 (1,1,1) 可带选项；(1,0,1) 按 §3.1.3 视为 AccECN；SYN 超时按 §3.1.5 回退并记录。ACE 初值 5，字节计数初值 1；选项 Kind 172/174；数据段 ECT(0)，纯 ACK Not-ECT；ACE 回绕按 §3.2.2.5；失效处理按 §3.2.x 并可观测。challenge 路径不协商，显式限定。AccECN 的价值在 EdgeCC 里是 `alpha` 的精确输入与最强的拥塞证据。

## 4. 用户态队列调度（fq/CAKE/FQ-PIE 的用户态重做）

（保留 v2 内容）fq：每流 `next_send_at` + 分层时间轮（最小堆参考，等价测试）；CAKE：时间基 deficit 整形、overhead 补偿、有界不均分的业务分层 T0/T1/T2；CoDel/PIE：只用于我们不是端点的转发队列，ECT 打 CE、Not-ECT 丢弃；合法发送条件 `min(cwnd, rwnd, pacer, worker_lease, xsk_slots)` 在 bridge 单点裁决。与 EdgeCC 的关系：聚合分配决定每流 `cwnd/pacing`，调度器决定何时把已允许的字节放上线；分层权重两处共用同一配置。

## 5. QUIC 路径

EdgeCC 实现 `quinn_proto::congestion::Controller`（C8）；quinn Pacer 偏差先度量再决定是否 patch（C9）；修 C11 的 ECN 贯通；不用内置 `Bbr`（C10）；`send_window` 进 F3 预算（C16）。

## 6. 回源方向由 XDP 接管

（保留 v2 内容）smoltcp-edge 主动打开、保留源端口范围、网关 ARP/NDP、ICMP 驱动 PMTU、复用 `virtual_l4_stream` 接 pingora 上游连接器；eBPF 出向流表（多队列复用 F7 方案）；`ip_local_reserved_ports` + netfilter DROP 守卫（C17）；`xdp.upstream = kernel|afxdp` 迁移期开关，接管完成后默认 `afxdp`；每代理连接两个会话进 F3 预算。

### 6.5 国际网络：路径多样性与选择

（保留 v2 内容，数据结构改为第 2.2 节的 `path_table`）杠杆：L1 源站候选按测得质量选择 + Happy Eyeballs 有界竞速；L2 源 IP/出接口/源端口重掷（仅在证明 ECMP 多样性时）；L3 父节点中转（仓库已有 `level`/`parentNodes`，`lb_factory.rs:244-246` 目前忽略）；L4 路径先验进 EdgeCC 启动与 `p_rand`；L5 幂等 cache-fill 传输中换路（默认关）；L6 客户端方向无换路能力，只导出前缀级质量给控制面。被动测量为主，主动 SYN 探测限速为辅，不用 ICMP；ε-greedy 探索 + 迟滞；连接池键含路径。

## 7. 验证策略

1. 模拟器扩展：多流共享瓶颈、RTT 抖动/噪声、路由切换（base_rtt 漂移）、policer、随机丢包 1–5% 叠加/不叠加拥塞、ACK 压缩、app-limited 发送方、长 RTT 300ms、双候选路径。
2. 不变量：任何层输出 ≤ `inflight_hi`；聚合内同时探测者 ≤1；分配之和 = 聚合额度；启动退出在界内；belief 随证据单调；随机丢包场景吞吐 ≥ `LossBlindRef` 的 x%，拥塞场景排队 ≤ `Bbr3Ref` 的 y%（x、y 在 T5 由基线测出后固定为回归阈值）。
3. 报文脚本测试（smoltcp-edge）、调度器等价测试、回源接管专项、路径选择测试（同 v2）。
4. 远程矩阵（同 v2，加国际多路径矩阵与共享瓶颈 N 流矩阵）；对照：`Bbr3Ref`（同栈）与 XDP 关闭路径（内核）。
5. 消融：每个机制单独关闭度量贡献（不确定度探测、效用微调、聚合、先验启动、接收侧控制、`p_rand`）。

## 8. 分阶段任务与 Devin 提示词

通用约束（每个提示词都包含）：

- 遵守 `.cursor/rules/no-unapproved-degradation.mdc`；发现已有降级先报告。
- 本机只编辑与静态阅读；编译/测试/eBPF 构建/压测在授权机器 `devin-build-90`（103.79.184.90，root，ssh 别名已配；代码树 `/root/cloud-node-rust`）或 vps-.110/.120 的隔离目录与 netns/veth，禁止清理生产 bpffs；不新增 B 组/TC 后端；不 tag/push/部署。
- 范围：只改造 XDP/AF_XDP 数据面；非 XDP 模式不做传输改造。
- 拥塞控制交付物是 EdgeCC 一个控制器；Reno/Cubic/BBRv1/BBRv3 只作为部件与校验模式，不作为生产可选算法，不新增"算法选择"配置项。
- 引用固定版本见第 0 节。
- 每个任务单独提交，证据写入 `docs/edge-node-evidence/` 与单一状态入口；最终报告区分：已修复、仍存在、设计限制、经审批的降级。

### 继续提示词（暂停后第一条）

第 9 节决策已全部批准（D-* 编号），提示词中引用 D-* 即对应结论，不再等待审批。

```
任务：按 tasks/xdp-transport-next-steps-2026-09-15.md v3 重新对齐 T2，把工作区未提交的 crates/cloud-node-transport 收敛为 EdgeCC 的基础层并提交。
现状：T0/T1 已提交（HEAD da21e7a）；工作区有未提交的 crates/cloud-node-transport/（rate_sample.rs、rtt.rs、instant.rs、cc.rs 及 cc/{new_reno,cubic,prr}.rs、sim.rs、tests/）与 Cargo.toml 的 workspace 声明。先 git status/diff 核对，不要丢弃任何已有工作。
方向变更：拥塞控制交付物改为统一控制器 EdgeCC（文档第 2 节），NewReno/Cubic 不再是交付物。
要求：
1. 保留并继续使用：TransportInstant、RateSample/RateSampler、RttState、CongestionController trait、PRR、HyStart++、模拟器与全部现有测试。
2. 把 cc/new_reno.rs 与 cc/cubic.rs 移到 cc/reference/ 下，改名为 NewRenoRef/CubicRef，文档注释明确"校验模式，不是生产算法"；PRR 与 HyStart++ 提升为 cc/parts/ 下可复用部件（EdgeCC 将复用）。
3. 新增 model.rs（PathModel，第 2.2 节）：bw_max 窗口最大值滤波、bw_est/bw_sigma EWMA 与置信度、base_rtt 长窗口最小值 + 漂移检测、qdelay 与 Kalman/EWMA 梯度、extra_acked、两列丢包率与突发长度与因果检验、p_rand 估计、alpha EWMA、lt_bw policer 判定、delay_signal_quality。全部为每 ACK O(1) 更新；每个量有单元测试与文档注释写明来源（BBR/BBRv1 lt_bw/Veno/DCTCP/GCC/新增）。
4. 新增 inference.rs（第 2.3 节）：有界 log-odds congestion_belief（证据权重表为常量并注明），queue_estimate，负证据（DSACK 伪重传）。共享瓶颈检测本任务只定义接口与统计量，判定实现留 T6。
5. 新增 envelope.rs（第 2.5 节）：inflight_hi 设定/保持/REFILL 规则，任何调用方通过 clamp() 取上限；测试断言不可越过。
6. CcSnapshot 扩展：belief_milli、queue_estimate_bytes、p_rand_milli、bw_sigma_bps、envelope_bytes、mode 与 reason_code 的 EdgeCC 取值集合；不能提供的字段保持 None。
7. 模拟器扩展（第 7.1 节）：多流共享同一瓶颈、RTT 抖动、路由切换（中途改变 delay）、随机丢包与拥塞叠加、app-limited 发送方、300ms RTT；输出多流 trace。
8. Cargo workspace 声明保留（含对 cloud-node-xdp-ebpf 与 pingora-main 的 exclude 说明）。
测试：现有测试全部通过；PathModel/Inference/Envelope 单元测试；golden trace 回归。
验收：VPS 上 cargo test -p cloud-node-transport 与根 crate cargo check 通过；单独提交，提交信息说明"T2 基础层：模型/推断/包络 + 参考模式重命名"。不实现 EdgeCC 决策层（T5），不修改 src/xdp。
```

### T3 · `vendor/smoltcp-edge`：受控 fork 与传输钩子（被动方）

```
任务：以 Cargo.lock 锁定的 smoltcp 0.14.0 建立受控 fork vendor/smoltcp-edge，通过 [patch.crates-io] 覆盖 Cargo.toml 两处声明；在 socket/tcp.rs 增加传输钩子，并把 AF_XDP reactor 的 accepted 会话接到 cloud-node-transport 的 CongestionController（本任务生产控制器仍为 CubicRef，保持 F8 止血行为；EdgeCC 在 T5 接入）。
基线：T2 提交后的 commit。
必须补齐（C1–C5）：
1. 每段 TxRecord 记录与 RateSample 生成（复用 transport crate），替换 pub(super) Controller 为公开 trait；保留上游 NoControl/Reno/Cubic feature 作为对照。
2. TCP Timestamps（RFC 7323）每 ACK RTT 与 PAWS；窗口缩放保持。
3. 发送侧 SACK 记分板 + RACK-TLP（reo_wnd 自适应）+ PRR + DSACK 伪重传识别 + Eifel 撤销；乱序专项用例断言无伪重传削减。
4. IP/TCP repr 贯通 ECN 字段（只贯通不协商）。
5. dispatch 发送时间门：socket 暴露 next_send_at 与 pacing_rate；poll_egress 只发已到期段。
6. app-limited 标记：发送缓冲耗尽时标记后续段；供第 2.7 节耦合使用。
7. rwnd 钩子：允许上层按第 2.7 节动态设定通告窗口上限（本任务只提供钩子）。
8. DIVERGENCE.md 逐项记录与上游差异。
9. reactor：生产 socket 创建处显式选择控制器，CcSnapshot 进 /status。
测试：上游 tcp 测试全部保留通过；报文脚本测试覆盖 SACK/RACK/TLP/TS/PAWS/DSACK；同一 ACK 轨迹下 fork 的 CubicRef 与上游 Cubic cwnd 曲线一致。
验收：VPS release 构建；veth 双栈协议矩阵无回归；证据入库。禁止在此任务中实现 ECN 协商或 active open。
```

### T4 · 回源方向由 AF_XDP 接管

```
任务：让回源连接（TCP 与 UDP）经 smoltcp-edge 在 AF_XDP 上主动打开，替代 pingora/tcp_proxy 的内核 socket；新增 eBPF 出向流表与内核 RST 防护。
基线：T3 完成后的 commit。设计输入：文档第 6 节与附录 A（接入点分析）；C12、C17；F1/F3/F7 合同。
回源连接面共四处，全部覆盖：toa::connect_with_toa（L4 唯一漏斗）、vendored pingora l4_connect（HTTP/HTTPS）、udp_proxy.rs 内核 UdpSocket、origin_h3.rs quinn Endpoint（见附录 A.4 边界决定）。
TOA：smoltcp 主动打开时内核模块不会经过 NF_INET_LOCAL_OUT，必须由我们在 SYN 里直接写 option 254（v4 8B / v6 20B）；客户端地址在拨号时已知，genl 映射与端口分配器在此路径上不再需要；v6 + TOA + AccECN 的 SYN 选项预算可能超过 40B，裁剪优先级按 T7 规则。
要求：
1. dialed 会话（connect），客户端侧选项 MSS/SACK-permitted/TS/窗口缩放（AccECN 请求留 T7）；源端口从保留范围分配并按 (local_ip, remote) 去重回收，保留范围默认 40000–49999、可配置、须落在 `ip_local_port_range` 内（D-B1）；网关 MAC 由 smoltcp ARP/NDP 自解析 + 缓存 + 失败计数可观测（D-B2），解析期间 SYN 排队；PMTU 由投递到 XSK 的 ICMP 驱动并带 RFC 4821 式黑洞检测回退，否则接口 MTU 派生（D-B3）。
2. reactor：accepted/dialed 共用 pump/sweep/reaper/预算；dialed 会话通过 virtual_l4_stream 暴露给 pingora 上游连接器与 tcp_proxy 后端；连接池/空闲超时/半关闭驱动 smoltcp 生命周期；UDP 回源并入出向流表。
3. eBPF 出向流表 (proto, local_ip, local_port, remote_ip, remote_port) → XSK；返回报文与匹配内层 5 元组的 ICMP 错误 redirect；多队列复用 F7 方案；关闭即删。
4. 内核守卫（D-B1）：`ip_local_reserved_ports` 标记保留范围 + 入向目标端口在范围内的 TCP/UDP netfilter DROP；守卫规则安装失败为显式启动错误；守卫命中计数进 /status。
5. 配置键 xdp.upstream = kernel|afxdp；本任务默认 kernel 仅用于分阶段验收，报告明确接管完成后默认 afxdp。
6. 配对耦合的最小实现：客户端侧流在源站侧供给不足时标记 app-limited（用 T3 的钩子）。
测试：报文脚本（三次握手、SYN 重传、同时关闭、RST）；VPS veth/netns 源站在另一 netns：SYN 经 AF_XDP 发出、SYN-ACK 被出向流表捕获、ss 无内核 socket、tcpdump 无 RST 外泄；XDP detach 窗口注入源站报文，守卫丢弃且计数增长；HTTP/HTTPS/TCP/UDP 回源矩阵双栈；带活跃回源连接的 reload 遵守 F1。
验收：VPS release 构建 + 上述测试；证据记录内核、队列数、copy 模式、保留端口范围与守卫规则。
```

### T4-8 · 回源接管端到端流量验证（先做，与 T5 可并行）

```
任务：补齐 T4 欠下的端到端流量验证（EN-20/21/22 只覆盖编译+单元/集成测试）。已有工具：commit a55fae0 的 `xdp dial-smoke`（AF_XDP 真实外拨 + PTB/out-CT 在线验证），commit b7db772 已实测 eBPF 过 kernel 6.1 verifier + native drv attach。
基线：a55fae0。环境：devin-build-90（netns/veth/nft/tcpdump 已装）。
要求：
1. netns 拓扑：veth 对，源站命名空间跑 TCP/UDP echo + HTTP 服务；本端 afxdp 模式启动节点。
2. 验证项：dial-smoke 外拨成功且 SYN 走 AF_XDP（源站侧 tcpdump 看到 SYN 带预期选项，回程 SYN-ACK 被 XDP_OUT_CT 捕获 → out_ct_hit 增长）；`ss -tn` 在源站 netns 内确认连接两端，本端 netns 内 `ss` 无对应内核 socket；tcpdump 全程无本端发出的 RST；XDP detach/reattach 窗口注入源站报文，nft 守卫丢弃且计数增长；非 PTB ICMP error 不杀会话；PTB 触发 set_path_mtu 后 MSS 收敛。
3. 带活跃回源连接执行 reload，验证 F1 合同（旧 worker 不被提前停）。
4. nft/sysctl 守卫的端到端安装与拆除（dial_guard ensure/unpin），重装幂等。
5. 顺带补 T3-10 债务：veth 双栈协议矩阵 + CubicRef 与上游 Cubic 同 ACK 轨迹 cwnd 对照。
测试：全部为真实流量/真实 netns，不是单元测试。
验收：每项有 tcpdump/ss/计数器证据；写入 EN-24 报告；发现问题按合同显式报告，不静默降级。
```

### T5 · EdgeCC 决策层（单流）与 QUIC 适配

```
任务：在 cloud-node-transport 实现 EdgeCC 决策层（文档第 2.4、2.5、2.8、2.9 节）：先验启动、双模控制、不确定度驱动探测、效用梯度微调、按 belief 比例响应、包络、base_rtt 刷新、policer 响应；实现校验模式 Bbr3Ref 与 LossBlindRef；实现 quinn_proto::congestion::Controller 适配；接入 accepted 与 dialed 会话（受 flag 控制，默认仍 CubicRef，切换在 T10 决定）。
基线：T4 完成后的 commit。
要求：
1. 决策层只消费 PathModel/Inference 输出与 Envelope；每个决策点（探测开始/结束/接受/回退、模式切换、响应、启动退出、base_rtt 下探）写原因码进 CcSnapshot。
2. 先验启动：path_table 有置信先验时 paced start（0.5×先验 bw、cwnd=先验 BDP×1.5、立即剂量-响应确认）；无先验 2.77 增益 + 平台期/HyStart++/伴随抬升丢包/CE 退出；IW 由先验有界推导，默认 10 MSS。本任务 path_table 只做单机内存版（T6 完成前缀级共享与 TTL）。
3. 双模：delay_signal_quality 高 → 时延目标控制；低 → 平台期探测；迟滞与原因码。
4. 探测：不确定度/horizon/先验触发，幅度 ∝ 不确定度（上下限常量注明），≥1 RTT，剂量-响应判定。
5. 效用微调：成对 ±ε 试验，U = goodput^a − b·(rate·qdelay_grad)+ − c·rate·loss_congestion，有界步进；仅非 app-limited、寿命 ≥5 RTT；可消融。
6. 响应：inflight_lo = inflight×(1−β·belief)，PRR 平滑；CE 按 alpha/2；RTO 从模型恢复；belief≈0 不改模型。
7. 包络：强证据设定 inflight_hi，K 轮低 belief 才 REFILL；所有输出 clamp。
8. Bbr3Ref：同一代码钉参数复现 google/bbr v3 @90210de4 的 STARTUP/DRAIN/ProbeBW/ProbeRTT/inflight_hi/lo/ECN 行为（常数来源行号注明）；LossBlindRef：belief 钉 0。
9. quinn 适配：EdgeCC 实现 Controller + ControllerFactory；按 D-C1 先度量 quinn Pacer 与 pacing_rate 的偏差并报告，仅当偏差使探测幅度无法表达时才 patch，patch 面限 `connection/pacing.rs`。
测试：模拟器矩阵 {RTT 10/50/150/300ms × bw 10/100/1000Mbit × buffer 0.25/1/4×BDP × 随机丢包 0/1/3/5% × policer 有/无 × 抖动有/无}；断言第 7.2 节不变量；EdgeCC vs Bbr3Ref vs LossBlindRef vs CubicRef 同轨迹对照并把 x/y 阈值固定为回归；消融矩阵（关掉每个机制）。
验收：VPS cargo test 通过；trace 与对照表入库；报告 EdgeCC 在哪些格优于/劣于 Bbr3Ref 及原因。不切生产默认。
```

### T6 · 聚合协调、共享瓶颈检测、path_table 与拨号路径选择

```
任务：实现第 2.6 节聚合协调与第 6.5 节路径选择：共享瓶颈检测、聚合级模型/包络、按业务分层分配、探测协调、base_rtt 共享；path_table 前缀级长期先验（TTL/置信度/被动更新）；dialed 会话拨号时的候选选择（源站多地址、A/AAAA、源 IP/出接口、源端口重掷）与有界 SYN 竞速；父节点候选接通 lb_factory.rs:244-246 被忽略的 level/parent_nodes。
基线：T5 完成后的 commit。
要求：
1. 候选聚合键与共享瓶颈判定（RFC 8382 思路：qdelay 变化与丢包时刻相关性），合并/拆分带迟滞与原因码；拆分规则必须有欠利用回归测试。
2. 分配：分层权重、T0/T1 最低保证、工作保持、每 RTT 再分配；探测者一次一个、错峰；base_rtt 共享；Σ聚合受节点出口治理上限（T8 接入前先以配置上限占位）。
3. path_table：键值按第 2.2 节；被动更新为主；主动 SYN 探测仅候选 ≥2 且条目陈旧时、限速、不用 ICMP；导出前缀级质量到现有 rpc/stats 通道。
4. 拨号选择：按请求类别估算完成时间；Happy Eyeballs 最多 2 路竞速，落选 RST；ε-greedy ≤5%；迟滞连续两个窗口 >20%；连接池键含路径；健康检查"不可用"优先级最高；weight 为先验。
5. 源端口重掷/flow label 仅在统计判据证明 ECMP 多样性时启用。
6. 传输中换路（L5）只建接口与计数，默认关。
7. /status 暴露聚合成员、分配、探测者、候选路径质量与选择。
测试：模拟器 N 流共享瓶颈（对比独立探测的超冲/排队/重传）、错误分组的拆分；双候选路径选择收敛与互换后重新收敛；VPS veth 源站经两条路径不同 netem 的拨号分布/迟滞/恢复发现/SYN 竞速无泄漏。
验收：VPS release 构建 + 双向协议矩阵无回归；证据记录聚合收益与选择分布。
```

### T7 · AccECN 双角色 + 经典 ECN + QUIC ECN 贯通

```
任务：在 vendor/smoltcp-edge 实现 AccECN（RFC 9768）被动方与主动方协商/反馈与经典 ECN；把 CE 计数喂入 PathModel.alpha 与 Inference；修复 src/quic_udp_demux.rs 丢弃 ECN 的问题。
基线：T6 完成后的 commit。设计输入：文档第 3 节；C11/C15。
要求：被动方/主动方协商编码、ACE（初值 5）与字节计数（初值 1）、选项 Kind 172/174 与裁剪优先级、数据段 ECT(0)/纯 ACK Not-ECT、ACE 回绕 §3.2.2.5、失效处理 §3.2.x 可观测、SYN 超时回退 §3.1.5；challenge 路径显式限定；quic_udp_demux try_send 传递 transmit.ecn 并在 AF_XDP 编码路径写 IP TOS/TC，poll_recv 填 RecvMeta.ecn；eBPF 核对 AE 位不被清零，出向流表对返回 SYN-ACK 不归一化。
测试：移植 Linux selftests tcp_accecn_*.pkt 用例语义（两角色）；经典 ECN 一次/RTT；veth 上 ≥6.18 内核或用户态模拟的源站验证主动方协商；QUIC 打 CE 验证 quinn 不再自禁 ECN；模拟器 CodelEcn 场景下 EdgeCC 的 alpha 响应优于丢包响应。
验收：VPS release 构建 + 双向协议矩阵；证据记录两方向协商成功率与失效原因分布。默认通告策略按 D-D1 落地：客户端方向被动响应常开（对端发起才用），回源方向主动通告由配置门控灰度、本任务默认关；公网 CE 按 D-D2 权重受限并封顶 belief 贡献，受控链路满权重。
```

### T8 · 用户态出口调度器与节点出口治理

```
任务：实现每连接发送时间调度（最小堆参考 + 分层时间轮）、有界业务分层、节点出口租约，接入 bridge.rs 的 TX 提交与 tcp_reactor 的会话选择；聚合分配与调度器共用分层配置；Σ聚合接入节点出口治理。
基线：T7 完成后的 commit。设计输入：文档第 4 节；C7。
要求：等价性测试；合法发送条件单点裁决；T0/T1/T2 分层（T1 含有客户端等待的 cache-miss 回源）；CAKE 式整形含 overhead 补偿、突发 ≤1ms×rate、配置键 `xdp.egress_rate_bps`、无配置不整形（D-G2）；线程等待 min(时间轮, poll_delay, RX)，忙等 ≤50µs；TX 背压 256 次退出并入 F2 过载合同；quinn poll_transmit 期限接入时间轮。
测试：等价性、generation、热桶/回绕、CPU 微基准；veth 1/10/100 并发（两方向）发送节奏与 CPU。
验收：VPS release 构建；证据入库。
```

### T9 · 接收侧控制、配对耦合、转发队列 AQM、自适应缓冲

```
任务：实现第 2.7 节接收侧控制（rwnd 右尺寸与 BDP 上限、配对连接耦合）；为 UDP/QUIC 透传与跨接口转发队列实现 CoDel 或 PIE（ECT 打 CE，Not-ECT 丢弃）；F3 预算内的自适应发送缓冲。
基线：T8 完成后的 commit。
要求：
1. rwnd = clamp(consumer_drain_rate×(srtt+margin)+Q_budget_rx, min, F3 份额) 且 ≤ BDP_est+Q_budget_rx；客户端侧发送缓冲逗留超阈值 → 收窄 dialed 会话 rwnd；反向对称。
2. 配对耦合：客户端侧交付率上限源站侧 rwnd；app-limited 标记的正确性用 RateSample 轨迹验证。
3. AQM 默认交付 CoDel（D-AQM）；PIE 仅在基准数据表明 CoDel 不满足时替换，替换需写明理由。
4. 自适应发送缓冲 clamp(2×BDP_est, 32KiB, per_conn_cap)，两类会话从 F3 三级预算申请；不足缩窗不拒绝已建连接；会话上限估算按"每代理连接两个会话"重算。
测试：模拟器 AQM 曲线；慢读/零窗口/慢源站下 queued bytes、RSS、预算释放、rwnd 轨迹；源站 bufferbloat 场景下 rwnd 上限的效果；透传 UDP 拥塞下 CE/丢弃计数。
验收：VPS release 多连接慢读矩阵；资源回到可解释基线。
```

### T10 · 矩阵、消融与生产默认决策

```
任务：在 VPS netns/veth 与云 vNIC 上执行弱网矩阵、国际多路径矩阵、共享瓶颈 N 流矩阵与机制消融，比较 EdgeCC / Bbr3Ref / LossBlindRef / CubicRef（同栈）与 XDP 关闭路径（内核），形成生产默认（EdgeCC 是否替代 CubicRef、xdp.upstream=afxdp、ECN 通告）的决策建议。
基线：T9 完成后的 commit。
要求：
1. netem 施加在真实经过的链路并确认计数增长；记录内核、网卡、队列数、copy 模式、release SHA。
2. 矩阵：RTT {5,50,150,300}ms × 丢包 {0,0.1,1,3,5}% × 带宽 {10,100,1000}Mbit × 缓冲 {0.25,1,4}×BDP × policer 有/无 × 抖动有/无 × 并发 {1,10,100} × 方向 {客户端侧,回源侧,双侧}；国际多路径矩阵（两条路径 {3%+150ms vs 0%+250ms}、{5% vs 0% 同 RTT}、乱序、中途互换、间歇黑洞）；共享瓶颈 N∈{10,100} 流对比聚合开/关。
3. 消融：不确定度探测、效用微调、聚合、先验启动、接收侧控制、p_rand、双模各自关闭。
4. 指标：成功业务字节/秒、完成时间分布、P99、重传字节比例、伪重传比例、自排队时延、CPU/Gbit 与每 ACK 开销、RSS、算法状态轨迹、路径选择分布。
5. 客户端与源站 ECN/AccECN 支持比例用真实样本测量。
6. 报告：无同环境基线不写百分比；极限如实标注；给出默认建议但不自行切换，等待审批。
```

### T11（可选，启动前提见 D-F2：确认多级节点部署且父节点可同版本升级）· node↔parent 受控隧道

（保留 v2 内容）两端都是我们的栈；父节点按 path_table 选择；FEC 只在隧道内、只对 `p_rand` 高的路径按需开启，去冗余后有效吞吐必须优于无 FEC；两节点 netns 拓扑验证；不自行启用。

## 9. 决策记录（2026-09-15 全部批准，按建议执行）

| 编号 | 决策 | 结论 | 落实位置 |
|---|---|---|---|
| D-A1 | 接受 EdgeCC 无上游参考的前提 | **批准**。保留 Bbr3Ref/CubicRef/LossBlindRef 作同栈内锚点；EdgeCC 不在 T10 同环境下优于 Bbr3Ref 则不切默认 | §2.9、T5、T10 |
| D-A2 | 聚合共享瓶颈的误判倾向 | **宁可误拆不可误并**：合并需强相关证据+迟滞，拆分门槛低；拆分规则配欠利用回归测试 | §2.6、T6 |
| D-A3 | smoltcp fork 为长期方案 | **批准**。纪律：只改 `socket/tcp.rs` 与 wire repr 最小面，DIVERGENCE.md 逐项记录，不 fork 其它模块 | T3 |
| D-B1 | 源端口保留 + netfilter DROP 守卫 | **批准**。默认保留 40000–49999（可配置，须落在 `ip_local_port_range` 内并由 `ip_local_reserved_ports` 标记）；守卫失败为显式启动错误，计数进 /status | T4 |
| D-B2 | 网关 MAC 来源 | smoltcp ARP/NDP 自解析 + 缓存 + 失败计数可观测，不用静态配置 | T4 |
| D-B3 | PMTU 策略 | ICMP 驱动 + RFC 4821 式黑洞检测回退 | T4 |
| D-B4 | `xdp.upstream` 开关 | 接管完成后**保留一个发布周期再删** | T4、T10 |
| D-C1 | quinn Pacer patch | T5 先度量偏差；偏差影响探测幅度表达时才 patch，patch 面限 `connection/pacing.rs` | T5 |
| D-D1 | ECN/AccECN 默认通告 | 客户端方向**被动响应常开**（对端发起才用）；回源方向主动通告由配置门控灰度、默认关，T10 实测后定最终默认 | T7、T10 |
| D-D2 | 公网 CE 作为拥塞证据 | 作为证据但**权重受限 + belief 贡献封顶**；受控链路（回源到自有 infra）给满权重 | §2.3、T5 |
| D-D3 | eBPF SYN-cookie 编码 ECN | **不需要**，challenge 路径已显式不协商 ECN；本项关闭 | — |
| D-E1 | 效用权重 (a,b,c) 与分层 `Q_budget`/`d_target` 初值 | T5 用模拟器扫参给建议表，T10 实测后可调 | T5、T10 |
| D-E2 | 效用梯度微调 | 实现并做消融；默认倾向开、带开关；T10 数据定最终默认 | §2.4、T5、T10 |
| D-E3 | 探索/选路参数 | ε-greedy ≤5%；连续两窗 >20% 才切换；SYN 竞速 ≤2 路；主动探测限速；源端口重掷仅在统计证明 ECMP 多样性后启用 | T6 |
| D-F1 | L5 传输中换路 | 只建接口与计数，默认关；T10 数据证明值得再开 | T6 |
| D-F2 | T11 隧道 | 启动前提：确认部署存在多级节点且父节点可同版本升级；未确认前不启动 | T11 |
| D-G1 | T10 数据离线参数拟合 | **允许**（仅离线分析，不进数据面） | T10 |
| D-G2 | 节点出口整形 | 加配置键 `xdp.egress_rate_bps`，**默认不整形**（无配置=现状） | T8 |
| D-AQM | 转发队列 AQM 选型 | 默认交付 CoDel；PIE 仅在基准数据表明 CoDel 不满足时替换 | T9 |

## 10. 已发现的既有降级

- `src/quic_udp_demux.rs:163-180, 717`：静默丢弃 ECN。
- `src/xdp/af_xdp/bridge.rs:511, 1042-1050`：TX 背压退出 worker。
- 现状记录、随回源接管退役：`tcp_proxy.rs:1855-1861` 忽略 `TCP_CONGESTION` 返回值；`kernel_tuning.rs:275-276` optional 且不核对 qdisc。
- F8 的 `NoControl` 已由 `be75083` 止血为 Cubic。

## 11. 明确的非目标与设计限制

- 非 XDP 模式不做传输改造。
- 不做跨流均分带宽或对其他算法的公平性优化。
- 不做 L4S/ECT(1)/Prague、MPTCP、通用 TCP 上的 FEC、数据面在线学习。
- 不用 quinn 内置 `Bbr`。
- 不把 fq/CAKE/FQ-PIE 的 sysctl/tc 当作 AF_XDP 发包的队列管理。
- EdgeCC 没有上游一致性可声称；所有性能结论来自 T10 同环境对照，缺基线不写提升百分比。

## 上游依据

- [google/bbr v3（90210de4）](https://github.com/google/bbr/tree/v3) · [draft-ietf-ccwg-bbr-06](https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/06/) · Linux 6.1 `net/ipv4/tcp_bbr.c`（BBRv1，`lt_bw`）
- [RFC 9768 AccECN](https://www.rfc-editor.org/rfc/rfc9768) · [LWN 1058666](https://lwn.net/Articles/1058666/) · [RFC 8257 DCTCP](https://www.rfc-editor.org/rfc/rfc8257)
- [RFC 8985 RACK-TLP](https://www.rfc-editor.org/rfc/rfc8985) · [RFC 6937 PRR](https://www.rfc-editor.org/rfc/rfc6937) · [RFC 2883 DSACK](https://www.rfc-editor.org/rfc/rfc2883) · [RFC 3522 Eifel](https://www.rfc-editor.org/rfc/rfc3522) · [RFC 9438 CUBIC](https://www.rfc-editor.org/rfc/rfc9438) · [RFC 9406 HyStart++](https://www.rfc-editor.org/rfc/rfc9406) · [RFC 7323](https://www.rfc-editor.org/rfc/rfc7323) · [RFC 3168](https://www.rfc-editor.org/rfc/rfc3168)
- [RFC 3124 Congestion Manager](https://www.rfc-editor.org/rfc/rfc3124) · [RFC 8382 Shared Bottleneck Detection](https://www.rfc-editor.org/rfc/rfc8382) · [RFC 8305 Happy Eyeballs v2](https://www.rfc-editor.org/rfc/rfc8305)
- PCC-Vivace（Dong et al., NSDI 2018）· Copa（Arun & Balakrishnan, NSDI 2018）· Swift（Kumar et al., SIGCOMM 2020）· GCC（Carlucci et al., RMCAT）· Veno（Fu & Liew, JSAC 2003）
- [Linux AF_XDP 文档](https://docs.kernel.org/networking/af_xdp.html) · [Linux 6.1 AF_XDP copy TX](https://github.com/torvalds/linux/blob/v6.1/net/xdp/xsk.c#L514-L577)
- 本地依赖源码：`smoltcp-0.14.0/src/socket/tcp/{congestion.rs,tcp.rs}`、`wire/{tcp,ipv4}.rs`；`quinn-proto-0.11.17/src/{congestion.rs,congestion/bbr/mod.rs,connection/pacing.rs}`

## 附录 A：接入点分析（v3.1，T2 进行期间补充）

### A.1 回源连接面共四处

| 连接面 | 位置 | 接管方式 |
|---|---|---|
| L4 TCP 回源唯一漏斗 | `src/toa.rs:522/627` `connect_with_toa`：非 TOA = `TcpStream::connect`；TOA = 绑定分配端口 + genl 注册映射 | 替换为 reactor dialed 会话 + `virtual_l4_stream` 包装 |
| HTTP/HTTPS 回源 | vendored pingora `connectors/mod.rs:351` `do_connect_inner → l4_connect(peer, bind_to)` → `l4/ext.rs:564` → `TcpStream` | patch `l4_connect` 产出 AF_XDP dialed `Stream`；连接池 `reuse_hash` 在此层之上，T6 须把路径键并入 reuse_hash |
| UDP 回源 | `src/udp_proxy.rs:114` `UdpSocket::bind`、`:1589` `connect` | smoltcp-edge UDP socket + 出向流表 |
| H3 回源 | `src/origin_h3.rs` `OriginH3Connector` → quinn `Endpoint` → 内核 UDP socket | 见 A.4：CC 已由 quinn 适配获得，AF_XDP UDP 非必需 |

### A.2 TOA 发现（影响 T4 设计）

- TOA 发送端是内核模块 `toa-sender/kernel/cloud_toa_sender_main.c`：netfilter `NF_INET_LOCAL_OUT` 钩子拦截首 SYN（`syn && !ack && !rst && !fin`），按本地端口查 genl 映射，注入 TCP 选项 **kind 254**（v4 8B `{opcode,opsize,port,ip}`；v6 20B）。
- AF_XDP TX 不经过 LOCAL_OUT → **smoltcp 必须在 SYN 里自行写 option 254**。客户端地址在拨号时直接可知，`KernelClient`/genl 映射/端口分配器在此路径上全部不需要。
- SYN 选项预算（40B）：v4 MSS4+SACKOK2+TS10+WS3+TOA8 = 27B 可行；v6 = 39B 恰好贴满；再叠加 AccECN 选项（kind 172/174）会超——T7 的裁剪优先级因此必须含 TOA。
- TOA 端口范围已有 `configured_port_range` + 分配器模式可复用（复用模式而非内核模块）。

### A.3 eBPF 数据面是双人格（影响出向流表设计）

- `xdp_nat_*` 程序族：**NAT 转发面**。入向 client SYN 建 CT 项（`XDP_PENDING` → `XDP_TCP_CT`），报文改写后 `XDP_TX` 直发后端；后端回复按反转 CT 键（`client_addr=dst, backend_addr=src`）匹配后改写发往客户端；还有 SNAT 反查绑定与 splice 卸载。**这条面从不过 smoltcp。**
- `dispatch_local`（main.rs:1001）：**终结面**。`local_flags`（目的 ∈ 受保护 VIP 集）+ `policy.mode==2` → 按 proto tail-call 到 TCP/UDP worker，slot 空则 `redirect_from_scratch` → `XDP_XSKS.redirect`。
- dialed 流回包现状：SYN-ACK 目的 IP 是本地 → 过 `local_flags` → TCP worker 按反转键查 FWD/CT → 无匹配 → PASS → 内核 → RST（即 C17）。因此出向流表 `XDP_OUT_CT`（`(proto, local_ip, local_port, remote_ip, remote_port)` → XSK/queue）必须在 TCP worker 落到 PASS **之前**被查；ICMP 错误按内层五元组匹配同表。
- `AfXdpRouteMeta`（af_xdp/mod.rs:373）= `{interface, queue, link{src_mac,dst_mac}}`，目前只从入向帧学到（对端 MAC 即回复 MAC）。dialed 流需要主动解析 dst_mac（网关或直连对端）+ 多出口接口时的路由选择——D-B2 的落实点。

### A.4 QUIC 适配与边界

- 接入点：`TransportConfig::congestion_controller_factory`（`config/transport.rs:326`），默认 `CubicConfig`（:393）。
- **控制器是每路径构建**：`connection/paths.rs:67,145` 调 `congestion_controller_factory.build(now, mtu)`——多路径 QUIC 连接会有多个 EdgeCC 实例；factory 单例可以把每个实例注册进聚合（T6 的对接点）。
- 服务端配置点 `src/quic_transport.rs`；客户端配置点 `src/origin_h3.rs`（回源 H3 的 quinn `ClientConfig` 同机制）。
- 边界决定：H3 回源走内核 UDP socket 时 **EdgeCC 依然生效**（CC 在 quinn 内部）；AF_XDP UDP 只额外提供调度器管辖与收包路径统一——列为可选项而非 T4 阻塞项。

### A.5 其余确认

- `virtual_l4_stream`（tcp_reactor.rs:167）包装 AsyncRead+Write → pingora `Stream` + `SocketDigest(peer_addr)`；dialed 方向复用同一包装（改填 local/peer 角色）。
- `lb_factory.rs:241-262` `build_lb` 确认忽略 `_level`/`_parent_nodes`/`_tiered_origin_bypass`；T6 的父节点候选从这里接入。
- `build_origin_pool` 已有 primary/backup 两级池与健康检查钩子，path_table 驱动的选择加在候选展开处而非重建池。
