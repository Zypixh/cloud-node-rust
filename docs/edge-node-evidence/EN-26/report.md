# EN-26: EdgeCC 法则重写 — ACK 压缩防膨胀 + 护栏盲区分流 + 自致丢包钳制

Base: `01cd028`（6.12 断流验证修复集）之后的 transport 层改动。
环境: 本机确定性 sim（`sim_acceptance` / `sim_harsh_cmp`），非生产性能声明。

## 背景

EN-25 法则在真实 WAN 与仿真中均落后于 bbr3ref ~3×。排查链：

1. `sim.rs` 把 `newly_acked`（cum 覆盖排出的记录集）喂给 `RateSample`——
   SACK 提前确认的字节在 hole-fill 时被整体计为瞬时交付，`delivered`
   虚高 → 速率样本被 ACK 压缩/hole-fill 膨胀（p50 观测 436MB/s
   于 12.5MB/s 链路）。
2. EdgeCC 以膨胀估计直设 BDP（cwnd=bw×baseRTT×gain）→ inflight
   数倍于浅 buffer → 尾丢被 `dupack≥3` massacre-mark 放大
   （retx 达 drops 的 24 倍）→ RTO 活锁。
3. 短 RTT 路径（5–10ms）的排队延迟永远达不到护栏阈值
   （T0: max(40ms, 0.4×base)），延迟护栏结构性失明——
   唯一可用的拥塞信号是丢包本身，而法则刻意 loss-blind。

## 改动

### sim.rs（语义修正，影响所有控制器）

`on_ack` 改为喂 `confirmed`：本次 ACK **首次**确认交付的记录
（未 SACK 过的 cum-drain 记录 + 新 SACK 记录），对齐 Linux
`tp->delivered` 的 SACK-即确认语义。hole-fill 不再把 backlog 计为
瞬时交付。注意：参考控制器同样受影响——bbr3ref 在该模型下的
样本更诚实，其自身无上界防护，矩阵中表现较旧模型变差，
作为参照值使用。

### model.rs

新增确认交付斜率估计（不可被单点 ACK 压缩污染）：

- `bw_slope_windowed()`：窗口割线，最小 span ≈ 0.5×srtt（2–50ms 钳制）；
- `bw_slope_lifetime()`：全程确认字节/存活时长——首个 ACK 对即可用，
  stall 期自然衰减但给出 liveness 下界；
- `ack_slope` 样本队列以 (µs, 累计确认字节) 记，有界 horizon。

### edgecc.rs（法则）

- `slope_bound()`：work_rate/pacing 上限 = max(窗口, 峰值, 全程) 斜率 ×
  slack（正常 2，clamped 时 1）+ 每 RTT 4 MSS 活性下限。
  **分流**：base_rtt ≥ 护栏阈值（WAN，延迟护栏可见队列）→ None；
  盲区路径（含 base_rtt 未知）→ 常驻上限。
- `peak_slope`：全 RTT 交付斜率超过前峰值才刷新，>4s 无新证明减半——
  stall 后恢复不被窗口斜率饿死，路径永久降级时上界会衰减。
- `assign_bdp_target`：base_rtt 缺失回退 last_srtt（Karn 饥饿路径）；
  盲区路径 inflight 另受 3×proven 窗口钳制；`queue_clamped` 期间
  loss inflation=1（否则排水期仍超溢）。
- ACK-clocked 回退 pacing：盲区 = min(delivery, 窗口隐含率, bound)，
  WAN = max(delivery, 隐含)（post-RTO catch-up 是合法速率）。
- 自致丢包钳制：丢包事件时 pre-loss inflight > 1.5×proven →
  `queue_clamped` 2 srtt（浅 buffer 溢出证据）；钳制期间丢包持续且
  inflight ≤1.2×proven → 判为外部丢包，测试自禁。自禁窗口按
  disproof 次数指数退避 8→16→32→64 srtt（`loss_clamp_off_shift`），
  诚实丢包路径不再每周期烧 ~2 srtt；真自致路径永不 disproof。
- `Ablations`/`Probe`/`Utility`/`DELAY_TARGET` 等旧模态删除——
  法则简化为 paced_start/startup/cruise/recovery，BDP 直设 + 护栏。

## 证据

`acceptance-matrix.csv`：25 单元 × 7 replica × 8 变体（SIM_ONLY 可复放）。
中位 FCT，edgecc ≤ bbr3ref 的单元 66/99；代表性单元：

| cell | edgecc | bbr3ref |
|---|---|---|
| rtt5_loss0_bw10 | 3.95s | 5.81s |
| rtt5_loss0_bw100 | 1.01s | 14.61s |
| rtt10_loss0_bw10 | 4.45s | 9.43s |
| rtt50_loss0_bw10 | 3.88s | 18.17s |
| rtt150_loss0_bw10 | 9.91s | 13.08s |

`sim_harsh_cmp`（深 buffer WAN 对照，2MB）：

| cell | edgecc | bbr3ref |
|---|---|---|
| rtt250+loss20%+100M | 3.6s (retx 1204) | 4.1s (351) |
| rtt300+loss30%+100M | 4.8s (1422) | 3.8s (702) |
| rtt200+loss20%+10M | 6.1s (3983) | 5.2s (2145) |
| rtt100+loss5%+100M | 1.1s (76) | 1.5s (421) |
| clean rtt100+100M | 0.6s (0) | 1.2s (442) |

## 遗留差距（已定位，未修）

- **bw1000 干净路径**（rtt50/150）：edgecc 0.76–0.92s vs bbr3
  0.14–0.49s——斜率上限把 ramp 限在 ~2×/RTT，bbr3 无界 max-filter
  直接打满。4MB 短流里 ramp 占比大；长流稳态差距收敛。slack=3
  试过：干净胖管加快 ~20%，但 rtt5_bw10 回归（3.95→5.67s），弃用。
- **高丢包 WAN**（rtt300+30%、rtt200+20%+10M）：落后 ~20%，retx
  2×——buffer 对 BDP 占比小（0.25–0.6×BDP），队列延迟又低于阈值，
  事实盲区但走 WAN 分支；靠自致钳制兜底。
- **rtt5_loss5_bw10**：8.2s vs 6.2s，RTO=16——尾部丢包触发的 RTO
  死时是主成本（200ms×16≈3.2s），非窗口问题。
- 真机 WAN A/B 未做——需要 .90 部署后实测，仿真数字不得外推。

## 测试

- `cargo test -p cloud-node-transport`：29 lib + 12 edgecc 集成全过；
- loss-blind 测试改为直接断言损失证据通道（`w_loss_qd_total`/
  `w_quiet_total`：blind=0 且 sighted>0）——聚合 belief 在 qdelay
  证据饱和时无法区分；
- quic_cc 断言更新为新语义（loss 不降窗、recovery 显示态、
  migrate 恢复至 cruise）。
