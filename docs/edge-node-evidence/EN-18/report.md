# EN-18: T2 — EdgeCC 基础层（PathModel / Inference / Envelope）+ 参考校验模式

Base: `da21e7a`（T1 之后）
规范: `tasks/xdp-transport-next-steps-2026-09-15.md` v3 第 2/7 节
环境: `vps-110` 构建+测试（Debian 12 / kernel 6.1 / 2c/2GiB）。本机仅编辑+传输。
范围: 仅 `crates/cloud-node-transport/` 与根 `Cargo.toml` workspace 声明；
未触碰 `src/xdp`；未实现 EdgeCC 决策层（T5）。

## 交付

### 参考校验模式（非生产算法）

- `cc/new_reno.rs` → `cc/reference/new_reno.rs`（`NewRenoRef`）
- `cc/cubic.rs` → `cc/reference/cubic.rs`（`CubicRef`）
- 模块文档明确"validation reference, not a production algorithm"；
  `CcSnapshot.mode` 报 `reference_new_reno` / `reference_cubic`，EdgeCC
  观测字段（belief/queue/p_rand/bw_sigma/envelope）保持 `None`——不伪造。

### 可复用部件 `cc/parts/`

- `parts/prr.rs`（PRR, RFC 6937）：`pipe` 采用 Linux
  `tcp_packets_in_flight` 语义——调用方提供"仍在管道内"的字节数
  （已排除 sacked/lost），PRR 不再叠加 `lost_out`（修复双重计数）。
- `parts/hystart.rs`（HyStart++, RFC 9406）：供 EdgeCC 及参考控制器复用。

### `model.rs` — PathModel（§2.2）

每 ACK O(1) 更新，全部状态有界：

- `bw_max`：分桶窗口最大值滤波（BBR win-filter）；
- `bw_est`/`bw_sigma`：EWMA + 置信度（BBRv2 风格不确定度）；
- `base_rtt`：长窗口最小值 + 漂移检测（BBR min_rtt / LEDBAT）；
- `qdelay` + Kalman/EWMA 梯度（GCC）；
- `extra_acked`（BBR `extra_acked`）；
- 两列丢包率（qdelay 升/静）+ 突发长度 + `loss_causation` 因果检验
  （加速窗口内加速交付 vs 加速丢失，Veno 灵感）；
- `p_rand` 随机丢包基线；`alpha` CE 分数 EWMA（DCTCP）；
- `lt_bw` policer 判定（BBRv1 长期带宽轮次）；
- `delay_signal_quality`（测量偏差 vs 噪声水平，新增）。

### `inference.rs` — 有界 log-odds 拥塞信念（§2.3）

- `congestion_belief` 有界 log-odds 累积器，证据权重表为常量并注明出处；
- `queue_estimate` 字节估计；
- 负证据：DSACK/伪重传；
- D-D2：公网 CE 权重受限 + 每 ACK belief 贡献封顶（防 CE 洪水淹没信念）；
- 共享瓶颈：`SbdStats` 统计量 + 接口定义已就位，判定实现留 T6。

### `envelope.rs` — 安全包络（§2.5）

- `inflight_hi` 的 set/hold/REFILL 规则；
- 任何调用方必须经 `clamp()` 取上限；测试断言不可越过。

### `CcSnapshot` 扩展

新增 `belief_milli` / `queue_estimate_bytes` / `p_rand_milli` /
`bw_sigma_bps` / `envelope_bytes` 及 EdgeCC `mode`/`reason_code` 取值集合。
不能诚实提供的字段保持 `None`。

### `sim.rs` — 确定性多流模拟器（§7.1）

- 多流共享单一瓶颈（共享 queue/policer/AQM，独立 per-flow sender）；
- RTT 抖动（均匀抖动 ±）、路由切换（中途改变双向 delay）、随机丢包与
  拥塞丢包叠加、app-limited 发送方、300ms RTT、延迟 ACK、CoDel 式 CE
  标记、policer 丢包；
- 每流独立 trace + 确定性 digest（固定种子）；
- per-packet scoreboard（`sacked`/`lost`/`retx_out` 状态机）保证
  `in_flight` 严格等于 Linux `packets_in_flight` 语义。

## 修复的正确性问题（本轮收敛中发现）

1. **pipe 幻影泄漏**：sacked/lost 记录原先永不离开 `in_flight`，
   PRR 又叠加 `lost_out` 双重计数 → cwnd 膨胀至 MB 级、RTO 后永久
   cwnd-blocked。重写 scoreboard 为三态状态机。
2. **重传风暴**：延迟到达的原始包被 sack 后仍因 `lost` 标志被重传；
   已重传在途的记录被后续 dupack 三元组反复重标重传（reorder 场景
   每段 ~74 次重传）。修复：重传选择要求 `lost && !sacked && !retx_out`，
   `retx_out` 即 sim 内 RACK 时间窗的替身。
3. **丢包标记过保守**：每 3 dupack 只标记 gap 头一段，droptail 大屠杀
   下恢复停滞。改为 frontier marking（SACK 前沿以下未确认段全部判丢，
   对齐 Linux `tcp_mark_head_lost`）。
4. **重传被 pacing 抑制**：纯重传阶段 Karn 规则冻结 srtt 导致
   `next_send_due` 推到数秒后。修复：有 `lost && !sacked` 记录时
   事件驱动立即重传，不受 pacing 定时器节制。
5. **RTO 时钟倒退**：`rto_due = last_ack_progress + rto` 在 policer
   节流等场景落入过去 → 事件时钟回退 → `now - policer_last_us`
   下溢 panic。修复：due 下界取 `now`，`push` 全局钳位保证单调。
6. **RTO 双重收缩**：`on_rto` 外又调用一次控制器 RTO 逻辑；
   `on_loss_event(persistent=true)` 已内含——移除外部重复调用。

## 验证（vps-110）

```
cargo test -p cloud-node-transport
  tests/cc.rs          7 passed
  tests/envelope.rs    5 passed
  tests/inference.rs   9 passed
  tests/model.rs      11 passed
  tests/rate_sample.rs 7 passed
  tests/sim_matrix.rs 17 passed   # 含 golden trace digest 钉定
  合计 56 passed / 0 failed

cargo check（根 crate）  Finished, 4 warnings（既有，与本次无关）
```

- golden trace digest: `13759154963003081103`（单流 CubicRef，
  100ms RTT / 100Mbps / 0.5×BDP droptail / 1MB，15s 上限；连续两次
  运行 digest 一致，`same_seed_same_trace` 与
  `multi_flow_trace_is_deterministic` 独立验证确定性）。
- 修复前后 sanity：4MB NewReno 参考运行在 ~4.0s 虚拟时间完成，
  drops=43 / retx=179 / rto=0，cwnd 稳定锯齿于 ~8×MSS（≈BDP）。

## 已知边界

- `dbg_sim.rs` 临时调试测试已删除——jitter/reorder 场景由 sim_matrix
  正式用例覆盖。
- EdgeCC 决策层（§2.4/§5）未实现，属 T5；共享瓶颈判定属 T6。
- 模拟器为离散事件模型：无 CPU 时间、无中断合并；loss 检测为
  3-dupack + frontier marking（非完整 RACK）。
- 参考控制器的 EdgeCC 观测字段为 `None`（有意不伪造）。
