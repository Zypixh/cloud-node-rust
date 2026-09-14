# EN-12: AF_XDP 队列正确性与预算治理

Base commit: `7a486e0` (EN-16 slice)
eBPF object: `data/cloud-node-xdp-ebpf.o` sha256 `00f0e34ee5350401152ae20381220f07520b6fa9d6db6cfb0d494b1b21056618`（未变，本轮纯用户态）
环境: OrbStack x86 VM, kernel 7.0.14-orbstack, netns/veth 双 RX 队列拓扑 (en2-a 10.99.0.5 <-> en2-b 10.99.0.6)

## 修复的缺陷

### 1. Fill-ring 饥饿不可恢复（need_wakeup 语义违反）

所有 socket 都以 `XDP_USE_NEED_WAKEUP` 绑定，但三条 fill 路径都用 `fill.produce()`——不产生 wakeup。驱动在 fill 环耗尽后睡眠，之后 produce 的 descriptor 永远不会被消费：**RX 永久饥饿**。

修复：`fill.produce_and_wakeup(..., rx.fd_mut(), 0)` 应用于初始 prime、运行期补充、RX 帧归还三处（`src/xdp/linux.rs`）。未产生的 descriptor 归还到正确的 free-frame 集合，不会双提交。

### 2. 队列数乘整机会话预算

每个队列 reactor 独立拿 `af_xdp_tcp_session_limit()` 整机预算——N 队列超订 N×。

修复：`af_xdp_tcp_session_limit_per_worker(total, workers)` 按 worker 数分摊（下限 1，仅退化配置生效）；`spawn_queue_reactors` 传入分摊值。单测 `af_xdp_tcp_session_limit_per_worker_divides_node_budget` 证明两 worker 不各占整机配额。

### 3. Socket 就绪被当成 worker 可处理

旧流程：XSK map 注册成功 → 立刻 `enable_proxy_redirect` → reactor 线程之后才 spawn。窗口内 eBPF 已把流量重定向进 XSK，但没有消费者在 poll——包静默进 ring 直到超时。

修复（worker 租约）：
- `XdpManager.proxy_workers_starting` 原子标志 + 每 reactor `ready_tx` 报告点——worker 在 Tokio runtime 建好、即将进入 bridge poll 循环时才报告。
- `spawn_queue_reactors` 在打开 redirect 前等待**全部**期望 worker（`AF_XDP_WORKER_READY_TIMEOUT` = 10s）。
- 超时/部分启动/spawn 失败 → `disable_proxy_redirect_for_fallback(reason)`：redirect 显式关闭、原因入 `fallback_reason`、流量走常规判决（PASS），不黑盒。
- `proxy_bridge_should_continue` 接受 `proxy_redirect_ready() || proxy_workers_starting()`：租约覆盖启动窗口但不提前导流。

### 4. copy/zero-copy 无探测无观测

旧代码永远 `XDP_USE_NEED_WAKEUP`（隐式 copy），驱动支持 zero-copy 也用不上；也不存在显式选择。

修复：`xdp.interfaces[].xskMode`：
- `auto`（默认）：先 `XDP_ZEROCOPY`，驱动拒绝则显式回退 `XDP_COPY`，探测轨迹写入队列 detail（`probe: zero-copy bind failed: ...`）。
- `copy`：直接 copy。
- `zero-copy`：硬要求，失败即队列 setup 失败——**不静默降级为 copy**。

落地模式记入 `XdpQueueStatus.xsk_mode`（`copy`/`zero-copy`），状态文件/dump 可见。失败错误带模式上下文（`AF_XDP zero-copy bind failed: ...`）。

### 5. reload 后 AF_XDP 数据面永久死亡（既有缺陷，实测证实）

bridge 曾是一次性任务：worker 检测 stale generation 退出后没有人为新 manager 重拉——**首次 reload 后 redirect 悬空**。EN-12 探针实测命中。

修复：`start_proxy_bridge_inner` 改为 generation-aware supervisor——换代时等新 manager attach 完成（proxy 接口存在 ⇒ 等 `af_xdp` runtime 就位或所有队列标记失败）再拉起；同代 bridge 失败不盲拉（显式失败合同）；stale manager 的 worker 由代次检查退出。

## 验证

- verifier：全部程序 kernel 7.0 接受（对象与 EN-09 同 sha，未改 eBPF）。
- 矩阵：T01 28/28 + T02/T03/T04/T06 全过（x86-build）。
- 单测：106 xdp 测试 / 662 全量通过。新增：worker 租约生命周期、预算分摊、xskMode 解析、supervisor 语义。
- 探针 `scripts/edge/en12_queue_probe.py` 五阶段全过（结果存 `probe.json`）：

| 阶段 | 结果 |
|---|---|
| A auto 探测 | veth 拒绝 zero-copy → 显式落 copy，双队列 ready，redirect 开 |
| B 导流+RX 健康 | 400 注入帧 → redirect +400，rx_dropped/invalid/ring_full 全 0 |
| B2 就绪序 | 2 个 reactor ready 报告先于 redirect enable |
| C 显式 zero-copy | 两队列 `socket_created=false` + 明确 bind 错误，redirect 关，流量仍 PASS |
| D 强制 copy | 直接 copy 绑定，双队列 ready |

## 遗留限制

- veth 不支持 zero-copy：落地模式证据只有 copy；zero-copy 成功路径需真实 NIC（drv 模式）验证。
- 跨队列 CID 导向由单测+矩阵覆盖；veth RSS 行为使 e2e 多队列分流证据为间接。
- worker 租约等待上限 10s：超时按硬故障合同处理（关 redirect + 记录原因 + PASS），不重试热重启同代 worker。
