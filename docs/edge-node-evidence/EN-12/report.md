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

### 6. 队列故障全局扩大 + 启动竞态（EN-05 切片）

旧行为：任一队列 worker 反复 TX 失败/背压/poll 错误或退出 → `disable_proxy_redirect_for_fallback` **全局**摘除所有队列的 XSK 槽位，其余健康队列的服务被无谓拉垮。另外发现一个**预先存在的竞态**：`set_proxy_workers_starting(false)` 在 `enable_proxy_redirect()` 之前执行——worker 在 "starting=false, enabled=false" 的窗口内 `should_continue` 为 false 直接退出，探针实测命中（reactor ready 后 1ms 退出）。

修复（队列级故障隔离）：
- `XdpManager.xsk_withdrawn: HashSet<(ifindex,queue)>` 记录被摘除队列；`linux::sync_xsk_indices` 跳过 withdrawn——周期性 map sync **不会复活死槽位**；新一代 attach 前清空（旧代的摘除不泄漏到新 socket 集）。
- `linux::disable_queue_redirect` 只删该队列的 XSK_INDEX + XSKS 槽位；map 操作失败才显式升级为全局摘除（`widening to global redirect disable`）。
- `XdpQueueStatus.faulted` 标记 + `congested_drops` 计数；`proxy_xsk_ready` 把 faulted 视为已处置（流量走显式数据面回退），不阻塞兄弟队列；`refresh_af_xdp_statuses` 合并时保留 faulted/congested_drops 标记（否则每次 status() 读取会覆写）。
- worker 自己触发摘除后退出，supervisor 对已 faulted 的队列跳过重标——保留 worker 的原始故障原因不被 "exited unexpectedly" 覆盖。
- 启动竞态：`workers_starting=false` 移到 enable 成功之后；失败路径在 join 前清（否则 join 死锁）。
- **拥塞门控**：`tx_failures` 记 Backpressured → 该队列 `congested=true`，期间拒绝新 UDP 路由准入与新 TCP 会话（`has_session` 为 false 即丢），已建立流继续服务；Sent 恢复。拥塞在准入边界卸压而不是整队列崩溃。

验证钩子（debug-only）：`CLOUD_NODE_XDP_TEST_WITHDRAW_QUEUE=iface:queue` 在 redirect 打开后对该队列走一遍真实摘除路径（map 摘除+状态标记+sync 防复活），release 构建完全忽略。

## 验证

- verifier：全部程序 kernel 7.0 接受（对象与 EN-09 同 sha，未改 eBPF）。
- 矩阵：T01 28/28 + T02/T03/T04/T06 全过（x86-build）。
- 单测：107 xdp 测试 / 668 全量通过。新增：`xdp_proxy_queue_fault_keeps_sibling_ready`（faulted 队列不阻塞兄弟 ready；仅 not-ready 仍阻塞）。
- 探针 `scripts/edge/en12_queue_probe.py` 六阶段全过（结果存 `probe.json`）：

| 阶段 | 结果 |
|---|---|
| A auto 探测 | veth 拒绝 zero-copy → 显式落 copy，双队列 ready，redirect 开 |
| B 导流+RX 健康 | 400 注入帧 → redirect +400，rx_dropped/invalid/ring_full 全 0 |
| B2 就绪序 | 2 个 reactor ready 报告先于 redirect enable |
| C 显式 zero-copy | 两队列 `socket_created=false` + 明确 bind 错误，redirect 关，流量仍 PASS |
| D 强制 copy | 直接 copy 绑定，双队列 ready |
| E 队列故障摘除 | 摘除 q1：`faulted=true`，XSK_INDEX 2→1 且跨 sync 不复活；q0 `ready=true` 照常转发（redirectDelta=400）；`proxy_redirect_enabled` 保持 true——故障未全局扩大 |

## 遗留限制

- veth 不支持 zero-copy：落地模式证据只有 copy；zero-copy 成功路径需真实 NIC（drv 模式）验证。
- 跨队列 CID 导向由单测+矩阵覆盖；veth RSS 行为使 e2e 多队列分流证据为间接。
- worker 租约等待上限 10s：超时按硬故障合同处理（关 redirect + 记录原因 + PASS），不重试热重启同代 worker。
- 拥塞门控只覆盖"新准入"维度；已建立流在持续背压下仍按既有逻辑处置（不新增无界排队）。队列级摘除的 e2e 走 debug 钩子路径（真实 map 操作+状态+防复活）；TX 失败计数器的触发路径由同一 machinery 承载。
