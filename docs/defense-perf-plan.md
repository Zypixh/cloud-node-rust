# 防御 + 性能全面优化计划

基于 `docs/perf-reports/20260912-023659-defense/perf-report.md` 实测数据与代码路径逐层分析制定。
每项标注：现状（已有什么，避免重复造轮子）→ 缺口 → 方案 → 涉及代码 → 验证 → 回退。

## 0. 现状盘点：已经存在的（不要重写）

| 层 | 已有能力 | 位置 |
|---|---|---|
| XDP/eBPF | 完整 eBPF 程序：精确 IP 封禁 map（v4/v6 各 262k 项）、LPM trie 网段封禁、端口+协议规则、XskMap（AF_XDP 重定向）、per-queue 统计、XDP 计数器 | `crates/cloud-node-xdp-ebpf`、`crates/cloud-node-xdp-common` |
| XDP 用户态 | 加载/attach（Auto/native/generic）、AF_XDP runtime、proxy redirect、queue 状态、status 持久化、shadow rules（allow>block 优先） | `src/xdp.rs`（7.4k 行）、`src/xdp_auto_config.rs`、`src/xdp_netdev_tuning.rs` |
| nftables | `inet cloud_node` 表 + `blocked_v4/blocked_v6` 精确 set + interval set + SYNPROXY（notrack/synproxy/drop-invalid 三规则 + sysctl 调和） | `src/firewall/kernel.rs`、`src/kernel_syn_defense.rs` |
| L4 判决 → 内核下沉 | `l4_defense` 封禁 → `WafStateManager::block_ip` → `publish_kernel_filter_snapshot` → `KernelFilter`（nft + XDP shadow） | `src/l4_defense.rs:1440`、`src/firewall/state.rs:523` |
| per-IP 精确计数 | DashMap 分片、262,144 项上限、饱和时 fail-closed、10s 滑动窗 | `src/l4_defense.rs`（`L4ExactCounterState`） |
| 聚合检测 | /24+v6/48 前缀窗口 + distinct-IP surge（1k/5k/10k 三档压力等级）+ prefix count | `src/l4_defense.rs`（`L4AggregateState`） |
| 活跃连接门禁 | per-IP CAS permit（`ActiveIpTracker`）、准入按内存预算 | 同上 |
| CC 限速 | governor `RateLimiter`（GCRA），全局 `max_qps` + per-IP `per_ip_max_qps` 双通道机制已存在 | `src/proxy.rs:4565 apply_cc_policy`、`src/firewall/state.rs:1321` |
| listener | SO_REUSEPORT 已开（每个 accept worker 独立 socket）、TCP_DEFER_ACCEPT=1s、backlog 由 governor 按内存推导 | `src/net_bind.rs`、`src/http_proxy_manager.rs:582` |
| UDP | SO_REUSEPORT、`UdpBatchReceiver`（recvmmsg 批收）、RXQ_OVF 监测、session 队列上限 + 满队列事件节流 | `src/net_bind.rs`、`src/udp_proxy.rs` |
| WAF | 规则编译为 AhoCorasick 预过滤 + RegexSet + 逐规则 evaluate | `src/firewall/compiled.rs` |
| 内存治理 | `MEMORY_GOVERNOR`：worker 数/缓冲/backlog 全由实时内存快照推导 | `src/memory_governor.rs` |

**结论：基础设施非常完整。报告暴露的不是"缺组件"，而是：检测→下沉的时延窗口、UDP 单 socket 读路径、个别语义 bug、以及 bench 未覆盖的内核下沉有效性验证。**

## 1. 缺口矩阵（报告数据 → 根因 → 修复层级）

| # | 报告现象 | 根因分析 | 层级 |
|---|---|---|---|
| G1 | churn 洪峰窗口合法 goodput 降至 ~5% | 封禁判定阈值（~200 conn/10s/IP）触发前，攻击连接挤满 accept 队列；封禁后才下沉。检测延迟 + accept 共享通道 | 检测速度 + 内核下沉生效性 |
| G2 | UDP 洪水合法 echo 0/100 | 1.5M pps 下 socket 队列在内核层即被耗尽，封禁下发之前合法包已进不来；入队后 per-IP 判决太晚 | 内核下沉 + UDP 读路径 |
| G3 | 封禁后 drain 仍耗 0.13 核 + accept 槽位 | 若 XDP/nftables 真实生效，封后流量应在 prerouting 被丢、完全不到 accept——0.13 核说明 bench 环境内核下沉未生效或部分生效 | 验证 + 下沉覆盖率 |
| G4 | 低速分布式 CC（每 IP <500/s）无防线 | `max_qps` 全局限额代码存在但 bench 未配置（=0）；且现实现是 governor keyed limiter | 配置 + 验证限额器热路径 |
| G5 | 403/UAM 响应声明 keep-alive 但实际关连接 | 响应头与行为不一致；每拦截消耗一次 accept 周期 | 正确性 bug |
| G6 | conn-hold 3000 连接 → RSS 12.6GB | 每连接驻留缓冲 ~MB 级；空闲连接未及时收缩 | 内存 |
| G7 | WAF 求值 −8.4% 吞吐 | 2 条规则 +4.4µs/req，预过滤器已存在；规则多时需看热点 | 观察项 |
| G8 | QUIC 伪源洪水 | `QuicNewRouteFlood` 有检测，但 quinn 收到 Initial 即分配状态，无 Retry 地址验证 | 协议层 |

## 2. 方案（按优先级分四个阶段）

### Phase A — 内核下沉生效性与延迟（最高杠杆，G1/G2/G3）

**A1. 验证并补齐封禁 → 内核下沉链路的真实覆盖率**

- 问题：报告没有验证封禁后攻击流量是在 XDP/nft 被丢还是仍到 userspace drain。"drain 0.13 核"暗示至少部分流量到了用户态。
- 方案：
  1. `bench-defense` 扩展：支持可选启用 XDP attach（generic mode 可挂 lo）与 nftables 初始化，默认关、env 开启——bench 显式声明模式，不改默认行为；
  2. 防御矩阵每阶段结束记录 `nft list set` 命中计数 + XDP `XdpCounters`（已持久化到 status）+ `nstat` 增量，对比 userspace drain 计数，量化"封禁后内核丢包占比"；
  3. 若发现 snapshot 同步有延迟窗口（`publish_kernel_filter_snapshot` 是批量快照而非即时写），评估封禁事件即时写路径——`update_block_ip` 单条下发而非等快照周期。
- 代码：`src/bin/bench-defense.rs`、`scripts/perf/run_defense_matrix.sh`、`src/xdp.rs:1093`、`src/firewall/kernel.rs`。
- 验证：复测 churn 阶段，封禁后攻击源 conn/s 应 →0（内核 drop），合法 goodput 在封禁后立即回到满速而非"缓解"。
- 回退：bench env 不开启时行为与现状完全一致。
- 实现状态（已提交）：
  - `BENCH_KERNEL_FILTER=auto|xdp|nftables|iptables|off`（默认 auto=生产行为）在 `bench-defense` 启动时显式选择后端；启动日志打印 `name/available/detail`，不可用后端显式报告而非静默降级。
  - `L4METRICS` 每 1s 快照新增三段：`kernel_filter`（名称/可用性/详情）、`xdp`（attach 模式 + `packets/pass/drop/redirect/parse_errors/map_miss/xsk_drops` + `blocked_v4/v6` map 条目数）、`kernel_sync`（`coalesced/reconcile_requested/failed/xdp_map_sync_failed`）。
  - `run_defense_matrix.sh` 透传 `BENCH_KERNEL_FILTER`；`l4_diff` 改为递归 diff，嵌套 kernel/xdp/kernel_sync 计数逐阶段差分。
  - 封禁→内核写入延迟确认：`reconcile_kernel_ip` 对 XDP filter 是**同调用栈同步 map 写入**（µs 级）；nftables 走 `kernel_sync` 批处理队列（coalesced），下沉延迟 = 队列批窗口。矩阵中对比 `xdp.drop` 增量 vs `blocked_total` 即可量化"封禁后内核丢包占比"。

**A2. 检测延迟压缩**

- 问题：`empty_connection_flood` 需要 ~200 hits/10s 才封——窗口内攻击 conn 已挤 accept。
- 方案：
  1. 压力自适应阈值：当 `L4PressureLevel ≥ Elevated`（聚合 surge 已检测到时）对 exact-counter 阈值做动态收紧（如 200→40 hits）——阈值本身是配置值，自适应系数在代码内显式定义并打日志；
  2. 快速通道：connect-and-close 特征在**第一个**事件即可高置信度识别（accepted + 0 bytes + 立即 FIN），当前按计数聚合；可对"零字节秒断"单独用更低阈值窗口；
  3. 封禁传播延迟：确认 `block_ip` → nft/XDP map 写入是同调用栈同步完成（读 `block_ip` 实现），若为队列异步则测量排队延迟。
- 风险：阈值收紧提高误封率。必须：保留原阈值作为 Normal 压力下的基线，只在 Elevated+ 收紧；封禁动作本身已有 TTL 与观测计数。
- 验证：churn 阶段合法 goodput 最低点的深度与持续时长（目标：从 ~5%/数秒 → >50%/<2s）。

**A3. XDP 层 per-IP/前缀速率压制（对付 G2 的根）**

- 问题：1.5M pps UDP 洪水在 socket 队列耗尽合法流量；userspace 判决再快也救不了入队前的饿死。
- 方案：扩展 `cloud-node-xdp-ebpf`：
  1. 新 map `XDP_RATE_V4/V6`（HashMap<IpKey, {window_start_ns, count}>）：per-IP 固定窗口 pps 计数，超限 `XDP_DROP`——eBPF 侧 token bucket 用 `bpf_ktime_get_ns` 原子窗口即可（已有 helper 在用）；
  2. 阈值由 userspace 按 pressure level 下发（Normal 时 map 为空即关闭，零开销）；
  3. 只对 UDP + 非已建立 TCP（SYN）生效，已建立连接包不查 map（per-CPU 数组标记协议开关）；
  4. 容量与现有 BLOCKED map 一致 262k，满时 fail-open 记录 `ratelimit_map_full` 计数（eBPF 不能扩表，fail-open + 指标是显式行为，符合"回退必须明确"）。
- 替代方案评估：nftables `limit` 表达式同样能限速但走 netfilter 全路径（conntrack/规则遍历），pps 越高越亏；XDP 在驱动层，1.5M pps 下 CPU 成本约为 netfilter 的 1/5-1/10。**选 XDP**。
- 验证：udpflood 阶段合法 echo 从 0/100 → ≥90/100；节点 CPU 在 1.5M pps 下 <2 核。
- 回退：map 为空=功能关闭；attach 失败按现有 `XdpFallbackMode` 处理。

### Phase B — accept/连接通道弹性（G1/G6）

**B1. accept worker 压力伸缩**

- 现状：`http_accept_worker_count` 由 governor 按 CPU/3 固定（8vCPU→2 worker=2 socket）。洪峰时 accept 是串行瓶颈。
- 方案：压力信号（`L4PressureLevel` + accept 队列溢出计数 ListenDrops）触发临时扩容 worker 至 cpu 数上限；压力回落后退出（worker 是独立 socket+task，退出即 unbind，无副作用）。伸缩事件打 warn 日志 + 指标。
- 风险：worker 扩容同时放大后续 L7 处理并发的内存——与 connection 准入预算联动：扩容仅在准入余量充足时发生。
- 验证：churn 洪峰值期间 accept 队列深度（`ss -ltn` Recv-Q）峰值对比。
- 实现状态（已提交）：HTTP/TCP listener 各维护一个共享 `AtomicUsize` 目标数的 SO_REUSEPORT worker 池；`pressure_accept_worker_target`（纯函数，Normal=base，Elevated/High/Critical 逐级+1 至 CPU 上限，恒≥1）驱动伸缩；worker 在两次 accept 之间比对目标数，超额即优雅退出（不动已建立连接）；压力下降→缩容，上升→spawn。含单测 `accept_worker_scaling_tracks_pressure_with_cpu_cap`。

**B2. 空闲连接内存收缩（G6）**

- 问题：3000 保持连接 → +12.6GB，约 4MB/连接驻留。
- 方案：
  1. 定位驻留构成：每连接的读缓冲/写缓冲/TLS 状态分别多少（jemalloc stats 或打印 buf capacity）；
  2. 对"已建立但空闲 >N 秒"的连接收缩读缓冲（`shutdown` 不可行，但可把应用层 buffer replace 成小容量）；
  3. 压力期准入策略：现有 `shared_connection_admission` 按预算拒连已工作——增加"空闲最久优先驱逐"（LRU idle-close）作为 Critical 压力下的显式动作，事件计入 L4 指标。
- 回退：驱逐仅在 `Critical` 触发且可观测（`idle_evict_total` 指标），Normal 下行为不变。
- 实现状态（已提交）：TCP relay 读路径在压力 idle-timeout 等待循环中把 copy buffer 整 Vec 替换为 4KB（`RELAY_IDLE_SHRINK_BYTES`），释放大分配回 allocator；数据到达时在 copy 循环顶部惰性 regrow 至 `relay_copy_buffer_bytes()`——收缩只释放空闲驻留内存，从不限制吞吐。收缩次数计入 `PipelineCounter::TcpRelayBufferShrunk` + debug 日志；配合既有 `tcp_relay_pressure_idle_timeout`（压力下空闲超时断连，显式 `PressureIdleTimeout` close reason）。LRU 驱逐项未实现——准入预算已限制连接数上限，列为候选。**无审批降级：无**（空闲收缩不影响语义；idle 超时已有显式 reason+指标）。

### Phase C — L7 防御补全（G4/G5/G8）

**C1. 全局 CC 限额验证与热路径检查**

- 机制已在（`apply_cc_policy` 同时查 `max_qps` 与 `per_ip_max_qps`），bench 未配置。
- 方案：① bench-defense 加全局 `BENCH_CC_MAX_QPS` 配置跑一轮验证纵深；② 审查 `check_rate_limit` 在 300k+ req/s 下 `check_key(&server_id)` 的争用——`RateLimiter::dashmap` 内部 per-key 锁，同 server_id 下是全局限额的单 key 热点，高并发下需确认 governor 实现是否为无锁 GCRA（若是有锁，换分片计数+惰性汇总或 `cell` 原子钟方案）。
- 验证：h1 hit 满速回归（全局限额开启时吞吐下降 <1%）。
- 实现状态（已提交）：`BENCH_CC_TOTAL_QPS` env 接 `cc.bench` 的 `max_qps`（全局限额）；`TrackedLimiter` 内层从 `RateLimiter::dashmap`（每个 limiter 一张 DashMap 只放一个 key，check_key 有哈希+分片锁）改为 `RateLimiter::direct`（NotKeyed/InMemoryState，单原子槽 GCRA 无锁），外层 DashMap key 不变、quota 变更即重建、容量 fail-closed 语义全保留——`check()` 每请求省一次 key 哈希+内层 DashMap 查找。

**C2. 拦截响应语义修正（G5）**

- 方案：403/429/UAM 响应统一 `Connection: close` 如实声明（行为不变，只修头）——防御语义上"关连接"是正确的，不应该为了省 accept 周期改成 keep-alive（那等于给被拦者免费复用通道）。
- 验证：curl 到 `/deny/` 检查响应头；回归 WAF 测试。

**C3. QUIC 地址验证（G8）**

- 问题：quinn 对伪造源 Initial 会分配连接状态（Retry 未启用）。QUIC 标准答案是无状态 Retry token。
- 方案：评估 quinn 0.11 是否暴露 Retry 控制——0.11 没有内建 Retry 生成；可行路径是 `quinn-proto` 层 `accept` 前手动发 Retry（`Initial::retry()`），成本高。替代：当 `QuicNewRouteFlood` 压力 ≥Elevated 时对 Initial 包走 XDP_RATE map（A3 的 map 对 UDP/443 同样生效）+ userspace 新路由限速（已有检测）。**结论：不实现 Retry 协议栈，用 L3 限速覆盖；记录为设计限制。**

### Phase X — XDP 主数据面（核心功能，全兼容）

**定位**：XDP/AF_XDP 不是可选加速项，是与 socket 路径平行的主数据面。用户确认：主部署环境为云 virtio。

**架构边界（verifier 硬约束，非工程量）**：eBPF 无法终结 TCP/TLS/HTTP。最大 XDP 化架构 = eBPF 快路径（drop/限速/steer）+ AF_XDP 用户态协议栈终结 + 内核栈只承接不匹配流量。现有代码已经是这个形态（`AfXdpTcpReactor` + smoltcp），以下是把"已有"变成"主力"的缺口清单。

**X1. virtio 现实与模式探测**
- virtio_net 的 AF_XDP zero-copy 需内核 ≥6.4；5.15（当前 bench）只有 generic/SKB 模式。
- 工作：attach 时探测并报告真实模式（native-zc / native / generic-skb），status/doctor 输出模式标签；SKB 模式下压性能预期（收益≈native 的 1/3-1/5，仍真实获得驱动层 drop + 绕过内核协议栈 + fill-ring 批收发）。
- 部署前置：virtio 多队列 `ethtool -L combined <vCPU>`，队列数 < vCPU 时 X2 无从谈起；安装脚本/doctor 检查项。

**X1.1 统一基线（已确认决策）**
- 支持矩阵：Debian 12 / Debian 13 / Ubuntu 22.04+，**兼容性门槛按内核 ≥6.4 划线而非发行版**；<6.4 → SKB 模式 + 显式 warn（可观测降级，非静默），<5.4 → 拒绝 attach。
- 构建基线 = **glibc 最老的 Ubuntu 22.04（2.35）**：CI release 已是此环境；本地 OrbStack 容器/虚拟机同样用 Ubuntu 22.04，本地产物可直接部署全部目标节点。
- 节点内核升级路径（安装脚本负责）：Debian 12 → `apt install -t bookworm-backports linux-image-amd64`；Ubuntu 22.04 → `linux-image-generic-hwe-22.04`；装完仍需重启生效，脚本需检测运行内核而非仅安装的包。
- 分工：OrbStack（编译 + Rust 测试，**内核共享 OrbStack 自带内核，无法验证 XDP/内核升级**）→ 真机 Debian13/Ubuntu24.04（XDP/eBPF/perf 矩阵验证）。现有 bench 机（Ubuntu 22.04/5.15）需重建或升 HWE 内核才能测 zc。
- glibc 结论：2.35→2.41 对本项目无性能差异（热路径全在内核/Rust/静态 C），基线永远取矩阵最老版本。

**X2. 单 reactor → per-queue pinned 线程（已实现，待真机验证）**
- 现状：`run_proxy_bridge` 单 async task 轮询全部 XSK 队列 = 单核天花板；SKB 模式每包成本更高，瓶颈更早到。
- 方案：每队列一个 pinned OS 线程，独立 `smoltcp::Interface`+reactor 实例（smoltcp `!Sync` 天然适配 per-queue 分片）；RSS 已保证 flow→queue 亲和，无需跨队列会话迁移。session/连接上限按队列切分预算。
- 性能优先强化：reactor 线程 **busy-poll 不睡眠**（去掉 5ms idle tick，或忙轮询+自适应退避二选一并可配置）、绑核、对应队列 IRQ 亲和绑定到同核、irqbalance 排除这些 CPU。
- 验证：8 队列下吞吐随队列数近线性。
- 实现状态（已提交）：
  - `AfXdpRuntimeHandle::take_queues()` 把队列 handle 移出共享 runtime；每队列一个 `afxdp-<iface>-<q>` OS 线程，各跑 `current_thread` tokio runtime + 独立 `AfXdpTcpReactor`/`udp_routes`/downstream mpsc——`manager.af_xdp` 互斥锁完全移出数据面。
  - CPU 绑核：`XdpInterfaceConfig.cpus[]` 与 `queues[]` 按索引对齐显式指定；缺省按全局队列序号 round-robin 到在线 CPU（`sched_setaffinity`，失败 warn 不降级）。
  - 空闲路径：5ms 固定 idle tick → 自适应退避（spin → 10µs 起步指数退避至 1ms 封顶，有流量立即复位）。
  - Watchdog：任一 reactor 线程在 bridge 应存活期间退出 → `disable_proxy_redirect_for_fallback`，全部队列显式回落内核 listener。
  - 队列状态：reactor 线程每 1s 自更新 `xsk_status` 中本队列的 rx_dropped/ring_full 等统计。

**X3. 全兼容 parity 矩阵（审计结论，2026-09-12）**

| 能力 | AF_XDP 路径现状 | 处理 |
|---|---|---|
| HTTP/1 + HTTPS + ALPN→h2 | 已 parity：`handle_af_xdp_l7_http_stream` → 共享 acceptor/`process_h2_stream`/`process_new_http`，含 admission/registry/shadow-transport guard | ✅ 已验证 |
| HTTP/3 + QUIC demux | 已 parity：`quic_udp_demux` AF_XDP handle + `receive_af_xdp_datagram` | ✅ 已验证 |
| TCP/UDP 透传 | 已 parity：`prepare_bypass_tcp_connection` 共享 L4 封禁/churn/active-limit/admission | ✅ 已验证 |
| SNI sniff + SNI 透传 | 已 parity：`handle_af_xdp_http_stream` 内置 ClientHello peek + `handle_sni_passthrough_stream` | ✅ 已验证 |
| PROXY protocol v1/v2 | **缺口（已修）**：`af_xdp_http_port_kind_sync` 不感知 `enableProxyProtocol`，L7 流不消费 PROXY 头 → PROXY 客户端会解析失败 | ✅ 已修：`af_xdp_port_requires_proxy_protocol_sync` + 入口先走 `maybe_consume_proxy_protocol_header_generic`（TCP 透传路径本就已消费） |
| IPv6 TCP/UDP | 已 parity：v6 包解析 + smoltcp 会话 + v6 block map | ✅ 已验证 |
| sendfile | virtual stream 无真实 fd，`sendfile_from` 对非 `RawStream::Tcp` 显式 `Ok(None)` → buffered-read 回退 | ✅ 显式回退已正确 |
| splice() 零拷贝 relay | 仅 socket 路径（`stream_tcp_bidirectional_with_metrics_options` 要 `TcpStream`）；AF_XDP 走 generic copy | 已知性能差异（虚拟流无法 splice），explicit-by-design |
| L4 防御事件 | 已 parity：churn-under-pressure/active-limit/admission-reject/handshake-timeout 全接 | ✅ 已验证 |
| 计费/带宽 | 已 parity：`copy_stream_and_count` + `ShadowTransportMetricsGuard` 两路径共享 | ✅ 已验证 |
| TLS session 复用 | 已 parity：共享 acceptor | ✅ 已验证 |
| idle/超时 | 已 parity：smoltcp session reaping + pressure-clamped read/handshake 超时 | ✅ 已验证 |
| loopback/UDS/管理面 | XDP 不经过 lo | **永远走内核 listener，文档注明** |
| 残余缺口 | 单 reactor 串行化（X2）、eBPF 快路径限速/NAT（X4） | 见对应条目 |

**X4. eBPF 快路径下沉（在 XDP 内完成的）**
- per-IP pps 限速 map（原 A3）：SYN/UDP/QUIC-Initial 限速在驱动层完成，smoltcp 只见合法流量。
  - 实现状态（已提交）：`XDP_RATE_CFG`（Array[1] 配置）+ `XDP_RATE_V4/V6`（262k per-IP 固定窗口 bucket，`bpf_ktime_get_ns` 判定）。UDP 全量计数，TCP 仅 SYN&&!ACK（连接建立尝试），已建立流不受限。map 满 fail-open + `ratelimit_map_full` 计数。userspace `sync_rate_limit_config` 挂 sweeper（5s 周期）按压力下发：Normal=关，Elevated=base，High=/2，Critical=/4；`XdpConfig.rateLimit`（`udpPps/tcpSynPps/windowMs`）为 None 时恒关。旧 .o 无 map → `rate_limit_detail` 显式报告 "missing map XDP_RATE_CFG"。计数 `rate_limited` 已入 `XdpStatusSnapshot` + bench L4METRICS。
- **UDP 纯 L4 透传全 XDP 化**：转发 map（listen 4元组→后端）+ 反向 conntrack map + 校验和重写，`XDP_TX` 直发，用户态零参与。需要 userspace 填邻居 MAC 表（云环境=网关 MAC）。这是 Katran 标准做法，pps 上限≈线速。
  - 实现状态（已提交）：`XDP_UDP_FWD`（listen tuple→backend+next_hop_mac+server_id）+ `XDP_UDP_CT`（client↔backend conntrack）+ `XDP_FLOW_ACCT`（per-CPU 字节/包计费，userspace 按 shadow delta 聚合进 `record_transfer`）。仅 `mode=proxy` 生效；CT/acct map 满 → `udp_fwd_map_full` 计数 + 回落正常数据面（不丢包）。配置项 `interfaces[].udpForwards[]`（listen/backend/nextHopMac/serverId），next-hop MAC 由 userspace 经 `ip -j route get`+`ip -j neigh` 解析，解析失败显式告警并保留原路径。CT GC 180s idle，挂 5s sweeper。**待真机验证**：校验和增量更新（bpf_csum_diff+fold）与 DSR 回包路径需在真网卡上跑通。
- **TCP 纯 L4 透传走 XDP NAT**（性能优先，不用 sockmap）：4-tuple DNAT+SNAT，逐包重写+校验和，`XDP_TX` 直发——不过内核 TCP 协议栈，线速。透传不改 payload，seq/ack 无需 delta 重写；回包路径依赖 backend 回流量经本节点（与 UDP NAT 同前提）。
  - 实现状态（已提交）：`XDP_TCP_FWD` + `XDP_TCP_CT`（conntrack 仅在裸 SYN 上创建；无状态的 mid-stream 包 → `None` → PASS 给用户态/内核路径，显式回退不静默 fast-path）；双向 FIN/RST 标记 `XDP_CT_STATE_CLOSING` 供 sweeper 提前回收（宽限 120s；established idle 7200s；UDP 180s）。TCP 校验和强制修正（两族皆然，不同于 UDP 零值跳过）。计费复用 `XDP_FLOW_ACCT`（CT key 新增 `proto` 字段防 UDP/TCP 元组冲突），计数 `tcp_fwd_tx`/`tcp_fwd_map_full`。**顺带修复**：原 sweep 先删 shadow 再折 acct delta 导致被回收流的字节全量重复计费——现在先折 delta 再删 CT/acct/shadow。配置项 `interfaces[].tcpForwards[]` 与 `udpForwards` 同构。**待真机验证**：同 UDP NAT，需真网卡验证 XDP_TX 路径与邻居解析；SACK/重传不需要处理（透传不改 seq）。
- **QUIC DCID 路由**：透传 → DCID 查 map 直转后端；终结在本机的 H3 → **DCID→XSK queue 映射**把连接钉到固定队列/worker，解决 QUIC 多核扩展与连接迁移（X2 的 QUIC 半边靠这个）。
  - 实现状态（已提交）：`XDP_QUIC_DCID` map（long-header DCID→XSK index）。eBPF 只解析 long header（DCID 长度显式编码，无状态也正确）；short header 无编码长度 → 保持 RSS 亲和 + 共享路由表/demux 交付（正确性已由 X2 修复的共享 route cache 保证）。queue reactor 观察到 long-header DCID 即注册 `DCID→自身 XSK`，镜像进共享 DashMap 随 route-cache 清扫过期摘除；旧 .o 无 map → 一次性显式告警 + RSS 回退。
- **SNI 混合快速路径**（性能优先）：eBPF 解析每 flow 首个数据段的 TLS ClientHello——SNI 完整则按路由 map 做 L4 直转；ClientHello 跨分片/解析不完整 → 该 flow 标记打回用户态慢路径（终结后 SNI 路由，现有路径）。注意 GRO/SKB 模式下首段可能聚合多包，长度判定按 TCP payload 边界做。永远存在慢路径分支，属协议边界而非降级。

**X4.5 全路径流量计费保证（计费=观测性契约，不可丢）**
- XDP 是入向流量的必经点：XDP RX 侧 per-CPU 计费 map 对**所有**路径（XSK/sockmap/PASS）统一计数；出向分路径：XDP_TX 程序内计、AF_XDP 在 reactor 计、内核路径补 TC egress。
- eBPF 侧：`BPF_MAP_TYPE_PERCPU_HASH`，key=`(server_id, flow/client)` → `{rx_bytes, tx_bytes, pkts, dropped_bytes}`；map 满 → `unaccounted` 兜底计数器 + 指标（不静默丢账）。
- AF_XDP L7 路径沿用现有 `response_body_len`/per-conn 累计/带宽延迟机制，X3 审计加"计费一致性"校验。
- 聚合：userspace collector 周期读 per-CPU map 按 CPU 求和 → 合并进现有 metrics/上报通道，下游看到的数据流与 socket 路径同构。
- 语义边界（明确记录）：L4 直转只能计 L4 字节/包，`response_body_len` 这类 L7 语义只在代理路径存在——计费维度本来就是字节，一致。

**X5. 兜底与存活（默认启用的前提）**
- 用户态 listener 永远绑定（XDP 只偷匹配流量；listener 空闲零成本，reactor 崩溃 → `fallback_pass` → 内核栈接管）。
- watchdog：reactor panic/连续 TX 失败 → 自动 `disable_proxy_redirect` + 指标 + 告警（现有 `AfXdpTxFailureTracker` 扩展）。
- 默认策略：auto-detect 成功 → 启用；失败 → 显式 fallback 原因记录。kill-switch 配置 `xdp.enabled=false` 保留。

**X6. 正确性门槛（默认值翻转前必须过）**
- AF_XDP vs socket 路径差异测试：同流量两侧结果一致（smoltcp 边界：重传、乱序、窗口、分片、RST）。
- 防御矩阵在 AF_XDP 模式下全量复跑（L4 事件、封禁、CC、UAM 一致性）。

### Phase D — 观察项与技术债（不排期，列入监控）

- **G7 WAF**：预过滤器（AhoCorasick+RegexSet）已是先进方案，8% 开销合理。若规则数 >50 再考虑：① 每规则 `#[inline]` 短路顺序重排（高频拦截规则前置）；② facts 提取惰性化（只提取被引用字段）。现在不动。
- **io_uring**：暂缓——用户已确认先不讨论。技术备注：全栈不可行（tokio 生态），accept-only multishot 可行但与 XDP 下沉收益重叠。
- **DPDK**：不采纳——AF_XDP 是同一思路的部署兼容版；DPDK 独占 NIC + hugepages + vfio，与云 virtio 部署模型冲突。
- **kTLS**：不采纳——rustls 不支持，换 OpenSSL 后端是 TLS 栈整体替换。
- **userspace TCP（mTCP 等）**：不采纳——smoltcp 已在 AF_XDP 路径中承担该角色，无引入第二套的理由。

## 3. 验证与 CI 加固

1. **CI 加 `cargo check --target` Linux job**（PR 阶段拦住 cfg-gated 编译错误，#33 类问题不再漏到 merge 后）；
2. 防御矩阵扩展：每阶段记录 nft set 命中、XDP counters、accept 队列深度、封禁下发延迟（判决时间→内核生效时间）；
3. 新增测量：A2 后 churn 合法 goodput 最低点；A3 后 udpflood 合法 echo 存活率；C1 后开全局限额的满速回归；
4. 全部 Rust 单测保持通过；L4 阈值/压力逻辑变更需带单测覆盖 Normal/Elevated 两档行为。

## 4. 执行顺序建议

| 序 | 项 | 理由 |
|---|---|---|
| 1 | CI linux check job | 立即防止回归，改动小 |
| 2 | A1 下沉链路验证（bench 加开关 + 矩阵计数） | 先量清现状，否则后续无基线 |
| 3 | X3 parity 审计（不改代码，先出缺口清单） | 决定 X 系列真实工作量 |
| 4 | X2 per-queue reactor 多核化 | XDP 主数据面的最大单点收益 |
| 5 | A2 检测延迟压缩 + C2 close 头修正 | 纯 userspace，风险可控 |
| 6 | X4 eBPF per-IP 限速 | eBPF 改动，独立 PR |
| 7 | C1 全局限额验证 | 配置+审查 |
| 8 | X1 模式探测/部署检查 + X5 watchdog + X6 对照测试 | 默认启用前置 |
| 9 | B1/B2 弹性伸缩+内存收缩 | 需要与 governor 联动设计 |

## 5. 明确的非目标

- 不改变任何已有防御语义（阈值默认值、封禁 TTL、fail-closed 行为全部保留）；
- 不引入静默降级：XDP map 满 fail-open 有指标、worker 伸缩有日志、空闲驱逐有计数；
- 所有新防御动作沿用现有 `L4DefenseKind` 指标与封禁 TTL 机制，不产生第二套生命周期。
