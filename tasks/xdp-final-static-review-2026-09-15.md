# XDP 全协议代理：315af04 发布前静态审阅

基线：`315af04070e5c5be0d5955bc483c929af1a0a89f`。审阅时工作区干净。

目标保持不变：默认启用 XDP/AF_XDP 全协议代理，允许显式关闭；云环境以 generic/SKB + AF_XDP copy 为当前目标。不新增 B 组过滤模式，不引入 TC 后端。

本次仅阅读代码、仓库内 VPS 证据及上游接口约束，未编译、未运行测试、未连接 VPS、未部署。下面的缺陷来自静态控制流和资源计算；它们的远程复现与修复验收尚未执行。测试通过的数字均引用已有报告。

## 当前判断

全协议软件路径已有实质交付：HTTP/HTTPS、H2、TCP、UDP、SNI、QUIC/H3 的 IPv4/IPv6 应用矩阵已有 veth/SKB 证据。应继续修复现有路径的具体问题，随后用最终 release 工件验证。当前不建议直接标记为默认接管生产流量的稳定版。

这不是要求等待 native/zero-copy 硬件才能交付 generic 版本。generic 的实际云网卡容量、抗压及恢复能力可以在当前 VPS 上先验证；native/zero-copy 能力应单独限定发布范围。

## 已有证据能证明什么

- `docs/edge-node-evidence/REVIEW-2026-09-15/R5-lifecycle-and-protocol-matrix.md` 与 `xdp-netns-smoke-run8.log`：.120、kernel 6.1、veth/SKB、单队列；二进制为 debug build。
- 应用矩阵：HTTP 2、HTTPS 4、TCP 2、UDP 2、SNI 2、QUIC 2、H3 2，H2 双栈有响应记录；应用阶段 `redirect=119`，`parseErrors=0`，`xskDrops=0`。
- reload 阶段确实替换 manager，supervisor 存活，新代 readiness 成立。
- 但 reload 前后 `redirect` 都是 0；该阶段不能证明携带活跃连接的 reload，更不能证明 prepare 失败后原连接不受影响。
- 最新 .110 库测试报告为 697 pass。先前 753 是不同命令范围、不同提交的历史结果，不把二者相减解释为测试减少。
- eBPF 先构建、用户态后内嵌，以及对象 SHA 校验的发布设计已改正；发布脚本自身仍有下述确定问题。
- 总任务表与 execution-status 中有旧 TODO/IN_PROGRESS/VERIFIED，不能取代最新代码及逐项证据。EN-18..33 的整个基础设施计划也不能仅凭本轮 XDP 烟测认定全部完成。

## 发布前应修复的问题

### F1 / P1：prepare 前替换全局 manager，会提前终止旧 AF_XDP worker

定位：`src/xdp/mod.rs:2658`、`:2239`、`:2675`；`src/xdp/af_xdp/tcp_reactor.rs:1458`；`src/xdp/af_xdp/bridge.rs:552`。

`reload_from_runtime` 在 `initialize_inner`/verifier prepare 前调用 `replace_manager_from_runtime`。后者立即发布新全局指针并停止旧 sweeper/map-sync/flow-consumer。旧队列线程每轮检查 `manager_is_current`，因此在新对象完成验证前就可能退出，关闭 XSK 并销毁 smoltcp 会话。

即使新对象在 prepare 被拒，旧 kernel link 仍存在也不代表旧用户态传输仍存活。错误分支的 `restore_manager` 只恢复指针；已退出的 worker 和旧连接无法恢复，已停止的维护任务也未在该分支完整重启。

修复合同：candidate 在 prepare 成功前不发布为 current；旧 worker 的有效性应由明确的数据面生命周期控制。失败恢复必须覆盖维护任务、队列持有者和实际收发能力。成功换代可以沿用明确的“旧 smoltcp 连接终止”合同，不要求实现跨栈迁移。

远程验收：保持已有 TCP/H2 连接持续收发，注入坏对象、verifier 拒绝或 ABI 不兼容，并让 prepare 持续足够久使旧 worker 获得调度机会。失败后原连接应继续工作，且 sweeper/map-sync/flow-consumer 均正常。另测成功换代的新连接恢复和旧连接显式终止。

### F2 / P1：正常容量拒绝会升级为队列永久退出

定位：`src/xdp/af_xdp/tcp_reactor.rs:206`；`src/xdp/af_xdp/bridge.rs:513`、`:785`、`:96`。

`RefusedAtCapacity` 和 `IngressQueueFull` 会增加连续拒绝计数；达到 1024 后，bridge 撤销本队列 redirect 并直接 `return`。supervisor 对仍为 current 的 manager 不自动重启。

触发条件是会话/ingress 满后连续收到新流量，期间没有可重置计数的 Accepted 等状态；这属于正常过载，不能据此认定收发设备故障。结果是本队列已有 TCP 会话也被销毁；单队列 VPS 会丢失整条 AF_XDP 服务路径。攻击结束后的容量释放无法让已退出线程继续服务。

修复合同：容量拒绝仅拒新、计数、背压，并继续处理存量与回收；只有设备/worker 的实际故障触发隔离。若设计成可恢复熔断，需要有界恢复机制及明确的存量连接语义，不能用退出代替负载削减。

远程验收：小会话上限、保留正常连接、填满容量，再连续发送超过 1024 次新连接请求；断言 worker 仍在、存量可用、压力停止后自动恢复新建。不要只断言 tracker 达到阈值。

### F3 / P1：TCP 消息队列上限没有与内存字节预算闭合

定位：`src/xdp/af_xdp/mod.rs:59`；`src/xdp/af_xdp/tcp_reactor.rs:1384`、`:1477`、`:1576`。

生产 stream 每方向 256 个消息槽，write 单块最多 16KiB，因此仅发送消息队列就能保留 `256 × 16KiB = 4MiB/连接`。接收方向也可以积累大块 Bytes；此外还有 smoltcp、pending、协议层和回源缓冲。

会话容量却按 `2 × 16KiB + 16KiB = 48KiB/连接` 估算，且最小强制 512。该 TCP 入队路径只申请消息槽，没有随 Bytes 生命周期保留的全局字节许可。消息数有界不等于在 2GiB 节点内存内有界。例如 512 个连接各填满发送队列，单项潜在数据保留量已是 2GiB；这是上限计算，尚未实测为可达到的 RSS。

修复合同：每连接、每队列、节点的 TCP 缓冲字节额度必须闭合；Bytes/pending 的转移不得漏记或重复计费；关闭、取消和错误释放额度。至少按真实最坏保留量缩小通道并修正会话估算，不能仅提高压力阈值或依赖定期 RSS 观测。

远程验收：release 模式下多连接慢读/零窗口、慢后端、取消与断开，记录 TCP queued bytes、RSS、会话数、预算释放。满足预算前拒绝或背压，结束后资源回到可解释的基线。

### F4 / P1：250ms sweep 在连续快速轮询下不会周期启动

定位：`src/xdp/af_xdp/tcp_reactor.rs:976`、`:1013`；测试 `src/xdp/tests.rs:2047`。

没有活动 sweep 时 `sweep_keys` 为空，`sweep_pos >= sweep_keys.len()` 仍为真，函数结尾于是每次都执行 `last_sweep = now`。下一次调用只要间隔小于 250ms，启动条件永远不满足。bridge 的 idle backoff 最大仅 1ms，这正是通常运行方式。

首次扫描可能完成，但完成后的普通轮询会不断把下一轮计时起点推后。现有分批测试直接跳到 250ms 以后再验证两批推进，没有覆盖“反复每 1ms poll，累计经过多次 250ms”的情况。

影响：无 ingress/wake 的冷会话变化失去兜底，例如应用直接 drop stream 后发送通道断开，reactor 未必及时处理关闭；只能等后续入包或其他超时。reaper 有独立 last_retain，仍可能运行；不能把此问题表述成全部回收永远停止。

修复合同：只在真实扫描周期完成时更新完成时间，或使用独立 next_sweep_due；区分“当前没有扫描”和“本次刚完成扫描”。补 drop/shutdown 的工作通知合同。

远程验收：以 1ms 步长连续 poll 数秒，断言周期扫描真实多次发生；冷会话无网络输入时 drop stream，验证在规定推进期限内观察关闭并释放资源；保留大表分批测试。

### F5 / P1：自动推导接口会丢失显式安全/资源配置

定位：`src/xdp/mod.rs:2264`；`src/xdp_auto_config.rs:146`。

无显式 interfaces 时自动推导构造全新 `XdpConfig`，把 budget/admission/ebpf_object/state_tables 置为 None，并重建 proxy。调用方只补回 attach_mode、fallback、rate_limit，然后以 derived 覆盖 runtime.xdp。

所以“自动发现网卡 + 显式 stateTables/budget/admission/ebpfObject”的组合会丢失运维设置。尤其显式 stateTables 本应超预算即报错，却可能被抹掉后走默认自动缩表，违反已声明的合同。

修复合同：在原配置上只补齐缺失的接口、队列与端口。对显式 proxy.protocols/ports 的覆盖语义也做统一处理。不得通过要求用户补一份接口清单绕过配置合并错误。

远程验收：interfaces 缺省、分别显式设置上述字段，经过真实 auto-config 入口后断言保留；再验证显式超预算拒绝、缺省允许缩表、显式外部对象确实被选择。

### F6 / P1：发布 CI 的 nightly 别名命令非法

定位：`.github/workflows/release.yml:190`；`xtask/src/main.rs:58`、`:122`；`build.rs` 的 nightly 子构建。

当前 CI 执行 `rustup toolchain link nightly <dated-toolchain-path>`。rustup 的 link 接收 custom toolchain name；`nightly` 能解析为官方 toolchain，因此不允许作为 custom 名称。`set -e` 下将在这一步终止，尚未进入后续对象/节点构建。

上游依据：rustup 1.28.2 `src/toolchain/names.rs` 的 `CustomToolchainName::validate` 明确拒绝能解析为 `PartialToolchainDesc` 的名称。不是在本机执行失败命令得出的结论。

修复合同：build.rs、xtask、CI 共用明确的 dated nightly 配置，并让 build 和 rust-src 检查读取同一值。不建议仅改 custom 名称，因为现有 xtask 还会通过 `rustup component list` 检查工具链组件，应使用正式的 dated 工具链完成整条链。

验收：远程或 CI 干净环境执行与发布一致的工具链准备、eBPF、node release、打包流程；拿该 tarball 在 VPS 安装/启动/协议烟测/关闭/回滚。对象与二进制记录完整 SHA，不能用 debug node-bin 替代。

### F7 / P1（多队列条件）：QUIC DCID 不能直接把入包跨 RX 队列送给另一 XSK

定位：`crates/cloud-node-xdp-ebpf/src/main.rs:1583`；`src/xdp/af_xdp/bridge.rs:683`。

用户态把长头 DCID 绑定到最初接收队列的 XSK；eBPF 用 `steered_xsk.or(default_xsk_index)` 优先选该 XSK，没有核对其 netdev/queue 是否等于当前 ingress。相同 DCID 因地址变化/RSS 分布等落入另一队列时，就可能重定向到不匹配的 XSK。

Linux AF_XDP 要求 XSK 与收包 netdev/RX queue 匹配，copy 模式也不能用 XSKMAP 任意跨队列交换；不匹配会丢包。单队列 veth 不会覆盖此触发条件，quinn 的 PATH_CHALLENGE 也无法修复已经在它之前被丢掉的包。

修复合同：先 redirect 到当前 ingress 对应的有效 XSK，再通过共享 demux 或有界用户态投递找到 QUIC owner；或采用经过验证的硬件 steering。不要给 UDP 透传注入终止端 Retry。

验收：相同 DCID 在两个队列/接口接收，覆盖长头重传及地址变化；核对内核实际 drop 与用户态投递。若当前环境无法建立多队列路径，应显式限定本次发布支持范围，而不是标注已验证。

### F8 / P1：AF_XDP TCP 当前落到 smoltcp NoControl，未启用网络拥塞控制

补充审阅：用户追问 BBR、流控和 fq/CAKE 后，对照 Cargo.lock 锁定的 smoltcp 0.14.0 与 quinn-proto 0.11.17 本地依赖源码；仍未执行本机编译/测试。

定位：`Cargo.toml:90`、`:95`；`src/xdp/af_xdp/tcp_reactor.rs:798`。

两个 smoltcp 声明均为 default-features=false，启用 socket-tcp，但未启用独立的 socket-tcp-cubic/socket-tcp-reno。Socket 创建后只关闭 Nagle，没有设置拥塞算法。smoltcp 0.14.0 的 `socket/tcp/congestion.rs::AnyController::new` 在这两个 feature 均未启用时选择 NoControl；其 `window()` 返回 usize::MAX。

所以客户端侧 AF_XDP TCP 仍有接收窗口、发送缓冲上限、ACK 与重传，但没有通过 Reno/Cubic/BBR 按网络拥塞调整 cwnd。XDP pps 防护预算、wake/pump 调度额度和通道背压都不能替代端到端拥塞控制。

修复合同：先启用已有且适用的控制器，例如 socket-tcp-cubic，并在生产 socket 创建处显式选择、在状态中暴露实际算法；需要对已连接 socket 断言不为 None。BBR 不在当前 smoltcp 提供的选项内，若未来必须使用，应选择经过验证的用户态传输实现/实现移植，不能把内核 sysctl 当成完成，也不能只加一个 bbr 配置字符串。

远程验收：final release 构建的算法检查；私有 netns/veth 下延迟/丢包/乱序/限速矩阵，记录重传、有效吞吐、P99、发送节奏、竞争流公平性和内存，不以无损低 RTT echo 通过代替。netem 应放在包实际经过的链路上，确认 impairment 计数增长，避免在 AF_XDP TX 绕过的根 qdisc 上配置后误判已施加弱网。

## 弱网、BBR 与 qdisc 补充

- `src/kernel_tuning.rs:275` 在 kernelTuning.enabled（默认 true）时尝试设置 default_qdisc=fq、tcp_congestion_control=bbr；可选项失败不阻止启动，结果会记录。`src/tcp_proxy.rs:1855` 还对普通 relay/backend TCP socket 尝试 TCP_CONGESTION=bbr，但忽略 setsockopt 返回值，需补实际算法读取与失败观测。
- 内核 BBR 只控制对应内核 TCP socket 的发送方向。AF_XDP/smoltcp 客户端侧不继承；回源内核 TCP 可使用它。H3/QUIC 终止由 quinn 自己控制，锁定依赖默认 Cubic 并有 pacing，当前未选择 quinn 的 BBR。纯 UDP/QUIC 透传不应由节点冒充协议端点重新实施 TCP 拥塞控制。
- 当前 smoltcp RX/TX buffer 各固定 16KiB。TX buffer 保存未确认字节，因此单连接窗口吞吐量级约为 16KiB/RTT；RTT=100ms 时约 1.31Mbit/s，RTT=200ms 时约 0.66Mbit/s，均为理想窗口上界估计而非实测。增大通道深度不会扩大 TCP 在途窗口，应在 F3 全局字节预算下做 BDP 感知/分级缓冲与明确上限。
- Linux 6.1 的 AF_XDP copy TX 经 `xsk_generic_xmit` → `__dev_direct_xmit` → `netdev_start_xmit`，绕过绑定设备普通 egress qdisc；即使入口为 generic/SKB，也不能据此认为本机 fq/CAKE 管到了 AF_XDP 发包。外部交换机、宿主机或其他实际经过的队列仍可施加排队与整形。
- fq 是队列调度/公平排队与 pacing 支持；CAKE 组合整形、流公平与主动队列管理。它们不是 TCP 拥塞算法。设置 default_qdisc 不会自动替换现有网卡队列；当前未发现安装 CAKE 或用 tc replace 配置运行中 qdisc 的生产代码。多队列网卡还要检查 mq 的叶子。
- 本项目 quinn 配置 send_window=32MiB 是每连接限制，源码“Per-stream send window”的注释不准确；stream_receive_window=4MiB 是每 stream 限制。窗口与并发额度应联合计费，不应直接把高吞吐参数推广到所有 2GiB 节点。
- 后续优先级：F8 启用拥塞控制 → F3 字节预算与 TCP 窗口 → 按连接 pacing/按队列有界公平发送 → 弱网验收。内核 TCP 的 BBR/fq 做真实生效检查；CAKE 仅在确认能控制的瓶颈、带宽和 CPU 预算下评估，不默认作为 AF_XDP 的弱网补丁。

## 高性能和强防护的实际边界

1. generic + AF_XDP copy 的客户端 TCP 路径为 skb/XDP → XSK copy → owned frame → smoltcp → Bytes 通道 → 现有代理逻辑。它已有多项拷贝/分配优化，仍保留内核至 UMEM、owned 帧及协议缓冲间的搬运，不能据此宣称比 socket 代理更快。
2. `pump_sessions` 的调用数预算不等于全部轮询成本预算：wake_set.retain 遍历整表；sweep 开始仍收集全部 keys；reaper 周期性全表扫描；smoltcp poll_egress 仍遍历 socket。热会话还可能在同一轮重新入队并重复消费 pump 额度。这些需按总循环时间、活跃/空闲比例、P99 和 CPU 测量。
3. TCP cookie 强验证当前是显式 IPv4 SNAT tcpForwards challenge 路径。默认 AF_XDP/smoltcp 终止路径仍在初始 SYN 建会话和 socket buffer，通过完成握手后才启动业务代理；这是有界半开，不是所有 TCP 入包均无状态挑战。不能把 EN-14 的成果泛化成默认 HTTP/HTTPS 的无状态 SYN 防护。
4. 全局 `unverifiedPps` 当前先于连接路径执行，包括已验证流。因此后续 verifiedPps 不是与未验证洪水完全隔离的可用性保留池。需要分别评估“内存不爆”“设备仍在运行”和“正常连接仍拿得到处理机会”。
5. 小内存自动缩表只调 state map 容量，默认 pps 阈值仍为固定百万级，不代表已匹配 2c2g 实际处理能力。应使用该云网卡的测量结果定容量和压力门。
6. `src/xdp_netdev_tuning.rs:1347` 的计划关闭 GRO/GSO/TSO 及 checksum 等 offload。AF_XDP 帧语义可能需要其中部分设置，但同接口的普通回源流量也可能受影响；性能比较需记录实际 offload 状态，不能只报告 XDP drop pps。
7. 当前报告的主机内存描述存在 2c/1GB 与先前 2c/2GiB 差异。容量测量应记录实际 MemTotal/cgroup 限额，勿以预期规格代替。
8. 同 netdev/queue 绝对不能有两个 XSK 的文档说法过强：Linux 存在 shared UMEM 多 socket 模式。当前每队列独立 UMEM/会话实现没有无缝迁移能力，这个实现限制仍然成立，不需要本轮引入 shared-UMEM 重构。

## 交给 Devin 的执行顺序

本地仅编辑/静态阅读。所有编译、测试、eBPF 构建、压力验证在既有授权 VPS .110/.120；复用隔离测试目录、私网/netns/veth，禁止测试清理生产 bpffs。不要在本机恢复 cargo target，不新增 B/TC，不代发版本。

1. 核对 HEAD 是否仍为本报告基线；若已有后续修复，逐条核销，避免覆盖并行工作。
2. 先修 F6 发布入口与 F5 配置合并，分别提交并保存远程复现/通过证据。
3. 修 F4 调度时间与 F2 过载处理，再修 F8 拥塞控制和 F3 字节预算/窗口；测试必须触发连续轮询、连续拒绝、慢读累积与真实弱网条件。
4. 修 F1 candidate/active 生命周期，补带流量的 prepare 失败与维护任务恢复测试。
5. 处理 F7 多队列约束；无硬件时限定能力声明并准备真实接收队列验证，不以 helper 返回 REDIRECT 当成实际交付成功。
6. 从最终源码生成 release 工件，用最终 tarball 重跑双栈协议矩阵、启动/关闭、失败回滚。功能验证允许 veth/SKB；generic 容量测量需要目标云 vNIC 的软件路径。
7. 性能只比较本项目现有 XDP 关闭路径与 generic 全协议代理路径。覆盖干净流量、长连接/小包、慢读、受控异常流量混合及恢复；固定代理功能、缓存状态和资源限制，记录成功业务吞吐、P99、CPU/softirq/RSS、字节队列、丢包、恢复时间及发生器上限。缺乏基线时不写提升百分比。
8. 更新单一状态入口与证据索引，列出已执行命令、完整提交/工件 SHA、实际内核/网卡/队列/copy 模式、每项结果和未测范围。先提交可审阅结果，不自动 tag/push/部署。

最终交付应回答：这台云主机上 generic 全协议代理能处理多少正常业务；过载是否仅拒新且停止后自行恢复；配置与发布工件是否确实按运维指定生效。通过这些门后再推荐稳定发布。

## 上游依据

- [Linux AF_XDP 文档：XSKMAP 绑定约束与 shared UMEM](https://docs.kernel.org/networking/af_xdp.html)
- [rustup 1.28.2：CustomToolchainName 校验](https://github.com/rust-lang/rustup/blob/1.28.2/src/toolchain/names.rs#L385-L397)
- [Linux 6.1 AF_XDP copy TX](https://github.com/torvalds/linux/blob/v6.1/net/xdp/xsk.c#L514-L577)
- [Linux 6.1 direct TX](https://github.com/torvalds/linux/blob/v6.1/net/core/dev.c#L4288-L4325)
