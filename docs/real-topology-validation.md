# 真实双机拓扑 XDP/AF_XDP 验证报告

日期：2026-09-18。本报告回答 veth 矩阵无法回答的"真实网卡"问题，取代 veth 数据作为真实性能参考。

## 测试拓扑

```
客户端 162.251.92.120 ──WAN ~3.9ms──▶ 103.79.184.90 (DNAT→10.1.10.2) ens17
                                          │ virtio_net，native drv XDP，8 个 RSS 队列
                                          │ 用户态 TCP（smoltcp-edge）+ EdgeCC
                                          ▼
源站 162.251.92.110 ◀──WAN ~3.8ms── 上游腿（kernel 或 afxdp）
   :19000 http  :19002 tcp-echo  :19003 udp-echo  :19005 sni-tls
```

- 二进制：`cloud-node-rust`（`/root/edge-src/target/release/cloud-node-rust`），sha256 `6b25f70e5e217979…`，开发构建 `lto=false`、`codegen-units=8`（非发布产物）。
- 配置：`xdp.enabled=true, attachMode=drv, fallback=fail-start, transport.controller=edgecc`，`queues: [0..7]`，`proxy.protocols=[tcp,udp,http,https,h3]`。
- 出站腿已由 `dial-smoke` 独立验证：`ccAlgorithm=edgecc`、`ccImpl=smoltcp-edge`、`outCtHit=2077`、`dialGuardInstalled=true`、`drop=0/xskDrops=0`，minRtt 4.6ms，源端口 `10.1.10.2:43603` 位于保留拨号段内。

## 实测矩阵

| 臂 | 吞吐 | 延迟 | XDP 计数器 |
|---|---|---|---|
| kernel HTTP | ~476 rps（9521×200/20s，经 REUSEPORT 分流按 200 归因） | p50 27.7ms | 内核路径 |
| AF_XDP HTTP + 内核上游 | **983 rps**（9829×200+9824×400/20s），0 连接错误 | dialup ~9ms | packets 134514，redirect 71735，drop/mapMiss/xskDrops=0；accepted 71718，proxyStarted 9871 |
| AF_XDP HTTP + AF_XDP 上游 | ~150 rps | dialup ~99ms | redirect 18803，0 丢包；proxyStarted 1550 |
| kernel TCP echo | 528.5 cps（10569 周期，经分流按 echo 归因） | conn 6.5ms，total 28.3ms，p99 67.5ms | 内核路径 |
| AF_XDP TCP（正常 FIN 关闭） | 599.7 cps（8995 周期/15s） | conn 7.7ms，total p50 17.8ms | 报告文件丢失，客户端数据可靠 |
| AF_XDP TCP（RST 中止 churn） | **128 后卡死**（8.5 cps） | — | accepted 52791，proxyStarted 13072，**backendConnectStart 恰好=128** |
| AF_XDP 上游 TCP | **128 后卡死**（6.3 cps） | — | accepted 109829，proxyStarted 26939，backendConnect 128/128/0 |
| AF_XDP HTTPS 终结 | ~422 rps（oha keepalive，3380 响应/8s）；6.5 cps 全新握手 @c20 | TCP dialup 17.4ms；完整 TLS 周期 ~1400ms | redirect 20665，accepted 20665，proxyStarted 1724，0 丢包 |
| AF_XDP SNI 透传 | 2.2 cps @c20（33 周期，20 错误） | 握手 ~4789ms，p99 ~10s | 同上 |
| UDP 入向 | **不可测**——云防火墙全量过滤 UDP（:80/:443/:18085 实测 0 包到达 ens17） | | |
| H3/QUIC 入向 | **不可测**——同 UDP 过滤；且 `--remote` 模式下 quic 后端保持 127.0.0.1 | | |

kernel 臂说明：该机器为共享主机，另一租户节点通过 SO_REUSEPORT 组同绑 `:80`，kernel 模式流量约五五分流。HTTP 用 200-vs-404 归因、TCP 用 echo 归因（只有我方路径能到 echo 后端）。数字是我方监听者的真实数据面，但有效并发约为一半。

## 结论与发现

1. **virtio ens17 上 native drv 可用**（`prog/xdp jited`，SSH 不受影响），但必须绑定**全部 RSS 队列**——`queues:[0]` 时落到其他队列的流全部 `mapMiss`。现配置绑 0–7。
2. **真实网卡上 AF_XDP ≥ kernel**，与 veth 结论相反：HTTP 983 vs 476 rps、TCP 599 vs 528 cps。veth-drv 的 −25/−40% 衰退是 veth-native 伪影（逐包 xmit 上下文、无 NAPI 批量），不具代表性。
3. **BUG——TCP 代理在 RST 中止 churn 下精确卡在 128 个上游连接。** `MEMORY_GOVERNOR.try_admit(AdmissionClass::OriginConnect)`（tcp_proxy.rs:1497）或连接类准入在 AF_XDP 入向流被客户端 RST 中止时泄漏一个槽位：三次独立运行 `backendConnectStart` 全部恰好冻结在 128，`proxyStarted` 持续堆积（13k–27k 排队），`.110:19002` 上恰好 128 条 ESTABLISHED 残留。正常 FIN 关闭的 churn 不泄漏（8995 周期稳定）。kernel 入向 TCP 不受影响（10569 周期）——泄漏在 AF_XDP 入向流的拆除/注册路径，非共享处理器代码。复现：`dp_tcp_probe.py`（发送 → 单次读 → 立即关闭）。
4. **AF_XDP 上游腿每连接 +50~90ms**（用户态 TCP 经 ens17 拨号）且拨号串行化（实测 ~3/s）：afxdpup-http 150 vs afxdp-http 983 rps。功能正确、计数完整，但按当前实现不适合短连接 churn。
5. **云防火墙入向仅放行 TCP 22/80。** UDP 全量过滤（实测 ens17 收 0 包）。本环境无法做 UDP 与 H3/QUIC 客户端入向验证——需同 L2/VPC 客户端或调整防火墙规则。出向 UDP/afxdp 同样未被覆盖（dial-smoke 仅支持 TCP）。
6. 测试脚手架注意事项（非数据面问题）：`proxy-smoke` 无 `--report-file`（报告走 stdout）；oha 支持显式 `:80`；所有大规模"connection refused"事件均为节点到时退出后打到租户监听者——每个失败窗口都与已退出节点对应。

## 环境限制（非产品缺陷）

- 云防火墙阻断 UDP 入向——本拓扑无法验证 UDP/H3。
- kernel A/B 与租户 REUSEPORT 共享 `:80`——归因式测量，有效并发约半。
- 开发二进制（`lto=false`）——绝对数值与 fat-LTO 发布产物可能有几个百分点差异。
- IPv6 未测——本拓扑无公网 v6。

## 缺陷根因分析与修复（静态分析 + 短复现，非重跑矩阵）

第 3、4 条发现的三个性能/卡死问题已全部定位到代码层根因并修复，未再跑全量矩阵。

### 根因 1：AF_XDP TCP 精确卡 128 —— CloseWait 不传播 EOF + 终态会话不回收 + fd 限额放大

三层机制叠加，缺一不可：

1. **relay 任务泄漏（主因）**：`af_xdp_tcp_stream_read_side_closed`（`src/xdp/af_xdp/tcp_reactor.rs`）的状态集合漏掉了 `CloseWait`。对端 FIN → smoltcp 进入 CloseWait → `ingress_tx` 不释放 → `AfXdpTcpStream::poll_read` 永久 Pending → 双向 relay 任务永不退出，持有的上游 socket、`ActiveIpPermit`、`TcpConnection` 许可全部泄漏。远端会话快照实证：`state=CLOSE-WAIT, closing=false`。
2. **终态会话不回收**：proxy-started 会话被 RST 打到 `Closed`（或 TimeWait 排干）后 `session.closing` 不置位，而回收条件要求 `closing && terminal`——只能等 300s 空闲超时。pre-proxy（握手期 RST）会话同样如此。
3. **fd 限额放大器**：`memory_governor` 的 fd 派生限额 `(nofile−512)×25%`，`systemd-run` 默认 `nofile=1024` → `TcpConnection` 上限恰为 **128**。128 个泄漏的 relay 任务占满后 `try_admit` 全拒 → `backendConnectStart` 精确冻结在 128、`proxyStarted` 堆积 13k~27k、`.110` 上恰 128 条残留 ESTABLISHED——所有观测完全吻合。

修复（`src/xdp/af_xdp/tcp_reactor.rs`）：

- `CloseWait` 加入读端关闭集合——对端 FIN 即读端 EOF（内核 `recv()→0` 语义），写半独立保持开放；
- proxy-started 与 pre-proxy 会话到达 `Closed`/`TimeWait` 时立即置 `closing`，250ms 扫表回收并唤醒停驻写端（BrokenPipe）。

无静默降级：EOF 语义即正确语义；残留 ingress 数据先排空再 EOF；许可释放路径不变。

### 根因 2：AF_XDP 上游拨号 ~99ms —— 每次拨号 fork 3 个 `ip` 子进程

`resolve_outbound_route`（`src/xdp/linux.rs`）每次调用执行 `ip -j route get` + `ip -j neigh show` + `ip -j link show` 三个子进程，单次 30~90ms 纯进程开销，无缓存——RTT ~4ms 的握手只占零头。这是 afxdpup-http 150 vs afxdp-http 983 rps 差距的主因（上游腿串行化 ~3/s 也与此一致）。

修复（`src/xdp/af_xdp/dial.rs`）：`AfXdpDialRegistry` 增加有界路由缓存——TTL 5s、上限 4096 项、满时先清过期再逐最旧；TCP 与 UDP 拨号共用；**拨号超时即失效该缓存项**（超时可能意味着邻居 MAC 过期，下次重解析）。路由/邻居失败仍显式报错，不猜 L2 头、不回退内核路径。

### 根因 3：HTTPS 终结与 SNI 透传慢 —— 同一组问题的表现

- HTTPS 终结复用同一条 AF_XDP stream 通道 + Pingora TLS acceptor。keepalive 下 ~422 rps 说明已建立连接的转发不慢；全新握手 6.5 cps 主要受 relay 泄漏背景下的许可耗尽与每记录一次用户态栈往返影响。CloseWait 修复后 TLS 任务同样不再悬挂。
- SNI 透传是双向 relay（`stream_sni_passthrough_bidirectional`），对 EOF 传播最敏感：对端 FIN 不传 EOF 时任务悬挂至空闲超时；且 afxdpup 臂每连接额外 +~99ms 拨号开销。两修复直接作用于该路径。
- 代码中两处 128 字节窥视缓冲（PROXY 头/协议嗅探）与 128 连接卡死无关，属巧合。

### 修复验证

- 单元测试：`af_xdp_tcp` 相关 37 个测试全过；既有测试 `keeps_stream_read_side_open_during_half_close` 原断言"CloseWait 读端保持开放"——该断言本身编码了 bug，已修正为断言 CloseWait 必须 EOF；dial/governor 相关 53 个测试全过。
- fd 限额告警：`memory_governor` 在 fd 派生限额低于类名义下限时输出一次性 warn（含类、实际限额、nofile soft、名义下限），`nofile=1024 → TcpConnection=128` 不再是黑盒。
- **veth churn 复现验证（修复后，90s）**：FIN 半关闭 churn 1500 周期 @346/s + RST 中止 churn 1500 周期 @506/s，0 错误。报告计数器：`relayStart=3000 / relayDone=3000 / relayLeak=0`，`backendConnectStart=Ok=3000`，`sessions=0`，`drop=0 / xskDrops=0`。对比修复前同拓扑：`backendConnectOk=3696` vs `relayDone=3568`，差值恰 128 且 `sessions` 滞留——泄漏消除，终态会话在 250ms 扫表节奏内即时回收。
- **真机 ens17 drv 臂修复后验证（2025-09-18，`xdp.upstream.mode=afxdp`，75s 窗口，churn 全程在窗口内）**：
  - churn 探针从 .120 经 ~4ms WAN 打 `160.202.234.171:80`（AF_XDP 入向 + AF_XDP 上游双腿）：FIN 半关闭 250 周期 1 错误 @11.9/s；RST 中止 250 周期 0 错误 @21.9/s。
  - 计数器：`backendConnectStart=501 / Ok=501 / Fail=0`——修复前同拓扑精确冻结在 128 的现象完全消失；`relayStart=501 / relayDone=500 / relayErrors=0`（差值 1 为服务停用快照瞬间的在途任务，非泄漏）；`sessions.total=38`（26 CLOSE-WAIT 为停用瞬间在途半关闭行，有界且不持有准入许可）；`drop=0 / mapMiss=0 / xskDrops=0 / refusedAtCapacity=0`。
  - **路由缓存实测**：`/usr/bin/ip` wrapper 计数以进程内 PATH 观测子进程——501 次上游拨号共产生 66 次 `ip` 调用（22 组 route+neigh+link 解析，TTL=5s 到期重解析 + 并发 miss 少量重复）。无缓存应为 ~1503 次（501×3），**子进程开销减少 ~95.6%**。首拨冷缓存解析一次、TTL 内全命中，与实现一致。
  - 同臂另一次窗口部分错位的运行（FIN 段 47s 超出节点 60s 存活）：`backendConnectStart=489 / Ok=488 / Fail=0`，同样无 128 冻结。
- **fail-closed 契约顺带实测验证**：一次 PATH 缺 `/usr/sbin` 的运行中 `nft` 不可执行 → `ensure_dial_guard` 显式失败 → dial registry 不发布 → 全部 799 次拨号显式报 "no live AF_XDP dial registry"（`backendConnectFail=799`），**未发生任何静默内核回退**——证明缺失护栏时的显式报错路径按设计工作，且该错误路径不产生 `ip` 子进程（拨号在路由解析前拒绝）。
- 验证范围说明：veth 与真机 ens17 均已验证缺陷机制修复（128 冻结消除、relay 任务随会话终止退出、准入许可正常流转、终态会话有界回收、拨号路由缓存生效）。上述为短程缺陷复现验证，非完整性能矩阵——修复后全协议吞吐对比仍需单独一轮完整基准；churn 速率（~12/s FIN、~22/s RST @8 workers）为功能探针口径，不代表吞吐上限。

## 第二轮：断流/异常断开场景深挖（kernel 6.12.95，fix4 二进制）

拓扑不变（.120 client → .90 XDP → .110 origin），客户端 20 并发大文件下载 15s 后整体 `pkill`，观察 reactor 行为与账目归零。

### 新发现并修复的缺陷

1. **smoltcp-edge `ring_buffer.rs:374` panic（`count <= self.window()`）**：`scaled_window()` 只按 rx buffer 通告窗口，assembler 持有的乱序字节不计入；`grow_recv_buffer` 缩容只校验 buffer length 不看 assembler。断流会话残留空洞 → 空闲缩容 → 后续报文填洞撑破窗口 → `panic=abort` 整进程死亡。修复：入口裁剪到可写空间 + 缩容自守 assembler 占用，694/694 测试过（`abd924e`）。
2. **afxdp worker 空转 ~20% CPU**：`poll_raw_once()` 只在发送路径回收 TX completion——流量停止后 CQ 残留描述符让 xsk fd 永久可读，POLLIN 每轮重武装成热循环。改为 poll 入口无条件 drain（`b432106`）。
3. **reactor 热路径同步读 smaps**：perf 实锤 ~39% 线程 CPU 在 `smaps_rollup`（480MB RSS 下单次 23ms，流量驱动的按需刷新叠加多调用方）。进程级 governor 改为 `memgov-snapshot` 后台线程 250ms 周期刷新 + 2s 硬过期兜底同步路径（`cf9a712`）。
4. **`sessionsCurrent` 口径错误**：单原子被 8 个 reactor 互相覆盖（last-writer-wins）——报告显示 0 会话时实际有 20 个 FIN-WAIT-2 各持 ~1MiB buffer charge。改为 per-queue map 聚合（`cf115cd`）。
5. **FIN-WAIT-2 僵尸会话永生**：`reapable` 要求 `Closed/TimeWait`，但 FIN-WAIT-2 无协议超时——对端不发 FIN 则会话及 ~1MiB charge 永久驻留。新增 60s closing 收割期限（对齐 TCP_LINGER2），移除路径 abort socket 释放全部 permit（`cf115cd`）。
6. **`accepted` 计数器口径**：对命中已存在会话的每个报文都 +1（70278 实为收包数），改为仅新会话计数（`cf115cd`）。

### 修复后实测（fix4，同场景）

- 客户端全杀后 47s：8 个 afxdp worker 中 7 个 0% CPU，queue-0 12.5% 为垂死会话退避重传的真实发包（perf 栈：`xsk_poll → __xsk_generic_xmit` + `epoll_wait`），非自旋；
- `strace` afxdp-ens17-0 全程 **0 次 openat**——`/proc` 读取完全隔离在 `memgov-snapshot` 线程（~8% CPU，可再优化但已出热路径）；
- 到期报告：`accepted=20`（口径修正）、`sessionsCurrent=1`（聚合正确）、`tcpQueueBytes=1,081,344` = 仅剩 1 个 CLOSING 会话的 charge——19/20 FIN-WAIT-2 僵尸已被 60s 期限收割，账目随会话归零；
- 全程无 panic、无 "Can't replace"、无 XDP link 残留。

### 遗留观察项

- `memgov-snapshot` 空闲期仍以 4Hz 刷新（~8% CPU 于 480MB RSS）——可考虑无消费者时降频；
- 单客户端 IP 的流量全 hash 到 queue-0——多队列扩展依赖 RSS 分流，同源高压场景 queue-0 是单点；
- CLOSING 态收割期限 60s 期间 zombie 仍占 ~1MiB/会话——预算压力下可考虑压力自适应缩短期限。
