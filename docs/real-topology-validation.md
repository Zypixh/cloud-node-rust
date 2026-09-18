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
- 验证范围说明：本轮为 veth-skb 拓扑（与先前本地复现同环境），验证的是缺陷机制本身；真机 ens17 drv 臂的吞吐复测与 ~99ms 拨号改善幅度需下一轮短程远端验证，尚未重测。
