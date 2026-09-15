# R5 生命周期 + 全协议双栈矩阵验收（.120 实测）

日期：2026-09-15（UTC 系日志时间）· 主机：vps-120（2c/1GB 级，kernel-BPF 预算约 134–137MB）
二进制：`cloud-node-rust` debug build，sha256 `e3314be7…`（vps-110 构建，经内网 `10.0.160.13→10.0.160.23` 直传校验一致）。
原始日志：`xdp-netns-smoke-run8.log`（411 行，含各阶段完整 JSON）。

## 通过的验证项

| 阶段 | 证据 |
|---|---|
| doctor / dataplane 声明 | `AF_XDP proxy ports supported=5 total=5`，`localIps=2`（v4+v6） |
| 内核-BPF 预算门 | 默认表投影 ~321MB > 预算 ~134MB → `stateTables` 缺省时自动按比例缩至预算内，attach 成功（此前三次 run 分别为 321.8/149.1/152.3MB 拒绝，修复 knob 分组计费 + 单快照后通过） |
| owner-respecting reload（真换代） | `managerReplaced: true`、`bridgeSupervisorAlive: true`、reload 后 `proxyReady/tcpDataplaneReady/xskReadyQueues=1` 全部保持，redirect 计数不回退 |
| raw AF_XDP 双栈 | samples 含 `10.200.0.1:443/udp`、`10.200.0.1:9443/tcp`、`[fd00:200::1]:443/udp`、`[fd00:200::1]:9443/tcp`；`redirect=4 parseErrors=0 xskDrops=0` |
| localIps bypass | 未列入地址 `pass=4 redirect=0` —— socket 路径显式保留 |
| 应用代理矩阵 | `h3Requests=2 httpRequests=2 httpsRequests=4 quicRequests=2 sniConnections=2 tcpConnections=2 udpDatagrams=2`；`h2(10.200.0.1)=2`、`h2(fd00:200::1)=2` —— HTTP/2 双栈均经 AF_XDP |
| TCP 代理诊断 | `backendConnectOk=2 relayDone=2 relayErrors=0 ingressQueueDropped=0` |
| protect 模式生命周期 | `xdp attach` → `xdp reload`（换代）→ netns ping 连通 → `xdp detach` 干净退出；commit 阶段 link 摘除后 `bpf_link_create` EBUSY 由有界重试吸收 |
| .110 回归 | `cargo test --lib` **697 pass / 0 fail** |

## 本轮修复记录

1. **预算门在小内存节点上拒挂**：默认 stateTables 投影 ~321MB，.120 预算 ~134MB。修法不是放宽门限，而是 `stateTables` 缺省时按预算自动缩表（比例收缩 + 1024 条下限 + 同构 pin 尺寸沿用保证重启稳定 + knob 组内取最小值保证计费与 spec 一致）。显式配置永不静默收缩。
2. **快照竞态**：`auto_scale` 与 `ensure_bpf_map_budget` 原先各取一次 governor 快照，可用内存漂移导致"按旧预算缩放、被新预算拒绝"。现为 attach 单次快照贯穿。
3. **knob 组计费错配**：`aclBlocked` 等 knob 覆盖多张 per-entry 字节不同的 map，逐 map 缩放再取代表值会使真实投影超过计费总量——组内统一取最小值后投影与计费精确一致。
4. **commit 摘除 link 后 `bpf_link_create` EBUSY**：pin 移除到内核 link 销毁存在 RCU 宽限；20×50ms 有界重试，耗尽仍失败走 commit 回滚。
5. **reload smoke 此前未真正换代**（配置相同走 fast-path）：现在把 effective stateTables 物化为显式配置强制换代，并断言 `managerReplaced` 与监管器存活。

## 设计限制（如实记录）

- 自动缩表在小内存节点上把 CT/ACL 等表缩到千级条目——容量与生产默认（262k 级）不同，是有观测（warn + status 投影）的容量规划，非静默降级；大内存节点不受影响。
- 真实 NIC/多队列/zero-copy/线速验收仍需硬件环境，本次 veth+SKB 模式只覆盖软件路径正确性。
- release 工件端到端验证（安装/启动/smoke/关闭/回滚）单独记录。
