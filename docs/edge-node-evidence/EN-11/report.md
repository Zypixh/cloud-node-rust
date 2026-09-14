# EN-11: NAT 正反向、SNAT 和计费

Base commit: `b4ab90e` (EN-10) + `341591c` (EN-16 slice 2)
eBPF object: `data/cloud-node-xdp-ebpf.o` sha256 `e6c3e0289bf3f0e39d109f0a189df150c5629b41f8378042d1129e5936fe406a`（ABI v10）
环境: OrbStack x86 VM, kernel 7.0.14-orbstack, netns/veth 拓扑
(en11-a VIP1=10.99.0.5 + VIP2=10.99.0.7 <-> en11-b 10.99.0.6，双 VIP 同后端)

## 交付内容

### 1. 多 VIP 同后端歧义消除（显式拒绝）

CT/pending key 为 `(client, backend, client_port, backend_port, family, proto)`，
不含 listen 地址。此前同 tuple 经不同 VIP 的二次绑定会静默改写 CT 的
`listen_addr`/`server_id`（UDP v4/v6 fwd 命中分支），VIP1 流的回包会被改绑到
VIP2 的服务身份——既破坏语义也错乱计费归属。

现所有四个命中分支（UDP v4 fwd、UDP v6 fwd、TCP v4、TCP v6 fwd CT 命中；
TCP pending 经 `pending_touch`）检查存量绑定的 `(listen_addr, listen_port)`
与包目的 `(dst, dport)` 是否一致：

- 不一致 → `nat_conflict++` + `XDP_FLOW_EVENT_REJECTED` /
  `XDP_DECISION_NAT_CONFLICT(=10)`，返回 `Ok(None)` 交给用户态路径
  （与 CT 表满一致的显式回退语义）。既有绑定与 pending 归属不被剥夺。
- `pending_touch` 返回码改用 u64 打包 `[state:8][incarnation:32][port:16]`，
  消除 sret 调用者栈指针（verifier 在该形态下报 `R11 is invalid`）。

### 2. SNAT 端口认领回滚与生命周期

- `snat_release(scratch)`：认领成功但后续 insert 失败时回滚
  `XDP_SNAT_REV` 绑定。接入全部 4 处失败路径（UDP v4/v6 fwd 的
  CT insert 失败、TCP v4/v6 fwd 的 PENDING insert 失败）——
  **map insert 失败不再泄漏端口**（此前孤儿项要等 sweeper 才发现）。
- `pending_touch` 过期逐出时同步释放该 pending 项的 SNAT 绑定
  （此前 pending 超时只删 pending，端口要孤儿到下一轮 sweep），
  并发射 `XDP_FLOW_EVENT_EXPIRED`。
- sweeper 孤儿判定收紧：`tcp_live`/`udp_live` 由 key 集合改为
  `key -> snat_port_be` 映射——绑定只有在属主流存活**且仍认领同一端口**
  时才算 live。同 tuple 复用认领新端口后，旧端口绑定被回收；
  被复用的端口（live 项端口匹配）不会被误删。

### 3. 可观测性

- `XdpCounters.nat_conflict`（ABI v9→v10，224→232B），经
  sum_percpu_counters、manager 原子量、status/`xdp dump-maps`
  的 `counters.natConflict` 透出。
- `XDP_DECISION_NAT_CONFLICT=10`（append-only，已 pin 测试）。
- `XDP_FLOW_EVENT_EXPIRED` 现在在 pending 逐出路径实际发射。

### 4. 计费核对（探针验证）

- `XDP_FLOW_ACCT` 双向记账正确：rx=客户端→后端方向，tx=回复方向
  （经 SNAT_REV 路径，CT 被回收后仍按 binding 的 server_id 记账）。
- `server_id` 归属随绑定固定——多 VIP 冲突拒绝同时保证了
  `server_id` 不会被同 tuple 的异 VIP 流量改绑。

## 验证

- `scripts/edge/en11_nat_probe.py`（`probe-result.json`）四阶段全过：
  - A UDP 冲突：VIP1 fwd +3 → VIP2 同 tuple ×2 全部 conflict（fwdDelta=0，
    CT 仍 1 条）→ VIP1 继续 fwd +2，绑定未动。
  - B TCP pending 冲突：VIP1 SYN 建 pending+SNAT 认领 → VIP2 同 tuple ×2
    全部 conflict，无新认领、无新 pending，归属不变。
  - C pending 过期端口释放：TTL 到期后同 tuple 再入 → 旧端口随逐出释放，
    SNAT_REV 仍 1 条（未累积孤儿）。
  - D 计费：FLOW_ACCT 中该流 `server_id=43`，rx=160B/5p、tx=31B/1p 双向齐全。
- EN-10 探针回归全绿（重启接管 + 事件通道在新 ABI 下不变）。
- `cargo test --lib` 667 通过；`cloud-node-xdp-common` 7 通过（含 ABI
  断言与 decision 常量 pin）；集成测试 18 通过。
- eBPF 对象在 x86-build 通过 verifier 并成功 attach（T01 路径被
  EN-10/EN-11 探针覆盖）。

## 仍存在的限制

- CT map 满 / pending 满导致的端口回滚路径无法在 netns 探针中触发
  （需灌满整张表）；已按代码路径审查 + sweeper 收紧兜底，无实测证据。
- sweeper 每周期 O(map) 扫描（既有行为，无上界恶化）；`stale` Vec 大小
  随失流数线性增长但只活在一个 sweep 周期内。
- 冲突拒绝的语义是"回退用户态路径"（Ok(None)），不是丢包——与
  CT-full 回退一致；若接口无用户态监听则该连接实际上不可达，但拒绝
  是可观测的（counter + event）。
- veth/netns 证据；真实 NIC 的 multi-queue SNAT 压力面未覆盖。
- TTL/MTU：NAT 为同子网 L2 改写（next_hop_mac + XDP_TX），不递减 TTL；
  邻居代理由配置的 nextHopMac 静态指定。两项均为既有既定语义。
