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

- `scripts/edge/en11_nat_probe.py`（`probe-result.json`）七阶段全过：
  - A UDP 冲突：VIP1 fwd +3 → VIP2 同 tuple ×2 全部 conflict（fwdDelta=0，
    CT 仍 1 条）→ VIP1 继续 fwd +2，绑定未动。
  - B TCP pending 冲突：VIP1 SYN 建 pending+SNAT 认领 → VIP2 同 tuple ×2
    全部 conflict，无新认领、无新 pending，归属不变。
  - C pending 过期端口释放：TTL 到期后同 tuple 再入 → 旧端口随逐出释放，
    SNAT_REV 仍 1 条（未累积孤儿）。
  - D 计费：FLOW_ACCT 中该流 `server_id=43`，rx=160B/5p、tx=31B/1p 双向齐全。
  - E CT 满晋级失败（故障注入 FAIL_CT_INSERT）：SYN→PENDING、
    SYN-ACK→PENDING_ACKED(3)，ACK 晋级失败 → pending 仍是 state=3 且
    last_seen 不变（绝对期限未被 ACK 延长）、tcpFwdMapFull+1、无 CT 项；
    清 flag 后重发 ACK → 晋级成功（CT +1、pending 移除）。
  - F pending 满插入失败（FAIL_PENDING_INSERT）：SYN → pendingLimited+1、
    SNAT_REV 无残留（端口回滚）、无 pending 项。
  - G SNAT 端口耗尽（FAIL_SNAT_ALLOC）：SYN → snatAllocFail+1、无绑定、
    无 pending——回退显式可观测。
- EN-10 探针回归全绿（重启接管 + 事件通道在新 ABI 下不变）。
- `cargo test --lib` 667 通过；`cloud-node-xdp-common` 7 通过（含 ABI
  断言与 decision 常量 pin）；集成测试 18 通过。
- eBPF 对象在 x86-build 通过 verifier 并成功 attach（T01 路径被
  EN-10/EN-11 探针覆盖）。

## 第二批改动（ABI v11）

- pending 晋级不再先污染 pending 记录：原样 insert，成功后才对 CT 副本
  置 OPEN/刷新 last_seen；失败时 pending 状态与绝对期限原封不动。
- sweeper：每 map 每轮删除上限 4096（syscall 有界、长期进度保证——下轮
  优先收集）；stale 判定改为 HashSet（消除 O(流数×stale)）；删除前重读
  last_seen 校验，扫描与删除之间的并发刷新/tuple 复用不会误删新条目；
  计费按 server_id 聚合后每轮一次 record_transfer（调用数有界于服务数）。
- XdpPendingCap.flags 故障注入位（配置 `xdp.admission.debugFailFlags`，
  测试专用、生产为 0）；`sync_pending_cap` 移到 attach 时一次写入，避免
  5s tick 覆写运行期注入的 flags。
- NatScratch +debug_flags（每包一次快照，flag 检查是普通 load）。

## 第三批改动（ABI v12，EN-06/07/13 首切片）

- EN-06 ACL 所有权：Allow 判定不再提前 XDP_PASS——白名单只跳过 block
  规则与 per-source 限流，仍须支付 dim0 未验证聚合预算，并继续走
  dispatch_local，已接管连接仍到达其 kernel/AF_XDP/NAT 所有者。
- EN-07 分层预算：dims 扩为 unverified(0)/new-flow(1)/xsk-redirect(2)/
  verified(4)/control(5)。verified 命中退还入口时的 unverified 计价并
  改记 verified 池（洪泛无法耗尽的保留额度）；control（ICMP/ND/PMTU）
  独立有界；redirect 逐包计价。所有拒绝 fail-closed 且有独立计数器。
- EN-13/14 首切片 TCP 序号锚点：准入存 expect_seq=client_isn+1；
  仅当后端 SYN-ACK 的 ackno==expect_seq 才标 PENDING_ACKED 并锚定
  expect_ack=backend_isn+1；晋级要求 client ACK seq==expect_seq，
  SNAT 流另需 ackno==expect_ack。弱观察包计数 nat_seq_rejected。
- 配置 `xdp.budget` +verifiedPps/xskRedirectPps/controlPps（默认
  8M/4M/100k pps 节点级，按 CPU 向上取整分摊，下限 1）。
- 探针 +Phase H：非 SYN-ACK 后端包保持 PENDING（state=2）、盲 ACK
  不晋级且 natSeqRejected+1、正确锚定握手正常晋级。
- en09 探针 phase E 修正：重启前清 pinned map，避免 EN-10 导入流
  污染"fresh table"断言。

## 仍存在的限制

- 并发晋级（双 CPU 同 tuple 竞争）由 insert 的 BPF_NOEXIST 与 pending
  单写者语义覆盖，未单独仪表化。
- verified 池的分类证据是"持有活跃 CT/SNAT 状态"——tuple 猜测命中
  既有流的包仍计入 verified 预算；更强的按流序号窗口属 EN-13/14 后续。
- 每服务/每队列公平维度尚未接线——listener 池（EN-16）只覆盖用户态
  准入，数据面队列级预算待 EN-05/EN-17。
- 冲突拒绝的语义是"回退用户态路径"（Ok(None)），不是丢包——与
  CT-full 回退一致；若接口无用户态监听则该连接实际上不可达，但拒绝
  是可观测的（counter + event）。
- veth/netns 证据；真实 NIC 的 multi-queue SNAT 压力面未覆盖。
- TTL/MTU：NAT 为同子网 L2 改写（next_hop_mac + XDP_TX），不递减 TTL；
  邻居代理由配置的 nextHopMac 静态指定。两项均为既有既定语义。
