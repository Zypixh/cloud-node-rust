# 生产级边缘节点开发计划

日期：2026-09-13。范围：现有单节点生产化。基线：0ca5cbd02b11f644943b25c05cdae55bd338b69b。

设计依据：[目标架构](../docs/edge-node-production-architecture.md)。执行入口：[模型开发交接](edge-node-development-handoff.md)。

本文件包含 34 个任务包。初始全部为 TODO；本次完成的是架构和计划，不代表任何实现或验收已完成。所有源文件路径是定位入口，不是要求创建一套同名替代实现。其他工作已修复的内容应以最新代码和测试证据合并结项。

## 1. 发布门槛和依赖

| 阶段 | 主要任务 | 完成条件 | 可以声称的能力 |
|---|---|---|---|
| G0 基线与合同 | EN-00～04 | 现状、ABI 草案、测试拓扑、观测与模块边界可用 | 可复现开发基线 |
| G1 常驻基础保护 | EN-05～08、16 | 基础解析/服务作用域/聚合准入/资源上限通过 | 基础防护有界，不代表强握手验证 |
| G2 连接与传输保护 | EN-09～15、17 | 所有权、NAT、队列、验证路径及生命周期通过 | 对获证 PathProfile 声明防护能力 |
| G3 代理与缓存 | EN-18～24 | 协议一致性、隔离、回源、缓存和持久化通过 | 正确且可限额的应用数据面 |
| G4 发布与故障恢复 | EN-25～29 | 代次发布、LKG、管理组件、观测和回滚通过 | 可运营候选版本 |
| G5 运行资格 | EN-30～33 | 故障矩阵、实机容量、长跑、灰度与报告全部通过 | 仅对证据覆盖的配置授予生产资格 |

阶段表示门槛，不是强制把所有工作串行化。EN-16、EN-18～24 可以在 G0 合同稳定后与数据包工作并行；EN-25～29 按任务依赖进入。发布只能沿门槛推进。

```mermaid
flowchart LR
    B[G0 基线与合同] --> R[G1 常驻保护与预算]
    R --> F[G2 状态和传输]
    B --> C[G3 代理和缓存]
    R --> C
    F --> L[G4 发布与恢复]
    C --> L
    L --> Q[G5 实机与运行资格]
```

## 2. 统一完成定义

每个任务都交付：问题与最终行为、实现、必要回归测试、配置/ABI/指标影响、验证记录、回退方式。状态只允许 TODO、IN_PROGRESS、IMPLEMENTED、VERIFIED；外部条件缺失单列 prerequisite，不把未运行的 Linux/网卡测试写为 VERIFIED。

记录放在拟建的 docs/edge-node-evidence/EN-xx/ 目录：manifest.json、report.md、必要原始结果。记录 start/end commit、dirty 状态、patch 摘要、命令与退出码、OS/内核/驱动/固件、CPU/NUMA/队列、cgroup、attach/copy 模式、配置摘要、生成器与被测机、采样方式、重复次数、已知限制。路径属于计划产物，当前尚未生成。

commit 与 patch 摘要指被测代码状态；未提交代码也可以验证，但必须记录其 diff 摘要。证据文件不计算进自身摘要，后补报告不能把未测试的新代码归入旧测试结果。

性能报告同时保留吞吐、P50/P95/P99、成功率、合法误伤率、资源、drop 原因、回源量与恢复时间。禁止只贴截图或最佳单次数字；禁止将发送端瓶颈报告成 XDP 上限；禁止通过关闭防护、缓存语义或计费来达标。

回退只能回到仍满足基础安全不变量的版本/策略。下文的 feature gate、generation 和 drain 是待实现机制，不能假装当前 CLI 已支持。没有安全退路时维持旧运行代并拒绝新发布，不能直接清 pin 或全局 PASS。

### 2.1 初始状态表

| ID | 名称 | 依赖 | 规模 | 状态 |
|---|---|---|---|---|
| EN-00 | 基线盘点与支持矩阵 | 无 | M | VERIFIED（证据 docs/edge-node-evidence/EN-00；待独立审阅） |
| EN-01 | 共享合同与资源账本规范 | EN-00 | L | TODO |
| EN-02 | 分层测试与证据工具 | EN-00 | L | TODO |
| EN-03 | 正确低成本的基础观测 | EN-01、EN-02 | M | TODO |
| EN-04 | XDP 模块边界整理 | EN-01、EN-02 | M | TODO |
| EN-05 | 有界解析与分片策略 | EN-04 | L | TODO |
| EN-06 | 独立受保护服务与路径策略 | EN-01、EN-04、EN-05 | L | TODO |
| EN-07 | 聚合预算与每路径容量保护 | EN-03、EN-06 | L | TODO |
| EN-08 | 源地址公平性与有界状态维护 | EN-07 | M | TODO |
| EN-09 | 准入状态机与 map 生命周期 | EN-06、EN-07 | L | TODO |
| EN-10 | 连接所有者反馈与存量流 | EN-09、EN-12 | L | TODO |
| EN-11 | NAT 正反向、SNAT 和计费 | EN-07、EN-09、EN-16 | L | TODO |
| EN-12 | AF_XDP 队列正确性与预算 | EN-04、EN-06、EN-07、EN-16 | L | TODO |
| EN-13 | TCP 无状态验证可行性与 ADR | EN-09、EN-12 | L | TODO |
| EN-14 | 获选 TCP 强验证实现 | EN-10、EN-11、EN-13 | L | TODO |
| EN-15 | QUIC Retry、迁移与透传边界 | EN-09、EN-12、EN-16 | L | TODO |
| EN-16 | 扩展统一资源治理 | EN-01、EN-02 | L | TODO |
| EN-17 | 用户态传输调度与拷贝优化 | EN-10、EN-12、EN-16 | L | TODO |
| EN-18 | 协议、客户身份与证书边界 | EN-01、EN-16 | L | TODO |
| EN-19 | 有成本上限的 WAF | EN-16、EN-18 | L | TODO |
| EN-20 | 回源隔离与重试预算 | EN-16、EN-18 | L | TODO |
| EN-21 | 缓存身份和 HTTP 语义 | EN-18 | L | TODO |
| EN-22 | 有界 fill、读取与工作合并 | EN-16、EN-20、EN-21 | L | TODO |
| EN-23 | purge 一致性与持久失效 | EN-21、EN-22 | L | TODO |
| EN-24 | 缓存崩溃恢复与损坏隔离 | EN-21、EN-22、EN-23 | L | TODO |
| EN-25 | 跨组件代次发布 | EN-06、EN-10、EN-18、EN-21、EN-23 | L | TODO |
| EN-26 | LKG、本地管理和控制任务 | EN-25 | L | TODO |
| EN-27 | 生命周期、排空与特权边界 | EN-06、EN-10、EN-12、EN-25、EN-26 | L | TODO |
| EN-28 | 完整观测、审计与计费交付 | EN-03、EN-16、EN-26 | L | TODO |
| EN-29 | 可验证发布与 ABI 回滚 | EN-04、EN-25、EN-27 | L | TODO |
| EN-30 | 集成故障与兼容矩阵 | EN-08、EN-11、EN-14、EN-15、EN-17、EN-19、EN-20、EN-24、EN-26、EN-27、EN-28、EN-29 | L | TODO |
| EN-31 | 实机容量与长期稳定性 | EN-30 | L | TODO |
| EN-32 | 灰度与运行演练 | EN-31 | M | TODO |
| EN-33 | 运行资格和文档闭合 | EN-32 | M | TODO |

S/M/L 表示相对实现与验证复杂度，不是工期承诺。L 任务必须拆成小 PR，但所有子项和验收结束后才能标记 VERIFIED。日历排期在 EN-00 确定测试机器、开发人数和协议范围后生成，不能用模型 token 量估算生产化工期。

## 3. 基线与合同任务卡

### EN-00 — 基线盘点与支持矩阵

- 范围：Cargo/build.rs、docs、tasks、src/xdp.rs、主要协议/cache/governor/config 入口；只做基线盘点和必要验证，不顺手重构。
- 交付：当前 commit、构建工具链、已有测试、已实现/未验证/缺失清单；真实生产目标的 NIC/内核/CPU/NUMA/cgroup/MTU/协议/对象和连接规模。无实际机器时保留为待测输入。
- 重点：复核架构列出的八类风险；区分当前代码、历史压测和旧方案。确认 XDP/AF_XDP、RKE2 和 socket 各自的部署边界；核对 Quinn 锁定 API。
- 验收：每个现状结论有源符号/commit 或测试证据；T18 支持矩阵各项标注证据等级；至少给出当前能运行的验证命令。
- 回退：仅记录，不改变运行配置；历史文档先标注差异，不能删除已有决策证据。

### EN-01 — 共享合同与资源账本规范

- 范围：cloud-node-xdp-common、runtime_mode、config/compiled、memory_governor 的接口定义与设计测试。
- 交付：ServiceIdentity、PathProfile、Generation、FlowKey/FlowRecord/FlowEvent、BudgetSnapshot、DecisionReason；固定 BPF ABI、端序、schema、容量单位和 metric 标签规则。
- 重点：listener 与 tenant 的识别阶段；owner_epoch 与 flow_incarnation；原连接与 NAT 后端 tuple；KERNEL/AFXDP/NAT 路径状态语义。
- 验收：I01～I15 有责任模块；ABI 尺寸/版本断言、序列化兼容样例；给出 map/UMEM/worker 总预算计算；禁止仅定义空 trait 不给接入规则。
- 回退：兼容 adapter 和旧接口保留；合同变化需同步所有消费者，不以默认值掩盖不兼容。

### EN-02 — 分层测试与证据工具

- 范围：scripts/xdp-netns-smoke.sh、scripts/perf、src/bin/bench-*、CI 和拟建的测试 fixture/证据工具。
- 交付：可重放报文语料、netns 双端观察、混合合法/异常流量工具、统一 JSON 结果；eBPF 的实际执行测试不能只用 Rust 镜像函数代替。
- 验收：为 T01～T18 建立可追踪测试入口/前置环境/断言；失败退出码传播；记录实际加载的 BPF 摘要、发送速率与接收数量；有单机功能和独立发包机容量两种拓扑。
- 回退：测试使用独立 namespace/缓存目录/配置，不修改现有公共接口或生产网卡；清理只能针对本轮创建的资源。

### EN-03 — 正确低成本的基础观测

- 范围：eBPF counters、共享 ABI、src/xdp.rs 聚合、pipeline_metrics。
- 交付：PerCpuArray 计数与聚合；区分 packet/action/parse/terminal drop/redirect attempt/XSK delivery failure；tail-call 的终结计数完整。
- 验收：T04/T06/T16，多 CPU 发包时计数不因普通读改写丢失；明确采样和交付差异；旧 pin 迁移可预演；观测成本有基线。
- 回退：兼容读取旧计数 ABI或拒绝不兼容加载，不通过清空连接 map 迁移计数器。

### EN-04 — XDP 模块边界整理

- 范围：src/xdp.rs 与 eBPF 主文件；建议逐步分出 policy、loader/maps、queue、tcp_reactor、bridge、stats，而不是立即新建多个 crate。
- 交付：保持公共入口兼容的小步拆分，给后续模型提供互不重叠的文件所有权；eBPF tail-call 和栈边界保留。
- 验收：既有 af_xdp/netns/protocol smoke 不变；无行为与性能调整混入；编译产物符号和加载逻辑保持兼容。
- 回退：可单独 revert；未完成拆分前，所有 src/xdp.rs 修改由一个集成者串行完成。

## 4. 包处理与状态任务卡

### EN-05 — 有界解析与分片策略

- 范围：eBPF parser、AF_XDP parser、共享 verdict、报文语料。
- 交付：MALFORMED/UNSUPPORTED/FRAGMENTED/CONTROL/SUPPORTED；长度验证、flags、扩展头和 VLAN 上限；按 VIP/安全域的完整分片策略；必要 ICMPv6/PMTU 合同。
- 验收：T01/T18 覆盖真实 eBPF 和用户态解析差异；合法 ECN/options/声明支持的 TFO 不误伤；首片不得单独创造可信 L4 流；无越界和 verifier 失败。
- 回退：按服务关闭新增严格策略但保留确定非法边界检查；不能恢复所有错误统一 PASS。

### EN-06 — 独立受保护服务与路径策略

- 范围：ProtectedServices、ACL、proxy port/XSK readiness 同步、runtime 配置。
- 交付：防护作用域与 redirect 开关独立；明确白名单优先级但不隐式绕过硬预算；方向识别；observe/protect/proxy 一致性；候选路径 readiness。
- 验收：T01/T08/T14：XSK 关闭后基础防护仍在；白名单不改变传输所有者；非目标管理流量和合法回包不误伤；同端口不同 VIP 配置无串扰。
- 回退：旧 schema 适配到显式策略；回退不清空受保护服务。跨组件完整代次切换由 EN-25 完成。

### EN-07 — 聚合预算与每路径容量保护

- 范围：eBPF limiter、budget config、XSK/NAT/PASS 各处理分支。
- 交付：建表前未验证/新状态预算、服务和接口预算、已验证保留池、最终每队列/后端 PPS/BPS、挑战响应预算；整数与单位规则。
- 验收：T02/T04：拒绝发生在源桶/CT/SNAT 创建前；重复同 tuple 不绕过处理预算；CPU/队列数变化总配额不倍增；Normal 有基础上限；用户态反馈停止仍有保护。
- 回退：保留已验证的静态整机限额，关闭可选自适应；不存在“除到 0 变关闭”的路径。

### EN-08 — 源地址公平性与有界状态维护

- 范围：XDP_RATE 类状态、GC、配置同步、前缀公平性。
- 交付：TCP/UDP 分桶、期限/回收、满表行为、并发更新规则；IPv4/IPv6 prefix 的可配置公平性；有界 GC 工作量。
- 验收：T02/T03/T04：随机源 churn 不导致永久失去限制；源桶满时聚合预算继续；NAT 出口合法样本误伤符合目标；各种 windowMs 正确换算。
- 回退：关闭可选 per-source/prefix 精细控制，保留聚合防护；不把近似计数描述成精确配额。

### EN-09 — 准入状态机与 map 生命周期

- 范围：PendingFlows/ValidatedFlows、shared ABI、过期与 GC。
- 交付：绝对 pending 期限、可信晋级条件、关闭状态、owner epoch/incarnation；临时/权威表隔离；容量和 map migration 合同。
- 验收：T02/T04/T08：任意命中不延长 pending；旧事件不覆盖重用 tuple；无状态/过期/旧 owner 不获可信；权威表满不随机驱逐正常流；lookup 即验证期限。
- 回退：只停止新接管，保留已绑定流；不能在无导入方案时对旧内核流开启 strict miss drop。

### EN-10 — 连接所有者反馈与存量流

- 范围：smoltcp reactor、内核 socket 生命周期接入、NAT 反馈与 FlowEvent 发布。
- 交付：实际握手/地址验证驱动晋级；关闭和拒绝回收；启动导入或分代接管；事件丢失和满队列的保守策略。
- 验收：T02/T05/T08：第三 ACK 后首批数据不被同步空窗误杀；reload 不切断已导入连接；未知流不被轻易“学习”为可信；旧 worker 无法续租新流。
- 回退：绑定既有 owner，停止新的严格接管；未实现权威桥接的 KERNEL 路径仅保留受限协议栈验证，不能宣称已完成严格 CT 防护。

### EN-11 — NAT 正反向、SNAT 和计费

- 范围：NAT handlers、CT/reverse maps、计费聚合和 sweeper。
- 交付：半开超时、唯一服务绑定、端口认领回滚和 incarnation；TTL/MTU/checksum/neighbor 策略；有界且避免 O(F×stale) 的回收；计费维度正确。
- 验收：T04/T05/T08/T12：多 VIP 同后端歧义被拒绝或消除；map insert 失败不泄漏端口；旧 sweep 不误删复用端口；端口满不挤爆代理；双向字节与服务归属可核对。
- 回退：按服务停止新 NAT 流并排空既有绑定；不能直接清空 CT 改走 socket；计费 map 迁移需独立计划。

### EN-12 — AF_XDP 队列正确性与预算

- 范围：queue、UMEM、XSK map、DCID 路由、worker 启动与队列状态。
- 交付：同网卡/同 RX 队列 redirect；QUIC 在原队列接收后有界转交 owner；fill/need_wakeup/TX completion 所有权；真实 copy/zero-copy 探测；队列预算和 worker 租约。
- 验收：T03/T06/T08/T18：跨队列 CID 不丢入不匹配 XSK；buffer 不重复提交；fill 饥饿可恢复；增加队列不复制整机内存/会话配额；socket ready 不等于 worker 可处理。
- 回退：停止新导流并保留旧 owner 排空；硬故障按服务故障合同执行，不随机逐包 PASS。

### EN-13 — TCP 无状态验证可行性与 ADR

- 范围：kernel_syn_defense、XDP cookie helpers、smoltcp 所需接口和 NAT 握手实验。
- 交付：内核、NAT、AF_XDP 三条路径的协议序列图与可运行最小验证；选择握手所有者和状态导入/序号处理方案；记录内核能力与 nft SYNPROXY 交互。
- 验收：T05 小规模双端抓包证明 SYN→cookie→ACK→应用数据正确；不只验证 cookie 数学正确；MSS/window/timestamp/ECN/重传与第三 ACK 数据的实施方案可检验。
- 回退：实验保持关闭，既有有界状态保护运行。此任务可完成 ADR，但不能替 EN-14 声称完整防护已实现。

### EN-14 — 获选 TCP 强验证实现

- 范围：EN-13 选定的握手验证与状态所有者接入，服务级能力配置。
- 交付：无状态挑战到完整传输的端到端路径、密钥/期限/回程验证、响应预算、切换规则；每条现有 TCP 承载明确是强验证完成还是仅有界准入。
- 验收：T02/T05/T08：随机源 SYN 不分配昂贵会话；有效客户端应用字节正确；不与内核 SYNPROXY 重复挑战；压力切换不使存量流失效；获证 profile 满足混合压力门槛。
- 回退：停止新强验证接管并排空相应流，继续基础准入；不能将未实现路径标成强验证，也不能静默强制全服务换承载。

### EN-15 — QUIC Retry、迁移与透传边界

- 范围：quic_udp_demux、http3_proxy_manager、quic_transport、AF_XDP QUIC 适配。
- 交付：使用锁定 Quinn Incoming API 的终止型 Retry；正确检查可 Retry/已验证状态；pending/reassembly/响应预算；token 轮换、NAT rebinding、CID 路由；透传不注入自定义 Retry。
- 验收：T03/T06/T07：伪造 Initial 状态有界；有效 Retry 无循环；H3 和 @quic 共享端口正确；合法迁移不因 tuple 变化被杀；小包/畸形 CID 不获得可信状态。
- 回退：按服务回到有界无 Retry 模式并声明较低防护能力；保持地址验证和防放大约束，不为通过测试降低这些要求。

## 5. 资源、代理和缓存任务卡

### EN-16 — 扩展统一资源治理

- 范围：memory_governor、l4_defense、resource_budget、所有 admission/queue 消费者。
- 交付：BPF/UMEM/kernel/heap/FD/字节/CPU/磁盘/spool 账本；node→listener/tenant/service→worker 配额；控制面与已验证流 reserve；迟滞与恢复。
- 验收：T04/T07/T12/T17：多队列不能各占整机预算；未识别租户流量进入 listener 池；取消/超时释放 permit；所有增长型结构列出上限和满额动作；物理观测与逻辑账目不双算。
- 回退：保留硬上限与节点 reserve，仅撤回新自适应策略；不能回退为流量驱动无界任务。

### EN-17 — 用户态传输调度与拷贝优化

- 范围：AF_XDP reactor/bridge、TCP stream、UDP queue、相关 bench。
- 交付：分阶段测量拷贝/分配/全会话扫描，有限每轮工作预算、活跃会话推进/定时器调度；必要时调整 buffer 所有权减少拷贝。
- 验收：T05/T06/T07/T17：高会话数下空闲扫描不淹没数据面；RX 洪水时 TX/定时器/其他任务仍前进；半关闭、backpressure、乱序重传和字节一致性不变；性能报告包含多连接而非只固定 tuple。
- 回退：按优化点回退，不撤销 EN-12/16 的正确性和上限；不未经测试修改 vendored 协议栈内部状态。

### EN-18 — 协议、客户身份与证书边界

- 范围：client_ip/proxy_protocol、HTTP/TCP/H3 manager、ssl、协议转换。
- 交付：明确可信代理范围，原 peer 与解析客户地址分离；Host/authority/SNI 一致合同；framing 与 H1/H2/H3 转换语料；证书授权/轮换/ALPN/OCSP；0-RTT 副作用策略。
- 验收：T09：歧义请求不可在 WAF/缓存/源站间获得不同解释；公网与非授权私网 PROXY/XFF 不能伪造身份；共享 443 和既有 gRPC/WebSocket/SNI/QUIC 能力回归；坏证书不替换旧证书。
- 回退：保留旧有效证书/配置代；兼容例外必须按服务声明并可观测，不全局放松解析或身份信任。

### EN-19 — 有成本上限的 WAF

- 范围：firewall/compiled/matcher/verifier/state、body inspection、challenge。
- 交付：编译时规则成本与数量约束、输入/解压/深度/队列预算；mandatory 与 best-effort 失败动作；作用域和过期清晰的自动封禁；有界 reason 指标。
- 验收：T07/T09/T12/T17：恶意规则/输入不占满 reactor；观察模式只改变策略动作；通用状态表满时节点聚合保护仍有效；合法语料误伤率和开销有记录；源失败不产生攻击封禁。
- 回退：回到上一个已编译策略代；不能用跳过 mandatory 检查、无记录 fail-open 达到性能目标。

### EN-20 — 回源隔离与重试预算

- 范围：lb_factory、origin_state、origin_h3_pool、proxy upstream、TCP/UDP origin。
- 交付：完整 pool key、TLS/租户隔离、DNS 最终地址策略；总 deadline、并发/排队/重试预算、可重放条件、失败熔断和限量恢复探测；父节点失败策略。
- 验收：T09/T13/T17：非幂等请求不因自动重试重复执行；TLS 策略不兼容连接不复用；全源失败后任务有界；合法 HIT 不被回源风暴拖垮；恢复无同时重连风暴。
- 回退：撤回新调度算法，保留重试与资源上限；不绕过证书验证或地址授权。

### EN-21 — 缓存身份和 HTTP 语义

- 范围：cache/compiled/matching/partial、cache_hybrid、proxy cache callbacks。
- 交付：版本化 cache key、服务隔离、Vary/Auth/freshness、HEAD/Range/304/If-Range、压缩/WebP 与 ETag/length 一致性；旧 namespace 迁移规则。
- 验收：T09/T10：相同 URL 不跨租户泄漏；表示不同不混用；H1/H2/H3 一致；不支持的安全组合受控 bypass cache；既有配置优先级不变。
- 回退：使用旧 key namespace 的独立配置选择或冷缓存新 namespace；不能把不同格式的旧对象误读成新对象。

### EN-22 — 有界 fill、读取与工作合并

- 范围：cache_hybrid、cache/process_lock、memory governor admission、warmup/read/write。
- 交付：同 key miss 合并、有界等待者、流式大对象、磁盘 IO/变换预算、取消和错误清理；缓存失败时受控回源。
- 验收：T10/T12/T13：热点单 key 不产生无限 origin；取消不泄漏临时文件/锁/字节 permit；磁盘慢时其他服务和 HIT 可进展；大文件内存与并发受限。
- 回退：关闭可选合并或晋升优化，保留 fill/IO/回源预算和已有一致性屏障。

### EN-23 — purge 一致性与持久失效

- 范围：cache purge_barrier/process_lock、metadata、RPC/cluster purge adapter。
- 交付：operation_id、scope、epoch、幂等状态；成功 ACK 线性化定义；旧 fill fence；重启可恢复的 tombstone/epoch；精确、前缀、tag/host/全量失效的能力表。
- 验收：T10/T11/T14：purge 与旧 fill/读取/取消/重复消息竞争不复活对象；ACK 后重启仍失效；多进程共享缓存一致；未支持的方法明确失败，不能假 ACK。
- 回退：保留已经提交的失效 epoch；回滚不能移除防复活记录。若新版本格式不可逆，先限制升级而非假称可回滚。

### EN-24 — 缓存崩溃恢复与损坏隔离

- 范围：HybridStorage、Mace metadata、缓存文件、启动恢复/janitor。
- 交付：temp/body/metadata 发布顺序、必要同步、校验、孤儿与损坏对象处理；有界启动恢复；缓存与控制/计费数据的不同持久化级别。
- 验收：T11/T12/T15：在每个发布阶段 kill/故障注入后重开，无错误 HIT；磁盘 full/read-only/slow/corrupt 不导致无界 RSS；控制记录不被缓存回收删除。
- 回退：隔离有问题 namespace/对象，保留旧有效索引或受控 MISS；不直接删除全盘生产缓存作为默认修复。

## 6. 发布、恢复与观测任务卡

### EN-25 — 跨组件代次发布

- 范围：config/config_apply/compiled、ssl、listener、XDP maps 与 policy 发布。
- 交付：NodeGeneration、prepare/readiness/commit/retire；一次请求固定计划；XDP 与用户态双代共存；每包固定 tail-call generation；紧急撤销层；构建内存峰值限制。
- 验收：T08/T14：各准备阶段失败旧代仍服务；新路由不配旧证书/错误 XSK；快速多次更新不无限保留旧代；非法配置不提交；存量连接 owner 不随请求级配置换代改变。
- 回退：按代次恢复选择点并保留必要消费者；不承诺跨 BPF/用户态单条原子指令实现事务。

### EN-26 — LKG、本地管理和控制任务

- 范围：rpc、config persistence、local admin、main 生命周期。
- 交付：最后成功代的完整性/兼容/有效性验证；远端版本到本地代次适配；乱序/重复任务防重放、限额/取消/超时；本地 Unix socket 或受保护入口。
- 验收：T12/T14：控制面断连已有有效配置服务；坏 LKG/过期证书不能无条件启用；重复 purge/预热不无限执行；未鉴权管理操作被拒绝；现有 RPC payload 兼容。
- 回退：继续旧有效 LKG/控制适配；不要求先开发新全球控制面才能完成节点功能。

### EN-27 — 生命周期、排空与特权边界

- 范围：XDP loader/maps/leases、worker、main/systemd 管理逻辑。
- 交付：独立于代理 worker 的基础保护所有权；最小特权管理组件；worker 租约；按服务 drain 和备用承载；管理组件/worker 各自崩溃策略。
- 验收：T06/T08/T12/T15：代理死时基础保护仍执行；死 XSK 不被永久导流；新连接受控切换，旧连接实际损失有报告；管理入口在压力下可用；退出释放 owned 资源而不误删别的服务 attachment。
- 回退：保留上一套管理者与兼容 BPF；回退前确认所有权，不能两个管理者竞争 attachment。

### EN-28 — 完整观测、审计与计费交付

- 范围：pipeline_metrics、metrics、logging/log_uploader、XDP status、local monitor、RPC stats。
- 交付：按架构第 10 节补齐关联 ID、指标与 reason；有界高基数/日志/spool；计费重试/去重与已知误差；liveness/readiness/degraded 分离。
- 验收：T12/T16/T17：采集器离线不阻塞代理；spool 满动作明确；每层 drop/准入/交付可对账；用户输入不能造成无限标签；关键事件与秘密脱敏测试。
- 回退：减少可选维度与采样量，保留硬保护/交付失败/丢失计数；远端无法去重时明确端到端限制。

### EN-29 — 可验证发布与 ABI 回滚

- 范围：build.rs、xtask、CI/release、安装/升级、pin 与存储迁移工具。
- 交付：二进制/eBPF/map/config/storage 兼容 manifest；正式构建不隐式嵌入旧对象；CPU 基线、跨架构产物、校验/签名验证、依赖与 vendored 补丁清单；可预演升级/回滚。
- 验收：T08/T15/T18：错 BPF、错 ABI、错 CPU、签名/校验失败被拒绝；升级中断可恢复；不兼容连接状态先排空/转换；缓存和失效状态回滚不复活旧内容。
- 回退：已验证旧组合；状态不可逆时拒绝不安全回滚并说明限制，不能靠删除 pin 或元数据制造“成功”。

## 7. 集成与运行资格任务卡

### EN-30 — 集成故障与兼容矩阵

- 范围：全部选定生产 PathProfile；T01～T18 的功能/故障子集与 CI/nightly。
- 交付：跨模块集成结果；攻击+reload、purge+fill+disk fault、worker death+新连接、控制断连+证书变化等组合故障。
- 验收：I01～I15 全部映射到实际测试证据；对无法运行的硬件 profile 保持未认证；新旧配置样例和全部现有协议至少有一个获选正确承载；未知失败不得归类为网络偶发后忽略。
- 回退：退回已通过门槛的版本；修复复现后再重跑受影响矩阵，不无理由反复重跑全仓测试。

### EN-31 — 实机容量与长期稳定性

- 范围：独立发包机、真实 virtio/物理 NIC、x86_64/aarch64 候选、混合租户场景。
- 交付：每个 PathProfile 的容量曲线、资源单价、瓶颈、工作负载/队列/MTU 适用范围；24h 压力和 72h 稳态报告。
- 验收：T17/T18 及架构第 12 节门槛；记录每租户合法成功率、误伤、P99、攻击实际入站、恢复、预算趋稳；至少三次短容量重复，长跑保留原始时序。
- 回退：降低获证容量或撤销某 profile 的生产资格必须显式记录；不能缩小测试范围后仍保留旧容量宣传。

### EN-32 — 灰度与运行演练

- 范围：隔离 staging 与实际发布流程；不由文档自动触发生产变更。
- 交付：容量预检、升级/排空/回滚 runbook，控制面失联、磁盘满、worker 故障处置；灰度观察指标、停止条件和责任分工。
- 验收：staging 完成演练后才进入获授权的 canary；先单服务/小范围再扩展，证据覆盖至少一次完整升级和回滚；外部探针验证实际业务而非只看进程存活。
- 回退：按 EN-29 兼容组合操作；明确哪些长连接不能无损迁移及最大排空时间。

### EN-33 — 运行资格和文档闭合

- 范围：docs/README、architecture/runtime/xdp/operations、历史计划差异、证据索引和发布说明。
- 交付：本节点能力清单、每 profile 资格/容量、已知限制、未完成能力、运行参数与告警；将本目标设计中的已实现部分链接到当前维护文档。
- 验收：每个 VERIFIED 有 commit+证据；未测目标不宣传支持；历史 Retry/内核版本/默认值等错误已标注或修正；用户可从一份入口文档完成部署前检查和故障定位。
- 回退：文档与实际版本匹配，旧版本说明保留；不得把本次计划文件当成实施完成证明。

## 8. 多模型开发的集成规则

建议职责：数据包与 BPF、传输与 AF_XDP、代理安全与回源、缓存与存储、配置发布与运行、独立验证。分工是交接建议，本任务没有启动或向其他模型发送开发任务。

1. 一个集成者维护 EN-01 合同；其他模型不得私自扩展共享 ABI 或修改既定失败语义。
2. EN-04 前，src/xdp.rs 及 eBPF main.rs 同时只允许一个写入任务。拆分后按文件集合分配，仍共同修改的 runtime_mode/config/governor 由集成者协调。
3. 每个开发分支从已包含依赖的基线创建，默认使用 codex/en-xx-主题；交付目标是可独立审阅的小 PR，不把一整个阶段堆成一个 diff。
4. 状态机、解析、失效/持久化和 ABI 更改必须由另一轮独立审阅检查反例，不能只依据实现模型的自测描述。
5. 性能优化与语义改变分 PR；涉及 vendored Pingora/smoltcp 能力时先确认源码归属和维护方式，提交最小补丁与上游差异说明。
6. 遇到缺失硬件可推进不依赖硬件的实现与测试，保留外部验收条件；不得编造运行结果或凭文档推测 native/zero-copy 已生效。
7. 新字段保留旧 payload 兼容；新运行能力必须在 status/doctor 中可解释。禁止添加读取不到、写入不生效的装饰性配置。

## 9. 第一轮建议执行顺序

先执行 EN-00；随后 EN-01 与 EN-02 可在不重叠文件上推进；合同确认后完成 EN-03/04，并启动 EN-16。第一批行为变更是 EN-05/06/07/08，先建立长期有效的基础保护。

不要第一轮就新增一个“tuple 命中直接放行”的 XDP_PROXY_CT。EN-09 的前置条件是服务作用域和建表前聚合预算已经就位；TCP cookie 必须经过 EN-13 的端到端接口验证再进入 EN-14。

完成 G1 后，可并行推进 G2 与 G3。G4 必须集成真实的旧/新代、状态所有者和缓存失效合同；G5 的实机与长期运行是发布条件，不是可选补充。
