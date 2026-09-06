# SNI 断流、连接统计与内存修复方案

日期：2026-09-05。基线：94eb6a1 / v1.2.5。目标节点：64.204.49.107。

本次交付是诊断与实施方案，尚未修改 Rust 源码、部署参数或生产进程。
证据见 [断流审计](/Users/moying/Documents/project/cloud-node-rust/tasks/sni-runtime-audit-2026-09-05.md) 和 [内存分析](/Users/moying/Documents/project/cloud-node-rust/tasks/sni-memory-analysis-2026-09-05.md)。
逐项执行与验收使用 [任务清单](/Users/moying/Documents/project/cloud-node-rust/tasks/sni-memory-repair-todo-2026-09-05.md)。

## 1. 目标与首批交付

首批修复必须同时满足：预算收缩和配置更新不再取消正常 SNI 长连接；所有失败/取消路径归还活动计数；Mace 大额常驻分配有明确的小内存规格；旧数据库能正常打开并保留原有数据。

不能只把 Critical 阈值调低或取消准入。前者掩盖主要分配问题，后者可能把断流问题变成真正的资源耗尽。也不能只降低后台显示值，必须修复其生命周期。

| 优先级 | 任务 | 首要结果 |
| --- | --- | --- |
| P1，首批 | T01 长连接保护与关闭原因 | 常规回收取消健康隧道的次数为 0 |
| P1，首批 | T02 SNI 指标 RAII | 失败、取消、热更新后计数回到正确基线 |
| P1，首批 | T03 真实压力与回收调度 | 不再用扣 reserve 的预算触发破坏性动作 |
| P1，首批 | T04 内存观测与启动分配预算 | 数据库、GeoIP 和未归属内存可见 |
| P1，首批 | T05 Mace 参数与旧库兼容 | WAL 候选从 256 MiB 降至 32 MiB |
| P1，第二批 | T06 配置去重；T07 原子发布与启停 | 重复更新不反复重建；更新没有空路由窗口 |
| P1，第二批 | T08 上报队列与存储背压 | 回收不静默丢统计，慢盘不无限积压 |
| P2 | T09 GeoIP；T10 历史清理 | 降低额外常驻和长期增长 |
| P2 | T11 TCP 半关闭；T12 连接口径迁移 | 完整响应、明确 transport/request 统计 |
| 发布门槛 | T13 集成、压测与灰度 | 正确性、驻留内存、恢复能力一起达标 |

## 2. 必须保持的不变量

1. 一个已经接受的连接，其 socket、registry guard、admission permit 和指标 guard 必须分别只有一个明确 owner；future 取消也执行同步 Drop 清理。
2. 常规内存回收只清可重建、可丢弃的缓存；未发送的统计不是可丢弃缓存。
3. 可分配预算不足可以拒绝新分配，但不能因此关闭健康存量隧道。显式管理关闭和安全拦截必须携带自己的原因与范围。
4. 压力采样、动作调度和资源分配分开；读取快照不在请求线程内同步触发复杂全局回收。
5. 配置代完整发布后才释放上一代 owner。新代准备失败或超预算时继续使用最后一个有效版本。
6. 数据库重开使用兼容参数；调缓存参数不改变统计 key、值编码或已存数据的意义。
7. 所有容量都标明是估算 bytes、分配 capacity、resident pages 还是 entries；共享内存不重复计费。

## 3. 第一阶段：停止周期断流，修正统计

### T01：分离缓存回收与连接取消

主要文件：`src/memory_reclaim.rs`、`src/l4_connection_registry.rs`、`src/tcp_proxy.rs`。

- 从 High/Critical 普通回收路径移除 `drain_sni_limited(8/32)`。配置 prepare、apply、周期回收均不得调用业务连接淘汰。
- registry 的取消消息由 bool 演进为有原因的内部类型，区分防御封禁、管理关闭、服务退出及明确启用的空闲回收。沿用现有 watch/owner 结构，逐一迁移生产者和消费者。
- 结束事件输出原因、阶段、持续时间、双向 bytes 和最近活动年龄；采用聚合计数及限频日志，不为每个正常连接写 INFO。
- 若后续需要压力下空闲回收，候选必须两方向均超过明确 idle 阈值，不能按 `started_at` 判断空闲。单向持续下载/上传都视为活动。首批不启用新的紧急活动连接淘汰策略。

测试同时运行连续传输隧道、真正空闲隧道及不同站点连接；反复触发普通 reclaim 和配置更新，前者不得被取消。显式防御 drain 仍只关闭匹配范围，且留下正确原因。

### T02：SNI 计数使用 RAII

主要文件：`src/metrics.rs`、`src/http_proxy_manager.rs`。

- 创建同步 Drop 的活动指标 guard，持有本次增量对应的 `Arc<ServerMetrics>`，不要在 Drop 按 server_id 重新查表，防止配置删除/重建后减错实例。
- 分离活动 gauge 的释放与请求结束时的字节/状态记录。结束记录使用消费式 finish 或幂等状态，防止显式 `request_end()` 加 Drop 导致重复递减。
- 覆盖选源失败、SNI admission 拒绝、OriginConnect admission 拒绝、connect/TLS/header 错误、正常完成、relay drain、外层 task abort。
- guard 的 Drop 不能 await、不能启动后台 task，不能在运行时退出时依赖另一次异步调度。release 构建为 panic=abort，不把进程 abort 列为可由 Drop 恢复的路径。

先保留 wire 字段和已有请求累计的业务含义。部署新进程后不再产生残留；旧进程的历史虚高值不能靠新 guard 自动修复，历史上报的修正必须另有数据处理规则。

### T03：压力状态和回收协调器

主要文件：`src/memory_governor.rs`、`src/memory_reclaim.rs`、`src/config_apply.rs`。

拆开以下数据：

| 数据 | 来源 | 用途 |
| --- | --- | --- |
| host_available_raw | MemAvailable | 主机实际可用内存信号 |
| cgroup_current / max / high | effective cgroup 祖先边界 | current 是 cgroup 总用量；high 是节流边界，max 是硬边界 |
| reclaimable_file | memory.stat 的文件页信息 | 单独展示，不能随意全部抵扣 |
| allocation_budget | 组件容量、预留和当前准入 | 限制新的连接、缓存、配置 staging |
| actual_pressure | 原始可用量、cgroup 事件与余量、PSI | 决定缓存降级和恢复节奏 |

`memoryPressure` 不再直接取 `available_after_reserve()` 的值。原始采样失败要标注 unknown/degraded，不能把缺失当作 0，也不能把无限 cgroup 当成 0 字节容量。

阈值作为可测策略函数先在 shadow 模式比较。候选 Critical 原始余量边界为 `min(64 MiB, 有效容量的 5%)`，High 为 `min(128 MiB, 10%)`，Elevated 为 `min(256 MiB, 20%)`；这些是实验起点，不是已验证生产值。cgroup high/max、持续 PSI 和事件变化单独参与判定。极低余量立即限制新增分配，不等待常规去抖。

一般升档要求连续 2 至 3 次采样，降档使用更高恢复余量并稳定 30 秒；所有时间使用单调时钟。普通回收由单个协调器执行，设置全局 in-flight、冷却和 bounded work。配置和定时线程只提出请求，禁止绕过调度器。现有 thread-local 防重入不能提供跨线程互斥。

每次记录触发来源、原始余量、目标缓存、释放条目/估算 bytes、耗时及后续 RSS/PSS 样本；无收益轮次退避，避免 5 秒一次清空/重建抖动。实际压力与动作没有一对一的“Critical 就杀连接”关系。

## 4. 第二阶段：处理主要内存分配

### T04：补齐内存观测与容量预算

主要文件：`src/memory_governor.rs`、`src/metrics/storage.rs`、`src/metrics/analyzer.rs`、`src/rpc/node.rs`。

先输出启动时有效的 Mace options、writer group 数、WAL capacity、bucket 参数、GeoIP loaded bytes/代数，以及配置代存活数量、队列 bytes/深度。字段不包含 URL 凭据或请求内容。

现有 resident 五类缓存账本继续表达原有含义，另加组件级 capacity/live-estimate 观测，不把虚拟 capacity 冒充 RSS。总预算需要包含不可回收基线、Mace、GeoIP、连接、缓存、队列、配置 staging 和系统余量，并清楚标注未知项。运行时原始可用量与静态组件预留避免重复扣减。

Mace 现有 Observer 有事务/GC/延迟等指标，但没有完整的 WAL/cache/pool live-byte gauge。先接入已有指标和可计算 capacity；缺失项通过受维护的依赖接口补充或在隔离环境使用 allocator profile，不改本机 Cargo registry 源码来伪装项目修复。

采样时区分 allocator live 与 retained/committed；不把 `RSS - resident` 或 `RSS - PSS` 叫作碎片。首次诊断采用隔离环境分配采样，不给生产注入 debugger。

### T05：Mace 小内存规格与旧库兼容

主要文件：`src/metrics/storage.rs`、`src/memory_plan.rs`、`tests/mace_storage.rs`。

在真正使用的 `mace_metrics_options()` / bucket 初始化路径集中设置参数。规格依据启动时稳定有效容量选择，不能跟随短时 MemAvailable 反复切换。下面都是候选测试配置，单位 MiB，非最终承诺：

| 参数 | 512 MiB 场景 | 约 1 GiB，本次节点 | 2 GiB 场景 |
| --- | --- | --- | --- |
| 现有数据库 writer groups | 保持 16 | 保持 16 | 保持 16 |
| 每组 WAL | 1 | 2 | 4 |
| WAL 总 capacity | 16 | 32 | 64 |
| 全局 LRU | 8 | 16 | 32 |
| metrics bucket tree cache | 8 | 16 | 32 |
| metrics bucket dirty pool | 8 | 16 | 32 |
| 单轮 checkpoint | 2 | 4 | 8 |
| stat-mask 条数 | 128 | 256 | 512 |
| data/blob handle cache 条数 | 16 / 8 | 32 / 16 | 64 / 32 |

这些值只约束所列资源，尚不构成整个 Mace 的硬上限；还要观察内部元数据 bucket、在途 checkpoint、共享引用和瞬时超额。1 GiB 规格 WAL 分配理论减少 224 MiB，其他项的 savings 必须实测。

兼容实施顺序：

1. 打开 engine 时保留现有 `concurrent_write=16`；不要按 1 CPU 自动改成 1 或 2。将来减少 group 必须针对新库或单独的导出/导入迁移，首批不迁移。
2. 原有格式不变，加载业务 bucket handle 前调用 Mace 的 `update_bucket_opt()`。新库 NotFound 时创建；旧库更新成功后再 get。Again、Invalid、I/O 错误显式处理，不静默退回旧大参数。
3. 保留原有 `inline_size` 和 `split_elems`；不能仅在 `new_bucket()` 的 Exist fallback 后认为新参数已生效。
4. 小 WAL 测试覆盖小记录、接近 ring 大小、超过 ring 的 `record_large()` 分支、事务取消和有 WAL 的非干净重开。不要把记录大小限制为 ring 大小，库已有大记录直写路径。
5. 保持当前 sync_on_write 的持久性语义；独立评估其风险，不在内存修复中顺便改变 fsync 策略。
6. bucket 背压按 T08 的错误处理和队列治理一起启用；缩小 pool 后不能用静默 commit 失败换取较低 RSS。

存储初始化失败不得让需要持久状态的服务在后台静默继续。增加明确 degraded/readiness 信号，区分可暂缓的统计与影响正确性的状态，错误时不得清空目录“自愈”。灰度必须验证旧库重开后实际采用的新参数。

### T09：GeoIP reader 合并与文件映射

主要文件：`src/metrics/analyzer.rs`、`src/metrics/storage.rs`、`src/rpc/files.rs`、`Cargo.toml`。

先由同一 reader 提供 ASN 编号和组织信息，删除两个独立读文件入口，保留有界查询缓存。确认 City/ASN 按功能需要初始化；不要只因目录有 Country 文件就加载它。

第二步采用 maxminddb 的 mmap feature。所有 City/ASN 写入统一为新 inode 校验后原子替换；完成权限、失败恢复和旧代生命周期检查后再使用 unsafe open_mmap。校验、加载、ArcSwap 发布尽量复用同一个已验证 reader，避免重复整文件读取。旧代只有仍有借用时才保留；并发 reload 串行化并合并重复版本。

隔离比较 mmap 与 Vec 的 RSS/PSS/anon/file-fault、查询延迟和更新峰值。mmap 的目标是减少匿名副本并提高可回收性，不承诺不占物理内存。THP 和 allocator 更换留作独立实验，只在证据显示额外收益后引入。

## 5. 第三阶段：配置、队列与长期增长

### T06：配置去重与限量处理

主要文件：`src/rpc/server.rs`、`src/config_apply.rs`。

- 按 server_id 维护已成功发布的 revision/fingerprint，结构化比较有效配置，包含继承的全局配置和引用对象版本；不能只对原始 JSON 文本做一次全局 hash。
- 删除字段、is_on 变化、引用配置变化必须使 fingerprint 失效。只有已经验证并成功提交的重复版本才可直接 ACK；失败版本不标记已应用。
- 对可替代的完整快照按站点合并待处理更新，限制待处理站点数量与 bytes；不合并具有独立副作用的删除、封禁或其他 RPC 命令。维持现有任务 ACK 语义。
- 常规 INFO 只输出 revision、apply/skip、耗时和站点数，重复无变化事件计数聚合。控制面为什么持续生成新 task ID 作为独立排查项，现有证据不支持认定 ACK 重试故障。

### T07：配置原子发布与停用路由

主要文件：`src/config.rs`、`src/config_apply.rs`、`src/rpc/node.rs`、`src/http_proxy_manager.rs`。

移除 High/Critical 下先释放最后有效代再构造新代的流程。复用已有 Arc/ArcSwap 模式发布包含路由与相关运行时引用的一致快照。准备在后台按 staging budget 限制，低内存时复用未改变的 Arc、按站点增量构建；若仍不足，保留旧代并延后更新，不发布部分空表。

在 passthrough 精确、通配、端口索引构建时过滤停用站点，并在最终接入判断中补充启用状态检查。新连接不能进入已停用站点；旧连接是否排空采用明确的管理策略，不能混入普通内存回收。

校验证书、LB/health 引用和 listener 资源随代切换的一致性。测试旧 task 迟到释放不影响新代；未改变站点的长连接持续工作。现有 `tests/config_sync_memory.rs` 对提前释放旧代的预期需要按新可用性不变量调整。

### T08：统计 flush、存储失败与有界背压

主要文件：`src/memory_reclaim.rs`、`src/metrics/aggregator.rs`、`src/metrics.rs`、`src/metrics/storage.rs`、`src/rpc/stats.rs`。

按“flush 所有权 -> 队列预算 -> 存储背压”三个小提交执行：

1. 取消 `.flush().len()` 后丢弃 rows。建立唯一 flush owner，把批次移交现有正常上传/持久化路径，协调周期任务与压力触发，防止双重 drain。
2. 批次队列同时限制条数和 bytes。上传/落盘成功前保留批次所有权和 retry 状态；超限对可合并指标合并，对允许丢弃的维度明确采样并记 drop counter。需要完整保留的计费统计不得通过“清缓存”丢失。
3. 为 Mace `begin/commit` 返回值建立可观察错误和有界重试；用现有 blocking writer/`spawn_blocking` 承接同步背压，不能阻塞 Tokio reactor。确认完成语义后启用 `enable_backpressure`，验证慢盘下 pool、队列和重试同时受限。

远端 RPC 未提供幂等批次语义时，不能承诺恰好一次上报；本阶段至少消除确定的本地静默丢弃，并注明正常重试契约。

### T10：修正统计历史清理

主要文件：`src/metrics/storage.rs`、`src/metrics.rs`、`tests/mace_storage.rs`。

保持现有 `S{server_id}_T{period}` 格式。为该格式使用明确 parser，按解析后的 period 判定过期；不再用 `S0_T...` 作为所有站点的时间边界。按扫描 cursor、单批条数和耗时上限拆分，定时续扫；不要一次建立覆盖全部历史的长事务。

区分站点记录、NODE_T 与其他前缀，防止误删 STAT_* 等键。用跨 server_id 位数、多个周期、截止时刻、异常 key 和超过 24 小时的数据验证。数据库物理文件释放可能滞后于逻辑删除，需要观察 Mace checkpoint/GC，不承诺清理后磁盘立即缩小。

## 6. 第四阶段：协议语义与后台指标

### T11：TCP 半关闭

主要文件：`src/tcp_proxy.rs`。

任一方向读到正常 EOF 时只 shutdown 对应目标写半边，继续等待反方向响应，直到其完成或命中明确的关闭超时。hard error、显式取消和正常 EOF 分开处理。半关闭后的等待有上限，但单向持续传输不因另一方向无数据被误判 idle。

用“客户端上传完 FIN，源站随后返回较大响应”的 fixture 校验完整内容/hash，另测源站先 FIN、RST、取消、超时。zero-copy 当前未开启；不能将其列为本次主因，但共享 relay 语义改变后仍需单独验证对应 feature 路径。

### T12：活动连接口径迁移

主要文件：`src/metrics.rs`、`src/rpc/node.rs`、`src/http_proxy_manager.rs`、`src/tcp_proxy.rs`。

明确下游 TCP transport 从 accept 到 close 计一次；上游、RPC 单独计数；HTTP/2 一个 TCP 可有多个 active request/stream；UDP session 和 QUIC connection 单独列出。建立 transport、pending、forwarding、active-request 等独立 gauge，不让 HTTP/2 stream 混进物理 TCP 数。

先新增兼容的 shadow 字段/指标并与旧 connectionCount 并排观测，保留现有协议字段类型和含义。确认后台消费者使用方式后再切换显示；若后台依赖旧语义，新旧字段按版本过渡。后台不必等此迁移才获得 T02 的漏减修复。

与 `ss` 对账时按端口、方向和状态过滤；全部 ESTABLISHED 含上游和 RPC，不应直接等于客户端连接数。fixture 在静止采样点要求精确相等，线上异步样本记录采样时间和允许的瞬时差异。

## 7. 验证矩阵与发布门槛

先做本地确定性测试，再在 Linux 上做实际 cgroup 和网络验证。macOS 的 `/proc` 缺失导致跳过的测试不能视为 Linux 内存验证通过。

| 场景 | 必须观察的结果 |
| --- | --- |
| 连续双向及单向长连接，普通 Critical reclaim，停用站点重复更新 | 健康连接取消数为 0，内容 hash 完整 |
| 选源失败、两种准入失败、task abort、配置删除/替换 | 指标和 permit/registry 各回到自己的基线，不下溢、不串代 |
| 本次 967 MiB total / 约 273 MiB raw available | 可限制预算，但不能误作系统即将 OOM并杀连接 |
| 512 MiB / 1 GiB / 2 GiB，含祖先 cgroup 限制及缺失采样 | 实际边界正确，缺失值不当 0，限流能恢复 |
| 16 组旧库，缩小 WAL/bucket，干净及非干净重开 | 全部已提交记录可按既有持久性契约读取，参数真实生效 |
| 大记录越过 WAL ring、慢盘、RPC 失败、队列满 | 无 panic、无静默丢失、积压有界且可恢复 |
| GeoIP 更新并发查询、文件校验失败、回滚 | 无截断映射、无错误版本发布、旧 reader 最终释放 |
| 新旧配置交替、准备失败、停用/启用、通配 SNI | 无空路由窗口，停用站点不接受新连接 |
| 跨 24 小时历史、不同 server_id、NODE_T/其他 key | 只删除应过期记录，扫描有界 |
| HTTP/2 多流与 TCP 半关闭 | 连接/请求口径分开，反向响应不被截断 |

建议命令按修改范围执行，不因本文档存在就运行所有集成测试：

```sh
cargo fmt --all --check
cargo test --lib sni
cargo test --lib relay
cargo test --test memory_reclaim
cargo test --test memory_governance
cargo test --test mace_storage
cargo test --test config_sync_memory
cargo check --all-targets
```

新增 T02/压力/存储恢复测试需按实际测试名运行并确认执行数量非 0。最终跑完整确定性测试集；依赖真实 API 的用例单列，在可控环境提供配置后才运行。存储和内存基准复用现有 mace-perf、storage/analyzer bench，先确认这些工具使用实际生产 option builder。

T13 的 1 GiB 目标使用约 261 个启用站点、与现场量级相近的连接、固定数据库基数和重复配置更新。记录初始化后、预热后、卸载后以及每分钟 RSS/PSS/anon/file、分配器、队列、连接数和吞吐/p99。

- 硬门槛：不发生非预期 drain、OOM、统计残留、配置空窗和存储重开丢数据。
- WAL 参数门槛：旧 16 组库的有效总 capacity 为 32 MiB，不能只检查配置文件。
- 内存候选目标：同负载下稳态 anon 相比旧版至少下降 150 MiB；这是一项待验证发布目标，不是测量结果。未达标时先定位抵消分配，不能宣称已完成降内存。
- 1 小时预热后继续 24 小时固定基数 soak；最后 12 小时 hourly-median anon 增长斜率候选不超过 1 MiB/h，且队列不持续增长。超过阈值需归属解释并重新评估，不直接称为泄漏。
- 吞吐下降超过 5% 或 p99 恶化超过 10% 时复核缓存与 WAL 大小、checkpoint 频率；这些是初始比较门槛，需用同机同负载重复测量确认噪声。

## 8. 灰度与回滚

1. 保存版本、有效参数和脱敏基线。隔离旧库重开测试使用一致副本或专用恢复 fixture，不能边写边复制数据库目录后声称是有效备份。
2. 首批 T01 至 T05 通过验证后，在测试节点验证；生产灰度由另一次明确部署操作执行。本任务没有重启或变更生产。
3. 生产先单节点，观察 30 至 60 分钟重点指标，再覆盖 24 小时。服务重启本身会中断现有连接，切换应结合流量摘除/排空窗口，不能承诺单进程热替换零断流。
4. 第二批逐步加入配置去重/原子发布、队列背压；GeoIP mmap 和半关闭分别灰度，便于定位差异。
5. 功能异常优先回退对应参数或独立提交，保留 T01 长连接保护和 T02 计数修复的可用构建。完整回到 v1.2.5 会恢复已确认缺陷，仅作最后应急选项。
6. bucket 参数会持久化，回退二进制并不自动恢复原值；准备在 bucket 加载前恢复原参数的受控启动选项，并在测试中演练。首批不改变 writer group 数、key 格式和数据库目录，不依赖删库回滚。
7. 本轮不直接给约 539 MiB current 的进程下调 memory.max。cgroup high/max 和 journald 配额等部署治理在新稳态及峰值测量后确定，避免设置边界立即引发回收或 OOM。

## 9. 依赖、工作量与未决项

主线依赖为 `T01/T02 -> T03 -> T04 -> T05 -> 首批集成验证`；T04 的存储观测可与 T01/T02 并行，但修改 metrics/governor 的提交需要协调。T06 在 T03 后，T07 在 T06 后；T08 先完成错误/队列治理再启用数据库背压；T09/T10 可独立验证；T11 与 T01 共享 relay 需顺序合并；T12 接在 T02 后；最终 T13 汇总所有上线项。

首批开发与定向验证粗估 3 至 5 个工程日，后续完整治理再需约 4 至 7 个工程日，另计 24 小时 soak 和发布观察。该估算以不更换存储引擎、不修改控制面协议为前提，依赖库补充接口或旧库恢复测试失败会增加工作量。

不阻塞首批的未决项：未归属匿名内存的 allocation profile、重复配置任务的控制面来源、后台 connectionCount 的消费者语义、当前旧库的完整持久化参数快照。各项已有验证任务，不需要先猜一个结论再实施。

现有 `tasks/oom-memory-management-plan.md` 与 `tasks/connection-reset-repair-plan.md` 的相关任务可复用；本计划用现场证据更新优先级。尤其应修正旧文档把 RSS 差值用于估计碎片的表述，以及把提前释放有效配置代视为低内存默认方案的假设。
