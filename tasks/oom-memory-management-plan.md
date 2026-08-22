# OOM 与常驻内存管理计划

## 目标与边界
本计划把进程生命周期内的常驻对象与请求 admission 分开记账，并以静态可证明的预算、条目数和生命周期删除作为第一道 OOM 防线。磁盘缓存是持久事实源；内存索引只是可重建的 resident view，不能因 resident 饱和删除磁盘元数据。

## 生产保护与 cgroup 边界
- 部署层为每个进程设置明确 cgroup memory.max、memory.high、memory.swap.max，并保留内核/sidecar headroom；memory.high 触发降级，memory.max 是最后边界。
- governor 读取 `/sys/fs/cgroup` 祖先链上的 effective limit（min of memory.max/high/swap.max）；失败时 `cgroup_managed=false` 并保守使用 sysinfo。
- 进程 RSS/PSS/anon 来自 `/proc/self/smaps_rollup`（失败回退 `status`）。resident estimate 只用于索引账本，不能替代 RSS。
- jemalloc/mimalloc arena 细节仍可后续叠加，当前以 RSS−PSS / RSS−resident 作为碎片与未记账偏差观察量。

## 统一账本与层级
- `ResidentCategory` 覆盖 metadata、access log、surrogate index、Bloom、negative cache；owner replacement 是唯一更新路径，replace/remove 必须幂等且不能下溢。
- 预算来源是 governor snapshot：cache metadata/index/access log 共享 cache budget，Bloom/negative 共享 bloom budget；连接、large object、队列仍使用 admission 层，并要求连接优先级高于可回收缓存。
- 各结构同时有 bytes 与 entries/members/tags/长度上限；任何单项先过单项上限，再过 category/global budget。

## 生命周期
- metadata 启动只载入未过期且同时满足 bytes/entries 的条目；跳过 resident 不影响磁盘。upsert 先移除旧 charge，拒绝新 charge 时保留旧 resident。
- access log 只接受当前 resident hash；按条数、年龄、每次 cleanup 扫描预算回收，flush 不构造无界临时 Vec。
- reverse index replacement 先移除旧 hash 的全部 membership；tag/member saturation 时降级为 Bloom/全量扫描补偿，不能承诺 tag purge 完整命中。
- 常规 Bloom 不支持即时删除；live 代承接 insert，contains 同时查询 retiring 代。后台按利用率/预算触发双代 rebuild、原子切换、旧代延迟回收。negative cache 可逐项删除，cleanup 必须 bounded。

## 可观测性
输出 resident total/category used、budget、pressure、拒绝计数、metadata entries、access entries、tag/membership counts、Bloom generation/estimated bytes、negative count/expiry cleanup，以及 degraded purge 次数。日志需带原因和边界类型，避免只报“memory pressure”。

## 测试与验收
- 单测：owner replace/remove 的总量守恒、重复 remove 不下溢；metadata 过期/预算启动逻辑；surrogate tag 长度、每 tag、total memberships 和 replacement。
- soak：持续随机 upsert/purge/access 24h，resident bytes 不超过 budget，entry/membership 上限不超；RSS 与 estimate 的偏差需有告警阈值。
- fault：cgroup high/max、DB 重启、writer queue 满、Bloom saturation、index saturation、并发 overwrite/purge；服务仍可响应且磁盘行为不被 resident 淘汰改变。
- 验收：所有 ownership mutation 经过 accounting API；压力时新 resident admission 可拒绝但已有值可移除；无 unbounded Vec cleanup；静态检查通过。

## rollout / rollback
先 shadow telemetry，再小比例开启 resident admission，逐步启用 metadata/index 限制，最后启用 Bloom rotation。每阶段保留开关、拒绝率和 p99/RSS 对照；异常时回滚 resident admission 到只读 telemetry，保留磁盘源和 purge 全量扫描补偿。

## 明确延期
soak/fault 压测、rollout dashboard、jemalloc arena dump 仍延期。cgroup reader、RSS sampler、启动 disk isolation、双代 Bloom、saturated tag 有界扫描已落地。
