# SNI 节点内存占用分析

日期：2026-09-05，UTC+8。对象：64.204.49.107，cloud-node.service，PID 129036。
源码基线：94eb6a1 / v1.2.5；线上版本 1.2.5，未做可重现构建或堆对象逐项比对。

## 结论

目前最明确的大额常驻分配来自实际使用的 Mace 存储初始化路径：默认 16 个 writer group，每组 16 MiB WAL ring，共 256 MiB，构造时会清零整个缓冲区。项目还保留了过大的数据库缓存目标、整文件读入的 GeoIP 数据以及重复的 ASN reader。它们没有进入当前只覆盖五类缓存索引的 resident 账本。

这说明内存治理没有覆盖主要分配。当前每 5 秒清小缓存、关闭隧道，并不能释放仍由数据库持有的 WAL；却会中断业务。不能把全部匿名内存直接定性为泄漏，未归属部分仍需隔离环境中的分配采样。

## 1. 线上实测

以下为 15:25 至 15:31 的只读采样，进程相同，没有重启。

| 项目 | 测量结果 | 解释 |
| --- | --- | --- |
| 主机 MemTotal | 967.3 MiB | 约 1 GiB 规格机器的内核可见内存 |
| 主机 MemAvailable | 约 273 至 276 MiB | 已考虑部分可回收缓存；不能再把 Cached 全部加进去 |
| 节点 RSS | 约 476.1 至 476.5 MiB | 进程当前驻留页 |
| 节点 PSS，15:28 | 473.7 MiB | 按比例分摊共享页 |
| 节点 Anonymous，15:28 | 462.9 MiB | 主要是堆、匿名映射、线程栈等 |
| 节点 AnonHugePages | 448 MiB | 上述匿名内存的子集，不是额外 448 MiB |
| 节点 Swap | 0 | 主机约 19 MiB swap 使用不属于该进程 |
| service memory.current，15:28 | 538.6 MiB | 包括 cgroup 内匿名页、文件缓存和内核内存，不能与 RSS 相加 |
| service file，15:25 至 15:31 | 约 67.9 至 71.2 MiB | cgroup 文件页缓存，不是应用堆 |
| service sock | 约 0.16 至 0.95 MiB | 内核 socket 记账，不包含用户态 relay buffer |
| PSI memory，15:28 | some/full avg10、avg60、avg300 均为 0 | 该采样窗口没有持续内存阻塞，不代表永远没有压力 |
| cgroup high/max | 无有限限制 | 没有观察到 OOM、OOM kill 或 high 事件 |

15:20 状态报文另外显示：`residentUsedBytes=1,266,432`，约 1.21 MiB；`connectionAdmissionUsedBytes` 约 3.5 MiB。两者是局部估算，既不是物理内存实测，也不是整个进程的内存上限。

启动日志曾报告约 114.4 MiB RSS；现在约 476 MiB。只能说明初始化后及运行期间发生了增长，不能仅用两点判断增长速率或证明持续泄漏。15:25 至 15:31 的 RSS 基本稳定。

## 2. 最大的确定分配：Mace WAL

生产使用的是 [storage.rs:53](/Users/moying/Documents/project/cloud-node-rust/src/metrics/storage.rs:53) 的 `mace_metrics_options()`，仅设置 `sync_on_write=false`；[storage.rs:61](/Users/moying/Documents/project/cloud-node-rust/src/metrics/storage.rs:61) 的 bucket 配置仅关闭 backpressure，其余沿用默认值。

Cargo 锁定的 `mace-kv 0.1.1` 源码证据：

- [options.rs:209](/Users/moying/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/mace-kv-0.1.1/src/utils/options.rs:209)：`CONCURRENT_WRITE=16`，`WAL_BUF_SZ=16 MiB`。
- [context.rs:98](/Users/moying/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/mace-kv-0.1.1/src/cc/context.rs:98)：按 `concurrent_write` 创建全部 writer group。
- [log.rs:89](/Users/moying/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/mace-kv-0.1.1/src/cc/log.rs:89)：每组创建独立的 WAL ring。
- [block.rs:131](/Users/moying/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/mace-kv-0.1.1/src/utils/block.rs:131)：`Block::alloc(cap)` 后执行 `data.zero()`，实际触碰整个分配，不只是预留虚拟地址。

因此该路径的 WAL 分配为 `16 x 16 MiB = 256 MiB`，量级相当于当前 RSS 的 54%。远端 log 目录有 group 0 至 15 的 WAL 文件，与 16 组配置相符。但尚未用分配探针把线上每个匿名页映射到 WAL 对象，256 MiB 是源码可计算的分配量，不是独立测得的当时 WAL RSS。

这部分内存由数据库对象长期持有，关闭几条隧道不会释放它。首次懒初始化存储可造成明显 RSS 台阶，因此启动早期 RSS 不能作为完成全部初始化后的基线。

旧库兼容细节：`concurrent_write` 已持久化，修改后会因 `check_compatible()` 返回 Invalid 而打不开旧库。首轮应保留 16 组，把每组 WAL 从 16 MiB 调至候选 2 MiB，总分配降到 32 MiB，理论减少 224 MiB 分配。实际 RSS 降幅、吞吐和恢复正确性必须通过旧库重开和等负载测试确认。

## 3. 数据库缓存目标明显超出机器容量

| 参数 | 当前生产代码默认值 | 是否启动即分配全部 |
| --- | --- | --- |
| 全局 `lru_capacity` | 256 MiB | 否，按访问增长的缓存目标 |
| `stat_mask_cache_count` | 16,384 条 | 否，条数上限，实际条目大小和两个类别需分别核算 |
| bucket `cache_capacity` | 1 GiB | 否，树页驻留目标 |
| bucket `pool_capacity` | 1 GiB | 否，脏页池目标 |
| bucket `checkpoint_size` | 256 MiB | 否，单轮 checkpoint 的目标上限 |
| bucket `enable_backpressure` | false | 取消写入侧限流，会放大慢盘时的积压风险 |

以上是不同层的目标，不应相加后宣称已经占用数 GiB；缓存、树页、脏页间还可能共享引用。缺陷在于这些目标没有根据本机约 967 MiB 的内存预算收敛。

[mace_backend.rs:131](/Users/moying/Documents/project/cloud-node-rust/src/metrics/mace_backend.rs:131) 中确实有一套较小缓存参数，但生产 `STORAGE` 的初始化走 [storage.rs:1103](/Users/moying/Documents/project/cloud-node-rust/src/metrics/storage.rs:1103)，没有调用该旧适配器。不能因为另一文件写了限制，就认为生产数据库已受这些限制。

旧 bucket 的参数也不是修改 `new_bucket()` 默认值即可生效：现有代码遇到 Exist 就 `get_bucket()`，继续使用已持久化的旧参数。Mace 0.1.1 提供 `update_bucket_opt()`，但 bucket 已加载时会返回 Again；必须在启动加载 handle 之前更新，并保留 `inline_size`、`split_elems` 等兼容敏感字段。

## 4. GeoIP 占用与重复加载

[analyzer.rs:63](/Users/moying/Documents/project/cloud-node-rust/src/metrics/analyzer.rs:63) 持有 `Reader<Vec<u8>>`；`open_readfile()` 底层是 `fs::read()`，整个数据库进入匿名堆内存。

| 文件 | 远端大小 | 代码生命周期 |
| --- | --- | --- |
| City | 65,121,293 bytes，62.1 MiB | 初始化及更新时读入，ArcSwap 持有当前版本 |
| ASN | 12,067,840 bytes，11.5 MiB | analyzer 有一个 Lazy reader |
| 同一 ASN | 同上 | storage 的 ASN_READER 再创建一个独立 Lazy reader |
| Country | 8,619,498 bytes，8.2 MiB | 仅看到文件存在，未据此计入已载入内存 |

City 加两个 ASN reader 的文件数据约 85.1 MiB。SNI 统计路径可进入这两类 ASN 查询；单个 Lazy 是否在线上已初始化没有直接对象观测，因此 85.1 MiB 是这些 reader 均已加载时的分配估算。

先合并 ASN reader 可去掉重复副本，理论少分配约 11.5 MiB。进一步用只读 mmap 可让 GeoIP 页变为文件映射、按访问加载并允许内核回收；全文件被访问时仍可能驻留，不能承诺 mmap 后 RSS 为零。

`open_mmap()` 是 unsafe API，要求 reader 存活时底层 inode 不被改写或截断。更新流程必须使用新文件校验、原子替换、ArcSwap 发布，保留旧映射供在途查询使用。现有 City 校验与 reload 还会整文件读取，改 mmap 时需一起梳理峰值与所有写入路径。

## 5. THP、分配器与日志的正确解释

宿主机 THP 为 `always`，节点 448 MiB 匿名内存由透明大页承载。大页可能影响稀疏访问时的驻留与释放粒度，但这一数字不能单独证明浪费或泄漏。最大的匿名 VMA 约 316 MiB，也不能只凭尺寸断言整个 VMA 就是 WAL。

项目没有显式全局 jemalloc/mimalloc；当前按 Linux glibc 分配器分析。`malloc_trim(0)` 只见于大配置代释放路径，普通回收不主动 trim。释放对象后 RSS 未立即下降可能来自分配器保留，也可能是对象仍然存活；要用 allocator live/retained 指标区分。`RSS - resident estimate` 不是碎片大小，`RSS - PSS` 主要反映共享页分摊，也不能作为碎片指标。

15:28 journald RSS 约 253.2 MiB，但 PSS 约 134.0 MiB，匿名页仅约 0.51 MiB，绝大部分是映射的日志文件页。日志文件占磁盘约 317.6 MiB。不能把它当作额外 253 MiB 私有堆，也不能与系统 Cached 重复累计。高频配置和 reclaim 日志会增加 I/O 和文件页工作集，适合限频优化，但不是节点 463 MiB 匿名内存的解释。

## 6. 与连接计数、断流的关系

已抓到 `connectionCount=137764`，同窗口进程只有 39 至 51 个 ESTABLISHED socket，含两侧和 RPC。SNI 错误出口漏减的是整数计数；这个数字本身不会创建对应数量的 socket 或 relay buffer。

当前链路是：大额常驻分配占用内存；governor 再把已扣 30% reserve 的预算当作真实可用内存，落入 Critical；周期和配置应用触发回收，按连接建立时间取消 SNI；重连及准入失败又可能漏减计数。断流与计数残留各有代码证据，不能据现有日志量化每一步反馈的历史贡献。

常规回收覆盖 L1、Bloom、Geo/UA 结果缓存、TLS connector 和 regex 等，未覆盖 WAL ring、Mace 主要缓存目标或 GeoIP reader 本体，回收动作与主要内存来源错位。

## 7. 额外发现：历史统计清理边界错误

[storage.rs:322](/Users/moying/Documents/project/cloud-node-rust/src/metrics/storage.rs:322) 用 `S0_T{截止时间}` 作为所有站点记录的词典序结束边界。实际 key 为 `S{server_id}_T{period}`，任一正数 server_id 的 key 都大于 `S0_...`；循环会提前 break，过期站点记录无法按预期删除。

[metrics.rs:1187](/Users/moying/Documents/project/cloud-node-rust/src/metrics.rs:1187) 尝试保留最近 24 小时，但该边界使站点历史数据可能长期积累，带动数据库文件和索引缓存增长。远端数据库目录约 498 MiB 是磁盘量，不能视为 498 MiB 堆；本次进程运行不足 24 小时，也没有盘内记录年代统计，尚不能把当前内存增长归因于该缺陷。

另外 `StorageBackend.counters` 只插入不清理，但 `increment_batch()` 在当前源码的调用者是测试和性能工具，没有查到生产调用，所以不列为此次主因。

## 8. 尚需验证的归属

在隔离 Linux 环境用同版本、脱敏配置和相同数据库布局，记录：进程启动、GeoIP 初始化、Mace 打开、配置发布、稳态流量、配置更新、流量停止后的 anon/PSS 和 allocator live/retained。分别只改变 WAL 大小、数据库缓存、ASN 共享、GeoIP 映射，比较分配与驻留差值。

剩余匿名内存可能包括 Mace 树页/元数据、配置和 TLS 对象、线程栈、其他应用状态及分配器保留。没有 heap profile 前不提供伪精确的分项占比或最终 RSS 承诺。生产目前没有注入探针、读取堆内容、强制 trim、关闭 THP 或执行负载测试。

关联文档：[原始断流审计](/Users/moying/Documents/project/cloud-node-rust/tasks/sni-runtime-audit-2026-09-05.md)、[详细修复方案](/Users/moying/Documents/project/cloud-node-rust/tasks/sni-memory-repair-plan-2026-09-05.md)。
