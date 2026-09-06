# SNI 断流与连接数异常审计

检查时间：2026-09-05 15:07 至 15:21，Asia/Hong_Kong（UTC+8）。

目标：root@64.204.49.107:22，主机 nbnet-3436。

部署：/root/cloud-node/cloud-node-rust，cloud-node.service，PID 129036。
运行版本 1.2.5，构建时间 2026-09-04 17:45:08 +0800，standalone，zeroCopy=false。
本地审计基线：94eb6a1（v1.2.5）。远端没有源码 checkout；版本与日志路径相符，但未进行二进制可重现构建比对。

## 结论与证据

断流主因是内存回收路径主动取消存量 SNI/TCP 隧道，触发条件又采用扣除预留之后的预算作为内存压力指标。SNI 失败出口存在连接统计漏减，能够留下已经没有 socket 的活跃连接计数。

线上直接观测：

| 项目 | 观测值 |
| --- | --- |
| 节点 connectionCount 上报 | 137,764，两个相隔 30 秒的状态报文相同 |
| 上报 timestamp | 1788592819、1788592849 |
| 状态抓取窗口 | 15:20:15 至 15:20:55 |
| 同窗口 cloud-node-rust ESTABLISHED socket | 窗口开始 39，结束 51，含下游、回源、RPC |
| 物理内存 | 1,014,317,056 bytes，约 967.3 MiB |
| 上报 memoryUsage | 约 72.3% |
| 上报 memoryPressure | critical |
| connectionBudgetBytes | 10,143,170 bytes，约 9.67 MiB |
| connectionAdmissionUsedBytes | 3,670,016 / 3,702,784 bytes |
| processRssBytes | 499,335,168 bytes |
| fdUsed / fdSoftLimit | 535 / 1,048,576；下一次为 550；fdPressure=normal |
| cgroup memory.high / memory.max | 均未设置有限值；memory.events 中 oom、oom_kill、high 均为 0 |
| 服务重启 | 自 2026-09-04 20:32:11 启动，NRestarts=0 |
| L4 拦截 | 捕获的两次状态中 blockedTotal、alreadyBlockedTotal、aggregateDropTotal 均为 0 |

15:13:22.852000 的日志记录一次 `memory reclaim completed level="critical"`。
同次被动抓包在 15:13:22.852296 至 15:13:22.854782，看到节点从 8443 端口向多名客户端批量主动发送 FIN，随后出现 RST。
相邻回收日志为 15:13:17.847000 和 15:13:27.857000，符合每 5 秒执行一次的回收线程。
这提供了节点主动关闭隧道与回收触发的毫秒级对应证据。

FD 数量不是连接数：一次分类中 273 个 FD 属于数据文件，另有 sysinfo 保留的 /proc/*/stat 文件，不能把约 540 个 FD 全部视为泄漏 socket。

## P1：内存回收不区分活动隧道，直接断开业务

[memory_reclaim.rs:80](/Users/moying/Documents/project/cloud-node-rust/src/memory_reclaim.rs:80) 和 [memory_reclaim.rs:96](/Users/moying/Documents/project/cloud-node-rust/src/memory_reclaim.rs:96) 在 High/Critical 时分别调用 `drain_sni_limited(8/32)`。
[l4_connection_registry.rs:189](/Users/moying/Documents/project/cloud-node-rust/src/l4_connection_registry.rs:189) 按 started_at 排序后发送取消信号，没有最近活动时间、双向传输进度、是否空闲的条件。
[tcp_proxy.rs:2073](/Users/moying/Documents/project/cloud-node-rust/src/tcp_proxy.rs:2073) 收到取消后退出 relay 并释放流，导致现有连接关闭。

回收线程每 5 秒执行；配置应用也能直接进入同一回收函数。长连接可能正在正常传输，也会被选中。
另外，ReclaimStats 虽有 sni_relays_drained 字段，[memory_reclaim.rs:114](/Users/moying/Documents/project/cloud-node-rust/src/memory_reclaim.rs:114) 的实际日志没有输出它，因此日志表面只像缓存回收。

修复方向：将可丢弃缓存回收与业务连接淘汰拆开；常规配置应用和预算收缩不应直接取消健康存量隧道。先限制新连接，真正需要淘汰时根据双向活动时间、真实压力和全局速率选择候选，并明确记录原因和数量。

## P1：SNI 失败出口漏减活跃连接数

[http_proxy_manager.rs:1687](/Users/moying/Documents/project/cloud-node-rust/src/http_proxy_manager.rs:1687) 先执行 request_start，将 active_connections 加一。
随后以下三个错误出口直接返回：

- 1697：选取后端失败。
- 1703：SNI relay 内存准入被拒绝。
- 1706：回源连接内存准入被拒绝。

这些出口没有 request_end，也没有管理该统计值的 Drop guard。
外层 L4 注册 guard 会销毁，但它管理的是独立注册表，不会递减 ServerMetrics.active_connections。
[metrics.rs:687](/Users/moying/Documents/project/cloud-node-rust/src/metrics.rs:687) 对这些计数求和；[rpc/node.rs:1460](/Users/moying/Documents/project/cloud-node-rust/src/rpc/node.rs:1460) 将和作为 connectionCount 发往后台。
因此连接失败并释放 socket 后，统计值可以永久残留，成功的新连接结束只能抵消它自身的增量。

线上已确认上报数与实际 socket 严重不符。上述漏减是确定的代码缺陷；现有 INFO 日志没有每次准入失败的明细，尚不能逐条归因全部 137,764 个计数残留。
此外 HTTP/2 按请求/流计入同一个 active_connections，因此该字段本身混合了请求数与传输连接数，也应明确拆分口径。

修复方向：用持有同一 ServerMetrics 实例的 RAII guard 管理增减，覆盖所有早退、future 取消及正常结束，并避免显式 request_end 与 Drop 重复递减。单独维护节点传输连接数和活动请求/流数。

## P1：将扣除预留的预算用于触发破坏性回收

[memory_governor.rs:2047](/Users/moying/Documents/project/cloud-node-rust/src/memory_governor.rs:2047) 从系统可用内存中减去物理总内存的 30%，不足时将预算托底为约总内存的 1%。
[memory_governor.rs:2492](/Users/moying/Documents/project/cloud-node-rust/src/memory_governor.rs:2492) 再用这一预算判断 Critical：小于等于总内存的 2%，或小于等于 64 MiB。

本机总内存约 967.3 MiB，30% 预留约 290.2 MiB。实际仍有约 268 至 279 MiB 可用时，扣除预留后的预算已托底为约 9.67 MiB，进而长期触发 Critical。
因绝对 64 MiB 阈值，这台机器在原始可用内存约 354 MiB 以下便可能达到 Critical，并不要求系统已经接近 OOM。
保留内存用于限制新分配是合理策略，但同一阈值直接驱动健康隧道淘汰，会造成当前故障。

修复方向：区分原始可用内存、可分配预算、cgroup/系统真实压力；破坏性动作应由真实压力触发，加入滞回、冷却与实际回收收益判断。

## P1：配置任务放大了全局断流

[rpc/server.rs:70](/Users/moying/Documents/project/cloud-node-rust/src/rpc/server.rs:70) 的 LAST_SINGLE_SERVER_JSON_HASH 只用于减少日志，既不是按 server_id 保存，也不会跳过未变化的配置应用。
[config_apply.rs:257](/Users/moying/Documents/project/cloud-node-rust/src/config_apply.rs:257) 在检查站点是否 is_on 之前调用 maybe_reclaim；[config_apply.rs:211](/Users/moying/Documents/project/cloud-node-rust/src/config_apply.rs:211) 直接回收，不经过全局 5 秒冷却。

15:00 至 15:15 的 journal 统计为 65 次 configChanged、65 次 materialize、255 次 reclaim。
日志中多次为 isOn=false 的 speedtest 配置，单次应用耗时约 1 至 2 ms，仍触发 Critical 回收。这意味着更新一个停用站点也能关闭其他站点的 SNI 隧道。
目前任务 ID 持续增加，不能仅据此认定是同一任务 ACK 失败重试；任务持续生成的控制面原因未在此次节点审计中确定。

修复方向：按站点的有效配置做去重及任务合并；站点配置应用使用独立、非破坏性的缓存回收；所有存量连接淘汰共享全局速率限制。

## 其他代码风险

- SNI 的 strict_close_on_eof 为 true：[tcp_proxy.rs:1829](/Users/moying/Documents/project/cloud-node-rust/src/tcp_proxy.rs:1829)。任意一个方向读到 EOF 就取消另一个方向，不能完整保留 TCP 半关闭后的反向响应，可能截断上传结束后返回的数据。此次抓包没有将它确认为主因。
- 全量配置在 High/Critical 时先清空旧路由，再异步构造新路由：[rpc/node.rs:974](/Users/moying/Documents/project/cloud-node-rust/src/rpc/node.rs:974)。存在新连接查不到路由的窗口，源码注释也承认这一行为。应保留最后一份有效路由直到新配置可发布。
- 停用站点仍保留在 all_servers，而 [config.rs:1839](/Users/moying/Documents/project/cloud-node-rust/src/config.rs:1839) 重建透传索引没有过滤 server.is_on；精确 SNI 查找及 handler 也未补这一检查。停用站点可能继续匹配，应增加启用状态过滤及回归覆盖。
- [memory_reclaim.rs:132](/Users/moying/Documents/project/cloud-node-rust/src/memory_reclaim.rs:132) 对统计聚合器 flush 后只取 len 并丢弃数据，可能造成请求维度统计缺失；这不会修复 active_connections 的残留。

## 修复与验收顺序

1. 先消除常规回收对健康 SNI/TCP 的无条件取消，并恢复完整的关闭原因可观测性。
2. 修正计数生命周期，测试选源失败、两类准入失败和 future 取消后计数恢复至基线。
3. 分离真实内存压力和分配预算，消除配置任务对连接回收的放大作用。
4. 验证持续下载、上传、长连接、半关闭、配置热更新；按口径比较后台连接数、L4 注册表和实际 socket。

此次未修改生产二进制、服务配置或项目源码，未重启服务，未对生产做负载测试。验证使用进程/内核状态、journal、被动 TCP 抓包和被动解析节点正常发送的 gzip gRPC 状态上报。诊断脚本只输出统计字段，没有保存报文内容或认证信息。未运行 Cargo 测试，本次结论不构成修复验证。

## 后续内存分析与详细计划

15:25 至 15:31 的追加检查已整理为 [内存分析](/Users/moying/Documents/project/cloud-node-rust/tasks/sni-memory-analysis-2026-09-05.md)。主要发现是生产 Mace 初始化默认分配 16 x 16 MiB WAL，而其大缓存目标和 GeoIP reader 没有纳入现有 resident 账本。另有统计历史清理边界错误，需修复长期增长风险。

实施顺序、旧库兼容、参数候选、验收和回滚见 [详细修复方案](/Users/moying/Documents/project/cloud-node-rust/tasks/sni-memory-repair-plan-2026-09-05.md)；执行状态见 [任务清单](/Users/moying/Documents/project/cloud-node-rust/tasks/sni-memory-repair-todo-2026-09-05.md)。这些是计划，尚未实施修复。
