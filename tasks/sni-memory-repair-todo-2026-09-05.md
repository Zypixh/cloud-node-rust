# SNI 与内存修复执行清单

基线：94eb6a1。方案：[详细设计](/Users/moying/Documents/project/cloud-node-rust/tasks/sni-memory-repair-plan-2026-09-05.md)。
本次已完成诊断与计划，以下实现任务均未执行，不能用计划中的验收值替代测试结果。

## 已完成

- [x] SSH 只读检查运行版本、进程、socket、内存和日志。
- [x] 关联回收日志与服务端主动 FIN，定位普通回收的 SNI 取消路径。
- [x] 被动解析状态报文，确认 connectionCount 与实际连接严重不符。
- [x] 定位 SNI 三处早退漏减、压力预算混用及配置应用放大。
- [x] 核对 Mace 默认 WAL 分配、数据库参数、GeoIP 和 journald 内存口径。
- [x] 制定依赖、旧库兼容、验证矩阵和回滚方案。

## T01：长连接保护及关闭原因，P1 / M

文件：`src/memory_reclaim.rs`、`src/l4_connection_registry.rs`、`src/tcp_proxy.rs`。
依赖：无。

- [ ] 常规 reclaim 和配置应用不取消健康 SNI/TCP；显式取消有类型化原因。
- [ ] 两方向共享活动判断，单向持续传输不被当作空闲。
- [ ] 正常流量、反复 reclaim 和范围化防御取消的测试通过，资源归还。

验证：`cargo test --lib relay`、`cargo test --test memory_reclaim`；fixture 校验传输内容与取消原因，不只检查返回值。

## T02：SNI 活动计数 RAII，P1 / S

文件：`src/metrics.rs`、`src/http_proxy_manager.rs`。
依赖：无，与 T01 合并时协调终止路径。

- [ ] guard 持有原 ServerMetrics 实例，Drop 同步递减且不能重复结束。
- [ ] 选源失败、两类准入失败、网络失败、task abort、正常结束均归还 gauge。
- [ ] 配置删除/重建后的旧请求不会减到新实例；累计 bytes/请求不重复记录。

验证：新增本地确定性失败注入测试，循环 10,000 次失败后 gauge 精确回到基线；与已有指标测试一起运行。

## T03：压力与回收调度，P1 / M

文件：`src/memory_governor.rs`、`src/memory_reclaim.rs`、`src/config_apply.rs`。
依赖：T01。

- [ ] 原始内存压力、cgroup 边界和 allocation budget 分离，缺失采样显式处理。
- [ ] 全局单次执行、单调冷却、滞回和无收益退避覆盖配置及定时入口。
- [ ] 回放本机样本及 512 MiB/1 GiB/2 GiB 边界，验证误报消除、真实低内存仍限制新增并能恢复。

验证：扩展 `tests/memory_governance.rs`、`tests/memory_reclaim.rs`；多线程并发触发时实际回收轮数受控。

## 检查点 A

- [ ] T01 至 T03 定向测试通过，持续传输不随压力预算变化断开。
- [ ] 日志/指标可以唯一解释取消与拒绝，敏感数据不进入诊断字段。

## T04：内存观测与预算，P1 / M

文件：`src/memory_governor.rs`、`src/metrics/storage.rs`、`src/metrics/analyzer.rs`、`src/rpc/node.rs`。
依赖：T03；只读观测实现可提前并行。

- [ ] 输出有效 Mace options、WAL capacity、GeoIP bytes/代数及队列 bytes。
- [ ] 组件预算覆盖主要分配，resident 估算与 RSS/PSS/cgroup 分层展示，无重复记账。
- [ ] 建立隔离 Linux 初始化阶段与 allocator live/retained 基线，记录仍未归属项。

验证：公式/采样解析定向测试，核对 shadow 状态字段兼容；存储观测无法提供 live bytes 时必须标为 capacity/unknown。

## T05：Mace 内存与重开兼容，P1 / M

文件：`src/metrics/storage.rs`、`src/memory_plan.rs`、`tests/mace_storage.rs`。
依赖：T04；背压开启依赖 T08。

- [ ] 1 GiB 候选保留 16 组、每组 2 MiB WAL，旧库 bucket 加载前更新兼容参数。
- [ ] 旧库、新库、大记录、非干净恢复和回退启动均验证；不得删除数据目录或静默使用旧大参数。
- [ ] 有效参数、初始化分配差值、RSS/anon、吞吐及 p99 对照完成，存储失败可观察。

验证：`cargo test --test mace_storage`，补充恢复子进程 fixture；同负载旧版/新版 mace-perf 对比。

## 检查点 B：首批候选

- [ ] T01 至 T05 集成通过，完成 Linux 1 GiB 预热与短时稳定性测试。
- [ ] 确认 WAL 224 MiB 的理论分配减少与实际 anon 变化之间的差异。
- [ ] 旧库兼容及参数回退演练通过，形成可灰度构建和验证记录。

## T06：配置去重，P1 / S

文件：`src/rpc/server.rs`、`src/config_apply.rs`。
依赖：T03。

- [ ] 按 server_id 和依赖版本识别有效配置，成功发布后才更新 fingerprint。
- [ ] 可替代配置队列同时限条数/bytes，合并不破坏 ACK 和有副作用命令语义。
- [ ] 重复配置不重建，失败版本可重试，全局依赖/is_on/删除变化不被误跳过。

验证：确定性配置 replay，包括无变化、乱序、失败、继承配置变化；量化 apply/reclaim/log 次数。

## T07：原子配置和启停，P1 / M

文件：`src/config.rs`、`src/config_apply.rs`、`src/rpc/node.rs`、`src/http_proxy_manager.rs`。
依赖：T06。

- [ ] 准备失败/预算不足保留最后有效代，不出现空路由，未变化对象可复用。
- [ ] 精确/通配/端口 SNI 索引排除停用站点，接入再次核对启用状态。
- [ ] 热更新中持续流量、旧代释放、健康状态与 listener 代次一致性通过。

验证：调整并运行 `cargo test --test config_sync_memory`，增加并发 lookup/发布与禁用站点测试。

## T08：统计与背压，P1 / M，分三次提交

文件：`src/memory_reclaim.rs`、`src/metrics/aggregator.rs`、`src/metrics.rs`、`src/metrics/storage.rs`、`src/rpc/stats.rs`。
依赖：T03、T05；在 T05 集成时先保留当前背压行为，T08 验证后启用。

- [ ] 压力 flush 的 rows 进入单一所有者流程，周期与压力并发不丢失/重复 drain。
- [ ] 队列按 bytes/条数有界，retry、合并、drop 各有明确策略与计数，计费数据不静默丢弃。
- [ ] begin/commit 失败可追踪并有界恢复，启用 Mace 背压后慢盘不阻塞 reactor、不无限积压。

验证：分别为 flush 所有权、队列饱和、存储失败/恢复做故障注入；核对前后累计总数。

## T09：GeoIP，P2 / M，分两次提交

文件：`src/metrics/analyzer.rs`、`src/metrics/storage.rs`、`src/rpc/files.rs`、`Cargo.toml`。
依赖：T04。

- [ ] ASN 的编号与名称查询共享 reader，不重复加载；其查询缓存有界。
- [ ] mmap 的所有写入者满足不截断旧 inode，校验失败不发布，旧 reader 最终释放。
- [ ] 同负载 anon/file-fault/延迟及并发更新峰值对照完成，unsafe 不变量审查通过。

验证：GeoIP fixture、`tests/waf_asn_visitor_ip.rs`、analyzer 定向测试；依赖变动后 `cargo check --all-targets`。

## T10：统计过期清理，P2 / S

文件：`src/metrics/storage.rs`、`src/metrics.rs`、`tests/mace_storage.rs`。
依赖：T05。

- [ ] 解析站点 key 的 period 判断过期，移除错误的 S0 词典序边界。
- [ ] 清理分批续扫，不误删 NODE_T、STAT_* 或其他前缀，不形成全量长事务。
- [ ] 多位 server_id、截止值、异常键、24 小时以上数据和 GC 滞后测试通过。

验证：实际 Mace 临时库写入/清理/重开后对比键集合与数值。

## 检查点 C

- [ ] 配置、统计和存储错误路径集成通过，队列和配置代数量有界。
- [ ] 固定基数持续变更下，数据库/队列/GeoIP 的增长均有可解释归属。

## T11：TCP 半关闭，P2 / S

文件：`src/tcp_proxy.rs`。
依赖：T01。

- [ ] 正常 EOF 仅关闭目标写半边，保留反向响应；hard error/取消单独处理。
- [ ] 等待有超时，但持续单向传输不误触发 idle。
- [ ] 上传后 FIN、延迟大响应、源站先 FIN、RST 和取消的内容/计数测试通过。

验证：扩展 `cargo test --lib relay`、`cargo test --lib sni`，Linux 上分别验证所支持的数据路径。

## T12：后台连接口径，P2 / M

文件：`src/metrics.rs`、`src/rpc/node.rs`、`src/http_proxy_manager.rs`、`src/tcp_proxy.rs`。
依赖：T02。

- [ ] 下游 transport、upstream、RPC、HTTP 请求/H2 stream、UDP/QUIC 分开定义。
- [ ] 先新增兼容 shadow 指标，后台消费者语义确认前不改变旧 wire 字段含义。
- [ ] 静态 fixture 中按同口径与 registry/socket 精确一致；线上采样标明时刻。

验证：HTTP/1 keepalive、H2 多流、SNI 与失败请求组合，核对字段类型和旧客户端兼容。

## T13：最终验证与灰度，M

文件：复用现有测试、性能脚本并新增本次复现 fixture/操作记录。
依赖：本次拟上线的所有任务；首批可独立先验证 T01 至 T05。

- [ ] 格式、定向测试、all-target check、完整确定性测试集和 Linux 矩阵通过。
- [ ] 1 GiB 约 261 站点固定基数 soak 完成，24 小时无意外 drain/OOM/计数残留，内存与性能门槛达标或明确记录未达原因。
- [ ] 单节点灰度、流量排空/切换、旧库参数回退演练与监控阈值记录完成。

验证：详见方案第 7、8 节。真实部署必须单独记录时间、版本、参数和结果，不能把文档任务勾选视为已部署。
