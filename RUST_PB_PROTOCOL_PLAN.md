# Rust Cloud-Node PB 协议补齐计划

## 1. 目标与范围

目标：以 `cloud-node/bin/output_protos` 中的最新 protobuf 协议为准，结合当前 Rust 实现和旧版 `EdgeNode-master` 的成熟逻辑，制定一份逐个 proto 对照的补齐计划，确保 Rust 版节点具备旧版 edge node 的完整运行能力，并完整支持 cloud-node 最新协议中与节点运行有关的功能。

本计划明确排除：

- 节点程序安装、升级、启动、停止、卸载等升级程序相关接口
- 仅供云端管理后台使用、且不属于节点运行时职责的纯控制面 CRUD 接口

## 2. 分析基线

### 2.1 当前 Rust 源码现状

当前 Rust 版本已经具备以下基础能力：

- protobuf 全量编译：`build.rs` 会编译 `cloud-node/bin/output_protos` 下所有 proto
- 基础节点启动：`src/main.rs`
- 配置同步与最小任务处理：`src/rpc.rs`
- HTTP/HTTPS 代理主链路：`src/proxy.rs`
- 动态证书选择：`src/ssl.rs`
- 基础缓存、回源、重写、头部处理、WAF 匹配、带宽/访问日志上报

但现状仍然是“阶段化/MVP”实现，明显缺口包括：

- `NodeStream` 只处理 `NewNodeTask`
- 节点任务类型只覆盖 `purgeServerCache` / `purgePathCache` / `preheatCache` / 部分生命周期任务
- 未实现旧版 edge node 的节点级配置增量同步、IP 列表增量同步、本地持久化、全局/用户配置更新、Agent IP、IP 库、OCSP、Daily Stat、NodeValue、MetricStat、WAF 事件通知等
- 大量 cloud-node proto 已编译但未在 Rust 侧使用

### 2.2 旧版 EdgeNode 参考实现重点

以下旧版实现是本计划的主要参照：

- RPC 客户端总表：`EdgeNode-master/internal/rpc/rpc_client.go`
- 节点配置与注册：`EdgeNode-master/internal/nodes/node.go`
- NodeStream：`EdgeNode-master/internal/nodes/api_stream.go`
- NodeTask 分发：`EdgeNode-master/internal/nodes/node_tasks.go`
- IP 列表同步：`EdgeNode-master/internal/iplibrary/manager_ip_list.go`
- WAF 事件通知：`EdgeNode-master/internal/waf/action_notify.go`
- WAF 自动记录 IP：`EdgeNode-master/internal/waf/action_record_ip.go`
- Access Log 上传：`EdgeNode-master/internal/nodes/http_access_log_queue.go`
- HTTP 请求统计：`EdgeNode-master/internal/stats/http_request_stat_manager.go`
- 带宽统计：`EdgeNode-master/internal/stats/bandwidth_stat_manager.go`
- Daily Stat：`EdgeNode-master/internal/stats/traffic_stat_manager.go`
- NodeValue：`EdgeNode-master/internal/monitor/value_queue.go`
- MetricStat：`EdgeNode-master/internal/metrics/task_kv.go`
- IP 库更新：`EdgeNode-master/internal/nodes/ip_library_updater.go`
- APINode 列表同步：`EdgeNode-master/internal/nodes/task_sync_api_nodes.go`
- 证书 OCSP：`EdgeNode-master/internal/nodes/task_ocsp_update.go`

## 3. 补齐原则

1. 先补“协议接入骨架”，再补“业务行为”。
2. 先补影响节点在线运行的接口，再补统计/优化/运维能力。
3. 以 `cloud-node` 最新 proto 为准，不再以旧 edge node 的 proto 版本为准。
4. 旧 edge node 仅作为行为参考，不能反向约束最新 proto。
5. 对每个 proto 服务明确标记：
   - `已接入`：Rust 已实际调用，且功能基本成立
   - `部分接入`：Rust 已有 client 或局部行为，但明显不完整
   - `未接入`：Rust 未使用
   - `控制面`：主要是云端管理接口，节点运行时不需要实现
   - `排除`：属于升级程序相关接口，本次不做

## 4. 按 Proto 逐项分析

### 4.1 核心节点控制与配置

| Proto | 服务 | 节点运行职责 | Rust 现状 | 旧版参考 | 补齐动作 |
| --- | --- | --- | --- | --- | --- |
| `service_ping.proto` | `PingService` | 探活 RPC Endpoint 可用性 | 未接入 | `rpc_client.go` 中用于 endpoint 测试 | 增加 endpoint 探测与故障切换，作为 APINode 列表更新后的连接验证基础 |
| `service_node.proto` | `NodeService` | 节点注册、拉取当前配置、状态上报、流式控制、节点级策略读取 | 部分接入 | `node.go`、`api_stream.go`、`node_tasks.go` | 补齐 `registerClusterNode`、`findCurrentNodeConfig` 的压缩/增量语义、`nodeStream` 全消息处理、`findNodeLevelInfo`、`findNodeGlobalServerConfig`、`findNodeDDoSProtection`、`findNodeTOAConfig`、`findNodeNetworkSecurityPolicy`、`findNodeWebPPolicies`、`findNodeAccessLogConfig`、`findNodeGRPCPolicies` 等节点运行接口；升级相关 RPC 标记排除 |
| `service_node_task.proto` | `NodeTaskService` | 拉取任务、回报任务完成 | 部分接入 | `node_tasks.go` | 以旧版任务分发模型为基准，补齐 `configChanged`、`ipItemChanged`、`nodeLevelChanged`、`ddosProtectionChanged`、`globalServerConfigChanged`、`userServersStateChanged`、`updatingServers`、`toaChanged`、`webPPolicyChanged`、`scriptsChanged`、`planChanged`、`networkSecurityPolicyChanged` 等；升级相关 task 类型排除 |
| `service_api_node.proto` | `APINodeService` | 获取可用 APINode、版本变更检测、切换控制面节点 | 未接入 | `node.go`、`task_sync_api_nodes.go` | 实现 APINode 列表同步、版本检测、连接漂移/切换，支撑多 endpoint 高可用 |
| `service_updating_server_list.proto` | `UpdatingServerListService` | 增量接收“更新中的服务”列表 | 未接入 | `node_tasks.go` | 增加更新中服务列表本地缓存，用于运行时屏蔽/特殊处理 |
| `service_plan.proto` | `PlanService` | 节点套餐/功能位同步 | 未接入 | `rpc_client.go`、`node_tasks_ext.go` | 先完成 client 接入与 plan 缓存结构，再将 plan 功能位接入功能开关 |
| `service_node_value.proto` | `NodeValueService` | 节点监控值上报 | 未接入 | `monitor/value_queue.go` | 建立节点监控值采集与批量上报链路，明确与 `updateNodeStatus` 的职责边界 |

### 4.2 服务配置、回源与业务面能力

| Proto | 服务 | 节点运行职责 | Rust 现状 | 旧版参考 | 补齐动作 |
| --- | --- | --- | --- | --- | --- |
| `service_server.proto` | `ServerService` | 组合服务配置、用户服务配置、HTTP 请求统计上传、缓存清理 | 部分接入 | `node.go`、`http_cache_task_manager.go`、`http_request_stat_manager.go` | 补齐 `composeServerConfig`、`composeAllUserServersConfig`、`purgeServerCache` 兼容路径、`uploadServerHTTPRequestStat` 的完整维度、TCP/UDP 端口发现、GRPC 配置、Traffic Limit 等与运行时相关接口 |
| `service_script.proto` | `ScriptService` | 节点脚本更新与脚本配置组合 | 未接入 | `rpc_client.go`、`node_tasks.go` | 增加脚本配置拉取、版本检查、落盘/热更新机制；若 Rust 版暂不支持脚本执行，需要在计划内明确替代方案或能力缺口 |
| `service_ssl_cert.proto` | `SSLCertService` | 节点证书配置、OCSP 更新 | 部分接入 | `task_ocsp_update.go` | 当前 Rust 仅消费配置中的证书数据做 SNI 选证；需补齐 OCSP 刷新、状态缓存、错误回退，以及最新 proto 中与节点运行相关的证书查询能力 |
| `service_acme_authentication.proto` | `ACMEAuthenticationService` | ACME challenge token -> key 查询 | 已接入 | `http_request_acme.go` | 核对字段名与 header 鉴权，补充缓存与限流，避免高频远程查询 |
| `service_file.proto` | `FileService` | 文件元信息获取 | 未接入 | `rpc_client.go` | 仅在 IP 库或其他运行时文件同步场景需要时接入；若当前最新流程只用 `FileChunkService`，则保留为次优先级 |
| `service_file_chunk.proto` | `FileChunkService` | 分片下载 IP 库等运行时文件 | 未接入 | `ip_library_updater.go` | 接入分片查询与下载，支持 IP 库、本地 artifact 更新等运行时文件同步 |
| `service_ip_library_artifact.proto` | `IPLibraryArtifactService` | 获取公共 IP 库 artifact | 未接入 | `ip_library_updater.go` | 实现 Geo/IP 库 artifact 版本检测、下载、校验、切换；与当前 MaxMind 本地库管理统一 |

### 4.3 IP 列表、WAF 与安全联动

| Proto | 服务 | 节点运行职责 | Rust 现状 | 旧版参考 | 补齐动作 |
| --- | --- | --- | --- | --- | --- |
| `service_ip_item.proto` | `IPItemService` | IP 条目增量同步、WAF 记录、黑白灰名单命中回写 | 部分接入 | `manager_ip_list.go`、`action_record_ip.go` | 将当前按 list 全量读取改为 `listIPItemsAfterVersion` 增量同步；补齐本地持久化、删除/过期处理、批量 `createIPItems`、状态一致性 |
| `service_ip_list.proto` | `IPListService` | IP 列表元信息、列表归属、listId/code 映射 | 未接入 | `rpc_client.go` | 增加列表元数据缓存，支撑 server/policy/global list 的解析与删除处理 |
| `service_firewall.proto` | `FirewallService` | 上报 WAF 事件、统计攻击拦截 | 未接入 | `action_notify.go` | 接入 `notifyHTTPFirewallEvent`；若 Rust 需要对齐新版行为，还要考虑 `countFirewallDailyBlocks` 的消费场景与全局看板所需元数据 |
| `service_http_cache_task_key.proto` | `HTTPCacheTaskKeyService` | 任务 key 下发与状态回报 | 部分接入 | `http_cache_task_manager.go` | 当前已支持 `findDoing...` / `update...`；需补齐 `validateHTTPCacheTaskKeys`、任务结果细节、集群维度字段、失败重试策略 |
| `service_server_deleted_content.proto` | `ServerDeletedContentService` | 已删除内容同步与缓存失效 | 未接入 | 无直接现成 Rust 逻辑 | 明确 cloud-node 当前是否仍用于节点清理已删除对象；若是，则加入缓存/磁盘清理链路 |

### 4.4 日志、指标与统计

| Proto | 服务 | 节点运行职责 | Rust 现状 | 旧版参考 | 补齐动作 |
| --- | --- | --- | --- | --- | --- |
| `service_node_log.proto` | `NodeLogService` | 节点日志上传 | 已接入 | `remotelogs/utils.go` | 补齐重试、批量发送、级别映射、断线缓冲 |
| `http_access_log_service.proto` | `HttpAccessLogService` | 访问日志批量上传 | 已接入 | `http_access_log_queue.go` | 统一 header 鉴权、字段映射、背压、失败落盘/有限重试 |
| `service_http_access_log.proto` | `HTTPAccessLogService` | 查询/管理访问日志 | 控制面 | 云端侧 | 节点运行时不需要实现 server 端逻辑；只需确认是否有任何节点侧必需消费接口，目前没有 |
| `service_metric_stat.proto` | `MetricStatService` | 指标批量上传 | 未接入 | `metrics/task_kv.go` | Rust 目前只有本地聚合和部分 HTTP 请求统计上传，需独立补齐 `uploadMetricStats` |
| `service_server_bandwidth_stat.proto` | `ServerBandwidthStatService` | 带宽与请求量周期上传 | 已接入 | `bandwidth_stat_manager.go` | 核对字段完整性、时间粒度、缓存流量/攻击流量口径、失败补偿 |
| `service_server_daily_stat.proto` | `ServerDailyStatService` | 服务日统计/小时统计上传 | 未接入 | `traffic_stat_manager.go` | 独立实现 Daily/Hourly/5Min 数据聚合与上传；这是 Rust 当前明显缺失的核心统计能力 |
| `service_server_top_ip_stat.proto` | `ServerTopIPStatService` | 热门 IP 统计上传或查询 | 未接入 | 旧版未见直接节点侧调用 | 核对 cloud-node 是否要求节点上报；如需要，新增 Top IP 聚合器 |
| `service_server_event.proto` | `ServerEventService` | 服务事件上报/查询 | 未接入 | 旧版未见明显调用 | 确认是否属于运行时必需；若 cloud-node 已将节点异常/事件统一归口到该服务，则纳入 P2 |

### 4.5 用户、Agent、权限与附加运行数据

| Proto | 服务 | 节点运行职责 | Rust 现状 | 旧版参考 | 补齐动作 |
| --- | --- | --- | --- | --- | --- |
| `service_user.proto` | `UserService` | 用户服务状态检测等节点运行辅助接口 | 未接入 | `node_tasks.go` | 至少补齐 `checkUserServersState`，用于 `userServersStateChanged` task；其余账户管理接口属于控制面 |
| `service_client_agent_ip.proto` | `ClientAgentIPService` | 客户端 Agent IP 上传与同步 | 未接入 | `utils/agents/queue.go`、`manager.go` | 增加 agent IP 队列、增量同步、本地缓存，决定是否影响 UA/IP 风险识别 |
| `service_authority_key.proto` | `AuthorityKeyService` | 权限 key 校验 | 控制面/次要 | `rpc_client.go` 仅预置 client | 若 Rust 节点暂不承担 authority 校验链路，可放 P3；先确认 cloud-node 最新节点职责 |
| `service_index.proto` | `IndexService` | KV 索引存取 | 控制面/次要 | 旧版节点侧未见常规调用 | 暂不纳入核心运行时；若最新 cloud-node 将边缘共享状态迁移到 IndexService，再补专门方案 |

### 4.6 纯控制面或本次明确不做

| Proto | 服务 | 结论 |
| --- | --- | --- |
| `service_api_node.proto` 中创建/更新/删除 APINode、部署文件上传等后台管理 RPC | 控制面，不要求 Rust 节点实现 server 端能力 |
| `service_server.proto` 中创建/删除/后台编辑类 RPC | 控制面，节点只需消费与运行时相关的方法 |
| `service_ssl_cert.proto` 中后台管理/解析/生成证书类 RPC | 控制面；节点只需消费运行时所需查询/OCSP 相关方法 |
| `service_user.proto` 中注册/登录/资料管理类 RPC | 控制面 |
| `service_authority_key.proto` 大部分方法 | 控制面 |
| `service_node.proto` 中 `installNode` / `upgradeNode` / `startNode` / `stopNode` / `uninstallNode` / `downloadNodeInstallationFile` 等 | 本次排除 |

## 5. 当前 Rust 与目标能力差距总结

### 5.1 已有但不完整

- `NodeService`
- `NodeTaskService`
- `ServerService`
- `NodeLogService`
- `HttpAccessLogService`
- `ServerBandwidthStatService`
- `IPItemService`
- `ACMEAuthenticationService`
- `HTTPCacheTaskKeyService`
- TLS 证书装载

### 5.2 明显缺失

- `APINodeService`
- `NodeValueService`
- `MetricStatService`
- `ServerDailyStatService`
- `UpdatingServerListService`
- `IPListService`
- `FirewallService`
- `SSLCertService` 的 OCSP/更新流程
- `ScriptService`
- `UserService` 的节点运行接口
- `ClientAgentIPService`
- `IPLibraryArtifactService`
- `FileChunkService`

### 5.3 行为层缺口

- NodeStream 消息类型基本未实现
- NodeTask 类型覆盖远低于旧版
- 配置同步没有压缩/增量/版本语义闭环
- 没有旧版 IPList 本地数据库与增量同步模型
- 统计体系缺少 Daily Stat、MetricStat、NodeValue
- WAF 联动缺少通知、批量记录 IP、删除名单联动
- APINode endpoint 漂移、高可用与自愈未实现
- IP 库/OCSP/Agent IP 等边缘运行时辅助能力未实现

## 6. 建议实施阶段

### P0: 协议基础与核心在线能力

- 重构 `src/rpc.rs`，按服务拆成独立 client 模块，统一鉴权、重试、压缩、endpoint 选择
- 补齐 `NodeService` 的运行时方法与 `NodeStream` 全消息分发
- 补齐 `NodeTaskService` 的任务表与 task handler 注册机制
- 将配置同步改成“全量 + 增量 + 版本 + 可压缩”的完整模型
- 补齐 `APINodeService`，支持 endpoint 自动切换

### P1: 服务配置与安全同步

- 补齐 `ServerService` 组合配置接口与用户服务配置同步
- 实现 `UpdatingServerListService`
- 以旧版 `manager_ip_list.go` 为基准，重建 `IPItemService` 增量同步与本地持久化
- 接入 `IPListService` 元数据
- 接入 `FirewallService` 通知与批量 `createIPItems`
- 补齐 `UserService.checkUserServersState`

### P2: 日志、指标、统计闭环

- 补齐 `MetricStatService.uploadMetricStats`
- 补齐 `ServerDailyStatService.uploadServerDailyStats`
- 完善 `ServerService.uploadServerHTTPRequestStat`
- 补齐 `NodeValueService`
- 升级日志上传的重试与缓冲策略

### P3: 证书、IP 库与边缘附加能力

- 接入 `SSLCertService` OCSP 更新
- 接入 `IPLibraryArtifactService` + `FileChunkService`
- 接入 `ClientAgentIPService`
- 接入 `ScriptService`
- 评估 `PlanService`、`AuthorityKeyService`、`ServerTopIPStatService`、`ServerEventService` 是否成为运行时刚需

## 7. 代码落地建议

建议新增以下模块边界，避免继续把所有 RPC 和业务耦合在 `src/rpc.rs`：

- `src/rpc/mod.rs`
- `src/rpc/auth.rs`
- `src/rpc/channel_pool.rs`
- `src/rpc/node.rs`
- `src/rpc/node_task.rs`
- `src/rpc/api_node.rs`
- `src/rpc/server.rs`
- `src/rpc/ip_list.rs`
- `src/rpc/firewall.rs`
- `src/rpc/logs.rs`
- `src/rpc/stats.rs`
- `src/rpc/files.rs`

同时建议建立能力注册表：

- `src/runtime/task_handlers.rs`
- `src/runtime/stream_handlers.rs`
- `src/runtime/feature_flags.rs`

## 8. 验收标准

Rust 版可视为“协议补齐完成”，至少需要满足以下条件：

1. `cloud-node/bin/output_protos` 中所有与节点运行有关的 service/rpc，均已明确归类为：已实现 / 控制面 / 排除。
2. 所有旧版 edge node 的运行时关键路径，在 Rust 版都有等价实现：
   - 配置同步
   - 任务同步
   - Stream 控制
   - IP 列表同步
   - 访问日志
   - 节点日志
   - HTTP 请求统计
   - 带宽统计
   - Daily Stat
   - WAF 通知与封禁记录
   - APINode 高可用
   - ACME
   - 证书 OCSP
   - IP 库更新
3. 排除项仅限升级程序相关接口，且文档中有明确说明。
4. 每个 proto 服务至少有一份集成测试或模拟测试，验证请求字段、header 鉴权、失败重试、版本推进语义。

## 9. 实施顺序结论

如果只按收益和风险排序，建议按下面顺序做：

1. `NodeService` / `NodeTaskService` / `NodeStream`
2. `APINodeService`
3. `ServerService`
4. `IPItemService` / `IPListService` / `FirewallService`
5. `HttpAccessLogService` / `NodeLogService`
6. `ServerBandwidthStatService` / `ServerDailyStatService` / `MetricStatService` / `NodeValueService`
7. `SSLCertService` / `ACMEAuthenticationService`
8. `IPLibraryArtifactService` / `FileChunkService`
9. `ClientAgentIPService` / `ScriptService` / `PlanService`

这份顺序的原因很简单：前四项决定节点能否“正确在线并持续收敛到最新配置”，后几项才是“观测、优化和运维增强”。
