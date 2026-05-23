# cloud-node-rust gRPC API 使用文档

本文档整理当前数据面会主动调用的控制面 gRPC 接口、请求内容、响应配置、解析方式和运行时用途。所有 gRPC 请求都会通过 `RpcClient` 注入认证 metadata：`nodeid`、`nodeId`、`token`，部分接口额外带 `type=edge`。默认开启 gzip 压缩，最大编码/解码消息大小为 512 MiB。

## 1. 节点配置与控制流

### NodeService.FindCurrentNodeConfig

- 调用位置：`src/rpc/node.rs`
- 请求：`FindCurrentNodeConfigRequest { version, compress: true, node_task_version, use_data_map: true }`
- 用途：拉取当前节点完整配置。
- 响应：`node_json`、`is_compressed`、`timestamp`、`is_changed`。
- 解析：如 `is_compressed=true`，先 Brotli 解压；随后解析为 `NodeConfigPayload`。
- 应用：更新节点 numeric id、全局 HTTP 配置、站点配置、缓存策略、WAF 策略、页面策略、证书、负载均衡、HTTP/3、UAM、CC、防火墙、访问日志、gRPC、WebP、TOA、DNS resolver 等运行时快照，并重建 compiled plan。

### NodeTaskService.FindNodeTasks

- 调用位置：`src/rpc/node_task.rs`
- 请求：`FindNodeTasksRequest { version }`
- 用途：按任务版本增量拉取控制面任务。
- 响应：`node_tasks[]`，包含 `id`、`version`、`type`、`server_id`、`user_id` 等。
- 解析和使用：
  - `configChanged`、`firewallPolicyChanged`、`cachePolicyChanged` 等：同步单站或触发完整配置同步。
  - `nodeLevelChanged`：同步节点层级和父节点。
  - `planChanged`：同步套餐。
  - `purgeServerCache`、`purgePathCache`、`preheatCache`：Leader 节点同步缓存任务。
  - `ipItemChanged`：同步 IP 名单条目。
  - `updatingServers`：同步正在更新的站点列表。
  - `userServersStateChanged`：同步用户站点启停状态。
  - `ipListDeleted@{...}`：本地删除名单元数据和已应用项目。

### NodeTaskService.ReportNodeTaskDone

- 调用位置：`src/rpc/node_task.rs`
- 请求：`ReportNodeTaskDoneRequest { node_task_id, is_ok, error }`
- 用途：任务处理完成后回报控制面。
- 应用：只有回报成功后才推进本地 task version，避免任务失败被跳过。

### NodeService.UpdateNodeUp

- 调用位置：`src/rpc/node.rs`
- 请求：`UpdateNodeUpRequest { node_id, is_up }`
- 用途：报告节点上线状态。
- 应用：启动或周期性维护节点在线状态。

### NodeService.UpdateNodeStatus

- 调用位置：`src/rpc/node.rs`、`src/rpc/node-status.rs`、`src/rpc/node-status-full.rs`
- 请求：`UpdateNodeStatusRequest`，包含节点 ID、系统负载、CPU、内存、连接数、流量、配置版本等状态字段。
- 用途：上报节点运行状态。
- RKE2 语义：只有 Leader 负责关键状态上报，避免多副本共用 nodeId 时重复覆盖。

### NodeService.UpdateNodeIsInstalled

- 调用位置：`src/rpc/node.rs`、`src/rpc/node_task.rs`
- 请求：`UpdateNodeIsInstalledRequest { node_id, is_installed }`
- 用途：报告安装/升级类任务完成。

### NodeService.UpdateNodeConnectedApiNodes

- 调用位置：`src/rpc/node.rs`
- 请求：`UpdateNodeConnectedApiNodesRequest { node_id, api_node_ids }`
- 用途：报告当前节点已连接的 API 节点列表。
- 数据来源：node stream 连接成功后记录 API node id，断开后移除。

### NodeStream

- 调用位置：`src/rpc/stream.rs`
- 传输：手工构造 HTTP/2 gRPC stream，请求路径为 node stream 服务路径，metadata 注入 `nodeid` 和 `token`。
- 发送：周期性 `NodeStreamMessage { node_id, code: "ping", is_ok: true }`。
- 接收：控制面推送任务和配置变更事件，触发本地任务同步。
- 用途：减少纯轮询延迟，让配置和任务更快生效。

## 2. 站点配置、状态和套餐

### ServerService.ComposeServerConfig

- 调用位置：`src/rpc/server.rs`
- 请求：`ComposeServerConfigRequest { server_id }`
- 用途：同步单个站点完整运行配置。
- 响应：`server_config_json`。
- 解析：解析为 `ServerConfig`。
- 应用：按 server/user scope 替换运行时站点、域名路由、负载均衡、健康检查、缓存/WAF/auth/rewrite/header/限速等配置，并同步套餐。

### UserService.CheckUserServersState

- 调用位置：`src/rpc/server.rs`
- 请求：`CheckUserServersStateRequest { user_id }`
- 用途：检查用户站点整体是否启用。
- 应用：用户禁用时移除该用户所有运行时站点。

### ServerService.ComposeAllUserServersConfig

- 调用位置：`src/rpc/server.rs`
- 请求：`ComposeAllUserServersConfigRequest { user_id }`
- 用途：同步某个用户的全部站点配置。
- 响应：`servers_config_json`。
- 解析：解析为 `Vec<ServerConfig>`。
- 应用：批量替换用户站点运行时 map 和路由 map。

### UpdatingServerListService.FindUpdatingServerLists

- 调用位置：`src/rpc/api_node.rs`
- 请求：`FindUpdatingServerListsRequest { last_id }`
- 用途：拉取正在更新中的站点列表。
- 应用：对命中的站点使用维护/更新态处理，避免请求进入不稳定配置。

### PlanService.FindServerUserPlan

- 调用位置：`src/rpc/plan.rs`
- 请求：`FindServerUserPlanRequest { server_id }`
- 用途：查询站点绑定的用户套餐关系。
- 应用：用于上传大小限制、功能能力和资源限制判断。

### PlanService.FindEnabledPlan / FindBasicPlan

- 调用位置：`src/rpc/plan.rs`
- 请求：`FindEnabledPlanRequest { plan_id }`，失败时回退 `FindBasicPlanRequest { plan_id }`。
- 用途：同步套餐配置。
- 应用：解析套餐容量、上传大小、功能开关等限制并写入 `ConfigStore`。

### ServerService.UploadServerHttpRequestStat

- 调用位置：`src/rpc/stats.rs`
- 请求：`UploadServerHttpRequestStatRequest`，包含站点请求数、状态码分布、流量、缓存命中、延迟等聚合统计。
- 用途：上报 HTTP 请求统计。
- 应用：控制面展示站点请求和性能数据。

### ServerEventService.CreateServerEvent

- 调用位置：`src/rpc/events.rs`
- 请求：`CreateServerEventRequest`，包含站点 ID、事件类型、级别、内容等。
- 用途：上报站点运行事件。

## 3. 缓存任务、缓存同步和文件

### HttpCacheTaskKeyService.FindDoingHttpCacheTaskKeys

- 调用位置：`src/rpc/cache.rs`
- 请求：`FindDoingHttpCacheTaskKeysRequest { size: 100 }`
- 用途：获取待处理缓存任务 key。
- 任务类型：purge server/path/key、preheat 等。
- 应用：Leader 节点执行本地 cache purge/preheat，并在 RKE2 下通过内部 API fanout 到其他 pod。

### HttpCacheTaskKeyService.UpdateHttpCacheTaskKeysStatus

- 调用位置：`src/rpc/cache.rs`
- 请求：`UpdateHttpCacheTaskKeysStatusRequest { ids, status, error }`
- 用途：回报缓存任务处理结果。

### ServerDeletedContentService.ListServerDeletedContentsAfterVersion

- 调用位置：`src/rpc/utils.rs`
- 请求：`ListServerDeletedContentsAfterVersionRequest { version, size }`
- 用途：同步已删除内容版本。
- 应用：构建 deleted content map，用于缓存和内容生命周期判断。

### IpLibraryArtifactService.FindPublicIpLibraryArtifact

- 调用位置：`src/rpc/files.rs`
- 请求：`FindPublicIpLibraryArtifactRequest {}`
- 用途：查找 GeoIP/IP 库制品。
- 应用：决定是否下载/更新本地 IP 库。

### FileChunkService.FindAllFileChunkIds / DownloadFileChunk

- 调用位置：`src/rpc/files.rs`
- 请求：`FindAllFileChunkIdsRequest`、`DownloadFileChunkRequest`。
- 用途：按 chunk 下载控制面文件制品。
- 应用：用于 GeoIP/IP 库等大文件分块同步。

### SslCertService.ListUpdatedSslCertOcsp

- 调用位置：`src/rpc/ssl.rs`
- 请求：`ListUpdatedSslCertOcspRequest { version, size: 100 }`
- 用途：增量同步 OCSP staple 数据。
- 应用：更新动态证书选择器内的 OCSP 数据，TLS 握手时直接读取快照。

### AcmeAuthenticationService.FindACMEAuthenticationKeyWithToken

- 调用位置：`src/rpc/acme.rs`
- 请求：`FindACMEAuthenticationKeyWithTokenRequest { token }`
- 用途：处理 `/.well-known/acme-challenge/` 请求时查找 ACME key authorization。
- 应用：命中后直接由边缘节点返回挑战内容。

## 4. WAF、IP 名单和安全事件

### FirewallService.NotifyHttpFirewallEvent

- 调用位置：`src/rpc/firewall.rs`
- 请求：`NotifyHttpFirewallEventRequest`，包含 node/server/policy/group/set/rule、客户端 IP、URL、action、level、tags 等。
- 用途：WAF 命中事件上报。
- 应用：控制面审计、告警和 WAF 日志展示。

### IpListService.ListEnabledIpLists

- 调用位置：`src/rpc/ip_list.rs`
- 请求：`ListEnabledIpListsRequest { type: "cluster", offset, size }`
- 用途：分页拉取启用的 IP 名单 metadata。
- 响应：`ip_lists[]`，包含 id、code、type、is_global 等。
- 应用：本地维护 list id -> 名单类型/作用域映射，供增量 IP item 应用时判断黑/白/灰和 global/site scope。

### IpItemService.ListIpItemsAfterVersion

- 调用位置：`src/rpc/ip_list.rs`
- 请求：`ListIpItemsAfterVersionRequest { version, size: 5000 }`
- 用途：增量同步 IP 名单条目。
- 响应：`ip_items[]` 和新版本号。
- 解析：解析 IP、CIDR、过期时间、删除标记、list type、serverId、is_global。
- 应用：写入 `WafStateManager` 黑/白/灰名单。所有 item 成功应用后才推进版本。

### IpItemService.ListIpItemsWithListId

- 调用位置：`src/rpc/ip_list.rs`
- 请求：`ListIpItemsWithListIdRequest { ip_list_id }`
- 用途：按名单 ID 拉取全部条目。
- 应用：用于特定名单引用或调试/补偿同步。

### IpListService.FindEnabledIpList

- 调用位置：`src/rpc/ip_list.rs`
- 请求：`FindEnabledIpListRequest { ip_list_id }`
- 用途：按 ID 查找启用名单 metadata。
- 应用：存在则更新 metadata，不存在则移除本地名单和对应条目。

### IpItemService.CreateIpItem

- 调用位置：`src/rpc/ip_list.rs`
- 请求：`CreateIpItemRequest { ip_list_id, value, reason }`
- 用途：单条记录 IP 到指定名单。
- 应用：WAF action 或手动逻辑触发名单记录。

### IpItemService.CreateIpItems

- 调用位置：`src/rpc/ip_report.rs`
- 请求：`CreateIpItemsRequest { ip_items[] }`
- 用途：批量上报黑/白/灰名单 item。
- 数据：包含 `ip_list_id`、IP、server scope、source node、过期时间、reason、level、trigger 等。
- 应用：控制面持久化后由各节点增量同步，实现跨节点名单传播。

### IpListService.FindIpListIdWithCode / CreateIpList

- 调用位置：`src/rpc/ip_report.rs`
- 请求：`FindIpListIdWithCodeRequest { code }`，必要时 `CreateIpListRequest { code, name, type, is_global }`。
- 用途：当 WAF action 没有显式 `ipListId` 时，按 scope/type 解析或创建名单。
- 应用：确保全局/站级黑白灰 action 能落到正确名单。

## 5. 日志、指标和统计

### HttpAccessLogService.CreateHttpAccessLogs

- 调用位置：`src/log_uploader.rs`
- 请求：`CreateHttpAccessLogsRequest { logs[] }`
- 用途：批量上传访问日志。
- 数据：请求/响应状态、host、URL、method、客户端 IP、headers/cookies/attrs/tags、WAF 命中、缓存命中、延迟、流量、origin 信息等。
- 应用：日志字段按控制面配置惰性生成；发送前按 protobuf 编码大小拆 chunk；失败进入 retry queue。

### NodeLogService.CreateNodeLogs

- 调用位置：`src/log_uploader.rs`、`src/rpc/logs.rs`
- 请求：`CreateNodeLogsRequest { node_logs[] }`
- 用途：上报节点运行日志、错误和诊断事件。
- 应用：服务端配置同步失败、站点解析失败、运行时错误等通过该接口上报。

### ServerBandwidthStatService.UploadServerBandwidthStats

- 调用位置：`src/rpc/stats.rs`
- 请求：`UploadServerBandwidthStatsRequest { stats[] }`
- 用途：上报按时间窗口聚合的站点带宽统计。

### ServerDailyStatService.UploadServerDailyStats

- 调用位置：`src/rpc/stats.rs`
- 请求：`UploadServerDailyStatsRequest { stats[] }`
- 用途：上报按天聚合的站点统计。

### MetricStatService.UploadMetricStats

- 调用位置：`src/rpc/stats.rs`
- 请求：`UploadMetricStatsRequest { stats[] }`
- 用途：上报自定义 metric items。
- 数据来源：控制面下发 metric item 配置，本地按配置采样/聚合。

### ServerTopIpStatService.UploadServerTopIpStats

- 调用位置：`src/rpc/stats.rs`
- 请求：`UploadServerTopIpStatsRequest { stats[] }`
- 用途：上报站点 Top IP 统计。

### NodeValueService.CreateNodeValues

- 调用位置：`src/rpc/node.rs`、`src/rpc/node-status-full.rs`
- 请求：`CreateNodeValuesRequest { node_value_items[] }`
- 用途：上报节点级时间序列指标。
- 数据：CPU、内存、连接、流量、缓存等节点值。

### NodeService.FindNodeLevelInfo

- 调用位置：`src/rpc/mod.rs`、`src/rpc/stats.rs`
- 请求：`FindNodeLevelInfoRequest {}`
- 用途：查询节点层级、父节点和回源层级信息。
- 应用：配置 `node_level`、父节点列表、分层回源策略和统计聚合语义。

## 6. API 节点、客户端代理和连通性

### ApiNodeService.FindAllEnabledApiNodes

- 调用位置：`src/rpc/api_node.rs`
- 请求：`FindAllEnabledApiNodesRequest {}`
- 用途：获取所有可用 API 节点。
- 应用：动态更新 runtime RPC endpoints，提升控制面连接容错能力。

### PingService.Ping

- 调用位置：`src/rpc/client.rs`
- 请求：`PingRequest {}`
- 用途：检测 gRPC endpoint 可用性。
- 应用：`RpcClient` 建连时选择可用控制面 endpoint。

### ClientAgentIpService.CreateClientAgentIPs

- 调用位置：`src/client_agent.rs`
- 请求：`CreateClientAgentIPsRequest { ips[] }`
- 用途：上报客户端代理 IP。
- 应用：控制面维护 client agent IP 池。

## 7. 运行时内部 API（RKE2 pod 间，不是控制面 gRPC）

RKE2 模式还启用 pod 内部 HTTP API，默认监听 `0.0.0.0:19090`，通过 `CLOUD_NODE_CLUSTER_INTERNAL_TOKEN` 鉴权，Headless Service 暴露给同 namespace 内其他 cloud-node pod。

- `GET /internal/v1/health`：健康检查，Kubernetes probe 使用。
- `POST /internal/v1/purge`：Leader 将 cache purge fanout 到其他 pod。
- `POST /internal/v1/metadata/events`：同步 cache metadata 事件。
- `POST /internal/v1/stats/snapshot`：上报 pod 本地统计快照给 Leader 聚合。
- `GET /internal/v1/cache/stat`：查询 pod 本地缓存对象数量和大小。

## 8. 配置解析总览

- 控制面主配置通过 `NodeConfigPayload` 进入 `ConfigStore`，热路径读取 `HotPathSnapshot` 和 `CompiledPlanSet`。
- 站点配置通过 `ServerConfig` 解析，重建域名路由、port-only 路由、负载均衡、缓存、WAF、rewrite、headers、auth、request limit、WebSocket、HLS、gRPC、HTTP/3 等模块。
- WAF 配置通过 `HTTPFirewallPolicy`、`HTTPFirewallInboundConfig`、`HTTPFirewallRuleGroup`、`HTTPFirewallRuleSet` 解析；compiled path 用于请求热路径，legacy path 作为 fallback。
- IP 名单配置分 metadata 和 item 两部分：metadata 决定名单类型/作用域，item 决定具体 IP/CIDR、过期时间、删除状态和 server scope。
- RKE2 runtime 配置来自 `/etc/cloud-node/configs/runtime.yaml`，决定 cluster mode、Leader 选举、内部 API、缓存分片和本地 metadata 目录。
