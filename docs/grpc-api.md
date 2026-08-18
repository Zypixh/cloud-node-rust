# cloud-node-rust gRPC API 使用文档

本文档只覆盖当前 Rust 数据面会主动调用的控制面 gRPC 接口。字段说明以 2026-05-26 对真实控制面节点凭据采样为准；写接口未为了文档造数据，因此写接口的响应按 proto 和运行时调用语义说明为准。

认证由 `RpcClient` 统一注入 metadata：`nodeid`、`nodeId`、`token`。`*_with_type()` 客户端额外注入 `type=node`，token 角色也保持为 `node`。默认 gzip 压缩，最大编码/解码消息大小为 512 MiB。真实采样入口是 `tests/real_api_config.rs` 中的 `real_api_grpc_documentation_snapshot`，需要显式设置 `CLOUD_NODE_REAL_API_TEST=1` 与 `CLOUD_NODE_REAL_API_DOC_SNAPSHOT=1`。

## 1. 节点配置与控制流

### NodeService.FindCurrentNodeConfig

- 调用位置：`src/rpc/node.rs`
- 请求：`FindCurrentNodeConfigRequest { version, compress: true, node_task_version, use_data_map: true }`
- 响应 proto：`nodeJSON: bytes`、`isChanged: bool`、`isCompressed: bool`、`dataSize: int64`、`timestamp: int64`
- 实测响应：`isChanged=true`、`isCompressed=true`、`dataSize=45562`、`nodeJSON` 压缩后 45562 bytes，Brotli 解压后 173818 bytes，`timestamp=1779809480`
- `nodeJSON` 实测顶层字段：`id`、`nodeId`、`name`、`secret`、`version`、`edition`、`isOn`、`level`、`groupId`、`regionId`、`allowedIPs`、`ipAddresses`、`apiNodeAddrs`、`dataMap`、`globalServerConfig`、`servers`、`metricItems`、`plans`、`httpCachePolicies`、`httpFirewallPolicies`、`grpcPolicies`、`primaryGRPCPolicy`、`http3Policies`、`httpCCPolicies`、`httpPagesPolicies`、`uamPolicies`、`webpImagePolicies`、`toa`、`networkSecurityPolicy`、`systemServices`、`clock`、`commonScripts`、`productConfig`、`enableIPLists`、`enablePlans`、`updatingServerListId`、`ocspVersion`
- 实测计数：`servers` 11 个，`metricItems` 8 个，`httpCachePolicies` 1 个，`httpFirewallPolicies` 1 个，`grpcPolicies` 1 个，`primaryGRPCPolicy` 非空，`sslCerts` 0 个
- 关键 JSON 形状：
  - `dataMap.Map`：key 形如 `CDN_DATA_MAP:<md5>`，value 为字符串
  - `globalServerConfig.httpAll`：包含 `serverName`、`forceLnRequest`、`lnRequestSchedulingMethod`、`supportsLowVersionHTTP`、`matchCertFromAllServers`、`enableServerAddrVariable`、`requestOriginsWithEncodings`、`xffMaxAddresses`、`allowLocalOrigins`
  - `grpcPolicies["2"]` 与 `primaryGRPCPolicy`：`isOn`、`maxReceiveMessageBytes`、`maxReceiveMessageSize`、`maxSendMessageBytes`、`maxSendMessageSize`
  - `servers[]`：`id`、`userId`、`name`、`type`、`isOn`、`clusterId`、`serverNames[]`、`aliasServerNames[]`、`http`、`https`、`reverseProxy`、`reverseProxyRef`、`web`、`grpc`、`uam`、`tcp`、`udp`、`trafficLimit`、`trafficLimitStatus`
- 应用：解析为 `NodeConfigPayload`，更新节点 numeric id、全局 HTTP 配置、站点配置、缓存策略、WAF 策略、页面策略、证书、负载均衡、HTTP/3、UAM、CC、防火墙、访问日志、gRPC、WebP、TOA、DNS resolver 等运行时快照，并重建 compiled plan。

### NodeTaskService.FindNodeTasks

- 调用位置：`src/rpc/node_task.rs`
- 请求：`FindNodeTasksRequest { version }`
- 响应 proto：`nodeTasks[]`
- `nodeTasks[]` 字段：`id`、`type`、`isDone`、`isOk`、`error`、`updatedAt`、`version`、`isPrimary`、`serverId`、`userId`
- 实测：以 `version=0` 拉取时返回空数组。
- 运行时处理的任务类型：`configChanged`、`ddosProtectionChanged`、`globalServerConfigChanged`、`uamPolicyChanged`、`httpCCPolicyChanged`、`http3PolicyChanged`、`httpPagesPolicyChanged`、`toaChanged`、`networkSecurityPolicyChanged`、`webPPolicyChanged`、`accessLogChanged`、`dnsResolverChanged`、`grpcPolicyChanged`、`scheduleChanged`、`apiConfigChanged`、`indexNodeConfigChanged`、`cachePolicyChanged`、`firewallPolicyChanged`、`nodeLevelChanged`、`planChanged`、`purgeServerCache`、`purgePathCache`、`preheatCache`、`ipItemChanged`、`updatingServers`、`userServersStateChanged`、`upgradeNode`、`installNode`、`startNode`、`scriptsChanged`

### NodeTaskService.ReportNodeTaskDone

- 调用位置：`src/rpc/node_task.rs`
- 请求：`ReportNodeTaskDoneRequest { node_task_id, is_ok, error }`
- 响应：`RPCSuccess {}` 空消息
- 采样说明：未对真实任务做完成回报，避免改变控制面任务游标。
- 应用：只有回报成功后才推进本地 task version。

### NodeService.UpdateNodeStatus

- 调用位置：`src/rpc/node.rs`、`src/rpc/node-status.rs`、`src/rpc/node-status-full.rs`
- 请求：`UpdateNodeStatusRequest { node_id, status_json }`
- 响应：`RPCSuccess {}` 空消息
- `status_json` 由运行时代码构造，字段包括：`buildVersion`、`buildVersionCode`、`configVersion`、`os`、`arch`、`hostname`、`hostIP`、`exePath`、`cpuUsage`、`cpuLogicalCount`、`cpuPhysicalCount`、`memoryUsage`、`memoryTotal`、`diskUsage`、`diskTotal`、`diskMaxUsage`、`diskMaxUsagePartition`、`load1m`、`load5m`、`load15m`、`trafficInBytes`、`trafficOutBytes`、`connectionCount`、`apiSuccessPercent`、`apiAvgCostSeconds`、`cacheTotalDiskSize`、`updatedAt`、`timestamp`、`isActive`、`isHealthy`
- RKE2 语义：只有 Leader 负责关键状态上报，多副本统计会先在集群内部聚合。

### NodeService.FindNodeLevelInfo

- 调用位置：`src/rpc/mod.rs`、`src/rpc/stats.rs`
- 请求：`FindNodeLevelInfoRequest {}`
- 响应 proto：`level: int32`、`parentNodesMapJSON: bytes`
- 实测响应：`level=1`，`parentNodesMapJSON` 为 `{}`，长度 2 bytes
- 应用：更新节点层级、父节点映射、分层回源和统计聚合语义。

### NodeService.FindEnabledNodeConfigInfo

- 调用位置：`src/rpc/node.rs`
- 请求：`FindEnabledNodeConfigInfoRequest { node_id }`
- 预期响应字段：`hasDNSInfo`、`hasCacheInfo`、`hasThresholds`、`hasSSH`、`hasSystemSettings`、`hasDDoSProtection`、`hasScheduleSettings`、`hasAccessLogSettings`
- 实测结果：节点凭据返回错误 `not supported node type: 'node'`。运行时已按 unsupported 处理，不把它作为必须成功的配置入口。

### NodeService.UpdateNodeConnectedAPINodes

- 调用位置：`src/rpc/node.rs`
- 请求：`UpdateNodeConnectedAPINodesRequest { api_node_ids }`
- 响应：`RPCSuccess {}` 空消息
- 数据来源：node stream 连接成功后记录 API node id，断开后移除。仅有已连接 API node id 时上报。

### NodeService.UpdateNodeUp / UpdateNodeIsInstalled

- 当前状态：不再作为节点侧正常运行路径调用。
- 原因：代码注释明确说明 `updateNodeUp` / `updateNodeIsInstalled` 在 cloud API 下需要管理端凭据，节点凭据会失败。节点侧使用 `UpdateNodeStatus` 表达在线/健康状态。

### NodeStream

- 调用位置：`src/rpc/stream.rs`
- 传输：手工构造 HTTP/2 gRPC stream，请求路径为 NodeService 的 `nodeStream`
- 发送：周期性 `NodeStreamMessage { node_id, code: "ping", is_ok: true }`
- 接收字段：`nodeId`、`requestId`、`timeoutSeconds`、`code`、`dataJSON`、`isOk`、`message`
- 应用：接收控制面推送的任务和配置变更事件，触发本地任务同步。

## 2. 站点配置、状态和套餐

### ServerService.ComposeServerConfig

- 调用位置：`src/rpc/server.rs`
- 请求：`ComposeServerConfigRequest { server_id }`
- 响应 proto：`serverConfigJSON: bytes`
- 实测：对 `server_id=22` 返回 `serverConfigJSON` 15225 bytes，可解析为单个 `ServerConfig`
- 实测顶层字段：`id`、`userId`、`name`、`description`、`type`、`isOn`、`clusterId`、`supportCNAME`、`cnameAsDomain`、`cnameDomain`、`serverNames[]`、`aliasServerNames[]`、`http`、`https`、`reverseProxy`、`reverseProxyRef`、`group`、`web`、`grpc`、`uam`、`tcp`、`tls`、`udp`、`trafficLimit`、`trafficLimitStatus`、`httpCachePolicy`、`httpCachePolicyId`、`httpFirewallPolicy`、`httpFirewallPolicyId`、`userPlan`
- 实测嵌套形状：
  - `serverNames[]`：`name`、`type`、`subNames`
  - `http`：`isOn`、`listen[]`
  - `https`：`isOn`、`listen[]`、`sslPolicy`、`sslPolicyRef`
  - `reverseProxy`：`id`、`isOn`、`primaryOrigins[]`、`backupOrigins`、`requestHost`、`requestURI`、`addHeaders[]`、`connTimeout`、`readTimeout`、`idleTimeout`、`maxConns`、`maxIdleConns`、`maxFails`、`followRedirects`、`retry40X`、`retry50X`、`stripPrefix`、`proxyProtocol`
  - `web`：`accessLog`、`cache`、`remoteAddr`、`shutdown`、`statRef`、`websocket`、`websocketRef` 等；未配置项实测多为 `null`
- 空响应语义：若 `serverConfigJSON` 为空，运行时会移除该 server。

### UserService.CheckUserServersState

- 调用位置：`src/rpc/server.rs`
- 请求：`CheckUserServersStateRequest { user_id }`
- 响应 proto：`CheckUserServersStateResponse { is_enabled }`
- 实测：`user_id=2` 返回 `isEnabled=true`
- 应用：用户禁用时移除该用户所有运行时站点。

### ServerService.ComposeAllUserServersConfig

- 调用位置：`src/rpc/server.rs`
- 请求：`ComposeAllUserServersConfigRequest { user_id }`
- 响应 proto：`serversConfigJSON: bytes`
- 实测：对 `user_id=2` 返回 628635 bytes，可解析为 `Vec<ServerConfig>`，数组长度 47
- 实测 item 形状与 `ComposeServerConfig` 相同；本次数组样本中的 `web` 还出现了 `auth`、`cache`、`compression`、`redirectToHTTPS`、`locations[]`、`locationRefs[]`、`requestLimit`、`remoteAddr`、`websocket` 等非空对象。
- 空响应语义：若 `serversConfigJSON` 为空，运行时移除该用户全部站点。

### UpdatingServerListService.FindUpdatingServerLists

- 调用位置：`src/rpc/api_node.rs`
- 请求：`FindUpdatingServerListsRequest { last_id }`
- 响应 proto：`serversJSON: bytes`、`maxId: int64`
- 实测：`maxId=0`，`serversJSON` 为空
- 非空语义：`serversJSON` 解析为 `Vec<ServerConfig>`，用于替换更新中的站点运行时配置。

### ServerService.FindServerUserPlan

- 调用位置：`src/rpc/plan.rs`
- 请求：`FindServerUserPlanRequest { server_id }`
- 响应 proto：`FindServerUserPlanResponse { userPlan }`
- 实测结果：对 `server_id=22` 使用节点凭据返回错误 `not supported node type: 'node'`
- 运行时处理：`sync_active_plans()` 对该错误只记录一次 debug 并返回 false；当前主配置 `nodeJSON.plans` 已包含可用套餐摘要。

### PlanService.FindEnabledPlan / FindBasicPlan

- 调用位置：`src/rpc/plan.rs`
- 请求：`FindEnabledPlanRequest { plan_id }`；失败后回退 `FindBasicPlanRequest { plan_id }`
- 响应 proto：`FindEnabledPlanResponse { plan }` / `FindBasicPlanResponse { plan }`
- 本次采样未触发成功响应：所选实测 server 的 `userPlanId` 为 0，且 `FindServerUserPlan` 已被节点凭据拒绝。
- `Plan` 字段来自 proto，只有成功返回时才可视为控制面实测值：`id`、`isOn`、`name`、`description`、`clusterId`、`trafficLimitJSON`、`bandwidthLimitPerNodeJSON`、`featuresJSON`、`maxUploadSizeJSON`、`priceType`、`trafficPriceJSON`、`bandwidthPriceJSON`、`monthlyPrice`、`seasonallyPrice`、`yearlyPrice`、`hasFullFeatures`、`totalServers`、`lbMode`

## 3. 缓存任务、删除内容、文件和证书

### HTTPCacheTaskKeyService.FindDoingHTTPCacheTaskKeys

- 调用位置：`src/rpc/cache.rs`
- 请求：`FindDoingHTTPCacheTaskKeysRequest { size: 100 }`
- 响应 proto：`httpCacheTaskKeys[]`
- 实测：返回空数组
- 非空 item 字段：`id`、`taskId`、`key`、`type`、`keyType`、`isDone`、`isDoing`、`errorsJSON`、`nodeClusterId`
- 运行时处理：`type=purge` 执行 key/prefix/tag purge；`type=preheat` 发本地预热请求；RKE2 Leader 会 fanout 到其他 pod。

### HTTPCacheTaskKeyService.UpdateHTTPCacheTaskKeysStatus

- 调用位置：`src/rpc/cache.rs`
- 请求：`UpdateHTTPCacheTaskKeysStatusRequest { key_results[] }`
- `key_results[]` 字段：`id`、`node_cluster_id`、`error`
- 响应：`RPCSuccess {}` 空消息
- 采样说明：未构造缓存任务回报，避免改变控制面任务状态。

### ServerDeletedContentService.ListServerDeletedContentsAfterVersion

- 调用位置：`src/rpc/utils.rs`
- 请求：`ListServerDeletedContentsAfterVersionRequest { version, size }`
- 响应 proto：`serverDeletedContents[]`
- 实测：以 `version=0,size=5` 返回空数组
- 非空 item 字段：`id`、`adminId`、`serverId`、`url`、`reasonType`、`version`、`createdAt`、`isDeleted`
- 应用：构建本地 deleted content map，用于缓存和内容生命周期判断。

### IPLibraryArtifactService.FindPublicIPLibraryArtifact

- 调用位置：`src/rpc/files.rs`
- 请求：`FindPublicIPLibraryArtifactRequest {}`
- 响应 proto：`ipLibraryArtifact`
- 实测：`ipLibraryArtifact=null`
- 非空字段：`id`、`fileId`、`createdAt`、`metaJSON`、`isPublic`、`name`、`code`、`file`
- `file` 字段：`id`、`filename`、`size`、`createdAt`、`isPublic`、`mimeType`、`type`
- 应用：有公开制品且 `fileId` 变化时，下载 GeoIP/IP 库。

### FileChunkService.FindAllFileChunkIds / DownloadFileChunk

- 调用位置：`src/rpc/files.rs`
- 请求：`FindAllFileChunkIdsRequest { file_id, access_ticket }`、`DownloadFileChunkRequest { file_chunk_id, access_ticket }`
- 响应：`FindAllFileChunkIdsResponse { file_chunk_ids[] }`、`DownloadFileChunkResponse { file_chunk.data }`
- 本次采样未触发：公开 IP 库制品为 `null`，没有可下载 `fileId`。
- 应用：按 chunk 下载大文件制品并写入本地目标文件。

### SSLCertService.ListUpdatedSSLCertOCSP

- 调用位置：`src/rpc/ssl.rs`
- 请求：`ListUpdatedSSLCertOCSPRequest { version, size }`
- 响应 proto：`sslCertOCSP[]`
- 实测：以 `version=0,size=5` 返回 5 条；item 字段为 `sslCertId`、`data`、`version`、`expiresAt`
- 实测样本：`sslCertId=50,dataBytes=0,version=10313,expiresAt=0`；其余样本 `dataBytes=504`，`version` 包括 `339650`、`445197`、`503708`、`507883`
- 应用：按 `sslCertId` 更新动态证书选择器内的 OCSP staple 数据，并用最大 `version` 推进游标。

### ACMEAuthenticationService.FindACMEAuthenticationKeyWithToken

- 调用位置：`src/rpc/acme.rs`
- 请求：`FindACMEAuthenticationKeyWithTokenRequest { token }`
- 响应 proto：`key: string`
- 实测：探测 token 返回空字符串
- 运行时语义：空字符串视为 `Missing`；非空时直接返回 ACME key authorization。

## 4. WAF、IP 名单和安全事件

### IPItemService.ListIPItemsAfterVersion

- 调用位置：`src/rpc/ip_list.rs`
- 请求：`ListIPItemsAfterVersionRequest { version, size }`
- 响应 proto：`ipItems[]`、`version`
- 实测：以 `version=0,size=10` 返回 10 条，响应 `version=1731077`
- 实测 item 字段：`id`、`value`、`ipFrom`、`ipTo`、`version`、`expiredAt`、`reason`、`listId`、`isDeleted`、`type`、`eventLevel`、`listType`、`isGlobal`、`createdAt`、`nodeId`、`serverId`、`sourceNodeId`、`sourceServerId`、`sourceHTTPFirewallPolicyId`、`sourceHTTPFirewallRuleGroupId`、`sourceHTTPFirewallRuleSetId`、`sourceURL`、`sourceUserAgent`、`isRead`
- 实测样本：`value` 为 IPv4，`type="ipv4"`，`listType` 包括 `white` / `black`，`eventLevel="error"`，样本均 `isDeleted=true`，`isGlobal=true`
- 应用：解析 IP/CIDR/range、过期时间、删除标记、名单类型和 server scope，写入 `WafStateManager`。当前实现不再单独拉 `IPListService` metadata，`listType` 已随 item 返回。

### IPItemService.CreateIPItems

- 调用位置：`src/rpc/ip_report.rs`
- 请求：`CreateIPItemsRequest { ip_items[] }`
- `ip_items[]` 字段：`ipListId`、`value`、`ipFrom`、`ipTo`、`expiredAt`、`reason`、`type`、`eventLevel`、`nodeId`、`serverId`、`sourceNodeId`、`sourceServerId`、`sourceHTTPFirewallPolicyId`、`sourceHTTPFirewallRuleGroupId`、`sourceHTTPFirewallRuleSetId`、`sourceURL`、`sourceUserAgent`、`sourceCategory`
- 响应 proto：`CreateIPItemsResponse { ipItemIds[] }`
- 采样说明：未创建真实名单项。
- 运行时说明：当 `ipListId<=0` 且为全局名单时，使用内置 ID：黑名单 `2000000000`、白名单 `2000000001`、灰名单 `2000000002`；站点级名单没有显式 `ipListId` 会被丢弃。

### IPListService 与 IPItemService.CreateIPItem/ListIPItemsWithListId

- 当前状态：运行时代码没有主动调用这些接口。
- 说明：`RpcClient` 仍保留 client helper，但 `src/rpc/ip_list.rs` 的同步路径只调用 `IPItemService.ListIPItemsAfterVersion`；`src/rpc/ip_report.rs` 也不再调用 `findIPListIdWithCode/createIPList`，因为这些接口在 cloud API 下属于 admin/user 凭据能力。

### FirewallService.NotifyHTTPFirewallEvent

- 调用位置：`src/rpc/firewall.rs`、`src/rpc/events.rs`
- 请求：`NotifyHTTPFirewallEventRequest { server_id, http_firewall_policy_id, http_firewall_rule_group_id, http_firewall_rule_set_id, created_at }`
- 响应：`RPCSuccess {}` 空消息
- 采样说明：未上报真实 WAF 事件。
- 注意：旧文档中提到的客户端 IP、URL、action、level、tags 不在当前 proto 请求内，当前 Rust 调用也没有发送这些字段。

## 5. 日志、指标和统计

本节主要是写接口。为避免污染控制面，文档采样未主动发送日志或统计；响应形状按 proto 均为空成功消息或空 response。

### HTTPAccessLogService.CreateHTTPAccessLogs

- 调用位置：`src/log_uploader.rs`
- 请求：`CreateHTTPAccessLogsRequest { http_access_logs[] }`
- 响应：`CreateHTTPAccessLogsResponse {}` 空消息
- `http_access_logs[]` 字段：`requestId`、`serverId`、`nodeId`、`locationId`、`rewriteId`、`originId`、`remoteAddr`、`rawRemoteAddr`、`remotePort`、`remoteUser`、`requestURI`、`requestPath`、`requestLength`、`requestTime`、`requestMethod`、`requestFilename`、`requestBody`、`scheme`、`proto`、`bytesSent`、`bodyBytesSent`、`status`、`statusMessage`、`sentHeader`、`timeISO8601`、`timeLocal`、`msec`、`timestamp`、`host`、`referer`、`userAgent`、`request`、`contentType`、`cookie`、`args`、`queryString`、`header`、`serverName`、`serverPort`、`serverProtocol`、`hostname`、`originAddress`、`originStatus`、`originHeaderResponseTime`、`errors[]`、`attrs`、`firewallPolicyId`、`firewallRuleGroupId`、`firewallRuleSetId`、`firewallRuleId`、`firewallActions[]`、`tags[]`
- 上传行为：按 protobuf 编码大小拆 chunk；失败进入 retry queue；ResourceExhausted 时二分拆批。

### NodeLogService.CreateNodeLogs

- 调用位置：`src/log_uploader.rs`
- 请求：`CreateNodeLogsRequest { node_logs[] }`
- 响应：`CreateNodeLogsResponse {}` 空消息
- `node_logs[]` 字段：`id`、`role`、`tag`、`description`、`level`、`nodeId`、`createdAt`、`count`、`serverId`、`isFixed`、`originId`、`isRead`、`paramsJSON`、`type`

### NodeValueService.CreateNodeValues

- 调用位置：`src/rpc/stats.rs`、`src/rpc/node.rs`、`src/rpc/node-status-full.rs`
- 请求：`CreateNodeValuesRequest { node_value_items[] }`
- 响应：`RPCSuccess {}` 空消息
- `node_value_items[]` 字段：`item`、`valueJSON`、`createdAt`
- `valueJSON` 由代码构造的实际形状：
  - `originHealth_<origin_id>`：`originId`、`status`、`latencyMs`、`lastCheckTs`
  - `cpu`：`usage`、`cores`、`logicalCount`、`physicalCount`
  - `memory`：`usage`、`total`、`used`、`memUsage`
  - `load`：`load1m`、`load5m`、`load15m`
  - `connections`：`total`
  - `trafficIn` / `trafficOut`：`total`
  - `allTraffic`：`inBytes`、`outBytes`、`avgInBytes`、`avgOutBytes`
  - `requests` / `attackRequests`：`total`
  - `disk`：`usage`、`total`、`used`、`maxUsage`
  - `traffic`：`in`、`out`、`total`
  - `cache`：`diskSize`、`memorySize`

### ServerBandwidthStatService.UploadServerBandwidthStats

- 调用位置：`src/rpc/stats.rs`
- 请求：`UploadServerBandwidthStatsRequest { server_bandwidth_stats[] }`
- 响应：`RPCSuccess {}` 空消息
- item 字段：`userId`、`serverId`、`day`、`timeAt`、`bytes`、`bits`、`totalBytes`、`cachedBytes`、`attackBytes`、`countRequests`、`countCachedRequests`、`countAttackRequests`、`userPlanId`、`countWebsocketConnections`、`originTotalBytes`、`originAvgBytes`、`originAvgBits`、`countIPs`、`nodeRegionId`

### ServerDailyStatService.UploadServerDailyStats

- 调用位置：`src/rpc/stats.rs`
- 请求：`UploadServerDailyStatsRequest { stats[], domain_stats[] }`
- 响应：`RPCSuccess {}` 空消息
- `stats[]` 字段：`serverId`、`userId`、`nodeRegionId`、`bytes`、`cachedBytes`、`countRequests`、`countCachedRequests`、`createdAt`、`countAttackRequests`、`attackBytes`、`checkTrafficLimiting`、`planId`、`day`、`hour`、`timeFrom`、`timeTo`、`countIPs`
- `domain_stats[]` 字段：`serverId`、`domain`、`bytes`、`cachedBytes`、`countRequests`、`countCachedRequests`、`countAttackRequests`、`attackBytes`、`createdAt`

### MetricStatService.UploadMetricStats

- 调用位置：`src/rpc/stats.rs`
- 请求：`UploadMetricStatsRequest { server_id, time, count, total, version, item_id, metric_stats[], keep_keys[] }`
- 响应：`RPCSuccess {}` 空消息
- `metric_stats[]` 字段：`id`、`hash`、`keys[]`、`value`
- `hash` 算法：`fnv_hash64("{server_id}@{keys.join(\"$EDGE$\")}@{time}@{version}@{item_id}")`
- `keys[]` 来自控制面 `metricItems[].keys`，代码支持 `${country}`、`${province}`、`${city}`、`${provider}`、`${browser}`、`${os}`、`${wafGroup}`、`${wafAction}` 和请求上下文变量，如 `${remoteAddr}`、`${requestPath}`、`${requestMethod}`、`${method}`
- 节点会先按解析后的 `keys[]` 本地聚合再上传，避免 `requestId`、query、header、请求耗时等单次请求字段把 IP、路径、方法和流量排行拆成一请求一条

### ServerService.UploadServerHTTPRequestStat

- 调用位置：`src/rpc/stats.rs`
- 请求：`UploadServerHTTPRequestStatRequest { month, day, region_cities[], region_providers[], systems[], browsers[], http_firewall_rule_groups[] }`
- 响应：`RPCSuccess {}` 空消息
- `region_cities[]` 字段：`serverId`、`countRequests`、`bytes`、`countAttackRequests`、`attackBytes`、`regionCountryId`、`regionProvinceId`、`regionCityId`
- `region_providers[]` 字段：`serverId`、`count`、`regionProviderId`
- `systems[]` / `browsers[]` 字段：`serverId`、`name`、`version`、`count`
- `http_firewall_rule_groups[]` 字段：`serverId`、`httpFirewallRuleGroupId`、`action`、`count`

### ServerTopIPStatService.UploadServerTopIPStats

- 调用位置：`src/rpc/stats.rs`
- 请求：`UploadServerTopIPStatsRequest { stats[] }`
- 响应：`RPCSuccess {}` 空消息
- `stats[]` 字段：`serverId`、`ip`、`countRequests`、`day`、`timeAt`

## 6. API 节点、客户端代理和连通性

### PingService.Ping

- 调用位置：`src/rpc/client.rs`
- 请求：`PingRequest {}`
- 响应 proto：`PingResponse { result }`
- 实测：`result="pong"`
- 应用：检测 gRPC endpoint 可用性。

### APINodeService.FindAllEnabledAPINodes

- 调用位置：`src/rpc/api_node.rs`
- 请求：`FindAllEnabledAPINodesRequest {}`
- 响应 proto：`apiNodes[]`
- 实测：返回 1 个 API node
- 实测字段：`id=1`、`isOn=true`、`nodeClusterId=0`、`name="默认API节点"`、`accessAddrs[]` 1 条、`accessAddrsJSON` 96 bytes、`httpJSON` 204 bytes、`httpsJSON` 100 bytes、`statusJSON` 为空、`isPrimary=true`、`instanceCode=""`
- JSON 形状：
  - `accessAddrsJSON`：数组，item 为 object
  - `httpJSON`：`isOn`、`listen[]`
  - `httpsJSON`：`isOn`、`listen`、`sslPolicy`、`sslPolicyRef`
- 应用：动态更新 runtime RPC endpoints，并对发现的 endpoint 执行 `PingService.Ping` 健康检查。

### ClientAgentIPService.ListClientAgentIPsAfterId

- 调用位置：`src/rpc/client_agent_ip.rs`
- 请求：`ListClientAgentIPsAfterIdRequest { id, size }`
- 响应 proto：`clientAgentIPs[]`
- 实测：以 `id=0,size=5` 返回 5 条
- item 字段：`id`、`ip`、`ptr`、`clientAgent`
- `clientAgent` 字段：`id`、`name`、`code`、`description`、`countIPs`
- 实测样本：`clientAgent.code="sm"`，`ptr` 为 `shenmaspider-...crawl.sm.cn.` 形态
- 应用：写入 Mace `CAIP_IP_{ip}` 与 `CAIP_META_last_id`，更新内存 verified-IP 索引。

### ClientAgentIPService.CreateClientAgentIPs

- 调用位置：`src/client_agent.rs`
- 请求：`CreateClientAgentIPsRequest { agent_ips[] }`
- `agent_ips[]` 字段：`agentCode`、`ip`、`ptr`
- 响应：`RPCSuccess {}` 空消息
- 采样说明：未创建真实 client-agent IP。

## 7. 当前未主动调用的 client helper

`RpcClient` 中还保留 `authority_key_service`、`file_service`、`script_service`、`ip_list_service`、`server_event_service` 等 helper，但当前 Rust 数据面没有主动调用对应 RPC。文档不把它们列为运行时依赖接口。

`ServerEventService.CreateServerEvent` 旧文档中曾列为运行时上报接口；当前代码只构造了 client helper，没有实际调用。

## 8. 运行时内部 API（RKE2 pod 间，不是控制面 gRPC）

RKE2 模式启用 pod 内部 HTTP API，默认监听 `0.0.0.0:19090`，通过 `CLOUD_NODE_CLUSTER_INTERNAL_TOKEN` 鉴权，Headless Service 暴露给同 namespace 内其他 cloud-node pod。

- `GET /internal/v1/health`：健康检查，Kubernetes probe 使用。
- `POST /internal/v1/purge`：Leader 将 cache purge fanout 到其他 pod。
- `POST /internal/v1/metadata/events`：同步 cache metadata 事件。
- `POST /internal/v1/stats/snapshot`：上报 pod 本地统计快照给 Leader 聚合。
- `GET /internal/v1/cache/stat`：查询 pod 本地缓存对象数量和大小。

## 9. 真实采样与复核

复跑文档采样：

```sh
CLOUD_NODE_REAL_API_TEST=1 \
CLOUD_NODE_REAL_API_DOC_SNAPSHOT=1 \
CLOUD_NODE_TEST_RPC_ENDPOINT=<rpc-endpoint> \
CLOUD_NODE_TEST_NODE_ID=<node-id> \
CLOUD_NODE_TEST_SECRET=<secret> \
cargo test --test real_api_config real_api_grpc_documentation_snapshot -- --nocapture
```

采样测试只主动调用读接口和无副作用探测；写接口不会为了文档构造真实上报数据。若要验证写接口，请在隔离控制面或临时测试租户中执行。
