# Cloud-Node Rust PB Protocol Matrix

Date: 2026-04-21

Scope:
- Protocol source: `cloud-node/bin/output_protos/service_*.proto`
- Runtime source: `src/main.rs`, `src/rpc/**`, `src/log_uploader.rs`, `src/client_agent.rs`
- Goal: identify actual runtime alignment, not just generated proto/client availability

## Status Legend

- `running`: wired into `main.rs` and participates in runtime
- `implemented_not_started`: code exists but `main.rs` does not start it
- `partial`: some methods are used, but service semantics are incomplete
- `stub_only`: client wrapper or helper exists, but not actually used in runtime
- `unused`: no meaningful runtime integration found

## Runtime Entry Points Actually Started

Started from `src/main.rs`:
- `start_config_syncer`
- `start_node_stream`
- `start_ip_list_syncer`
- `start_api_node_syncer`
- `start_updating_server_list_syncer`
- `start_metrics_reporter`
- `start_node_value_reporter`
- `start_bandwidth_reporter`
- `start_daily_stat_reporter`
- `start_metric_stat_reporter`
- `start_top_ip_stat_reporter`
- `start_metrics_aggregator_reporter`
- `start_ip_report_service`
- `start_ocsp_syncer`
- `LogUploader`
- `NodeLogUploader`
- HTTP listener manager
- TCP listener manager
- UDP listener manager

Implemented but not started from `main.rs`:
- `start_ip_library_syncer`

## Service Matrix

| Proto service | Rust status | Methods actually used | Notes |
|---|---|---|---|
| `NodeService` | `running` | `findCurrentNodeConfig`, `nodeStream`, `updateNodeStatus`, `updateNodeIsInstalled`, `updateNodeConnectedAPINodes`, `findNodeLevelInfo`, `createNodeValues` | Main control plane is active. `find_node_level_info()` is implemented and used. Lifecycle tasks are still soft placeholders for install/start/upgrade semantics. |
| `NodeTaskService` | `partial` | `findNodeTasks`, `reportNodeTaskDone` | Tasks are consumed. `planChanged` and `nodeLevelChanged` now perform real sync. `scriptsChanged` is explicitly ignored because edge script runtime is unsupported. |
| `ServerService` | `partial` | `composeServerConfig`, `composeAllUserServersConfig`, `uploadServerHTTPRequestStat`, `findServerUserPlan` | Core server config, user server state sync, request stat upload, and user-plan association sync are wired. Large admin surface is intentionally unused. |
| `UserService` | `partial` | `checkUserServersState` | Only used for user server enablement refresh. |
| `APINodeService` | `running` | `findAllEnabledAPINodes` | API node list refresh is active. |
| `UpdatingServerListService` | `running` | `findUpdatingServerLists` | Periodic syncer is started and task-trigger path exists. |
| `IPItemService` | `running` | `listIPItemsWithListId`, `listIPItemsAfterVersion`, `createIPItem`, `createIPItems` | Incremental IP sync and block reporting are active. |
| `IPListService` | `running` | `listEnabledIPLists`, `findEnabledIPList` | Metadata sync exists and is started via IP list syncer. |
| `FirewallService` | `partial` | `notifyHTTPFirewallEvent` | Event upload exists. Other service capabilities are unused. |
| `HTTPAccessLogService` | `running` | `createHTTPAccessLogs` | Access log uploader is active. |
| `NodeLogService` | `running` | `createNodeLogs` | Node log bus is wired and uploader is started. |
| `HTTPCacheTaskKeyService` | `partial` | `findDoingHTTPCacheTaskKeys`, `updateHTTPCacheTaskKeysStatus` | Cache task sync exists, but runs only when specific node tasks trigger it. |
| `MetricStatService` | `running` | `uploadMetricStats` | Active. |
| `NodeValueService` | `running` | `createNodeValues` | Active. |
| `ServerBandwidthStatService` | `running` | `uploadServerBandwidthStats` | Active. |
| `ServerDailyStatService` | `running` | `uploadServerDailyStats` | Active. Daily stat bytes currently fold origin traffic because PB has no dedicated daily-stat origin fields. |
| `ServerTopIPStatService` | `running` | `uploadServerTopIPStats` | Active. |
| `ServerDeletedContentService` | `running` | `listServerDeletedContentsAfterVersion` | Deleted content sync is implemented and called from config sync loop. |
| `ScriptService` | `unused` | none | Explicitly unsupported. Rust node does not implement edge script runtime and ignores `scriptsChanged`. |
| `SSLCertService` | `running` | `listUpdatedSSLCertOCSP` | OCSP sync is active. |
| `IPLibraryArtifactService` | `implemented_not_started` | `findPublicIPLibraryArtifact` | Sync logic exists but is not started. |
| `FileChunkService` | `implemented_not_started` | `findAllFileChunkIds`, `downloadFileChunk` | Used only by IP library sync, which itself is not started. |
| `ACMEAuthenticationService` | `stub_only` | helper exists | `find_acme_key()` exists but I did not find it wired into runtime request handling. |
| `ServerEventService` | `stub_only` | helper exists | `report_server_event()` exists but no runtime call site was found. |
| `ClientAgentIPService` | `stub_only` | helper exists | `maybe_report_client_agent()` exists but no runtime call site was found. |
| `AuthorityKeyService` | `stub_only` | client wrapper only | No runtime usage found and currently out of scope. |
| `FileService` | `stub_only` | client wrapper only | No runtime usage found and currently out of scope. |
| `PingService` | `partial` | `ping` | Used for API endpoint health verification before runtime endpoint switch. |
| `PlanService` | `partial` | `findEnabledPlan`, `findBasicPlan` | Active for plan cache refresh. Runtime currently consumes `maxUploadSizeJSON` and `trafficLimitJSON` execution paths; daily/monthly quota decisions remain control-plane derived. |
| `IndexService` | `unused` | commented-out client | No usable runtime integration. |

## High-Risk Gaps

### 1. IP library sync remains intentionally disabled

`IPLibraryArtifactService` and `FileChunkService` logic exists, but `main.rs` does not start `start_ip_library_syncer()`.

Impact:
- protocol support is present in code but intentionally inactive
- current node runtime will not auto-download IP library artifacts

### 2. Lifecycle tasks are still soft placeholders

`upgradeNode`, `installNode`, and `startNode` are still treated as lightweight completion/report flows instead of real local automation.

Impact:
- node task protocol is only partially aligned for lifecycle operations
- this is currently intentional scope control, not a hidden runtime feature

### 3. Plan quota execution remains control-plane derived

The Rust node now caches `Plan` and consumes:
- `maxUploadSizeJSON`
- `trafficLimitJSON` when `trafficLimitStatus` is already present

But it still does **not** locally decide:
- `dailyRequests`
- `monthlyRequests`
- `dailyWebsocketConnections`
- `monthlyWebsocketConnections`

Impact:
- node/runtime alignment follows the chosen control-plane model
- these fields should not be treated as locally enforced limits

### 4. Daily-stat origin traffic is folded, not PB-native

`ServerBandwidthStat` has dedicated origin traffic fields, but `ServerDailyStat` does not.

Impact:
- Rust folds origin traffic into `ServerDailyStat.bytes`
- if PB later adds dedicated daily origin fields, this rule must be removed and replaced with direct mapping

## AI Coding Backlog

### P0: preserve runtime alignment

1. Keep intentionally excluded features documented as excluded:
- `start_ip_library_syncer`
- node lifecycle automation

2. Keep runtime-start list synchronized with `src/main.rs`

3. Re-verify any newly added syncer/uploader against endpoint hot-switch behavior

### P1: remove false alignment

1. Re-check all `NodeTaskService` task type mappings
2. Mark any intentionally unsupported task types explicitly in code/comments
3. Keep unsupported `ScriptService` documented as non-goal capability

### P2: complete runtime convergence

1. Implement upstream TCP client certificate support
2. Reconnect any remaining long-lived tasks that still pin old runtime state
3. Re-check traffic/stat/billing field mapping when PB changes

### P3: clean protocol surface

1. Decide whether these services are truly needed on node runtime:
- `AuthorityKeyService`
- `FileService`
- `IndexService`

2. Decide whether helper-only services should be wired or removed:
- `ACMEAuthenticationService`
- `ServerEventService`
- `ClientAgentIPService`

## Verification Rules

Any future PB alignment claim must prove all three:

1. the proto method exists
2. Rust has a real call path to it
3. that call path is started in runtime or intentionally documented as on-demand only

## Traffic Reporting Rules

These rules are the current source of truth for traffic statistics and billing-related reporting behavior.

1. `ServerBandwidthStat` uses PB-native origin traffic fields.
- `originTotalBytes` is the only origin traffic field currently populated by Rust runtime.
- `originAvgBytes` and `originAvgBits` are defined in PB but are not currently populated.

2. Origin traffic is collected on all active data paths.
- `TCP` and `UDP` record origin traffic directly through `record_origin_traffic()`.
- `HTTP` records origin traffic at request finalization time by folding:
- request body bytes sent upstream
- response body bytes received from upstream

3. `ServerDailyStat` has no origin traffic field in PB.
- Because `model_server_daily_stat.proto` does not define any `origin*` field, Rust cannot perform field-level origin traffic alignment for daily stats.
- To preserve billing/statistics visibility, Rust folds origin traffic into `ServerDailyStat.bytes`.

4. `ServerDailyStat.bytes` is a folded metric, not a pure downstream metric.
- Current upload rule:
- `ServerDailyStat.bytes = downstream bytes_sent + origin_bytes_sent + origin_bytes_received`
- This is an intentional compatibility rule for control-plane aggregation, not a PB-native dedicated origin field.

5. Billing is still control-plane derived.
- Rust node does not directly upload `server bill` / `user bill` / `user traffic bill` records.
- The node uploads statistics only.
- Any billing result is assumed to be computed by control plane from uploaded stats.

6. Future change rule.
- If PB later adds daily-stat origin fields, Rust must stop folding origin bytes into `ServerDailyStat.bytes` and instead map origin traffic into the new dedicated fields.

## Cache Logging Rules

These rules are the current source of truth for cache-hit related logging and reporting behavior.

1. Cache hit state has a coarse access-log tag.
- When `ctx.cache_hit == true`, Rust appends `CACHE_HIT` to `HTTPAccessLog.tags`.

2. Cache phase has a finer-grained access-log marker.
- Rust also records the effective `x-cache` value into access logs.
- `HTTPAccessLog.attrs.cacheStatus` stores the exact cache phase string.
- `HTTPAccessLog.tags` additionally stores `X_CACHE_<phase>`, for example:
- `X_CACHE_HIT`
- `X_CACHE_MISS`
- `X_CACHE_STALE`
- `X_CACHE_REVALIDATED`

3. Response headers remain the runtime source for exact cache phase.
- Rust writes `x-cache` on responses using the current Pingora cache phase.
- Current values include `HIT`, `MISS`, `STALE`, `BYPASS`, `EXPIRED`, `REVALIDATED`, and `DISABLED:*`.

4. Aggregated stats do not preserve cache phase granularity.
- `ServerBandwidthStat` and `ServerDailyStat` only upload:
- `cachedBytes`
- `countCachedRequests`
- PB currently has no dedicated field for per-phase cache metrics such as `STALE` or `REVALIDATED`.

## HTTP/3 Runtime Rules

These rules are the current source of truth for HTTP/3 support in the Rust node.

1. HTTP/3 support is implemented as an independent QUIC/H3 ingress, not as native Pingora H3 handling.
- The current vendored `pingora` stack does not expose native HTTP/3 server support.
- Rust runs a separate `quinn + h3 + h3-quinn` listener for UDP/QUIC/H3 traffic.

2. H3 requests are bridged back into the existing HTTPS runtime.
- Incoming HTTP/3 requests are forwarded to the local HTTPS listener.
- This intentionally reuses the existing website/global runtime features:
- routing
- WAF
- UAM
- CC defense
- cache
- logging
- metrics

3. HTTP/3 certificate handling uses the same certificate source as HTTPS.
- The H3 listener builds its rustls certificate resolver from `DynamicCertSelector` snapshots.
- Exact names, wildcard names, and default-certificate fallback are all supported.
- Certificate changes trigger listener recreation so H3 converges with current runtime certificates.

4. HTTP/3 logging is PB-aligned through access logs, not through dedicated stat fields.
- H3 requests are logged with `proto=HTTP/3.0`.
- Access-log attrs and tags also mark H3 transport.
- PB currently has no HTTP/3-specific fields in `ServerBandwidthStat`, `ServerDailyStat`, or `MetricStat`.

5. `Alt-Svc` advertisement is runtime-controlled.
- When global `HTTP3Policy` is enabled and the target site has HTTPS enabled, Rust advertises `Alt-Svc` for H3.
- This is policy-driven runtime behavior, not proof that Pingora itself handles HTTP/3 natively.
