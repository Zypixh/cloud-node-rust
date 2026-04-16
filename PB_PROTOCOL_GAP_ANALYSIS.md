# PB Protocol Gap Analysis

Date: 2026-04-14

Scope:
- Baseline proto set: `cloud-node/bin/output_protos/*.proto`
- Compared target: current Rust workspace
- Goal of this document: re-check every PB service against the current Rust source, identify omissions precisely, and distinguish between:
  - fully connected runtime support
  - partially connected support
  - client stub only
  - completely missing

Non-scope:
- upgrade program packaging / installer delivery interfaces are still excluded as previously agreed
- cloud-node server-side admin/query interfaces that do not need node-side consumption are marked separately

## Current Build Status

Current repo is not in a clean buildable state.

- `cargo build` fails at [src/main.rs](/Users/moying/Documents/project/cloud-node-rust/src/main.rs#L209)
- Error: `health_check_service` does not satisfy `ServiceWithDependents`
- This affects confidence for any claim of "fully supported"

Relevant location:
- [src/main.rs](/Users/moying/Documents/project/cloud-node-rust/src/main.rs#L201)

## Runtime Entry Points Present

The current binary starts these background sync/report tasks from [src/main.rs](/Users/moying/Documents/project/cloud-node-rust/src/main.rs):

- `start_config_syncer`
- `start_ip_list_syncer`
- `start_api_node_syncer`
- `start_updating_server_list_syncer`
- `start_metrics_aggregator_reporter`
- `start_metrics_reporter`
- `start_bandwidth_reporter`
- `start_daily_stat_reporter`
- `start_node_value_reporter`
- `start_metric_stat_reporter`
- `start_ocsp_syncer`
- `start_ip_library_syncer`
- access log uploader

This means the Rust node already has a partial control-plane/runtime loop, but protocol coverage still needs service-by-service verification.

## Service-by-Service Result

### 1. `NodeService`

Status: Partial

Actually used methods:
- `findCurrentNodeConfig`
- `findNodeHTTPPagesPolicies`
- `nodeStream`
- `updateNodeStatus`
- `updateNodeConnectedAPINodes`
- `findNodeLevelInfo`
- `createNodeValues`

Relevant code:
- [src/rpc/node.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/node.rs#L85)
- [src/rpc/node.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/node.rs#L172)
- [src/rpc/node.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/node.rs#L224)
- [src/rpc/node.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/node.rs#L364)
- [src/rpc/node.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/node.rs#L428)

What is aligned:
- full config pull is wired
- node status heartbeat is wired
- pages policy pull is wired
- connected API node reporting is wired
- node value reporting is wired

What is missing or not aligned:
- `nodeStream` only handles:
  - `newNodeTask`
  - `NewNodeTask`
  - `connectedAPINode`
  - `changeAPINode`
- stream codes beyond these are not implemented
- `changeAPINode` only logs the target address and does not rebind running RPC clients
- policy/config push semantics are still mainly handled by a later full pull, not by exact event-specific application

Impact:
- Node control path exists but does not yet fully match the cloud-node PB event model.

### 2. `NodeTaskService`

Status: Partial

Actually used methods:
- `findNodeTasks`
- `reportNodeTaskDone`

Relevant code:
- [src/rpc/node_task.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/node_task.rs#L26)
- [src/rpc/node_task.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/node_task.rs#L77)

Task types currently handled:
- `configChanged`
- `purgeServerCache`
- `purgePathCache`
- `preheatCache`
- `ipItemChanged`
- `userServersStateChanged`
- `upgradeNode`
- `installNode`
- `startNode`

Missing task coverage still apparent:
- `nodeLevelChanged`
- `ddosProtectionChanged`
- `globalServerConfigChanged`
- `updatingServers`
- `uamPolicyChanged`
- `httpCCPolicyChanged`
- `http3PolicyChanged`
- `httpPagesPolicyChanged`
- `plusChanged`
- `toaChanged`
- `networkSecurityPolicyChanged`
- `webPPolicyChanged`
- `planChanged`
- `scriptsChanged`
- task types related to exact list deletion or artifact/script/file refresh if defined in proto and emitted by cloud-node

Notes:
- install/start/upgrade tasks are currently treated as "mark installed and done", not real lifecycle execution.

### 3. `ServerService`

Status: Partial

Actually used methods:
- `composeServerConfig`
- `composeAllUserServersConfig`
- `uploadServerHTTPRequestStat`

Relevant code:
- [src/rpc/server.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/server.rs#L25)
- [src/rpc/server.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/server.rs#L98)
- [src/rpc/stats.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/stats.rs#L297)

What is aligned:
- per-server config recompose is present
- per-user server config recompose is present
- HTTP request stat upload is present

What is missing or not aligned:
- service-level exact change handling is still not fully decomposed by PB feature category
- runtime behavior depends heavily on `compose*` pull instead of fully explicit per-policy protocol handling

### 4. `UserService`

Status: Partial

Actually used methods:
- `checkUserServersState`

Relevant code:
- [src/rpc/server.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/server.rs#L82)

What is missing:
- no other `UserService` methods are consumed in the current node runtime

### 5. `APINodeService`

Status: Partial

Actually used methods:
- `findAllEnabledAPINodes`

Related node-side reporting:
- `updateNodeConnectedAPINodes` is sent via `NodeService`

Relevant code:
- [src/rpc/api_node.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/api_node.rs#L81)
- [src/rpc/api_node.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/api_node.rs#L119)

What is aligned:
- API node list is periodically refreshed
- enabled API node addresses are persisted back to local config
- connected API node IDs can be reported upstream

What is missing or not aligned:
- updated endpoints are only written into config file
- already running background RPC loops still hold startup-time config
- no real hot switch for current long-lived RPC traffic

This is one of the biggest remaining protocol-runtime mismatches.

### 6. `IPItemService`

Status: Partial

Actually used methods:
- `listIpItemsWithListId`
- `listIpItemsAfterVersion`
- `createIpItem`

Relevant code:
- [src/rpc/ip_list.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/ip_list.rs#L26)
- [src/rpc/ip_list.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/ip_list.rs#L57)
- [src/rpc/ip_list.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/ip_list.rs#L86)

What is aligned:
- full list item pull by `list_id` exists
- incremental sync by version exists
- local firewall list manager can apply incremental updates
- blocked IP reporting path exists

What is missing or not aligned:
- no full `IPListService` metadata coupling
- deletion and list ownership semantics are incomplete
- no broader item management coverage beyond current runtime needs

### 7. `IPListService`

Status: Missing

Current Rust status:
- no active client usage
- no list metadata sync
- no runtime storage of full list definitions from this service

Why this matters:
- current node only knows raw IP items, not full list metadata lifecycle
- list deletion, attribute changes, and relationship updates cannot be faithfully matched

### 8. `FirewallService`

Status: Partial

Actually used methods:
- `notifyHTTPFirewallEvent`

Relevant code:
- [src/rpc/firewall.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/firewall.rs#L5)
- [src/proxy.rs](/Users/moying/Documents/project/cloud-node-rust/src/proxy.rs#L495)

What is aligned:
- WAF hit event reporting is wired
- proxy now reports `policy_id`, `group_id`, `set_id`

What is missing:
- no other `FirewallService` PB capabilities are consumed

### 9. `ServerDeletedContentService`

Status: Implemented for runtime path

Actually used methods:
- `listServerDeletedContentsAfterVersion`

Relevant code:
- [src/rpc/utils.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/utils.rs#L63)
- [src/proxy.rs](/Users/moying/Documents/project/cloud-node-rust/src/proxy.rs#L268)

What is aligned:
- version-based sync exists
- proxy blocks matched content with `410 Gone`

### 10. `UpdatingServerListService`

Status: Implemented for runtime path

Actually used methods:
- `findUpdatingServerLists`

Relevant code:
- [src/rpc/api_node.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/api_node.rs#L30)
- [src/config.rs](/Users/moying/Documents/project/cloud-node-rust/src/config.rs#L70)
- [src/proxy.rs](/Users/moying/Documents/project/cloud-node-rust/src/proxy.rs#L255)

What is aligned:
- node syncs updating server IDs
- proxy returns `503` for those servers

### 11. `HTTPCacheTaskKeyService`

Status: Partial

Actually used methods:
- `findDoingHttpCacheTaskKeys`
- `updateHttpCacheTaskKeysStatus`

Relevant code:
- [src/rpc/cache.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/cache.rs)

What is aligned:
- purge task execution exists
- preheat task execution exists
- task result callback exists

What is missing or not aligned:
- only currently used task forms are handled
- protocol coverage still needs exact per-method comparison if cache proto evolves

### 12. `HttpAccessLogService`

Status: Implemented for runtime path

Actually used methods:
- `createHttpAccessLogs`

Relevant code:
- [src/log_uploader.rs](/Users/moying/Documents/project/cloud-node-rust/src/log_uploader.rs#L117)

What is aligned:
- access logs are uploaded upstream

### 13. `HTTPAccessLogService`

Status: Not consumed by node runtime

Current Rust status:
- no actual client usage found

Interpretation:
- likely cloud-side query/admin service rather than edge runtime ingestion path
- still not "fully covered" if strict proto-by-proto parity is required

### 14. `MetricStatService`

Status: Partial

Actually used methods:
- `uploadMetricStats`

Relevant code:
- [src/rpc/stats.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/stats.rs#L174)

What is aligned:
- metric aggregation exists
- periodic upload exists

What is not aligned:
- `item_id` is hardcoded to `0`
- `version` is hardcoded to `1`
- metric keys are locally synthesized from geo/browser/os/WAF aggregation
- there is no synced metric-item definition model from control plane

Consequence:
- upload path exists, but semantics are not fully PB-model aligned

### 15. `NodeValueService`

Status: Partial

Actually used methods:
- `createNodeValues`

Relevant code:
- [src/rpc/node.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/node.rs#L428)

What is missing:
- no other node value methods are consumed

### 16. `ServerDailyStatService`

Status: Partial

Actually used methods:
- `uploadServerDailyStats`

Relevant code:
- [src/rpc/stats.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/stats.rs#L103)

Assessment:
- basic daily upload path exists
- still needs field-level check against proto payload completeness

### 17. `ServerBandwidthStatService`

Status: Implemented for base runtime path

Actually used methods:
- `uploadServerBandwidthStats`

Relevant code:
- [src/rpc/stats.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/stats.rs#L50)

### 18. `SSLCertService`

Status: Partial

Actually used methods:
- `listUpdatedSslCertOcsp`

Relevant code:
- [src/rpc/ssl.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/ssl.rs#L21)
- [src/ssl.rs](/Users/moying/Documents/project/cloud-node-rust/src/ssl.rs#L68)
- [src/ssl.rs](/Users/moying/Documents/project/cloud-node-rust/src/ssl.rs#L193)

What is aligned:
- OCSP blobs are pulled from control plane
- OCSP blobs are stored in dynamic cert selector

What is missing or not aligned:
- actual TLS handshake stapling is commented out
- therefore OCSP sync is not effective in live TLS response

This is a clear functional omission.

### 19. `ACMEAuthenticationService`

Status: Implemented for current use case

Actually used methods:
- `findAcmeAuthenticationKeyWithToken`

Relevant code:
- [src/rpc/acme.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/acme.rs#L13)

### 20. `IPLibraryArtifactService`

Status: Partial

Actually used methods:
- `findPublicIpLibraryArtifact`

Relevant code:
- [src/rpc/files.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/files.rs#L17)

What is aligned:
- public IP library artifact discovery exists

What is missing:
- implementation is narrow and tied to the IP library flow only
- not a general artifact sync subsystem

### 21. `FileChunkService`

Status: Partial

Actually used methods:
- `findAllFileChunkIds`
- `downloadFileChunk`

Relevant code:
- [src/rpc/files.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/files.rs#L47)
- [src/rpc/files.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/files.rs#L57)

What is aligned:
- chunk enumeration and download exist

What is missing:
- only used for a narrow IP library file flow
- no generic file/chunk runtime handling layer

### 22. `FileService`

Status: Client stub only

Relevant code:
- [src/rpc/client.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/client.rs#L148)

Current Rust status:
- client factory exists
- no runtime call sites found

### 23. `PingService`

Status: Client stub only

Relevant code:
- [src/rpc/client.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/client.rs#L128)

Current Rust status:
- client factory exists
- no runtime call sites found

### 24. `PlanService`

Status: Client stub only

Relevant code:
- [src/rpc/client.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/client.rs#L132)

### 25. `AuthorityKeyService`

Status: Client stub only

Relevant code:
- [src/rpc/client.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/client.rs#L140)

### 26. `ClientAgentIPService`

Status: Client stub only

Relevant code:
- [src/rpc/client.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/client.rs#L144)

### 27. `NodeLogService`

Status: Helper exists, not wired into main runtime path

Relevant code:
- [src/rpc/logs.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/logs.rs#L13)

Current Rust status:
- `createNodeLogs` helper exists
- no active caller found in runtime startup path

### 28. `ServerEventService`

Status: Client stub only

Relevant code:
- [src/rpc/client.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/client.rs#L156)

### 29. `ServerTopIPStatService`

Status: Client stub only

Relevant code:
- [src/rpc/client.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/client.rs#L160)

### 30. `IndexService`

Status: Missing

Relevant code:
- [src/rpc/client.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/client.rs#L152)

Current Rust status:
- client declaration is commented out
- no runtime usage

### 31. `ScriptService`

Status: Missing

Current Rust status:
- no client factory
- no runtime usage

This is a direct protocol coverage gap.

## Cross-Cutting Runtime Gaps

These are the main gaps that prevent the project from being considered fully PB-complete on the node side.

### A. Node event/task coverage is still incomplete

The biggest gap is not one RPC method but the incomplete mapping from PB event/task model into runtime actions.

Missing categories include:
- more `nodeStream` message codes
- more `NodeTask` types
- exact event-driven reload behavior by policy family

### B. APINode hot switching is not really complete

Current code updates config file only:
- [src/rpc/api_node.rs](/Users/moying/Documents/project/cloud-node-rust/src/rpc/api_node.rs#L111)

But long-running workers still use startup config snapshots, so current runtime does not fully follow PB control changes.

### C. IP list model is incomplete without `IPListService`

Only item sync exists right now. Full list-definition lifecycle is absent.

### D. OCSP data is synced but not applied

This is a hard functional mismatch.

### E. Metric stat semantics are only approximate

Transport exists, but item/version/key semantics are not fully controlled by PB definitions.

### F. Several PB services still exist only as stubs or are entirely absent

Main ones:
- `ScriptService`
- `IndexService`
- `PlanService`
- `AuthorityKeyService`
- `ClientAgentIPService`
- `FileService`
- `ServerEventService`
- `ServerTopIPStatService`

## Practical Overall Judgment

Current Rust implementation should be judged as:

- control-plane foundation: present
- major node runtime functions: partially present
- strict PB parity with latest cloud-node: not achieved

It is not accurate to claim that the current Rust source already fully supports all latest cloud-node PB-defined node-side capabilities.

## Recommended Next Audit/Development Order

If this document is used as the execution baseline, the next development order should be:

1. Fix build break in `src/main.rs`
2. Complete `NodeService.nodeStream` message coverage
3. Complete `NodeTaskService` task-type coverage
4. Introduce shared live RPC endpoint state to finish `APINodeService` runtime hot switch
5. Implement `IPListService` metadata sync and local lifecycle management
6. Enable real OCSP stapling in TLS callback
7. Align `MetricStatService` with actual PB metric item model
8. Decide whether `ScriptService`, `IndexService`, `PlanService`, `AuthorityKeyService`, `ClientAgentIPService`, `FileService`, `ServerEventService`, `ServerTopIPStatService` are required for node-side parity, then implement or explicitly classify as cloud-only

## Summary

After re-checking against the latest proto set, the current Rust project has already covered a meaningful subset of node runtime PB functionality, but still has clear omissions:

- incomplete task and event coverage
- incomplete APINode runtime switching
- missing `IPListService`
- ineffective OCSP application
- only partial metric-stat semantic alignment
- multiple proto services still stubbed or absent

This document should replace broader earlier claims of "almost complete" and be treated as the current precise PB gap baseline.
