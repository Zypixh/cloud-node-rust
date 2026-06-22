# Unified Memory Governance

This node uses one runtime memory governor for connection admission, origin establishment, Pingora keepalive sizing, cache memory, Bloom filters, negative cache, QUIC staging queues, and background work.

## Priorities

1. Downstream connection establishment: HTTP/HTTPS, TCP, HTTP/3.
2. Origin establishment: HTTP cache misses, passthrough, TCP forwarding, TOA, PROXY protocol origins, and HTTP/3 origins.
3. Reused upstream keepalive pools.
4. Cache memory and admission filters.
5. Background cache work.

Under memory pressure, cache promotion and background jobs yield before request establishment and origin connection.

## Budgets

`src/memory_governor.rs` reads host or cgroup memory and derives:

- connection budget: downstream connections, H2 streams, H3 requests, origin connect permits.
- FD-equivalent pressure: process FD count plus admission pressure, used before memory usage becomes high.
- zero-copy relay budget: extra duplicated FDs, pipe FDs, pipe buffers, and blocking tasks for Linux splice relays.
- keepalive budget: Pingora upstream keepalive pool size per worker.
- cache budget: TinyUFO L1 memory cache.
- Bloom budget: adaptive Bloom filter growth limit.
- negative cache limit: bounded by Bloom scale and governor memory budget.
- cache read budget: bounded admission for small disk HITs read into memory.
- UDP queued byte budget: bytes waiting in passthrough session queues.
- QUIC/H3 budget: H3 datagram queued bytes, H3 per-connection streams, and pending QUIC route/reassembly bytes.
- background work limit: cache warmup, purge, janitor, and L2-to-L1 promotion.

On Linux, cgroup v1/v2 limits take precedence over host memory. `inactive_file` is subtracted from cgroup usage so budgets track the working set instead of charging reclaimable page cache as active heap. If no cgroup limit is present, the governor falls back to `/proc/meminfo` `MemAvailable`. The governor keeps a hard reserve headroom and refreshes memory snapshots with a short TTL to avoid hot-path sysinfo calls.

## Covered Paths

- HTTP/HTTPS listener admission: `AdmissionClass::HttpConnection`.
- TCP listener admission: `AdmissionClass::TcpConnection`.
- HTTP/3 listener admission: `AdmissionClass::Http3Connection`.
- H2 per-connection stream limit: `AdmissionClass::Http2Stream`.
- H3 per-connection request stream limit: `AdmissionClass::Http3Request`.
- L7 origin path: `proxy_upstream_filter` holds `OriginConnect` until Pingora reports the upstream connection is established or reused; request logging is only a fallback release point.
- SNI passthrough and TCP forwarding: hold `OriginConnect` only until the upstream socket, optional PROXY protocol header, and optional TLS handshake are established. Long-lived relay time is accounted by connection/session admission, not origin-establishment admission.
- TCP/SNI relay: read loops periodically re-evaluate pressure and close idle slow connections under `Elevated`/`High`/`Critical` pressure even if the connection entered `read` while pressure was normal.
- Linux zero-copy relay: requires a separate zero-copy permit and is automatically disabled under High/Critical memory or FD-equivalent pressure. The async copy path remains the fallback.
- TOA connect helper: guards connect/resolve/setup with `OriginConnect`.
- PROXY protocol custom L4 connector: guards custom upstream connect with `OriginConnect`.
- HTTP/3 origin connector: guards H3 origin establishment with `OriginConnect`.
- UDP passthrough: session queues are capped by item count and global queued bytes.
- QUIC UDP demux: pending route/reassembly buffers, adaptive route idle, and H3 shared UDP queue bytes are capped by the governor.
- HTTP/3 server: request permits are acquired before stream tasks are spawned, and each connection has a per-connection stream semaphore.
- TinyUFO L1: auto budget comes from `cache_budget_bytes`.
- Adaptive Bloom: layer growth is bounded by `bloom_budget_bytes`.
- Negative cache: capacity is bounded by Bloom scale and governor negative-cache budget.
- Cache purger, janitor, warmup, and L2 promotion: use `BackgroundWork` admission and skip under pressure.

## Large-Scale Behavior

For very large caches, Bloom starts small and grows in sharded layers instead of preallocating for worst-case key counts. At billion-key scale it keeps reads concurrent, grows without rebuilding existing layers, and stops adding layers when the Bloom budget is reached. Negative cache remains short lived and bounded; it cannot grow independently of the governor.

The old fixed caps are replaced by dynamic limits. Remaining numeric constants are guardrails, not single-node scale caps.

## L4 Adaptive Defense

Automatic L4 blocking reuses the existing control-plane `emptyConnectionFlood` policy. When `emptyConnectionFlood.isOn=true` and `maxEmptyConnections>0`, TCP, UDP, SNI passthrough, QUIC passthrough, and HTTP/3 resource-exhaustion events can trigger local cluster-scope blocks and `ip_report` synchronization. When the policy is off, the node still applies local admission, drop, timeout, and metrics, but it does not report automatic blacklist entries.

The L4 pressure level is computed as `Normal`, `Elevated`, `High`, or `Critical` from:

- connection admission usage.
- memory pressure.
- FD-equivalent pressure.
- TCP/HTTP/H3/UDP admission rejects.
- UDP queued byte usage.
- QUIC route, pending route, and reassembly usage.
- IPv4 `/24`, IPv6 `/64`, and cluster-wide distinct-IP surge.

Per-IP TCP-like active connection limits are shared by HTTP, HTTPS, TCP, TCP-TLS, and SNI passthrough. They start broad in Normal pressure and tighten as pressure rises. Slow-first-byte, slow ClientHello, and slow HTTP header deadlines also tighten under pressure so distributed slow attacks release FDs and tasks earlier.

L4 event thresholds are still based on `emptyConnectionFlood.maxEmptyConnections`. High-confidence events use the base threshold, medium-confidence events use `2x`, and low-confidence events use `4x`; under High and Critical pressure the effective threshold is reduced to one half or one quarter with a floor of 2. Source failures, origin timeouts, backend resets, normal SNI passthrough, and valid QUIC/HY2 passthrough are not counted as attacks.

Exact IP counters are kept in a reserved L4 counter table so high-confidence L4 events do not fail open if the general WAF rolling counter table is full. Prefix scoring is used mainly to increase pressure and trigger local emergency drop. A temporary cluster-scope prefix block is allowed only for sustained high-confidence events and only when no whitelist covers that prefix.

Inbound PROXY Protocol is trusted only from loopback, private, or link-local immediate peers. Public peers may send a syntactically valid PROXY header, but it is consumed without replacing the real socket client IP, so L4 defense, WAF counters, access logs, and blacklist reports cannot be spoofed by the header.

## Pingora Cache Notes

`openFileCache` controls whether small L2 disk HITs may be read into memory for faster serving and L1 promotion. When it is disabled, small L2 HITs stream from the file path instead of being pulled into a `Bytes` buffer.

`enableSendfile` is tracked and exposed in runtime stats. The current Pingora cache `HandleHit` interface returns `Bytes` chunks and supports seek, but it does not expose the downstream socket to storage handlers. Because of that, this node cannot safely call Linux `sendfile(2)` inside the existing storage handler. The current implementation uses larger disk HIT chunks when sendfile is requested and implements Pingora `seek` for memory HIT handlers so range responses avoid extra filtering and over-read. True kernel sendfile would require a larger Pingora serving-path extension or a custom response path that owns both the file descriptor and downstream connection.

## API Compatibility

The node does not require new control-plane configuration fields for this feature. Control-plane-visible memory totals use the same governor snapshot as admission decisions, including cgroup working-set accounting. Runtime visibility is local through logs, `memory_plan`, admission reject counters, and local performance samples. Node status also includes best-effort `resourceGovernor` and `l4Defense` JSON sections with FD pressure, zero-copy permits, UDP queued bytes, L4 pressure, top event kind, top prefix, prefix pressure, aggregate drops, and exact-counter saturation. This keeps configuration compatibility while allowing newer control planes to display the richer runtime snapshot.
