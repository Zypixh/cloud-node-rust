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
- keepalive budget: Pingora upstream keepalive pool size per worker.
- cache budget: TinyUFO L1 memory cache.
- Bloom budget: adaptive Bloom filter growth limit.
- negative cache limit: bounded by Bloom scale and governor memory budget.
- cache read budget: bounded admission for small disk HITs read into memory.
- QUIC/H3 budget: H3 datagram queued bytes and pending QUIC route/reassembly bytes.
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
- TOA connect helper: guards connect/resolve/setup with `OriginConnect`.
- PROXY protocol custom L4 connector: guards custom upstream connect with `OriginConnect`.
- HTTP/3 origin connector: guards H3 origin establishment with `OriginConnect`.
- QUIC UDP demux: pending route/reassembly buffers and H3 shared UDP queue bytes are capped by the governor.
- TinyUFO L1: auto budget comes from `cache_budget_bytes`.
- Adaptive Bloom: layer growth is bounded by `bloom_budget_bytes`.
- Negative cache: capacity is bounded by Bloom scale and governor negative-cache budget.
- Cache purger, janitor, warmup, and L2 promotion: use `BackgroundWork` admission and skip under pressure.

## Large-Scale Behavior

For very large caches, Bloom starts small and grows in sharded layers instead of preallocating for worst-case key counts. At billion-key scale it keeps reads concurrent, grows without rebuilding existing layers, and stops adding layers when the Bloom budget is reached. Negative cache remains short lived and bounded; it cannot grow independently of the governor.

The old fixed caps are replaced by dynamic limits. Remaining numeric constants are guardrails, not single-node scale caps.

## Pingora Cache Notes

`openFileCache` controls whether small L2 disk HITs may be read into memory for faster serving and L1 promotion. When it is disabled, small L2 HITs stream from the file path instead of being pulled into a `Bytes` buffer.

`enableSendfile` is tracked and exposed in runtime stats. The current Pingora cache `HandleHit` interface returns `Bytes` chunks and supports seek, but it does not expose the downstream socket to storage handlers. Because of that, this node cannot safely call Linux `sendfile(2)` inside the existing storage handler. The current implementation uses larger disk HIT chunks when sendfile is requested and implements Pingora `seek` for memory HIT handlers so range responses avoid extra filtering and over-read. True kernel sendfile would require a larger Pingora serving-path extension or a custom response path that owns both the file descriptor and downstream connection.

## API Compatibility

The node does not require new control-plane status fields for this feature. Control-plane-visible memory totals use the same governor snapshot as admission decisions, including cgroup working-set accounting. Runtime visibility is local through logs, `memory_plan`, admission reject counters, and local performance samples. This keeps API compatibility until the server side explicitly supports new memory-governance statistics.
