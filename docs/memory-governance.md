# Unified Memory Governance

This node uses one runtime memory governor for connection admission, origin establishment, Pingora keepalive sizing, cache memory, Bloom filters, negative cache, and background work.

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
- background work limit: cache warmup, purge, janitor, and L2-to-L1 promotion.

The governor keeps a hard reserve headroom and refreshes memory snapshots with a short TTL to avoid hot-path sysinfo calls.

## Covered Paths

- HTTP/HTTPS listener admission: `AdmissionClass::HttpConnection`.
- TCP listener admission: `AdmissionClass::TcpConnection`.
- HTTP/3 listener admission: `AdmissionClass::Http3Connection`.
- H2 per-connection stream limit: `AdmissionClass::Http2Stream`.
- H3 per-connection request stream limit: `AdmissionClass::Http3Request`.
- L7 origin path: `proxy_upstream_filter` holds `OriginConnect` until request logging.
- SNI passthrough and TCP forwarding: hold `OriginConnect` for the upstream relay lifetime.
- TOA connect helper: guards connect/resolve/setup with `OriginConnect`.
- PROXY protocol custom L4 connector: guards custom upstream connect with `OriginConnect`.
- HTTP/3 origin connector: guards H3 origin establishment with `OriginConnect`.
- TinyUFO L1: auto budget comes from `cache_budget_bytes`.
- Adaptive Bloom: layer growth is bounded by `bloom_budget_bytes`.
- Negative cache: capacity is bounded by Bloom scale and governor negative-cache budget.
- Cache purger, janitor, warmup, and L2 promotion: use `BackgroundWork` admission and skip under pressure.

## Large-Scale Behavior

For very large caches, Bloom starts small and grows in sharded layers instead of preallocating for worst-case key counts. At billion-key scale it keeps reads concurrent, grows without rebuilding existing layers, and stops adding layers when the Bloom budget is reached. Negative cache remains short lived and bounded; it cannot grow independently of the governor.

The old fixed caps are replaced by dynamic limits. Remaining numeric constants are guardrails, not single-node scale caps.

## API Compatibility

The node does not add new control-plane status fields for this feature. Runtime visibility is local through logs, `memory_plan`, and local performance samples. This keeps API compatibility until the server side explicitly supports new memory-governance statistics.
