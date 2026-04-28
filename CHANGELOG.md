# Changelog

## v1.0.5 (Unreleased)

### Security Fixes

- **X-Cloud-Real-Ip Spoofing**: Re-enabled loopback check so that `X-Cloud-Real-Ip`, `X-Cloud-Real-Port`, and `X-Cloud-Http3-Bridge` headers are only trusted when the request originates from 127.0.0.1/::1. External clients can no longer forge their source IP via these headers.
- **X-Cloud-Access-Token Leak**: Internal L1→L2 authentication headers (`X-Cloud-Access-Token`, `X-Cloud-Node-Id`, `X-Cloud-Real-Ip`, `X-Cloud-Real-Port`, `X-Cloud-Http3-Bridge`) are now stripped in `upstream_request_filter` before forwarding to origin servers, preventing credential replay attacks.
- **HTTP/3 Bridge SSRF**: Removed attacker-controlled port from URI (`request.uri().port_u16()`) in the HTTP/3 bridge handler. Requests are now always forwarded to the known local proxy port (`listen_port`). Also removed `danger_accept_invalid_certs(true)` — TLS certificates are now always verified.
- **X-Cloud-Node-Id Poisoning**: The `X-Cloud-Node-Pressure` response header is now only emitted when the request originates from loopback. External clients can no longer probe node pressure information.
- **Weak AES IV**: Token generation (`auth::generate_token`) now uses SHA256-based key derivation instead of space padding, and generates a random 16-byte IV per token instead of deriving it deterministically from `node_id`. IV is prepended to ciphertext (standard CFB pattern).
- **TLS Verify Disabled**: Removed `danger_accept_invalid_certs(true)` from the internal cache preheat HTTP client in `rpc/cache.rs`.
- **Regex DoS Protection**: All user-controlled regex compilations in `firewall/matcher.rs` now use `RegexBuilder` with a 1MB `size_limit` to prevent catastrophic backtracking from malicious WAF rule patterns.

### Performance Optimizations

- **Lock-free FAST_L1 Cache**: Global `DashMap` bypasses `MemCache` single-lock bottleneck for zero-copy cache hits. FAST_L1 now checks all cache policy types (file, memory, hybrid).
- **Config Store: parking_lot::RwLock**: Replaced `std::sync::RwLock` with `parking_lot::RwLock` for `ConfigStore`, reducing contention under high concurrency.
- **HotPathSnapshot**: Per-request config snapshot (`host_path`, `firewall_policies`, `cache_policy`, `global_http`) built inside a single parking_lot read lock, eliminating repeated lock acquisitions in `response_filter` / `response_body_filter`.
- **Arc Migration**: `HTTPCachePolicy` wrapped in `Arc` for zero-cost clone. `HTTPFirewallPolicy` vec wrapped in `Arc<Vec>` for zero-cost clone on every request.
- **Global Config Pre-build**: `GlobalHTTPAllConfig` pre-built as `Arc` in `NodeConfig`, eliminating struct construction + 2 String clones inside the config lock on every request.
- **Cache HIT Fast Path**: `response_filter` skips header sync, WAF, and Alt-Svc on cache hits. `response_body_filter` skips optimize/webp/hls/outbound WAF on cache hits.
- **Deferred WAF**: Heavy inbound WAF evaluation deferred to `upstream_peer` (cache-miss path only). Policy type checked via `AtomicU8` for lock-free fast path.
- **In-memory Cache Index**: RocksDB sync reads eliminated from cache HIT hot path via in-memory metadata index.
- **Small File Memory Serving**: Cache hits under threshold served directly from `Bytes` buffer, eliminating disk streaming overhead.
- **32KB Chunked Streaming**: `MemoryHitHandler` streams in 32KB chunks instead of one-shot delivery to prevent memory spikes.
- **Sharded LRU Caches**: Per-shard LRU locks reduce contention under high concurrency.
- **Static Hostname Caching**: `CACHED_HOSTNAME` computed once via `Lazy`, eliminating per-request `hostname::get()` syscalls.
- **AtomicU8 Policy Type**: Lock-free policy type check for cache policy routing.
- **TCP Backlog 4096**: Increased listen backlog to prevent `Connection Refused` under high concurrency.

### Bug Fixes

- Cache HIT access logs now correctly include response headers and `cache.status` attribute.
- `x-cloud-preheat` security reimplemented: removed insecure manual file I/O; preheat now uses normal proxy path with `X-Edge-Cache-Action: fetch` header (localhost-only).
- DashMap deadlock and FAST_L1 memory leak resolved.
- Connection counter leak fixed in request_filter execution order.
- Access log timestamps now use local timezone (`local_from_timestamp_millis`), matching Go EdgeNode format.
- Panic in `MemCache::update_meta` when cache policy type is not "memory" resolved.
- `purge_by_key` `CacheKey` creation restored after FAST_L1 cleanup.
- MD5 hash used for FAST_L1 cache keys to guarantee consistency with `FileStorage`.
- Request ID format changed from UUID to pure numeric format matching GoEdge.
- Cache stampede protection via `CacheLock` to prevent concurrent writes to the same cache key.
- SslAcceptor instantiated outside accept loop to avoid massive CPU overhead per TLS connection.
- Upstream read and write timeouts added to prevent hanging connections.

### Benchmarks

Added comprehensive benchmarks covering all hot-path operations:

- **auth_bench**: `generate_token` (3 variants: typical, short secret, long inputs), `verify_url_auth`
- **firewall_bench**: 12 operator benchmarks including SQLi/XSS detection, regex match/not-match/case-insensitive, wildcard, IP CIDR, string equality, contains, prefix, suffix
- **logging_bench** (NEW): `next_request_id` (single + batch), time formatting (ISO8601, Apache Common), `report_node_log`
- **hotpath_bench** (NEW): 6-stage request pipeline simulation (request ID → header parsing → URI parsing → firewall → time formatting → cache hash), 12 firewall payloads, string operations (host parsing, XFF, content-type)
- **config_models_bench** (NEW): `parse_life_to_seconds` (5 units), `URLPattern::matches` (8 variants), `SizeCapacity::from_json`/`to_bytes`, `ServerConfig` methods
- **rewrite_bench**: Expanded with `evaluate_host_redirects`, 20-rule iteration, redirect mode, no-match paths
- **cache_bench**: Added `create_meta` (3 status code variants)
- **config_bench**: Added `get_global_http_config_sync`, `get_request_context_sync`, lookup miss
- **metrics_bench**: Updated to match current function signatures
