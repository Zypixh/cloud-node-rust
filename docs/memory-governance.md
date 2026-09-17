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

## Pressure Detection and Reclaim

Pressure classification still comes from the governor snapshot (thresholds
unchanged), but detection no longer relies on the 2s snapshot TTL alone. On
Linux, `start_reclaim_monitor` also starts an idempotent event watcher that
polls two kernel sources and, on wakeup, invalidates the snapshot cache so the
next snapshot re-reads cgroup state immediately:

- PSI `/proc/pressure/memory` trigger `some 200000 1000000` (any-task memory
  stall ≥200ms per 1s window). Works on cgroup v1 and v2.
- cgroup v2 `memory.events`, resolved by walking the process cgroup upward
  until a readable file is found (delegated hierarchies often only expose it
  on an ancestor). Rising `high` counters floor the observation at `High`;
  `max`, `oom`, or `oom_kill` increments floor it at `Critical`. Events are
  coalesced to 250ms and never lower the pressure level — the snapshot-derived
  classifier remains the single source of truth.
- The classifier additionally folds in PSI avg10 stall ratios (oomd-style):
  `some` ≥10% floors the level at `Elevated`; `some` ≥30% or `full` ≥5%
  floors it at `High`. Ratio thresholds measure how much memory is *left*;
  PSI measures how much tasks are *already stalling* — a host in reclaim
  congestion can thrash while still reporting free bytes. PSI floors only
  ever escalate; `Critical` stays byte-threshold/event-driven so a transient
  stall cannot trigger the most destructive reclaim. Both ratios are exported
  as `psiMemorySomeAvg10PctX100`/`psiMemoryFullAvg10PctX100`.

Reclaim actions target the allocator that actually owns the heap. The global
allocator is mimalloc, so heap return uses `mi_collect` instead of the
glibc-only `malloc_trim`:

- `Elevated`: non-forced `mi_collect(false)` on a rotating thread basis via the
  60s cache-janitor cycle (the janitor task migrates across Tokio workers, so
  repeated cycles eventually collect each worker's heap; `mi_collect` only
  affects the calling thread).
- L1 entry weight now accounts for the entry's real heap cost — body bytes
  plus the cache key, response header name/value bytes (names are stored
  twice, raw + case-preserved), and a fixed ~512B struct/index/bookkeeping
  overhead. Previously only `data.len()` was weighed, so header-heavy
  entries could hold several times the nominal byte budget.
- `High`/`Critical`: forced `mi_collect(true)` in the reclaim monitor.
- After `ConfigStore::replace_all_servers` under High/Critical: forced collect
  on the same thread that dropped the previous generation, so its segments
  are purged before reuse.
- moka-backed caches (L1, regex cache, WAF regex cache) call
  `run_pending_tasks()` after `invalidate_all()` so evictions actually release
  memory instead of waiting for moka's lazy janitor.

`ReclaimStats` records process RSS before and after each reclaim pass, so the
effectiveness of a reclaim cycle is observable instead of assumed.

### Reclaim robustness (unwind builds)

The reclaim machinery is panic-hardened so a single faulting pass cannot
silently disable the whole subsystem:

- `RECLAIM_IN_FLIGHT`, the thread-local `RECLAIM_IN_PROGRESS`, and the
  ledger's `RESIDENT_OWNER_UPDATE_IN_PROGRESS` are all cleared by RAII guards
  during unwinding, so a panic can never wedge a flag permanently.
- `request_reclaim` contains unwind panics with `catch_unwind`: the pass is
  logged as an error, the panic still hits the default panic hook, and the
  call returns `None` so the coordinator rolls the trigger back and the
  pressure level is re-observed on the next cycle instead of being lost. The
  cooldown is armed even on panic so a deterministically faulting path cannot
  hot-loop.
- The reclaim-monitor loop and the kernel pressure-event watcher each wrap
  their iteration body in `catch_unwind`, so neither dedicated thread dies on
  a faulting iteration — the pending-level slot and unpark target keep working.
- `start_reclaim_monitor` is idempotent (`RECLAIM_MONITOR_STARTED` guard);
  a repeated call can no longer spawn a duplicate monitor thread that would
  drain the same pending level. A failed spawn clears the flag so a later
  call can retry.
- The cooldown's `last == 0` state means "never reclaimed", so the first
  reclaim of a fresh process is not suppressed, and the cooldown is measured
  from reclaim completion rather than reclaim start. Release builds use
  `panic = "abort"`, where containment is moot; these guards protect debug
  builds and tests.

## Resident Ledger Consistency

Every map that charges the resident ledger refunds its owner on every removal
path: per-key delete, expiry cleanup, capacity eviction, and bulk drain.
Negative-cache inserts charge the ledger *before* writing the entry, so a
rejected charge can never leave an uncharged entry behind (the rejection
increments `negativeCacheAdmissionRejected`). The same charge-before-insert
rule applies to the cache access log (`CACHE_ACCESS_LOG` uses the `Entry`
API so a rejected charge skips the insert) and to surrogate index members
(a rejected member charge degrades the tag to a saturated mark, which purge
handles via the authoritative metadata scan).

Attacker-driven maps are hard-bounded regardless of TTL sweeping:
`HTTP_REQUEST_PARSE_MARKS` (client-address keyed) caps at 262k entries
(65k under High+ pressure) with a force-sweep plus a rate-limited warning;
a dropped mark only means the connection is treated as having no parsed
request — the fail-closed direction for the L4 early-close signal.

Three mechanisms bound residual drift:

- Saturated surrogate marks are bounded by `surrogate_index_capacity()` and
  ledger-charged like index members, so origin-controlled `Surrogate-Key`
  headers cannot grow them without limit.
- `reclaim_caches_critical` additionally drops the whole surrogate reverse
  index (`surrogateIndexTagsRemoved` in `lastReclaim`). Purge stays correct
  because the purge path always merges the authoritative metadata scan; the
  index is only an accelerator.
- Every 5 minutes the reclaim monitor runs a ledger-vs-map reconciliation
  (skipped above Elevated pressure) that refunds owners whose key no longer
  exists. Cumulative `ledgerReconcileStaleOwners`/`ledgerReconcileBytesRefunded`
  are exported in `resourceGovernor`; a nonzero counter indicates a missed
  refund somewhere and should be investigated rather than accepted.
- The ledger's own owner map is bounded (`RESIDENT_LEDGER_MAX_OWNERS`):
  brand-new owner charges are refused at the cap — every call site already
  treats charge failure as fail-closed — while updates/refunds of tracked
  owners always proceed so accounting stays exact. Refusals are exported as
  `ledgerOwnerCapRejections` and current rows as `ledgerTrackedOwners`.
- High-pressure reclaim also trims the surrogate reverse index down to
  `SURROGATE_INDEX_MAX_TAGS_PRESSURE`, dropping the largest membership sets
  first and refunding every member owner; saturated marks are retained
  because they are cheap and keep degraded-purge semantics.

Other formerly insert-only maps are now bounded or self-cleaning:
`ORIGIN_HEALTH_MAP` (stale-check GC in the reporter plus a 65k backstop),
`APPLIED_PURGE_IDS` (65k cap; beyond it dedup degrades to re-applying an
idempotent purge), `REPLICA_STATS` (the 30s staleness filter now also
removes dead rows), and `HEADER_NAME_CACHE` (65k).

## WAF Scoped-State and Persistence Bounds

`WafStateManager` scoped maps (`blocks`, `kernel_blocks`, `block_networks`,
`kernel_block_networks`, `list_blocks`, `list_whitelists`, `graylists`, and
their network/range mirrors) are attacker-driven — a spoofed-source flood can
mint one entry per IP. All scoped insertions now run through
`apply_scoped_ip_with_capacity`-style paths bounded by
`governor.firewall_state_map_capacity()` (pressure-aware: ~1M normal,
~131k under pressure). When a map is full, expired entries are swept first,
then earliest-`expires_at` live entries are evicted in batches
(`over.max(capacity/16)`, clamped to 262144) — approved policy:
evict-soonest-expiring rather than refuse the new block. The batch scales
with capacity because each victim scan is O(map): a fixed small batch would
rescan the whole map every few hundred inserts under a sustained storm. Evictions increment `wafStateEvicted`,
emit a rate-limited warning, and reconcile paired kernel-mirror maps plus
range/network snapshots so enforcement stays coherent. Existing-key updates
never evict. Approved tradeoff: under extreme cardinality pressure the
soonest-expiring blocks can be released early; the new block always takes
effect.

`firewall::persistence::PENDING` (coalesced upserts + delete tombstones held
while storage is unavailable) is bounded at
`firewall_state_map_capacity() / 4`, clamped to [4096, 2M]. Full upserts
evict earliest-expiring records; full tombstone sets drop arbitrary excess
deletes. Drops increment `firewallPendingDropped` and warn rate-limited.
Approved tradeoff: a dropped tombstone can let a deleted block resurrect on
restart (expiry cleanup is the backstop); a dropped upsert loses persistence
for that record while in-memory enforcement remains.

## Metrics Memory Observability

Metrics tracker memory (metric aggregators, top-IP tracker, daily-domain and
unique-IP trackers) is estimated every 30s and published as
`metrics_aggregator_bytes` on the governor snapshot. It is an observational
gauge: these maps are not charged into the resident ledger, which is
deliberately scoped to cache categories. A rate-limited `METRICS_MEMORY`
warning fires when the estimate exceeds max(1/8 of node memory, 64MiB).

Tracker cardinality is additionally hard-bounded: each tracker
(`MetricAggregator` x2 incl. nested `request_samples`, `TopIpTracker`,
`DailyDomainTracker`, `UniqueIpTracker`) admits new keys only while below
`governor.metrics_cardinality_capacity()` — `state_budget_bytes / 40`
divided by a 256-byte entry estimate, clamped between
`MIN_METRIC_CARDINALITY_ENTRIES` and `MAX_METRIC_CARDINALITY_ENTRIES`, so the
limit scales with node memory and shrinks under pressure. New keys beyond the
cap are dropped with `metricsCardinalityDropped` incremented and a
rate-limited warning; existing keys always keep accumulating so tracked
totals stay exact. `restore`/seed-load paths honor the same cap — persisted
state cannot bypass it. Dropped unique keys are also not persisted, so the
observed cardinality floor equals the cap.

Mace storage capacity is selected cgroup-first: `memory.max`, then
`memory.high`, then host total. A small cgroup limit can no longer pick a
host-sized storage tier.

The node pressure signal propagated over `X-Cloud-Node-Pressure` now includes
a memory component (elevated memory pressure raises the score alongside the
existing connection/CPU mix), so L1/L2 peers see memory stress instead of an
idle-looking node.

## API Compatibility

The node does not require new control-plane configuration fields for this feature. Control-plane-visible memory totals use the same governor snapshot as admission decisions, including cgroup working-set accounting. Runtime visibility is local through logs, `memory_plan`, admission reject counters, and local performance samples. Node status also includes best-effort `resourceGovernor` and `l4Defense` JSON sections with FD pressure, zero-copy permits, UDP queued bytes, L4 pressure, top event kind, top prefix, prefix pressure, aggregate drops, and exact-counter saturation. This keeps configuration compatibility while allowing newer control planes to display the richer runtime snapshot.
