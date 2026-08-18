# Mace KV, XDP and Tokio Modernization Plan

## Objective and boundaries

Replace the current `rust-rocksdb` persistence implementation with `mace-kv` only after a
compatibility and durability gate, separate every persistent data domain behind a typed
repository, make blocking persistence work safe for the Tokio runtime, rationalize the XDP
dataplane, and establish reproducible CI, stress, and release validation.

This document is a plan, not an approved direct dependency replacement. The current direct
RocksDB dependency is confined to `src/metrics/storage.rs`, but that module is the persistence
backend for more than metrics. It also stores cache metadata, unique-IP state, firewall records,
WAF tokens, client-agent data, and pending bandwidth state. A mechanical `DB -> Mace` rewrite
would risk a silent loss of security and cache state.

Existing `tasks/connection-reset-repair-*.md` documents are intentionally out of scope and must
not be overwritten. Their listener, FD, L4-defense, and connection-lifecycle fixes remain
prerequisites for production load and attack validation.

## Evidence and constraints

- Root crate: Rust 1.96.0, edition 2024. `Cargo.toml` currently uses `rust-rocksdb = 0.50.0`
  with `lz4` and `jemalloc`.
- `rust-librocksdb-sys` compiles the C++ engine and materially increases build time and disk use.
- `mace` is an unrelated malware-configuration extraction crate. The intended embedded engine is
  `mace-kv`, whose library package name is `mace`.
- The inspected Mace 0.0.34 package supports buckets, transactions, consistent views, prefix/range
  iteration, WAL/checkpoints, and optional write backpressure. Its own README states that storage
  format and APIs are not stable. The requested 0.1.0 release must be independently verified and
  pinned exactly before it can become a production dependency.
- Mace and RocksDB formats are incompatible. Never open `metrics.db` with Mace and never delete a
  RocksDB directory during a migration or rollback.
- Current local disk free space was about 11 GiB. A fresh `cargo test --all-targets --locked`
  build reached 2.1 GiB before tests ran and was intentionally stopped; `cargo clean --target-dir`
  removed all 2.1 GiB. The baseline test therefore did not pass or fail.
- Existing release CI builds and packages Linux artifacts, but does not run the root test suite.
  Its path filter also omits important application paths such as `src/**`, `Cargo.toml`,
  `Cargo.lock`, `crates/**`, and `data/**`.
- Sol Max's independent XDP/Tokio audit identifies AF_XDP bridge lifecycle as the most credible
  restart-cleared dataplane fault. A bridge is started only at process startup (`src/main.rs:3560`),
  while XDP reload can replace the manager (`src/xdp.rs:1616`, `src/xdp.rs:1628`). The existing
  bridge holds the old manager (`src/xdp.rs:6291`) and exits when it becomes stale
  (`src/xdp.rs:6397`); no code starts a bridge for the replacement. This is a P0 availability
  defect, independent of the RocksDB-to-Mace work.

## Target persistence architecture

```text
request paths
    |-- CacheCatalog (DashMap snapshot, no disk I/O)
    |-- SecurityState (bounded in-memory state)
    `-- MetricAccumulator (sharded atomics)
                         |
                         v
                bounded persistence command queue
                         |
                         v
          fixed-size blocking persistence worker pool
                         |
                         v
        typed repositories over KvEngine / Mace buckets
```

`KvEngine` is a small synchronous engine contract because both RocksDB and Mace expose blocking
disk APIs. The Tokio-facing layer is `PersistenceService`: it owns a bounded command queue,
coalesces idempotent cache updates, batches writes, and runs a fixed number of blocking workers.
It must not call `spawn_blocking` once per request and it must not let unbounded backlog consume
memory. Read paths either use an in-memory index or explicitly await a bounded worker only on a
cold/control-plane path.

Each repository owns its schema, prefix/range encoding, serialization version, migration and
durability policy. No application module may create arbitrary string keys or call a raw database
handle after the migration is complete.

| Repository / Mace bucket | Current key family | Criticality and durability | Target behavior |
| --- | --- | --- | --- |
| `metrics` | `S*_T*`, `NODE_T*` | Observability; bounded loss acceptable if documented | Sharded in-memory deltas, periodic transactional batch flush; no per-request read-modify-write |
| `unique_ip` | `UIP_*` | Reporting and retention | Binary, ordered key by day/server/IP; bounded range deletion |
| `cache_catalog` | `CMETA_*` | Cache recovery; disk objects remain source of payload truth | DashMap read index plus coalesced durable metadata writes; startup scan is bounded and cancellable |
| `firewall` | `FIREWALL_*` and legacy marker | Security-critical | Ordered binary key and atomic put/delete batch; successful commit is required before acknowledging durable update |
| `waf_token` | `WAFTOK_*` | Security/session state | TTL-aware typed record; lazy and periodic expiration, explicit clock tests |
| `client_agent` | `CAIP_*` | Control-plane synchronization | Transactionally write records and cursor together |
| `runtime_stats` | bandwidth JSON key and future state | Control-plane telemetry | Versioned typed records with explicit retention |

Schema keys must start with a repository namespace and schema version, use binary fields where
ordering matters, and define a closed range rather than relying on string lexicographic order.
Values carry a format version and are decoded strictly. Malformed values are counted and isolated;
they must not panic a listener task.

## Mace migration and rollback

1. Keep RocksDB as the production source of truth while a backend-neutral conformance suite is
   written. Implement the Mace adapter only after the target release passes its own license,
   security, API, durability, disk-amplification and maintenance review.
2. Store Mace data in a new directory, for example `data/mace-v1`. Keep the RocksDB directory
   read-only to the migration process and make a filesystem snapshot/backup before conversion.
3. Implement an offline importer that scans one RocksDB prefix at a time, writes bounded Mace
   transactions, records a per-bucket progress marker only after durable commit, and emits counts,
   byte totals and a deterministic digest. It must resume safely after interruption.
4. Add `rocksdb`, `mace_dual`, and `mace` backend modes. In `mace_dual`, writes go to RocksDB first
   and then Mace; sampled reads compare decoded typed values and report mismatches. Backpressure or
   Mace errors retain RocksDB authority and alert instead of dropping security state.
5. Cut over one repository at a time: metrics, unique IP, client agents, cache catalog, WAF tokens,
   and firewall last. The firewall cutover needs an explicit human approval after a clean recovery
   test and shadow mismatch window.
6. Roll back by changing the configured backend to RocksDB. Retain Mace files and migration markers
   for the agreed rollback period. Deletion requires a separate, explicitly approved retention task.

Mace does not provide RocksDB's merge operator. Metric counters must therefore become accumulated
deltas flushed in a single transaction, not transaction-per-increment read/modify/write. This
preserves request-path performance and avoids losing increments under concurrent writers.

## Tokio plan

Tokio is already used widely. The goal is not to convert synchronous functions into `async` for
style; it is to remove blocking work from reactor threads, establish bounded ownership, and make
task failure observable.

Priority changes:

1. Replace synchronous RocksDB/Mace calls currently reached from async cache paths
   (`cache_hybrid.rs`) and the cache access flusher (`metrics/storage.rs`) with repository commands
   sent to the bounded persistence service. Cache reads remain from `CACHE_META_INDEX`.
2. Make metrics aggregation hand a compact batch to the persistence worker. The periodic task must
   own a cancellation token and be supervised rather than run as a detached infinite loop.
3. Add supervisors for TCP/HTTP listener workers, XDP bridge workers, cache maintenance and other
   critical background loops. A supervisor owns `JoinHandle`s, restart backoff, generation state,
   readiness and shutdown. Detached error logs alone are not recovery.
4. Audit every `tokio::spawn` that is driven by a new connection, packet or RPC item. Require a
   semaphore, bounded channel or task set; capture no DashMap/parking_lot guard across `.await`.
5. Use `spawn_blocking` only for bounded CPU or synchronous I/O units. Long-lived work belongs in a
   named fixed worker pool; no unbounded `spawn_blocking` fan-out.

Known evidence includes synchronous `STORAGE.delete_cache_meta` and
`STORAGE.upsert_cache_meta_absolute` calls from async cache paths, and synchronous
`STORAGE.flush_cache_accesses()` inside a Tokio task. These are first migration targets. Listener
worker supervision, relay resource limits and FD recovery follow the existing connection-reset
plan and are availability work, not a speculative Tokio rewrite.

## XDP target design

The present `src/xdp.rs` combines BPF lifecycle, Aya maps, AF_XDP UMEM/rings, TCP reconstruction,
UDP routing, bridge tasks, socket hand-off, configuration reconciliation, status output and a large
test suite. Split it by ownership, not merely by line count.

### Control plane

`XdpManager` owns an explicit per-interface state machine:
`Disabled -> Probing -> Attaching -> Priming -> Ready -> Draining -> Disabled`, with `Failed` as a
visible terminal state. Desired configuration, probed kernel capability and applied runtime state
are separate types. Every map, program, AF_XDP queue and bridge gets a generation; stale tasks may
not remove or overwrite a newer generation.

The supervisor must own and restart bridge task handles. Current poll, UDP queue, TCP admission
and TX failures can disable redirect then exit the bridge (`src/xdp.rs:6440`, `6511`, `6547`,
`6612`, `6674`) with no rebuild path. The target behavior is bounded exponential recovery; after
the retry budget is exhausted the affected queue transitions to an explicit kernel `PASS` fallback,
not a silent dead bridge or process-wide restart requirement.

### Dataplane

The eBPF program remains a thin parser/classifier with versioned shared ABI maps. It may PASS,
DROP for an explicit firewall policy, or REDIRECT only after userspace has fully primed the target
queue and published readiness. It must not encode policy that cannot be observed and reconciled
from userspace.

For TCP, retain kernel TCP plus normal Tokio listener handling as the default and recovery path.
The user-space AF_XDP TCP reactor is experimental until it has a complete TCP state/loss/reorder,
backpressure, teardown and replay test matrix. AF_XDP should first serve the narrow UDP/QUIC path
where its ownership boundary is clear. A stopped bridge must first switch redirect maps to PASS,
then drain queues and tasks; it must never leave a black-hole redirect.

### Operating rules

- Prepare inactive map entries, UMEM and bridge health first; publish REDIRECT only at `Ready`.
- A heartbeat failure, queue fault or generation mismatch changes only the affected interface/queue
  back to PASS and emits a high-signal event.
- Give each RSS queue one owner with its XSK, UMEM and RX/TX rings. The current bridge is one Tokio
  task for all queues (`src/xdp.rs:6318`) behind a global runtime mutex (`src/xdp.rs:6412`), and its
  busy TCP path has no await (`src/xdp.rs:6541`). Replace it with a dedicated queue worker or a
  correctly readiness-driven `AsyncFd` loop that has an explicit yield/work budget; do not retain
  `Arc<Mutex<AfXdpRuntime>>` as the dataplane coordination model.
- Keep per-interface and per-queue counters for pass/drop/redirect/map-miss/ring-full/invalid-desc,
  bridge liveness, queue depth and fallback events.
- Treat unsafe AF_XDP calls as audited ownership boundaries. Each `unsafe` block needs a local
  lifetime/ownership invariant and fault-injection coverage.
- Split the current overloaded fallback policy into `startup_policy`, `runtime_degrade_policy` and
  `packet_miss_policy`. The present `fail-start` setting controls eBPF runtime PASS/DROP behavior
  (`src/runtime_mode.rs:70`, `src/xdp.rs:3868`, `crates/cloud-node-xdp-ebpf/src/main.rs:336`), so a
  transient XSK/map failure can unexpectedly become packet loss.
- Do not refresh a TCP route or activity timestamp from an unverified packet. Current AF_XDP TCP
  handling updates route state before smoltcp validation (`src/xdp.rs:5604`) and allocates two
  16 KiB buffers for a new SYN (`src/xdp.rs:5613`), enabling spoofing and SYN-flood amplification.
  Use a handshake-aware admission budget and a route key that includes interface, destination IP,
  protocol and port.

## Build hygiene and CI design

Every repository-provided build/test/bench command must use a fresh `CARGO_TARGET_DIR` outside the
working tree. Add an `xtask` command and a small shell entry point, for example
`./scripts/cargo-fresh`, that:

1. checks free disk space before starting (`>= 50 GiB` for full test/XDP build; a smaller documented
   threshold for lint-only checks);
2. creates a dedicated temporary target directory;
3. packages/copies any requested artifact before cleanup;
4. invokes `cargo clean --target-dir <temporary-dir>` on normal completion and error paths; and
5. records the peak target size and cleanup result.

Direct ad-hoc `cargo` commands cannot be technically forbidden by Cargo. The supported developer,
CI, benchmark and release entry points must therefore use this wrapper, and the contribution guide
must make bypassing it unsupported. Do not run `cargo clean` against a developer's shared target
directory.

CI is layered rather than claiming one job proves long-term safety:

| Layer | Required environment | Required gates |
| --- | --- | --- |
| Fast PR | Linux and macOS | fmt, locked metadata, check all targets, clippy, unit/integration tests |
| Storage conformance | Linux/macOS temp disks | RocksDB/Mace contract tests, importer resume, dual-write comparison, crash/reopen cases |
| Linux dataplane | privileged VM with veth/netns and BPF | eBPF object build, attach/detach, map generation swap, bridge failure -> PASS fallback, AF_XDP queue tests |
| Security/load | isolated Linux runner | slowloris, connection churn, malformed PROXY/TLS/QUIC, FD pressure, L4 policy isolation and recovery without restart |
| Performance | pinned bare-metal or stable VM | Criterion baseline comparison plus HTTP/TCP/QUIC throughput and p95/p99/RSS/FD regressions |
| Soak | dedicated Linux host, 6 h then 24 h | workload, config reload, cache churn, forced backend failures, task/FD/RSS slope and post-run recovery |

The current release workflow must gain a separate PR CI workflow and corrected path triggers. Its
release matrix may keep a cache for dependencies, but build artifacts must still be cleaned after
packaging. CI cache keys must be explicit and never reuse a workspace `target/` directory.

XDP integration tests must exercise real configuration changes, not only no-op reloads. The current
smoke script preserves the manager when configuration is unchanged (`scripts/xdp-netns-smoke.sh:345`,
`:374`) and therefore misses the stale-manager bridge exit. Required fault injections include bridge
panic, XSK FD close, map update failure, TX/channel pressure and second-interface attach failure.
Acceptance includes 1,000 generation-changing reloads with a Ready bridge continuously present,
fault recovery within 30 seconds or explicit PASS fallback, and no monotonic increase in pinned
links, sessions, tasks, RSS or FDs during a 24-hour Linux soak.

## Implementation phases

### Phase 0: Baseline and contracts

Define the repository schemas, durability policy, error taxonomy, metrics and a backend
conformance suite. No production data is migrated in this phase.

### Phase 1: Persistence service and Mace proof of concept

Introduce `KvEngine`, Mace/RocksDB adapters, bounded persistence workers and typed repositories.
Use only temporary test databases. Establish Mace release pinning and fault/recovery evidence.

### Phase 2: Repository-by-repository migration

Migrate non-security data under dual write, verify parity, then cut over. Migrate WAF/firewall only
after a separate approval checkpoint. Retain RocksDB rollback data throughout.

### Phase 3: Runtime and XDP hardening

Move blocking persistence off reactors, add supervisors, split XDP by ownership, make redirect
readiness generation-safe, and keep AF_XDP TCP disabled by default until its validation gate passes.

### Phase 4: CI, attack and soak gates

Make fresh-target builds the only supported automated entry point, add Linux privileged tests,
benchmark baselines and scheduled soak jobs. Promote only if no resource drift, no shadow mismatch,
no black-hole fallback and no regression budget breach is observed.

## Decision gates and risks

| Risk | Gate / mitigation |
| --- | --- |
| Mace is not yet storage/API stable | Exact version pin, adapter isolation, format versioning, dual-write, crash/reopen and rollback retention |
| Metrics merge semantics change | Sharded delta accumulator and transactional batch invariants; property tests against RocksDB totals |
| A blocking engine stalls Tokio | Bounded persistence service and request-path cache index; runtime latency tests under slow disk fault injection |
| Migration corrupts or loses state | New data directory, snapshot, resumable importer, per-bucket digest, no automatic delete |
| XDP redirect black-holes traffic | Readiness gate before redirect, heartbeat, generation control, immediate PASS fallback and veth/netns fault tests |
| AF_XDP reload leaves no bridge | Supervisor owns generations and queue task handles; reload is prepare/swap/drain/rollback, never replacement without a new bridge |
| AF_XDP TCP is abused by spoofed SYNs | Kernel TCP by default; feature gate user-space TCP until SYN flood, route spoofing, retransmit, half-close and soak gates pass |
| CI consumes developer disk | Fresh temporary target, free-space guard, Cargo cleanup and peak-size report |
| Benchmarks produce noisy claims | Compare fixed hardware/baseline distributions; gate only stable metrics with explicit tolerance |

## Approval checkpoints

1. Confirm that `mace-kv` 0.1.0 is the intended dependency and approve its exact pin/license/supply
   chain review.
2. Review the KV schema and durability policy before any adapter changes.
3. Approve Mace cutover only after dual-write parity, restart/crash recovery and rollback drills.
4. Approve AF_XDP TCP only after privileged Linux integration, packet replay and soak criteria pass.
5. Approve production rollout only after CI, load and 24-hour soak reports are attached.
