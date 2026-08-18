# Mace KV, XDP and Tokio Modernization Checklist

This checklist implements `mace-kv-xdp-tokio-plan.md`. Each task is intentionally bounded and
must leave the repository buildable with the prior backend available for rollback.

## Phase 0: Guardrails and contracts

### Task 1: Establish a fresh-target build entry point

**Description:** Add `xtask` and script entry points for clean build, test and benchmark execution.

**Acceptance criteria:**

- [ ] Each supported command creates a new external target directory and checks free space.
- [ ] Success, failure and interruption clean the owned target through `cargo clean --target-dir`.
- [ ] Release packaging copies the artifact before cleanup and records peak target size.

**Verification:** Run a fast command and a failed command; assert workspace `target/` remains absent
and the temporary target is removed.

**Dependencies:** None. **Likely files:** `xtask/`, `scripts/`, `.github/workflows/`. **Scope:** M.

### Task 2: Define KV schemas and repository contracts

**Description:** Replace arbitrary string-key access with versioned, typed repository APIs.

**Acceptance criteria:**

- [ ] Each current key family has an owner, binary ordering rule, value version and retention policy.
- [ ] The contract covers point read, atomic batch, bounded range scan, durable flush and health error.
- [ ] No new caller receives a raw engine handle.

**Verification:** Schema round-trip, ordering, malformed-value and retention tests.

**Dependencies:** None. **Likely files:** new `src/persistence/`, `src/metrics/storage.rs`. **Scope:** M.

### Task 3: Create backend conformance fixtures

**Description:** Run the same behavior suite against temporary RocksDB and Mace stores.

**Acceptance criteria:**

- [ ] Atomic batch, snapshot visibility, prefix/range boundaries, reopen and error behavior are tested.
- [ ] Counter accumulation, cache metadata, firewall records, WAF token expiration and client cursor are covered.
- [ ] Tests cannot touch production node paths or global `STORAGE`.

**Verification:** `cargo test persistence::conformance` on both backends with a timeout.

**Dependencies:** Task 2. **Likely files:** `src/persistence/tests/`. **Scope:** M.

## Phase 1: Mace proof of concept and isolation

### Task 4: Add a pinned Mace adapter behind the contract

**Description:** Introduce Mace only in the adapter with an exact reviewed version pin.

**Acceptance criteria:**

- [ ] Mace opens a separate `mace-v1` path, creates named buckets and exposes no Mace types above the adapter.
- [ ] Engine errors carry operation/repository context and never panic a traffic task.
- [ ] Mace synchronous operations run only in persistence workers or test code.

**Verification:** `cargo check --all-targets --locked`, conformance tests and dependency/license report.

**Dependencies:** Tasks 2-3. **Likely files:** `Cargo.toml`, `Cargo.lock`, `src/persistence/mace.rs`. **Scope:** M.

### Task 5: Build the bounded persistence service

**Description:** Add fixed blocking workers, command budgets, coalescing and health metrics.

**Acceptance criteria:**

- [ ] A full queue has documented per-domain behavior: coalesce cache metadata, retry critical security writes, shed only permitted metrics.
- [ ] No request path creates unbounded `spawn_blocking` work or synchronously waits for disk unless contractually required.
- [ ] Shutdown flushes bounded critical work and reports incomplete work explicitly.

**Verification:** Slow-engine test checks queue cap, reactor responsiveness, cancellation and counter cleanup.

**Dependencies:** Task 4. **Likely files:** `src/persistence/service.rs`, `src/resource_budget.rs`. **Scope:** M.

### Task 6: Migrate metrics and unique-IP repositories under dual write

**Description:** Replace merge-operator usage with delta batches and shadow compare non-security data.

**Acceptance criteria:**

- [ ] Aggregate totals match after concurrent flush and restart.
- [ ] Range cleanup is bounded and does not scan unrelated namespaces.
- [ ] Shadow mismatch is measurable and prevents cutover.

**Verification:** Property/concurrency tests, importer resume test and benchmark against current metrics path.

**Dependencies:** Task 5. **Likely files:** `src/metrics.rs`, `src/metrics/storage.rs`. **Scope:** M.

### Task 7: Migrate cache catalog and client-agent repositories

**Description:** Move durable metadata while preserving the in-memory cache hit path.

**Acceptance criteria:**

- [ ] Cache hits read only the memory catalog; write/delete updates are queued and coalesced.
- [ ] Startup recovery is bounded, cancellable and reconciles missing disk objects.
- [ ] Client-agent records and cursor are atomic.

**Verification:** Existing cache tests, restart/recovery fixture, cache churn and metadata mismatch test.

**Dependencies:** Task 5. **Likely files:** `src/cache_hybrid.rs`, `src/client_agent.rs`. **Scope:** M.

### Checkpoint: Non-security Mace decision

- [ ] Exact Mace pin and supply-chain review approved.
- [ ] Conformance, crash/reopen and dual-write parity are clean for the agreed observation window.
- [ ] RocksDB rollback store is intact and its disk retention is documented.

## Phase 2: Security data and cutover

### Task 8: Migrate WAF token and firewall repositories last

**Description:** Move security-critical durable state after non-security evidence is complete.

**Acceptance criteria:**

- [ ] Firewall put/delete batch is atomic and survives kill/reopen fault injection.
- [ ] Expiration, legacy import marker and retry semantics are versioned and observable.
- [ ] Any durable-write uncertainty retains RocksDB authority during dual mode.

**Verification:** Kill/reopen tests, simulated disk-full/error tests and firewall isolation integration test.

**Dependencies:** Tasks 5-7 and explicit approval. **Likely files:** `src/firewall/persistence.rs`, `src/auth.rs`. **Scope:** M.

### Task 9: Implement resumable importer, verifier and rollback drill

**Description:** Provide an offline migration tool that never mutates the source store.

**Acceptance criteria:**

- [ ] Per-bucket count/bytes/digest match before a completion marker is written.
- [ ] Interrupted imports resume without duplicate or missing visible records.
- [ ] Backend switch rollback works without deleting Mace or RocksDB files.

**Verification:** Temporary fixtures with interruption at every batch boundary and a documented restore drill.

**Dependencies:** Task 8. **Likely files:** `xtask/`, `src/persistence/migration.rs`. **Scope:** M.

## Phase 3: Tokio and XDP reliability

### Task 10: Remove synchronous persistence from reactor paths

**Description:** Route cache, metrics and firewall persistence through the bounded service.

**Acceptance criteria:**

- [ ] `cache_hybrid` async paths do not call a blocking engine directly.
- [ ] Flusher and maintenance tasks have cancellation, join ownership and health metrics.
- [ ] Disk-fault latency stays within the agreed p99 budget for normal proxy traffic.

**Verification:** Runtime responsiveness test with a deliberately slow backend and task leak check.

**Dependencies:** Task 5. **Likely files:** `src/cache_hybrid.rs`, `src/metrics/storage.rs`, `src/metrics.rs`. **Scope:** M.

### Task 11: Introduce supervised critical background tasks

**Description:** Make listener, persistence, XDP bridge and maintenance task state queryable and restartable.

**Acceptance criteria:**

- [ ] Every critical task has an owner, generation, readiness, bounded restart policy and shutdown path.
- [ ] An old task cannot remove a newer generation's state.
- [ ] A worker failure produces a metric and a recovery/fallback action.
- [ ] The AF_XDP bridge is recreated when a config reload replaces its manager; it cannot exit
  permanently after observing a stale manager.

**Verification:** Inject failures into each task class and assert readiness/recovery without process restart.

**Dependencies:** Task 10 plus existing connection-reset tasks. **Likely files:** `src/tcp_proxy.rs`, `src/http_proxy_manager.rs`, `src/xdp.rs`. **Scope:** M.

### Task 12: Split XDP control plane and shared ABI

**Description:** Separate desired configuration, capability probe, generation-aware apply/reconcile and thin eBPF maps.

**Acceptance criteria:**

- [ ] `XdpManager` owns interface state transitions and map generations.
- [ ] The eBPF program is limited to parse/classify/PASS/DROP/REDIRECT decisions based on versioned maps.
- [ ] Status exposes desired, applied and effective fallback state per interface/queue.
- [ ] Reload uses prepare -> health-check -> atomic map switch -> drain, and rolls back every
  already-attached interface on failure.

**Verification:** Unit tests for transitions and BPF object ABI compile check.

**Dependencies:** Task 11. **Likely files:** `src/xdp/`, `src/runtime_mode.rs`, `crates/cloud-node-xdp-common/`. **Scope:** M.

### Task 13: Make AF_XDP redirect fail-open and lifecycle-safe

**Description:** Prime queues and bridge health before redirect; reverse the order for shutdown/failure.

**Acceptance criteria:**

- [ ] Redirect is published only when queue, UMEM, socket and bridge are ready in the same generation.
- [ ] Bridge failure changes the affected redirect to PASS before queue teardown.
- [ ] Per-queue counter and heartbeat telemetry identifies map miss, ring-full and fallback.
- [ ] Poll/XSK/TX/admission faults recover with bounded backoff within 30 seconds or settle in
  observable PASS fallback; they never require a process restart to restore kernel traffic.

**Verification:** Linux privileged veth/netns test kills bridge, rotates config and proves continued kernel-path traffic.

**Dependencies:** Task 12. **Likely files:** `src/xdp/af_xdp.rs`, `src/xdp/manager.rs`. **Scope:** M.

### Task 14: Gate AF_XDP TCP separately from UDP/QUIC

**Description:** Keep kernel TCP as default and isolate user-space TCP experimentation.

**Acceptance criteria:**

- [ ] TCP AF_XDP is disabled by default and cannot be enabled implicitly by generic redirect settings.
- [ ] Its state/reorder/loss/backpressure/teardown behavior has packet replay and fault tests before any rollout.
- [ ] UDP/QUIC and TCP ownership boundaries do not share ambiguous queues or cleanup paths.
- [ ] A SYN or spoofed four-tuple cannot allocate unbounded state or overwrite the L2 route of an
  established session before handshake validation.

**Verification:** Replay corpus plus 6-hour privileged Linux soak before approval.

**Dependencies:** Task 13. **Likely files:** `src/xdp/`, `src/quic_udp_demux.rs`, `src/tcp_proxy.rs`. **Scope:** M.

## Phase 4: CI, performance and attack validation

### Task 15: Add PR, Linux dataplane and scheduled soak workflows

**Description:** Separate fast checks from privileged integration and long-running validation.

**Acceptance criteria:**

- [ ] PR CI runs fmt, metadata, all-target check, clippy and test with corrected source path triggers.
- [ ] Linux privileged job builds eBPF and executes netns/veth/XDP tests.
- [ ] Scheduled jobs run storage crash recovery, load/attack fixtures and 6-hour/24-hour soak tiers.
- [ ] XDP reload tests change port/interface/queue state 1,000 times and inject bridge panic, XSK
  close, map update, TX/channel pressure and partial multi-interface attach failure.

**Verification:** Deliberately break one Rust file, one test and one BPF fixture; each required workflow fails.

**Dependencies:** Tasks 1, 3, 9 and 13. **Likely files:** `.github/workflows/`. **Scope:** M.

### Task 16: Establish measurable regression budgets

**Description:** Turn performance and availability claims into tracked, hardware-qualified thresholds.

**Acceptance criteria:**

- [ ] Criterion baseline covers cache, firewall, metrics and new persistence paths.
- [ ] HTTP/TCP/QUIC load tests record throughput, p95/p99, CPU, RSS, FD, task count, queue depth and error/reset rate.
- [ ] Attack fixtures cover slow clients, connection churn, malformed protocol input, FD pressure, L4 isolation and recovery without restart.

**Verification:** Baseline and intentionally regressed runs show the alert/gate behavior.

**Dependencies:** Tasks 10-15. **Likely files:** `benches/`, `tests/`, `scripts/`. **Scope:** M.

## Definition of done

- [ ] No direct RocksDB or Mace engine type is reachable outside persistence adapters.
- [ ] No direct blocking KV call remains on a proxy reactor path.
- [ ] Mace migration has passed conformance, importer, dual-write, crash/reopen and rollback gates.
- [ ] Workspace builds use owned temporary targets and report successful cleanup.
- [ ] CI covers source changes, Linux XDP integration, performance regressions and scheduled soak/attack scenarios.
- [ ] XDP redirect cannot black-hole traffic when an AF_XDP bridge or queue fails.
- [ ] Production rollout retains a tested RocksDB rollback path until the agreed retention period ends.
