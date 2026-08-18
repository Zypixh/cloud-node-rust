# RKE2 Performance Test Matrix

## Scope

Run a reproducible, isolated performance and availability matrix for the current
cloud-node source on VPS `36.134.185.75` (RKE2 node `hz-rke2-01`). The matrix
compares the Rust `dev` profile (Cargo debug) with the production `release`
profile and measures the Mace KV path used by the current tree.

The test namespace is `cloud-node-perf`. Existing namespaces, deployments,
services, secrets, and production processes are out of scope.

## Definitions

- Dev: `cargo build --bin ...` using the default debug profile.
- Non-dev: `cargo build --release --bin ...` using the checked-in release profile.
- Network target: the project `bench-proxy` with a local origin sidecar.
- KV target: the project Mace-backed `MetricStorage` API in a dedicated temporary
  database. No production data or credentials are used.

## Matrix

### Build and binary checks

- Fresh Debug and Release target directories, one Cargo job, no incremental
  compilation, locked offline dependency resolution.
- Record wall time, peak RSS, target size, binary size, warnings, and cleanup.
- Run `--version`, `--help`, and a post-build liveness check for both profiles.

### HTTP throughput and latency

For each profile, run cold and warm cache tests for 1 KiB, 64 KiB, and 1 MiB
objects. Use keep-alive and connection-churn modes at concurrency 1, 16, 64,
256, and 512 for 15 seconds per point. Record requests/s, bytes/s, success
rate, p50/p95/p99/max latency, connection resets, timeouts, and HTTP status
errors.

### Mace KV

For each profile, run direct Mace tests with temporary databases for single
put/get, batched writes (1, 32, 256), mixed read/write, and concurrent workers
(1, 4, 16). Record operations/s, p50/p95/p99 latency, error count, database
size, reopen success, and checksum/value correctness.

### Attack and resilience pressure

- New-connection churn at bounded concurrency (256 and 512).
- Slow/incomplete headers with bounded sockets and deadlines.
- Malformed request lines and oversized headers.
- Burst traffic followed by normal traffic to verify recovery without restart.
- Capture pod restarts, process exit, HTTP resets, RSS, CPU, open FDs, and node
  health. Never target existing public services.

### Long-run availability

Run a five-minute mixed workload at concurrency 64 and 256 for each profile,
sampling CPU, RSS, FD count, socket state, errors, and latency every five
seconds. After each run, execute a clean request and a Mace reopen check.

## Acceptance gates

- Both profiles build and start in the isolated namespace.
- No unexpected pod restart, process exit, OOM kill, or node health regression.
- Every workload reports complete machine-readable results; failures are not
  hidden by shell pipelines.
- After pressure tests, normal requests recover without restarting the proxy.
- Mace values remain correct after concurrent writes and close/reopen.
- Results are compared by profile and workload; no cross-machine speed claim is
  made without recording the hardware and resource limits.

## Known limits

This validates the project proxy/cache and Mace persistence path. A full
control-plane-connected cloud-node production process is not started because
that would require real node credentials and could affect existing services.
XDP is not enabled in this first matrix; it requires a separate privileged
veth/netns test and must not be attached to the host production interface.
