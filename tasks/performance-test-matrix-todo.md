# Performance Test Matrix Checklist

- [ ] Record RKE2 node, kernel, CPU, memory, disk, and existing workload baseline.
- [ ] Create isolated `cloud-node-perf` namespace and pin workloads to `hz-rke2-01`.
- [ ] Add deterministic HTTP load generator and Mace KV benchmark entry point.
- [ ] Build Debug `bench-proxy` and Mace benchmark with a fresh target.
- [ ] Build Release `bench-proxy` and Mace benchmark with a fresh target.
- [ ] Deploy and smoke-test Debug proxy.
- [ ] Deploy and smoke-test Release proxy.
- [ ] Run HTTP cold/warm throughput and latency matrix.
- [ ] Run Mace single-thread, batch, mixed, concurrent, and reopen matrix.
- [ ] Run bounded connection churn, slow header, malformed request, and burst recovery tests.
- [ ] Run five-minute Debug soak and recovery check.
- [ ] Run five-minute Release soak and recovery check.
- [ ] Save raw JSON/CSV results and resource samples.
- [ ] Remove test Deployments, Pods, Services, namespace, temporary Mace data, and build targets.
- [ ] Report failed or skipped points and residual risks.
