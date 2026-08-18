# Connection Reset Repair Checklist

## Static Baseline

- [ ] Confirm effective runtime `toa.isOn=false`; keep TOA out of the current incident root-cause claim.
- [ ] Confirm `xdp.enabled`, `proxy_redirect_enabled`, AF_XDP bridge state and runtime fallback.
- [ ] Capture PIDs, FD limit/usage, socket state counts and listener readiness before any restart.
- [ ] Search logs for `EMFILE`, `ENFILE`, `No healthy backends`, `marked down`, `TcpAdmissionReject`, `TcpPressureIdleClose`, L4 block/drain and XDP map/queue failures.
- [ ] Record whether all failing clients share one IP/prefix or span unrelated sources.

## Phase 0: Evidence

- [ ] Implement connection-stage counters and correlation ids.
- [ ] Implement relay close reason and upstream error classification.
- [ ] Add origin/L4/FD/listener/XDP diagnostic snapshot fields.
- [ ] Add deterministic backend failure, FD pressure, L4 pressure, worker failure and cancellation fixtures.
- [ ] Add the incident runbook and restart-before-capture guardrail.

## Phase 1: Restart-Cleared State

- [ ] Replace origin all-down exclusion with half-open probe and bounded backoff.
- [ ] Classify origin failures so local pressure/cancel/defense events do not mark origin down.
- [ ] Bound L4 exact-counter saturation, prefix block and connection drain scope.
- [ ] Add L4 whitelist/TTL/recovery and cross-IP isolation tests.
- [ ] Supervise TCP and HTTP listener workers with generation-aware handles.
- [ ] Add EMFILE/ENFILE spare-fd recovery, backoff and metrics.

## Phase 2: Resource Lifecycle

- [ ] Enforce real FD hard margin in accept and origin-connect admission.
- [ ] Add stale relay policy based on shared activity/max lifetime.
- [ ] Verify every permit, active-IP token and registry guard drops on all exit paths.
- [ ] Add RAII TOA lease and kernel DEL reconciliation.
- [ ] Test TOA disabled branch has no allocation/module side effects.
- [ ] Separate upstream failure logs/metrics from client reset behavior.

## Phase 3: Conditional Dataplane

- [ ] Make XDP redirect conditional on queue and bridge readiness.
- [ ] Add bridge heartbeat and automatic pass/fail-start behavior.
- [ ] Add health state for all critical background tasks.
- [ ] Add bounded metrics creation and task shutdown tests.

## Verification

- [ ] Run touched-module targeted tests.
- [ ] Run `cargo check --all-targets`.
- [ ] Run full tests with bounded timeouts and no leftover tasks/resources.
- [ ] Run Linux-only TOA/XDP/socket tests.
- [ ] Compare async-copy and zero-copy with the same fixture; roll out async-copy first.
- [ ] Demonstrate recovery without process restart.
- [ ] Stage rollout and retain binary/config rollback.
