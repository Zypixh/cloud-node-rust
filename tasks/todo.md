# AnyTLS SNI Relay Repair Checklist

## Baseline

- [ ] Confirm production `relay.zeroCopy` value.
- [ ] Capture one slow and one fast mihomo upload with the same AnyTLS configuration.
- [ ] Capture both TCP legs on the node when possible.
- [ ] Collect memory/FD pressure and relay close-reason logs.

## Core fixes

- [ ] Add a deterministic silent-response upload fixture.
- [ ] Remove or redesign the established relay per-direction pressure timeout.
- [ ] Cover async-copy and zero-copy with the same timeout semantics.
- [ ] Fix `ServerMetrics` DashMap re-entry during first creation.
- [ ] Add a bounded first-metrics-creation regression test.

## Shutdown and observability

- [ ] Test SNI benign drain with delayed upload tail and backend reset.
- [ ] Re-evaluate the SNI/AnyTLS upload drain window.
- [ ] Make pressure close, L4 drain, hard error and benign close distinct in logs/metrics.
- [ ] Verify L4 drain scope and prevent unexpected collateral connection cleanup.

## Validation and rollout

- [ ] Run `cargo check --all-targets`.
- [ ] Run `cargo test memory_governor::tests -- --nocapture`.
- [ ] Run TCP/SNI relay targeted tests.
- [ ] Repeat 8 MiB and 64 MiB uploads through mihomo.
- [ ] Compare retransmission, complete payload, close reason, and upload duration.
- [ ] Roll out with `relay.zeroCopy=false` first, then test zero-copy separately.
- [ ] Keep the previous binary and operational rollback procedure available.

