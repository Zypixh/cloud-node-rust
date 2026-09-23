# smoltcp-edge — controlled fork of smoltcp 0.14.0

This crate is a vendored fork of `smoltcp 0.14.0` (Cargo.lock-pinned upstream)
maintained for the cloud-node edge dataplane (T3). It is patched into the root
build via `[patch.crates-io]` in `/Cargo.toml`. Every behavioural divergence
from upstream is listed here; code sites are marked `smoltcp-edge` /
`smoltcp-edge (T3)`.

Upstream invariant: **when no external transport controller is installed,
every code path is byte-for-byte upstream.** All 673 upstream lib tests pass
unmodified; the only test-tree edits are new-field literal updates and two new
tests at the end of `socket::tcp::test`.

## Dependency divergence

- `Cargo.toml` gains `cloud-node-transport` (workspace path) and an empty
  `[workspace]` table so the fork stays outside the root workspace and its
  test suite runs standalone.

## `src/socket/tcp/transport_ext.rs` (new, ~700 lines)

`ExtTransport` — sender-side machinery driven by an installed
`cloud_node_transport::cc::CongestionController`:

- per-segment `SentRecord` scoreboard (`seq`, `end_seq`, `first_tx`/`last_tx`,
  `sacked`, `lost`, `retransmitted`, `delivered_to_sampler`, `tsval`,
  `app_limited`); `pipe` follows Linux `tcp_packets_in_flight` semantics
  (SACKed and lost-marked records leave the pipe; retransmission re-enters).
- SACK block consumption + DSACK detection (first SACK block below the
  cumulative edge, RFC 2883 §4).
- Frontier loss marking on 3 dupacks (Linux `tcp_mark_head_lost` analogue);
  without SACK the gap head alone is marked (classic fast retransmit).
- RACK (RFC 8985) time-based marking with adaptive reorder window
  (`min_rtt/4`, 1 ms floor, srtt cap, DSACK-driven multiplier ×2 up to 8×).
- TLP probe: `max(2·srtt, 10 ms)` deadline capped under the RTO; probe
  retransmits the tail unacked record when no new data is available.
- Eifel undo: DSACK or TSecr-older-than-retx-tsval evidence calls
  `CongestionController::on_loss_undo`; `loss_response_outstanding` scopes
  undo to the first evidence after a loss response.
- RTT sampling: scoreboard first-tx timing (Karn-safe) with TSecr RTTM
  fallback when the sample stream is all retransmits.
- Pacing gate (`next_send_due`) for new-data segments only — retransmits
  and control traffic are exempt.
- App-limited marking on send-buffer drain; `on_idle_restart` once per
  idle gap ≥ srtt.
- Observability counters: `dsack_events`, `rack_lost_bytes`.

## `src/socket/tcp.rs`

- `congestion::Controller` trait and its impls made `pub`;
  `RttEstimator` made `pub` so the public trait signature is nameable.
- New field `ext_transport: Option<ExtTransport>` plus public APIs:
  `set_transport_controller`, `has_transport_controller`,
  `transport_snapshot` (`Option<CcSnapshot>`), `transport_pacing_rate`,
  `transport_next_send_due`, `set_rx_window_cap`.
- Read-only observability getters (additive, non-behavioural):
  `remote_window` (`remote_win_len` after scaling), `unacked_bytes`
  (`flight_size` — whole unacked range), `transport_pipe` (scoreboard
  pipe under an external controller), `timer_state` (retransmit /
  zero-window-probe / idle timer name for remote diagnostics).
- `rx_window_cap: Option<usize>` — `scaled_window()` applies the cap
  before window scaling (dynamic advertised-window control, D-R1 hook).
- PAWS (RFC 7323 §5.3): after ACK acceptability, segments with
  serially-older TSval are dropped once timestamps are negotiated.
  **Divergence:** the 24-day `TS.Recent` timeout escape is not
  implemented — a long-idle connection keeps rejecting stale TSval.
- DSACK generation: a data segment entirely below the cumulative
  receive edge records `last_rx_duplicate_range`, emitted as the first
  SACK block of the next ACK.
- `process()` ACK path: when `ext_transport` is installed,
  `ext.on_segment_ack(...)` replaces the builtin dupack/cwnd block; the
  builtin match is preserved verbatim in the `else` branch.
  `local_rx_last_ack`, `local_seq_no` (una) advance and the
  `remote_last_seq < local_seq_no` clamp stay shared.
- `on_mss_update` forwarded to the external controller at both
  handshake MSS-learn sites (lines ~2047, ~2105) alongside the builtin
  `set_mss`.
- Classic-ECN ECE: an ACK segment carrying `ecn_echo` calls
  `cc.on_ecn_ce` once per ACK (field passthrough only; no ECN
  negotiation — AccECN is T7).
- `dispatch()`: `ext.timer_checks` (RACK/TLP deadlines) each dispatch;
  RTO expiry calls `ext.mark_all_lost` instead of rewinding
  `remote_last_seq`; the fast-retransmit timer does not arm
  `pending_fast_retransmit` under ext; send selection order is
  scoreboard-lost records (cwnd-gated) → new data (cwnd + pacing gated)
  → TLP tail probe; post-emit `note_sent` + `pace_after_send` +
  `mark_app_limited` + `clear_tlp_probe`.
- `cwnd_remaining()`: under ext returns `cc.cwnd() - pipe` instead of
  `controller.window() - flight_size`.
- `seq_to_transmit()`: admits cwnd-admissible lost records and pending
  TLP probes under ext.
- `poll_at()`: merged with `next_send_due` and `ext.next_timer()` so
  pacing/RACK/TLP deadlines wake the socket.
- New tests `test_external_transport_controller` and
  `test_external_transport_loss_event_shrinks_cwnd` (end of test mod).

### T4 additions (T4-2 dial options / T4-7 PMTU)

- `syn_extra_options: Option<Vec<u8>>` + `set_syn_extra_options` (T4-2)
  — raw option bytes (validated kind/len walk + SYN option-budget
  check, rejection is explicit `SynOptionsError`) appended verbatim to
  emitted SYNs. `wire/tcp.rs` `Repr` gains `extra_options: &'a [u8]`;
  emit caps the copy at the option area.
- `connect()` (T4-3) — active-open path producing
  SYN/SYN-ACK/Established through the normal state machine (used by the
  AF_XDP reactor's dialed sessions).
- `path_mtu_cap: Option<usize>` + `set_path_mtu`/`path_mtu` (T4-7) — ICMP
  PTB reports install a per-socket IP-datagram-size cap; the stored
  value floors at headers + `MIN_REMOTE_MSS` so a bogus small report
  cannot wedge the flow. Installing a cap disarms the blackhole probe
  and forwards the new effective MSS to the ext controller via
  `on_mss_update`.
- `pmtu_probe_floor` + `rto_no_progress` — RFC 4821-style blackhole
  recovery: `PMTU_BLACKHOLE_RTO_THRESHOLD` (2) consecutive RTOs without
  cumulative-ACK progress arm the probe (`PMTU_PROBE_MSS` = 512 floor);
  any cumulative-ACK advance disarms it.
- `effective_send_mss(interface_mss)` — send-side segment size is now
  `min(interface_mss, remote_mss, pmtu_cap - headers, probe_floor)`;
  the cap term floors at `MIN_REMOTE_MSS` but the final result does
  not (a deliberately small `remote_mss` stays honored).
- New tests `test_set_path_mtu_clamps_segment_size`,
  `test_set_path_mtu_floors_bogus_small_values`,
  `test_pmtu_report_disarms_blackhole_probe`,
  `test_rto_blackhole_probe_arms_and_ack_disarms`.

### T9 additions (in-session buffer autotune)

- `src/storage/ring_buffer.rs`: `RingBuffer::resize(new_capacity)`
  (alloc-gated) — copies the logical contents in read order into a
  fresh owned allocation, preserving `length` and re-basing `read_at`.
  Refuses `new_capacity == capacity` or `< length`; borrowed storage is
  promoted to owned on success.
- `src/socket/tcp.rs`: public APIs
  `grow_recv_buffer`/`grow_send_buffer` (ring resize passthrough),
  `rx_window_wire_cap` (`u16::MAX << remote_win_shift` — the largest
  window encodable under the negotiated scale, 64 KiB when the peer
  offered no RFC 1323 scaling), and
  `set_rx_window_shift_for_ceiling` — raises `remote_win_shift` as if
  the buffer were already the ceiling size, so in-session growth stays
  encodable. Must be called before the socket emits SYN/SYN-ACK (the
  shift is negotiated there); a peer without window-scaling support
  still zeroes it at handshake.
- New field `rx_win_shift_floor: u8` — persists the configured ceiling
  shift across `reset()` (which otherwise re-derives the shift from
  current capacity and would silently drop a pre-handshake ceiling).
  `reset()` now computes `max(capacity-derived shift, floor)`; with
  the floor at its default 0 the computation is byte-for-byte
  upstream.

## `src/socket/tcp/congestion.rs`

- `trait Controller`, `AnyController`, and the builtin `Reno`/`Cubic`
  impls are `pub` — required so reactor code can keep the builtin
  algorithm selected as a comparison path while the external
  controller drives the socket.

## Wire layer

- `wire/tcp.rs`: `Repr` gains `ecn_echo: bool`, `cwr: bool`; parsed
  from/written to the ECE/CWR header flags.
- `wire/ipv4.rs`, `wire/ipv6.rs`: `Repr` gains `ecn: u8`; parsed
  from/written to the DS field ECN bits / traffic class.
- `wire/ip.rs`: `Repr::new` initialises `ecn: 0`; `ecn()` accessor.
- All struct literals (lib + test) updated — field passthrough only,
  no negotiation or egress marking.

## Deferred

- Egress ECT/CE marking and receive-side CE reflection (T7).
- AccECN negotiation (T7).
- Shared-bottleneck detection (T6): statistics interface lives in
  `cloud-node-transport::inference`.
- EdgeCC decision layer (T5): the installed controller remains
  `CubicRef` for T3.
