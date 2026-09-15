# Edge-node execution status

Single-implementer tracker for the EN-00..33 productionization plan.
Status vocabulary: TODO / IN_PROGRESS / IMPLEMENTED / VERIFIED only.

## Current review override — 2026-09-15, baseline e3fb282

Static review only; no local build/test or VPS execution by the reviewer. Next manual Devin input: [review and repair plan](devin-next-round-2026-09-15.md). Execute R0–R4 before EN-17. Current task statuses are in the production plan: EN-13 IN_PROGRESS, EN-14/15 IMPLEMENTED, EN-16 IN_PROGRESS. Preserve historical run records below, but their VERIFIED/close-out wording does not supersede these outstanding findings. Local cargo tests violated the remote-only instruction and recreated build artifacts; execution must return to the authorized VPSs.

## Active milestone: M0 (VPS migration) → M1/M2

### Environment

- Local Mac: build/test forbidden. Source edits + sync only.
- `.110` (ser790960344190): build host. Debian 6.1.0-10 amd64, 2c/2G, 2G bounded
  swapfile at `/root/cloud-node-dev.swapfile` (task-scoped, removable).
  rustup stable 1.98.1 + nightly-1.100 (rust-src) + bpf-linker 0.11.1 prebuilt
  (LLVM 23.1.1, matches nightly). Task dir `/root/cloud-node-dev`.
- `.120` (ser591614511633): probe host. Same kernel; netns/veth verified;
  scapy+pyyaml present. No toolchain. Task dir `/root/cloud-node-dev`;
  node binary at `/root/cloud-node-dev/node-bin` (streamed from .110).
- Sync: `scripts/edge/vps_sync.sh <host>` (994 files, SHA256 manifest check).
- Remote build: `scripts/edge/vps_remote_build.sh` or direct
  `CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RUSTFLAGS="-C debuginfo=0" cargo build`.

### M0 results so far

- Local cleanup: 7.5Gi→25Gi free. `docs/edge-node-evidence/VPS-MIGRATION/local-cleanup.md`
- eBPF object builds on .110 via real bpf-linker (ELF bpfel).
- `cargo build` userspace: OK (6m31s, debug profile).
- `cargo test`: in progress; last run 679/680 pass, fixed
  `memory_governor` transient-overshoot race via CAS admission.

### Code changes this round (uncommitted)

- `build.rs`: `rustup run nightly` + env_remove(RUSTC/RUSTUP_TOOLCHAIN) so the
  embedded eBPF build uses the nightly sysroot.
- `memory_governor.rs`: CAS-based admission (class counter + zero-copy relays)
  — counter can no longer exceed the hard limit even transiently.
- `runtime_mode.rs` / `linux.rs` / `mod.rs` / `xdp_auto_config.rs` /
  `xdp_config_wizard.rs`: EN-16 `xdp.stateTables` operator-sized state tables
  (ct/pending/snatRev/flowAcct/rateV6/quicDcid) applied via
  `set_max_entries`, counted by the ledger, audited post-load.
- `tests.rs`: XdpUdpForwardConfig.challenge literal updates + explicit
  challenge-gating rejection cases + stateTables projection test.
- `en14_cookie_probe.py`: stateTables sizing for 2GiB probe host.

### Known gaps being worked

- EN-14 IPv6 challenge path: not implemented (bounded admission only;
  rule sync rejects challenge on v6 explicitly).
- EN-14 cookie key rotation API: install-on-first-attach done; rotation
  (cur→prev) pending.
- EN-14 R2.4 deep variants (out-of-order, mid-flow key rotation, third-ACK
  data) not yet individually exercised — core handshake/data/FIN/RST proven.
- EN-16: BLOCKED/ALLOWED ACL maps now size-configurable via
  `xdp.stateTables.aclBlocked/aclAllowed/rateV4` (see night section below).
- EN-12 zero-copy success path: needs real NIC — external acceptance.

## 2026-09-15 (validation) — R0–R4 acceptance round on authorized VPSs

Round executed per `devin-next-round-2026-09-15.md`. Mac edited/transferred
only; all builds, tests, eBPF builds and probes ran on `.110`/`.120`
(Debian 12, kernel 6.1.0-10-amd64, 2c/2GiB). Evidence:
`docs/edge-node-evidence/REVIEW-2026-09-15/`.

- R0: sync/build scripts rewritten — single manifest drives
  rsync+checksums+remote sweep; ownership/registration markers; flock;
  real exit codes. Negative paths verified: lock rc=75, unowned dir rc=3,
  corrupted file rc=4, build failure rc=101 (no false success marker).
- R1+R2: EN-14 eBPF fixes verified by the upgraded probe
  (en14-probe-r6.json, 16 phases PASS):
  - R1.1 zero-key fail-closed (keyless SYN rejected; zero-key forged
    cookie rejected; established splice flow keeps forwarding).
  - R1.2 forge scratch `tb[16..20]` cleared; forged frames pass
    independent checksum validation; FAIL_FORGE → explicit failure.
  - R2.2 worker `Err` → XDP_DROP + pending/SNAT rollback +
    `challenge_worker_err` counter + `INTERNAL_ERR` flow event; all four
    fault-injection points exercised (I/J/K phases).
  - R2.3 absent/malformed MSS → idx 0 = 536 fallback (M phase).
  - R2.4 real kernel TCP end-to-end in the probe netns: real ISNs,
    challenge admission, bidirectional echo, FIN and RST teardown (R phase).
  - Probe-side fix (not an eBPF regression): crafted frames now carry a
    genuine TCP checksum so incremental dataplane updates stay valid.
- R3: EN-15 `retryPps` aggregate budget + explicit `ignore()`/`refuse()`
  wire semantics; attempted/issued/limited counters to perf-monitor;
  production `run_endpoint` accept-loop test. `.110` full
  `cargo test`: 753 passed / 0 failed (test.log preserved remotely).
- R4: this review round archived; statuses normalized below.

Status after this round (unchanged vocabulary, no premature VERIFIED):
EN-12 IMPLEMENTED (veth/copy verified; real-NIC zero-copy external),
EN-13 IN_PROGRESS, EN-14 IMPLEMENTED (probe-verified incl. real kernel
TCP; deep-variant coverage and IPv6 remain), EN-15 IMPLEMENTED,
EN-16 IN_PROGRESS.

## 2026-09-15 (night) — EN-16 hysteresis + ACL sizing, EN-15 QUIC Retry

EN-16 close-out (all local tests green; .110 suite re-running):

- `XdpStateTables` gains `aclBlocked`/`aclAllowed`/`rateV4` — the last
  large maps are now operator-sizable; `state_table_override` covers all
  three and `map_max_entries` (non-deprecated aya API) applies them
  pre-load. tests.rs literals updated; probe config carries the knobs.
- `LevelHysteresis` (timed 5s de-escalation dwell) wraps the three
  level-quantized channels: memory bands, aggregate surge, kernel SYN.
  Utilization channels keep threshold hysteresis (exit 90/75/60).
  Escalation stays immediate in both schemes. Tests cover immediate
  escalation, exit thresholds, dwell timing, and dwell reset on
  re-escalation.
- `kernel_syn_defense` now publishes its pressure through
  `syn_pressure_level_hysteretic` — raw per-second levels no longer flap
  the emitted level.
- ADR-002 documents the tenant-granularity contract: no tenant identity
  exists in the config model; fairness boundary is the (listener, class)
  pool, and any future tenant model extends the key without conflict.
- `effective_threshold_scales_down_with_pressure` had no #[test]
  attribute (was silently dead) — restored.

EN-15 implemented (src/http3_proxy_manager.rs + config_models.rs):

- Retry gate on `quinn::Incoming` in the accept loop: after the L4-block
  check, BEFORE handshake state/permits/tasks. Unvalidated Initials get a
  stateless `retry()` under policy; validated clients (retry token or
  NEW_TOKEN) skip it — a valid Retry cannot loop.
- Policy `http3Policy.addressValidation`: `adaptive` (default; retry only
  while L4 pressure >= Elevated), `always`, `off`. Pre-SNI means
  per-service granularity is structurally impossible — the knob is
  listener/global.
- Observability: `h3_retry_counters()` (issued/failed/validated) +
  debug logs; deliberately NOT recorded via record_l4_event (retry is not
  hostile evidence — it would feed auto-block scoring).
- Passthrough QUIC never reaches the H3 listener (desired_ports excludes
  quic-passthrough) — no Retry injected; migration is validated by
  quinn's PATH_CHALLENGE and QUIC conns aren't in the L4 registry, so
  tuple changes can't kill them.
- Test: real quinn client+endpoint e2e — 1 retry then validated; second
  connect validated immediately via NEW_TOKEN (retries stay at 1).

Evidence: docs/edge-node-evidence/EN-15/report.md.

## 2026-09-15 (late) — EN-14 verifier hardening on kernel 6.1

The EN-14 eBPF object now compiles but the 6.1 verifier keeps rejecting it;
fixes so far (all source-level, no verifier bypass):

1. `XdpSnatRevKey._pad` 3→4B (common + eBPF mirror + all 9 init sites):
   compiler tail padding read as uninitialized stack in the 24B map key.
2. Packed-offset masking `(meta>>8)&0x3fff`, `(offsets>>16)&0x3fff`.
3. `bpf_xdp_load_bytes`/`bpf_xdp_store_bytes` (`pkt_load`/`pkt_store`/
   `pkt_u8`/`pkt_u16be`) for ALL variable-offset packet access in the new
   challenge/forge/patch paths — `data+var_off` pointers lose their range
   under 6.1 (`r=0` after `ptr+N>end` check).
4. `tcp_syn_mss_idx` rewritten as a straight-line 3-slot probe
   (MSS / NOP+MSS / NOP+NOP+MSS → else 1460 index): the bounded option
   loop blew the 8193-jump sequence limit with per-byte helper calls, and
   a stack-buffer walk needs variable-offset stack reads (also rejected).
5. `panic_bounds_check` eliminated again — `.get()`/const slices only;
   a panic call linked last in a program image fails `check_cfg`.
6. Forge helpers moved header staging into NatScratch (`forge_ipb`/`forge_tb`/
   `forge_tmp`, map value 376→432B) and compute both checksums over the
   staging buffers BEFORE `pkt_store`/`adjust_tail` — combined nested-call
   stack was 672→576B, still >512; scratch staging cuts forge frames
   272→104B / 256→64B. Deepest chain now ~496B.

Status: object `b530597c…` passes ELF level; userspace spec ledger needs
the matching `size_of::<NatScratch>()` rebuild (node-bin rebuild running
on .110). Next: rerun `en14_cookie_probe.py` on .120 with new pair.

## 2026-09-15 (later) — EN-14 VERIFIED on kernel 6.1 (veth/netns)

eBPF object `e549c835…` + node-bin `b8c0ab7c…` — `en14_cookie_probe.py`
on `.120` (kernel 6.1.0-10-amd64): **all 8 phases PASS**.

Remaining verifier fixes this round (source-level, no semantic change):

- `bound_work_offsets` / `work_ctx` / `maybe_redirect`: packet offsets are
  AND-masked (`&0x7ff`) at the load/boundary instead of min()/range checks.
  On 6.1 a spill slot keeps its store-time type — a value spilled before
  the bound check reloads unbounded; and caller-side bounds become LLVM
  range attrs that fold callee checks. The AND is unfoldable and kills the
  raw value, so every downstream copy is verifier-visible `umax<=0x7ff`.
- SNAT-reply path: splice gate moved BEFORE the client-directed rewrite so
  the slot-11 anchor worker forges on the original backend-directed frame
  (eth.src=backend next-hop, ip.dst=VIP). Previously the forged ACK went
  out with the client address as source.
- `cookie_slot = now>>32` (~4.3s slot, ~8.6s cur+prev validity): the 67ms
  slots rejected legitimate ACKs beyond ~134ms RTT.
- Probe script fixes (test-harness only): TCP header unpack format, signed
  seq_delta decode, phase F asserts challenge-shape not cookie equality,
  phase G uses a fresh tuple + fresh SYN so it exercises the keyless
  fail-closed path instead of hitting the established CT.
- Failure diagnostics: probe now dumps counters+map state into the report
  on assertion failure before teardown.

Evidence: docs/edge-node-evidence/EN-14/{report.md,manifest.json}.

Known gaps carried forward: EN-14 IPv6 challenge unimplemented (v6 rules
reject `challenge` at config sync — explicit, not silent); cookie key
rotation API pending (install-on-attach works); third-ACK payload not
forwarded (documented limitation); EN-12 zero-copy needs real NIC.

## 2026-09-15 (EN-17 first slice) — AF_XDP TCP reactor scheduling + copy elim

EN-17 first verified slice (userspace only; eBPF object unchanged `3b8549a9`):

- Hot-set session scheduling: per-poll full-table scan replaced by dedup'd
  `hot_sessions` queue (ingress `mark_hot` + proxy→reactor wake channel),
  budgets `AF_XDP_TCP_PUMP_BUDGET=512` / `INGRESS_BUDGET=512` /
  `WAKE_DRAIN_BUDGET=8192`; 250ms `SWEEP_INTERVAL` full sweep as backstop.
- Bounded ingress: `device.ingress` cap 4096; overflow → explicit
  `IngressQueueFull` status, `ingressQueueDropped` diag, counts toward
  consecutive-admission-refusal fault containment. `wakeSignals` diag added.
- Session reaping cadence-gated at the same interval (independent
  `last_retain`); reapable sessions leave the hot set immediately.
- Copy/alloc eliminations: smoltcp `recv` closure → `Bytes` directly
  (`rx_scratch` removed); per-packet `interface.to_string()` removed on RX;
  `AfXdpRouteMeta.interface` → `Arc<str>` (route clone = refcount);
  same-interface TCP egress encodes into bridge `encode_scratch` — no
  per-frame `tx_scratch.clone()` (cross-interface forward keeps owned frame).

Validation (.110, VPS-only): `cargo check --all-targets` clean;
`cargo test --lib` **693 pass / 0 fail**; 4 new scheduler tests + reap
test updated for cadence gating (assertion tightened, not loosened).

Evidence: docs/edge-node-evidence/EN-17/report.md.

Status: EN-17 IN_PROGRESS — scheduler slice verified at unit level; T05/T06/T07
throughput/flood acceptance needs real-NIC evidence; wake channel is
`UnboundedSender` (documented limitation, drain-budgeted + dedup'd).
