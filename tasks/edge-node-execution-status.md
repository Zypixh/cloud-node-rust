# Edge-node execution status

Single-implementer tracker for the EN-00..33 productionization plan.
Status vocabulary: TODO / IN_PROGRESS / IMPLEMENTED / VERIFIED only.

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

- EN-14 eBPF verifier acceptance on kernel 6.1 — pending probe run on .120.
- EN-14 IPv6 challenge path: not implemented (bounded admission only;
  rule sync rejects challenge on v6 explicitly).
- EN-14 cookie key rotation API: install-on-first-attach done; rotation
  (cur→prev) pending.
- EN-16: BLOCKED/ALLOWED ACL maps now size-configurable via
  `xdp.stateTables.aclBlocked/aclAllowed/rateV4` (see night section below).
- EN-12 zero-copy success path: needs real NIC — external acceptance.

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
