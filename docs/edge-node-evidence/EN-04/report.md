# EN-04 — XDP Module Boundary Refactor

Base commit: `9602ef2` (post EN-03). Scope: `src/xdp.rs` (11,049 lines, single file)
split into a module directory with non-overlapping ownership boundaries. **No
behavior, verdict, ABI, or performance change was mixed into this refactor** —
the eBPF object (`data/cloud-node-xdp-ebpf.o`, sha256
`1532610c…fddb9bbee53bfe6bdb3f40ee5d8c6fc6345bb20f`) is byte-identical to the
EN-03 build.

## Module boundaries

| File | Lines | Ownership |
|---|---|---|
| `src/xdp/mod.rs` | 2,022 | Public API, `XdpManager`, runtime status/snapshots, attach/detach orchestration, doctor/tune/dump-maps entry points |
| `src/xdp/policy.rs` | 292 | `RangeKey`, `RuleState`, shadow rule state, `XdpRuleVerdict`, range conversion |
| `src/xdp/linux.rs` | 2,032 | eBPF loader, pinned-map spec/GC, `XDP_COUNTERS` per-CPU aggregation, map sync, AF_XDP socket setup |
| `src/xdp/smoke.rs` | 1,214 | raw/proxy/reload smoke harnesses (Linux-gated bodies) |
| `src/xdp/af_xdp/mod.rs` | 282 | Shared AF_XDP types/imports; named `pub use` re-exports (external surface) + `pub(crate)` glob re-exports (internal surface) |
| `src/xdp/af_xdp/parser.rs` | 664 | Wire parsing, flow keys, reply-frame encoding |
| `src/xdp/af_xdp/tcp_reactor.rs` | 1,340 | `AfXdpTcpStream`, virtual-stream reactor, smoltcp diagnostics |
| `src/xdp/af_xdp/bridge.rs` | 881 | `AfXdpRuntime`, queue bridge, UDP/TCP proxy loops |
| `src/xdp/tests.rs` | 2,353 | XDP + AF_XDP unit/integration tests |

## Public entry points preserved

- `crate::xdp::af_xdp::{AfXdpRuntime, runtime, start_proxy_bridge,
  start_udp_bridge, parse_proxy_frame, extract_ip_frame, parse_l4_packet,
  encode_ip_reply_frame, encode_udp_reply_frame, AfXdpTcpStream,
  AfXdpTcpStreamParts}` — consumed unchanged by `src/udp_proxy.rs`,
  `src/quic_udp_demux.rs`, `src/http_proxy_manager.rs`, `src/tcp_proxy.rs`,
  `src/main.rs`.
- `crate::xdp::{XdpManager, attach, detach, status, dump_maps, doctor, tune,
  reload, smoke entry points, virtual_l4_stream, tcp_flags_are_initial_syn}`
  all re-exported from `mod.rs` with original signatures.
- Non-Linux callers keep `virtual_l4_stream` and all cross-platform APIs;
  Linux-only bodies stay behind `cfg(target_os = "linux")`.

## Mechanism

Mechanical line-range cut at the three pre-existing `mod` seams
(`mod linux`, `pub mod af_xdp`, `mod tests`), then af_xdp sub-split at item
boundaries (parser / tcp_reactor / bridge). Post-split fixes were confined to
Rust module-system mechanics:

- Orphan `#[derive]` lines left at cut seams re-attached to their items
  (`RangeKey`/`RuleState` → `policy.rs`; `AfXdpRuntime` → `bridge.rs`).
- Visibility: cross-module field/method access raised to `pub(crate)` on
  item definitions only (struct literals inside function bodies untouched);
  `pub(super)` normalized to `pub(crate)`; trait-impl methods keep no
  visibility qualifier.
- `smoke.rs` `include_bytes!`/`include_str!` paths gained one `..` level
  (file moved from `src/` to `src/xdp/`).
- Non-Linux unused-import warnings on glob re-exports handled with
  `cfg_attr(not(linux), allow(unused_imports))` — re-exports stay compiled so
  `af_xdp::item` paths resolve on all targets (tests + tcp_reactor use them
  cross-platform).

## Verification

| Check | Result |
|---|---|
| macOS `cargo check --lib` | PASS, 0 unused warnings |
| macOS `cargo test --lib xdp` | PASS — 93/93 |
| Linux (x86-build, kernel 7.0) `cargo check --lib --tests` | PASS, 0 errors |
| Linux `cargo test --lib xdp` | PASS — 97/97 (includes linux-gated cases) |
| Linux real-eBPF runner (`--mode proxy`, netns topology) | PASS — T01 17/17, T02 4/4, T03 3/3, T04 2/2, T06 1/1; `ok: true` |
| `cargo fmt -- --check` (xdp files) | clean |
| eBPF object | unchanged from EN-03 (userspace-only refactor) |

## Independently revertible

The split is a pure `git mv` + boundary fix commit; `src/xdp.rs` history is
preserved as rename (`RM src/xdp.rs -> src/xdp/mod.rs`). Reverting this commit
restores the monolith byte-for-byte; no other task depends on the new paths
yet (EN-05+ will target them).

## Known remaining warnings (pre-existing, not EN-04)

- Dead-code warnings in `http_proxy_manager.rs` / `runtime_mode.rs` predate
  the split (verified on `9602ef2` baseline).
- `XdpRuleVerdict` fields flagged unused on non-Linux builds — pre-existing
  pattern, verdict type is consumed by linux-gated code.
