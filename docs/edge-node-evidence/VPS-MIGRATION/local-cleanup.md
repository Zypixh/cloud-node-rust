# M0 local cleanup — Mac host

Date: 2026-09-14. Host: macOS (dev workstation). Policy: no local compile/test; remote-only builds on authorized VPSs.

## Freed space

`/dev/disk3s3s1` free: **7.5 GiB → 25 GiB** (~17.5 GiB released).

## Removed paths

| Path | Size before | Git-tracked | Origin | Action |
|---|---|---|---|---|
| `target/` (repo root) | 17 GiB | no (gitignored) | prior cargo builds | removed |
| `crates/cloud-node-xdp-common/target/` | 25 MiB | no | nested crate build | removed |
| `data/cloud-node-xdp-ebpf.o` | 136 KiB | **no** — untracked + matched by `.gitignore:/data/` | generated eBPF object | removed; regenerated on VPS by `build.rs`/`cargo +nightly` |
| `/tmp/en14-ebpf.o` | ~130 KiB | n/a | prior eBPF build output | removed |
| `~/.cargo/registry/cache/*` | 166 MiB | n/a | shared cargo download cache (regeneratable) | removed |
| `~/.cargo/registry/src/*` | 1.1 GiB | n/a | extracted crate sources (regeneratable) | removed |
| `~/.cargo/git/*` | 992 KiB | n/a | git dep checkouts (regeneratable) | removed |

## Preserved

- All source/dirty work: 6 modified files + `docs/adr/`, `scripts/edge/en14_cookie_probe.py`, `tasks/devin-vps-continuation.md` intact.
- Rust toolchains (`~/.rustup`, `~/.cargo/bin`), cargo config, credentials — untouched.
- No `cargo clean` invoked; no toolchain/bootstrap triggered. Direct `rm` on verified artifact paths only.
- No unrelated project dirs touched.

## Process check

`pgrep -fl 'cargo|rustc|orb'` → no running build/test processes at cleanup time. Nothing killed.

## Notes

- `data/cloud-node-xdp-ebpf.o` ambiguity resolved: `git ls-files --error-unmatch` fails (untracked) and `git check-ignore -v` shows `.gitignore:4:/data/` — it is a generated artifact, safe to remove; remote builds embed a freshly built object.
- No custom `CARGO_TARGET_DIR` was set; no other nested `target/` dirs found (`find . -name target -type d`).
