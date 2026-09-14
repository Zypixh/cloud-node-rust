#!/bin/sh
# Remote build script — run ON an authorized VPS inside /root/cloud-node-dev.
# Constrained: CARGO_BUILD_JOBS=1, debuginfo=0, one build at a time.
# Prereqs on the build host (.110):
#   - rustup stable + nightly (rust-src component)
#   - bpf-linker prebuilt binary in ~/.cargo/bin (v0.11.1 musl, LLVM 23.1.1)
#     cargo install bpf-linker FAILS: llvm-sys needs LLVM==23, Debian has 14.
set -eu
cd "$(dirname "$0")/../.." 2>/dev/null || cd /root/cloud-node-dev
[ -f Cargo.toml ] || { echo "missing Cargo.toml" >&2; exit 2; }
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-C debuginfo=0"
echo "=== build $(date -u +%FT%TZ) ==="
rustc --version
rustc +nightly --version
bpf-linker --version 2>/dev/null | head -1
free -m | head -2
echo "--- userspace debug build (build.rs also builds eBPF object) ---"
cargo build 2>&1 | tail -25
ls -la crates/cloud-node-xdp-ebpf/target/bpfel-unknown-none/release/cloud-node-xdp-ebpf 2>/dev/null
echo "--- tests ---"
cargo test --workspace 2>&1 | tail -15
echo "=== done $(date -u +%FT%TZ) ==="
