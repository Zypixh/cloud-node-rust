#!/bin/bash
# Remote build script — run ON an authorized VPS inside /root/cloud-node-dev.
# Constrained: CARGO_BUILD_JOBS=1, debuginfo=0, one build at a time (flock).
# Prereqs on the build host (.110):
#   - rustup stable + the dated nightly pinned in
#     crates/cloud-node-xdp-ebpf/rust-toolchain.toml (rust-src component)
#   - bpf-linker prebuilt binary in ~/.cargo/bin (v0.11.1 musl, LLVM 23.1.1)
#     cargo install bpf-linker FAILS: llvm-sys needs LLVM==23, Debian has 14.
#
# R0 contract: every step's exit code is real — logs are written in full and
# only tailed for display. A failed build/test exits nonzero and never
# prints the done marker.
set -euo pipefail

TASK_DIR="${1:-/root/cloud-node-dev}"
LOCK="$TASK_DIR/.build.lock"
MARKER="$TASK_DIR/.cn-task-owner"

# --- entry gates: OS, registered host, owned task dir -------------------
[ "$(uname -s)" = "Linux" ] || { echo "refusing: not Linux" >&2; exit 64; }
[ -f /root/.cn-authorized-vps ] || {
    echo "refusing: host not enrolled (/root/.cn-authorized-vps missing)" >&2
    exit 64
}
[ -d "$TASK_DIR" ] || { echo "refusing: missing task dir $TASK_DIR" >&2; exit 64; }
[ -f "$MARKER" ] || {
    echo "refusing: $TASK_DIR lacks .cn-task-owner marker (not a registered task dir)" >&2
    exit 64
}
cd "$TASK_DIR"
[ -f Cargo.toml ] || { echo "missing Cargo.toml" >&2; exit 2; }

# --- single-build mutex (non-blocking; a contended build fails fast) ----
exec 9>"$LOCK"
flock -n 9 || { echo "refusing: another build holds $LOCK" >&2; exit 75; }

export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-C debuginfo=0"

echo "=== build $(date -u +%FT%TZ) host=$(hostname) dir=$TASK_DIR ==="
rustc --version
EBPF_NIGHTLY="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' crates/cloud-node-xdp-ebpf/rust-toolchain.toml | head -1)"
rustc "+${EBPF_NIGHTLY:-nightly}" --version
bpf-linker --version 2>/dev/null | head -1
free -m | head -2

echo "--- userspace debug build (build.rs also builds eBPF object) ---"
# Full log kept on disk; tail is display-only. No pipe status ambiguity.
rc=0
cargo build > build.log 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then
    echo "BUILD FAILED rc=$rc (full log: $TASK_DIR/build.log)" >&2
    tail -25 build.log >&2
    exit "$rc"
fi
tail -25 build.log
ls -la crates/cloud-node-xdp-ebpf/target/bpfel-unknown-none/release/cloud-node-xdp-ebpf
sha256sum crates/cloud-node-xdp-ebpf/target/bpfel-unknown-none/release/cloud-node-xdp-ebpf target/debug/cloud-node-rust

echo "--- tests ---"
rc=0
cargo test --workspace > test.log 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then
    echo "TEST FAILED rc=$rc (full log: $TASK_DIR/test.log)" >&2
    tail -30 test.log >&2
    exit "$rc"
fi
tail -15 test.log
echo "=== done $(date -u +%FT%TZ) ==="
