#!/usr/bin/env bash
# cloud-node-rust release build — LOCAL macOS cross-compile to Linux x86_64.
#
# Mirrors /root/memgov/build-release.sh semantics on the build host:
# - Invoke the real rustup cargo, not the mbx PATH shim (mbx's GC has deleted
#   target/ mid-build on the remote; the same shim exists here).
# - CARGO_TARGET_DIR stays unset so it cannot leak into the nested eBPF cargo
#   (build.rs) and deadlock on the parent's build lock.
# - v3 codegen is scoped to TARGET units only via CARGO_TARGET_*_RUSTFLAGS.
#   Cargo flag precedence means this also OVERRIDES the repo .cargo/config
#   `target-cpu=native` for the linux target — required: native would resolve
#   to the M1 host CPU and break x86_64 codegen. Host units (build scripts,
#   proc macros) still get native -> arm64, which is correct.
# - zigbuild supplies the linker + C toolchain (zig cc) + glibc floor (2.36;
#   node runs Debian 13 with a newer glibc).
# - Default target is the production binary only (plain --release would
#   fat-LTO all 8 src/bin targets ~2x wall time). Pass --all-bins to override.
#
# Cross-toolchain inputs (all under ~/.local/share/cross-sysroot):
# - debian-amd64/: Debian 12 amd64 sysroot assembled from .deb packages
#   (libelf-dev, zlib1g-dev, linux-libc-dev) — gives pkg-config a TARGET
#   libelf/zlib for libbpf-sys' vendored libbpf, and kernel UAPI headers
#   for the BPF object compile.
# - cross-clang.sh: homebrew llvm clang (has the bpf backend) + sysroot
#   include paths — libxdp-sys builds xdp-dispatcher.c as a BPF object.
# - cross-ld.sh: ld.lld -m elf_x86_64 — libxdp-sys' GNU-ld-style binary
#   embed step; /usr/bin/ld is Apple's and rejects GNU flags.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
unset CARGO_TARGET_DIR CARGO_ENCODED_RUSTFLAGS RUSTFLAGS RUSTC_WRAPPER CARGO_BUILD_TARGET

SYSROOT="$HOME/.local/share/cross-sysroot/debian-amd64"
export PKG_CONFIG_PATH="$SYSROOT/usr/lib/x86_64-linux-gnu/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$SYSROOT"
export CLANG="${CLANG:-$HOME/.local/share/cross-sysroot/cross-clang.sh}"
export LD="${LD:-$HOME/.local/share/cross-sysroot/cross-ld.sh}"
export OBJCOPY="${OBJCOPY:-/opt/homebrew/opt/llvm/bin/llvm-objcopy}"
export AR="${AR:-/opt/homebrew/opt/llvm/bin/llvm-ar}"

# x86-64-v2 default: matches the CI baseline and the fleet floor — the
# XDP node runs Ivy Bridge Xeons (AVX, no AVX2/BMI2/FMA) and v3 SIGILLs
# there. Override with CLOUD_NODE_TARGET_CPU for v3-capable targets.
TARGET_CPU="${CLOUD_NODE_TARGET_CPU:-x86-64-v2}"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=$TARGET_CPU -L $SYSROOT/usr/lib/x86_64-linux-gnu"
GLIBC="${CLOUD_NODE_GLIBC:-2.36}"
TARGET="x86_64-unknown-linux-gnu.${GLIBC}"
if [ "${1:-}" = "--all-bins" ]; then
  shift
  exec cargo zigbuild --release --target "$TARGET" "$@"
fi
exec cargo zigbuild --release --target "$TARGET" --bin cloud-node-rust "$@"
