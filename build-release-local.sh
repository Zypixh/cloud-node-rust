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
# - libelf/zlib come from a Debian-dev sysroot (~/tools/sysroot-*) because
#   libbpf-sys/libxdp-sys link -lelf -lz; elfutils' autotools cross build is
#   fragile, the .deb extraction path is not.
# - Default target is the production binary only (plain --release would
#   fat-LTO all 8 src/bin targets ~2x wall time). Pass --all-bins to override.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:/opt/homebrew/opt/flex/bin:/opt/homebrew/opt/bison/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
unset CARGO_TARGET_DIR CARGO_ENCODED_RUSTFLAGS RUSTFLAGS RUSTC_WRAPPER CARGO_BUILD_TARGET
SYSROOT="$HOME/tools/sysroot-x86_64-linux-gnu"
SYSROOT_LIB="$SYSROOT/usr/lib/x86_64-linux-gnu"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=x86-64-v3 -L native=$SYSROOT_LIB"
export CFLAGS_x86_64_unknown_linux_gnu="-I$SYSROOT/usr/include"
export LIBBPF_SYS_EXTRA_CFLAGS="-I$SYSROOT/usr/include"
export LIBBPF_SYS_LIBRARY_PATH="$SYSROOT_LIB"
# libxdp-sys use_cc_build toolchain: real clang w/ BPF backend + lld + binutils
# equivalents from brew llvm (keg-only paths, so no PATH pollution needed).
LLVM_BIN="/opt/homebrew/opt/llvm/bin"
export CLANG="$LLVM_BIN/clang"
export LD="$HOME/tools/x-wrappers/ld.lld-x86_64"
# zigbuild's `ar` wrapper emits empty archives on ELF objects (breaks
# libbpf-sys/libxdp-sys static archives); use real llvm-ar instead.
export AR="$LLVM_BIN/llvm-ar"
export RANLIB="$LLVM_BIN/llvm-ranlib"
export OBJCOPY="$LLVM_BIN/llvm-objcopy"
export READELF="$LLVM_BIN/llvm-readelf"
export LLC="$LLVM_BIN/llc"
export PKG_CONFIG_PATH="$SYSROOT_LIB/pkgconfig"
export PKG_CONFIG_LIBDIR="$SYSROOT_LIB/pkgconfig"
# Kernel uapi headers for libxdp-sys's BPF program compiles (xdp-dispatcher
# hardcodes -I/usr/include/x86_64-linux-gnu which does not exist on macOS;
# C_INCLUDE_PATH supplies the real search dirs for clang -target bpf).
export C_INCLUDE_PATH="$SYSROOT/usr/include:$SYSROOT/usr/include/x86_64-linux-gnu"
GLIBC="${CLOUD_NODE_GLIBC:-2.36}"
TARGET="x86_64-unknown-linux-gnu.${GLIBC}"
if [ "${1:-}" = "--all-bins" ]; then
  shift
  exec cargo zigbuild --release --target "$TARGET" "$@"
fi
exec cargo zigbuild --release --target "$TARGET" --bin cloud-node-rust "$@"
