use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn find_protos(dir: &str) -> Result<Vec<String>, std::io::Error> {
    let mut protos = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("._"))
        {
            continue;
        }
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("proto") {
            protos.push(path.to_string_lossy().into_owned());
        } else if path.is_dir() {
            protos.extend(find_protos(path.to_str().unwrap())?);
        }
    }
    Ok(protos)
}

/// SHA-256 hex of `bytes` via the platform tool — build scripts avoid
/// pulling a crypto dependency; release environments guarantee coreutils.
fn sha256_hex(bytes: &[u8]) -> String {
    use std::io::Write;
    for cmd in ["sha256sum", "shasum"] {
        let mut command = Command::new(cmd);
        if cmd == "shasum" {
            command.args(["-a", "256"]);
        }
        command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        let Ok(mut child) = command.spawn() else {
            continue;
        };
        if child
            .stdin
            .as_mut()
            .and_then(|stdin| stdin.write_all(bytes).ok())
            .is_none()
        {
            let _ = child.kill();
            continue;
        }
        if let Ok(output) = child.wait_with_output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                if let Some(hex) = text.split_whitespace().next() {
                    return hex.to_ascii_lowercase();
                }
            }
        }
    }
    panic!("sha256sum/shasum is required to verify CLOUD_NODE_XDP_EBPF_SOURCE");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    let build_timestamp = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0)
        });
    println!(
        "cargo:rustc-env=CLOUD_NODE_BUILD_TIMESTAMP={}",
        build_timestamp
    );

    let proto_dir = "proto_defs/output_protos";
    let models_dir = "proto_defs/output_protos/models";

    if std::path::Path::new(proto_dir).exists() {
        let protos = find_protos(proto_dir)?;
        let includes = vec![proto_dir.to_string(), models_dir.to_string()];

        println!("cargo:rerun-if-changed={}", proto_dir);

        // Compile with configure
        tonic_prost_build::configure()
            .build_server(false)
            .compile_protos(&protos, &includes)?;
    }

    embed_xdp_ebpf_object()?;
    Ok(())
}

/// The XDP program must ship inside the main binary: the kernel only accepts
/// eBPF bytecode at the XDP hook, and keeping the object as a separate runtime
/// file invites binary/object version skew. Build the eBPF crate for Linux
/// targets and point `CLOUD_NODE_XDP_EBPF_OBJECT` at the artifact so
/// `aya::include_bytes_aligned!` can embed it.
fn embed_xdp_ebpf_object() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let dest = out_dir.join("cloud-node-xdp-ebpf.o");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        // XDP is Linux-only; emit a placeholder so include_bytes compiles.
        fs::write(&dest, b"")?;
        println!("cargo:rustc-env=CLOUD_NODE_XDP_EBPF_OBJECT={}", dest.display());
        return Ok(());
    }

    println!("cargo:rerun-if-changed=crates/cloud-node-xdp-ebpf/src");
    println!("cargo:rerun-if-changed=crates/cloud-node-xdp-ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=crates/cloud-node-xdp-common/src");
    println!("cargo:rerun-if-changed=crates/cloud-node-xdp-common/Cargo.toml");
    println!("cargo:rerun-if-env-changed=CLOUD_NODE_XDP_EBPF_SOURCE");
    println!("cargo:rerun-if-env-changed=CLOUD_NODE_XDP_EBPF_SHA256");

    // Release builds embed a caller-designated object so the embedded bytes
    // are provably identical to the packaged data/cloud-node-xdp-ebpf.o:
    // CI builds the object first, records its SHA256, then builds the node
    // with both env vars set. When CLOUD_NODE_XDP_EBPF_SHA256 is present the
    // file must match — a stale or foreign object fails the build loudly
    // instead of being embedded silently.
    if let Ok(source) = std::env::var("CLOUD_NODE_XDP_EBPF_SOURCE") {
        let source_path = PathBuf::from(&source);
        let bytes = fs::read(&source_path).map_err(|err| {
            format!(
                "CLOUD_NODE_XDP_EBPF_SOURCE={source} is not readable: {err}"
            )
        })?;
        if bytes.is_empty() {
            return Err(format!(
                "CLOUD_NODE_XDP_EBPF_SOURCE={source} is empty"
            )
            .into());
        }
        if let Ok(expected) = std::env::var("CLOUD_NODE_XDP_EBPF_SHA256") {
            let expected = expected.trim().to_ascii_lowercase();
            if !expected.is_empty() {
                let actual = sha256_hex(&bytes);
                if actual != expected {
                    return Err(format!(
                        "CLOUD_NODE_XDP_EBPF_SOURCE={source} sha256 mismatch: expected {expected}, got {actual}"
                    )
                    .into());
                }
            }
        }
        fs::copy(&source_path, &dest)?;
        println!("cargo:rustc-env=CLOUD_NODE_XDP_EBPF_OBJECT={}", dest.display());
        return Ok(());
    }

    let ebpf_target = "bpfel-unknown-none";
    let manifest = "crates/cloud-node-xdp-ebpf/Cargo.toml";
    // Spawn via `rustup run` so the nested build resolves the nightly
    // sysroot even though the parent cargo exports RUSTUP_TOOLCHAIN=<stable>
    // (an env leak that would make `cargo +nightly` look for rust-src under
    // the stable toolchain dir and fail).
    let mut cmd = Command::new("rustup");
    cmd.args([
        "run",
        "nightly",
        "cargo",
        "build",
        "--manifest-path",
        manifest,
        "--target",
        ebpf_target,
        "-Z",
        "build-std=core",
        "--release",
    ]);
    // Do not inherit the host's .cargo/config rustflags (target-cpu=native
    // breaks the bpf target); panic=abort is required for eBPF.
    cmd.env("CARGO_ENCODED_RUSTFLAGS", "-C\u{1f}panic=abort");
    // Parent cargo exports RUSTC/RUSTUP_TOOLCHAIN pointing at the pinned
    // stable toolchain; the nested nightly build must resolve its own
    // sysroot or -Z build-std looks for rust-src under the stable dir.
    cmd.env_remove("RUSTC");
    cmd.env_remove("RUSTUP_TOOLCHAIN");
    let built = cmd
        .status()
        .map(|status| status.success())
        .unwrap_or(false);

    let mut source = None;
    if built {
        let mut candidates = Vec::new();
        if let Some(target_dir) = std::env::var_os("CARGO_TARGET_DIR") {
            candidates.push(
                PathBuf::from(target_dir)
                    .join(ebpf_target)
                    .join("release")
                    .join("cloud-node-xdp-ebpf"),
            );
        }
        candidates.push(
            Path::new("crates/cloud-node-xdp-ebpf")
                .join("target")
                .join(ebpf_target)
                .join("release")
                .join("cloud-node-xdp-ebpf"),
        );
        source = candidates.into_iter().find(|path| path.is_file());
    }
    if source.is_none() {
        // Nightly/rust-src unavailable (or build failed): fall back to a
        // prebuilt object produced by `cargo xtask build-ebpf` so local dev
        // builds on machines without the bpf toolchain still work. This is
        // loud, not silent: stale-object risk is printed as a warning.
        let prebuilt = Path::new("data").join("cloud-node-xdp-ebpf.o");
        if prebuilt.is_file() {
            println!(
                "cargo:warning=eBPF toolchain build unavailable; embedding prebuilt {} (run `cargo xtask build-ebpf` to refresh)",
                prebuilt.display()
            );
            source = Some(prebuilt);
        }
    }
    let Some(source) = source else {
        return Err(
            "cannot build embedded XDP eBPF object: nightly toolchain with rust-src is required \
             (rustup toolchain install nightly --profile minimal -c rust-src), or provide a \
             prebuilt data/cloud-node-xdp-ebpf.o via `cargo xtask build-ebpf`"
                .into(),
        );
    };
    fs::copy(&source, &dest)?;
    println!("cargo:rustc-env=CLOUD_NODE_XDP_EBPF_OBJECT={}", dest.display());
    Ok(())
}
