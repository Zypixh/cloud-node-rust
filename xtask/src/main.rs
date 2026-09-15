use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Command;

#[cfg(feature = "migrate-metrics")]
mod mace_migration;

#[derive(Parser)]
#[command(name = "xtask")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build the XDP eBPF object and copy it into data/
    BuildEbpf {
        /// Build profile to use for the eBPF crate
        #[arg(long, default_value = "release")]
        profile: String,
    },
    /// Import a legacy RocksDB metrics database into a separate Mace directory.
    #[cfg(feature = "migrate-metrics")]
    MigrateMetricsToMace {
        /// Existing RocksDB directory, typically data/metrics.db
        #[arg(long)]
        source: PathBuf,
        /// New Mace directory, typically data/metrics.mace
        #[arg(long)]
        destination: PathBuf,
        /// Maximum records committed per Mace transaction
        #[arg(long, default_value_t = 512)]
        batch_size: usize,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::BuildEbpf { profile } => build_ebpf(&profile),
        #[cfg(feature = "migrate-metrics")]
        Commands::MigrateMetricsToMace {
            source,
            destination,
            batch_size,
        } => mace_migration::migrate_rocksdb_metrics(&source, &destination, batch_size),
    }
}

/// Resolve the pinned eBPF toolchain. `crates/cloud-node-xdp-ebpf/
/// rust-toolchain.toml` is the single source of truth for the dated nightly;
/// CLOUD_NODE_EBPF_TOOLCHAIN may override it. Never a bare `nightly` name:
/// the release chain must build with the same verified dated toolchain that
/// CI installed, not whatever `nightly` happens to resolve to.
fn ebpf_toolchain() -> anyhow::Result<String> {
    if let Ok(name) = std::env::var("CLOUD_NODE_EBPF_TOOLCHAIN") {
        let name = name.trim().to_string();
        if !name.is_empty() {
            return Ok(name);
        }
    }
    let manifest_dir = PathBuf::from("crates").join("cloud-node-xdp-ebpf");
    let toml_path = manifest_dir.join("rust-toolchain.toml");
    let toml = std::fs::read_to_string(&toml_path)
        .with_context(|| format!("failed to read {}", toml_path.display()))?;
    toolchain_channel(&toml).with_context(|| {
        format!(
            "{} does not declare toolchain.channel",
            toml_path.display()
        )
    })
}

/// Minimal `[toolchain] channel = "..."` extraction; keeps xtask free of a
/// TOML dependency for a single scalar.
fn toolchain_channel(toml: &str) -> Option<String> {
    let mut in_toolchain = false;
    for raw in toml.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            in_toolchain = line.trim_start_matches('[').starts_with("toolchain");
            continue;
        }
        if in_toolchain {
            if let Some((key, value)) = line.split_once('=') {
                if key.trim() == "channel" {
                    return Some(value.trim().trim_matches('"').to_string());
                }
            }
        }
    }
    None
}

fn build_ebpf(profile: &str) -> anyhow::Result<()> {
    let toolchain = ebpf_toolchain()?;
    ensure_bpf_toolchain(&toolchain)?;
    let target = "bpfel-unknown-none";
    let crate_dir = PathBuf::from("crates").join("cloud-node-xdp-ebpf");
    // Spawn via `rustup run` so the nested build resolves the pinned sysroot
    // even when a parent cargo leaked RUSTUP_TOOLCHAIN/RUSTC into the env.
    let mut cmd = Command::new("rustup");
    cmd.args([
        "run",
        &toolchain,
        "cargo",
        "build",
        "--manifest-path",
        "crates/cloud-node-xdp-ebpf/Cargo.toml",
        "--target",
        target,
        "-Z",
        "build-std=core",
    ]);
    cmd.env_remove("RUSTC");
    cmd.env_remove("RUSTUP_TOOLCHAIN");
    if profile == "release" {
        cmd.arg("--release");
    }
    cmd.env("CARGO_ENCODED_RUSTFLAGS", "-C\u{1f}panic=abort");
    let status = cmd
        .status()
        .context("failed to spawn cargo build for eBPF")?;
    if !status.success() {
        anyhow::bail!("eBPF build failed with status {}", status);
    }

    let profile_dir = if profile == "release" {
        "release"
    } else {
        "debug"
    };
    let mut candidates = Vec::new();
    if let Some(target_dir) = std::env::var_os("CARGO_TARGET_DIR") {
        candidates.push(
            PathBuf::from(target_dir)
                .join(target)
                .join(profile_dir)
                .join("cloud-node-xdp-ebpf"),
        );
    }
    candidates.extend([
        crate_dir
            .join("target")
            .join(target)
            .join(profile_dir)
            .join("cloud-node-xdp-ebpf"),
        PathBuf::from("target")
            .join(target)
            .join(profile_dir)
            .join("cloud-node-xdp-ebpf"),
    ]);
    let source = candidates
        .iter()
        .find(|path| path.exists())
        .cloned()
        .unwrap_or_else(|| candidates[0].clone());
    let dest_dir = PathBuf::from("data");
    std::fs::create_dir_all(&dest_dir)?;
    let dest = dest_dir.join("cloud-node-xdp-ebpf.o");
    std::fs::copy(&source, &dest).with_context(|| {
        format!(
            "failed to copy eBPF object from {} to {}",
            source.display(),
            dest.display()
        )
    })?;
    println!("Built XDP eBPF object: {}", dest.display());
    Ok(())
}

fn ensure_bpf_toolchain(toolchain: &str) -> anyhow::Result<()> {
    let rustc = Command::new("rustup")
        .args(["run", toolchain, "rustc", "--version"])
        .output()
        .context("failed to inspect eBPF toolchain with rustup")?;
    if !rustc.status.success() {
        let stderr = String::from_utf8_lossy(&rustc.stderr);
        anyhow::bail!(
            "eBPF toolchain {toolchain} is unavailable or incomplete: {}. Install it with: rustup toolchain install {toolchain} --profile minimal -c rust-src",
            stderr.trim()
        );
    }

    let components = Command::new("rustup")
        .args(["component", "list", "--toolchain", toolchain, "--installed"])
        .output()
        .context("failed to inspect eBPF toolchain components with rustup")?;
    if components.status.success() {
        let stdout = String::from_utf8_lossy(&components.stdout);
        if !stdout
            .lines()
            .any(|line| line == "rust-src" || line.starts_with("rust-src "))
        {
            anyhow::bail!(
                "rust-src component is required for {toolchain}. Install it with: rustup component add rust-src --toolchain {toolchain}"
            );
        }
    }
    Ok(())
}
