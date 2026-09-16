//! T4-5 (D-B1): kernel guard for the AF_XDP outbound-dial port span.
//!
//! Two cooperating mechanisms keep node-dialed tuples safe:
//!
//! 1. `net.ipv4.ip_local_reserved_ports` pins the span so the kernel's
//!    ephemeral allocator can never hand a port to a socket that XDP's
//!    XDP_OUT_CT steering would then hijack.
//! 2. An `inet` nftables table drops inbound TCP/UDP destined at the
//!    span. During a detach window (redirect withdrawn, XSKs gone) reply
//!    packets would otherwise reach the kernel — which has no listener —
//!    and RST the smoltcp-side handshake in flight.
//!
//! Install failure is an explicit startup error for the upstream-dial
//! feature (the registry is not published); removal is idempotent so a
//! half-applied guard never wedges a restart. Guard hits are readable
//! through `dial_guard_hits` and surface in /status.

use crate::kernel_syn_defense::{CommandOutput, CommandRunner, SynproxySysctlStore};

pub(crate) const DIAL_GUARD_FAMILY: &str = "inet";
pub(crate) const DIAL_GUARD_TABLE: &str = "cloud_node_dial_guard";
pub(crate) const DIAL_GUARD_CHAIN: &str = "dial_input";
pub(crate) const DIAL_GUARD_COUNTER: &str = "dial_guard_hits";

const IP_LOCAL_RESERVED_PORTS: &str = "net.ipv4.ip_local_reserved_ports";
const IP_LOCAL_PORT_RANGE: &str = "net.ipv4.ip_local_port_range";

/// What `ensure_dial_port_guard` established — reported to /status so an
/// operator can tell a guarded span from a partial install.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DialGuardReport {
    pub port_range: (u16, u16),
    pub reserved_ports_value: String,
    pub nft_installed: bool,
}

/// Refuse the span when it is empty or escapes the kernel's ephemeral
/// range — the guard would shadow ports the kernel may legitimately
/// allocate.
pub(crate) fn validate_dial_port_range(
    store: &impl SynproxySysctlStore,
    start: u16,
    end: u16,
) -> anyhow::Result<()> {
    if start > end {
        anyhow::bail!("dial port range is empty: {start}-{end}");
    }
    let raw = store
        .read(IP_LOCAL_PORT_RANGE)
        .map_err(|err| anyhow::anyhow!("cannot read {IP_LOCAL_PORT_RANGE}: {err}"))?;
    let mut parts = raw.split_whitespace();
    let lo: u16 = parts
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("malformed {IP_LOCAL_PORT_RANGE}: {raw:?}"))?;
    let hi: u16 = parts
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("malformed {IP_LOCAL_PORT_RANGE}: {raw:?}"))?;
    if start < lo || end > hi {
        anyhow::bail!(
            "dial port range {start}-{end} escapes ip_local_port_range {lo}-{hi}"
        );
    }
    Ok(())
}

/// Merge `start-end` into `ip_local_reserved_ports` idempotently and
/// return the final sysctl value. The kernel accepts comma-separated
/// ranges; ours is appended only when not already covered verbatim.
pub(crate) fn pin_dial_port_range(
    store: &impl SynproxySysctlStore,
    start: u16,
    end: u16,
) -> anyhow::Result<String> {
    let range = format!("{start}-{end}");
    let current = store
        .read(IP_LOCAL_RESERVED_PORTS)
        .map_err(|err| anyhow::anyhow!("cannot read {IP_LOCAL_RESERVED_PORTS}: {err}"))?;
    let current = current.trim();
    let already = current
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .any(|entry| entry == range);
    if already {
        return Ok(current.to_string());
    }
    let next = if current.is_empty() {
        range
    } else {
        format!("{current},{range}")
    };
    store
        .write(IP_LOCAL_RESERVED_PORTS, &next)
        .map_err(|err| anyhow::anyhow!("cannot write {IP_LOCAL_RESERVED_PORTS}: {err}"))?;
    // Verify — a silent partial write would leave the span unreserved.
    let written = store
        .read(IP_LOCAL_RESERVED_PORTS)
        .map_err(|err| anyhow::anyhow!("cannot re-read {IP_LOCAL_RESERVED_PORTS}: {err}"))?;
    let written = written.trim();
    if !written
        .split(',')
        .map(str::trim)
        .any(|entry| entry == format!("{start}-{end}"))
    {
        anyhow::bail!("{IP_LOCAL_RESERVED_PORTS} did not retain {start}-{end}: {written:?}");
    }
    Ok(written.to_string())
}

/// Remove our range from `ip_local_reserved_ports`, preserving entries
/// the operator or other subsystems pinned.
pub(crate) fn unpin_dial_port_range(
    store: &impl SynproxySysctlStore,
    start: u16,
    end: u16,
) -> anyhow::Result<String> {
    let range = format!("{start}-{end}");
    let current = store
        .read(IP_LOCAL_RESERVED_PORTS)
        .map_err(|err| anyhow::anyhow!("cannot read {IP_LOCAL_RESERVED_PORTS}: {err}"))?;
    let kept: Vec<&str> = current
        .trim()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty() && *entry != range)
        .collect();
    let next = kept.join(",");
    store
        .write(IP_LOCAL_RESERVED_PORTS, &next)
        .map_err(|err| anyhow::anyhow!("cannot write {IP_LOCAL_RESERVED_PORTS}: {err}"))?;
    Ok(next)
}

async fn nft(runner: &impl CommandRunner, args: &[&str]) -> anyhow::Result<String> {
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
    let output: CommandOutput = runner
        .run("nft", &args)
        .await
        .map_err(|err| anyhow::anyhow!("failed to execute nft; is nftables installed? {err}"))?;
    if output.success {
        return Ok(output.stdout);
    }
    anyhow::bail!("nft {} failed: {}", args.join(" "), output.stderr.trim())
}

fn is_exists_error(err: &anyhow::Error) -> bool {
    err.to_string().contains("File exists")
}

fn is_missing_error(err: &anyhow::Error) -> bool {
    let message = err.to_string();
    message.contains("No such file or directory") || message.contains("does not exist")
}

async fn nft_allow_exists(runner: &impl CommandRunner, args: &[&str]) -> anyhow::Result<()> {
    match nft(runner, args).await {
        Ok(_) => Ok(()),
        Err(err) if is_exists_error(&err) => Ok(()),
        Err(err) => Err(err),
    }
}

async fn nft_ignore_missing(runner: &impl CommandRunner, args: &[&str]) -> anyhow::Result<()> {
    match nft(runner, args).await {
        Ok(_) => Ok(()),
        Err(err) if is_missing_error(&err) => Ok(()),
        Err(err) => Err(err),
    }
}

/// Install the netfilter half of the guard: a dedicated table with a
/// named hit counter and DROP rules for TCP+UDP traffic into the span.
/// Idempotent — repeated installs recreate nothing.
pub(crate) async fn install_dial_guard_rules(
    runner: &impl CommandRunner,
    start: u16,
    end: u16,
) -> anyhow::Result<()> {
    let range = format!("{start}-{end}");
    nft(runner, &["--version"]).await?;
    nft_allow_exists(runner, &["add", "table", DIAL_GUARD_FAMILY, DIAL_GUARD_TABLE]).await?;
    nft_allow_exists(
        runner,
        &[
            "add",
            "counter",
            DIAL_GUARD_FAMILY,
            DIAL_GUARD_TABLE,
            DIAL_GUARD_COUNTER,
        ],
    )
    .await?;
    nft_allow_exists(
        runner,
        &[
            "add",
            "chain",
            DIAL_GUARD_FAMILY,
            DIAL_GUARD_TABLE,
            DIAL_GUARD_CHAIN,
            "{",
            "type",
            "filter",
            "hook",
            "input",
            "priority",
            "filter",
            "+",
            "10",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ],
    )
    .await?;
    // Flush + re-add the two rules: idempotent under a changed span —
    // stale rules for a previous range must not survive reconfigure.
    nft_ignore_missing(
        runner,
        &[
            "flush", "chain", DIAL_GUARD_FAMILY, DIAL_GUARD_TABLE, DIAL_GUARD_CHAIN,
        ],
    )
    .await?;
    for proto in ["tcp", "udp"] {
        nft(
            runner,
            &[
                "add",
                "rule",
                DIAL_GUARD_FAMILY,
                DIAL_GUARD_TABLE,
                DIAL_GUARD_CHAIN,
                "meta",
                "l4proto",
                proto,
                proto,
                "dport",
                &range,
                "counter",
                "name",
                DIAL_GUARD_COUNTER,
                "drop",
            ],
        )
        .await?;
    }
    Ok(())
}

/// Drop the whole guard table — rules and counter together. Missing
/// objects are fine; the guard may have been half-installed.
pub(crate) async fn remove_dial_guard_rules(
    runner: &impl CommandRunner,
) -> anyhow::Result<()> {
    nft_ignore_missing(
        runner,
        &["delete", "table", DIAL_GUARD_FAMILY, DIAL_GUARD_TABLE],
    )
    .await
}

/// Packet count on the guard's named counter — how many inbound packets
/// the DROP actually stopped (detach-window replies, stray traffic).
pub(crate) async fn dial_guard_hits(runner: &impl CommandRunner) -> anyhow::Result<u64> {
    let output = nft(
        runner,
        &[
            "-j",
            "list",
            "counter",
            DIAL_GUARD_FAMILY,
            DIAL_GUARD_TABLE,
            DIAL_GUARD_COUNTER,
        ],
    )
    .await?;
    let json: serde_json::Value = serde_json::from_str(&output)
        .map_err(|err| anyhow::anyhow!("nft counter JSON parse failed: {err}"))?;
    json["nftables"]
        .as_array()
        .and_then(|entries| {
            entries.iter().find_map(|entry| {
                entry["counter"]["packets"]
                    .as_u64()
            })
        })
        .ok_or_else(|| anyhow::anyhow!("nft counter {DIAL_GUARD_COUNTER} not found in output"))
}

/// Full guard install: range validation → sysctl pin → nft rules. Any
/// step failing aborts with an explicit error; partial nft state is
/// tolerated on the next install attempt (idempotent re-run).
pub(crate) async fn ensure_dial_port_guard(
    store: &impl SynproxySysctlStore,
    runner: &impl CommandRunner,
    start: u16,
    end: u16,
) -> anyhow::Result<DialGuardReport> {
    validate_dial_port_range(store, start, end)?;
    let reserved_ports_value = pin_dial_port_range(store, start, end)?;
    install_dial_guard_rules(runner, start, end).await?;
    Ok(DialGuardReport {
        port_range: (start, end),
        reserved_ports_value,
        nft_installed: true,
    })
}

/// Full guard teardown: nft table then sysctl unpin. Both steps are
/// best-effort-complete — a failure on one does not skip the other; the
/// first error is returned.
pub(crate) async fn remove_dial_port_guard(
    store: &impl SynproxySysctlStore,
    runner: &impl CommandRunner,
    start: u16,
    end: u16,
) -> anyhow::Result<()> {
    let nft_result = remove_dial_guard_rules(runner).await;
    let sysctl_result = unpin_dial_port_range(store, start, end);
    nft_result.and(sysctl_result.map(|_| ()))
}

fn nft_blocking(args: &[&str]) -> anyhow::Result<()> {
    let output = std::process::Command::new("nft")
        .args(args)
        .output()
        .map_err(|err| anyhow::anyhow!("failed to execute nft: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    anyhow::bail!(
        "nft {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

/// Synchronous teardown for non-async call sites (manager generation
/// swap, disable path). Missing nft objects are fine.
pub(crate) fn remove_dial_port_guard_blocking(
    store: &impl SynproxySysctlStore,
    start: u16,
    end: u16,
) -> anyhow::Result<()> {
    let nft_result = match nft_blocking(&[
        "delete",
        "table",
        DIAL_GUARD_FAMILY,
        DIAL_GUARD_TABLE,
    ]) {
        Ok(()) => Ok(()),
        Err(err) if is_missing_error(&err) => Ok(()),
        Err(err) => Err(err),
    };
    let sysctl_result = unpin_dial_port_range(store, start, end);
    nft_result.and(sysctl_result.map(|_| ()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_syn_defense::CommandOutput;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io;
    use std::sync::Mutex;

    const RANGE_KEY: &str = "net.ipv4.ip_local_port_range";
    const RESERVED_KEY: &str = "net.ipv4.ip_local_reserved_ports";

    #[derive(Default)]
    struct FakeStore {
        values: RefCell<HashMap<String, String>>,
        write_errors: HashMap<String, io::ErrorKind>,
    }

    impl FakeStore {
        fn with(self, key: &str, value: &str) -> Self {
            self.values
                .borrow_mut()
                .insert(key.to_string(), value.to_string());
            self
        }
    }

    impl SynproxySysctlStore for FakeStore {
        fn exists(&self, _key: &str) -> bool {
            true
        }
        fn read(&self, key: &str) -> io::Result<String> {
            self.values
                .borrow()
                .get(key)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
        fn write(&self, key: &str, value: &str) -> io::Result<()> {
            if let Some(kind) = self.write_errors.get(key) {
                return Err(io::Error::from(*kind));
            }
            self.values
                .borrow_mut()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }
    }

    fn store() -> FakeStore {
        FakeStore::default()
            .with(RANGE_KEY, "32768 60999")
            .with(RESERVED_KEY, "")
    }

    #[derive(Default)]
    struct FakeRunner {
        calls: Mutex<Vec<Vec<String>>>,
        outputs: Mutex<Vec<(String, CommandOutput)>>,
    }

    impl FakeRunner {
        fn push(&self, needle: &str, output: CommandOutput) {
            self.outputs
                .lock()
                .unwrap()
                .push((needle.to_string(), output));
        }
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
        fn ran(&self, needle: &str) -> bool {
            self.calls()
                .iter()
                .any(|args| args.join(" ").contains(needle))
        }
    }

    #[async_trait::async_trait]
    impl CommandRunner for FakeRunner {
        async fn run(&self, _program: &str, args: &[String]) -> io::Result<CommandOutput> {
            self.calls.lock().unwrap().push(args.to_vec());
            let joined = args.join(" ");
            let mut outputs = self.outputs.lock().unwrap();
            if let Some(pos) = outputs.iter().position(|(needle, _)| joined.contains(needle)) {
                return Ok(outputs.remove(pos).1);
            }
            Ok(CommandOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn validate_rejects_empty_and_out_of_ephemeral_range() {
        let store = store();
        assert!(validate_dial_port_range(&store, 40_000, 49_999).is_ok());
        assert!(validate_dial_port_range(&store, 50_000, 40_000).is_err());
        assert!(validate_dial_port_range(&store, 10_000, 40_000).is_err());
        assert!(validate_dial_port_range(&store, 60_000, 65_000).is_err());
    }

    #[test]
    fn validate_rejects_malformed_sysctl() {
        let store = FakeStore::default().with(RANGE_KEY, "garbage");
        assert!(validate_dial_port_range(&store, 40_000, 49_999).is_err());
    }

    #[test]
    fn pin_writes_range_and_is_idempotent() {
        let store = store();
        let value = pin_dial_port_range(&store, 40_000, 49_999).unwrap();
        assert_eq!(value, "40000-49999");
        // Second pin leaves the value untouched (no duplicate entries).
        let value = pin_dial_port_range(&store, 40_000, 49_999).unwrap();
        assert_eq!(value, "40000-49999");
    }

    #[test]
    fn pin_preserves_foreign_reserved_entries() {
        let store = store().with(RESERVED_KEY, "53,8080-8090");
        let value = pin_dial_port_range(&store, 40_000, 49_999).unwrap();
        assert_eq!(value, "53,8080-8090,40000-49999");
    }

    #[test]
    fn unpin_removes_only_our_range() {
        let store = store().with(RESERVED_KEY, "53,40000-49999,8080");
        let value = unpin_dial_port_range(&store, 40_000, 49_999).unwrap();
        assert_eq!(value, "53,8080");
    }

    #[tokio::test]
    async fn install_creates_table_counter_chain_and_drop_rules() {
        let runner = FakeRunner::default();
        install_dial_guard_rules(&runner, 40_000, 49_999)
            .await
            .unwrap();
        assert!(runner.ran(&format!("add table {DIAL_GUARD_FAMILY} {DIAL_GUARD_TABLE}")));
        assert!(runner.ran(&format!("add counter {DIAL_GUARD_FAMILY} {DIAL_GUARD_TABLE} {DIAL_GUARD_COUNTER}")));
        assert!(runner.ran("tcp dport 40000-49999"));
        assert!(runner.ran("udp dport 40000-49999"));
        // Every DROP rule must reference the named counter for /status hits.
        let drops = runner
            .calls()
            .into_iter()
            .filter(|args| args.join(" ").contains("drop"))
            .count();
        assert_eq!(drops, 2);
        assert!(runner
            .calls()
            .iter()
            .filter(|args| args.join(" ").contains("drop"))
            .all(|args| args.join(" ").contains(DIAL_GUARD_COUNTER)));
    }

    #[tokio::test]
    async fn install_fails_explicitly_when_nft_errors() {
        let runner = FakeRunner::default();
        runner.push(
            "add rule",
            CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "Error: Operation not permitted".to_string(),
            },
        );
        let err = install_dial_guard_rules(&runner, 40_000, 49_999)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Operation not permitted"));
    }

    #[tokio::test]
    async fn hits_parses_named_counter() {
        let runner = FakeRunner::default();
        runner.push(
            "list counter",
            CommandOutput {
                success: true,
                stdout: r#"{"nftables":[{"metainfo":{"json_schema_version":1}},{"counter":{"family":"inet","table":"cloud_node_dial_guard","name":"dial_guard_hits","handle":3,"packets":42,"bytes":2520}}]}"#
                    .to_string(),
                stderr: String::new(),
            },
        );
        assert_eq!(dial_guard_hits(&runner).await.unwrap(), 42);
    }

    #[tokio::test]
    async fn remove_is_idempotent_over_missing_table() {
        let runner = FakeRunner::default();
        runner.push(
            "delete table",
            CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "Error: No such file or directory".to_string(),
            },
        );
        remove_dial_guard_rules(&runner).await.unwrap();
    }

    #[tokio::test]
    async fn ensure_fails_when_range_escapes_ephemeral() {
        let store = store().with(RANGE_KEY, "32768 45000");
        let runner = FakeRunner::default();
        let err = ensure_dial_port_guard(&store, &runner, 40_000, 49_999)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ip_local_port_range"));
        // And nothing reached nft — no guard half-installed.
        assert!(runner.calls().is_empty());
    }

    #[tokio::test]
    async fn ensure_installs_both_halves() {
        let store = store();
        let runner = FakeRunner::default();
        let report = ensure_dial_port_guard(&store, &runner, 40_000, 49_999)
            .await
            .unwrap();
        assert_eq!(report.port_range, (40_000, 49_999));
        assert_eq!(report.reserved_ports_value, "40000-49999");
        assert!(report.nft_installed);
        assert!(runner.ran("drop"));
    }
}
