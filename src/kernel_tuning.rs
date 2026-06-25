use std::fmt;
use std::io;

const NODE_LOG_TAG: &str = "kernel_tuning";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelParamTune {
    pub key: &'static str,
    pub target: &'static str,
    pub optional: bool,
}

impl KernelParamTune {
    const fn exact(key: &'static str, target: &'static str) -> Self {
        Self {
            key,
            target,
            optional: false,
        }
    }

    const fn optional(key: &'static str, target: &'static str) -> Self {
        Self {
            key,
            target,
            optional: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelTuningStatus {
    Applied,
    AlreadySet,
    SkippedMissing,
    FailedRead,
    FailedWrite,
    FailedVerify,
    VerifyMismatch,
    SkippedOptional,
    NotAppliedPersistentOnly,
    SkippedUnsupportedPlatform,
}

impl KernelTuningStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::AlreadySet => "already_set",
            Self::SkippedMissing => "skipped_missing",
            Self::FailedRead => "failed_read",
            Self::FailedWrite => "failed_write",
            Self::FailedVerify => "failed_verify",
            Self::VerifyMismatch => "verify_mismatch",
            Self::SkippedOptional => "skipped_optional",
            Self::NotAppliedPersistentOnly => "not_applied_persistent_only",
            Self::SkippedUnsupportedPlatform => "skipped_unsupported_platform",
        }
    }

    fn log_level(&self) -> &'static str {
        match self {
            Self::Applied
            | Self::AlreadySet
            | Self::SkippedMissing
            | Self::SkippedOptional
            | Self::NotAppliedPersistentOnly
            | Self::SkippedUnsupportedPlatform => "info",
            Self::FailedRead | Self::FailedWrite | Self::FailedVerify | Self::VerifyMismatch => {
                "warn"
            }
        }
    }
}

impl fmt::Display for KernelTuningStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelTuningReport {
    pub key: String,
    pub old: Option<String>,
    pub target: String,
    pub final_value: Option<String>,
    pub status: KernelTuningStatus,
    pub reason: String,
}

impl KernelTuningReport {
    fn description(&self) -> String {
        format!(
            "key={} old={} target={} final={} status={} reason={}",
            quote_field(&self.key),
            quote_field(self.old.as_deref().unwrap_or("-")),
            quote_field(&self.target),
            quote_field(self.final_value.as_deref().unwrap_or("-")),
            self.status,
            quote_field(&self.reason)
        )
    }

    fn log(&self) {
        crate::logging::report_node_log(
            self.status.log_level().to_string(),
            NODE_LOG_TAG.to_string(),
            self.description(),
            0,
        );
    }
}

pub trait SysctlStore {
    fn exists(&self, key: &str) -> bool;
    fn read(&self, key: &str) -> io::Result<String>;
    fn write(&self, key: &str, value: &str) -> io::Result<()>;
}

#[cfg(target_os = "linux")]
pub struct ProcSysctlStore;

#[cfg(target_os = "linux")]
impl ProcSysctlStore {
    fn path_for_key(key: &str) -> std::path::PathBuf {
        std::path::PathBuf::from("/proc/sys").join(key.replace('.', "/"))
    }
}

#[cfg(target_os = "linux")]
impl SysctlStore for ProcSysctlStore {
    fn exists(&self, key: &str) -> bool {
        Self::path_for_key(key).exists()
    }

    fn read(&self, key: &str) -> io::Result<String> {
        std::fs::read_to_string(Self::path_for_key(key))
    }

    fn write(&self, key: &str, value: &str) -> io::Result<()> {
        std::fs::write(Self::path_for_key(key), value)
    }
}

pub fn apply_runtime_tuning_and_report() {
    #[cfg(target_os = "linux")]
    {
        tracing::info!("Starting runtime kernel parameter tuning...");
        let store = ProcSysctlStore;
        let reports = apply_runtime_tuning_with_store(&store);
        report_all(&reports);
        return;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let reports = vec![KernelTuningReport {
            key: "kernel_tuning".to_string(),
            old: None,
            target: "linux_runtime_sysctl".to_string(),
            final_value: None,
            status: KernelTuningStatus::SkippedUnsupportedPlatform,
            reason: "runtime sysctl tuning is only supported on Linux".to_string(),
        }];
        report_all(&reports);
    }
}

pub fn apply_runtime_tuning_with_store(store: &impl SysctlStore) -> Vec<KernelTuningReport> {
    let mut reports = runtime_tuning_plan()
        .into_iter()
        .map(|param| apply_param(store, param))
        .collect::<Vec<_>>();
    reports.extend(persistent_only_reports());
    reports
}

fn apply_param(store: &impl SysctlStore, param: KernelParamTune) -> KernelTuningReport {
    if !store.exists(param.key) {
        return KernelTuningReport {
            key: param.key.to_string(),
            old: None,
            target: param.target.to_string(),
            final_value: None,
            status: KernelTuningStatus::SkippedMissing,
            reason: if param.optional {
                "optional sysctl is not available on this kernel".to_string()
            } else {
                "sysctl is not available on this kernel".to_string()
            },
        };
    }

    let old = match store.read(param.key) {
        Ok(value) => normalize_sysctl_value(&value),
        Err(err) => {
            return KernelTuningReport {
                key: param.key.to_string(),
                old: None,
                target: param.target.to_string(),
                final_value: None,
                status: KernelTuningStatus::FailedRead,
                reason: err.to_string(),
            };
        }
    };

    let target = normalize_sysctl_value(param.target);
    if old == target {
        return KernelTuningReport {
            key: param.key.to_string(),
            old: Some(old.clone()),
            target,
            final_value: Some(old),
            status: KernelTuningStatus::AlreadySet,
            reason: "already matches target".to_string(),
        };
    }

    if let Err(err) = store.write(param.key, param.target) {
        return KernelTuningReport {
            key: param.key.to_string(),
            old: Some(old.clone()),
            target,
            final_value: Some(old),
            status: if param.optional {
                KernelTuningStatus::SkippedOptional
            } else {
                KernelTuningStatus::FailedWrite
            },
            reason: err.to_string(),
        };
    }

    match store.read(param.key) {
        Ok(value) => {
            let final_value = normalize_sysctl_value(&value);
            let status = if final_value == target {
                KernelTuningStatus::Applied
            } else if param.optional {
                KernelTuningStatus::SkippedOptional
            } else {
                KernelTuningStatus::VerifyMismatch
            };
            let reason = if final_value == target {
                "runtime value updated".to_string()
            } else if param.optional {
                "optional sysctl did not accept target".to_string()
            } else {
                "runtime value differs after write".to_string()
            };
            KernelTuningReport {
                key: param.key.to_string(),
                old: Some(old),
                target,
                final_value: Some(final_value),
                status,
                reason,
            }
        }
        Err(err) => KernelTuningReport {
            key: param.key.to_string(),
            old: Some(old),
            target,
            final_value: None,
            status: KernelTuningStatus::FailedVerify,
            reason: err.to_string(),
        },
    }
}

fn runtime_tuning_plan() -> Vec<KernelParamTune> {
    vec![
        KernelParamTune::optional("net.core.default_qdisc", "fq"),
        KernelParamTune::optional("net.ipv4.tcp_congestion_control", "bbr"),
        KernelParamTune::exact("net.core.somaxconn", "65535"),
        KernelParamTune::exact("net.core.netdev_max_backlog", "250000"),
        KernelParamTune::exact("net.core.rmem_max", "134217728"),
        KernelParamTune::exact("net.core.wmem_max", "134217728"),
        KernelParamTune::exact("net.core.rmem_default", "262144"),
        KernelParamTune::exact("net.core.wmem_default", "262144"),
        KernelParamTune::exact("net.ipv4.tcp_rmem", "4096 87380 134217728"),
        KernelParamTune::exact("net.ipv4.tcp_wmem", "4096 65536 134217728"),
        KernelParamTune::exact("net.ipv4.tcp_mem", "786432 1048576 26777216"),
        KernelParamTune::exact("net.ipv4.tcp_max_syn_backlog", "65535"),
        KernelParamTune::exact("net.ipv4.tcp_max_tw_buckets", "2000000"),
        KernelParamTune::exact("net.ipv4.tcp_fin_timeout", "10"),
        KernelParamTune::exact("net.ipv4.tcp_syn_retries", "3"),
        KernelParamTune::exact("net.ipv4.tcp_synack_retries", "3"),
        KernelParamTune::exact("net.ipv4.tcp_slow_start_after_idle", "0"),
        KernelParamTune::exact("net.ipv4.tcp_mtu_probing", "1"),
        KernelParamTune::exact("net.ipv4.tcp_fastopen", "3"),
        KernelParamTune::exact("net.ipv4.ip_local_port_range", "1024 65535"),
        KernelParamTune::exact("net.ipv4.tcp_tw_reuse", "1"),
        KernelParamTune::exact("fs.file-max", "2097152"),
        KernelParamTune::exact("fs.nr_open", "2097152"),
        KernelParamTune::exact("vm.swappiness", "10"),
        KernelParamTune::exact("vm.dirty_ratio", "20"),
        KernelParamTune::exact("vm.dirty_background_ratio", "5"),
    ]
}

fn persistent_only_reports() -> Vec<KernelTuningReport> {
    [
        (
            "/etc/sysctl.d/99-bbr-tuning.conf",
            "persistent sysctl drop-in is managed by install/ops, not the runtime process",
        ),
        (
            "/etc/security/limits.d/99-openfiles.conf",
            "persistent login nofile limits are managed by install/ops, not the runtime process",
        ),
        (
            "/etc/systemd/system.conf.d/99-limits.conf",
            "persistent systemd manager limits are managed by install/ops, not the runtime process",
        ),
        (
            "/etc/systemd/user.conf.d/99-limits.conf",
            "persistent systemd user manager limits are managed by install/ops, not the runtime process",
        ),
    ]
    .into_iter()
    .map(|(key, reason)| KernelTuningReport {
        key: key.to_string(),
        old: None,
        target: "not_applied".to_string(),
        final_value: None,
        status: KernelTuningStatus::NotAppliedPersistentOnly,
        reason: reason.to_string(),
    })
    .collect()
}

fn report_all(reports: &[KernelTuningReport]) {
    for report in reports {
        match report.status {
            KernelTuningStatus::Applied => tracing::info!(
                "Kernel tuning applied: {} {:?} -> {:?}",
                report.key,
                report.old,
                report.final_value
            ),
            KernelTuningStatus::AlreadySet
            | KernelTuningStatus::SkippedMissing
            | KernelTuningStatus::SkippedOptional
            | KernelTuningStatus::NotAppliedPersistentOnly
            | KernelTuningStatus::SkippedUnsupportedPlatform => {
                tracing::info!("Kernel tuning {}: {}", report.status, report.key)
            }
            KernelTuningStatus::FailedRead
            | KernelTuningStatus::FailedWrite
            | KernelTuningStatus::FailedVerify
            | KernelTuningStatus::VerifyMismatch => tracing::warn!(
                "Kernel tuning {} for {}: {}",
                report.status,
                report.key,
                report.reason
            ),
        }
        report.log();
    }
}

fn normalize_sysctl_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn quote_field(value: &str) -> String {
    format!("{value:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};

    #[derive(Default)]
    struct FakeSysctlStore {
        values: RefCell<HashMap<String, String>>,
        missing: HashSet<String>,
        read_errors: HashMap<String, io::ErrorKind>,
        write_errors: HashMap<String, io::ErrorKind>,
        write_overrides: HashMap<String, String>,
    }

    impl FakeSysctlStore {
        fn with_value(self, key: &str, value: &str) -> Self {
            self.values
                .borrow_mut()
                .insert(key.to_string(), value.to_string());
            self
        }

        fn missing(mut self, key: &str) -> Self {
            self.missing.insert(key.to_string());
            self
        }

        fn write_error(mut self, key: &str, kind: io::ErrorKind) -> Self {
            self.write_errors.insert(key.to_string(), kind);
            self
        }

        fn write_override(mut self, key: &str, value: &str) -> Self {
            self.write_overrides
                .insert(key.to_string(), value.to_string());
            self
        }
    }

    impl SysctlStore for FakeSysctlStore {
        fn exists(&self, key: &str) -> bool {
            !self.missing.contains(key)
        }

        fn read(&self, key: &str) -> io::Result<String> {
            if let Some(kind) = self.read_errors.get(key) {
                return Err(io::Error::from(*kind));
            }
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
            let next = self
                .write_overrides
                .get(key)
                .map(String::as_str)
                .unwrap_or(value);
            self.values
                .borrow_mut()
                .insert(key.to_string(), next.to_string());
            Ok(())
        }
    }

    #[test]
    fn kernel_tuning_applies_changed_value() {
        let store = FakeSysctlStore::default().with_value("net.core.somaxconn", "4096\n");

        let report = apply_param(
            &store,
            KernelParamTune::exact("net.core.somaxconn", "65535"),
        );

        assert_eq!(report.status, KernelTuningStatus::Applied);
        assert_eq!(report.old.as_deref(), Some("4096"));
        assert_eq!(report.final_value.as_deref(), Some("65535"));
    }

    #[test]
    fn kernel_tuning_reports_missing_sysctl() {
        let store = FakeSysctlStore::default().missing("net.core.netdev_max_backlog");

        let report = apply_param(
            &store,
            KernelParamTune::exact("net.core.netdev_max_backlog", "250000"),
        );

        assert_eq!(report.status, KernelTuningStatus::SkippedMissing);
        assert!(report.old.is_none());
    }

    #[test]
    fn kernel_tuning_reports_permission_denied() {
        let store = FakeSysctlStore::default()
            .with_value("fs.nr_open", "1048576")
            .write_error("fs.nr_open", io::ErrorKind::PermissionDenied);

        let report = apply_param(&store, KernelParamTune::exact("fs.nr_open", "2097152"));

        assert_eq!(report.status, KernelTuningStatus::FailedWrite);
        assert_eq!(report.final_value.as_deref(), Some("1048576"));
    }

    #[test]
    fn kernel_tuning_optional_bbr_unavailable_is_nonfatal() {
        let store = FakeSysctlStore::default()
            .with_value("net.ipv4.tcp_congestion_control", "cubic")
            .write_error(
                "net.ipv4.tcp_congestion_control",
                io::ErrorKind::InvalidInput,
            );

        let report = apply_param(
            &store,
            KernelParamTune::optional("net.ipv4.tcp_congestion_control", "bbr"),
        );

        assert_eq!(report.status, KernelTuningStatus::SkippedOptional);
        assert_eq!(report.final_value.as_deref(), Some("cubic"));
    }

    #[test]
    fn kernel_tuning_detects_verify_mismatch() {
        let store = FakeSysctlStore::default()
            .with_value("net.core.default_qdisc", "pfifo_fast")
            .write_override("net.core.default_qdisc", "fq_codel");

        let report = apply_param(
            &store,
            KernelParamTune::exact("net.core.default_qdisc", "fq"),
        );

        assert_eq!(report.status, KernelTuningStatus::VerifyMismatch);
        assert_eq!(report.final_value.as_deref(), Some("fq_codel"));
    }

    #[test]
    fn kernel_tuning_includes_persistent_only_skips() {
        let reports = persistent_only_reports();

        assert!(reports.iter().any(|report| {
            report.key == "/etc/sysctl.d/99-bbr-tuning.conf"
                && report.status == KernelTuningStatus::NotAppliedPersistentOnly
        }));
    }
}
