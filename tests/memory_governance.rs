use cloud_node_rust::memory_governor::{
    AdmissionClass, MEMORY_GOVERNOR, MemoryPressureLevel, reported_memory_totals,
};
use cloud_node_rust::memory_plan::current_memory_plan;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

struct ActiveGuard {
    active: Arc<AtomicU64>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn assert_budget_fields_within_available(snapshot: &cloud_node_rust::memory_governor::GovernorSnapshot) {
    let available = snapshot.memory_available_bytes.max(1);
    let budgets = [
        ("connection", snapshot.connection_budget_bytes),
        ("cache", snapshot.cache_budget_bytes),
        ("bloom", snapshot.bloom_budget_bytes),
        ("keepalive", snapshot.keepalive_budget_bytes),
        ("cache_read_memory", snapshot.cache_read_memory_budget_bytes),
        ("udp_queue", snapshot.udp_queued_bytes_budget),
        ("zero_copy", snapshot.zero_copy_relay_budget_bytes),
        ("l4_aggregate", snapshot.l4_aggregate_state_budget_bytes),
        ("kernel_sync", snapshot.kernel_sync_queue_budget_bytes),
        ("cardinality", snapshot.cardinality_state_budget_bytes),
        ("regex_cache", snapshot.regex_cache_budget_bytes),
        ("logging_retry", snapshot.logging_retry_budget_bytes),
        ("local_log_queue", snapshot.local_log_queue_budget_bytes),
        ("ip_report_queue", snapshot.ip_report_queue_budget_bytes),
        ("af_xdp", snapshot.af_xdp_budget_bytes),
    ];
    for (name, budget) in budgets {
        assert!(
            budget <= available,
            "{name} budget ({budget}) must not exceed available memory ({available})"
        );
    }
}

#[test]
fn memory_plan_snapshot_is_internally_consistent() {
    let threads = MEMORY_GOVERNOR.pingora_worker_threads();
    let plan = current_memory_plan(threads);
    assert!(
        !plan.summary.is_empty(),
        "memory plan summary should describe the active governor snapshot"
    );
    assert!(
        plan.items.iter().any(|item| item.area == "cache_and_background"),
        "memory plan should expose cache/background budgets"
    );
    assert!(
        plan.items
            .iter()
            .any(|item| item.area == "downstream_http"),
        "memory plan should expose downstream HTTP admission policy"
    );
}

#[test]
fn reported_memory_totals_match_governor_snapshot() {
    let (total, used) = reported_memory_totals();
    let snapshot = MEMORY_GOVERNOR.snapshot(MEMORY_GOVERNOR.pingora_worker_threads());
    assert_eq!(total, snapshot.memory_total_bytes.min(i64::MAX as u64) as i64);
    assert_eq!(used, snapshot.memory_used_bytes.min(i64::MAX as u64) as i64);
    assert_budget_fields_within_available(&snapshot);
}

#[test]
fn all_downstream_admission_classes_have_positive_limits() {
    for class in [
        AdmissionClass::HttpConnection,
        AdmissionClass::TcpConnection,
        AdmissionClass::Http3Connection,
        AdmissionClass::UdpSession,
        AdmissionClass::Http2Stream,
        AdmissionClass::Http3Request,
        AdmissionClass::OriginConnect,
    ] {
        assert!(
            MEMORY_GOVERNOR.limit_for(class) > 0,
            "downstream class {class:?} must keep a positive admission limit"
        );
    }
}

#[test]
fn control_plane_admission_classes_have_positive_limits() {
    for class in [
        AdmissionClass::ClusterInternalConnection,
        AdmissionClass::RpcStreamCommand,
    ] {
        assert!(
            MEMORY_GOVERNOR.limit_for(class) > 0,
            "control-plane class {class:?} must keep a positive admission limit"
        );
    }
}

#[test]
fn high_cost_background_classes_stay_bounded() {
    for class in [
        AdmissionClass::BackgroundWork,
        AdmissionClass::RequestBodyWaf,
        AdmissionClass::ResponseBodyWaf,
        AdmissionClass::ResponseTransform,
        AdmissionClass::CacheRevalidate,
        AdmissionClass::CacheWrite,
        AdmissionClass::CacheReadMemory,
    ] {
        let limit = MEMORY_GOVERNOR.limit_for(class);
        assert!(limit > 0, "class {class:?} must keep a positive limit");
        assert!(
            limit <= 1_000_000,
            "class {class:?} must remain below the hard guardrail max"
        );
    }
}

#[test]
fn concurrent_mixed_admission_never_exceeds_per_class_limits() {
    let classes = [
        AdmissionClass::HttpConnection,
        AdmissionClass::TcpConnection,
        AdmissionClass::OriginConnect,
        AdmissionClass::ClusterInternalConnection,
        AdmissionClass::RpcStreamCommand,
        AdmissionClass::BackgroundWork,
    ];
    let limits: Arc<Vec<usize>> = Arc::new(
        classes
            .iter()
            .map(|class| MEMORY_GOVERNOR.limit_for(*class))
            .collect(),
    );
    let active: Arc<Vec<Arc<AtomicU64>>> = Arc::new(
        (0..classes.len())
            .map(|_| Arc::new(AtomicU64::new(0)))
            .collect(),
    );
    let peak_active: Arc<Vec<Arc<AtomicU64>>> = Arc::new(
        (0..classes.len())
            .map(|_| Arc::new(AtomicU64::new(0)))
            .collect(),
    );
    let barrier = Arc::new(Barrier::new(24));
    let mut handles = Vec::new();
    for _ in 0..24 {
        let limits = Arc::clone(&limits);
        let active = Arc::clone(&active);
        let peak_active = Arc::clone(&peak_active);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut permits = Vec::new();
            for (idx, class) in classes.iter().enumerate() {
                for _ in 0..limits[idx] / 24 + 32 {
                    if let Some(permit) = MEMORY_GOVERNOR.try_admit(*class) {
                        let current = active[idx].fetch_add(1, Ordering::AcqRel) + 1;
                        peak_active[idx].fetch_max(current, Ordering::AcqRel);
                        permits.push((
                            permit,
                            ActiveGuard {
                                active: Arc::clone(&active[idx]),
                            },
                        ));
                    }
                }
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    for (idx, class) in classes.iter().enumerate() {
        assert_eq!(
            active[idx].load(Ordering::Acquire),
            0,
            "all permits for {class:?} must be released after concurrent stress"
        );
        assert!(
            peak_active[idx].load(Ordering::Acquire) <= limits[idx] as u64,
            "peak concurrent admissions for {class:?} must not exceed the hard limit"
        );
    }
}

#[test]
fn zero_copy_relay_is_disabled_when_memory_or_fd_pressure_is_high() {
    let snapshot = MEMORY_GOVERNOR.snapshot(MEMORY_GOVERNOR.pingora_worker_threads());
    if snapshot.memory_pressure_level >= MemoryPressureLevel::High
        || snapshot.fd_pressure_level >= MemoryPressureLevel::High
        || MEMORY_GOVERNOR.is_connection_admission_pressure_high()
    {
        assert!(
            MEMORY_GOVERNOR.try_admit_zero_copy_relay().is_none(),
            "zero-copy relay should stay disabled under high pressure"
        );
    } else {
        let permit = MEMORY_GOVERNOR.try_admit_zero_copy_relay();
        if let Some(permit) = permit {
            assert_eq!(MEMORY_GOVERNOR.zero_copy_relay_active(), 1);
            drop(permit);
            assert_eq!(MEMORY_GOVERNOR.zero_copy_relay_active(), 0);
        }
    }
}

#[test]
fn relay_copy_buffer_stays_within_pressure_aware_bounds() {
    let buffer = MEMORY_GOVERNOR.relay_copy_buffer_bytes();
    assert!(
        (16 * 1024..=256 * 1024).contains(&buffer),
        "relay copy buffer should stay within governor min/max bounds, got {buffer}"
    );
}

#[test]
fn firewall_and_event_queue_capacities_scale_without_fixed_explosion() {
    let snapshot = MEMORY_GOVERNOR.snapshot(MEMORY_GOVERNOR.pingora_worker_threads());
    assert!(
        snapshot.access_log_queue_capacity <= 1_000_000,
        "access log queue must stay below guardrail max"
    );
    assert!(
        snapshot.metrics_queue_capacity <= 1_000_000,
        "metrics queue must stay below guardrail max"
    );
    assert!(
        snapshot.firewall_ip_limiter_capacity <= 32_000_000,
        "firewall ip limiter capacity must stay below guardrail max"
    );
    assert!(
        snapshot.firewall_rolling_counter_capacity <= 16_000_000,
        "firewall rolling counter capacity must stay below guardrail max"
    );
    assert!(
        snapshot.node_log_queue_capacity <= 100_000,
        "node log queue must stay below guardrail max"
    );
}
