use cloud_node_rust::l4_defense::{
    self, L4DefenseKind, L4PressureLevel, first_byte_timeout, metrics_snapshot,
    quic_new_route_limit, tcp_active_limit_per_ip_for_level, try_acquire_tcp_active_ip,
};
use cloud_node_rust::memory_governor::{AdmissionClass, MEMORY_GOVERNOR};
use cloud_node_rust::memory_plan::current_memory_plan;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

struct ActiveGuard {
    active: Arc<AtomicU64>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[test]
fn memory_plan_exposes_l4_and_l7_attack_budgets() {
    let plan = current_memory_plan(MEMORY_GOVERNOR.pingora_worker_threads());
    assert!(
        plan.summary.contains("l4_pressure"),
        "memory plan should expose live L4 pressure for attack response auditing"
    );
    assert!(
        plan.items.iter().any(|item| item.area == "waf_body"),
        "memory plan should expose L7 WAF body admission limits"
    );
    assert!(
        plan.items
            .iter()
            .any(|item| item.area == "response_transform"),
        "memory plan should expose L7 response transform admission limits"
    );
    assert!(
        plan.items.iter().any(|item| item.area == "downstream_h2"),
        "memory plan should expose H2 stream admission limits for rapid-reset style attacks"
    );
    assert!(
        plan.items.iter().any(|item| item.area == "downstream_h3"),
        "memory plan should expose H3/QUIC admission limits"
    );
    assert!(
        plan.items.iter().any(|item| item.area == "downstream_udp"),
        "memory plan should expose UDP/QUIC passthrough queue budgets"
    );

    let snapshot = MEMORY_GOVERNOR.snapshot(MEMORY_GOVERNOR.pingora_worker_threads());
    assert!(
        snapshot.l4_aggregate_state_budget_bytes > 0,
        "L4 aggregate state must have a positive governor budget under attack"
    );
    assert!(
        snapshot.cardinality_state_budget_bytes > 0,
        "L4 exact counter/cardinality state must have a positive governor budget under attack"
    );
}

#[test]
fn l7_waf_and_transform_admission_stays_bounded_under_attack_load() {
    for class in [
        AdmissionClass::RequestBodyWaf,
        AdmissionClass::ResponseBodyWaf,
        AdmissionClass::ResponseTransform,
        AdmissionClass::CacheRevalidate,
    ] {
        let limit = MEMORY_GOVERNOR.limit_for(class);
        assert!(
            limit > 0,
            "L7 class {class:?} must keep positive admission during attacks"
        );
        assert!(
            limit <= 1_000_000,
            "L7 class {class:?} must stay below hard guardrail max during floods"
        );
    }
}

#[test]
fn l4_adaptive_limits_tighten_under_attack_pressure() {
    let total = MEMORY_GOVERNOR
        .limit_for(AdmissionClass::TcpConnection)
        .max(1);
    let normal_per_ip = tcp_active_limit_per_ip_for_level(total, L4PressureLevel::Normal);
    let critical_per_ip = tcp_active_limit_per_ip_for_level(total, L4PressureLevel::Critical);
    assert!(
        critical_per_ip < normal_per_ip,
        "single-IP TCP flood limit should tighten under critical L4 pressure"
    );

    let normal_timeout = first_byte_timeout(L4PressureLevel::Normal);
    let critical_timeout = first_byte_timeout(L4PressureLevel::Critical);
    assert!(
        critical_timeout < normal_timeout,
        "slow-first-byte defense should release sockets faster under critical pressure"
    );
    assert!(critical_timeout <= Duration::from_millis(250));

    let normal_quic_routes = quic_new_route_limit(L4PressureLevel::Normal);
    let critical_quic_routes = quic_new_route_limit(L4PressureLevel::Critical);
    assert!(
        critical_quic_routes < normal_quic_routes,
        "QUIC route flood limit should shrink under critical pressure"
    );
}

#[test]
fn single_ip_tcp_flood_hits_active_connection_limit() {
    let ip: IpAddr = "198.51.100.250".parse().unwrap();
    let limit = 8;
    let mut permits = Vec::new();
    for _ in 0..limit {
        permits.push(
            try_acquire_tcp_active_ip(ip, limit).expect("should admit up to the per-IP TCP limit"),
        );
    }
    assert!(
        try_acquire_tcp_active_ip(ip, limit).is_none(),
        "single-IP TCP flood must fail closed once the active-per-IP limit is reached"
    );
    drop(permits);
    assert!(
        try_acquire_tcp_active_ip(ip, limit).is_some(),
        "dropping attack sockets must release the per-IP permit"
    );
}

#[test]
fn concurrent_h2_h3_udp_admission_respects_attack_path_limits() {
    let classes = [
        AdmissionClass::Http2Stream,
        AdmissionClass::Http3Request,
        AdmissionClass::UdpSession,
        AdmissionClass::Http3Connection,
    ];
    let limits: Vec<usize> = classes
        .iter()
        .map(|class| MEMORY_GOVERNOR.limit_for(*class))
        .collect();
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
    let barrier = Arc::new(Barrier::new(16));
    let mut handles = Vec::new();
    for _ in 0..16 {
        let limits = limits.clone();
        let active = Arc::clone(&active);
        let peak_active = Arc::clone(&peak_active);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut permits = Vec::new();
            for (idx, class) in classes.iter().enumerate() {
                for _ in 0..limits[idx] / 16 + 16 {
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
            "all {class:?} attack-path permits must be released"
        );
        assert!(
            peak_active[idx].load(Ordering::Acquire) <= limits[idx] as u64,
            "peak concurrent {class:?} admissions must not exceed hard limit during flood"
        );
    }
}

#[test]
fn l4_metrics_snapshot_is_available_for_attack_observability() {
    let metrics = metrics_snapshot();
    assert!(
        metrics.events_total >= metrics.blocked_total,
        "blocked events cannot exceed total L4 events"
    );
    assert!(
        metrics.admission_reject_total <= metrics.events_total,
        "admission reject metrics must stay consistent with total events"
    );
    assert!(
        !metrics.top_event_kind.is_empty() || metrics.events_total == 0,
        "top L4 event kind should be populated once attack events were recorded"
    );
}

#[test]
fn l4_defense_kinds_cover_common_attack_vectors() {
    let vectors = [
        (L4DefenseKind::TcpAdmissionReject, "connection flood"),
        (L4DefenseKind::TcpSlowFirstByte, "slowloris"),
        (L4DefenseKind::TlsSlowClientHello, "slow TLS"),
        (L4DefenseKind::HttpSlowHeader, "slow HTTP headers"),
        (L4DefenseKind::H2RapidReset, "H2 rapid reset"),
        (L4DefenseKind::H2StreamAdmissionReject, "H2 stream flood"),
        (L4DefenseKind::UdpSessionFlood, "UDP session flood"),
        (L4DefenseKind::QuicNewRouteFlood, "QUIC route flood"),
        (L4DefenseKind::H3AdmissionReject, "HTTP/3 admission flood"),
        (L4DefenseKind::SynBacklogPressure, "SYN backlog pressure"),
    ];
    for (kind, label) in vectors {
        assert!(
            !kind.as_str().is_empty(),
            "{label} kind should have stable metric name"
        );
    }
}

#[test]
fn current_l4_pressure_integrates_live_governor_signals() {
    let level = l4_defense::current_pressure_level();
    let _ = level.as_str();
    let tcp_limit = l4_defense::current_tcp_active_limit_per_ip();
    assert!(
        tcp_limit >= 16,
        "current TCP per-IP limit must remain usable under audit"
    );
}
