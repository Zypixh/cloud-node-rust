//! Integration tests for OOM / memory-growth audit findings.
//! These tests verify bounded structures and document structural gaps where
//! governor budgets exist but are not yet wired to every runtime cache.

use cloud_node_rust::firewall::matcher::evaluate_operator;
use cloud_node_rust::memory_governor::MEMORY_GOVERNOR;
use cloud_node_rust::metrics::aggregator::{AggregationKey, MetricAggregator};
use cloud_node_rust::metrics::daily::DailyDomainTracker;
use cloud_node_rust::metrics::top_ip::TopIpTracker;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

const IP_REPORT_CHANNEL_CAPACITY: usize = 1000;
const RPC_STREAM_CHANNEL_CAPACITY: usize = 100;

fn governor_snapshot() -> cloud_node_rust::memory_governor::GovernorSnapshot {
    MEMORY_GOVERNOR.snapshot(MEMORY_GOVERNOR.pingora_worker_threads())
}

#[test]
fn governor_cardinality_and_regex_budgets_stay_within_available_memory() {
    let snapshot = governor_snapshot();
    let available = snapshot.memory_available_bytes.max(1);

    assert!(snapshot.cardinality_state_budget_bytes > 0);
    assert!(snapshot.regex_cache_budget_bytes > 0);
    assert!(snapshot.cardinality_state_budget_bytes <= available);
    assert!(snapshot.regex_cache_budget_bytes <= snapshot.l4_aggregate_state_budget_bytes);
    assert!(snapshot.l4_aggregate_state_budget_bytes <= available);
}

#[test]
fn governor_event_queue_capacities_stay_below_guardrail_max() {
    let snapshot = governor_snapshot();
    assert!(snapshot.access_log_queue_capacity <= 1_000_000);
    assert!(snapshot.metrics_queue_capacity <= 1_000_000);
    assert!(snapshot.node_log_queue_capacity <= 100_000);
    assert!(snapshot.local_log_queue_budget_bytes <= snapshot.memory_available_bytes);
    assert!(snapshot.ip_report_queue_budget_bytes <= snapshot.memory_available_bytes);
}

#[test]
fn rpc_stream_channel_depth_aligns_with_governor_admission_limit() {
    let snapshot = governor_snapshot();
    let aligned = snapshot
        .rpc_stream_command_limit
        .clamp(1, RPC_STREAM_CHANNEL_CAPACITY);
    assert!(
        aligned <= RPC_STREAM_CHANNEL_CAPACITY,
        "RPC stream channel depth should not exceed the historical fixed cap"
    );
    assert!(
        snapshot.rpc_stream_command_limit > 0,
        "RPC stream admission limit must remain positive"
    );
    assert!(
        snapshot.cluster_internal_connection_limit > 0,
        "cluster internal admission must remain positive"
    );
}

#[test]
fn ip_report_channel_depth_is_conservative_relative_to_governor_budget() {
    let snapshot = governor_snapshot();
    let budget_items = snapshot
        .ip_report_queue_budget_bytes
        .saturating_div(256)
        .max(1) as usize;
    assert!(
        IP_REPORT_CHANNEL_CAPACITY <= budget_items,
        "ip_report mpsc depth ({IP_REPORT_CHANNEL_CAPACITY}) should stay within governor-derived item budget ({budget_items})"
    );
}

#[test]
fn metric_aggregator_flush_empties_in_memory_store() {
    let aggregator = MetricAggregator::new();
    let key = AggregationKey {
        category: Arc::from(cloud_node_rust::metrics::METRIC_CATEGORY_HTTP),
        server_id: 1,
        country: Arc::from(""),
        country_id: 0,
        province: Arc::from(""),
        province_id: 0,
        city: Arc::from(""),
        city_id: 0,
        provider: Arc::from("Unknown"),
        browser: Arc::from(""),
        os: Arc::from(""),
        waf_group_id: 0,
        waf_action: Arc::from(""),
        provider_id: 0,
        browser_version: Arc::from(""),
        os_version: Arc::from(""),
        request_attrs: Arc::new(BTreeMap::new()),
    };

    aggregator.record(key, 100, 10, false);
    assert_eq!(aggregator.data.len(), 1);

    let flushed = aggregator.flush();
    assert_eq!(flushed.len(), 1);
    assert!(
        aggregator.data.is_empty(),
        "flush must drain aggregator keys"
    );
}

#[test]
fn metric_stat_aggregator_with_samples_flush_drains_all_state() {
    let aggregator = MetricAggregator::with_request_samples(true);
    let mut attrs = BTreeMap::new();
    attrs.insert("requestId".to_string(), "1".to_string());
    let key = AggregationKey {
        category: Arc::from(cloud_node_rust::metrics::METRIC_CATEGORY_HTTP),
        server_id: 42,
        country: Arc::from(""),
        country_id: 0,
        province: Arc::from(""),
        province_id: 0,
        city: Arc::from(""),
        city_id: 0,
        provider: Arc::from("Unknown"),
        browser: Arc::from(""),
        os: Arc::from(""),
        waf_group_id: 0,
        waf_action: Arc::from(""),
        provider_id: 0,
        browser_version: Arc::from(""),
        os_version: Arc::from(""),
        request_attrs: Arc::new(attrs),
    };

    aggregator.record(key, 1, 1, false);
    assert_eq!(aggregator.data.len(), 1);
    let rows = aggregator.flush();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1.request_samples.len(), 1);
    assert!(aggregator.data.is_empty());
}

#[test]
fn top_ip_tracker_flush_empties_counts() {
    let tracker = TopIpTracker::new();
    let ip: IpAddr = "203.0.113.10".parse().unwrap();
    tracker.record_addr(7, ip);
    tracker.record_addr(7, ip);

    let rows = tracker.flush();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], (7, "203.0.113.10".to_string(), 2));
    assert!(tracker.flush().is_empty(), "second flush must be empty");
}

#[test]
fn daily_domain_tracker_flush_drops_stale_days() {
    let tracker = DailyDomainTracker::new();
    tracker.record(1, 20240101, "a.example.com", 10, 0, 1, 0, 0, 0);
    tracker.record(1, 20240102, "b.example.com", 20, 0, 1, 0, 0, 0);

    let flushed = tracker.flush_older_than(20240102);
    assert_eq!(flushed.len(), 1);
    assert_eq!(flushed[0].2, "a.example.com");

    let remaining = tracker.flush_older_than(20240103);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].2, "b.example.com");
}

#[test]
fn waf_regex_evaluator_reuses_compiled_patterns_without_error() {
    let pattern = "^oom-audit-reuse-[0-9]+$";
    for value in ["oom-audit-reuse-1", "oom-audit-reuse-2", "no-match"] {
        let _ = evaluate_operator(value, "regexp", pattern, false);
    }
    assert!(evaluate_operator(
        "oom-audit-reuse-99",
        "regexp",
        pattern,
        false
    ));
    assert!(!evaluate_operator("bad", "regexp", pattern, false));
}

#[test]
fn config_sync_decode_budget_is_bounded_by_governor_available_memory() {
    let snapshot = governor_snapshot();
    let limits = cloud_node_rust::config_apply::ConfigApplyLimits::from_governor();
    assert_eq!(limits.available_bytes, snapshot.memory_available_bytes);
    assert!(limits.decode_budget_bytes() > 0);
    assert!(
        limits.decode_budget_bytes() <= snapshot.memory_available_bytes.max(16 * 1024 * 1024),
        "config-sync decode budget must not exceed available memory"
    );
    assert!(
        limits.server_chunk_size() <= 256,
        "config-sync chunk size must stay bounded"
    );
    let high = cloud_node_rust::config_apply::ConfigApplyLimits::synthetic(
        2 * 1024 * 1024 * 1024,
        150 * 1024 * 1024,
    );
    let low = cloud_node_rust::config_apply::ConfigApplyLimits::synthetic(
        512 * 1024 * 1024,
        32 * 1024 * 1024,
    );
    assert!(high.drop_previous_generation());
    assert!(low.drop_previous_generation());
    assert!(
        !limits.drop_previous_generation()
            || snapshot.memory_pressure_level
                >= cloud_node_rust::memory_governor::MemoryPressureLevel::High
    );
}

#[test]
fn waf_regex_evaluator_handles_many_unique_patterns_without_panic() {
    for i in 0..512 {
        let pattern = format!("^unique-pattern-{i}$");
        assert!(evaluate_operator(
            &format!("unique-pattern-{i}"),
            "regexp",
            &pattern,
            false
        ));
    }
}
