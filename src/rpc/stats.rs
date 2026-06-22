use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::metrics::ServerStatusSnapshot;
use crate::pb;
use crate::rpc::client::SharedRpcClient;
use chrono::{Datelike, Duration as ChronoDuration, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock as Lazy;
use std::sync::atomic::{AtomicI64, AtomicU8, Ordering};
use tracing::{debug, info, warn};

#[allow(dead_code)]
const ORIGIN_HEALTH_STATUS_UNKNOWN: u8 = 0;
const ORIGIN_HEALTH_STATUS_HEALTHY: u8 = 1;
const ORIGIN_HEALTH_STATUS_DOWN: u8 = 2;

struct OriginHealthEntry {
    status: AtomicU8,
    latency_ms: AtomicI64,
    last_check_ts: AtomicI64,
}

static ORIGIN_HEALTH_MAP: Lazy<dashmap::DashMap<i64, Arc<OriginHealthEntry>>> =
    Lazy::new(dashmap::DashMap::new);

pub fn push_origin_health_event(origin_id: i64, healthy: bool, latency_ms: i64) {
    if origin_id <= 0 {
        return;
    }
    let now = crate::utils::time::now_timestamp();
    let status = if healthy {
        ORIGIN_HEALTH_STATUS_HEALTHY
    } else {
        ORIGIN_HEALTH_STATUS_DOWN
    };
    if let Some(entry) = ORIGIN_HEALTH_MAP.get(&origin_id) {
        entry.status.store(status, Ordering::Relaxed);
        entry.latency_ms.store(latency_ms, Ordering::Relaxed);
        entry.last_check_ts.store(now, Ordering::Relaxed);
    } else {
        ORIGIN_HEALTH_MAP.insert(
            origin_id,
            Arc::new(OriginHealthEntry {
                status: AtomicU8::new(status),
                latency_ms: AtomicI64::new(latency_ms),
                last_check_ts: AtomicI64::new(now),
            }),
        );
    }
}

pub async fn start_origin_health_reporter(api_config: ApiConfig) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        if !crate::cluster::leader::require_leader("origin_health_reporter") {
            continue;
        }
        if ORIGIN_HEALTH_MAP.is_empty() {
            continue;
        }
        let created_at = crate::utils::time::now_timestamp();
        let items: Vec<_> = ORIGIN_HEALTH_MAP
            .iter()
            .map(|entry| {
                let origin_id = *entry.key();
                let e = entry.value();
                let status_str = match e.status.load(Ordering::Relaxed) {
                    ORIGIN_HEALTH_STATUS_HEALTHY => "healthy",
                    ORIGIN_HEALTH_STATUS_DOWN => "down",
                    _ => "unknown",
                };
                pb::create_node_values_request::NodeValueItem {
                    item: format!("originHealth_{}", origin_id),
                    value_json: serde_json::json!({
                        "originId": origin_id,
                        "status": status_str,
                        "latencyMs": e.latency_ms.load(Ordering::Relaxed),
                        "lastCheckTs": e.last_check_ts.load(Ordering::Relaxed),
                    })
                    .to_string()
                    .into_bytes(),
                    created_at,
                }
            })
            .collect();

        if items.is_empty() {
            continue;
        }

        let client = match SharedRpcClient::get(&api_config).await {
            Ok(shared) => shared.as_rpc_client(),
            Err(e) => {
                warn!("Origin health reporter failed to connect: {}", e);
                continue;
            }
        };
        let mut service = client.node_value_service();
        if let Err(e) =
            crate::rpc::track_rpc(service.create_node_values(pb::CreateNodeValuesRequest {
                node_value_items: items,
            }))
            .await
        {
            debug!("Origin health report failed: {}", e);
        }
    }
}

fn billable_bytes(snapshot: &ServerStatusSnapshot, api_config: &ApiConfig) -> u64 {
    if api_config.billing_count_inbound_traffic {
        snapshot.total_bytes()
    } else {
        snapshot.bytes_sent
    }
}

const BANDWIDTH_REPORT_INTERVAL_SECS: u64 = 300;
const BANDWIDTH_SAMPLE_INTERVAL_SECS: u64 = 2;
const STAT_RETRY_RETENTION_SECS: i64 = 1200;
const BANDWIDTH_ALGO_AVG: &str = "avg";

fn bandwidth_bytes_per_sec(stat: &BandwidthWindowStat, config_store: &ConfigStore) -> u64 {
    let use_avg = stat.user_plan_id > 0
        && config_store
            .get_user_plan_sync(stat.user_plan_id)
            .and_then(|user_plan| user_plan.user)
            .map(|user| user.bandwidth_algo == BANDWIDTH_ALGO_AVG)
            .unwrap_or(false);

    if use_avg {
        stat.total_bytes / BANDWIDTH_REPORT_INTERVAL_SECS
    } else {
        stat.peak_bytes_per_sec
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct BandwidthWindowStat {
    day: String,
    time_at: String,
    user_id: i64,
    server_id: i64,
    user_plan_id: i64,
    peak_bytes_per_sec: u64,
    total_bytes: u64,
    cached_bytes: u64,
    attack_bytes: u64,
    count_requests: u64,
    count_cached_requests: u64,
    count_attack_requests: u64,
    count_websocket_connections: u64,
    origin_total_bytes: u64,
    origin_avg_bytes: u64,
    origin_avg_bits: u64,
    count_ips: u64,
}

#[derive(Clone)]
struct PendingBandwidthStat {
    queued_at: i64,
    stat: pb::ServerBandwidthStat,
}

#[derive(Default, Serialize, Deserialize)]
struct StoredBandwidthState {
    current_window: String,
    window_stats: Vec<BandwidthWindowStat>,
    pending_stats: Vec<StoredPendingBandwidthStat>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct StoredPendingBandwidthStat {
    queued_at: i64,
    user_id: i64,
    server_id: i64,
    day: String,
    time_at: String,
    bytes: i64,
    bits: i64,
    total_bytes: i64,
    cached_bytes: i64,
    attack_bytes: i64,
    count_requests: i64,
    count_cached_requests: i64,
    count_attack_requests: i64,
    user_plan_id: i64,
    count_websocket_connections: i64,
    origin_total_bytes: i64,
    origin_avg_bytes: i64,
    origin_avg_bits: i64,
    count_i_ps: i64,
    node_region_id: i64,
}

const BANDWIDTH_STATE_STORAGE_KEY: &str = "STAT_BANDWIDTH_STATE_V1";

impl From<&PendingBandwidthStat> for StoredPendingBandwidthStat {
    fn from(value: &PendingBandwidthStat) -> Self {
        let stat = &value.stat;
        Self {
            queued_at: value.queued_at,
            user_id: stat.user_id,
            server_id: stat.server_id,
            day: stat.day.clone(),
            time_at: stat.time_at.clone(),
            bytes: stat.bytes,
            bits: stat.bits,
            total_bytes: stat.total_bytes,
            cached_bytes: stat.cached_bytes,
            attack_bytes: stat.attack_bytes,
            count_requests: stat.count_requests,
            count_cached_requests: stat.count_cached_requests,
            count_attack_requests: stat.count_attack_requests,
            user_plan_id: stat.user_plan_id,
            count_websocket_connections: stat.count_websocket_connections,
            origin_total_bytes: stat.origin_total_bytes,
            origin_avg_bytes: stat.origin_avg_bytes,
            origin_avg_bits: stat.origin_avg_bits,
            count_i_ps: stat.count_i_ps,
            node_region_id: stat.node_region_id,
        }
    }
}

impl From<StoredPendingBandwidthStat> for PendingBandwidthStat {
    fn from(value: StoredPendingBandwidthStat) -> Self {
        Self {
            queued_at: value.queued_at,
            stat: pb::ServerBandwidthStat {
                user_id: value.user_id,
                server_id: value.server_id,
                day: value.day,
                time_at: value.time_at,
                bytes: value.bytes,
                bits: value.bits,
                total_bytes: value.total_bytes,
                cached_bytes: value.cached_bytes,
                attack_bytes: value.attack_bytes,
                count_requests: value.count_requests,
                count_cached_requests: value.count_cached_requests,
                count_attack_requests: value.count_attack_requests,
                user_plan_id: value.user_plan_id,
                count_websocket_connections: value.count_websocket_connections,
                origin_total_bytes: value.origin_total_bytes,
                origin_avg_bytes: value.origin_avg_bytes,
                origin_avg_bits: value.origin_avg_bits,
                count_i_ps: value.count_i_ps,
                node_region_id: value.node_region_id,
                ..Default::default()
            },
        }
    }
}

fn load_bandwidth_state() -> (
    String,
    HashMap<i64, BandwidthWindowStat>,
    Vec<PendingBandwidthStat>,
) {
    let Some(state) = crate::metrics::storage::STORAGE
        .get_json::<StoredBandwidthState>(BANDWIDTH_STATE_STORAGE_KEY)
    else {
        return (String::new(), HashMap::new(), Vec::new());
    };

    let now = crate::utils::time::now_local();
    let today = now.format("%Y%m%d").to_string();
    let available_time = (now - ChronoDuration::seconds(BANDWIDTH_REPORT_INTERVAL_SECS as i64))
        .format("%H%M")
        .to_string();
    let mut window_stats = HashMap::new();
    for stat in state.window_stats {
        if stat.day == today && stat.time_at >= available_time {
            window_stats.insert(stat.server_id, stat);
        }
    }
    let current_window = if window_stats.is_empty() {
        String::new()
    } else {
        state.current_window
    };

    let now_ts = crate::utils::time::now_timestamp();
    let pending_stats = state
        .pending_stats
        .into_iter()
        .map(PendingBandwidthStat::from)
        .filter(|item| now_ts - item.queued_at <= STAT_RETRY_RETENTION_SECS)
        .collect();

    (current_window, window_stats, pending_stats)
}

fn persist_bandwidth_state(
    current_window: &str,
    window_stats: &HashMap<i64, BandwidthWindowStat>,
    pending_stats: &[PendingBandwidthStat],
) {
    if current_window.is_empty() && window_stats.is_empty() && pending_stats.is_empty() {
        let _ = crate::metrics::storage::STORAGE.delete_key(BANDWIDTH_STATE_STORAGE_KEY);
        return;
    }

    let state = StoredBandwidthState {
        current_window: current_window.to_string(),
        window_stats: window_stats.values().cloned().collect(),
        pending_stats: pending_stats
            .iter()
            .map(StoredPendingBandwidthStat::from)
            .collect(),
    };
    let _ = crate::metrics::storage::STORAGE.put_json(BANDWIDTH_STATE_STORAGE_KEY, &state);
}

fn snapshot_delta(
    current: &ServerStatusSnapshot,
    last: Option<&ServerStatusSnapshot>,
) -> ServerStatusSnapshot {
    let delta = |field: fn(&ServerStatusSnapshot) -> u64| -> u64 {
        let current_value = field(current);
        let last_value = last.map(field).unwrap_or(0);
        current_value.saturating_sub(last_value)
    };

    ServerStatusSnapshot {
        server_id: current.server_id,
        user_id: current.user_id,
        user_plan_id: current.user_plan_id,
        plan_id: current.plan_id,
        total_requests: delta(|s| s.total_requests),
        active_connections: current.active_connections,
        bytes_sent: delta(|s| s.bytes_sent),
        bytes_received: delta(|s| s.bytes_received),
        cached_bytes: delta(|s| s.cached_bytes),
        attack_bytes: delta(|s| s.attack_bytes),
        count_cached_requests: delta(|s| s.count_cached_requests),
        count_attack_requests: delta(|s| s.count_attack_requests),
        count_websocket_connections: delta(|s| s.count_websocket_connections),
        origin_bytes_sent: delta(|s| s.origin_bytes_sent),
        origin_bytes_received: delta(|s| s.origin_bytes_received),
        count_ips: current.count_ips,
    }
}

pub async fn start_bandwidth_reporter(config_store: ConfigStore, api_config: ApiConfig) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
        BANDWIDTH_SAMPLE_INTERVAL_SECS,
    ));
    let mut last_snapshots: HashMap<i64, ServerStatusSnapshot> = HashMap::new();
    let (mut current_window, mut window_stats, mut pending_stats) = load_bandwidth_state();

    loop {
        interval.tick().await;
        let is_leader = crate::cluster::leader::is_leader();
        let snapshots = crate::metrics::METRICS.take_snapshots();

        // Always refresh baselines so deltas are accurate when leadership
        // resumes — otherwise the first delta after becoming leader spans the
        // entire non-leader gap and produces a huge phantom bandwidth spike.
        if !is_leader {
            for snap_tuple in &snapshots {
                let snap = &snap_tuple.1;
                last_snapshots.insert(snap.server_id, snap.clone());
            }
            continue;
        }
        let now = crate::utils::time::now_local();
        let day = now.format("%Y%m%d").to_string();
        let minute_floor = (now.minute() / 5) * 5;
        let time_at = format!("{:02}{:02}", now.hour(), minute_floor);
        let window_started_at = now
            .with_second(0)
            .and_then(|dt| dt.with_minute(minute_floor))
            .map(|dt| dt.timestamp())
            .unwrap_or_else(|| now.timestamp());
        let window_key = format!("{}@{}", day, time_at);

        if current_window.is_empty() {
            current_window = window_key.clone();
        } else if current_window != window_key {
            let node_region_id = config_store.get_node_region_id().await;
            let now_ts = crate::utils::time::now_timestamp();
            pending_stats.retain(|item| now_ts - item.queued_at <= STAT_RETRY_RETENTION_SECS);
            let mut upload_items = std::mem::take(&mut pending_stats);
            upload_items.extend(window_stats.drain().map(|(_, stat)| {
                let bytes_per_sec = bandwidth_bytes_per_sec(&stat, &config_store);
                PendingBandwidthStat {
                    queued_at: window_started_at - BANDWIDTH_REPORT_INTERVAL_SECS as i64,
                    stat: pb::ServerBandwidthStat {
                        user_id: stat.user_id,
                        server_id: stat.server_id,
                        day: stat.day.clone(),
                        time_at: stat.time_at,
                        bytes: bytes_per_sec as i64,
                        bits: (bytes_per_sec * 8) as i64,
                        total_bytes: stat.total_bytes as i64,
                        cached_bytes: stat.cached_bytes.min(stat.total_bytes) as i64,
                        attack_bytes: stat.attack_bytes.min(stat.total_bytes) as i64,
                        count_requests: stat.count_requests as i64,
                        count_cached_requests: stat.count_cached_requests as i64,
                        count_attack_requests: stat.count_attack_requests as i64,
                        user_plan_id: stat.user_plan_id,
                        count_websocket_connections: stat.count_websocket_connections as i64,
                        origin_total_bytes: stat.origin_total_bytes as i64,
                        origin_avg_bytes: stat.origin_avg_bytes as i64,
                        origin_avg_bits: stat.origin_avg_bits as i64,
                        count_i_ps: crate::metrics::daily::UNIQUE_IP_TRACKER
                            .count(stat.server_id, &stat.day),
                        node_region_id,
                        ..Default::default()
                    },
                }
            }));
            if !upload_items.is_empty() {
                let stats: Vec<_> = upload_items.iter().map(|item| item.stat.clone()).collect();
                let client = match SharedRpcClient::get(&api_config).await {
                    Ok(shared) => shared.as_rpc_client(),
                    Err(e) => {
                        warn!("Bandwidth reporter failed to connect: {}", e);
                        pending_stats = upload_items;
                        current_window = window_key;
                        persist_bandwidth_state(
                            &current_window,
                            &window_stats,
                            pending_stats.as_slice(),
                        );
                        continue;
                    }
                };
                let mut service = client.bandwidth_stat_service();
                let result = crate::rpc::track_rpc(service.upload_server_bandwidth_stats(
                    pb::UploadServerBandwidthStatsRequest {
                        server_bandwidth_stats: stats,
                    },
                ))
                .await;
                if let Err(e) = result {
                    warn!("Failed to upload bandwidth stats: {}", e);
                    pending_stats = upload_items;
                } else {
                    pending_stats.clear();
                }
                persist_bandwidth_state(&current_window, &window_stats, pending_stats.as_slice());
            }
            current_window = window_key.clone();
            persist_bandwidth_state(&current_window, &window_stats, pending_stats.as_slice());
        }

        for snap_tuple in snapshots {
            let snap = &snap_tuple.1;
            let prior = last_snapshots.insert(snap.server_id, snap.clone());
            // Skip first sample for a server — without a baseline the delta
            // would be the cumulative total, producing a phantom bandwidth spike.
            if prior.is_none() {
                continue;
            }
            let delta = snapshot_delta(snap, prior.as_ref());
            if delta.server_id <= 0 {
                continue;
            }

            let origin_total_bytes = delta.origin_bytes_received + delta.origin_bytes_sent;
            let billable_bytes = billable_bytes(&delta, &api_config);
            let peak_bytes_per_sec = billable_bytes / BANDWIDTH_SAMPLE_INTERVAL_SECS;
            let stat = window_stats
                .entry(delta.server_id)
                .or_insert_with(|| BandwidthWindowStat {
                    day: day.clone(),
                    time_at: time_at.clone(),
                    user_id: delta.user_id,
                    server_id: delta.server_id,
                    user_plan_id: delta.user_plan_id,
                    ..Default::default()
                });
            stat.user_id = delta.user_id;
            stat.user_plan_id = delta.user_plan_id;
            stat.peak_bytes_per_sec = stat.peak_bytes_per_sec.max(peak_bytes_per_sec);
            stat.total_bytes += billable_bytes;
            stat.cached_bytes += delta.cached_bytes;
            stat.attack_bytes += delta.attack_bytes;
            stat.count_requests += delta.total_requests;
            stat.count_cached_requests += delta.count_cached_requests;
            stat.count_attack_requests += delta.count_attack_requests;
            stat.count_websocket_connections += delta.count_websocket_connections;
            stat.origin_total_bytes += origin_total_bytes;
            stat.origin_avg_bytes = stat.origin_total_bytes / BANDWIDTH_REPORT_INTERVAL_SECS;
            stat.origin_avg_bits = (stat.origin_total_bytes * 8) / BANDWIDTH_REPORT_INTERVAL_SECS;
            stat.count_ips = stat.count_ips.max(delta.count_ips);
        }
        persist_bandwidth_state(&current_window, &window_stats, pending_stats.as_slice());
    }
}

pub async fn start_daily_stat_reporter(config_store: ConfigStore, api_config: ApiConfig) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
        BANDWIDTH_SAMPLE_INTERVAL_SECS,
    ));
    let mut last_snapshots: HashMap<i64, ServerStatusSnapshot> = HashMap::new();
    let mut current_window = String::new();
    let mut window_stats: HashMap<i64, pb::ServerDailyStat> = HashMap::new();
    let mut pending_stats: Vec<pb::ServerDailyStat> = Vec::new();
    let mut pending_domain_stats: Vec<pb::upload_server_daily_stats_request::DomainStat> =
        Vec::new();

    loop {
        interval.tick().await;
        let is_leader = crate::cluster::leader::is_leader();
        let snapshots = crate::metrics::METRICS.take_snapshots();

        // Keep baselines fresh even when not leader so that deltas are
        // accurate when leadership resumes.
        if !is_leader {
            for snap_tuple in &snapshots {
                let snap = &snap_tuple.1;
                last_snapshots.insert(snap.server_id, snap.clone());
            }
            continue;
        }
        let now = crate::utils::time::now_local();
        let day = now.format("%Y%m%d").to_string();
        let minute_floor = (now.minute() / 5) * 5;
        let time_from = format!("{:02}{:02}", now.hour(), minute_floor);
        let created_at = now
            .with_second(0)
            .and_then(|dt| dt.with_minute(minute_floor))
            .map(|dt| dt.timestamp())
            .unwrap_or_else(|| now.timestamp());
        let node_region_id = config_store.get_node_region_id().await;
        let window_key = format!("{}@{}", day, time_from);

        if current_window.is_empty() {
            current_window = window_key.clone();
        } else if current_window != window_key {
            let min_day = (now - ChronoDuration::days(2)).format("%Y%m%d").to_string();
            crate::metrics::daily::UNIQUE_IP_TRACKER.cleanup_before(&min_day);

            let now_ts = crate::utils::time::now_timestamp();
            pending_stats.retain(|item| now_ts - item.created_at <= STAT_RETRY_RETENTION_SECS);
            pending_domain_stats
                .retain(|item| now_ts - item.created_at <= STAT_RETRY_RETENTION_SECS);

            let mut stats: Vec<_> = std::mem::take(&mut pending_stats);
            stats.extend(window_stats.drain().map(|(_, mut stat)| {
                stat.cached_bytes = stat.cached_bytes.min(stat.bytes);
                stat.attack_bytes = stat.attack_bytes.min(stat.bytes);
                stat
            }));

            let mut domain_stats = std::mem::take(&mut pending_domain_stats);
            let mut domain_rows = crate::metrics::daily::DAILY_DOMAIN_TRACKER
                .flush_older_than(created_at)
                .into_iter()
                .map(|(server_id, created_at, domain, mut value)| {
                    value.cached_bytes = value.cached_bytes.min(value.bytes);
                    value.attack_bytes = value.attack_bytes.min(value.bytes);
                    pb::upload_server_daily_stats_request::DomainStat {
                        server_id,
                        domain,
                        bytes: value.bytes,
                        cached_bytes: value.cached_bytes,
                        count_requests: value.count_requests,
                        count_cached_requests: value.count_cached_requests,
                        count_attack_requests: value.count_attack_requests,
                        attack_bytes: value.attack_bytes,
                        created_at,
                    }
                })
                .collect::<Vec<_>>();
            domain_rows.sort_by(|a, b| {
                a.server_id
                    .cmp(&b.server_id)
                    .then_with(|| b.count_requests.cmp(&a.count_requests))
            });
            let mut per_server_counts: HashMap<i64, usize> = HashMap::new();
            for item in domain_rows {
                let count = per_server_counts.entry(item.server_id).or_default();
                if *count < 20 {
                    domain_stats.push(item);
                    *count += 1;
                }
            }

            if !stats.is_empty() || !domain_stats.is_empty() {
                let client = match SharedRpcClient::get(&api_config).await {
                    Ok(shared) => shared.as_rpc_client(),
                    Err(e) => {
                        warn!("Daily stat reporter failed to connect: {}", e);
                        pending_stats = stats;
                        pending_domain_stats = domain_stats;
                        current_window = window_key;
                        continue;
                    }
                };
                let mut service = client.daily_stat_service();

                if let Err(e) = crate::rpc::track_rpc(service.upload_server_daily_stats(
                    pb::UploadServerDailyStatsRequest {
                        stats: stats.clone(),
                        domain_stats: domain_stats.clone(),
                    },
                ))
                .await
                {
                    warn!("Failed to upload daily stats: {}", e);
                    pending_stats = stats;
                    pending_domain_stats = domain_stats;
                } else {
                    pending_stats.clear();
                    pending_domain_stats.clear();
                }
            }
            current_window = window_key.clone();
        }

        for snap_tuple in snapshots {
            let snap = &snap_tuple.1;
            let prior = last_snapshots.insert(snap.server_id, snap.clone());
            // Skip first sample for a server — without a baseline the delta
            // would be the cumulative total, producing phantom traffic.
            if prior.is_none() {
                continue;
            }
            let delta = snapshot_delta(snap, prior.as_ref());
            if delta.server_id <= 0 {
                continue;
            }

            let check_traffic_limiting = config_store
                .get_server_by_id(delta.server_id)
                .await
                .map(|server| server.has_valid_traffic_limit())
                .unwrap_or(false);

            let stat = window_stats
                .entry(delta.server_id)
                .or_insert_with(|| pb::ServerDailyStat {
                    server_id: delta.server_id,
                    user_id: delta.user_id,
                    node_region_id,
                    created_at,
                    check_traffic_limiting,
                    plan_id: delta.plan_id,
                    ..Default::default()
                });
            stat.user_id = delta.user_id;
            stat.node_region_id = node_region_id;
            stat.created_at = created_at;
            stat.check_traffic_limiting = check_traffic_limiting;
            stat.plan_id = delta.plan_id;
            stat.bytes += billable_bytes(&delta, &api_config) as i64;
            stat.cached_bytes += delta.cached_bytes as i64;
            stat.count_requests += delta.total_requests as i64;
            stat.count_cached_requests += delta.count_cached_requests as i64;
            stat.count_attack_requests += delta.count_attack_requests as i64;
            stat.attack_bytes += delta.attack_bytes as i64;
        }
    }
}

fn get_period_time(period: i32, unit: &str) -> String {
    let now = crate::utils::time::now_local();
    match unit.to_lowercase().as_str() {
        "month" => now.format("%Y%m").to_string(),
        "week" => {
            let week = now.iso_week();
            format!("{:04}{:02}", week.year(), week.week())
        }
        "day" => now.format("%Y%m%d").to_string(),
        "hour" => {
            if period > 1 {
                let hour = (now.hour() as i32 / period) * period;
                format!("{}{:02}", now.format("%Y%m%d"), hour)
            } else {
                now.format("%Y%m%d%H").to_string()
            }
        }
        "minute" => {
            if period > 1 {
                let minute = (now.minute() as i32 / period) * period;
                format!("{}{:02}", now.format("%Y%m%d%H"), minute)
            } else {
                now.format("%Y%m%d%H%M").to_string()
            }
        }
        _ => now.format("%Y%m%d%H%M").to_string(),
    }
}

fn metric_item_category(item: &crate::config_models::MetricItemConfig) -> String {
    crate::metrics::normalize_metric_category(&item.category)
}

fn sample_matches_metric_category(
    sample: &(
        crate::metrics::aggregator::AggregationKey,
        crate::metrics::aggregator::AggregatedValue,
    ),
    category: &str,
) -> bool {
    sample.0.category.as_ref() == category
}

fn metric_sample_value(
    item_value: &serde_json::Value,
    value: &crate::metrics::aggregator::AggregatedRequestValue,
) -> f32 {
    match item_value.as_str() {
        Some("${bytesSent}") | Some("${countTrafficOut}") => value.bytes_sent as f32,
        Some("${countTrafficIn}") => value.bytes_received as f32,
        Some("${countRequest}") => value.count as f32,
        Some("${countConnection}") => value.count as f32,
        Some("${countAttackRequest}") => value.count_attack as f32,
        _ => value.count as f32,
    }
}

fn build_metric_uploads_for_item(
    item: &crate::config_models::MetricItemConfig,
    time_key: &str,
    samples: &[(
        crate::metrics::aggregator::AggregationKey,
        crate::metrics::aggregator::AggregatedValue,
    )],
    values_cache: &mut HashMap<String, f32>,
) -> Vec<pb::UploadMetricStatsRequest> {
    let item_category = metric_item_category(item);
    let mut grouped: HashMap<(i64, Vec<String>), (i64, f32)> = HashMap::new();

    for (key, value) in samples
        .iter()
        .filter(|sample| sample_matches_metric_category(sample, &item_category))
    {
        if value.request_samples.is_empty() {
            let aggregate_value = crate::metrics::aggregator::AggregatedRequestValue {
                count: value.count,
                count_attack: value.count_attack,
                bytes_sent: value.bytes_sent,
                bytes_received: value.bytes_received,
                attack_bytes: value.attack_bytes,
            };
            let keys = item
                .keys
                .iter()
                .map(|configured_key| key.resolve_metric_key(configured_key))
                .collect::<Vec<_>>();
            let entry = grouped.entry((key.server_id, keys)).or_default();
            entry.0 += aggregate_value.count;
            entry.1 += metric_sample_value(&item.value, &aggregate_value);
            continue;
        }

        for (request_attrs, request_value) in &value.request_samples {
            let keys = item
                .keys
                .iter()
                .map(|configured_key| {
                    key.resolve_metric_key_with_attrs(configured_key, request_attrs.as_ref())
                })
                .collect::<Vec<_>>();
            let entry = grouped.entry((key.server_id, keys)).or_default();
            entry.0 += request_value.count;
            entry.1 += metric_sample_value(&item.value, request_value);
        }
    }

    let mut by_server: HashMap<i64, Vec<(Vec<String>, i64, f32)>> = HashMap::new();
    for ((server_id, keys), (count, value)) in grouped {
        by_server
            .entry(server_id)
            .or_default()
            .push((keys, count, value));
    }

    let mut requests = Vec::with_capacity(by_server.len());
    for (server_id, mut rows) in by_server {
        rows.sort_by(|a, b| a.0.cmp(&b.0));

        let mut metric_stats = Vec::with_capacity(rows.len());
        let mut keep_keys = Vec::new();
        let mut count = 0i64;
        let mut total = 0f32;

        for (keys, row_count, value) in rows {
            count += row_count;
            total += value;

            // GO ALGORITHM: hashString(serverId + "@" + keys.join("$EDGE$") + "@" + time + "@" + version + "@" + itemId)
            let keys_data = keys.join("$EDGE$");
            let hash_raw = format!(
                "{}@{}@{}@{}@{}",
                server_id, keys_data, time_key, item.version, item.id
            );
            let hash = crate::utils::fnv_hash64(&hash_raw).to_string();

            let cache_key = format!("{}_{}", item.id, hash);
            if let Some(&old_val) = values_cache.get(&cache_key)
                && (value - old_val).abs() < 0.001
            {
                keep_keys.push(hash);
                continue;
            }

            values_cache.insert(cache_key, value);

            metric_stats.push(pb::UploadingMetricStat {
                id: 0,
                hash,
                keys,
                value,
            });
        }

        requests.push(pb::UploadMetricStatsRequest {
            server_id,
            time: time_key.to_string(),
            count,
            total,
            version: item.version,
            item_id: item.id,
            metric_stats,
            keep_keys,
        });
    }

    requests
}

pub async fn start_metric_stat_reporter(
    config_store: Arc<crate::config::ConfigStore>,
    api_config: ApiConfig,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    let mut values_cache: HashMap<String, f32> = HashMap::new();

    loop {
        interval.tick().await;
        if !crate::cluster::leader::require_leader("metric_stat_reporter") {
            continue;
        }
        let metric_items = config_store.get_metric_items().await;
        if metric_items.is_empty() {
            let _ = crate::metrics::aggregator::METRIC_STAT_AGGREGATOR.flush();
            continue;
        }

        let client = match SharedRpcClient::get(&api_config).await {
            Ok(shared) => shared.as_rpc_client(),
            Err(e) => {
                warn!("Metric stat reporter failed to connect: {}", e);
                continue;
            }
        };
        let mut service = client.metric_stat_service();

        let samples = crate::metrics::aggregator::METRIC_STAT_AGGREGATOR.flush();
        if samples.is_empty() {
            // Even if no new samples, we might still want to report if we have cached keys
            // But usually we skip
            continue;
        }

        for item in metric_items {
            if !item.is_on {
                continue;
            }
            let item_category = metric_item_category(&item);

            let time_key = get_period_time(item.period, &item.period_unit);
            if !samples
                .iter()
                .any(|sample| sample_matches_metric_category(sample, &item_category))
            {
                continue;
            }

            for req in build_metric_uploads_for_item(&item, &time_key, &samples, &mut values_cache)
            {
                let server_id = req.server_id;
                if let Err(e) = crate::rpc::track_rpc(service.upload_metric_stats(req)).await {
                    warn!(
                        "Failed to upload metric stats for server {} item {}: {}",
                        server_id, item.id, e
                    );
                }
            }
        }
    }
}

use std::sync::atomic::{AtomicBool, AtomicI32};

static LAST_NODE_LEVEL: AtomicI32 = AtomicI32::new(-1);
static LAST_HAS_PARENTS: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
struct HttpRequestStatUploadLimits {
    max_cities: usize,
    max_providers: usize,
    max_systems: usize,
    max_browsers: usize,
}

impl HttpRequestStatUploadLimits {
    fn from_config(config: &crate::config_models::GlobalStatUploadConfig) -> Self {
        Self {
            max_cities: positive_or_default(config.max_cities, 32),
            max_providers: positive_or_default(config.max_providers, 32),
            max_systems: positive_or_default(config.max_systems, 64),
            max_browsers: positive_or_default(config.max_browsers, 64),
        }
    }
}

fn positive_or_default(value: i16, default_value: usize) -> usize {
    if value > 0 {
        value as usize
    } else {
        default_value
    }
}

fn trim_http_request_stat_rows_with_limits(
    req: &mut pb::UploadServerHttpRequestStatRequest,
    limits: HttpRequestStatUploadLimits,
) {
    req.region_cities
        .sort_by(|a, b| b.count_requests.cmp(&a.count_requests));
    let mut server_counts = HashMap::<i64, usize>::new();
    req.region_cities.retain(|row| {
        let count = server_counts.entry(row.server_id).or_default();
        *count += 1;
        *count <= limits.max_cities
    });

    req.region_providers.sort_by(|a, b| b.count.cmp(&a.count));
    server_counts.clear();
    req.region_providers.retain(|row| {
        let count = server_counts.entry(row.server_id).or_default();
        *count += 1;
        *count <= limits.max_providers
    });

    req.systems.sort_by(|a, b| b.count.cmp(&a.count));
    server_counts.clear();
    req.systems.retain(|row| {
        let count = server_counts.entry(row.server_id).or_default();
        *count += 1;
        *count <= limits.max_systems
    });

    req.browsers.sort_by(|a, b| b.count.cmp(&a.count));
    server_counts.clear();
    req.browsers.retain(|row| {
        let count = server_counts.entry(row.server_id).or_default();
        *count += 1;
        *count <= limits.max_browsers
    });
}

pub async fn start_metrics_aggregator_reporter(config_store: ConfigStore, api_config: ApiConfig) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        interval.tick().await;
        if !crate::cluster::leader::require_leader("metrics_aggregator_reporter") {
            continue;
        }

        let client = match SharedRpcClient::get(&api_config).await {
            Ok(shared) => shared.as_rpc_client(),
            Err(e) => {
                warn!("Metrics aggregator reporter failed to connect: {}", e);
                continue;
            }
        };
        let mut node_service = client.node_service();
        let mut server_service = client.server_service();

        match node_service
            .find_node_level_info(pb::FindNodeLevelInfoRequest {})
            .await
        {
            Ok(resp) => {
                let info = resp.into_inner();
                let has_parents = !info.parent_nodes_map_json.is_empty();

                if info.level != LAST_NODE_LEVEL.load(Ordering::Relaxed)
                    || has_parents != LAST_HAS_PARENTS.load(Ordering::Relaxed)
                {
                    LAST_NODE_LEVEL.store(info.level, Ordering::Relaxed);
                    LAST_HAS_PARENTS.store(has_parents, Ordering::Relaxed);
                    info!(
                        "Node Level identified: {}, Parents: {}",
                        info.level, has_parents
                    );
                } else {
                    debug!(
                        "Node Level verified: {}, Parents: {}",
                        info.level, has_parents
                    );
                }
            }
            Err(e) => {
                warn!("Failed to fetch node level info: {}", e);
            }
        }

        let samples = crate::metrics::aggregator::HTTP_REQUEST_STAT_AGGREGATOR.flush();

        if samples.is_empty() {
            continue;
        }

        let now = crate::utils::time::now_local();
        let month = now.format("%Y%m").to_string();
        let day = now.format("%Y%m%d").to_string();

        let mut req = pb::UploadServerHttpRequestStatRequest {
            month,
            day,
            region_cities: vec![],
            region_providers: vec![],
            systems: vec![],
            browsers: vec![],
            http_firewall_rule_groups: vec![],
        };

        let mut city_map: HashMap<(i64, i64, i64, i64), (i64, i64, i64, i64)> = HashMap::new();
        let mut provider_map: HashMap<(i64, i64), i64> = HashMap::new();
        let mut system_map: HashMap<(i64, String, String), i64> = HashMap::new();
        let mut browser_map: HashMap<(i64, String, String), i64> = HashMap::new();
        let mut waf_map: HashMap<(i64, i64, String), i64> = HashMap::new();

        for (key, val) in samples {
            if key.country_id > 0 {
                let entry = city_map
                    .entry((key.server_id, key.country_id, key.province_id, key.city_id))
                    .or_default();
                entry.0 += val.count;
                entry.1 += val.bytes_sent;
                entry.2 += val.count_attack;
                entry.3 += val.attack_bytes;
            }

            if key.provider_id > 0 {
                *provider_map
                    .entry((key.server_id, key.provider_id))
                    .or_default() += val.count;
            }

            if !key.os.is_empty() {
                *system_map
                    .entry((
                        key.server_id,
                        key.os.to_string(),
                        key.os_version.to_string(),
                    ))
                    .or_default() += val.count;
            }

            if !key.browser.is_empty() {
                *browser_map
                    .entry((
                        key.server_id,
                        key.browser.to_string(),
                        key.browser_version.to_string(),
                    ))
                    .or_default() += val.count;
            }

            if key.waf_group_id > 0 && val.count_attack > 0 {
                *waf_map
                    .entry((key.server_id, key.waf_group_id, key.waf_action.to_string()))
                    .or_default() += val.count_attack;
            }
        }

        for ((server_id, country_id, province_id, city_id), value) in city_map {
            req.region_cities
                .push(pb::upload_server_http_request_stat_request::RegionCity {
                    server_id,
                    count_requests: value.0,
                    bytes: value.1,
                    count_attack_requests: value.2,
                    attack_bytes: value.3,
                    region_country_id: country_id,
                    region_province_id: province_id,
                    region_city_id: city_id,
                });
        }

        for ((server_id, provider_id), count) in provider_map {
            req.region_providers.push(
                pb::upload_server_http_request_stat_request::RegionProvider {
                    server_id,
                    count,
                    region_provider_id: provider_id,
                },
            );
        }

        for ((server_id, name, version), count) in system_map {
            req.systems
                .push(pb::upload_server_http_request_stat_request::System {
                    server_id,
                    name,
                    version,
                    count,
                });
        }

        for ((server_id, name, version), count) in browser_map {
            req.browsers
                .push(pb::upload_server_http_request_stat_request::Browser {
                    server_id,
                    name,
                    version,
                    count,
                });
        }

        for ((server_id, waf_group_id, action), count) in waf_map {
            req.http_firewall_rule_groups.push(
                pb::upload_server_http_request_stat_request::HttpFirewallRuleGroup {
                    server_id,
                    http_firewall_rule_group_id: waf_group_id,
                    action,
                    count,
                },
            );
        }

        let upload_limits =
            HttpRequestStatUploadLimits::from_config(&config_store.get_global_stat_upload_sync());
        trim_http_request_stat_rows_with_limits(&mut req, upload_limits);

        if let Err(e) =
            crate::rpc::track_rpc(server_service.upload_server_http_request_stat(req)).await
        {
            warn!("Failed to upload HTTP request stats: {}", e);
        }
    }
}

pub async fn start_top_ip_stat_reporter(api_config: ApiConfig) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));

    loop {
        interval.tick().await;
        if !crate::cluster::leader::require_leader("top_ip_stat_reporter") {
            continue;
        }
        let rows = crate::metrics::top_ip::TOP_IP_TRACKER.flush();
        if rows.is_empty() {
            continue;
        }

        let client = match SharedRpcClient::get(&api_config).await {
            Ok(shared) => shared.as_rpc_client(),
            Err(e) => {
                warn!("Top IP stat reporter failed to connect: {}", e);
                continue;
            }
        };
        let mut service = client.server_top_ip_stat_service();

        let now = crate::utils::time::now_local();
        let day = now.format("%Y%m%d").to_string();
        let minute_floor = (now.minute() / 5) * 5;
        let time_at = format!("{:02}{:02}", now.hour(), minute_floor);

        let stats = rows
            .into_iter()
            .map(
                |(server_id, ip, count_requests)| pb::upload_server_top_ip_stats_request::Stat {
                    server_id: server_id as u64,
                    ip,
                    // u64 → u32 silent wraparound at 4.3B would mask runaway IPs;
                    // saturate to u32::MAX so the upper bound stays visible.
                    count_requests: u32::try_from(count_requests).unwrap_or(u32::MAX),
                    day: day.clone(),
                    time_at: time_at.clone(),
                },
            )
            .collect();

        if let Err(e) = crate::rpc::track_rpc(
            service.upload_server_top_ip_stats(pb::UploadServerTopIpStatsRequest { stats }),
        )
        .await
        {
            warn!("Failed to upload top IP stats: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metric_key_with_attrs(
        request_attrs: std::collections::BTreeMap<String, String>,
    ) -> crate::metrics::aggregator::AggregationKey {
        crate::metrics::aggregator::AggregationKey {
            category: std::sync::Arc::from(crate::metrics::METRIC_CATEGORY_HTTP),
            server_id: 1,
            country: std::sync::Arc::from(""),
            country_id: 0,
            province: std::sync::Arc::from(""),
            province_id: 0,
            city: std::sync::Arc::from(""),
            city_id: 0,
            provider: std::sync::Arc::from("Unknown"),
            browser: std::sync::Arc::from(""),
            os: std::sync::Arc::from(""),
            waf_group_id: 0,
            waf_action: std::sync::Arc::from(""),
            provider_id: 0,
            browser_version: std::sync::Arc::from(""),
            os_version: std::sync::Arc::from(""),
            request_attrs: std::sync::Arc::new(request_attrs),
        }
    }

    fn metric_item(
        id: i64,
        keys: Vec<&str>,
        value: &str,
    ) -> crate::config_models::MetricItemConfig {
        crate::config_models::MetricItemConfig {
            id,
            name: String::new(),
            code: String::new(),
            category: crate::metrics::METRIC_CATEGORY_HTTP.to_string(),
            keys: keys.into_iter().map(str::to_string).collect(),
            value: serde_json::Value::String(value.to_string()),
            period: 1,
            period_unit: "minute".to_string(),
            version: 1,
            is_on: true,
        }
    }

    #[test]
    fn metric_stat_upload_groups_request_count_by_resolved_ip() {
        let aggregator = crate::metrics::aggregator::MetricAggregator::with_request_samples(true);
        for request_id in ["a", "b"] {
            let mut attrs = std::collections::BTreeMap::new();
            attrs.insert("remoteAddr".to_string(), "203.0.113.9".to_string());
            attrs.insert("requestId".to_string(), request_id.to_string());
            attrs.insert(
                "requestURI".to_string(),
                format!("/index.html?rid={request_id}"),
            );
            aggregator.record(metric_key_with_attrs(attrs), 100, 10, false);
        }

        let samples = aggregator.flush();
        assert_eq!(samples.len(), 1);

        let item = metric_item(10, vec!["${remoteAddr}"], "${countRequest}");
        let mut cache = HashMap::new();
        let uploads = build_metric_uploads_for_item(&item, "202606221200", &samples, &mut cache);

        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].count, 2);
        assert_eq!(uploads[0].total, 2.0);
        assert_eq!(uploads[0].metric_stats.len(), 1);
        assert_eq!(uploads[0].metric_stats[0].keys, vec!["203.0.113.9"]);
        assert_eq!(uploads[0].metric_stats[0].value, 2.0);
    }

    #[test]
    fn metric_stat_upload_groups_paths_and_sums_bytes() {
        let aggregator = crate::metrics::aggregator::MetricAggregator::with_request_samples(true);
        for (request_id, bytes_sent) in [("a", 123), ("b", 456)] {
            let mut attrs = std::collections::BTreeMap::new();
            attrs.insert("remoteAddr".to_string(), "203.0.113.9".to_string());
            attrs.insert("requestId".to_string(), request_id.to_string());
            attrs.insert(
                "requestURI".to_string(),
                format!("/assets/app.js?rid={request_id}"),
            );
            attrs.insert("requestPath".to_string(), "/assets/app.js".to_string());
            aggregator.record(metric_key_with_attrs(attrs), bytes_sent, 10, false);
        }

        let samples = aggregator.flush();
        let item = metric_item(11, vec!["${requestPath}"], "${countTrafficOut}");
        let mut cache = HashMap::new();
        let uploads = build_metric_uploads_for_item(&item, "202606221200", &samples, &mut cache);

        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].count, 2);
        assert_eq!(uploads[0].total, 579.0);
        assert_eq!(uploads[0].metric_stats.len(), 1);
        assert_eq!(uploads[0].metric_stats[0].keys, vec!["/assets/app.js"]);
        assert_eq!(uploads[0].metric_stats[0].value, 579.0);
    }

    #[test]
    fn metric_stat_upload_resolves_method_aliases() {
        let aggregator = crate::metrics::aggregator::MetricAggregator::with_request_samples(true);
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert("requestMethod".to_string(), "POST".to_string());
        attrs.insert("requestPath".to_string(), "/submit".to_string());
        attrs.insert("requestURI".to_string(), "/submit?x=1".to_string());
        aggregator.record(metric_key_with_attrs(attrs), 10, 100, false);

        let samples = aggregator.flush();
        let item = metric_item(
            12,
            vec!["${requestMethod}", "${method}", "${request.method}"],
            "${countRequest}",
        );
        let mut cache = HashMap::new();
        let uploads = build_metric_uploads_for_item(&item, "202606221200", &samples, &mut cache);

        assert_eq!(uploads.len(), 1);
        assert_eq!(
            uploads[0].metric_stats[0].keys,
            vec!["POST", "POST", "POST"]
        );
        assert_eq!(uploads[0].metric_stats[0].value, 1.0);
    }

    #[test]
    fn trims_http_request_dimension_rows_per_server() {
        let mut req = pb::UploadServerHttpRequestStatRequest::default();
        for count in [10, 30, 20] {
            req.region_cities
                .push(pb::upload_server_http_request_stat_request::RegionCity {
                    server_id: 1,
                    region_city_id: count,
                    count_requests: count,
                    ..Default::default()
                });
            req.region_providers.push(
                pb::upload_server_http_request_stat_request::RegionProvider {
                    server_id: 1,
                    region_provider_id: count,
                    count,
                },
            );
            req.systems
                .push(pb::upload_server_http_request_stat_request::System {
                    server_id: 1,
                    name: format!("os-{count}"),
                    count,
                    ..Default::default()
                });
            req.browsers
                .push(pb::upload_server_http_request_stat_request::Browser {
                    server_id: 1,
                    name: format!("browser-{count}"),
                    count,
                    ..Default::default()
                });
        }
        req.region_cities
            .push(pb::upload_server_http_request_stat_request::RegionCity {
                server_id: 2,
                region_city_id: 5,
                count_requests: 5,
                ..Default::default()
            });

        trim_http_request_stat_rows_with_limits(
            &mut req,
            HttpRequestStatUploadLimits {
                max_cities: 2,
                max_providers: 2,
                max_systems: 2,
                max_browsers: 2,
            },
        );

        assert_eq!(
            req.region_cities
                .iter()
                .filter(|row| row.server_id == 1)
                .map(|row| row.region_city_id)
                .collect::<Vec<_>>(),
            vec![30, 20]
        );
        assert_eq!(
            req.region_cities
                .iter()
                .filter(|row| row.server_id == 2)
                .count(),
            1
        );
        assert_eq!(req.region_providers.len(), 2);
        assert_eq!(req.systems.len(), 2);
        assert_eq!(req.browsers.len(), 2);
    }

    #[test]
    fn bandwidth_pending_stat_round_trips_storage_shape() {
        let pending = PendingBandwidthStat {
            queued_at: 123,
            stat: pb::ServerBandwidthStat {
                user_id: 1,
                server_id: 2,
                day: "20260621".to_string(),
                time_at: "1200".to_string(),
                bytes: 3,
                bits: 24,
                total_bytes: 4,
                cached_bytes: 5,
                attack_bytes: 6,
                count_requests: 7,
                count_cached_requests: 8,
                count_attack_requests: 9,
                user_plan_id: 10,
                count_websocket_connections: 11,
                origin_total_bytes: 12,
                origin_avg_bytes: 13,
                origin_avg_bits: 14,
                count_i_ps: 15,
                node_region_id: 16,
                ..Default::default()
            },
        };

        let restored = PendingBandwidthStat::from(StoredPendingBandwidthStat::from(&pending));

        assert_eq!(restored.queued_at, pending.queued_at);
        assert_eq!(restored.stat.server_id, pending.stat.server_id);
        assert_eq!(restored.stat.total_bytes, pending.stat.total_bytes);
        assert_eq!(restored.stat.count_i_ps, pending.stat.count_i_ps);
        assert_eq!(restored.stat.node_region_id, pending.stat.node_region_id);
    }

    #[test]
    fn metric_stat_category_filter_excludes_tcp_rows_from_http_items() {
        fn sample(
            category: &str,
        ) -> (
            crate::metrics::aggregator::AggregationKey,
            crate::metrics::aggregator::AggregatedValue,
        ) {
            (
                crate::metrics::aggregator::AggregationKey {
                    category: std::sync::Arc::from(category),
                    server_id: 1,
                    country: std::sync::Arc::from(""),
                    country_id: 0,
                    province: std::sync::Arc::from(""),
                    province_id: 0,
                    city: std::sync::Arc::from(""),
                    city_id: 0,
                    provider: std::sync::Arc::from("Unknown"),
                    browser: std::sync::Arc::from(""),
                    os: std::sync::Arc::from(""),
                    waf_group_id: 0,
                    waf_action: std::sync::Arc::from(""),
                    provider_id: 0,
                    browser_version: std::sync::Arc::from(""),
                    os_version: std::sync::Arc::from(""),
                    request_attrs: std::sync::Arc::new(std::collections::BTreeMap::new()),
                },
                crate::metrics::aggregator::AggregatedValue {
                    count: 1,
                    ..Default::default()
                },
            )
        }

        let samples = vec![
            sample(crate::metrics::METRIC_CATEGORY_HTTP),
            sample(crate::metrics::METRIC_CATEGORY_TCP),
        ];
        let http_category = crate::metrics::METRIC_CATEGORY_HTTP.to_string();

        let matching = samples
            .iter()
            .filter(|sample| sample_matches_metric_category(sample, &http_category))
            .count();

        assert_eq!(matching, 1);
        assert!(sample_matches_metric_category(&samples[0], &http_category));
        assert!(!sample_matches_metric_category(&samples[1], &http_category));
    }
}
