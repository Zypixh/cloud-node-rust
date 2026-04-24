use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::pb;
use crate::rpc::client::RpcClient;
use crate::metrics::ServerStatusSnapshot;
use chrono::Timelike;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info};

const BANDWIDTH_REPORT_INTERVAL_SECS: u64 = 300;

fn snapshot_delta(current: &ServerStatusSnapshot, last: Option<&ServerStatusSnapshot>) -> ServerStatusSnapshot {
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

pub async fn start_bandwidth_reporter(api_config: ApiConfig) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(BANDWIDTH_REPORT_INTERVAL_SECS));
    let mut last_snapshots: HashMap<i64, ServerStatusSnapshot> = HashMap::new();

    loop {
        interval.tick().await;
        let snapshots = crate::metrics::METRICS.take_snapshots();
        if snapshots.is_empty() {
            continue;
        }

        let now = chrono::Local::now();
        let day = now.format("%Y%m%d").to_string();
        let minute_floor = (now.minute() / 5) * 5;
        let time_at = format!("{:02}{:02}", now.hour(), minute_floor);

        let mut stats = vec![];
        for snap in snapshots {
            let delta = snapshot_delta(&snap, last_snapshots.get(&snap.server_id));
            last_snapshots.insert(snap.server_id, snap);

            let origin_total_bytes = delta.origin_bytes_received + delta.origin_bytes_sent;
            let avg_bits = ((delta.bytes_sent * 8) / BANDWIDTH_REPORT_INTERVAL_SECS) as i64;
            let origin_avg_bytes = (origin_total_bytes / BANDWIDTH_REPORT_INTERVAL_SECS) as i64;
            let origin_avg_bits = ((origin_total_bytes * 8) / BANDWIDTH_REPORT_INTERVAL_SECS) as i64;
            stats.push(pb::ServerBandwidthStat {
                user_id: delta.user_id,
                server_id: delta.server_id,
                day: day.clone(),
                time_at: time_at.clone(),
                bytes: delta.bytes_sent as i64,
                bits: avg_bits,
                total_bytes: delta.total_bytes() as i64,
                cached_bytes: delta.cached_bytes as i64,
                attack_bytes: delta.attack_bytes as i64,
                count_requests: delta.total_requests as i64,
                count_cached_requests: delta.count_cached_requests as i64,
                count_attack_requests: delta.count_attack_requests as i64,
                user_plan_id: delta.user_plan_id,
                count_websocket_connections: delta.count_websocket_connections as i64,
                origin_total_bytes: origin_total_bytes as i64,
                origin_avg_bytes,
                origin_avg_bits,
                count_i_ps: delta.count_ips as i64,
                ..Default::default()
            });
            // Clear UV set after reporting
            if let Some(m) = crate::metrics::METRICS.servers.get(&delta.server_id) {
                m.clear_ips();
            }
        }

        let req = pb::UploadServerBandwidthStatsRequest {
            server_bandwidth_stats: stats,
        };
        let client = match RpcClient::new(&api_config).await {
            Ok(c) => c,
            Err(e) => {
                error!("Bandwidth reporter failed to connect: {}", e);
                continue;
            }
        };
        let mut service = client.bandwidth_stat_service();
        let start = std::time::Instant::now();
        let result = service.upload_server_bandwidth_stats(req).await;
        let cost = start.elapsed().as_millis() as u64;
        crate::metrics::record::record_rpc_call(result.is_ok(), cost);

        if let Err(e) = result {
            error!("Failed to upload bandwidth stats: {}", e);
        }
    }
}

pub async fn start_daily_stat_reporter(config_store: ConfigStore, api_config: ApiConfig) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(BANDWIDTH_REPORT_INTERVAL_SECS));
    let mut last_snapshots: HashMap<i64, ServerStatusSnapshot> = HashMap::new();

    loop {
        interval.tick().await;
        let snapshots = crate::metrics::METRICS.take_snapshots();
        if snapshots.is_empty() {
            continue;
        }

        let now = chrono::Local::now();
        let created_at = now.timestamp();
        let day = now.format("%Y%m%d").to_string();
        let hour = now.format("%H").to_string();
        let minute_floor = (now.minute() / 5) * 5;
        let time_from = format!("{:02}{:02}", now.hour(), minute_floor);
        let time_to = format!("{:02}{:02}", now.hour(), (minute_floor + 4).min(59));

        let mut stats = Vec::with_capacity(snapshots.len());
        for snap in snapshots {
            let delta = snapshot_delta(&snap, last_snapshots.get(&snap.server_id));
            last_snapshots.insert(snap.server_id, snap);
            let check_traffic_limiting = config_store
                .get_server_by_id(delta.server_id)
                .await
                .map(|server| server.has_valid_traffic_limit())
                .unwrap_or(false);

            stats.push(pb::ServerDailyStat {
                server_id: delta.server_id,
                user_id: delta.user_id,
                bytes: (delta.bytes_sent + delta.origin_bytes_sent + delta.origin_bytes_received)
                    as i64,
                cached_bytes: delta.cached_bytes as i64,
                count_requests: delta.total_requests as i64,
                count_cached_requests: delta.count_cached_requests as i64,
                created_at,
                count_attack_requests: delta.count_attack_requests as i64,
                attack_bytes: delta.attack_bytes as i64,
                check_traffic_limiting,
                plan_id: delta.plan_id,
                day: day.clone(),
                hour: hour.clone(),
                time_from: time_from.clone(),
                time_to: time_to.clone(),
                count_i_ps: delta.count_ips as i64,
                ..Default::default()
            });
        }

        let client = match RpcClient::new(&api_config).await {
            Ok(c) => c,
            Err(e) => {
                error!("Daily stat reporter failed to connect: {}", e);
                continue;
            }
        };
        let mut service = client.daily_stat_service();

        if let Err(e) = service
            .upload_server_daily_stats(pb::UploadServerDailyStatsRequest {
                stats,
                domain_stats: vec![],
            })
            .await
        {
            error!("Failed to upload daily stats: {}", e);
        }
    }
}

fn get_period_time(period: i32, unit: &str) -> String {
    let now = chrono::Local::now();
    match unit.to_lowercase().as_str() {
        "month" => now.format("%Y%m").to_string(),
        "week" => now.format("%Y%U").to_string(), // Approximation of YYYYWW
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

pub async fn start_metric_stat_reporter(
    config_store: Arc<crate::config::ConfigStore>,
    api_config: ApiConfig,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    let mut values_cache: HashMap<String, f32> = HashMap::new();

    loop {
        interval.tick().await;
        let metric_items = config_store.get_metric_items().await;
        if metric_items.is_empty() {
            continue;
        }

        let samples = crate::metrics::aggregator::AGGREGATOR.flush();
        if samples.is_empty() {
            // Even if no new samples, we might still want to report if we have cached keys
            // But usually we skip
            continue;
        }

        let client = match RpcClient::new(&api_config).await {
            Ok(c) => c,
            Err(e) => {
                error!("Metric stat reporter failed to connect: {}", e);
                continue;
            }
        };
        let mut service = client.metric_stat_service();

        for item in metric_items {
            if !item.is_on {
                continue;
            }

            let time_key = get_period_time(item.period, &item.period_unit);

            // Group samples by server_id
            let mut by_server: HashMap<
                i64,
                Vec<(
                    crate::metrics::aggregator::AggregationKey,
                    crate::metrics::aggregator::AggregatedValue,
                )>,
            > = HashMap::new();
            for sample in &samples {
                by_server
                    .entry(sample.0.server_id)
                    .or_default()
                    .push(sample.clone());
            }

            for (server_id, rows) in by_server {
                let mut metric_stats = Vec::with_capacity(rows.len());
                let mut keep_keys = Vec::new();
                let mut count = 0i64;
                let mut total = 0f32;

                for (key, value) in rows {
                    count += value.count;

                    let val = match item.value.as_str() {
                        Some("${bytesSent}") => value.bytes_sent as f32,
                        Some("${countRequest}") => value.count as f32,
                        Some("${countAttackRequest}") => value.count_attack as f32,
                        _ => value.count as f32,
                    };
                    total += val;

                    let mut keys = Vec::new();
                    for k in &item.keys {
                        let v = match k.as_str() {
                            "${country}" => key.country.clone(),
                            "${province}" => key.province.clone(),
                            "${city}" => key.city.clone(),
                            "${provider}" => key.provider.clone(),
                            "${browser}" => key.browser.clone(),
                            "${os}" => key.os.clone(),
                            "${wafGroup}" => key.waf_group_id.to_string(),
                            "${wafAction}" => key.waf_action.clone(),
                            _ => "".to_string(),
                        };
                        keys.push(v);
                    }

                    // GO ALGORITHM: hashString(serverId + "@" + keys.join("$EDGE$") + "@" + time + "@" + version + "@" + itemId)
                    let keys_data = keys.join("$EDGE$");
                    let hash_raw = format!(
                        "{}@{}@{}@{}@{}",
                        server_id, keys_data, time_key, item.version, item.id
                    );
                    let hash = crate::utils::fnv_hash64(&hash_raw).to_string();

                    // Check cache for keep_keys optimization
                    let cache_key = format!("{}_{}", item.id, hash);
                    if let Some(&old_val) = values_cache.get(&cache_key)
                        && (val - old_val).abs() < 0.001 {
                            keep_keys.push(hash);
                            continue;
                        }

                    values_cache.insert(cache_key, val);

                    metric_stats.push(pb::UploadingMetricStat {
                        id: 0,
                        hash,
                        keys,
                        value: val,
                    });
                }

                if let Err(e) = service
                    .upload_metric_stats(pb::UploadMetricStatsRequest {
                        server_id,
                        time: time_key.clone(),
                        count,
                        total,
                        version: item.version,
                        item_id: item.id,
                        metric_stats,
                        keep_keys,
                    })
                    .await
                {
                    error!(
                        "Failed to upload metric stats for server {} item {}: {}",
                        server_id, item.id, e
                    );
                }
            }
        }
    }
}

use std::sync::atomic::{AtomicI32, AtomicBool, Ordering};

static LAST_NODE_LEVEL: AtomicI32 = AtomicI32::new(-1);
static LAST_HAS_PARENTS: AtomicBool = AtomicBool::new(false);

pub async fn start_metrics_aggregator_reporter(api_config: ApiConfig) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        interval.tick().await;

        let client = match RpcClient::new(&api_config).await {
            Ok(c) => c,
            Err(e) => {
                error!("Metrics aggregator reporter failed to connect: {}", e);
                continue;
            }
        };
        let mut node_service = client.node_service_with_type();
        let mut server_service = client.server_service();

        match node_service
            .find_node_level_info(pb::FindNodeLevelInfoRequest {})
            .await
        {
            Ok(resp) => {
                let info = resp.into_inner();
                let has_parents = !info.parent_nodes_map_json.is_empty();
                
                if info.level != LAST_NODE_LEVEL.load(Ordering::Relaxed) || has_parents != LAST_HAS_PARENTS.load(Ordering::Relaxed) {
                    LAST_NODE_LEVEL.store(info.level, Ordering::Relaxed);
                    LAST_HAS_PARENTS.store(has_parents, Ordering::Relaxed);
                    info!(
                        "Node Level identified: {}, Parents: {}",
                        info.level,
                        has_parents
                    );
                } else {
                    debug!(
                        "Node Level verified: {}, Parents: {}",
                        info.level,
                        has_parents
                    );
                }
            }
            Err(e) => {
                error!("Failed to fetch node level info: {}", e);
            }
        }

        let samples = crate::metrics::aggregator::AGGREGATOR.flush();

        if samples.is_empty() {
            continue;
        }

        let now = chrono::Local::now();
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

        for (key, val) in samples {
            req.systems
                .push(pb::upload_server_http_request_stat_request::System {
                    server_id: key.server_id,
                    name: key.os.clone(),
                    version: "".to_string(),
                    count: val.count,
                });

            req.browsers
                .push(pb::upload_server_http_request_stat_request::Browser {
                    server_id: key.server_id,
                    name: key.browser.clone(),
                    version: "".to_string(),
                    count: val.count,
                });

            if key.waf_group_id > 0 {
                req.http_firewall_rule_groups.push(
                    pb::upload_server_http_request_stat_request::HttpFirewallRuleGroup {
                        server_id: key.server_id,
                        http_firewall_rule_group_id: key.waf_group_id,
                        action: key.waf_action.clone(),
                        count: val.count_attack,
                    },
                );
            }

            req.region_cities
                .push(pb::upload_server_http_request_stat_request::RegionCity {
                    server_id: key.server_id,
                    count_requests: val.count,
                    bytes: val.bytes_sent,
                    count_attack_requests: val.count_attack,
                    attack_bytes: 0,
                    region_country_id: key.country_id,
                    region_province_id: key.province_id,
                    region_city_id: key.city_id,
                });

            req.region_providers.push(
                pb::upload_server_http_request_stat_request::RegionProvider {
                    server_id: key.server_id,
                    count: val.count,
                    region_provider_id: 0,
                },
            );
        }

        if let Err(e) = server_service.upload_server_http_request_stat(req).await {
            error!("Failed to upload HTTP request stats: {}", e);
        }
    }
}

pub async fn start_top_ip_stat_reporter(api_config: ApiConfig) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));

    loop {
        interval.tick().await;
        let rows = crate::metrics::top_ip::TOP_IP_TRACKER.flush();
        if rows.is_empty() {
            continue;
        }

        let client = match RpcClient::new(&api_config).await {
            Ok(c) => c,
            Err(e) => {
                error!("Top IP stat reporter failed to connect: {}", e);
                continue;
            }
        };
        let mut service = client.server_top_ip_stat_service();

        let now = chrono::Local::now();
        let day = now.format("%Y%m%d").to_string();
        let minute_floor = (now.minute() / 5) * 5;
        let time_at = format!("{:02}{:02}", now.hour(), minute_floor);

        let stats = rows
            .into_iter()
            .map(
                |(server_id, ip, count_requests)| pb::upload_server_top_ip_stats_request::Stat {
                    server_id: server_id as u64,
                    ip,
                    count_requests: count_requests as u32,
                    day: day.clone(),
                    time_at: time_at.clone(),
                },
            )
            .collect();

        if let Err(e) = service
            .upload_server_top_ip_stats(pb::UploadServerTopIpStatsRequest { stats })
            .await
        {
            error!("Failed to upload top IP stats: {}", e);
        }
    }
}
