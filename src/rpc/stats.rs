use crate::api_config::ApiConfig;
use crate::pb;
use crate::rpc::client::RpcClient;
use chrono::Timelike;
use std::collections::HashMap;
use tracing::{error, info};

pub async fn start_bandwidth_reporter(api_config: ApiConfig) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));

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
            stats.push(pb::ServerBandwidthStat {
                server_id: snap.server_id,
                day: day.clone(),
                time_at: time_at.clone(),
                bytes: snap.bytes_sent as i64,
                total_bytes: snap.total_bytes() as i64,
                cached_bytes: snap.cached_bytes as i64,
                attack_bytes: snap.attack_bytes as i64,
                count_requests: snap.total_requests as i64,
                count_cached_requests: snap.count_cached_requests as i64,
                count_attack_requests: snap.count_attack_requests as i64,
                count_websocket_connections: snap.count_websocket_connections as i64,
                origin_total_bytes: (snap.origin_bytes_received + snap.origin_bytes_sent) as i64,
                count_i_ps: snap.count_ips as i64,
                ..Default::default()
            });
            // Clear UV set after reporting
            if let Some(m) = crate::metrics::METRICS.servers.get(&snap.server_id) {
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

pub async fn start_daily_stat_reporter(api_config: ApiConfig) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));

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

        let stats = snapshots
            .into_iter()
            .map(|snap| pb::ServerDailyStat {
                server_id: snap.server_id,
                bytes: snap.bytes_sent as i64,
                cached_bytes: snap.cached_bytes as i64,
                count_requests: snap.total_requests as i64,
                count_cached_requests: snap.count_cached_requests as i64,
                created_at,
                count_attack_requests: snap.count_attack_requests as i64,
                attack_bytes: snap.attack_bytes as i64,
                day: day.clone(),
                hour: hour.clone(),
                time_from: time_from.clone(),
                time_to: time_to.clone(),
                ..Default::default()
            })
            .collect();

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
    api_config: ApiConfig,
    config_store: crate::config::ConfigStore,
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
                        "${bytesSent}" => value.bytes_sent as f32,
                        "${countRequest}" => value.count as f32,
                        "${countAttackRequest}" => value.count_attack as f32,
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
                info!(
                    "Node Level identified: {}, Parents: {}",
                    info.level,
                    !info.parent_nodes_map_json.is_empty()
                );
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
