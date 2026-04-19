pub async fn start_metrics_reporter(config_store: Arc<ConfigStore>, api_config: ApiConfig) {
    let mut sys = sysinfo::System::new_all();
    // Initial refresh to populate CPU baseline
    sys.refresh_all();
    
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));

    loop {
        interval.tick().await;
        let node_id = config_store.get_node_id().await;
        if node_id == 0 { continue; }

        sys.refresh_all(); // Refresh everything
        let (traffic_out, traffic_in, connections) = crate::metrics::METRICS.get_node_totals();
        let (api_success_percent, api_avg_cost) = crate::metrics::METRICS.rpc.snapshot();
        let load = sysinfo::System::load_average();

        let mut total_memory = sys.total_memory() as i64;
        let mut used_memory = sys.used_memory() as i64;

        // Linux container cgroup memory limit detection
        #[cfg(target_os = "linux")]
        {
            if let Ok(limit_str) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes") {
                if let Ok(limit) = limit_str.trim().parse::<i64>() {
                    if limit > 0 && limit < 1024 * 1024 * 1024 * 1024 {
                        total_memory = limit;
                        if let Ok(usage_str) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.usage_in_bytes") {
                            if let Ok(usage) = usage_str.trim().parse::<i64>() { used_memory = usage; }
                        }
                    }
                }
            } else if let Ok(limit_str) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
                if let Ok(limit) = limit_str.trim().parse::<i64>() {
                    if limit > 0 { 
                        total_memory = limit; 
                        if let Ok(usage_str) = std::fs::read_to_string("/sys/fs/cgroup/memory.current") {
                            if let Ok(usage) = usage_str.trim().parse::<i64>() { used_memory = usage; }
                        }
                    }
                }
            }
        }

        let cpu_usage = sys.global_cpu_usage() as f64 / 100.0;
        let mem_usage = if total_memory > 0 { used_memory as f64 / total_memory as f64 } else { 0.0 };

        let now = chrono::Utc::now().timestamp();
        let hostname = hostname::get().ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_default();
        let host_ip = local_ip_address::local_ip().map(|ip| ip.to_string()).unwrap_or_default();
        let exe_path = std::env::current_exe().ok().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();

        let mut disk_total = 0u64;
        let mut disk_used = 0u64;
        let mut disk_max_usage = 0.0f64;
        let mut disk_max_partition = String::new();

        let disks = sysinfo::Disks::new_with_refreshed_list();
        for disk in &disks {
            let total = disk.total_space();
            let available = disk.available_space();
            let used = total.saturating_sub(available);
            disk_total += total;
            disk_used += used;
            let usage = if total > 0 { used as f64 / total as f64 } else { 0.0 };
            if usage > disk_max_usage {
                disk_max_usage = usage;
                disk_max_partition = disk.mount_point().to_string_lossy().to_string();
            }
        }
        let disk_usage = if disk_total > 0 { disk_used as f64 / disk_total as f64 } else { 0.0 };

        let status = serde_json::json!({
            "buildVersion": "1.1.5",
            "buildVersionCode": 1001005, 
            "configVersion": config_store.get_config_version().await,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "hostname": hostname,
            "hostIP": host_ip,
            "exePath": exe_path,
            "cpuUsage": cpu_usage,
            "cpuLogicalCount": sys.cpus().len(),
            "cpuPhysicalCount": sys.physical_core_count().unwrap_or(sys.cpus().len()),
            "memoryUsage": mem_usage,
            "memoryTotal": total_memory,
            "diskUsage": disk_usage,
            "diskTotal": disk_total,
            "diskMaxUsage": disk_max_usage,
            "diskMaxUsagePartition": disk_max_partition,
            "load1m": load.one,
            "load5m": load.five,
            "load15m": load.fifteen,
            "trafficInBytes": traffic_in, 
            "trafficOutBytes": traffic_out,
            "connectionCount": connections,
            "apiSuccessPercent": api_success_percent,
            "apiAvgCostSeconds": api_avg_cost,
            "cacheTotalDiskSize": crate::metrics::storage::STORAGE.total_cache_size(),
            "updatedAt": now,
            "timestamp": now,
            "isActive": true, 
            "isHealthy": true,
        });

        if let Ok(client) = RpcClient::new(&api_config).await {
            let mut service = client.node_service();
            let _ = service.update_node_status(pb::UpdateNodeStatusRequest {
                node_id,
                status_json: status.to_string().into_bytes(),
            }).await;
        }
    }
}

pub async fn start_node_value_reporter(config_store: Arc<ConfigStore>, api_config: ApiConfig) {
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        interval.tick().await;
        let node_id = config_store.get_node_id().await;
        if node_id == 0 { continue; }

        sys.refresh_all();
        let (traffic_out, traffic_in, connections) = crate::metrics::METRICS.get_node_totals();
        let load = sysinfo::System::load_average();
        
        let mut total_memory = sys.total_memory() as i64;
        let mut used_memory = sys.used_memory() as i64;

        #[cfg(target_os = "linux")]
        {
            if let Ok(limit_str) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes") {
                if let Ok(limit) = limit_str.trim().parse::<i64>() {
                    if limit > 0 && limit < 1024 * 1024 * 1024 * 1024 {
                        total_memory = limit;
                        if let Ok(usage_str) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.usage_in_bytes") {
                            if let Ok(usage) = usage_str.trim().parse::<i64>() { used_memory = usage; }
                        }
                    }
                }
            } else if let Ok(limit_str) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
                if let Ok(limit) = limit_str.trim().parse::<i64>() {
                    if limit > 0 { 
                        total_memory = limit; 
                        if let Ok(usage_str) = std::fs::read_to_string("/sys/fs/cgroup/memory.current") {
                            if let Ok(usage) = usage_str.trim().parse::<i64>() { used_memory = usage; }
                        }
                    }
                }
            }
        }

        let mut disk_total = 0u64;
        let mut disk_used = 0u64;
        let mut disk_max_usage = 0.0f64;
        let disks = sysinfo::Disks::new_with_refreshed_list();
        for disk in &disks {
            let total = disk.total_space();
            disk_total += total;
            disk_used += total.saturating_sub(disk.available_space());
            let usage = if total > 0 { (total.saturating_sub(disk.available_space())) as f64 / total as f64 } else { 0.0 };
            if usage > disk_max_usage { disk_max_usage = usage; }
        }

        let values = vec![
            ("cpu", serde_json::json!({
                "usage": sys.global_cpu_usage() / 100.0,
                "cores": sys.cpus().len()
            })),
            ("memory", serde_json::json!({
                "usage": if total_memory > 0 { used_memory as f64 / total_memory as f64 } else { 0.0 },
                "total": total_memory,
                "used": used_memory
            })),
            ("load", serde_json::json!({
                "load1m": load.one,
                "load5m": load.five,
                "load15m": load.fifteen
            })),
            ("connections", serde_json::json!({
                "total": connections
            })),
            ("traffic", serde_json::json!({
                "in": traffic_in,
                "out": traffic_out,
                "total": traffic_in + traffic_out
            })),
            ("disk", serde_json::json!({
                "total": disk_total,
                "used": disk_used,
                "usage": if disk_total > 0 { disk_used as f64 / disk_total as f64 } else { 0.0 },
                "maxUsage": disk_max_usage
            })),
            ("cache", serde_json::json!({
                "diskSize": crate::metrics::storage::STORAGE.total_cache_size(),
                "memorySize": 0 
            })),
        ];

        let node_value_items: Vec<pb::create_node_values_request::NodeValueItem> = values.into_iter().map(|(item, value)| pb::create_node_values_request::NodeValueItem {
            item: item.to_string(),
            value_json: value.to_string().into_bytes(),
            created_at: chrono::Utc::now().timestamp(),
        }).collect();

        let node_value_items_count = node_value_items.len();
        if let Ok(client) = RpcClient::new(&api_config).await {
            let mut service = client.node_value_service_with_type();
            match service.create_node_values(pb::CreateNodeValuesRequest { node_value_items }).await {
                Ok(_) => info!("Successfully reported {} node values", node_value_items_count),
                Err(e) => error!("Error reporting node values: {}", e),
            }
        }
    }
}
