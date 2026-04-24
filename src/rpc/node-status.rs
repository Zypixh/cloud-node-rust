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
                        // For used memory in CGroup V1
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

        let now = crate::utils::time::now_timestamp();
        let hostname = hostname::get().ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_default();
        let host_ip = local_ip_address::local_ip().map(|ip| ip.to_string()).unwrap_or_default();

        let mut disk_total = 0u64;
        let mut disk_used = 0u64;
        let mut disk_max_usage = 0.0f64;

        for disk in sys.disks() {
            let total = disk.total_space();
            let available = disk.available_space();
            let used = total.saturating_sub(available);
            disk_total += total;
            disk_used += used;
            let usage = if total > 0 { used as f64 / total as f64 } else { 0.0 };
            if usage > disk_max_usage {
                disk_max_usage = usage;
            }
        }
        let disk_usage = if disk_total > 0 { disk_used as f64 / disk_total as f64 } else { 0.0 };

        let status = serde_json::json!({
            "buildVersion": env!("CARGO_PKG_VERSION"),
            "buildVersionCode": 1000000, 
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "hostname": hostname,
            "hostIP": host_ip,
            "cpuUsage": cpu_usage,
            "cpuLogicalCount": sys.cpus().len(),
            "cpuPhysicalCount": sys.physical_core_count().unwrap_or(sys.cpus().len()),
            "memoryUsage": mem_usage,
            "memoryTotal": total_memory,
            "diskUsage": disk_usage,
            "diskTotal": disk_total,
            "diskMaxUsage": disk_max_usage,
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
