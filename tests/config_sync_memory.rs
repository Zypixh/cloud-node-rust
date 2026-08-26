//! Dynamic memory and performance coverage for large website-config sync.
//!
//! These tests exercise the apply/hot-reload path under several in-process
//! governor budgets, with emphasis on the LOW / Critical budget. They fail if
//! sync panics, deadlocks, drops sites, or grows RSS without bound across
//! repeated applies.

use cloud_node_rust::config::ConfigStore;
use cloud_node_rust::config_apply::{
    ConfigApplyLimits, RuntimeServerMaps, apply_server_snapshot, parse_node_config_json,
};
use cloud_node_rust::config_models::ServerConfig;
use cloud_node_rust::health_manager::GlobalHealthManager;
use cloud_node_rust::memory_governor::{MEMORY_GOVERNOR, MemoryPressureLevel};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MANY_SITES: usize = 800;
const SITE_PAGE_BYTES: usize = 8 * 1024;
const LARGE_SERVER_PAGE_BYTES: usize = 512 * 1024;
const APPLY_TIMEOUT: Duration = Duration::from_secs(120);

struct RssSample {
    rss_bytes: u64,
    peak_bytes: u64,
}

fn process_rss() -> RssSample {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let mut rss_bytes = 0u64;
    let mut peak_bytes = 0u64;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            rss_bytes = kb.saturating_mul(1024);
        } else if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            peak_bytes = kb.saturating_mul(1024);
        }
    }
    RssSample {
        rss_bytes,
        peak_bytes,
    }
}

fn budgets() -> Vec<(&'static str, ConfigApplyLimits)> {
    vec![
        (
            "normal",
            ConfigApplyLimits::synthetic(8 * 1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024),
        ),
        (
            "elevated",
            ConfigApplyLimits::synthetic(2 * 1024 * 1024 * 1024, 300 * 1024 * 1024),
        ),
        (
            "high",
            ConfigApplyLimits::synthetic(2 * 1024 * 1024 * 1024, 150 * 1024 * 1024),
        ),
        (
            "low",
            ConfigApplyLimits::synthetic(512 * 1024 * 1024, 32 * 1024 * 1024),
        ),
    ]
}

fn site_value(id: i64, page_body: &str, rule_count: usize) -> serde_json::Value {
    let cache_refs: Vec<serde_json::Value> = (0..rule_count.max(1))
        .map(|idx| {
            json!({
                "isOn": true,
                "key": format!("${{scheme}}://${{host}}${{requestURI}}:{idx}"),
                "life": {"count": 3600, "unit": "second"}
            })
        })
        .collect();
    json!({
        "id": id,
        "userId": 1,
        "isOn": true,
        "serverNames": [
            {"name": format!("s{id}.example.com")},
            {"name": format!("www.s{id}.example.com")}
        ],
        "http": {
            "isOn": true,
            "listen": [{"protocol": "http", "host": "0.0.0.0", "portRange": "80"}]
        },
        "reverseProxy": {
            "isOn": true,
            "primaryOrigins": [{
                "id": id,
                "isOn": true,
                "addr": "http://10.0.0.8:8080"
            }]
        },
        "web": {
            "isOn": true,
            "cache": {
                "isOn": true,
                "cacheRefs": cache_refs
            },
            "pages": [{
                "id": id,
                "isOn": true,
                "status": 404,
                "body": page_body
            }]
        }
    })
}

fn many_site_json(count: usize, page_bytes: usize) -> Vec<u8> {
    let page = "x".repeat(page_bytes);
    let servers: Vec<serde_json::Value> = (1..=count as i64)
        .map(|id| site_value(id, &page, 4))
        .collect();
    serde_json::to_vec(&json!({
        "id": 42,
        "version": 7,
        "isOn": true,
        "servers": servers
    }))
    .expect("serialize node payload")
}

fn assert_sites_applied(store: &ConfigStore, maps: &RuntimeServerMaps, count: usize) {
    assert_eq!(maps.all_servers.len(), count, "all_servers dropped sites");
    assert_eq!(
        maps.stats.servers_indexed, count,
        "routing index dropped enabled sites"
    );
    assert_eq!(
        store.get_all_servers_sync().len(),
        count,
        "ConfigStore dropped sites"
    );
    let first = store
        .get_server_sync("s1.example.com")
        .expect("exact host must resolve");
    let alias = store
        .get_server_sync("www.s1.example.com")
        .expect("alias host must resolve");
    assert!(
        Arc::ptr_eq(&first, &alias),
        "host indexes must share one ServerConfig allocation, not clone the body per name"
    );
    let stored = store
        .get_all_servers_sync()
        .into_iter()
        .find(|server| server.numeric_id() == 1)
        .expect("server 1 in all_servers");
    assert!(
        Arc::ptr_eq(&first, &stored),
        "all_servers and host map must share the same Arc"
    );
}

async fn apply_with_timeout(
    store: &ConfigStore,
    health: &GlobalHealthManager,
    servers: Vec<ServerConfig>,
    limits: ConfigApplyLimits,
) -> RuntimeServerMaps {
    tokio::time::timeout(
        APPLY_TIMEOUT,
        apply_server_snapshot(store, health, servers, limits),
    )
    .await
    .unwrap_or_else(|_| panic!("config sync deadlocked or exceeded {APPLY_TIMEOUT:?}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_site_config_sync_survives_low_memory_budgets() {
    let json_bytes = many_site_json(MANY_SITES, SITE_PAGE_BYTES);
    assert!(
        json_bytes.len() > 4 * 1024 * 1024,
        "fixture must be a genuinely large snapshot, got {} bytes",
        json_bytes.len()
    );

    let (payload, hash, decoded) =
        parse_node_config_json(&json_bytes).expect("full snapshot JSON must parse");
    assert!(!hash.is_empty());
    assert_eq!(decoded, json_bytes.len() as u64);
    assert_eq!(payload.servers.len(), MANY_SITES);

    let low = budgets()
        .into_iter()
        .find(|(name, _)| *name == "low")
        .map(|(_, limits)| limits)
        .expect("low budget");
    assert_eq!(low.pressure, MemoryPressureLevel::Critical);
    assert_eq!(low.server_chunk_size(), 4);
    assert!(low.decode_budget_bytes() <= low.available_bytes);

    let health = GlobalHealthManager::new(4);
    let store = ConfigStore::new();
    let mut previous_rss = process_rss().rss_bytes;
    let mut last_growth = u64::MAX;

    for (round, (name, limits)) in budgets().into_iter().enumerate() {
        let before = process_rss();
        let governor_before = MEMORY_GOVERNOR.snapshot(MEMORY_GOVERNOR.pingora_worker_threads());
        let started = Instant::now();
        let parsed = parse_node_config_json(&json_bytes)
            .expect("full snapshot JSON must parse")
            .0
            .servers;
        let maps = apply_with_timeout(&store, &health, parsed, limits).await;
        let elapsed = started.elapsed();
        let after = process_rss();
        let governor_after = MEMORY_GOVERNOR.snapshot(MEMORY_GOVERNOR.pingora_worker_threads());

        eprintln!(
            "config-sync budget={name} round={} sites={} json_bytes={} elapsed_ms={} rss_before={} rss_after={} rss_delta={} vmhwm={} chunks={} reclaim={} admitted={} gov_used_before={} gov_used_after={}",
            round,
            MANY_SITES,
            json_bytes.len(),
            elapsed.as_millis(),
            before.rss_bytes,
            after.rss_bytes,
            after.rss_bytes.saturating_sub(before.rss_bytes),
            after.peak_bytes,
            maps.stats.chunks,
            maps.stats.reclaim_runs,
            maps.stats.admitted,
            governor_before.memory_used_bytes,
            governor_after.memory_used_bytes
        );

        assert_sites_applied(&store, &maps, MANY_SITES);
        assert!(
            elapsed < APPLY_TIMEOUT,
            "{name} apply took too long: {elapsed:?}"
        );
        if name == "low" {
            assert!(
                maps.stats.chunks >= MANY_SITES / limits.server_chunk_size(),
                "low-memory apply must chunk instead of materializing every site at once"
            );
            assert!(
                maps.stats.reclaim_runs >= 1,
                "low-memory apply must reclaim under Critical pressure"
            );
        }

        let growth = after.rss_bytes.saturating_sub(before.rss_bytes);
        let cap = (json_bytes.len() as u64)
            .saturating_mul(8)
            .max(96 * 1024 * 1024);
        assert!(
            growth < cap,
            "{name} apply grew RSS by {growth} bytes, over the {cap} bound for a {}-byte snapshot",
            json_bytes.len()
        );

        if round >= 2 {
            let repeat_growth = after.rss_bytes.saturating_sub(previous_rss);
            assert!(
                repeat_growth < 48 * 1024 * 1024,
                "{name} repeated apply grew RSS by {repeat_growth} after the snapshot was already resident — config sync is leaking"
            );
            assert!(
                last_growth == u64::MAX
                    || repeat_growth <= last_growth.saturating_add(8 * 1024 * 1024),
                "RSS growth is not stabilizing across repeated applies"
            );
            last_growth = repeat_growth;
        }
        previous_rss = after.rss_bytes;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_server_json_and_hot_reload_under_low_memory() {
    let page = "W".repeat(LARGE_SERVER_PAGE_BYTES);
    let large = serde_json::from_value::<ServerConfig>(site_value(9_001, &page, 64))
        .expect("large server JSON must parse");
    let encoded = serde_json::to_vec(&large).expect("serialize large server");
    assert!(
        encoded.len() > 400 * 1024,
        "single-server JSON must be large, got {} bytes",
        encoded.len()
    );

    let health = GlobalHealthManager::new(2);
    let store = ConfigStore::new();
    let (_, many) = {
        let json_bytes = many_site_json(120, 1024);
        let payload = parse_node_config_json(&json_bytes)
            .expect("baseline snapshot JSON must parse")
            .0;
        (json_bytes, payload.servers)
    };
    let limits = ConfigApplyLimits::synthetic(512 * 1024 * 1024, 32 * 1024 * 1024);
    let baseline = apply_with_timeout(&store, &health, many, limits).await;
    assert_eq!(baseline.all_servers.len(), 120);

    let before = process_rss();
    let started = Instant::now();
    let maps = tokio::time::timeout(
        APPLY_TIMEOUT,
        cloud_node_rust::config_apply::materialize_runtime_servers(
            vec![large],
            &health,
            1,
            Arc::new(Default::default()),
            false,
            true,
            None,
            limits,
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("hot-reload materialize deadlocked"));
    store
        .replace_server(
            9_001,
            maps.all_servers.clone(),
            maps.servers.clone(),
            maps.routes.clone(),
        )
        .await;
    let elapsed = started.elapsed();
    let after = process_rss();

    eprintln!(
        "hot-reload large-server json_bytes={} elapsed_ms={} rss_delta={} chunks={} reclaim={}",
        encoded.len(),
        elapsed.as_millis(),
        after.rss_bytes.saturating_sub(before.rss_bytes),
        maps.stats.chunks,
        maps.stats.reclaim_runs
    );

    assert_eq!(maps.all_servers.len(), 1);
    let loaded = store
        .get_server_by_id_sync(9_001)
        .expect("hot-reloaded large server must be stored");
    assert_eq!(loaded.numeric_id(), 9_001);
    assert!(
        store.get_server_sync("s1.example.com").is_some(),
        "hot-reload of one site must not drop the rest of the snapshot"
    );
    assert!(store.get_all_servers_sync().len() >= 121);
    let growth = after.rss_bytes.saturating_sub(before.rss_bytes);
    assert!(
        growth
            < (encoded.len() as u64)
                .saturating_mul(6)
                .max(64 * 1024 * 1024),
        "large-server hot reload grew RSS by {growth}"
    );
    assert!(elapsed < APPLY_TIMEOUT);
}

#[test]
fn apply_limits_track_governor_available_memory() {
    let live = ConfigApplyLimits::from_governor();
    let snapshot = MEMORY_GOVERNOR.snapshot(MEMORY_GOVERNOR.pingora_worker_threads());
    assert_eq!(live.available_bytes, snapshot.memory_available_bytes);
    assert_eq!(live.total_bytes, snapshot.memory_total_bytes);
    assert!(live.decode_budget_bytes() <= live.available_bytes.max(16 * 1024 * 1024));
    assert!(live.server_chunk_size() >= 1);
}
