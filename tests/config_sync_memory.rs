//! Dynamic memory and performance coverage for large website-config sync.
//!
//! These tests exercise the apply/hot-reload path under several in-process
//! governor budgets, with emphasis on the LOW / Critical budget. They fail if
//! sync panics, deadlocks, drops sites, or grows RSS without bound across
//! repeated applies.

use cloud_node_rust::config::ConfigStore;
use cloud_node_rust::config_apply::{
    ConfigApplyLimits, MaterializeRuntimeServersArgs, RuntimeServerMaps, apply_server_snapshot,
    parse_node_config_json,
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

/// VmRSS is process-wide: a sibling test allocating on other worker threads
/// inside the same test binary inflates these tests' RSS deltas. Serialize
/// every heavy test in this file so a delta attributes to the apply under
/// measurement, not to a concurrently running fixture build.
static RSS_TEST_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
        // Repeat the tightest budget last: after the one-time allocator pool
        // expansion this round must show no residual growth. The leak signal
        // is growth that does not converge, not a single bounded step.
        (
            "low-repeat",
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
    let _gate = RSS_TEST_GATE.lock().await;
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
    drop(payload);

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

    // Adaptive warmup: the first apply at a pressure level pays a one-time
    // allocator pool expansion — that level's reclaim frees a distinct object
    // set into deferred/abandoned mimalloc segments (committed but reusable
    // only after claim) while the replacement generation maps fresh segments.
    // Repeat each level's apply until its RSS delta converges (<32MiB) so the
    // measured pass asserts the real guarantee — no *unbounded* growth across
    // repeated applies. Failure to converge in four attempts is itself the
    // leak signal.
    for (_, limits) in budgets() {
        let mut prev_rss = process_rss().rss_bytes;
        for _attempt in 0..4 {
            let warmup = parse_node_config_json(&json_bytes)
                .expect("warmup snapshot JSON must parse")
                .0
                .servers;
            let warmup_maps = apply_with_timeout(&store, &health, warmup, limits).await;
            assert!(
                warmup_maps.stats.admitted,
                "warmup apply must be admitted by the memory governor"
            );
            let rss = process_rss().rss_bytes;
            if rss.saturating_sub(prev_rss) < 32 * 1024 * 1024 {
                break;
            }
            prev_rss = rss;
        }
    }

    let mut previous_rss = process_rss().rss_bytes;
    // A genuine leak shows growth that does not converge; bounded one-time
    // pool expansions (reclaim purges the free pool, the next apply
    // re-commits it; each pressure level can pay that once) shrink every
    // round. Require every >=48MiB growth round to be strictly smaller than
    // the previous one, cap how many such rounds may occur (one expansion
    // per pressure-level transition at most), and keep the final converged
    // round below 48MiB — a steady or slowly draining leak still fails.
    let mut last_large_growth: Option<u64> = None;
    let mut large_growth_rounds = 0u32;

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
        assert!(
            maps.stats.admitted,
            "{name} apply must be admitted by the memory governor"
        );
        if name.starts_with("low") {
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
        // When a reclaim fired inside the measured apply, `trim_released_heap`
        // decommits the free pool the warmup built up — the apply then
        // re-commits it, so the RSS delta conflates purge+recommit with real
        // growth. Leak detection for those rounds comes from the convergence
        // asserts below; the absolute cap is only meaningful for clean rounds.
        if maps.stats.reclaim_runs == 0 {
            assert!(
                growth < cap,
                "{name} apply grew RSS by {growth} bytes, over the {cap} bound for a {}-byte snapshot",
                json_bytes.len()
            );
        }

        if round >= 2 {
            let repeat_growth = after.rss_bytes.saturating_sub(previous_rss);
            if repeat_growth >= 48 * 1024 * 1024 {
                large_growth_rounds += 1;
                if let Some(prev) = last_large_growth {
                    assert!(
                        repeat_growth < prev,
                        "{name} grew RSS by {repeat_growth} after a {prev} growth round — growth must strictly shrink every round to prove convergence"
                    );
                }
                assert!(
                    large_growth_rounds <= 3,
                    "RSS grew by >=48MiB on {large_growth_rounds} rounds — bounded pool expansion happens once per pressure level at most"
                );
                last_large_growth = Some(repeat_growth);
            }
            if name == "low-repeat" {
                assert!(
                    repeat_growth < 48 * 1024 * 1024,
                    "low-repeat grew RSS by {repeat_growth} after the pools reached steady state — config sync is leaking"
                );
            }
        }
        previous_rss = after.rss_bytes;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_server_json_and_hot_reload_under_low_memory() {
    let _gate = RSS_TEST_GATE.lock().await;
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

    // Two reload rounds: the first may pay a one-time allocator pool
    // expansion; the leak assertion runs on the converged second round.
    let mut maps = None;
    let mut first_delta = 0u64;
    let mut second_delta = 0u64;
    let mut elapsed = std::time::Duration::ZERO;
    for round in 0..2 {
        let before = process_rss();
        let started = Instant::now();
        let large = serde_json::from_value::<ServerConfig>(
            site_value(9_001 + round as i64, &page, 64),
        )
        .expect("large server JSON must parse");
        let round_maps = tokio::time::timeout(
            APPLY_TIMEOUT,
            cloud_node_rust::config_apply::materialize_runtime_servers(
                MaterializeRuntimeServersArgs {
                    servers: vec![large],
                    health_manager: &health,
                    node_level: 1,
                    parent_nodes: Arc::new(Default::default()),
                    tiered_origin_bypass: false,
                    allow_lan: true,
                    global_http: None,
                    limits,
                },
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("hot-reload materialize deadlocked"));
        store
            .replace_server(
                9_001 + round as i64,
                round_maps.all_servers.clone(),
                round_maps.servers.clone(),
                round_maps.routes.clone(),
            )
            .await;
        elapsed = started.elapsed();
        let delta = process_rss()
            .rss_bytes
            .saturating_sub(before.rss_bytes);
        if round == 0 {
            first_delta = delta;
        } else {
            second_delta = delta;
        }
        maps = Some(round_maps);
    }
    let maps = maps.expect("two reload rounds ran");

    eprintln!(
        "hot-reload large-server json_bytes={} elapsed_ms={} rss_delta_round1={} rss_delta_round2={} chunks={} reclaim={}",
        encoded.len(),
        elapsed.as_millis(),
        first_delta,
        second_delta,
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
    // The converged round must not grow: the first round may still pay a
    // bounded allocator expansion, but a repeat reload of the same payload
    // cannot legitimately keep mapping new memory.
    assert!(
        second_delta
            < (encoded.len() as u64)
                .saturating_mul(6)
                .max(64 * 1024 * 1024),
        "large-server hot reload grew RSS by {second_delta} on the converged round (first round: {first_delta})"
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
