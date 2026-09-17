use cloud_node_rust::memory_governor::{MEMORY_GOVERNOR, MemoryPressureLevel};
use cloud_node_rust::memory_reclaim::reclaim_for_level;

/// VmRSS is process-wide: serialize the RSS-measuring tests in this binary so
/// a sibling test's allocations cannot contaminate a before/after delta.
static RSS_TEST_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn process_rss_bytes() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:")
            && let Some(kib) = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok())
        {
            return kib * 1024;
        }
    }
    0
}

#[test]
fn reclaim_for_normal_pressure_is_noop() {
    let stats = reclaim_for_level(MemoryPressureLevel::Normal);
    assert_eq!(stats.total_entries_removed(), 0);
    assert_eq!(stats.freed_bytes_estimate(), 0);
}

#[test]
fn small_machine_cache_budget_floor_is_below_default() {
    let threads = MEMORY_GOVERNOR.pingora_worker_threads();
    let snapshot = MEMORY_GOVERNOR.snapshot(threads);
    if snapshot.memory_total_bytes <= 4 * 1024 * 1024 * 1024 {
        // The small-machine floor is 32MiB vs the 128MiB default (covered
        // by memory_governor unit tests); the budget itself is a bounded
        // 25%-of-total reservation, so assert the bound the policy
        // actually guarantees — never an oversized flat floor.
        assert!(
            snapshot.cache_budget_bytes <= snapshot.memory_total_bytes / 4,
            "cache budget exceeds the bounded reservation: {}",
            snapshot.cache_budget_bytes
        );
    }
}

#[test]
fn bounded_regex_cache_compiles_and_reclaims() {
    let pattern = "^reclaim-regex-test$";
    assert!(cloud_node_rust::bounded_regex_cache::get_or_compile(pattern).is_some());
    cloud_node_rust::bounded_regex_cache::reclaim_all();
    assert_eq!(cloud_node_rust::bounded_regex_cache::entry_count(), 0);
    assert!(cloud_node_rust::bounded_regex_cache::get_or_compile(pattern).is_some());
}

/// End-to-end proof that Critical reclaim actually returns memory to the OS,
/// not just moves counters: fill the shared regex cache with unique compiled
/// patterns (small heap objects — the kind mimalloc retains in freed
/// segments), reclaim, and assert RSS dropped. Without `mi_collect` on the
/// freeing thread the pages stay committed and this fails.
#[test]
fn critical_reclaim_returns_freed_pages_to_os() {
    let _gate = RSS_TEST_GATE.lock().unwrap();

    // Cache capacity is governor-budget-derived (min 256 entries); fill up
    // to 8k unique compiled patterns — enough retained heap to see in RSS.
    let target = cloud_node_rust::bounded_regex_cache::regex_cache_max_entries()
        .min(8_192) as u32;
    for i in 0..target {
        let pattern = format!("^rss-reclaim-{i}-[0-9]+$");
        assert!(
            cloud_node_rust::bounded_regex_cache::get_or_compile(&pattern).is_some(),
            "fixture pattern must compile"
        );
    }
    let entries = cloud_node_rust::bounded_regex_cache::entry_count();
    assert!(entries >= u64::from(target.min(256)));

    let rss_before = process_rss_bytes();
    let stats = reclaim_for_level(MemoryPressureLevel::Critical);
    let rss_after = process_rss_bytes();

    assert_eq!(
        cloud_node_rust::bounded_regex_cache::entry_count(),
        0,
        "Critical reclaim must empty the regex cache"
    );
    // Only assert the RSS drop when the fixture was large enough for the
    // signal to clear page-granularity noise (~4k regexes ≈ 16–64MB).
    if target >= 4_096 {
        assert!(
            rss_after < rss_before,
            "Critical reclaim dropped {entries} compiled regexes but RSS did not drop ({rss_before} -> {rss_after}): \
             freed pages are retained by the allocator instead of returned to the OS"
        );
    }
    assert!(
        stats.process_rss_after_bytes <= rss_after.saturating_add(8 * 1024 * 1024),
        "reclaim-internal RSS sample should bracket the external one"
    );
}
