use cloud_node_rust::memory_governor::{MEMORY_GOVERNOR, MemoryPressureLevel};
use cloud_node_rust::memory_reclaim::reclaim_for_level;

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
        assert!(
            snapshot.cache_budget_bytes <= 64 * 1024 * 1024
                || snapshot.memory_available_bytes <= 512 * 1024 * 1024,
            "small machines should not reserve an oversized cache floor"
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
