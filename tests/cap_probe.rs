// Branch-only probe — prints governor-derived caps so bench numbers can be
// interpreted against the actual limits on the build host.
use cloud_node_rust::memory_governor::MEMORY_GOVERNOR;

#[test]
fn print_caps() {
    let view = MEMORY_GOVERNOR.account_view();
    let snap = MEMORY_GOVERNOR.snapshot(MEMORY_GOVERNOR.pingora_worker_threads());
    let view2 = MEMORY_GOVERNOR.account_view();
    println!(
        "CAP firewall_state_map={} metrics_cardinality={}",
        MEMORY_GOVERNOR.firewall_state_map_capacity(),
        MEMORY_GOVERNOR.metrics_cardinality_capacity(),
    );
    println!(
        "ACCOUNT before_refresh={:?} after_refresh={:?}",
        view, view2
    );
    println!(
        "SNAP total={} used={} avail={} raw_avail={:?} cgroup_max={} cgroup_high={} reclaimable={} obs_age_ms={} headroom={:?} grantable={} pressure={:?}",
        snap.memory_total_bytes,
        snap.memory_used_bytes,
        snap.memory_available_bytes,
        snap.memory_raw_available_bytes,
        snap.cgroup_memory_max_bytes,
        snap.cgroup_memory_high_bytes,
        snap.cgroup_reclaimable_bytes,
        snap.observation_age_ms,
        snap.account_headroom_bytes,
        snap.account_grantable_bytes,
        snap.memory_pressure_level,
    );
}
