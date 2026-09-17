// Branch-only probe — prints governor-derived caps so bench numbers can be
// interpreted against the actual limits on the build host.
use cloud_node_rust::memory_governor::MEMORY_GOVERNOR;

#[test]
fn print_caps() {
    println!(
        "CAP firewall_state_map={} metrics_cardinality={}",
        MEMORY_GOVERNOR.firewall_state_map_capacity(),
        MEMORY_GOVERNOR.metrics_cardinality_capacity(),
    );
}
