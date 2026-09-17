// RSS comparison bench — this file is copied verbatim onto the v1.2.7
// baseline tree and the hardened branch, so it only uses APIs that exist in
// both. Run: CLOUD_NODE_HOME=/tmp/bench-node cargo test --release \
//   --test memory_compare -- --nocapture --test-threads 1
use cloud_node_rust::firewall::persistence;
use cloud_node_rust::firewall::state::WafStateManager;
use cloud_node_rust::metrics::aggregator::{AggregationKey, MetricAggregator};
use cloud_node_rust::metrics::daily::{DailyDomainTracker, UniqueIpTracker};
use cloud_node_rust::metrics::top_ip::TopIpTracker;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

fn rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    let kb: u64 = rest
                        .trim()
                        .trim_end_matches(" kB")
                        .trim()
                        .parse()
                        .unwrap_or(0);
                    return kb * 1024;
                }
            }
        }
    }
    0
}

fn env_n(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn report(name: &str, before: u64, after: u64, extra: &str) {
    let delta = after as i64 - before as i64;
    println!(
        "BENCH {name} rss_before={:.1}MiB rss_after={:.1}MiB delta={:+.1}MiB {extra}",
        before as f64 / 1048576.0,
        after as f64 / 1048576.0,
        delta as f64 / 1048576.0,
    );
}

fn ip_of(i: usize) -> IpAddr {
    // 11.x.x.x range — 16M distinct addresses, far from reserved space.
    IpAddr::V4(Ipv4Addr::from(0x0B00_0000u32 + i as u32))
}

#[test]
fn bench_waf_scoped_state_flood() {
    let before = rss_bytes();
    let mgr = WafStateManager::new();
    let n = env_n("BENCH_WAF_N", 1_500_000);
    let expiry = crate::utils_now_plus(86_400);
    for i in 0..n {
        mgr.apply_black_ip_until(7, ip_of(i), expiry);
    }
    // Spot-check eviction semantics: probe the first, middle and last IPs.
    let first = mgr.is_blocked(ip_of(0), 7);
    let mid = mgr.is_blocked(ip_of(n / 2), 7);
    let last = mgr.is_blocked(ip_of(n - 1), 7);
    let after = rss_bytes();
    report(
        "waf_scoped_state",
        before,
        after,
        &format!("n={n} first_blocked={first} mid_blocked={mid} last_blocked={last}"),
    );
    drop(mgr);
}

#[test]
fn bench_metrics_cardinality_flood() {
    let before = rss_bytes();
    let n = env_n("BENCH_METRICS_N", 400_000);

    let top = TopIpTracker::new();
    for i in 0..n {
        top.record_addr(7, ip_of(i));
    }
    let after_top = rss_bytes();
    report("top_ip_tracker", before, after_top, &format!("n={n}"));

    let daily = DailyDomainTracker::new();
    for i in 0..n {
        let domain = format!("d{i}.example.com");
        daily.record(7, 100, &domain, 10, 0, 1, 0, 0, 0);
    }
    let after_daily = rss_bytes();
    report("daily_domain_tracker", after_top, after_daily, &format!("n={n}"));

    let agg = MetricAggregator::new();
    for i in 0..n {
        agg.record(agg_key(&format!("city-{i}")), 10, 1, false);
    }
    let after_agg = rss_bytes();
    report("metric_aggregator", after_daily, after_agg, &format!("n={n}"));

    // UniqueIpTracker persists each admitted row — keep N smaller.
    let uniq_n = env_n("BENCH_UNIQUE_N", 150_000);
    let uniq = UniqueIpTracker::new();
    for i in 0..uniq_n {
        uniq.record(7, "20260917", ip_of(i));
    }
    let after_uniq = rss_bytes();
    report(
        "unique_ip_tracker",
        after_agg,
        after_uniq,
        &format!("n={uniq_n}"),
    );

    drop((top, daily, agg, uniq));
}

#[test]
fn bench_pending_delete_flood() {
    let before = rss_bytes();
    // Delete tombstones are ~40B keys; the queue cap sits far above this N on
    // big hosts, so this measures enqueue-path overhead parity more than the
    // bound itself (the bound is unit-proven).
    let n = env_n("BENCH_PENDING_N", 60_000);
    for i in 0..n {
        persistence::enqueue_delete("server", 7, &format!("{}", ip_of(i)));
    }
    let after = rss_bytes();
    report("pending_delete_queue", before, after, &format!("n={n}"));
}

fn agg_key(tag: &str) -> AggregationKey {
    AggregationKey {
        category: Arc::from("http"),
        server_id: 7,
        country: Arc::from(""),
        country_id: 0,
        province: Arc::from(""),
        province_id: 0,
        city: Arc::from(tag),
        city_id: 0,
        provider: Arc::from("Unknown"),
        browser: Arc::from(""),
        os: Arc::from(""),
        waf_group_id: 0,
        waf_action: Arc::from(""),
        provider_id: 0,
        browser_version: Arc::from(""),
        os_version: Arc::from(""),
        request_attrs: Arc::new(BTreeMap::new()),
    }
}

fn utils_now_plus(secs: i64) -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64 + secs)
        .unwrap_or(0)
}
