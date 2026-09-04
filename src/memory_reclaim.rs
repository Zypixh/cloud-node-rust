use crate::memory_governor::{MEMORY_GOVERNOR, MemoryPressureLevel};
use std::cell::Cell;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReclaimStats {
    pub l1_entries_removed: usize,
    pub l1_bytes_freed_estimate: u64,
    pub bloom_layers_removed: u64,
    pub negative_cache_entries_removed: usize,
    pub geo_cache_entries_removed: usize,
    pub ua_cache_entries_removed: usize,
    pub tls_connectors_removed: usize,
    pub waf_regex_entries_removed: u64,
    pub metric_rows_flushed: usize,
    pub sni_relays_drained: usize,
}

impl ReclaimStats {
    pub fn total_entries_removed(&self) -> usize {
        self.l1_entries_removed
            .saturating_add(self.negative_cache_entries_removed)
            .saturating_add(self.geo_cache_entries_removed)
            .saturating_add(self.ua_cache_entries_removed)
            .saturating_add(self.tls_connectors_removed)
            .saturating_add(self.metric_rows_flushed)
    }

    pub fn freed_bytes_estimate(&self) -> u64 {
        self.l1_bytes_freed_estimate
    }
}

static LAST_OBSERVED_PRESSURE: AtomicU8 = AtomicU8::new(MemoryPressureLevel::Normal as u8);
static LAST_RECLAIM_AT_MS: AtomicU64 = AtomicU64::new(0);

thread_local! {
    // Reclaiming cache state can update resident-memory accounting, which in
    // turn observes pressure again. Keep recursive notifications from
    // re-entering the same reclaim path on the current thread.
    static RECLAIM_IN_PROGRESS: Cell<bool> = const { Cell::new(false) };
}

const RECLAIM_COOLDOWN_MS: u64 = 5_000;

fn level_from_u8(value: u8) -> MemoryPressureLevel {
    match value {
        1 => MemoryPressureLevel::Elevated,
        2 => MemoryPressureLevel::High,
        3 => MemoryPressureLevel::Critical,
        _ => MemoryPressureLevel::Normal,
    }
}

fn level_to_u8(level: MemoryPressureLevel) -> u8 {
    level as u8
}

pub fn current_observed_pressure() -> MemoryPressureLevel {
    level_from_u8(LAST_OBSERVED_PRESSURE.load(Ordering::Relaxed))
}

pub fn reclaim_for_level(level: MemoryPressureLevel) -> ReclaimStats {
    if RECLAIM_IN_PROGRESS.with(|in_progress| in_progress.replace(true)) {
        return ReclaimStats::default();
    }

    let mut stats = ReclaimStats::default();
    match level {
        MemoryPressureLevel::Normal => {}
        MemoryPressureLevel::Elevated => {
            let cache_stats = crate::cache_hybrid::reclaim_caches_elevated();
            stats.l1_entries_removed = cache_stats.l1_entries_removed;
            stats.l1_bytes_freed_estimate = cache_stats.l1_bytes_freed_estimate;
            stats.negative_cache_entries_removed = cache_stats.negative_cache_entries_removed;
            stats.metric_rows_flushed = flush_metric_aggregators();
        }
        MemoryPressureLevel::High => {
            stats.sni_relays_drained = crate::l4_connection_registry::drain_sni_limited(8);
            let cache_stats = crate::cache_hybrid::reclaim_caches_high();
            stats.l1_entries_removed = cache_stats.l1_entries_removed;
            stats.l1_bytes_freed_estimate = cache_stats.l1_bytes_freed_estimate;
            stats.bloom_layers_removed = cache_stats.bloom_layers_removed;
            stats.negative_cache_entries_removed = cache_stats.negative_cache_entries_removed;
            let geo = crate::metrics::analyzer::reclaim_geo_ua_caches(false);
            stats.geo_cache_entries_removed = geo.0;
            stats.ua_cache_entries_removed = geo.1;
            stats.tls_connectors_removed = crate::tcp_proxy::reclaim_tls_connector_cache(0.5);
            stats.waf_regex_entries_removed =
                crate::firewall::matcher::reclaim_waf_regex_caches(false);
            stats.metric_rows_flushed = flush_metric_aggregators();
            crate::firewall::state::accelerate_block_map_gc();
        }
        MemoryPressureLevel::Critical => {
            stats.sni_relays_drained = crate::l4_connection_registry::drain_sni_limited(32);
            let cache_stats = crate::cache_hybrid::reclaim_caches_critical();
            stats.l1_entries_removed = cache_stats.l1_entries_removed;
            stats.l1_bytes_freed_estimate = cache_stats.l1_bytes_freed_estimate;
            stats.bloom_layers_removed = cache_stats.bloom_layers_removed;
            stats.negative_cache_entries_removed = cache_stats.negative_cache_entries_removed;
            let geo = crate::metrics::analyzer::reclaim_geo_ua_caches(true);
            stats.geo_cache_entries_removed = geo.0;
            stats.ua_cache_entries_removed = geo.1;
            stats.tls_connectors_removed = crate::tcp_proxy::reclaim_tls_connector_cache(0.0);
            stats.waf_regex_entries_removed =
                crate::firewall::matcher::reclaim_waf_regex_caches(true);
            stats.metric_rows_flushed = flush_metric_aggregators();
            crate::firewall::state::accelerate_block_map_gc();
            crate::bounded_regex_cache::reclaim_all();
        }
    }

    tracing::info!(
        target: "memory_reclaim",
        level = level.as_str(),
        l1_removed = stats.l1_entries_removed,
        l1_bytes = stats.l1_bytes_freed_estimate,
        bloom_layers = stats.bloom_layers_removed,
        negative = stats.negative_cache_entries_removed,
        geo = stats.geo_cache_entries_removed,
        ua = stats.ua_cache_entries_removed,
        tls = stats.tls_connectors_removed,
        waf_regex = stats.waf_regex_entries_removed,
        metrics = stats.metric_rows_flushed,
        "memory reclaim completed"
    );
    RECLAIM_IN_PROGRESS.with(|in_progress| in_progress.set(false));
    stats
}

fn flush_metric_aggregators() -> usize {
    let stat_rows = crate::metrics::aggregator::METRIC_STAT_AGGREGATOR
        .flush()
        .len();
    let http_rows = crate::metrics::aggregator::HTTP_REQUEST_STAT_AGGREGATOR
        .flush()
        .len();
    stat_rows.saturating_add(http_rows)
}

pub fn on_memory_pressure_observed(level: MemoryPressureLevel) {
    let previous = level_from_u8(LAST_OBSERVED_PRESSURE.load(Ordering::Relaxed));
    LAST_OBSERVED_PRESSURE.store(level_to_u8(level), Ordering::Relaxed);

    let now = crate::utils::time::system_timestamp_millis().max(0) as u64;
    let last = LAST_RECLAIM_AT_MS.load(Ordering::Relaxed);
    let cooled_down = now.saturating_sub(last) >= RECLAIM_COOLDOWN_MS;

    let should_reclaim = level > previous
        || (level >= MemoryPressureLevel::High && cooled_down)
        || (level >= MemoryPressureLevel::Elevated
            && previous >= MemoryPressureLevel::Elevated
            && cooled_down);

    if should_reclaim && level >= MemoryPressureLevel::Elevated {
        reclaim_for_level(level);
        LAST_RECLAIM_AT_MS.store(now, Ordering::Relaxed);
    }
}

pub fn periodic_reclaim_check() {
    let level = MEMORY_GOVERNOR.current_memory_pressure_level();
    on_memory_pressure_observed(level);
}

/// Return freed pages to the OS after dropping a large config generation.
/// No-op on non-Linux targets; glibc `malloc_trim` is what the node ships on.
pub fn trim_released_heap() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::malloc_trim(0);
    }
}

pub fn start_reclaim_monitor() {
    std::thread::spawn(|| {
        loop {
            std::thread::sleep(Duration::from_secs(5));
            periodic_reclaim_check();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elevated_reclaim_stats_default_fields_are_zero_when_normal_noop() {
        let stats = ReclaimStats::default();
        assert_eq!(stats.total_entries_removed(), 0);
        assert_eq!(stats.freed_bytes_estimate(), 0);
    }

    #[test]
    fn pressure_level_roundtrip_via_atomic_storage() {
        for level in [
            MemoryPressureLevel::Normal,
            MemoryPressureLevel::Elevated,
            MemoryPressureLevel::High,
            MemoryPressureLevel::Critical,
        ] {
            assert_eq!(level_from_u8(level_to_u8(level)), level);
        }
    }
}
