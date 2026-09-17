use crate::memory_governor::MEMORY_GOVERNOR;
use moka::sync::Cache;
use regex::Regex;
use std::cell::Cell;
use std::sync::Arc;
use std::sync::LazyLock as Lazy;
use std::time::Duration;

const REGEX_CACHE_MIN_ENTRIES: u64 = 256;
const REGEX_CACHE_MAX_ENTRIES: u64 = 16_384;
const REGEX_CACHE_ESTIMATED_BYTES: u64 = 64 * 1024;

static SHARED_REGEX_CACHE: Lazy<Cache<String, Arc<Regex>>> = Lazy::new(build_regex_cache);

thread_local! {
    static CACHE_INITIALIZATION_IN_PROGRESS: Cell<bool> = const { Cell::new(false) };
}

fn build_regex_cache() -> Cache<String, Arc<Regex>> {
    CACHE_INITIALIZATION_IN_PROGRESS.with(|in_progress| {
        let was_initializing = in_progress.replace(true);
        debug_assert!(!was_initializing);
        let cache = Cache::builder()
            .max_capacity(regex_cache_max_entries())
            .time_to_idle(Duration::from_secs(15 * 60))
            .build();
        in_progress.set(was_initializing);
        cache
    })
}

pub fn regex_cache_max_entries() -> u64 {
    let budget = MEMORY_GOVERNOR
        .snapshot(MEMORY_GOVERNOR.pingora_worker_threads())
        .regex_cache_budget_bytes;
    budget
        .saturating_div(REGEX_CACHE_ESTIMATED_BYTES)
        .clamp(REGEX_CACHE_MIN_ENTRIES, REGEX_CACHE_MAX_ENTRIES)
}

pub fn get_or_compile(pattern: &str) -> Option<Arc<Regex>> {
    if let Some(cached) = SHARED_REGEX_CACHE.get(pattern) {
        return Some(cached);
    }
    SHARED_REGEX_CACHE
        .try_get_with(pattern.to_string(), || Regex::new(pattern).map(Arc::new))
        .ok()
}

pub fn entry_count() -> u64 {
    SHARED_REGEX_CACHE.entry_count()
}

pub fn reclaim_all() {
    if CACHE_INITIALIZATION_IN_PROGRESS.with(Cell::get) {
        return;
    }
    SHARED_REGEX_CACHE.invalidate_all();
    // invalidate_all only marks entries — without maintenance the regexes
    // stay heap-resident until moka's lazy janitor runs. Force it so a
    // Critical reclaim actually frees the pages instead of deferring them.
    SHARED_REGEX_CACHE.run_pending_tasks();
}

/// Partial reclaim for High pressure: evict a deterministic ~half of the
/// cache by key-hash parity. Uniform over the key space; hot patterns
/// recompile on demand. Returns entries removed.
pub fn reclaim_partial() -> u64 {
    if CACHE_INITIALIZATION_IN_PROGRESS.with(Cell::get) {
        return 0;
    }
    let before = SHARED_REGEX_CACHE.entry_count();
    let victims: Vec<String> = SHARED_REGEX_CACHE
        .iter()
        .filter_map(|(key, _)| {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash(&*key, &mut hasher);
            (std::hash::Hasher::finish(&hasher) & 1 == 0).then(|| (*key).clone())
        })
        .collect();
    for key in victims {
        SHARED_REGEX_CACHE.invalidate(&key);
    }
    SHARED_REGEX_CACHE.run_pending_tasks();
    before.saturating_sub(SHARED_REGEX_CACHE.entry_count())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_reclaim_evicts_roughly_half_and_keeps_cache_usable() {
        for i in 0..64 {
            let pattern = format!("^partial-reclaim-{i}$");
            assert!(get_or_compile(&pattern).is_some());
        }
        SHARED_REGEX_CACHE.run_pending_tasks();
        let before = SHARED_REGEX_CACHE.entry_count();
        let removed = reclaim_partial();
        let after = SHARED_REGEX_CACHE.entry_count();
        assert_eq!(removed, before.saturating_sub(after));
        assert!(
            after < before,
            "partial reclaim must evict entries (before={before}, after={after})"
        );
        // A fresh lookup still works and an evicted pattern recompiles.
        assert!(get_or_compile("^partial-reclaim-0$").is_some());
    }
}
