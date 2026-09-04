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
}
