use std::sync::LazyLock;
use std::time::{Duration, Instant};

use dashmap::DashMap;

const ORIGIN_H3_STATE_IDLE_SECS: u64 = 6 * 3600;
const ORIGIN_H3_STATE_SWEEP_SECS: u64 = 60;
const ORIGIN_H3_STATE_MAX_NORMAL: usize = 131_072;
const ORIGIN_H3_STATE_MAX_PRESSURE: usize = 16_384;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum OriginH3Key {
    OriginId(i64),
    Target { addr: String, sni: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginH3Capability {
    Unknown,
    Supported,
    Unsupported,
}

#[derive(Clone, Debug)]
struct OriginH3Entry {
    capability: OriginH3Capability,
    last_probe_at: Instant,
    next_probe_after: Instant,
    fail_count: u32,
}

pub struct OriginH3StateManager {
    entries: DashMap<OriginH3Key, OriginH3Entry>,
    last_sweep: std::sync::atomic::AtomicU64,
}

impl OriginH3StateManager {
    fn new() -> Self {
        Self {
            entries: DashMap::new(),
            last_sweep: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn should_try_h3(&self, key: &OriginH3Key) -> bool {
        let now = Instant::now();
        self.sweep_if_needed(now);
        self.entries
            .get(key)
            .map(|entry| match entry.capability {
                OriginH3Capability::Unknown | OriginH3Capability::Supported => true,
                OriginH3Capability::Unsupported => now >= entry.next_probe_after,
            })
            .unwrap_or(true)
    }

    pub fn record_success(&self, key: OriginH3Key) {
        let now = Instant::now();
        if !self.ensure_capacity_for(&key, now) {
            return;
        }
        self.entries.insert(
            key,
            OriginH3Entry {
                capability: OriginH3Capability::Supported,
                last_probe_at: now,
                next_probe_after: now,
                fail_count: 0,
            },
        );
    }

    pub fn record_failure(&self, key: OriginH3Key) {
        let now = Instant::now();
        if !self.ensure_capacity_for(&key, now) {
            return;
        }
        self.entries
            .entry(key)
            .and_modify(|entry| {
                entry.capability = OriginH3Capability::Unsupported;
                entry.last_probe_at = now;
                entry.fail_count = entry.fail_count.saturating_add(1);
                entry.next_probe_after = now + backoff(entry.fail_count);
            })
            .or_insert_with(|| OriginH3Entry {
                capability: OriginH3Capability::Unsupported,
                last_probe_at: now,
                next_probe_after: now + backoff(1),
                fail_count: 1,
            });
    }

    #[cfg(test)]
    pub fn capability(&self, key: &OriginH3Key) -> OriginH3Capability {
        self.entries
            .get(key)
            .map(|entry| entry.capability)
            .unwrap_or(OriginH3Capability::Unknown)
    }

    fn capacity(&self) -> usize {
        if crate::memory_governor::MEMORY_GOVERNOR.is_memory_pressure_high() {
            ORIGIN_H3_STATE_MAX_PRESSURE
        } else {
            ORIGIN_H3_STATE_MAX_NORMAL
        }
    }

    fn ensure_capacity_for(&self, key: &OriginH3Key, now: Instant) -> bool {
        self.sweep_if_needed(now);
        if self.entries.contains_key(key) || self.entries.len() < self.capacity() {
            return true;
        }
        self.sweep_idle(now);
        self.entries.len() < self.capacity()
    }

    fn sweep_if_needed(&self, now: Instant) {
        let now_secs = crate::utils::time::now_timestamp().max(0) as u64;
        let last = self.last_sweep.load(std::sync::atomic::Ordering::Relaxed);
        if now_secs.saturating_sub(last) < ORIGIN_H3_STATE_SWEEP_SECS {
            return;
        }
        if self
            .last_sweep
            .compare_exchange(
                last,
                now_secs,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
        {
            self.sweep_idle(now);
        }
    }

    fn sweep_idle(&self, now: Instant) {
        self.entries.retain(|_, entry| {
            now.duration_since(entry.last_probe_at).as_secs() < ORIGIN_H3_STATE_IDLE_SECS
        });
    }
}

fn backoff(fail_count: u32) -> Duration {
    let seconds = match fail_count {
        0 | 1 => 60,
        2 => 300,
        3 => 900,
        _ => 1800,
    };
    Duration::from_secs(seconds)
}

pub static ORIGIN_H3_STATE_MANAGER: LazyLock<OriginH3StateManager> =
    LazyLock::new(OriginH3StateManager::new);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_origin_is_attempted() {
        let manager = OriginH3StateManager::new();
        let key = OriginH3Key::OriginId(1);

        assert!(manager.should_try_h3(&key));
        assert_eq!(manager.capability(&key), OriginH3Capability::Unknown);
    }

    #[test]
    fn failure_marks_unsupported_and_backs_off() {
        let manager = OriginH3StateManager::new();
        let key = OriginH3Key::OriginId(1);

        manager.record_failure(key.clone());

        assert!(!manager.should_try_h3(&key));
        assert_eq!(manager.capability(&key), OriginH3Capability::Unsupported);
    }

    #[test]
    fn success_marks_supported_and_allows_attempts() {
        let manager = OriginH3StateManager::new();
        let key = OriginH3Key::OriginId(1);

        manager.record_failure(key.clone());
        manager.record_success(key.clone());

        assert!(manager.should_try_h3(&key));
        assert_eq!(manager.capability(&key), OriginH3Capability::Supported);
    }

    #[test]
    fn idle_entries_are_swept() {
        let manager = OriginH3StateManager::new();
        let key = OriginH3Key::OriginId(7);
        manager.record_failure(key.clone());
        assert_eq!(manager.entries.len(), 1);

        if let Some(mut entry) = manager.entries.get_mut(&key) {
            entry.last_probe_at =
                Instant::now() - Duration::from_secs(ORIGIN_H3_STATE_IDLE_SECS + 1);
        }
        manager.sweep_idle(Instant::now());

        assert_eq!(manager.entries.len(), 0);
        assert!(manager.should_try_h3(&key));
    }

    #[test]
    fn capacity_refuses_new_entries_after_idle_sweep_cannot_free_space() {
        let manager = OriginH3StateManager::new();
        let now = Instant::now();
        for i in 0..ORIGIN_H3_STATE_MAX_NORMAL {
            manager.entries.insert(
                OriginH3Key::OriginId(i as i64),
                OriginH3Entry {
                    capability: OriginH3Capability::Unsupported,
                    last_probe_at: now,
                    next_probe_after: now + backoff(1),
                    fail_count: 1,
                },
            );
        }

        manager.record_failure(OriginH3Key::OriginId(
            (ORIGIN_H3_STATE_MAX_NORMAL + 1) as i64,
        ));

        assert_eq!(manager.entries.len(), ORIGIN_H3_STATE_MAX_NORMAL);
    }
}
