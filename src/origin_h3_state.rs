use std::sync::LazyLock;
use std::time::{Duration, Instant};

use dashmap::DashMap;

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
}

impl OriginH3StateManager {
    fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    pub fn should_try_h3(&self, key: &OriginH3Key) -> bool {
        let now = Instant::now();
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
}
