//! Fixed-capacity scoped-state table for attacker-driven maps.
//!
//! `DashMap` grows by allocation and enforces a bound by checking `len()`
//! then scanning for victims — under a sustained insert flood every insert
//! costs an O(len) retain/scan and the map retains a high-water-mark heap
//! footprint. This table instead pre-allocates `capacity` slots across 64
//! mutexed segments once at construction: memory is physically incapable of
//! exceeding the bound, insert is a constant 8-slot probe with in-window
//! earliest-expiry replacement (Redis maxmemory sampled-eviction style),
//! and flood CPU is flat O(1) regardless of fill level.
//!
//! Eviction policy: within the probe window the smallest `expiry` wins —
//! already-expired rows sort first naturally, so dead entries are reclaimed
//! before live ones without a sweep. A soft capacity below the physical cap
//! can be enforced per-insert via `soft_cap` (used when the governor shrinks
//! the budget); the table never exceeds `min(soft_cap, physical_cap)`.
//!
//! Hashing uses `ahash::RandomState` (per-instance seed) — attacker-chosen
//! keys cannot be pre-computed into collisions.

use ahash::RandomState;
use parking_lot::Mutex;
use std::hash::Hash;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Slots probed per insert/lookup. 8 keeps the window in ~1-2 cache lines
/// worth of scanning while giving eviction enough candidates to prefer
/// expired entries.
const PROBES: usize = 8;
const SEGMENTS: usize = 64;

/// One fixed-size probe region behind a mutex; `len` lives under the same
/// lock as the slots it counts.
struct Segment<K> {
    slots: Box<[Option<(K, i64)>]>,
    len: usize,
}

/// Bounded map with fixed physical capacity. All operations are O(PROBES)
/// except `retain`/`for_each`, which sweep the physical table and are meant
/// for periodic/cold paths only.
pub struct BoundedScopedMap<K> {
    segs: Box<[Mutex<Segment<K>>]>,
    /// Per-segment physical capacity. Global physical cap =
    /// `seg_cap * SEGMENTS` (>= requested capacity).
    seg_cap: usize,
    /// Global live count, maintained exactly under the segment locks so
    /// `len()` and the insert soft-cap check stay O(1).
    total_len: AtomicUsize,
    rs: RandomState,
}

impl<K> BoundedScopedMap<K>
where
    K: Copy + Eq + Hash,
{
    /// Allocate `capacity` slots up front. The footprint never changes
    /// afterwards: inserts reuse dead slots or evict in-window.
    pub fn new(capacity: usize) -> Self {
        let seg_cap = (capacity.max(1) / SEGMENTS).max(64);
        let segs = (0..SEGMENTS)
            .map(|_| {
                Mutex::new(Segment {
                    slots: vec![None; seg_cap].into_boxed_slice(),
                    len: 0,
                })
            })
            .collect();
        Self {
            segs,
            seg_cap,
            total_len: AtomicUsize::new(0),
            rs: RandomState::new(),
        }
    }

    #[inline]
    fn hash(&self, k: &K) -> u64 {
        self.rs.hash_one(k)
    }

    #[inline]
    fn seg_of(&self, h: u64) -> usize {
        // High bits pick the segment; low bits pick the home slot — the two
        // are independent enough for a hash-mixed key.
        (h >> 26) as usize % SEGMENTS
    }

    pub fn len(&self) -> usize {
        self.total_len.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Probe-window lookup under the segment lock.
    pub fn get(&self, key: &K) -> Option<i64> {
        let h = self.hash(key);
        let seg = &self.segs[self.seg_of(h)];
        let seg = seg.lock();
        let home = (h as usize) % self.seg_cap;
        for probe in 0..PROBES {
            if let Some((k, expiry)) = seg.slots[(home + probe) % self.seg_cap]
                && k == *key
            {
                return Some(expiry);
            }
        }
        None
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Insert or update. When the map is at `soft_cap`, or the probe window
    /// is full, the lowest-expiry live slot found is overwritten and the
    /// victim key is returned for downstream reconciliation. Inserts with
    /// `expiry <= now` act as removes (same convention as the previous
    /// DashMap callers).
    pub fn insert(&self, key: K, expiry: i64, now: i64, soft_cap: usize) -> Option<K> {
        if now >= expiry {
            self.remove(&key);
            return None;
        }
        let h = self.hash(&key);
        let seg_idx = self.seg_of(h);
        let seg = &self.segs[seg_idx];
        let mut seg = seg.lock();
        let home = (h as usize) % self.seg_cap;
        let mut dead: Option<usize> = None;
        // Track the lowest-expiry live slot as the eviction victim; expired
        // entries sort first since expiry <= now < any live expiry.
        let mut victim: Option<usize> = None;
        let mut victim_expiry = i64::MAX;
        for probe in 0..PROBES {
            let idx = (home + probe) % self.seg_cap;
            match seg.slots[idx] {
                None => {
                    if dead.is_none() {
                        dead = Some(idx);
                    }
                }
                Some((k, slot_expiry)) => {
                    if k == key {
                        seg.slots[idx] = Some((key, expiry));
                        return None;
                    }
                    if slot_expiry < victim_expiry {
                        victim_expiry = slot_expiry;
                        victim = Some(idx);
                    }
                }
            }
        }
        // At the soft cap we must evict rather than occupy a dead slot —
        // the global count would otherwise exceed the budget.
        let must_evict = self.len() >= soft_cap.max(1);
        if !must_evict {
            if let Some(idx) = dead {
                seg.slots[idx] = Some((key, expiry));
                seg.len += 1;
                self.total_len.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
        if let Some(idx) = victim {
            // Full window or soft-cap pressure: evict earliest-expiry.
            let (evicted, _) = seg.slots[idx].expect("victim slot is live");
            seg.slots[idx] = Some((key, expiry));
            return Some(evicted);
        }
        // Rare corner: the window has dead slots but no live slot to evict
        // while the global count is at the soft cap (other segments hold
        // the entries). Evict the earliest-expiry live entry elsewhere —
        // a bounded scan across segments, taken only in this corner.
        if let Some(idx) = dead {
            if let Some(evicted) = self.evict_anywhere(seg_idx, now) {
                seg.slots[idx] = Some((key, expiry));
                seg.len += 1;
                self.total_len.fetch_add(1, Ordering::Relaxed);
                return Some(evicted);
            }
            // `total_len` disagreed with reality (impossible while the
            // counters are exact): fall back to the dead slot rather than
            // dropping the insert.
            seg.slots[idx] = Some((key, expiry));
            seg.len += 1;
            self.total_len.fetch_add(1, Ordering::Relaxed);
        }
        None
    }

    /// Test-only backdoor: plant an entry bypassing the expired-as-remove
    /// convention, so tests can seed a dead row deterministically.
    #[cfg(test)]
    pub fn seed_unchecked(&self, key: K, expiry: i64) {
        let h = self.hash(&key);
        let seg = &self.segs[self.seg_of(h)];
        let mut seg = seg.lock();
        let home = (h as usize) % self.seg_cap;
        // Stay inside the PROBES window so get() can see the seeded row.
        for probe in 0..PROBES {
            let idx = (home + probe) % self.seg_cap;
            if seg.slots[idx].is_none() {
                seg.slots[idx] = Some((key, expiry));
                seg.len += 1;
                self.total_len.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        panic!("test seed found no free slot in probe window");
    }

    /// Corner-case eviction: find and remove one live entry with the lowest
    /// expiry across segments other than `skip_seg`. Bounded by the
    /// physical cap; only reachable when the insert probe window contained
    /// no live slot but the soft cap is already reached.
    fn evict_anywhere(&self, skip_seg: usize, _now: i64) -> Option<K> {
        for offset in 1..SEGMENTS {
            let idx = (skip_seg + offset) % SEGMENTS;
            let mut other = self.segs[idx].lock();
            if other.len == 0 {
                continue;
            }
            let mut victim: Option<usize> = None;
            let mut victim_expiry = i64::MAX;
            for (i, slot) in other.slots.iter().enumerate() {
                if let Some((_, expiry)) = slot
                    && *expiry < victim_expiry
                {
                    victim_expiry = *expiry;
                    victim = Some(i);
                }
            }
            if let Some(i) = victim {
                let (k, _) = other.slots[i].take().expect("live");
                other.len -= 1;
                self.total_len.fetch_sub(1, Ordering::Relaxed);
                return Some(k);
            }
        }
        None
    }

    pub fn remove(&self, key: &K) -> bool {
        let h = self.hash(key);
        let seg = &self.segs[self.seg_of(h)];
        let mut seg = seg.lock();
        let home = (h as usize) % self.seg_cap;
        for probe in 0..PROBES {
            let idx = (home + probe) % self.seg_cap;
            if let Some((k, _)) = seg.slots[idx]
                && k == *key
            {
                seg.slots[idx] = None;
                seg.len -= 1;
                self.total_len.fetch_sub(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    /// Remove only if the stored expiry still equals `expected` — the
    /// conditional form the DashMap callers use so a concurrent refresh of
    /// the same key survives an eviction race.
    pub fn remove_if(&self, key: &K, expected: i64) -> bool {
        let h = self.hash(key);
        let seg = &self.segs[self.seg_of(h)];
        let mut seg = seg.lock();
        let home = (h as usize) % self.seg_cap;
        for probe in 0..PROBES {
            let idx = (home + probe) % self.seg_cap;
            if let Some((k, expiry)) = seg.slots[idx]
                && k == *key
                && expiry == expected
            {
                seg.slots[idx] = None;
                seg.len -= 1;
                self.total_len.fetch_sub(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    /// Visit every live entry; `f` returning false stops the walk. Each
    /// segment is locked briefly in turn — callers do cold work (snapshot
    /// rebuilds, kernel sync, any-scope checks).
    pub fn for_each(&self, mut f: impl FnMut(K, i64) -> bool) {
        for seg in self.segs.iter() {
            let seg = seg.lock();
            for slot in seg.slots.iter() {
                if let Some((k, expiry)) = *slot
                    && !f(k, expiry)
                {
                    return;
                }
            }
        }
    }

    /// Sweep: drop entries where `keep` is false. O(physical cap); intended
    /// for the periodic expiry sweep, never the per-insert path.
    pub fn retain(&self, mut keep: impl FnMut(i64) -> bool) {
        for seg in self.segs.iter() {
            let mut seg = seg.lock();
            let mut removed = 0usize;
            for slot in seg.slots.iter_mut() {
                if let Some((_, expiry)) = *slot
                    && !keep(expiry)
                {
                    *slot = None;
                    removed += 1;
                }
            }
            seg.len -= removed;
            if removed > 0 {
                self.total_len.fetch_sub(removed, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_remove_roundtrip() {
        let map = BoundedScopedMap::new(1024);
        assert_eq!(map.insert(7u64, 100, 10, 1024), None);
        assert_eq!(map.get(&7), Some(100));
        assert_eq!(map.len(), 1);
        assert_eq!(map.insert(7, 200, 10, 1024), None);
        assert_eq!(map.get(&7), Some(200));
        assert_eq!(map.len(), 1);
        assert!(map.remove(&7));
        assert_eq!(map.len(), 0);
        assert!(!map.remove(&7));
    }

    #[test]
    fn physical_cap_is_enforced_by_eviction() {
        let map = BoundedScopedMap::new(64 * 64);
        for i in 0..(64 * 64 * 2) {
            map.insert(i as u64, i as i64 + 1000, 10, 64 * 64);
        }
        assert!(
            map.len() <= 64 * 64,
            "physical bound must hold under flood: {}",
            map.len()
        );
    }

    #[test]
    fn soft_cap_evicts_earliest_expiry() {
        let map = BoundedScopedMap::new(4096);
        for i in 0..100u64 {
            map.insert(i, 500, 10, 100);
        }
        assert_eq!(map.len(), 100);
        // Next insert must evict someone even though dead slots exist.
        let evicted = map.insert(999, 600, 10, 100);
        assert!(evicted.is_some());
        assert_eq!(map.len(), 100);
        assert_eq!(map.get(&999), Some(600));
    }

    #[test]
    fn expired_insert_is_a_remove() {
        let map = BoundedScopedMap::new(1024);
        map.insert(5u64, 100, 10, 1024);
        assert_eq!(map.insert(5, 5, 10, 1024), None);
        assert_eq!(map.get(&5), None);
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn retain_sweeps_dead_entries() {
        let map = BoundedScopedMap::new(1024);
        for i in 0..50u64 {
            map.insert(i, i as i64, 0, 1024);
        }
        map.retain(|expiry| expiry > 25);
        assert_eq!(map.len(), 24);
        assert_eq!(map.get(&10), None);
        assert_eq!(map.get(&40), Some(40));
    }

    #[test]
    fn remove_if_only_drops_matching_expiry() {
        let map = BoundedScopedMap::new(1024);
        map.insert(9u64, 100, 0, 1024);
        assert!(!map.remove_if(&9, 50));
        assert_eq!(map.get(&9), Some(100));
        assert!(map.remove_if(&9, 100));
        assert_eq!(map.get(&9), None);
    }

    #[test]
    fn concurrent_flood_never_exceeds_cap() {
        use std::sync::Arc;
        let map = Arc::new(BoundedScopedMap::new(64 * 64));
        let mut handles = Vec::new();
        for t in 0..8 {
            let m = map.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..20_000u64 {
                    m.insert(i.wrapping_mul(2654435761) ^ t, i as i64 + 10_000, 5, 64 * 64);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert!(map.len() <= 64 * 64);
    }
}
