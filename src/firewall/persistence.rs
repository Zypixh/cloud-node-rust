use serde::{Deserialize, Serialize};
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::LazyLock as Lazy;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use tracing::warn;

const BLOCK_PREFIX: &str = "FWBLK_V1_";
const FLUSH_THRESHOLD: usize = 1024;
/// Pending-queue records are ~4x a scoped-state entry (~400B vs ~96B), so the
/// queue takes a quarter of the same governor-derived budget.
const PENDING_CAPACITY_DIVISOR: usize = 4;
const PENDING_CAPACITY_MIN: usize = 4_096;
const PENDING_CAPACITY_MAX: usize = 2_000_000;
const PENDING_CAPACITY_WARN_INTERVAL_SECS: i64 = 60;
static PENDING_CAPACITY_WARN_AT: AtomicI64 = AtomicI64::new(0);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallBlockRecord {
    pub target: String,
    pub server_id: i64,
    pub scope: String,
    pub source: String,
    pub reason: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub kernel_wanted: bool,
    pub kernel_applied: bool,
    pub kernel_status: String,
}

impl FirewallBlockRecord {
    pub fn runtime(
        target: String,
        server_id: i64,
        scope: String,
        expires_at: i64,
        kernel_wanted: bool,
    ) -> Self {
        let now = crate::utils::time::now_timestamp();
        Self {
            target,
            server_id,
            scope,
            source: "runtime".to_string(),
            reason: "local runtime block".to_string(),
            expires_at,
            created_at: now,
            updated_at: now,
            kernel_wanted,
            kernel_applied: false,
            kernel_status: if kernel_wanted {
                "pending".to_string()
            } else {
                "not_applicable".to_string()
            },
        }
    }

    pub fn key(&self) -> String {
        block_key(&self.scope, self.server_id, &self.target)
    }
}

enum PendingOp {
    Upsert(FirewallBlockRecord),
    Delete {
        scope: String,
        server_id: i64,
        target: String,
    },
}

#[derive(Default)]
struct PendingState {
    upserts: HashMap<String, FirewallBlockRecord>,
    deletes: HashSet<String>,
}

static PENDING: Lazy<Mutex<PendingState>> = Lazy::new(|| Mutex::new(PendingState::default()));

fn block_key(scope: &str, server_id: i64, target: &str) -> String {
    format!("{BLOCK_PREFIX}{scope}_{server_id}_{target}")
}

pub fn enqueue_upsert(record: FirewallBlockRecord) {
    enqueue(PendingOp::Upsert(record));
}

pub fn enqueue_delete(scope: &str, server_id: i64, target: &str) {
    enqueue(PendingOp::Delete {
        scope: scope.to_string(),
        server_id,
        target: target.to_string(),
    });
}

fn pending_queue_capacity() -> usize {
    (crate::memory_governor::MEMORY_GOVERNOR.firewall_state_map_capacity()
        / PENDING_CAPACITY_DIVISOR)
        .clamp(PENDING_CAPACITY_MIN, PENDING_CAPACITY_MAX)
}

fn warn_pending_capacity_full(area: &str, len: usize, capacity: usize) {
    let now = crate::utils::time::now_timestamp();
    let last = PENDING_CAPACITY_WARN_AT.load(Ordering::Relaxed);
    if now.saturating_sub(last) < PENDING_CAPACITY_WARN_INTERVAL_SECS {
        return;
    }
    if PENDING_CAPACITY_WARN_AT
        .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        warn!(
            "firewall persistence pending queue full for {}; len={} capacity={}, dropping entries",
            area, len, capacity
        );
    }
}

/// Max-heap entry ordered by `expires_at` so the earliest-expiring pending
/// upserts can be evicted without `Ord` on the record type.
struct EarliestPending {
    expires_at: i64,
    key: String,
}
impl PartialEq for EarliestPending {
    fn eq(&self, other: &Self) -> bool {
        self.expires_at == other.expires_at
    }
}
impl Eq for EarliestPending {}
impl PartialOrd for EarliestPending {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for EarliestPending {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.expires_at.cmp(&other.expires_at)
    }
}

/// Evict the earliest-expiring pending upserts until the queue is back under
/// `capacity`. A dropped upsert only loses on-disk persistence — enforcement
/// still lives in `WafStateManager`'s in-memory maps.
fn trim_pending_upserts_with_capacity(pending: &mut PendingState, capacity: usize) -> usize {
    let over = pending.upserts.len().saturating_sub(capacity);
    if over == 0 {
        return 0;
    }
    // Small queues evict exactly `over`; large queues free ~6% headroom per
    // scan so a sustained enqueue storm amortizes the O(n) pass.
    let batch = over.max(capacity / 16).min(1024).min(pending.upserts.len());
    let mut heap: BinaryHeap<EarliestPending> = BinaryHeap::with_capacity(batch + 1);
    for (key, record) in pending.upserts.iter() {
        heap.push(EarliestPending {
            expires_at: record.expires_at,
            key: key.clone(),
        });
        if heap.len() > batch {
            heap.pop();
        }
    }
    let mut dropped = 0usize;
    for victim in heap {
        if pending.upserts.remove(&victim.key).is_some() {
            dropped += 1;
        }
    }
    if dropped > 0 {
        crate::pipeline_metrics::add(
            crate::pipeline_metrics::PipelineCounter::FirewallPendingDropped,
            dropped as u64,
        );
        warn_pending_capacity_full("upserts", pending.upserts.len(), capacity);
    }
    dropped
}

fn trim_pending_deletes_with_capacity(pending: &mut PendingState, capacity: usize) -> usize {
    let over = pending.deletes.len().saturating_sub(capacity);
    if over == 0 {
        return 0;
    }
    // A dropped tombstone means a deleted block can resurrect on restart —
    // bounded by `cleanup_expired` since every record carries expires_at.
    // Drop arbitrary excess; all pending deletes are equally droppable.
    let victims: Vec<String> = pending.deletes.iter().take(over).cloned().collect();
    let mut dropped = 0usize;
    for key in victims {
        if pending.deletes.remove(&key) {
            dropped += 1;
        }
    }
    if dropped > 0 {
        crate::pipeline_metrics::add(
            crate::pipeline_metrics::PipelineCounter::FirewallPendingDropped,
            dropped as u64,
        );
        warn_pending_capacity_full("deletes", pending.deletes.len(), capacity);
    }
    dropped
}

fn trim_pending_with_capacity(pending: &mut PendingState, capacity: usize) {
    trim_pending_upserts_with_capacity(pending, capacity);
    trim_pending_deletes_with_capacity(pending, capacity);
}

fn lock_pending() -> std::sync::MutexGuard<'static, PendingState> {
    // Pending state stays internally consistent across a panic — recover the
    // guard instead of silently dropping the persistence operation.
    PENDING.lock().unwrap_or_else(|e| e.into_inner())
}

fn enqueue(op: PendingOp) {
    let should_flush = {
        let mut pending = lock_pending();
        match op {
            PendingOp::Upsert(record) => {
                let key = record.key();
                pending.deletes.remove(&key);
                pending.upserts.insert(key, record);
            }
            PendingOp::Delete {
                scope,
                server_id,
                target,
            } => {
                let key = block_key(&scope, server_id, &target);
                pending.upserts.remove(&key);
                pending.deletes.insert(key);
            }
        }
        trim_pending_with_capacity(&mut pending, pending_queue_capacity());
        pending.upserts.len() + pending.deletes.len() >= FLUSH_THRESHOLD
    };
    if should_flush {
        let _ = flush_pending();
    }
}

pub fn flush_pending() -> bool {
    let (upserts, deletes) = {
        let mut pending = lock_pending();
        if pending.upserts.is_empty() && pending.deletes.is_empty() {
            return true;
        }
        let upserts = std::mem::take(&mut pending.upserts);
        let deletes = std::mem::take(&mut pending.deletes);
        (upserts, deletes)
    };

    let upsert_records = upserts.into_iter().collect::<Vec<_>>();
    let delete_records = deletes.into_iter().collect::<Vec<_>>();

    let mut puts = Vec::with_capacity(upsert_records.len());
    for (key, record) in &upsert_records {
        match serde_json::to_vec(&record) {
            Ok(bytes) => puts.push((key.clone(), bytes)),
            Err(err) => warn!("failed to serialize firewall block record: {}", err),
        }
    }
    let ok = crate::metrics::storage::STORAGE.write_raw_batch(puts, delete_records.clone());
    if !ok {
        warn!("failed to flush firewall block records to storage");
        {
            let mut pending = lock_pending();
            for (key, record) in upsert_records {
                if !pending.deletes.contains(&key) {
                    pending.upserts.insert(key, record);
                }
            }
            for key in delete_records {
                pending.upserts.remove(&key);
                pending.deletes.insert(key);
            }
            // Re-queued records plus whatever arrived during the failed write
            // can exceed the cap — trim so a dead storage backend plus a
            // block storm cannot grow the queue without bound.
            trim_pending_with_capacity(&mut pending, pending_queue_capacity());
        }
    }
    ok
}

pub fn start_flush_task() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let _ = flush_pending();
        }
    });
}

pub fn load_active_runtime_blocks(now: i64) -> Vec<FirewallBlockRecord> {
    crate::metrics::storage::STORAGE
        .scan_json_prefix::<FirewallBlockRecord>(BLOCK_PREFIX)
        .into_iter()
        .filter_map(|(_, record)| {
            (record.expires_at > now && is_runtime_source(&record.source)).then_some(record)
        })
        .collect()
}

pub fn load_active_blacklist_records(now: i64) -> Vec<FirewallBlockRecord> {
    crate::metrics::storage::STORAGE
        .scan_json_prefix::<FirewallBlockRecord>(BLOCK_PREFIX)
        .into_iter()
        .filter_map(|(_, record)| (record.expires_at > now).then_some(record))
        .collect()
}

pub fn cleanup_expired(now: i64) -> usize {
    let expired = crate::metrics::storage::STORAGE
        .scan_json_prefix::<FirewallBlockRecord>(BLOCK_PREFIX)
        .into_iter()
        .filter_map(|(key, record)| (record.expires_at <= now).then_some(key))
        .collect::<Vec<_>>();
    let count = expired.len();
    if count > 0 {
        let _ = crate::metrics::storage::STORAGE.write_raw_batch(Vec::new(), expired);
    }
    count
}

fn is_runtime_source(source: &str) -> bool {
    matches!(source, "runtime" | "legacy_json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_persistence_record_key_uses_fixed_namespace() {
        let record = FirewallBlockRecord::runtime(
            "192.0.2.1".to_string(),
            42,
            "server".to_string(),
            99,
            true,
        );
        assert_eq!(record.key(), "FWBLK_V1_server_42_192.0.2.1");
    }

    #[test]
    fn pending_upserts_trim_evicts_earliest_expiry() {
        let mut pending = PendingState::default();
        // cap 4, insert 6 records — ip(1) and ip(2) expire earliest.
        for n in 1..=6u8 {
            let record = FirewallBlockRecord {
                expires_at: n as i64,
                ..FirewallBlockRecord::runtime(
                    format!("192.0.2.{n}"),
                    7,
                    "server".to_string(),
                    1000,
                    false,
                )
            };
            pending.upserts.insert(record.key(), record);
        }
        let dropped = trim_pending_upserts_with_capacity(&mut pending, 4);
        assert_eq!(dropped, 2);
        assert_eq!(pending.upserts.len(), 4);
        // The two earliest-expiring records must be gone.
        assert!(!pending.upserts.contains_key("FWBLK_V1_server_7_192.0.2.1"));
        assert!(!pending.upserts.contains_key("FWBLK_V1_server_7_192.0.2.2"));
        assert!(pending.upserts.contains_key("FWBLK_V1_server_7_192.0.2.6"));
    }

    #[test]
    fn pending_deletes_trim_bounds_tombstones() {
        let mut pending = PendingState::default();
        for n in 0..8u8 {
            pending
                .deletes
                .insert(block_key("server", 7, &format!("192.0.2.{n}")));
        }
        let dropped = trim_pending_deletes_with_capacity(&mut pending, 4);
        assert_eq!(dropped, 4);
        assert_eq!(pending.deletes.len(), 4);
    }
}
