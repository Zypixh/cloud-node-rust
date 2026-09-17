//! Per-connection admission tickets (request-workspace pool).
//!
//! Request-scoped admissions (request/response body WAF, response
//! transforms, H2 streams) previously each performed their own global
//! counter RMW per request. Under sustained QPS those adds are pure
//! cacheline contention: every core hammers the same padded counter for
//! work that is private to one connection.
//!
//! A `TicketBucket` is attached to each registered L4 connection (via
//! `L4ConnectionRegistry`'s `by_addr` index) and holds a pool of bytes
//! checked out from the governor's `request_workspace` ledger once, in
//! chunks. Request-scoped classes then *spend* from the bucket with a local
//! CAS on a connection-private line — uncontended, ~5ns — and only an empty
//! bucket reaches the global ledger.
//!
//! # Semantics (approved isolation change)
//!
//! Per-class isolation is replaced by a per-connection pool: inside a
//! connection, classes share the bucket, so heavy use of one (say request
//! body WAF) can starve another (transform) on that same connection — but
//! never a *different* connection's pool. Globally the workspace ledger
//! keeps the same scale of bound the shared-connection byte budget had.
//! Failure semantics at each call site are unchanged: a spend that cannot
//! be satisfied returns `None`, which is exactly what `try_admit` returned,
//! and the class's own reject counter is still incremented.
//!
//! # Float and refund policy
//!
//! - Refill draws `need + TICKET_FLOAT_BYTES` so a stream of small charges
//!   (H2 streams, small WAF buffers) amortizes to one global op per
//!   ~`FLOAT/charge` spends. If the float top-up cannot be afforded the
//!   refill retries with the bare need, then fails closed.
//! - `release` returns bytes to the bucket; once the balance exceeds
//!   `TICKET_FLOAT_CAP_BYTES` the excess is refunded to the global ledger,
//!   so a connection that ran a 16MiB transform does not idle-hold the
//!   whole charge. Idle-held budget is capped at the float (≤1.25MiB) per
//!   working connection — and zero for connections that never spend.
//! - Dropping the bucket (connection close) refunds everything still held.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::memory_governor::{
    AdmissionClass, MEMORY_GOVERNOR, MemoryGovernor, StaticAdmissionPermit,
};

/// Over-fetch margin added to each bucket refill: small charges (H2 streams
/// are 16KiB) amortize to one global ledger op per ~16 spends.
const TICKET_FLOAT_BYTES: u64 = 256 * 1024;

/// Maximum balance a bucket may hold between requests. Larger releases
/// refund the excess to the global workspace ledger, bounding idle-held
/// budget at `CAP + in-flight` per connection.
const TICKET_FLOAT_CAP_BYTES: u64 = 1024 * 1024;

/// Per-connection pool of pre-admitted workspace bytes.
pub struct TicketBucket {
    /// Spendable bytes currently held from the workspace ledger.
    balance: AtomicU64,
    /// Total bytes checked out (balance + in-flight spends); refunded on drop.
    held: AtomicU64,
    governor: &'static MemoryGovernor,
}

impl TicketBucket {
    pub fn new(governor: &'static MemoryGovernor) -> Self {
        Self {
            balance: AtomicU64::new(0),
            held: AtomicU64::new(0),
            governor,
        }
    }

    /// Draw `bytes` from the local pool without touching the global ledger.
    /// CAS loop on a connection-private line — uncontended in the common
    /// case (HTTP/2 streams on one connection can race, so CAS is required).
    fn try_draw(&self, bytes: u64) -> bool {
        let mut cur = self.balance.load(Ordering::Acquire);
        loop {
            if cur < bytes {
                return false;
            }
            match self.balance.compare_exchange_weak(
                cur,
                cur - bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => cur = observed,
            }
        }
    }

    /// Pull `need` bytes (plus float margin when affordable) from the global
    /// workspace ledger into the local pool.
    fn refill(&self, need: u64) -> bool {
        let want = need.saturating_add(TICKET_FLOAT_BYTES);
        if self.governor.try_admit_workspace(want) {
            self.held.fetch_add(want, Ordering::AcqRel);
            self.balance.fetch_add(want, Ordering::AcqRel);
            return true;
        }
        // Float unaffordable: still try the bare need so a tight ledger
        // degrades to per-spend global accounting instead of rejecting.
        if self.governor.try_admit_workspace(need) {
            self.held.fetch_add(need, Ordering::AcqRel);
            self.balance.fetch_add(need, Ordering::AcqRel);
            return true;
        }
        false
    }

    /// Spend `bytes` from the pool for `class`, refilling from the global
    /// ledger when the local balance cannot cover it. Returns `None` (and
    /// records the class reject) only when the global ledger cannot cover
    /// the spend — identical fail-closed contract to `try_admit`.
    pub fn spend(self: &Arc<Self>, class: AdmissionClass, bytes: u64) -> Option<TicketPermit> {
        let bytes = bytes.max(1);
        // Bounded retries: a racing stream on the same connection could
        // drain a fresh refill before we get to draw from it.
        for _ in 0..3 {
            if self.try_draw(bytes) {
                return Some(TicketPermit {
                    bucket: Arc::clone(self),
                    bytes,
                });
            }
            let cur = self.balance.load(Ordering::Relaxed);
            if !self.refill(bytes.saturating_sub(cur)) {
                break;
            }
        }
        self.governor.record_reject(class);
        None
    }

    /// Return `bytes` to the pool; refund the excess over the float cap to
    /// the global ledger so big one-off charges (a 16MiB transform) are not
    /// idle-held for the connection's remaining lifetime.
    fn release(&self, bytes: u64) {
        let mut cur = self.balance.fetch_add(bytes, Ordering::AcqRel) + bytes;
        while cur > TICKET_FLOAT_CAP_BYTES {
            let excess = cur - TICKET_FLOAT_CAP_BYTES;
            match self.balance.compare_exchange_weak(
                cur,
                cur - excess,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.held.fetch_sub(excess, Ordering::AcqRel);
                    self.governor.workspace_refund(excess);
                    break;
                }
                Err(observed) => cur = observed,
            }
        }
    }

    /// Bytes currently held from the workspace ledger (observability).
    pub fn held_bytes(&self) -> u64 {
        self.held.load(Ordering::Relaxed)
    }
}

impl Drop for TicketBucket {
    fn drop(&mut self) {
        let held = self.held.swap(0, Ordering::AcqRel);
        if held > 0 {
            self.governor.workspace_refund(held);
        }
    }
}

/// RAII release of a pooled spend: dropping returns the bytes to the
/// owning bucket (which may refund the global ledger past the float cap).
pub struct TicketPermit {
    bucket: Arc<TicketBucket>,
    bytes: u64,
}

impl Drop for TicketPermit {
    fn drop(&mut self) {
        self.bucket.release(self.bytes);
    }
}

/// Permit type stored in `ProxyCTX` for pooled classes: either a bucket
/// spend (registered connection) or a plain class admission (paths where no
/// connection ticket exists, e.g. unregistered sessions).
pub enum WorkspacePermit {
    Pooled(TicketPermit),
    Direct(StaticAdmissionPermit),
}

/// Pooled admission for request-scoped classes: draw from the connection's
/// ticket bucket when one exists, else fall back to a direct class admit so
/// unregistered paths keep identical semantics.
pub fn admit_pooled(
    bucket: Option<&Arc<TicketBucket>>,
    class: AdmissionClass,
    bytes: u64,
) -> Option<WorkspacePermit> {
    match bucket {
        Some(b) => b.spend(class, bytes).map(WorkspacePermit::Pooled),
        None => MEMORY_GOVERNOR
            .try_admit(class)
            .map(WorkspacePermit::Direct),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_governor::MemoryGovernor;

    fn leaked_governor(available: u64) -> &'static MemoryGovernor {
        let g: &'static MemoryGovernor = Box::leak(Box::new(MemoryGovernor::new()));
        let now = crate::utils::time::system_timestamp_millis().max(0) as u64;
        // Seed the cached-memory inputs directly; seed_governor_memory in
        // governor tests is module-private.
        g.seed_cached_for_test(available * 4, available, 65536, 0, now);
        g
    }

    #[test]
    fn bucket_spends_locally_after_first_refill() {
        let g = leaked_governor(256 * 1024 * 1024);
        let bucket = Arc::new(TicketBucket::new(g));

        let p1 = bucket
            .spend(AdmissionClass::Http2Stream, 16 * 1024)
            .expect("first spend refills");
        let held_after = bucket.held_bytes();
        assert!(held_after >= 16 * 1024);
        let ledger_after_first = g.request_workspace_used_bytes();
        assert_eq!(ledger_after_first, held_after);

        // Second small spend draws locally — global ledger unchanged.
        let p2 = bucket
            .spend(AdmissionClass::Http2Stream, 16 * 1024)
            .expect("second spend is local");
        assert_eq!(g.request_workspace_used_bytes(), ledger_after_first);

        drop(p1);
        drop(p2);
        // 32KiB back in balance, under the cap — bucket keeps it.
        assert!(bucket.held_bytes() >= 32 * 1024);
    }

    #[test]
    fn release_refunds_excess_over_cap() {
        let g = leaked_governor(256 * 1024 * 1024);
        let bucket = Arc::new(TicketBucket::new(g));
        let big = 8 * 1024 * 1024; // > TICKET_FLOAT_CAP_BYTES
        let p = bucket
            .spend(AdmissionClass::ResponseTransform, big)
            .expect("big spend refills");
        let held_in_flight = bucket.held_bytes();
        drop(p);
        // After release, idle balance is capped at the float cap.
        assert!(bucket.held_bytes() <= TICKET_FLOAT_CAP_BYTES);
        assert!(bucket.held_bytes() < held_in_flight);
    }

    #[test]
    fn spend_fails_closed_when_ledger_full() {
        let g = leaked_governor(64 * 1024);
        let bucket = Arc::new(TicketBucket::new(g));
        let need = 512 * 1024 * 1024; // far beyond any budget
        assert!(bucket.spend(AdmissionClass::RequestBodyWaf, need).is_none());
        assert_eq!(g.request_workspace_used_bytes(), 0);
    }

    #[test]
    fn bucket_drop_refunds_held() {
        let g = leaked_governor(256 * 1024 * 1024);
        let bucket = Arc::new(TicketBucket::new(g));
        let p = bucket
            .spend(AdmissionClass::Http2Stream, 16 * 1024)
            .unwrap();
        drop(p);
        let held = bucket.held_bytes();
        assert!(held > 0);
        drop(bucket); // last Arc besides the permit's? permit dropped already
        assert_eq!(g.request_workspace_used_bytes(), 0);
    }

    #[test]
    fn unregistered_path_falls_back_to_direct_admit() {
        let g = leaked_governor(256 * 1024 * 1024);
        let _ = g; // admit_pooled(None,...) uses MEMORY_GOVERNOR global;
        // just assert the fallback shape — the global governor may or may
        // not be budgeted in tests, but a None bucket never panics.
        let permit = admit_pooled(None, AdmissionClass::RequestBodyWaf, 2 * 1024 * 1024);
        match permit {
            Some(WorkspacePermit::Direct(_)) | None => {}
            Some(WorkspacePermit::Pooled(_)) => panic!("None bucket must not pool"),
        }
    }
}
