use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};

use crate::memory_ticket::TicketBucket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::watch;

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);
pub static L4_CONNECTION_REGISTRY: LazyLock<L4ConnectionRegistry> =
    LazyLock::new(L4ConnectionRegistry::new);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum L4ConnectionProtocol {
    Http1,
    Http2,
    SniTcp,
}

impl L4ConnectionProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::Http2 => "http2",
            Self::SniTcp => "sni_tcp",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConnectionCancelReason {
    None,
    DefenseBlocked,
    ManagementShutdown,
    ServiceExit,
    ExplicitIdleReclaim,
    MemoryPressureShed,
}

impl ConnectionCancelReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::DefenseBlocked => "defense_blocked",
            Self::ManagementShutdown => "management_shutdown",
            Self::ServiceExit => "service_exit",
            Self::ExplicitIdleReclaim => "explicit_idle_reclaim",
            Self::MemoryPressureShed => "memory_pressure_shed",
        }
    }
}

#[derive(Clone)]
pub struct RegisteredConnection {
    pub id: u64,
    pub ip: IpAddr,
    pub protocol: L4ConnectionProtocol,
    pub started_at: Instant,
    pub cancel_rx: watch::Receiver<ConnectionCancelReason>,
    cancel_tx: watch::Sender<ConnectionCancelReason>,
}

impl RegisteredConnection {
    pub fn cancel(&self, reason: ConnectionCancelReason) {
        let _ = self.cancel_tx.send(reason);
    }

    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }
}

pub struct L4ConnectionGuard {
    id: u64,
    ip: IpAddr,
    addr: SocketAddr,
    protocol: L4ConnectionProtocol,
    active: AtomicBool,
}

impl L4ConnectionGuard {
    pub fn cancel_receiver(&self) -> watch::Receiver<ConnectionCancelReason> {
        L4_CONNECTION_REGISTRY
            .get(self.ip, self.protocol, self.id)
            .map(|conn| conn.cancel_rx)
            .unwrap_or_else(|| {
                let (_tx, rx) = watch::channel(ConnectionCancelReason::None);
                rx
            })
    }

    /// Re-register this connection under a different protocol (SNI takeover,
    /// HTTP/1 → HTTP/2 upgrade) while preserving any cancel that raced in.
    ///
    /// The old entry is removed first so a defense drain can only ever reach
    /// one entry: anything delivered before the swap is still readable from
    /// the old watch channel and is replayed onto the new one. Unregistering
    /// before re-registering is what closes the old-guard/new-guard race —
    /// a cancel cannot land on an entry that no longer exists.
    pub fn switch_protocol(
        self,
        new_protocol: L4ConnectionProtocol,
    ) -> (L4ConnectionGuard, watch::Receiver<ConnectionCancelReason>) {
        let old_rx = self.cancel_receiver();
        let ip = self.ip;
        let addr = self.addr;
        drop(self);
        let pending = *old_rx.borrow();
        let new_guard = L4_CONNECTION_REGISTRY.register(addr, new_protocol);
        let new_rx = new_guard.cancel_receiver();
        if pending != ConnectionCancelReason::None
            && let Some(conn) = L4_CONNECTION_REGISTRY.get(ip, new_protocol, new_guard.id)
        {
            conn.cancel(pending);
        }
        (new_guard, new_rx)
    }
}

impl Drop for L4ConnectionGuard {
    fn drop(&mut self) {
        if self.active.swap(false, Ordering::AcqRel) {
            L4_CONNECTION_REGISTRY.unregister(self.ip, self.addr, self.protocol, self.id);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct L4ConnectionRegistrySnapshot {
    pub total: usize,
    pub http1: usize,
    pub http2: usize,
    pub sni_tcp: usize,
}

pub struct L4ConnectionRegistry {
    by_key: DashMap<(IpAddr, L4ConnectionProtocol, u64), RegisteredConnection>,
    /// Secondary index for the request-hot path: a connection's admission
    /// ticket bucket is looked up by peer socket address so proxy code can
    /// reach it without knowing the registry id. The `u64` is the
    /// connection id — a guard for same-addr port reuse so a stale
    /// unregister cannot evict the newer connection's bucket.
    by_addr: DashMap<SocketAddr, (u64, Arc<TicketBucket>)>,
}

impl L4ConnectionRegistry {
    fn new() -> Self {
        Self {
            by_key: DashMap::new(),
            by_addr: DashMap::new(),
        }
    }

    pub fn register(
        &self,
        addr: SocketAddr,
        protocol: L4ConnectionProtocol,
    ) -> L4ConnectionGuard {
        let ip = addr.ip();
        let id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        self.by_addr
            .insert(addr, (id, Arc::new(TicketBucket::new(std::sync::LazyLock::force(&crate::memory_governor::MEMORY_GOVERNOR)))));
        let (cancel_tx, cancel_rx) = watch::channel(ConnectionCancelReason::None);
        self.by_key.insert(
            (ip, protocol, id),
            RegisteredConnection {
                id,
                ip,
                protocol,
                started_at: Instant::now(),
                cancel_rx,
                cancel_tx,
            },
        );
        L4ConnectionGuard {
            id,
            ip,
            addr,
            protocol,
            active: AtomicBool::new(true),
        }
    }

    fn get(
        &self,
        ip: IpAddr,
        protocol: L4ConnectionProtocol,
        id: u64,
    ) -> Option<RegisteredConnection> {
        self.by_key
            .get(&(ip, protocol, id))
            .map(|entry| entry.value().clone())
    }

    fn unregister(&self, ip: IpAddr, addr: SocketAddr, protocol: L4ConnectionProtocol, id: u64) {
        self.by_key.remove(&(ip, protocol, id));
        // Port reuse: only remove when the entry still belongs to this
        // connection id — a newer connection may already hold the addr.
        self.by_addr.remove_if(&addr, |_, v| v.0 == id);
    }

    /// Connection's admission ticket bucket for the request hot path.
    /// `None` for unregistered transports (e.g. H3) — callers fall back to
    /// direct per-class admission with identical semantics.
    pub fn ticket_for(&self, addr: &SocketAddr) -> Option<Arc<TicketBucket>> {
        self.by_addr.get(addr).map(|e| e.value().1.clone())
    }

    pub fn drain_ip(&self, ip: IpAddr) -> usize {
        self.drain_ip_with_reason(ip, ConnectionCancelReason::DefenseBlocked)
    }

    pub fn drain_ip_with_reason(&self, ip: IpAddr, reason: ConnectionCancelReason) -> usize {
        let conns = self
            .by_key
            .iter()
            .filter(|entry| entry.key().0 == ip)
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        let count = conns.len();
        for conn in conns {
            conn.cancel(reason);
        }
        count
    }

    pub fn drain_matching<F>(&self, predicate: F) -> usize
    where
        F: FnMut(&RegisteredConnection) -> bool,
    {
        self.drain_matching_with_reason(predicate, ConnectionCancelReason::DefenseBlocked)
    }

    pub fn drain_matching_with_reason<F>(
        &self,
        mut predicate: F,
        reason: ConnectionCancelReason,
    ) -> usize
    where
        F: FnMut(&RegisteredConnection) -> bool,
    {
        let conns = self
            .by_key
            .iter()
            .filter_map(|entry| {
                let conn = entry.value();
                predicate(conn).then(|| conn.clone())
            })
            .collect::<Vec<_>>();
        let count = conns.len();
        for conn in conns {
            conn.cancel(reason);
        }
        count
    }

    pub fn snapshot(&self) -> L4ConnectionRegistrySnapshot {
        let mut snapshot = L4ConnectionRegistrySnapshot {
            total: self.by_key.len(),
            ..Default::default()
        };
        for entry in self.by_key.iter() {
            match entry.key().1 {
                L4ConnectionProtocol::Http1 => snapshot.http1 += 1,
                L4ConnectionProtocol::Http2 => snapshot.http2 += 1,
                L4ConnectionProtocol::SniTcp => snapshot.sni_tcp += 1,
            }
        }
        snapshot
    }
}

pub fn register(addr: SocketAddr, protocol: L4ConnectionProtocol) -> L4ConnectionGuard {
    L4_CONNECTION_REGISTRY.register(addr, protocol)
}

/// Hot-path accessor for the connection's admission ticket bucket.
pub fn ticket_for(addr: &SocketAddr) -> Option<Arc<TicketBucket>> {
    L4_CONNECTION_REGISTRY.ticket_for(addr)
}

pub fn drain_ip(ip: IpAddr) -> usize {
    L4_CONNECTION_REGISTRY.drain_ip(ip)
}

pub fn snapshot() -> L4ConnectionRegistrySnapshot {
    L4_CONNECTION_REGISTRY.snapshot()
}

/// Serializes tests that touch the shared `L4_CONNECTION_REGISTRY` — global
/// drains (e.g. memory-shed age ladders) can cancel connections registered
/// by another test running in parallel.
#[cfg(test)]
pub(crate) static REGISTRY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn registry_drains_matching_ip() {
        let _serial = REGISTRY_TEST_LOCK.lock().unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let guard = register(SocketAddr::new(ip, 40001), L4ConnectionProtocol::Http2);
        let _other_guard =
            register(SocketAddr::new(other, 40002), L4ConnectionProtocol::Http2);
        let mut rx = guard.cancel_receiver();

        assert_eq!(drain_ip(ip), 1);
        assert_eq!(
            *rx.borrow_and_update(),
            ConnectionCancelReason::DefenseBlocked
        );

        drop(guard);
    }

    #[test]
    fn switch_protocol_carries_cancel_that_raced_before_the_swap() {
        let _serial = REGISTRY_TEST_LOCK.lock().unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
        let guard = register(SocketAddr::new(ip, 40011), L4ConnectionProtocol::Http1);

        assert_eq!(drain_ip(ip), 1);
        let (_new_guard, mut new_rx) = guard.switch_protocol(L4ConnectionProtocol::Http2);
        assert_eq!(
            *new_rx.borrow_and_update(),
            ConnectionCancelReason::DefenseBlocked
        );
    }

    #[test]
    fn switch_protocol_keeps_new_entry_cancellable_and_noop_without_cancel() {
        let _serial = REGISTRY_TEST_LOCK.lock().unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12));
        let (guard, mut rx) = register(SocketAddr::new(ip, 40012), L4ConnectionProtocol::Http1)
            .switch_protocol(L4ConnectionProtocol::SniTcp);

        assert_eq!(*rx.borrow(), ConnectionCancelReason::None);
        assert_eq!(drain_ip(ip), 1);
        assert_eq!(
            *rx.borrow_and_update(),
            ConnectionCancelReason::DefenseBlocked
        );
        drop(guard);
        assert_eq!(drain_ip(ip), 0);
    }
}
