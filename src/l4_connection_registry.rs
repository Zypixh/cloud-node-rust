use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::LazyLock;
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

#[derive(Clone)]
pub struct RegisteredConnection {
    pub id: u64,
    pub ip: IpAddr,
    pub protocol: L4ConnectionProtocol,
    pub started_at: Instant,
    pub cancel_rx: watch::Receiver<bool>,
    cancel_tx: watch::Sender<bool>,
}

impl RegisteredConnection {
    pub fn cancel(&self) {
        let _ = self.cancel_tx.send(true);
    }

    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }
}

pub struct L4ConnectionGuard {
    id: u64,
    ip: IpAddr,
    protocol: L4ConnectionProtocol,
    active: AtomicBool,
}

impl L4ConnectionGuard {
    pub fn cancel_receiver(&self) -> watch::Receiver<bool> {
        L4_CONNECTION_REGISTRY
            .get(self.ip, self.protocol, self.id)
            .map(|conn| conn.cancel_rx)
            .unwrap_or_else(|| {
                let (_tx, rx) = watch::channel(false);
                rx
            })
    }
}

impl Drop for L4ConnectionGuard {
    fn drop(&mut self) {
        if self.active.swap(false, Ordering::AcqRel) {
            L4_CONNECTION_REGISTRY.unregister(self.ip, self.protocol, self.id);
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
}

impl L4ConnectionRegistry {
    fn new() -> Self {
        Self {
            by_key: DashMap::new(),
        }
    }

    pub fn register(&self, ip: IpAddr, protocol: L4ConnectionProtocol) -> L4ConnectionGuard {
        let id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let (cancel_tx, cancel_rx) = watch::channel(false);
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

    fn unregister(&self, ip: IpAddr, protocol: L4ConnectionProtocol, id: u64) {
        self.by_key.remove(&(ip, protocol, id));
    }

    pub fn drain_ip(&self, ip: IpAddr) -> usize {
        let conns = self
            .by_key
            .iter()
            .filter(|entry| entry.key().0 == ip)
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        let count = conns.len();
        for conn in conns {
            conn.cancel();
        }
        count
    }

    pub fn drain_matching<F>(&self, mut predicate: F) -> usize
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
            conn.cancel();
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

pub fn register(ip: IpAddr, protocol: L4ConnectionProtocol) -> L4ConnectionGuard {
    L4_CONNECTION_REGISTRY.register(ip, protocol)
}

pub fn drain_ip(ip: IpAddr) -> usize {
    L4_CONNECTION_REGISTRY.drain_ip(ip)
}

pub fn snapshot() -> L4ConnectionRegistrySnapshot {
    L4_CONNECTION_REGISTRY.snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn registry_drains_matching_ip() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let guard = register(ip, L4ConnectionProtocol::Http2);
        let _other_guard = register(other, L4ConnectionProtocol::Http2);
        let rx = guard.cancel_receiver();

        assert_eq!(drain_ip(ip), 1);
        assert!(rx.has_changed().unwrap_or(false));

        drop(guard);
    }
}
