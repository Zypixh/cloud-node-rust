use dashmap::DashMap;
use quinn::{Connection, Endpoint};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use crate::origin_h3_state::OriginH3Key;

const H3_POOL_IDLE: Duration = Duration::from_secs(120);
const H3_POOL_MAX_ENTRIES: usize = 4_096;

struct PooledH3Connection {
    endpoint: Endpoint,
    connection: Connection,
    last_used: Instant,
}

static H3_CONNECTION_POOL: LazyLock<DashMap<OriginH3Key, PooledH3Connection>> =
    LazyLock::new(DashMap::new);

pub fn take(key: &OriginH3Key) -> Option<(Endpoint, Connection)> {
    sweep_idle();
    let (_, pooled) = H3_CONNECTION_POOL.remove(key)?;
    if pooled.connection.close_reason().is_some() {
        return None;
    }
    Some((pooled.endpoint, pooled.connection))
}

pub fn offer(key: OriginH3Key, endpoint: Endpoint, connection: Connection) {
    if connection.close_reason().is_some() {
        return;
    }
    sweep_idle();
    if H3_CONNECTION_POOL.len() >= H3_POOL_MAX_ENTRIES {
        return;
    }
    H3_CONNECTION_POOL.insert(
        key,
        PooledH3Connection {
            endpoint,
            connection,
            last_used: Instant::now(),
        },
    );
}

fn sweep_idle() {
    let cutoff = Instant::now()
        .checked_sub(H3_POOL_IDLE)
        .unwrap_or_else(Instant::now);
    H3_CONNECTION_POOL
        .retain(|_, entry| entry.last_used >= cutoff && entry.connection.close_reason().is_none());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_sweep_removes_stale_entries_without_panicking() {
        sweep_idle();
        assert!(H3_CONNECTION_POOL.is_empty());
    }
}
