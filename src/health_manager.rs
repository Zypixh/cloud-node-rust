use dashmap::DashMap;
use pingora_load_balancing::{
    LoadBalancer,
    selection::{Consistent, RoundRobin},
};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// Represents a single health check target.
struct HealthCheckItem<S: pingora_load_balancing::selection::BackendSelection> {
    lb: Weak<LoadBalancer<S>>,
    frequency: Duration,
    last_check: Instant,
}

/// A scalable manager for active health checks.
/// Handles millions of upstreams by using a pooled executor and rate-limiting.
pub struct GlobalHealthManager {
    /// Key: Unique ID for the upstream pool (e.g. Server ID)
    registry: DashMap<i64, HealthCheckItem<RoundRobin>>,
    /// Registry for L2 (Parent) pools using consistent hashing
    parent_registry: DashMap<i64, HealthCheckItem<Consistent>>,
    /// Global limit on concurrent probes
    concurrency_limiter: Arc<Semaphore>,
}

impl GlobalHealthManager {
    /// Creates a new manager with a specified maximum concurrency.
    pub fn new(max_concurrency: usize) -> Arc<Self> {
        Arc::new(Self {
            registry: DashMap::new(),
            parent_registry: DashMap::new(),
            concurrency_limiter: Arc::new(Semaphore::new(max_concurrency)),
        })
    }

    /// Registers a load balancer for periodic health monitoring.
    pub fn register(&self, id: i64, lb: Arc<LoadBalancer<RoundRobin>>, frequency: Duration) {
        info!(
            "Registering health check for upstream pool {} (Frequency: {:?})",
            id, frequency
        );
        self.registry.insert(
            id,
            HealthCheckItem {
                lb: Arc::downgrade(&lb),
                frequency,
                last_check: Instant::now(), // Set to now because we trigger it immediately below
            },
        );

        // Trigger an immediate check in the background
        let lb_clone = lb.clone();
        tokio::spawn(async move {
            debug!("Immediate health check for pool {}", id);
            lb_clone.backends().run_health_check(true).await;

            let backends = lb_clone.backends();
            let backends_set = backends.get_backend();
            for backend in backends_set.iter() {
                if backends.ready(backend) {
                    debug!("Pool {}: Backend {} is HEALTHY (Initial)", id, backend.addr);
                } else {
                    warn!(
                        "Pool {}: Backend {} is UNHEALTHY (Initial)",
                        id, backend.addr
                    );
                }
            }
        });
    }

    /// Registers an L2 (Parent) load balancer for periodic health monitoring.
    pub fn register_parent(
        &self,
        cluster_id: i64,
        lb: Arc<LoadBalancer<Consistent>>,
        frequency: Duration,
    ) {
        info!(
            "Registering health check for L2 pool cluster {} (Frequency: {:?})",
            cluster_id, frequency
        );
        self.parent_registry.insert(
            cluster_id,
            HealthCheckItem {
                lb: Arc::downgrade(&lb),
                frequency,
                last_check: Instant::now(),
            },
        );

        // Immediate check
        let lb_clone = lb.clone();
        tokio::spawn(async move {
            lb_clone.backends().run_health_check(true).await;
        });
    }

    /// Removes an upstream pool from monitoring.
    pub fn unregister(&self, id: i64) {
        self.registry.remove(&id);
        self.parent_registry.remove(&id);
    }

    /// Starts the main scheduling loop.
    pub async fn start(self: Arc<Self>) {
        info!("Global Health Manager started.");
        let mut interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            interval.tick().await;
            self.schedule_probes().await;
        }
    }

    async fn schedule_probes(&self) {
        let now = Instant::now();

        // 1. Probes for Standard Origin Pools
        let mut targets = Vec::new();
        for mut entry in self.registry.iter_mut() {
            let id = *entry.key();
            let item = entry.value_mut();
            if now.duration_since(item.last_check) >= item.frequency {
                if let Some(lb) = item.lb.upgrade() {
                    targets.push((id, lb));
                    item.last_check = now;
                }
            }
        }

        self.registry.retain(|id, v| {
            if v.lb.strong_count() == 0 {
                debug!(
                    "Removing health check for pool {} (LoadBalancer dropped)",
                    id
                );
                false
            } else {
                true
            }
        });

        for (id, lb) in targets {
            let limiter = self.concurrency_limiter.clone();
            tokio::spawn(async move {
                let _permit = match limiter.acquire().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                lb.backends().run_health_check(true).await;
                let backends = lb.backends();
                for backend in backends.get_backend().iter() {
                    if !backends.ready(backend) {
                        warn!("Pool {}: Backend {} is UNHEALTHY", id, backend.addr);
                    }
                }
            });
        }

        // 2. Probes for Parent (L2) Pools
        let mut parent_targets = Vec::new();
        for mut entry in self.parent_registry.iter_mut() {
            let id = *entry.key();
            let item = entry.value_mut();
            if now.duration_since(item.last_check) >= item.frequency {
                if let Some(lb) = item.lb.upgrade() {
                    parent_targets.push((id, lb));
                    item.last_check = now;
                }
            }
        }

        self.parent_registry
            .retain(|_id, v| v.lb.strong_count() > 0);

        for (id, lb) in parent_targets {
            let limiter = self.concurrency_limiter.clone();
            tokio::spawn(async move {
                let _permit = match limiter.acquire().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                lb.backends().run_health_check(true).await;
                let backends = lb.backends();
                for backend in backends.get_backend().iter() {
                    if !backends.ready(backend) {
                        warn!("L2 Cluster {}: Parent Node {} is DOWN", id, backend.addr);
                    }
                }
            });
        }
    }
}
