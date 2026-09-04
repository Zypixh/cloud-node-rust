use dashmap::DashMap;
use pingora_load_balancing::{LoadBalancer, selection::Consistent};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// Represents a single health check target.
struct HealthCheckItem<L> {
    lb: Weak<L>,
    frequency: Duration,
    last_check: Instant,
}

/// A scalable manager for active health checks.
/// Handles millions of upstreams by using a pooled executor and rate-limiting.
pub struct GlobalHealthManager {
    /// Key: Unique ID for the upstream pool (e.g. Server ID)
    registry: DashMap<i64, HealthCheckItem<crate::lb_factory::AnyLoadBalancer>>,
    /// Registry for L2 (Parent) pools using consistent hashing
    parent_registry: DashMap<i64, HealthCheckItem<LoadBalancer<Consistent>>>,
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
    pub fn register(
        &self,
        id: i64,
        lb: Arc<crate::lb_factory::AnyLoadBalancer>,
        frequency: Duration,
    ) {
        self.register_inner(id, lb, frequency, true);
    }

    /// Register without an immediate probe. Used under High/Critical memory so a
    /// full snapshot cannot pin hundreds of load balancers in in-flight tasks.
    pub fn register_deferred(
        &self,
        id: i64,
        lb: Arc<crate::lb_factory::AnyLoadBalancer>,
        frequency: Duration,
    ) {
        self.register_inner(id, lb, frequency, false);
    }

    fn register_inner(
        &self,
        id: i64,
        lb: Arc<crate::lb_factory::AnyLoadBalancer>,
        frequency: Duration,
        immediate: bool,
    ) {
        debug!(
            "Registering health check for upstream pool {} (Frequency: {:?}, immediate={})",
            id, frequency, immediate
        );
        self.registry.insert(
            id,
            HealthCheckItem {
                lb: Arc::downgrade(&lb),
                frequency,
                last_check: Instant::now(),
            },
        );

        if !immediate {
            return;
        }

        // Do not clone the Arc into the task. Wait on the limiter with a Weak
        // so a replaced generation can drop while probes are queued.
        let weak = Arc::downgrade(&lb);
        let limiter = self.concurrency_limiter.clone();
        tokio::spawn(async move {
            let _permit = match limiter.acquire().await {
                Ok(permit) => permit,
                Err(_) => return,
            };
            let Some(lb) = weak.upgrade() else {
                return;
            };
            debug!("Immediate health check for pool {}", id);
            lb.run_health_check(true).await;

            for (backend, healthy) in lb.backend_health() {
                if healthy {
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
        debug!(
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

        let weak = Arc::downgrade(&lb);
        let limiter = self.concurrency_limiter.clone();
        tokio::spawn(async move {
            let _permit = match limiter.acquire().await {
                Ok(permit) => permit,
                Err(_) => return,
            };
            let Some(lb) = weak.upgrade() else {
                return;
            };
            lb.backends().run_health_check(true).await;
        });
    }

    /// Removes an upstream pool from monitoring.
    pub fn unregister(&self, id: i64) {
        self.registry.remove(&id);
        self.parent_registry.remove(&id);
    }

    /// Drop every registered probe. Used when a full snapshot replaces all sites
    /// under memory pressure so old load balancers are not kept alive.
    pub fn unregister_all(&self) {
        self.registry.clear();
        self.parent_registry.clear();
    }

    pub fn origin_check_count(&self) -> usize {
        self.registry.len()
    }

    pub fn sweep_dropped_checks(&self) {
        self.registry.retain(|id, item| {
            if item.lb.strong_count() == 0 {
                debug!(
                    "Removing health check for pool {} (LoadBalancer dropped)",
                    id
                );
                false
            } else {
                true
            }
        });
        self.parent_registry
            .retain(|_id, item| item.lb.strong_count() > 0);
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
            if now.duration_since(item.last_check) >= item.frequency
                && let Some(lb) = item.lb.upgrade()
            {
                targets.push((id, lb));
                item.last_check = now;
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
                lb.run_health_check(true).await;
                for (backend, healthy) in lb.backend_health() {
                    if !healthy {
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
            if now.duration_since(item.last_check) >= item.frequency
                && let Some(lb) = item.lb.upgrade()
            {
                parent_targets.push((id, lb));
                item.last_check = now;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn immediate_probe_does_not_pin_replaced_load_balancer() {
        let health = GlobalHealthManager::new(0);
        let (lb, _) = crate::rpc::utils::fallback_runtime_lb();
        health.register(7, Arc::clone(&lb), Duration::from_secs(30));
        assert_eq!(health.origin_check_count(), 1);
        drop(lb);
        tokio::task::yield_now().await;
        health.sweep_dropped_checks();
        assert_eq!(
            health.origin_check_count(),
            0,
            "health checks must not keep a replaced load balancer alive"
        );
    }

    #[tokio::test]
    async fn deferred_register_lets_replaced_lb_drop() {
        let health = GlobalHealthManager::new(4);
        let (lb, _) = crate::rpc::utils::fallback_runtime_lb();
        health.register_deferred(9, Arc::clone(&lb), Duration::from_secs(30));
        drop(lb);
        health.sweep_dropped_checks();
        assert_eq!(health.origin_check_count(), 0);
    }
}
