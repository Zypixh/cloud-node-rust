use dashmap::DashMap;
use pingora_load_balancing::{LoadBalancer, selection::RoundRobin};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, info};

/// Represents a single health check target.
struct HealthCheckItem {
    lb: Weak<LoadBalancer<RoundRobin>>,
    frequency: Duration,
    last_check: Instant,
}

/// A scalable manager for active health checks.
/// Handles millions of upstreams by using a pooled executor and rate-limiting.
pub struct GlobalHealthManager {
    /// Key: Unique ID for the upstream pool (e.g. Server ID)
    registry: DashMap<i64, HealthCheckItem>,
    /// Global limit on concurrent probes
    concurrency_limiter: Arc<Semaphore>,
}

impl GlobalHealthManager {
    /// Creates a new manager with a specified maximum concurrency.
    pub fn new(max_concurrency: usize) -> Arc<Self> {
        Arc::new(Self {
            registry: DashMap::new(),
            concurrency_limiter: Arc::new(Semaphore::new(max_concurrency)),
        })
    }

    /// Registers a load balancer for periodic health monitoring.
    pub fn register(&self, id: i64, lb: Arc<LoadBalancer<RoundRobin>>, frequency: Duration) {
        debug!("Registering health check for upstream pool {}", id);
        self.registry.insert(
            id,
            HealthCheckItem {
                lb: Arc::downgrade(&lb),
                frequency,
                last_check: Instant::now() - frequency, // Trigger immediate check
            },
        );
    }

    /// Removes an upstream pool from monitoring.
    pub fn unregister(&self, id: i64) {
        self.registry.remove(&id);
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
        let mut targets = Vec::new();

        // 1. Identify which LBs are due for a check
        // We use a separate pass to minimize holding the DashMap entry locks
        for mut entry in self.registry.iter_mut() {
            let item = entry.value_mut();
            if now.duration_since(item.last_check) >= item.frequency {
                if let Some(lb) = item.lb.upgrade() {
                    targets.push(lb);
                    item.last_check = now;
                } else {
                    // LB was dropped (e.g. server deleted), we'll cleanup later
                }
            }
        }

        // 2. Perform periodic cleanup of dead weak pointers
        self.registry.retain(|_, v| v.lb.strong_count() > 0);

        if targets.is_empty() {
            return;
        }

        debug!("Scheduling {} health check probes", targets.len());

        // 3. Spawn workers with concurrency limiting
        for lb in targets {
            let limiter = self.concurrency_limiter.clone();
            tokio::spawn(async move {
                // Acquire permit - this limits total concurrent probes globally
                let _permit = match limiter.acquire().await {
                    Ok(p) => p,
                    Err(_) => return,
                };

                // Perform the actual active probe
                lb.backends().run_health_check(true).await;
            });
        }
    }
}
