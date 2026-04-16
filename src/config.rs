use pingora_load_balancing::{LoadBalancer, selection::RoundRobin};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::config_models::{HTTPPageConfig, MetricItemConfig, ParentNodeConfig, ServerConfig, HTTPCachePolicy, HTTPFirewallPolicy};

/// Configuration for the local EdgeNode.
#[derive(Clone)]
pub struct NodeConfig {
    /// The numeric ID in the central database
    pub id: i64,
    /// Current node config version reported by control plane
    pub version: i64,
    /// Mapping of Host domain to its server configuration
    pub servers: HashMap<String, ServerConfig>,
    /// Mapping of Host domain to an upstream load balancer
    pub routes: HashMap<String, Arc<LoadBalancer<RoundRobin>>>,
    /// Banned URLs (e.g. for legal compliance)
    pub deleted_contents: Vec<String>,
    /// Cluster-wide custom pages
    pub global_pages: Vec<HTTPPageConfig>,
    /// IDs of servers currently being updated by the control plane
    pub updating_server_ids: std::collections::HashSet<i64>,
    /// Metric items definitions
    pub metric_items: Vec<MetricItemConfig>,
    /// Current node level (1=L1, 2=L2, etc.)
    pub level: i32,
    /// Parent nodes (L2s) for tiered origin, grouped by cluster id
    pub parent_nodes: HashMap<i64, Vec<ParentNodeConfig>>,
    /// Whether to bypass L2 and go direct to origin (Load protection)
    pub tiered_origin_bypass: bool,
    /// Global or node-specific cache policy
    pub cache_policy: Option<HTTPCachePolicy>,
    /// Global or node-specific firewall policies
    pub firewall_policies: Vec<HTTPFirewallPolicy>,
    /// Global WAF action defaults
    pub waf_actions: Vec<crate::config_models::WAFActionConfig>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            id: 0,
            version: 0,
            servers: HashMap::new(),
            routes: HashMap::new(),
            deleted_contents: Vec::new(),
            global_pages: Vec::new(),
            updating_server_ids: std::collections::HashSet::new(),
            metric_items: Vec::new(),
            level: 1, // Default to L1
            parent_nodes: HashMap::new(),
            tiered_origin_bypass: false,
            cache_policy: None,
            firewall_policies: Vec::new(),
            waf_actions: Vec::new(),
        }
    }
}

/// A thread-safe handle to the NodeConfig to allow dynamic updates from the gRPC syncer.
#[derive(Clone)]
pub struct ConfigStore {
    inner: Arc<RwLock<NodeConfig>>,
}

impl Default for ConfigStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(NodeConfig::default())),
        }
    }

    // Sync versions for high-performance path (proxy)
    pub fn get_upstream_sync(&self, host: &str) -> Option<Arc<LoadBalancer<RoundRobin>>> {
        let lock = self.inner.read().unwrap();
        lock.routes.get(host).cloned()
    }

    pub fn get_server_sync(&self, host: &str) -> Option<ServerConfig> {
        let lock = self.inner.read().unwrap();
        lock.servers.get(host).cloned()
    }

    pub fn get_cache_policy_sync(&self) -> Option<HTTPCachePolicy> {
        let lock = self.inner.read().unwrap();
        lock.cache_policy.clone()
    }

    pub fn get_firewall_policies_sync(&self) -> Vec<HTTPFirewallPolicy> {
        let lock = self.inner.read().unwrap();
        lock.firewall_policies.clone()
    }

    pub fn get_waf_actions_sync(&self) -> Vec<crate::config_models::WAFActionConfig> {
        let lock = self.inner.read().unwrap();
        lock.waf_actions.clone()
    }

    // Async versions (keep name compatibility for most parts)
    pub async fn get_upstream(&self, host: &str) -> Option<Arc<LoadBalancer<RoundRobin>>> {
        self.get_upstream_sync(host)
    }

    pub async fn get_server(&self, host: &str) -> Option<ServerConfig> {
        self.get_server_sync(host)
    }

    pub async fn get_all_servers(&self) -> Vec<ServerConfig> {
        let lock = self.inner.read().unwrap();
        lock.servers.values().cloned().collect()
    }

    pub async fn is_deleted_content(&self, url: &str) -> bool {
        let lock = self.inner.read().unwrap();
        lock.deleted_contents
            .iter()
            .any(|banned| url == banned || url.starts_with(banned))
    }

    pub async fn is_updating_server(&self, server_id: i64) -> bool {
        let lock = self.inner.read().unwrap();
        lock.updating_server_ids.contains(&server_id)
    }

    pub async fn set_updating_servers(&self, ids: Vec<i64>) {
        let mut lock = self.inner.write().unwrap();
        lock.updating_server_ids = ids.into_iter().collect();
    }

    pub async fn get_global_pages(&self) -> Vec<HTTPPageConfig> {
        let lock = self.inner.read().unwrap();
        lock.global_pages.clone()
    }

    pub async fn get_server_id_by_host(&self, host: &str) -> Option<i64> {
        let lock = self.inner.read().unwrap();
        lock.servers.get(host).and_then(|s| s.id)
    }

    pub async fn find_upstream_by_server_id(&self, server_id: i64) -> Option<Arc<LoadBalancer<RoundRobin>>> {
        let lock = self.inner.read().unwrap();
        let host = lock
            .servers
            .iter()
            .find(|(_, s)| s.id == Some(server_id))
            .map(|(h, _)| h.clone())?;
        lock.routes.get(&host).cloned()
    }

    pub async fn get_lb_by_id(&self, server_id: i64) -> Option<Arc<LoadBalancer<RoundRobin>>> {
        self.find_upstream_by_server_id(server_id).await
    }

    pub async fn get_metric_items(&self) -> Vec<MetricItemConfig> {
        let lock = self.inner.read().unwrap();
        lock.metric_items.clone()
    }

    pub async fn get_tiered_origin_info(&self) -> (i32, HashMap<i64, Vec<ParentNodeConfig>>) {
        let lock = self.inner.read().unwrap();
        (lock.level, lock.parent_nodes.clone())
    }

    pub async fn is_tiered_origin_bypass(&self) -> bool {
        let lock = self.inner.read().unwrap();
        lock.tiered_origin_bypass
    }

    pub async fn set_tiered_origin_bypass(&self, bypass: bool) {
        let mut lock = self.inner.write().unwrap();
        lock.tiered_origin_bypass = bypass;
    }

    pub async fn get_node_id(&self) -> i64 {
        let lock = self.inner.read().unwrap();
        lock.id
    }

    pub async fn update_id(&self, id: i64) {
        let mut lock = self.inner.write().unwrap();
        lock.id = id;
    }

    pub async fn get_config_version(&self) -> i64 {
        let lock = self.inner.read().unwrap();
        lock.version
    }

    pub async fn get_cache_policy(&self) -> Option<HTTPCachePolicy> {
        self.get_cache_policy_sync()
    }

    pub async fn get_deleted_contents(&self) -> Vec<String> {
        let lock = self.inner.read().unwrap();
        lock.deleted_contents.clone()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_config(
        &self,
        id: i64,
        version: i64,
        servers: HashMap<String, ServerConfig>,
        routes: HashMap<String, Arc<LoadBalancer<RoundRobin>>>,
        deleted_contents: Vec<String>,
        global_pages: Vec<HTTPPageConfig>,
        metric_items: Vec<MetricItemConfig>,
        level: i32,
        parent_nodes: HashMap<i64, Vec<ParentNodeConfig>>,
        tiered_origin_bypass: bool,
        cache_policy: Option<HTTPCachePolicy>,
        firewall_policies: Vec<HTTPFirewallPolicy>,
        waf_actions: Vec<crate::config_models::WAFActionConfig>,
    ) {
        let mut lock = self.inner.write().unwrap();
        lock.id = id;
        lock.version = version;
        lock.servers = servers;
        lock.routes = routes;
        lock.deleted_contents = deleted_contents;
        lock.global_pages = global_pages;
        lock.metric_items = metric_items;
        lock.level = level;
        lock.parent_nodes = parent_nodes;
        lock.tiered_origin_bypass = tiered_origin_bypass;
        lock.cache_policy = cache_policy;
        lock.firewall_policies = firewall_policies;
        lock.waf_actions = waf_actions;
    }


    pub async fn replace_server(&self, _server_id: i64, servers: HashMap<String, ServerConfig>, routes: HashMap<String, Arc<LoadBalancer<RoundRobin>>>) {
        let mut lock = self.inner.write().unwrap();
        for (host, config) in servers {
            lock.servers.insert(host, config);
        }
        for (host, lb) in routes {
            lock.routes.insert(host, lb);
        }
    }

    pub async fn replace_user_servers(&self, _user_id: i64, servers: HashMap<String, ServerConfig>, routes: HashMap<String, Arc<LoadBalancer<RoundRobin>>>) {
        let mut lock = self.inner.write().unwrap();
        for (host, config) in servers {
            lock.servers.insert(host, config);
        }
        for (host, lb) in routes {
            lock.routes.insert(host, lb);
        }
    }

    pub async fn remove_user_servers(&self, user_id: i64) {
        let mut lock = self.inner.write().unwrap();
        lock.servers.retain(|_, s| s.user_id != user_id);
    }

    pub async fn set_deleted_contents(&self, deleted_contents: Vec<String>) {
        let mut lock = self.inner.write().unwrap();
        lock.deleted_contents = deleted_contents;
    }
}
