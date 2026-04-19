use pingora_load_balancing::{LoadBalancer, selection::{RoundRobin, Consistent}};
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
    /// Direct mapping from Server ID to Load Balancer
    pub id_to_lb: HashMap<i64, Arc<LoadBalancer<RoundRobin>>>,
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
    /// Whether the node is enabled
    pub is_on: bool,
    /// Whether to sync IP lists
    pub enable_ip_lists: bool,
    /// Parent nodes (L2s) for tiered origin, grouped by cluster id
    pub parent_nodes: HashMap<i64, Vec<ParentNodeConfig>>,
    /// Whether to bypass L2 and go direct to origin (Load protection)
    pub tiered_origin_bypass: bool,
    /// Force all requests through L2 (Tiered Origin)
    pub force_ln_request: bool,
    /// Selection method for L2 nodes: "random" or "urlMapping"
    pub ln_request_scheduling_method: String,
    /// L2 Load Balancers (Tiered Origin pools)
    pub parent_routes: HashMap<i64, Arc<LoadBalancer<Consistent>>>,
    /// Global gRPC policy
    pub grpc_policy: Option<crate::config_models::GRPCConfig>,

    // New Global Cluster Settings
    pub supports_low_version_http: bool,
    pub match_cert_from_all_servers: bool,
    pub server_name: String,
    pub enable_server_addr_variable: bool,
    pub request_origins_with_encodings: bool,
    pub xff_max_addresses: i32,
    pub allow_lan_ip: bool,

    /// Real-time pressure/load factor for L2 nodes (0.0 - 1.0)
    pub parent_pressure: HashMap<String, (f32, std::time::Instant)>,
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
            id_to_lb: HashMap::new(),
            deleted_contents: Vec::new(),
            global_pages: Vec::new(),
            updating_server_ids: std::collections::HashSet::new(),
            metric_items: Vec::new(),
            level: 1, // Default to L1
            is_on: true,
            enable_ip_lists: false,
            parent_nodes: HashMap::new(),
            tiered_origin_bypass: false,
            force_ln_request: false,
            ln_request_scheduling_method: "random".to_string(),
            parent_routes: HashMap::new(),
            grpc_policy: None,
            supports_low_version_http: false,
            match_cert_from_all_servers: false,
            server_name: String::new(),
            enable_server_addr_variable: false,
            request_origins_with_encodings: false,
            xff_max_addresses: 0,
            allow_lan_ip: false,
            parent_pressure: HashMap::new(),
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

    pub fn get_parent_upstream_sync(&self, cluster_id: i64) -> Option<Arc<LoadBalancer<Consistent>>> {
        let lock = self.inner.read().unwrap();
        lock.parent_routes.get(&cluster_id).cloned()
    }

    pub fn get_force_ln_request_sync(&self) -> bool {
        let lock = self.inner.read().unwrap();
        lock.force_ln_request
    }

    pub fn get_ln_method_sync(&self) -> String {
        let lock = self.inner.read().unwrap();
        lock.ln_request_scheduling_method.clone()
    }

    pub fn get_node_level_sync(&self) -> i32 {
        let lock = self.inner.read().unwrap();
        lock.level
    }

    pub fn get_node_is_on_sync(&self) -> bool {
        let lock = self.inner.read().unwrap();
        lock.is_on
    }

    pub fn get_node_enable_ip_lists_sync(&self) -> bool {
        let lock = self.inner.read().unwrap();
        lock.enable_ip_lists
    }

    pub fn get_global_http_config_sync(&self) -> crate::config_models::GlobalHTTPAllConfig {
        let lock = self.inner.read().unwrap();
        crate::config_models::GlobalHTTPAllConfig {
            force_ln_request: lock.force_ln_request,
            ln_request_scheduling_method: lock.ln_request_scheduling_method.clone(),
            supports_low_version_http: lock.supports_low_version_http,
            match_cert_from_all_servers: lock.match_cert_from_all_servers,
            server_name: lock.server_name.clone(),
            enable_server_addr_variable: lock.enable_server_addr_variable,
            request_origins_with_encodings: lock.request_origins_with_encodings,
            xff_max_addresses: lock.xff_max_addresses,
            allow_lan_ip: lock.allow_lan_ip,
        }
    }

    pub fn get_grpc_policy_sync(&self) -> Option<crate::config_models::GRPCConfig> {
        let lock = self.inner.read().unwrap();
        lock.grpc_policy.clone()
    }

    pub fn update_parent_pressure(&self, addr: &str, pressure: f32) {
        let mut lock = self.inner.write().unwrap();
        lock.parent_pressure.insert(addr.to_string(), (pressure, std::time::Instant::now()));
    }

    pub fn get_parent_pressure(&self, addr: &str) -> f32 {
        let lock = self.inner.read().unwrap();
        if let Some((p, ts)) = lock.parent_pressure.get(addr) {
            // Data expires after 60 seconds of no update
            if ts.elapsed().as_secs() < 60 {
                return *p;
            }
        }
        0.0
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

    pub fn get_all_hosts_sync(&self) -> Vec<String> {
        let lock = self.inner.read().unwrap();
        lock.servers.keys().cloned().collect()
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

    pub async fn get_lb_by_id(&self, server_id: i64) -> Option<Arc<LoadBalancer<RoundRobin>>> {
        let lock = self.inner.read().unwrap();
        lock.id_to_lb.get(&server_id).cloned()
    }

    pub async fn find_upstream_by_server_id(&self, server_id: i64) -> Option<Arc<LoadBalancer<RoundRobin>>> {
        self.get_lb_by_id(server_id).await
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
        id_to_lb: HashMap<i64, Arc<LoadBalancer<RoundRobin>>>,
        deleted_contents: Vec<String>,
        global_pages: Vec<HTTPPageConfig>,
        metric_items: Vec<MetricItemConfig>,
        level: i32,
        is_on: bool,
        enable_ip_lists: bool,
        parent_nodes: HashMap<i64, Vec<ParentNodeConfig>>,
        tiered_origin_bypass: bool,
        force_ln_request: bool,
        ln_method: String,
        parent_routes: HashMap<i64, Arc<LoadBalancer<Consistent>>>,
        grpc_policy: Option<crate::config_models::GRPCConfig>,
        // New Global Cluster Settings
        supports_low_version_http: bool,
        match_cert_from_all_servers: bool,
        server_name: String,
        enable_server_addr_variable: bool,
        request_origins_with_encodings: bool,
        xff_max_addresses: i32,
        allow_lan_ip: bool,
        cache_policy: Option<HTTPCachePolicy>,
        firewall_policies: Vec<HTTPFirewallPolicy>,
        waf_actions: Vec<crate::config_models::WAFActionConfig>,
    ) {
        let mut lock = self.inner.write().unwrap();
        lock.id = id;
        lock.version = version;
        lock.servers = servers;
        lock.routes = routes;
        lock.id_to_lb = id_to_lb;
        lock.deleted_contents = deleted_contents;
        lock.global_pages = global_pages;
        lock.metric_items = metric_items;
        lock.level = level;
        lock.is_on = is_on;
        lock.enable_ip_lists = enable_ip_lists;
        lock.parent_nodes = parent_nodes;
        lock.tiered_origin_bypass = tiered_origin_bypass;
        lock.force_ln_request = force_ln_request;
        lock.ln_request_scheduling_method = ln_method;
        lock.parent_routes = parent_routes;
        lock.grpc_policy = grpc_policy;
        lock.supports_low_version_http = supports_low_version_http;
        lock.match_cert_from_all_servers = match_cert_from_all_servers;
        lock.server_name = server_name;
        lock.enable_server_addr_variable = enable_server_addr_variable;
        lock.request_origins_with_encodings = request_origins_with_encodings;
        lock.xff_max_addresses = xff_max_addresses;
        lock.allow_lan_ip = allow_lan_ip;
        lock.cache_policy = cache_policy;
        lock.firewall_policies = firewall_policies;
        lock.waf_actions = waf_actions;
    }


    pub async fn replace_server(
        &self, 
        server_id: i64, 
        servers: HashMap<String, ServerConfig>, 
        routes: HashMap<String, Arc<LoadBalancer<RoundRobin>>>
    ) {
        let mut lock = self.inner.write().unwrap();
        for (host, config) in servers {
            lock.servers.insert(host, config);
        }
        for (host, lb) in routes {
            if server_id > 0 {
                lock.id_to_lb.insert(server_id, lb.clone());
            }
            lock.routes.insert(host, lb);
        }
    }

    pub async fn replace_user_servers(
        &self, 
        _user_id: i64, 
        servers: HashMap<String, ServerConfig>, 
        routes: HashMap<String, Arc<LoadBalancer<RoundRobin>>>
    ) {
        let mut lock = self.inner.write().unwrap();
        for (host, config) in servers {
            if let Some(sid) = config.id {
                if let Some(lb) = routes.get(&host) {
                    lock.id_to_lb.insert(sid, lb.clone());
                }
            }
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
