use pingora_load_balancing::{
    LoadBalancer,
    selection::{Consistent, RoundRobin},
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::Notify;

use crate::config_models::{
    HTTP3Policy, HTTPCCPolicy, HTTPCachePolicy, HTTPFirewallPolicy, HTTPPageConfig,
    HTTPPagesPolicy, MetricItemConfig, ParentNodeConfig, ServerConfig, TOAConfig, UAMPolicy,
    WebPImagePolicy,
};

/// Configuration for the local EdgeNode.
#[derive(Clone)]
pub struct NodeConfig {
    /// The numeric ID in the central database
    pub id: i64,
    /// Current node config version reported by control plane
    pub version: i64,
    /// Mapping of Host domain to its server configuration
    pub servers: HashMap<String, Arc<ServerConfig>>,
    /// Unique runtime server list preserved independently from host routing map
    pub all_servers: Vec<Arc<ServerConfig>>,
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
    /// Region ID used by stats aggregation APIs
    pub node_region_id: i64,
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
    /// Global UAM policies keyed by cluster id
    pub uam_policies: HashMap<i64, UAMPolicy>,
    /// Global HTTP CC policies keyed by cluster id
    pub http_cc_policies: HashMap<i64, HTTPCCPolicy>,
    /// Global HTTP/3 policies keyed by cluster id
    pub http3_policies: HashMap<i64, HTTP3Policy>,
    /// Global HTTP page policies keyed by cluster id
    pub http_pages_policies: HashMap<i64, HTTPPagesPolicy>,
    /// Global WebP image policies keyed by cluster id
    pub webp_image_policies: HashMap<i64, WebPImagePolicy>,
    /// Global TOA config
    pub toa: Option<TOAConfig>,
    /// Cached plans referenced by current runtime servers
    pub plans: HashMap<i64, crate::pb::Plan>,
    /// Cached user plans referenced by current runtime servers
    pub user_plans: HashMap<i64, crate::pb::UserPlan>,
    /// Whether any SNI passthrough server is configured (fast check for TLS path)
    pub has_any_sni_passthrough: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            id: 0,
            version: 0,
            servers: HashMap::new(),
            all_servers: Vec::new(),
            routes: HashMap::new(),
            id_to_lb: HashMap::new(),
            deleted_contents: Vec::new(),
            global_pages: Vec::new(),
            updating_server_ids: std::collections::HashSet::new(),
            metric_items: Vec::new(),
            level: 1, // Default to L1
            node_region_id: 0,
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
            uam_policies: HashMap::new(),
            http_cc_policies: HashMap::new(),
            http3_policies: HashMap::new(),
            http_pages_policies: HashMap::new(),
            webp_image_policies: HashMap::new(),
            toa: None,
            plans: HashMap::new(),
            user_plans: HashMap::new(),
            has_any_sni_passthrough: false,
        }
    }
}

/// A thread-safe handle to the NodeConfig to allow dynamic updates from the gRPC syncer.
#[derive(Clone)]
pub struct ConfigStore {
    inner: Arc<RwLock<NodeConfig>>,
    reload_notify: Arc<Notify>,
}

#[derive(Clone)]
pub struct HotPathSnapshot {
    pub is_on: bool,
    pub global_http: crate::config_models::GlobalHTTPAllConfig,
    pub firewall_policies: Vec<HTTPFirewallPolicy>,
    pub grpc_policy: Option<crate::config_models::GRPCConfig>,
    pub has_any_sni_passthrough: bool,
    pub cache_policy: Option<HTTPCachePolicy>,
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
            reload_notify: Arc::new(Notify::new()),
        }
    }

    pub async fn wait_for_runtime_reload(&self) {
        self.reload_notify.notified().await;
    }

    fn notify_runtime_reload(&self) {
        self.reload_notify.notify_waiters();
    }

    // Sync versions for high-performance path (proxy)
    pub fn get_upstream_sync(&self, host: &str) -> Option<Arc<LoadBalancer<RoundRobin>>> {
        let lock = self.inner.read().unwrap();
        lock.routes.get(host).cloned()
    }

    pub fn get_server_sync(&self, host: &str) -> Option<Arc<ServerConfig>> {
        let lock = self.inner.read().unwrap();
        lock.servers.get(host).cloned()
    }

    pub fn get_server_and_upstream_sync(
        &self,
        host: &str,
    ) -> (
        Option<Arc<ServerConfig>>,
        Option<Arc<LoadBalancer<RoundRobin>>>,
    ) {
        let lock = self.inner.read().unwrap();
        (
            lock.servers.get(host).cloned(),
            lock.routes.get(host).cloned(),
        )
    }

    pub fn get_hot_path_snapshot_sync(&self) -> HotPathSnapshot {
        let lock = self.inner.read().unwrap();
        Self::build_hot_path_snapshot(&lock)
    }

    /// Combined accessor: returns HotPathSnapshot + server + upstream in one lock acquisition.
    /// Reduces RwLock atomic overhead by 50% on the request hot path.
    pub fn get_request_context_sync(
        &self,
        host: &str,
    ) -> (
        HotPathSnapshot,
        Option<Arc<ServerConfig>>,
        Option<Arc<LoadBalancer<RoundRobin>>>,
    ) {
        let lock = self.inner.read().unwrap();
        let hot_path = Self::build_hot_path_snapshot(&lock);
        let server = lock.servers.get(host).cloned();
        let upstream = lock.routes.get(host).cloned();
        (hot_path, server, upstream)
    }

    fn build_hot_path_snapshot(lock: &NodeConfig) -> HotPathSnapshot {
        HotPathSnapshot {
            is_on: lock.is_on,
            global_http: crate::config_models::GlobalHTTPAllConfig {
                force_ln_request: lock.force_ln_request,
                ln_request_scheduling_method: lock.ln_request_scheduling_method.clone(),
                supports_low_version_http: lock.supports_low_version_http,
                match_cert_from_all_servers: lock.match_cert_from_all_servers,
                server_name: lock.server_name.clone(),
                enable_server_addr_variable: lock.enable_server_addr_variable,
                request_origins_with_encodings: lock.request_origins_with_encodings,
                xff_max_addresses: lock.xff_max_addresses,
                allow_lan_ip: lock.allow_lan_ip,
            },
            firewall_policies: lock.firewall_policies.clone(),
            grpc_policy: lock.grpc_policy.clone(),
            has_any_sni_passthrough: lock.has_any_sni_passthrough,
            cache_policy: lock.cache_policy.clone(),
        }
    }

    pub fn get_server_for_tls_name_sync(&self, host: &str) -> Option<Arc<ServerConfig>> {
        let normalized = host.trim_end_matches('.').to_ascii_lowercase();

        // 1. Try exact match from the fast index
        {
            let lock = self.inner.read().unwrap();
            if let Some(server) = lock.servers.get(&normalized) {
                return Some(server.clone());
            }
        }

        // 2. Try wildcard match from the fast index
        if let Some(pos) = normalized.find('.') {
            let wildcard = format!("*{}", &normalized[pos..]);
            let lock = self.inner.read().unwrap();
            if let Some(server) = lock.servers.get(&wildcard) {
                return Some(server.clone());
            }
        }

        // 3. Fallback to robust scanner (handles @sni_passthrough, complex wildcards, and sub_names)
        // This port 0 means we don't care about the port for certificate matching
        self.find_sni_passthrough_server_sync(host, 0)
    }

    pub fn find_sni_passthrough_server_sync(
        &self,
        host: &str,
        port: u16,
    ) -> Option<Arc<ServerConfig>> {
        let normalized = host.trim_end_matches('.').to_ascii_lowercase();
        let lock = self.inner.read().unwrap();

        let matches_name = |server: &ServerConfig| {
            server.server_names.iter().any(|sn| {
                // Check primary name
                let name = ServerConfig::normalize_runtime_server_name(&sn.name);
                if !name.is_empty() {
                    if name == normalized {
                        return true;
                    }
                    if name.starts_with("*.") {
                        let suffix = &name[1..];
                        if normalized == &suffix[1..] || normalized.ends_with(suffix) {
                            return true;
                        }
                    }
                }

                // Check sub_names
                sn.sub_names.iter().any(|sub| {
                    let sub = ServerConfig::normalize_runtime_server_name(sub);
                    if !sub.is_empty() {
                        if sub == normalized {
                            return true;
                        }
                        if sub.starts_with("*.") {
                            let suffix = &sub[1..];
                            if normalized == &suffix[1..] || normalized.ends_with(suffix) {
                                return true;
                            }
                        }
                    }
                    false
                })
            })
        };

        for server in lock.all_servers.iter() {
            // If port is 0, we bypass port check (used for general TLS name matching)
            let port_matches = port == 0 || server.listens_on_https_port(port);
            if server.is_sni_passthrough() && port_matches {
                if matches_name(server) {
                    return Some(server.clone());
                }
            }
        }
        None
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

    pub fn get_global_pages_sync(&self) -> Vec<HTTPPageConfig> {
        let lock = self.inner.read().unwrap();
        lock.global_pages.clone()
    }

    fn pick_global_policy<T: Clone>(map: &HashMap<i64, T>) -> Option<T> {
        map.get(&0)
            .cloned()
            .or_else(|| map.values().next().cloned())
    }

    pub fn get_global_uam_policy_sync(&self) -> Option<UAMPolicy> {
        let lock = self.inner.read().unwrap();
        Self::pick_global_policy(&lock.uam_policies)
    }

    pub fn get_global_http_cc_policy_sync(&self) -> Option<HTTPCCPolicy> {
        let lock = self.inner.read().unwrap();
        Self::pick_global_policy(&lock.http_cc_policies)
    }

    pub fn get_global_http3_policy_sync(&self) -> Option<HTTP3Policy> {
        let lock = self.inner.read().unwrap();
        Self::pick_global_policy(&lock.http3_policies)
    }

    pub fn get_global_http_pages_policy_sync(&self) -> Option<HTTPPagesPolicy> {
        let lock = self.inner.read().unwrap();
        Self::pick_global_policy(&lock.http_pages_policies)
    }

    pub fn get_global_webp_policy_sync(&self) -> Option<WebPImagePolicy> {
        let lock = self.inner.read().unwrap();
        Self::pick_global_policy(&lock.webp_image_policies)
    }

    pub fn get_toa_config_sync(&self) -> Option<TOAConfig> {
        let lock = self.inner.read().unwrap();
        lock.toa.clone()
    }

    pub fn get_parent_upstream_sync(
        &self,
        cluster_id: i64,
    ) -> Option<Arc<LoadBalancer<Consistent>>> {
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

    pub fn get_plan_sync(&self, plan_id: i64) -> Option<crate::pb::Plan> {
        let lock = self.inner.read().unwrap();
        lock.plans.get(&plan_id).cloned()
    }

    pub fn get_user_plan_sync(&self, user_plan_id: i64) -> Option<crate::pb::UserPlan> {
        let lock = self.inner.read().unwrap();
        lock.user_plans.get(&user_plan_id).cloned()
    }

    pub fn update_parent_pressure(&self, addr: &str, pressure: f32) {
        let mut lock = self.inner.write().unwrap();
        lock.parent_pressure
            .insert(addr.to_string(), (pressure, std::time::Instant::now()));
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

    pub async fn get_server(&self, host: &str) -> Option<Arc<ServerConfig>> {
        self.get_server_sync(host)
    }

    pub async fn get_server_by_id(&self, server_id: i64) -> Option<Arc<ServerConfig>> {
        let lock = self.inner.read().unwrap();
        lock.all_servers
            .iter()
            .find(|server| server.id == Some(server_id))
            .cloned()
    }

    pub async fn get_all_servers(&self) -> Vec<Arc<ServerConfig>> {
        let lock = self.inner.read().unwrap();
        lock.all_servers.clone()
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

    pub async fn find_upstream_by_server_id(
        &self,
        server_id: i64,
    ) -> Option<Arc<LoadBalancer<RoundRobin>>> {
        self.get_lb_by_id(server_id).await
    }

    pub async fn get_metric_items(&self) -> Vec<MetricItemConfig> {
        let lock = self.inner.read().unwrap();
        lock.metric_items.clone()
    }

    pub async fn get_plan_ids(&self) -> Vec<i64> {
        let lock = self.inner.read().unwrap();
        let mut plan_ids = lock
            .servers
            .values()
            .filter_map(|server| (server.user_plan_id > 0).then_some(server.user_plan_id))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        plan_ids.sort_unstable();
        plan_ids
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

    pub async fn get_node_region_id(&self) -> i64 {
        let lock = self.inner.read().unwrap();
        lock.node_region_id
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
        node_region_id: i64,
        all_servers: Vec<Arc<ServerConfig>>,
        servers: HashMap<String, Arc<ServerConfig>>,
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
        uam_policies: HashMap<i64, UAMPolicy>,
        http_cc_policies: HashMap<i64, HTTPCCPolicy>,
        http3_policies: HashMap<i64, HTTP3Policy>,
        http_pages_policies: HashMap<i64, HTTPPagesPolicy>,
        webp_image_policies: HashMap<i64, WebPImagePolicy>,
        toa: Option<TOAConfig>,
    ) {
        let mut lock = self.inner.write().unwrap();
        lock.id = id;
        lock.version = version;
        lock.node_region_id = node_region_id;
        lock.all_servers = all_servers;
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
        lock.uam_policies = uam_policies;
        lock.http_cc_policies = http_cc_policies;
        lock.http3_policies = http3_policies;
        lock.http_pages_policies = http_pages_policies;
        lock.webp_image_policies = webp_image_policies;
        lock.toa = toa;
        // Track whether any SNI passthrough server exists (for fast TLS path)
        lock.has_any_sni_passthrough = lock.all_servers.iter().any(|s| s.is_sni_passthrough());
        drop(lock);
        self.notify_runtime_reload();
    }

    pub async fn replace_server(
        &self,
        server_id: i64,
        all_servers: Vec<Arc<ServerConfig>>,
        servers: HashMap<String, Arc<ServerConfig>>,
        routes: HashMap<String, Arc<LoadBalancer<RoundRobin>>>,
    ) {
        let mut lock = self.inner.write().unwrap();
        lock.all_servers
            .retain(|server| server.numeric_id() != server_id);
        let stale_hosts = lock
            .servers
            .iter()
            .filter_map(|(host, server)| (server.numeric_id() == server_id).then_some(host.clone()))
            .collect::<Vec<_>>();

        for host in &stale_hosts {
            lock.servers.remove(host);
            lock.routes.remove(host);
        }
        if server_id > 0 {
            lock.id_to_lb.remove(&server_id);
        }

        lock.all_servers.extend(all_servers);
        for (host, config) in servers {
            lock.servers.insert(host, config);
        }
        for (host, lb) in routes {
            if server_id > 0 {
                lock.id_to_lb.insert(server_id, lb.clone());
            }
            lock.routes.insert(host, lb);
        }
        drop(lock);
        self.notify_runtime_reload();
    }

    pub async fn replace_user_servers(
        &self,
        user_id: i64,
        all_servers: Vec<Arc<ServerConfig>>,
        servers: HashMap<String, Arc<ServerConfig>>,
        routes: HashMap<String, Arc<LoadBalancer<RoundRobin>>>,
    ) {
        let mut lock = self.inner.write().unwrap();
        lock.all_servers.retain(|server| server.user_id != user_id);
        let stale_hosts = lock
            .servers
            .iter()
            .filter_map(|(host, server)| (server.user_id == user_id).then_some(host.clone()))
            .collect::<Vec<_>>();
        let stale_server_ids = lock
            .servers
            .values()
            .filter_map(|server| (server.user_id == user_id).then_some(server.numeric_id()))
            .collect::<std::collections::HashSet<_>>();

        for host in &stale_hosts {
            lock.servers.remove(host);
            lock.routes.remove(host);
        }
        for server_id in stale_server_ids {
            if server_id > 0 {
                lock.id_to_lb.remove(&server_id);
            }
        }

        lock.all_servers.extend(all_servers);
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
        drop(lock);
        self.notify_runtime_reload();
    }

    pub async fn remove_user_servers(&self, user_id: i64) {
        let mut lock = self.inner.write().unwrap();
        lock.all_servers.retain(|server| server.user_id != user_id);
        let stale_hosts = lock
            .servers
            .iter()
            .filter_map(|(host, server)| (server.user_id == user_id).then_some(host.clone()))
            .collect::<Vec<_>>();
        let stale_server_ids = lock
            .servers
            .values()
            .filter_map(|server| (server.user_id == user_id).then_some(server.numeric_id()))
            .collect::<std::collections::HashSet<_>>();

        for host in stale_hosts {
            lock.servers.remove(&host);
            lock.routes.remove(&host);
        }
        for server_id in stale_server_ids {
            if server_id > 0 {
                lock.id_to_lb.remove(&server_id);
            }
        }
        drop(lock);
        self.notify_runtime_reload();
    }

    pub async fn remove_server(&self, server_id: i64) {
        let mut lock = self.inner.write().unwrap();
        lock.all_servers
            .retain(|server| server.numeric_id() != server_id);
        let stale_hosts = lock
            .servers
            .iter()
            .filter_map(|(host, server)| (server.numeric_id() == server_id).then_some(host.clone()))
            .collect::<Vec<_>>();

        for host in stale_hosts {
            lock.servers.remove(&host);
            lock.routes.remove(&host);
        }
        if server_id > 0 {
            lock.id_to_lb.remove(&server_id);
        }
        drop(lock);
        self.notify_runtime_reload();
    }

    pub async fn cache_server_route(
        &self,
        host: String,
        server: Arc<ServerConfig>,
        lb: Arc<LoadBalancer<RoundRobin>>,
    ) {
        let mut lock = self.inner.write().unwrap();
        let server_id = server.numeric_id();
        if server_id > 0 {
            lock.id_to_lb.insert(server_id, lb.clone());
            lock.all_servers
                .retain(|existing| existing.numeric_id() != server_id);
        }
        lock.all_servers.push(server.clone());
        lock.servers.insert(host.clone(), server);
        lock.routes.insert(host, lb);
        drop(lock);
        self.notify_runtime_reload();
    }

    pub async fn set_deleted_contents(&self, deleted_contents: Vec<String>) {
        let mut lock = self.inner.write().unwrap();
        lock.deleted_contents = deleted_contents;
    }

    pub async fn set_plans(&self, plans: HashMap<i64, crate::pb::Plan>) {
        let mut lock = self.inner.write().unwrap();
        lock.plans = plans;
    }

    pub async fn set_user_plans(&self, user_plans: HashMap<i64, crate::pb::UserPlan>) {
        let mut lock = self.inner.write().unwrap();
        lock.user_plans = user_plans;
    }

    pub async fn update_node_level_info(
        &self,
        level: i32,
        parent_nodes: HashMap<i64, Vec<ParentNodeConfig>>,
    ) {
        let allow_lan_ip = {
            let lock = self.inner.read().unwrap();
            lock.allow_lan_ip
        };

        let mut parent_routes = HashMap::new();
        for (cluster_id, nodes) in &parent_nodes {
            let lb = crate::lb_factory::build_parent_lb(*cluster_id, nodes, allow_lan_ip);
            parent_routes.insert(*cluster_id, lb);
        }

        let mut lock = self.inner.write().unwrap();
        lock.level = level;
        lock.parent_nodes = parent_nodes;
        lock.parent_routes = parent_routes;
        drop(lock);
        self.notify_runtime_reload();
    }
}
