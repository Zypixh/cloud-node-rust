use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use pingora_load_balancing::{LoadBalancer, selection::Consistent};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Notify;
use tracing::warn;

use crate::config_models::{
    HTTP3Policy, HTTPCCPolicy, HTTPCachePolicy, HTTPFirewallPolicy, HTTPPageConfig,
    HTTPPagesPolicy, MetricItemConfig, ParentNodeConfig, SSLCertConfig, SSLPolicyConfig,
    ServerConfig, SizeCapacity, TOAConfig, TrafficLimitConfig, UAMPolicy, WAFBlockOptions,
    WebPImagePolicy,
};

#[derive(Clone, Default)]
pub struct PlanDerivedConfig {
    pub max_upload_bytes: i64,
    pub traffic_limit_notice_body: Option<String>,
    pub cc_max_qps: i32,
    pub cc_per_ip_max_qps: i32,
    pub cc_max_bandwidth: i64,
}

/// Configuration for the local cloud node.
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
    pub routes: HashMap<String, Arc<crate::lb_factory::AnyLoadBalancer>>,
    /// Direct mapping from Server ID to Load Balancer
    pub id_to_lb: HashMap<i64, Arc<crate::lb_factory::AnyLoadBalancer>>,
    /// Banned URLs (e.g. for legal compliance)
    pub deleted_contents: Vec<String>,
    pub deleted_content_urls: HashSet<String>,
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
    /// Node cluster ID for policy selection (0 = default cluster)
    pub node_cluster_id: i64,
    /// Module enable flags from findEnabledNodeConfigInfo
    pub dns_info_enabled: bool,
    pub cache_info_enabled: bool,
    pub thresholds_enabled: bool,
    pub ssh_enabled: bool,
    pub system_settings_enabled: bool,
    pub ddos_protection_enabled: bool,
    pub schedule_info_enabled: bool,
    pub access_log_settings_enabled: bool,
    /// Whether the node is enabled
    pub is_on: bool,
    /// Whether to sync IP lists
    pub enable_ip_lists: bool,
    /// Parent nodes (L2s) for tiered origin, grouped by cluster id
    pub parent_nodes: Arc<HashMap<i64, Vec<ParentNodeConfig>>>,
    /// Whether to bypass L2 and go direct to origin (Load protection)
    pub tiered_origin_bypass: bool,
    /// Force all requests through L2 (Tiered Origin)
    pub force_ln_request: bool,
    /// Selection method for L2 nodes: "random" or "urlMapping"
    pub ln_request_scheduling_method: String,
    /// L2 Load Balancers (Tiered Origin pools)
    pub parent_routes: HashMap<i64, Arc<LoadBalancer<Consistent>>>,
    /// Global gRPC policy
    pub grpc_policy: Option<Arc<crate::config_models::GRPCConfig>>,
    /// Cluster/global certificates delivered with the full node config.
    pub ssl_certs: Vec<SSLCertConfig>,
    pub ssl_policy: Option<SSLPolicyConfig>,
    /// Last updating-server-list cursor delivered with the full node config.
    pub updating_server_list_id: i64,

    // New Global Cluster Settings
    pub supports_low_version_http: bool,
    pub match_cert_from_all_servers: bool,
    pub server_name: String,
    pub enable_server_addr_variable: bool,
    pub request_origins_with_encodings: bool,
    pub xff_max_addresses: i32,
    pub allow_lan_ip: bool,
    /// Pre-built global HTTP config to avoid per-request construction inside config lock.
    pub global_http_config: Arc<crate::config_models::GlobalHTTPAllConfig>,

    /// Global or node-specific cache policies (multi-policy support)
    pub cache_policies: Arc<Vec<Arc<HTTPCachePolicy>>>,
    /// Global or node-specific firewall policies
    pub firewall_policies: Arc<Vec<HTTPFirewallPolicy>>,
    /// Firewall policies that can be attributed to a site cluster via server references.
    pub firewall_policies_by_cluster: HashMap<i64, Arc<Vec<HTTPFirewallPolicy>>>,
    pub compiled_plans: Arc<crate::compiled::CompiledPlanSet>,
    /// Global WAF action defaults
    pub waf_actions: Arc<Vec<crate::config_models::WAFActionConfig>>,
    pub global_waf_block_options: Option<Arc<WAFBlockOptions>>,
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
    pub global_access_log: Option<Arc<crate::config_models::GlobalHTTPAccessLogConfig>>,
    pub global_stat_upload: Arc<crate::config_models::GlobalStatUploadConfig>,
    /// Cached plans referenced by current runtime servers
    pub plans: HashMap<i64, crate::pb::Plan>,
    /// Cached user plans referenced by current runtime servers
    pub user_plans: HashMap<i64, crate::pb::UserPlan>,
    pub plan_derived: HashMap<i64, PlanDerivedConfig>,
    /// Whether any SNI passthrough server is configured (fast check for TLS path)
    pub has_any_sni_passthrough: bool,
    pub sni_passthrough_exact: HashMap<(u16, String), Arc<ServerConfig>>,
    pub sni_passthrough_wildcard: HashMap<(u16, String), Arc<ServerConfig>>,
    pub has_any_quic_passthrough: bool,
    pub quic_passthrough_exact: HashMap<(u16, String), Arc<ServerConfig>>,
    pub quic_passthrough_wildcard: HashMap<(u16, String), Arc<ServerConfig>>,
    pub unique_quic_passthrough_by_port: HashMap<u16, Option<Arc<ServerConfig>>>,
    pub udp_server_by_port: HashMap<u16, Arc<ServerConfig>>,
}

#[derive(Clone)]
pub struct TlsRouteInspection {
    pub host: String,
    pub has_l7_server: bool,
    pub sni_passthrough_server: Option<Arc<ServerConfig>>,
}

fn compile_plan_derived(plan: &crate::pb::Plan) -> PlanDerivedConfig {
    let (cc_max_qps, cc_per_ip_max_qps, cc_max_bandwidth) = compile_plan_cc_limits(plan);
    PlanDerivedConfig {
        max_upload_bytes: compile_plan_max_upload_bytes(plan),
        traffic_limit_notice_body: compile_plan_traffic_limit_notice_body(plan),
        cc_max_qps,
        cc_per_ip_max_qps,
        cc_max_bandwidth,
    }
}

fn compile_plan_cc_limits(plan: &crate::pb::Plan) -> (i32, i32, i64) {
    if plan.features_json.is_empty() {
        return (0, 0, 0);
    }
    let value = match serde_json::from_slice::<serde_json::Value>(&plan.features_json) {
        Ok(v) => v,
        Err(_) => return (0, 0, 0),
    };
    let max_qps = value
        .get("ccMaxQPS")
        .and_then(|v| v.as_i64())
        .map(|v| v.max(0) as i32)
        .unwrap_or(0);
    let per_ip_max_qps = value
        .get("ccPerIPMaxQPS")
        .and_then(|v| v.as_i64())
        .map(|v| v.max(0) as i32)
        .unwrap_or(0);
    let max_bandwidth = value
        .get("ccMaxBandwidth")
        .and_then(|v| v.as_i64())
        .map(|v| v.max(0))
        .unwrap_or(0);
    (max_qps, per_ip_max_qps, max_bandwidth)
}

fn compile_plan_max_upload_bytes(plan: &crate::pb::Plan) -> i64 {
    if plan.max_upload_size_json.is_empty() {
        return 0;
    }
    let value = match serde_json::from_slice::<serde_json::Value>(&plan.max_upload_size_json) {
        Ok(value) => value,
        Err(_) => return 0,
    };
    if let Some(bytes) = value.as_i64() {
        return bytes.max(0);
    }
    if let Some(bytes) = value.get("bytes").and_then(|v| v.as_i64()) {
        return bytes.max(0);
    }
    SizeCapacity::from_json(&value).to_bytes().max(0)
}

fn compile_plan_traffic_limit_notice_body(plan: &crate::pb::Plan) -> Option<String> {
    if plan.traffic_limit_json.is_empty() {
        return None;
    }
    let config = serde_json::from_slice::<TrafficLimitConfig>(&plan.traffic_limit_json).ok()?;
    (config.is_on && !config.notice_page_body.is_empty()).then_some(config.notice_page_body)
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
            deleted_content_urls: HashSet::new(),
            global_pages: Vec::new(),
            updating_server_ids: std::collections::HashSet::new(),
            metric_items: Vec::new(),
            level: 1, // Default to L1
            node_region_id: 0,
            node_cluster_id: 0,
            dns_info_enabled: true,
            cache_info_enabled: true,
            thresholds_enabled: true,
            ssh_enabled: true,
            system_settings_enabled: true,
            ddos_protection_enabled: true,
            schedule_info_enabled: true,
            access_log_settings_enabled: true,
            is_on: true,
            enable_ip_lists: false,
            parent_nodes: Arc::new(HashMap::new()),
            tiered_origin_bypass: false,
            force_ln_request: false,
            ln_request_scheduling_method: "random".to_string(),
            parent_routes: HashMap::new(),
            grpc_policy: None,
            ssl_certs: Vec::new(),
            ssl_policy: None,
            updating_server_list_id: 0,
            supports_low_version_http: false,
            match_cert_from_all_servers: false,
            server_name: String::new(),
            enable_server_addr_variable: false,
            request_origins_with_encodings: false,
            xff_max_addresses: 0,
            allow_lan_ip: false,
            global_http_config: Arc::default(),
            cache_policies: Arc::new(Vec::new()),
            firewall_policies: Arc::new(Vec::new()),
            firewall_policies_by_cluster: HashMap::new(),
            compiled_plans: Arc::new(crate::compiled::CompiledPlanSet::default()),
            waf_actions: Arc::new(Vec::new()),
            global_waf_block_options: None,
            uam_policies: HashMap::new(),
            http_cc_policies: HashMap::new(),
            http3_policies: HashMap::new(),
            http_pages_policies: HashMap::new(),
            webp_image_policies: HashMap::new(),
            toa: None,
            global_access_log: None,
            global_stat_upload: Arc::default(),
            plans: HashMap::new(),
            user_plans: HashMap::new(),
            plan_derived: HashMap::new(),
            has_any_sni_passthrough: false,
            sni_passthrough_exact: HashMap::new(),
            sni_passthrough_wildcard: HashMap::new(),
            has_any_quic_passthrough: false,
            quic_passthrough_exact: HashMap::new(),
            quic_passthrough_wildcard: HashMap::new(),
            unique_quic_passthrough_by_port: HashMap::new(),
            udp_server_by_port: HashMap::new(),
        }
    }
}

/// A thread-safe handle to the NodeConfig to allow dynamic updates from the gRPC syncer.
#[derive(Clone)]
pub struct ConfigStore {
    inner: Arc<RwLock<NodeConfig>>,
    update_gate: Arc<Mutex<()>>,
    reload_notify: Arc<Notify>,
    reload_generation: Arc<AtomicU64>,
    parent_pressure: Arc<DashMap<String, (f32, std::time::Instant)>>,
}

#[derive(Clone, Default)]
pub struct EnabledNodeFeatures {
    pub dns_info: bool,
    pub cache_info: bool,
    pub thresholds: bool,
    pub ssh: bool,
    pub system_settings: bool,
    pub ddos_protection: bool,
    pub schedule_info: bool,
    pub access_log_settings: bool,
}

#[derive(Clone)]
pub struct HotPathSnapshot {
    pub is_on: bool,
    pub global_http: Arc<crate::config_models::GlobalHTTPAllConfig>,
    pub firewall_policies: Arc<Vec<HTTPFirewallPolicy>>,
    pub compiled_plans: Arc<crate::compiled::CompiledPlanSet>,
    pub grpc_policy: Option<Arc<crate::config_models::GRPCConfig>>,
    pub has_any_sni_passthrough: bool,
    pub cache_policies: Arc<Vec<Arc<HTTPCachePolicy>>>,
    pub global_access_log: Option<Arc<crate::config_models::GlobalHTTPAccessLogConfig>>,
    pub global_waf_block_options: Option<Arc<WAFBlockOptions>>,
    pub enabled_features: EnabledNodeFeatures,
}

#[derive(Clone)]
pub struct OriginBuildContext {
    pub generation: u64,
    pub node_level: i32,
    pub parent_nodes: Arc<HashMap<i64, Vec<ParentNodeConfig>>>,
    pub tiered_origin_bypass: bool,
    pub allow_lan: bool,
    pub global_http: Option<crate::config_models::GlobalHTTPAllConfig>,
}

pub enum ServerRuntimeMutation {
    ReplaceServer {
        server_id: i64,
        all_servers: Vec<Arc<ServerConfig>>,
        servers: HashMap<String, Arc<ServerConfig>>,
        routes: HashMap<String, Arc<crate::lb_factory::AnyLoadBalancer>>,
    },
    ReplaceUserServers {
        user_id: i64,
        all_servers: Vec<Arc<ServerConfig>>,
        servers: HashMap<String, Arc<ServerConfig>>,
        routes: HashMap<String, Arc<crate::lb_factory::AnyLoadBalancer>>,
    },
    RemoveServer {
        server_id: i64,
    },
    RemoveUserServers {
        user_id: i64,
    },
}

impl Default for ConfigStore {
    fn default() -> Self {
        Self::new()
    }
}

fn cert_data_score(cert: &SSLCertConfig) -> usize {
    fn score(value: &Option<serde_json::Value>) -> usize {
        match value {
            Some(serde_json::Value::String(s)) => {
                if s.contains("-----BEGIN ") {
                    4
                } else if s.contains("GOEDGE_DATA_MAP:") || s.contains("_DATA_MAP:") {
                    1
                } else if s.trim().len() >= 128 {
                    3
                } else {
                    2
                }
            }
            Some(serde_json::Value::Array(items)) if items.len() >= 128 => 3,
            Some(serde_json::Value::Object(_)) => 2,
            Some(_) => 1,
            None => 0,
        }
    }

    score(&cert.cert_data_json) + score(&cert.key_data_json)
}

fn dedup_ssl_certs(certs: Vec<SSLCertConfig>) -> Vec<SSLCertConfig> {
    let mut order = Vec::new();
    let mut by_id: HashMap<i64, SSLCertConfig> = HashMap::new();
    // Certs with id<=0 are unsaved/local — they previously collided on the
    // same map key (0 or -1), silently dropping all but the last one.
    // Give each its own synthetic negative key so order/by_id stay in sync.
    let mut synthetic_id: i64 = -1;

    for mut cert in certs {
        if cert.id <= 0 {
            let key = synthetic_id;
            synthetic_id -= 1;
            cert.id = key;
            order.push(key);
            by_id.insert(key, cert);
            continue;
        }
        if !by_id.contains_key(&cert.id) {
            order.push(cert.id);
            by_id.insert(cert.id, cert);
            continue;
        }
        let replace = by_id
            .get(&cert.id)
            .map(|existing| cert_data_score(&cert) > cert_data_score(existing))
            .unwrap_or(true);
        if replace {
            by_id.insert(cert.id, cert);
        }
    }

    order.dedup();
    order
        .into_iter()
        .filter_map(|id| by_id.remove(&id))
        .collect()
}

impl ConfigStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(NodeConfig::default())),
            update_gate: Arc::new(Mutex::new(())),
            reload_notify: Arc::new(Notify::new()),
            reload_generation: Arc::new(AtomicU64::new(0)),
            parent_pressure: Arc::new(DashMap::new()),
        }
    }

    pub fn runtime_reload_generation(&self) -> u64 {
        self.reload_generation.load(Ordering::Acquire)
    }

    pub async fn wait_for_runtime_reload(&self, seen_generation: u64) -> u64 {
        loop {
            let notified = self.reload_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let generation = self.reload_generation.load(Ordering::Acquire);
            if generation != seen_generation {
                return generation;
            }
            notified.await;
        }
    }

    fn notify_runtime_reload(&self) {
        self.reload_generation.fetch_add(1, Ordering::Release);
        self.reload_notify.notify_waiters();
    }

    // Sync versions for high-performance path (proxy)
    pub fn get_upstream_sync(&self, host: &str) -> Option<Arc<crate::lb_factory::AnyLoadBalancer>> {
        let lock = self.inner.read();
        let normalized = Self::normalize_host(host);
        Self::find_route_locked(&lock, &normalized)
    }

    pub fn get_server_sync(&self, host: &str) -> Option<Arc<ServerConfig>> {
        let lock = self.inner.read();
        let normalized = Self::normalize_host(host);
        Self::find_server_locked(&lock, &normalized)
    }

    pub fn get_server_and_upstream_sync(
        &self,
        host: &str,
    ) -> (
        Option<Arc<ServerConfig>>,
        Option<Arc<crate::lb_factory::AnyLoadBalancer>>,
    ) {
        let lock = self.inner.read();
        let normalized = Self::normalize_host(host);
        (
            Self::find_server_locked(&lock, &normalized),
            Self::find_route_locked(&lock, &normalized),
        )
    }

    /// Lightweight check: avoids full HotPathSnapshot clone, only reads one bool.
    pub fn has_any_sni_passthrough_sync(&self) -> bool {
        self.inner.read().has_any_sni_passthrough
    }

    pub fn has_any_quic_passthrough_sync(&self) -> bool {
        self.inner.read().has_any_quic_passthrough
    }

    pub fn get_hot_path_snapshot_sync(&self) -> HotPathSnapshot {
        let lock = self.inner.read();
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
        Option<Arc<crate::lb_factory::AnyLoadBalancer>>,
    ) {
        let lock = self.inner.read();
        let hot_path = Self::build_hot_path_snapshot(&lock);
        let normalized = Self::normalize_host(host);

        (
            hot_path,
            Self::find_server_locked(&lock, &normalized),
            Self::find_route_locked(&lock, &normalized),
        )
    }

    fn normalize_host(host: &str) -> String {
        crate::lb_factory::strip_addr_port(host)
            .trim_end_matches('.')
            .to_ascii_lowercase()
    }

    fn find_server_locked(lock: &NodeConfig, normalized_host: &str) -> Option<Arc<ServerConfig>> {
        if let Some(server) = lock.servers.get(normalized_host) {
            return Some(server.clone());
        }
        let mut wildcard = String::with_capacity(normalized_host.len() + 2);
        wildcard.push_str("*.");
        wildcard.push_str(normalized_host);
        if let Some(server) = lock.servers.get(&wildcard) {
            return Some(server.clone());
        }
        let mut suffix = normalized_host;
        while let Some((_, rest)) = suffix.split_once('.') {
            suffix = rest;
            wildcard.truncate(2);
            wildcard.push_str(suffix);
            if let Some(server) = lock.servers.get(&wildcard) {
                return Some(server.clone());
            }
        }
        None
    }

    fn find_route_locked(
        lock: &NodeConfig,
        normalized_host: &str,
    ) -> Option<Arc<crate::lb_factory::AnyLoadBalancer>> {
        if let Some(route) = lock.routes.get(normalized_host) {
            return Some(route.clone());
        }
        let mut wildcard = String::with_capacity(normalized_host.len() + 2);
        wildcard.push_str("*.");
        wildcard.push_str(normalized_host);
        if let Some(route) = lock.routes.get(&wildcard) {
            return Some(route.clone());
        }
        let mut suffix = normalized_host;
        while let Some((_, rest)) = suffix.split_once('.') {
            suffix = rest;
            wildcard.truncate(2);
            wildcard.push_str(suffix);
            if let Some(route) = lock.routes.get(&wildcard) {
                return Some(route.clone());
            }
        }
        None
    }

    fn build_hot_path_snapshot(lock: &NodeConfig) -> HotPathSnapshot {
        HotPathSnapshot {
            is_on: lock.is_on,
            global_http: Arc::clone(&lock.global_http_config),
            firewall_policies: Arc::clone(&lock.firewall_policies),
            compiled_plans: Arc::clone(&lock.compiled_plans),
            grpc_policy: lock.grpc_policy.clone(),
            has_any_sni_passthrough: lock.has_any_sni_passthrough,
            cache_policies: lock.cache_policies.clone(),
            global_access_log: lock.global_access_log.clone(),
            global_waf_block_options: lock.global_waf_block_options.clone(),
            enabled_features: EnabledNodeFeatures {
                dns_info: lock.dns_info_enabled,
                cache_info: lock.cache_info_enabled,
                thresholds: lock.thresholds_enabled,
                ssh: lock.ssh_enabled,
                system_settings: lock.system_settings_enabled,
                ddos_protection: lock.ddos_protection_enabled,
                schedule_info: lock.schedule_info_enabled,
                access_log_settings: lock.access_log_settings_enabled,
            },
        }
    }

    pub fn get_server_for_tls_name_sync(&self, host: &str) -> Option<Arc<ServerConfig>> {
        let normalized = Self::normalize_host(host);
        let lock = self.inner.read();

        Self::find_l7_server_locked(&lock, &normalized)
            .or_else(|| Self::find_sni_passthrough_server_locked(&lock, &normalized, 0))
    }

    pub fn get_l7_server_for_tls_name_sync(&self, host: &str) -> Option<Arc<ServerConfig>> {
        let normalized = Self::normalize_host(host);
        let lock = self.inner.read();
        Self::find_l7_server_locked(&lock, &normalized)
    }

    pub fn get_exact_l7_server_for_tls_name_sync(&self, host: &str) -> Option<Arc<ServerConfig>> {
        let normalized = Self::normalize_host(host);
        let lock = self.inner.read();
        lock.servers
            .get(&normalized)
            .filter(|server| !server.is_sni_passthrough() && !server.is_quic_passthrough())
            .cloned()
    }

    pub fn find_exact_sni_passthrough_server_sync(
        &self,
        host: &str,
        port: u16,
    ) -> Option<Arc<ServerConfig>> {
        let normalized = Self::normalize_host(host);
        let lock = self.inner.read();
        lock.sni_passthrough_exact.get(&(port, normalized)).cloned()
    }

    fn find_l7_server_locked(
        lock: &NodeConfig,
        normalized_host: &str,
    ) -> Option<Arc<ServerConfig>> {
        let is_l7 = |server: &&Arc<ServerConfig>| {
            !server.is_sni_passthrough() && !server.is_quic_passthrough()
        };

        if let Some(server) = lock.servers.get(normalized_host).filter(is_l7) {
            return Some(server.clone());
        }
        let mut wildcard = String::with_capacity(normalized_host.len() + 2);
        wildcard.push_str("*.");
        wildcard.push_str(normalized_host);
        if let Some(server) = lock.servers.get(&wildcard).filter(is_l7) {
            return Some(server.clone());
        }

        let mut suffix = normalized_host;
        while let Some((_, rest)) = suffix.split_once('.') {
            suffix = rest;
            wildcard.truncate(2);
            wildcard.push_str(suffix);
            if let Some(server) = lock.servers.get(&wildcard).filter(is_l7) {
                return Some(server.clone());
            }
        }

        None
    }

    pub fn find_sni_passthrough_server_sync(
        &self,
        host: &str,
        port: u16,
    ) -> Option<Arc<ServerConfig>> {
        let normalized = Self::normalize_host(host);
        let lock = self.inner.read();
        Self::find_sni_passthrough_server_locked(&lock, &normalized, port)
    }

    pub fn find_quic_passthrough_server_sync(
        &self,
        host: &str,
        port: u16,
    ) -> Option<Arc<ServerConfig>> {
        let normalized = Self::normalize_host(host);
        let lock = self.inner.read();
        Self::find_quic_passthrough_server_locked(&lock, &normalized, port)
    }

    pub fn find_exact_quic_passthrough_server_sync(
        &self,
        host: &str,
        port: u16,
    ) -> Option<Arc<ServerConfig>> {
        let normalized = Self::normalize_host(host);
        let lock = self.inner.read();
        for lookup_port in [port, 0] {
            if let Some(server) = lock
                .quic_passthrough_exact
                .get(&(lookup_port, normalized.clone()))
            {
                return Some(server.clone());
            }
        }
        None
    }

    pub fn find_unique_quic_passthrough_server_by_port_sync(
        &self,
        port: u16,
    ) -> Option<Arc<ServerConfig>> {
        let lock = self.inner.read();
        lock.unique_quic_passthrough_by_port
            .get(&port)
            .and_then(Clone::clone)
    }

    pub fn has_quic_passthrough_on_port_sync(&self, port: u16) -> bool {
        let lock = self.inner.read();
        lock.unique_quic_passthrough_by_port.contains_key(&port)
    }

    pub fn quic_passthrough_ports_sync(&self) -> HashSet<u16> {
        let lock = self.inner.read();
        lock.unique_quic_passthrough_by_port
            .keys()
            .copied()
            .collect()
    }

    pub fn find_udp_server_by_port_sync(&self, port: u16) -> Option<Arc<ServerConfig>> {
        self.inner.read().udp_server_by_port.get(&port).cloned()
    }

    pub fn inspect_tls_route_sync(&self, host: &str, port: u16) -> Option<TlsRouteInspection> {
        let normalized = Self::normalize_host(host);
        let lock = self.inner.read();
        if lock
            .servers
            .get(&normalized)
            .filter(|server| {
                !server.is_sni_passthrough()
                    && !server.is_quic_passthrough()
                    && server.listens_on_https_port(port)
            })
            .is_some()
        {
            return Some(TlsRouteInspection {
                host: normalized,
                has_l7_server: true,
                sni_passthrough_server: None,
            });
        }

        if let Some(server) = lock
            .sni_passthrough_exact
            .get(&(port, normalized.clone()))
            .cloned()
        {
            return Some(TlsRouteInspection {
                host: normalized,
                has_l7_server: false,
                sni_passthrough_server: Some(server),
            });
        }

        if Self::find_l7_server_locked(&lock, &normalized)
            .is_some_and(|server| server.listens_on_https_port(port))
        {
            return Some(TlsRouteInspection {
                host: normalized,
                has_l7_server: true,
                sni_passthrough_server: None,
            });
        }

        Some(TlsRouteInspection {
            sni_passthrough_server: Self::find_sni_passthrough_server_locked(
                &lock,
                &normalized,
                port,
            ),
            host: normalized,
            has_l7_server: false,
        })
    }

    fn find_sni_passthrough_server_locked(
        lock: &NodeConfig,
        normalized_host: &str,
        port: u16,
    ) -> Option<Arc<ServerConfig>> {
        Self::find_passthrough_server_locked(
            &lock.sni_passthrough_exact,
            &lock.sni_passthrough_wildcard,
            normalized_host,
            port,
        )
    }

    fn find_quic_passthrough_server_locked(
        lock: &NodeConfig,
        normalized_host: &str,
        port: u16,
    ) -> Option<Arc<ServerConfig>> {
        Self::find_passthrough_server_locked(
            &lock.quic_passthrough_exact,
            &lock.quic_passthrough_wildcard,
            normalized_host,
            port,
        )
    }

    fn find_passthrough_server_locked(
        exact: &HashMap<(u16, String), Arc<ServerConfig>>,
        wildcard: &HashMap<(u16, String), Arc<ServerConfig>>,
        normalized_host: &str,
        port: u16,
    ) -> Option<Arc<ServerConfig>> {
        for lookup_port in [port, 0] {
            if let Some(server) = exact.get(&(lookup_port, normalized_host.to_string())) {
                return Some(server.clone());
            }
            if let Some(server) = wildcard.get(&(lookup_port, normalized_host.to_string())) {
                return Some(server.clone());
            }
            let mut suffix = normalized_host;
            while let Some((_, rest)) = suffix.split_once('.') {
                suffix = rest;
                if let Some(server) = wildcard.get(&(lookup_port, suffix.to_string())) {
                    return Some(server.clone());
                }
            }
        }
        None
    }

    pub fn get_cache_policy_sync(&self) -> Arc<Vec<Arc<HTTPCachePolicy>>> {
        let lock = self.inner.read();
        Arc::clone(&lock.cache_policies)
    }

    pub fn get_firewall_policies_sync(&self) -> Arc<Vec<HTTPFirewallPolicy>> {
        let lock = self.inner.read();
        Arc::clone(&lock.firewall_policies)
    }

    pub fn get_firewall_policies_for_cluster_sync(
        &self,
        cluster_id: i64,
    ) -> Arc<Vec<HTTPFirewallPolicy>> {
        if cluster_id <= 0 {
            return Arc::new(Vec::new());
        }
        let lock = self.inner.read();
        lock.firewall_policies_by_cluster
            .get(&cluster_id)
            .cloned()
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    pub(crate) fn get_tls_exhaustion_config_for_cluster_sync(
        &self,
        cluster_id: i64,
    ) -> Option<crate::special_defense::SpecialDefenseConfig> {
        if cluster_id <= 0 {
            return None;
        }
        let policies = self.get_firewall_policies_for_cluster_sync(cluster_id);
        policies.iter().find_map(|policy| {
            if !policy.is_on {
                return None;
            }
            let config = policy.tls_exhaustion_attack.as_ref()?;
            if !config.is_on || config.max_handshake_fails == 0 {
                return None;
            }
            Some(crate::special_defense::SpecialDefenseConfig {
                threshold: config.max_handshake_fails,
                period_secs: i64::from(config.period).max(1),
                block_secs: i64::from(config.block_seconds).max(1),
                use_local_firewall: policy.use_local_firewall,
                policy_name: policy.name.clone(),
            })
        })
    }

    pub(crate) fn get_empty_connection_flood_config_for_cluster_sync(
        &self,
        cluster_id: i64,
    ) -> Option<crate::special_defense::SpecialDefenseConfig> {
        if cluster_id <= 0 {
            return None;
        }
        let policies = self.get_firewall_policies_for_cluster_sync(cluster_id);
        policies.iter().find_map(|policy| {
            if !policy.is_on {
                return None;
            }
            let config = policy.empty_connection_flood.as_ref()?;
            if !config.is_on || config.max_empty_connections == 0 {
                return None;
            }
            Some(crate::special_defense::SpecialDefenseConfig {
                threshold: config.max_empty_connections,
                period_secs: i64::from(config.period).max(1),
                block_secs: i64::from(config.block_seconds).max(1),
                use_local_firewall: policy.use_local_firewall,
                policy_name: policy.name.clone(),
            })
        })
    }

    pub fn get_http_cc_policy_for_cluster_sync(&self, cluster_id: i64) -> Option<HTTPCCPolicy> {
        if cluster_id <= 0 {
            return None;
        }
        let lock = self.inner.read();
        lock.http_cc_policies.get(&cluster_id).cloned()
    }

    pub fn get_waf_actions_sync(&self) -> Arc<Vec<crate::config_models::WAFActionConfig>> {
        let lock = self.inner.read();
        Arc::clone(&lock.waf_actions)
    }

    pub fn get_global_pages_sync(&self) -> Vec<HTTPPageConfig> {
        let lock = self.inner.read();
        lock.global_pages.clone()
    }

    fn pick_global_policy<T: Clone>(map: &HashMap<i64, T>, node_cluster_id: i64) -> Option<T> {
        // Priority: exact cluster_id → default cluster (0) → any available
        map.get(&node_cluster_id)
            .or_else(|| map.get(&0))
            .or_else(|| map.values().next())
            .cloned()
    }

    pub fn get_global_uam_policy_sync(&self) -> Option<UAMPolicy> {
        let lock = self.inner.read();
        let cluster_id = lock.node_cluster_id;
        Self::pick_global_policy(&lock.uam_policies, cluster_id)
    }

    pub fn get_global_http_cc_policy_sync(&self) -> Option<HTTPCCPolicy> {
        let lock = self.inner.read();
        let cluster_id = lock.node_cluster_id;
        Self::pick_global_policy(&lock.http_cc_policies, cluster_id)
    }

    pub fn get_global_http3_policy_sync(&self) -> Option<HTTP3Policy> {
        let lock = self.inner.read();
        let cluster_id = lock.node_cluster_id;
        Self::pick_global_policy(&lock.http3_policies, cluster_id)
    }

    pub fn get_global_http_pages_policy_sync(&self) -> Option<HTTPPagesPolicy> {
        let lock = self.inner.read();
        let cluster_id = lock.node_cluster_id;
        Self::pick_global_policy(&lock.http_pages_policies, cluster_id)
    }

    pub fn get_global_webp_policy_sync(&self) -> Option<WebPImagePolicy> {
        let lock = self.inner.read();
        let cluster_id = lock.node_cluster_id;
        Self::pick_global_policy(&lock.webp_image_policies, cluster_id)
    }

    pub fn get_toa_config_sync(&self) -> Option<TOAConfig> {
        let lock = self.inner.read();
        lock.toa.clone()
    }

    pub fn get_parent_upstream_sync(
        &self,
        cluster_id: i64,
    ) -> Option<Arc<LoadBalancer<Consistent>>> {
        let lock = self.inner.read();
        lock.parent_routes.get(&cluster_id).cloned()
    }

    pub fn get_parent_route_keys_sync(&self) -> Vec<i64> {
        let lock = self.inner.read();
        lock.parent_routes.keys().copied().collect()
    }

    pub fn get_force_ln_request_sync(&self) -> bool {
        let lock = self.inner.read();
        lock.force_ln_request
    }

    pub fn get_ln_method_sync(&self) -> String {
        let lock = self.inner.read();
        lock.ln_request_scheduling_method.clone()
    }

    pub fn get_node_level_sync(&self) -> i32 {
        let lock = self.inner.read();
        lock.level
    }

    pub fn get_upstream_peer_context_sync(&self) -> (i32, bool, bool, bool, i64) {
        let lock = self.inner.read();
        (
            lock.level,
            lock.force_ln_request,
            lock.tiered_origin_bypass,
            lock.ln_request_scheduling_method == "urlMapping",
            lock.node_cluster_id,
        )
    }

    pub fn get_origin_build_context_sync(
        &self,
    ) -> (
        i32,
        Arc<HashMap<i64, Vec<ParentNodeConfig>>>,
        bool,
        bool,
        Option<crate::config_models::GlobalHTTPAllConfig>,
    ) {
        let lock = self.inner.read();
        (
            lock.level,
            Arc::clone(&lock.parent_nodes),
            lock.tiered_origin_bypass,
            lock.allow_lan_ip,
            Some((*lock.global_http_config).clone()),
        )
    }

    pub fn origin_build_context_snapshot(&self) -> OriginBuildContext {
        loop {
            let before = self.runtime_reload_generation();
            let context = {
                let lock = self.inner.read();
                OriginBuildContext {
                    generation: before,
                    node_level: lock.level,
                    parent_nodes: Arc::clone(&lock.parent_nodes),
                    tiered_origin_bypass: lock.tiered_origin_bypass,
                    allow_lan: lock.allow_lan_ip,
                    global_http: Some((*lock.global_http_config).clone()),
                }
            };
            if self.runtime_reload_generation() == before {
                return context;
            }
        }
    }

    pub fn get_upstream_peer_context_with_firewall_policies_sync(
        &self,
    ) -> (i32, bool, bool, bool, i64, Arc<Vec<HTTPFirewallPolicy>>) {
        let lock = self.inner.read();
        (
            lock.level,
            lock.force_ln_request,
            lock.tiered_origin_bypass,
            lock.ln_request_scheduling_method == "urlMapping",
            lock.node_cluster_id,
            Arc::clone(&lock.firewall_policies),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn set_enabled_features(
        &self,
        has_dns: bool,
        has_cache: bool,
        has_thresholds: bool,
        has_ssh: bool,
        has_system: bool,
        has_ddos: bool,
        has_schedule: bool,
        has_access_log: bool,
    ) {
        let _update = self.update_gate.lock();
        let mut lock = self.inner.write();
        lock.dns_info_enabled = has_dns;
        lock.cache_info_enabled = has_cache;
        lock.thresholds_enabled = has_thresholds;
        lock.ssh_enabled = has_ssh;
        lock.system_settings_enabled = has_system;
        lock.ddos_protection_enabled = has_ddos;
        lock.schedule_info_enabled = has_schedule;
        lock.access_log_settings_enabled = has_access_log;
    }

    pub fn get_node_is_on_sync(&self) -> bool {
        let lock = self.inner.read();
        lock.is_on
    }

    pub fn get_node_cluster_id_sync(&self) -> i64 {
        let lock = self.inner.read();
        lock.node_cluster_id
    }

    pub fn get_node_enable_ip_lists_sync(&self) -> bool {
        let lock = self.inner.read();
        lock.enable_ip_lists
    }

    pub fn get_global_http_config_sync(&self) -> Arc<crate::config_models::GlobalHTTPAllConfig> {
        let lock = self.inner.read();
        Arc::clone(&lock.global_http_config)
    }

    pub fn get_global_access_log_sync(
        &self,
    ) -> Option<Arc<crate::config_models::GlobalHTTPAccessLogConfig>> {
        let lock = self.inner.read();
        lock.global_access_log.clone()
    }

    pub fn get_global_stat_upload_sync(&self) -> Arc<crate::config_models::GlobalStatUploadConfig> {
        let lock = self.inner.read();
        Arc::clone(&lock.global_stat_upload)
    }

    pub fn set_global_stat_upload(
        &self,
        config: Option<crate::config_models::GlobalStatUploadConfig>,
    ) {
        let _update = self.update_gate.lock();
        let mut lock = self.inner.write();
        lock.global_stat_upload = Arc::new(config.unwrap_or_default());
    }

    pub fn get_grpc_policy_sync(&self) -> Option<Arc<crate::config_models::GRPCConfig>> {
        let lock = self.inner.read();
        lock.grpc_policy.clone()
    }

    pub fn get_plan_sync(&self, plan_id: i64) -> Option<crate::pb::Plan> {
        let lock = self.inner.read();
        lock.plans.get(&plan_id).cloned()
    }

    pub fn get_user_plan_sync(&self, user_plan_id: i64) -> Option<crate::pb::UserPlan> {
        let lock = self.inner.read();
        lock.user_plans.get(&user_plan_id).cloned()
    }

    pub fn get_user_plan_id_sync(&self, user_plan_id: i64) -> Option<i64> {
        let lock = self.inner.read();
        lock.user_plans
            .get(&user_plan_id)
            .map(|user_plan| user_plan.plan_id)
    }

    pub fn get_plan_derived_sync(&self, user_plan_id: i64) -> Option<PlanDerivedConfig> {
        let lock = self.inner.read();
        lock.plan_derived.get(&user_plan_id).cloned()
    }

    pub fn update_parent_pressure(&self, addr: &str, pressure: f32) {
        self.parent_pressure
            .insert(addr.to_string(), (pressure, std::time::Instant::now()));
    }

    pub fn get_parent_pressure(&self, addr: &str) -> f32 {
        if let Some(entry) = self.parent_pressure.get(addr) {
            let (p, ts) = *entry.value();
            // Data expires after 60 seconds of no update
            if ts.elapsed().as_secs() < 60 {
                return p;
            }
        }
        0.0
    }

    // Async versions (keep name compatibility for most parts)
    pub async fn get_upstream(
        &self,
        host: &str,
    ) -> Option<Arc<crate::lb_factory::AnyLoadBalancer>> {
        self.get_upstream_sync(host)
    }

    pub async fn get_server(&self, host: &str) -> Option<Arc<ServerConfig>> {
        self.get_server_sync(host)
    }

    pub async fn get_server_by_id(&self, server_id: i64) -> Option<Arc<ServerConfig>> {
        let lock = self.inner.read();
        lock.all_servers
            .iter()
            .find(|server| server.id == Some(server_id))
            .cloned()
    }

    pub fn get_server_by_id_sync(&self, server_id: i64) -> Option<Arc<ServerConfig>> {
        let lock = self.inner.read();
        lock.all_servers
            .iter()
            .find(|server| server.id == Some(server_id))
            .cloned()
    }

    pub async fn get_all_servers(&self) -> Vec<Arc<ServerConfig>> {
        let lock = self.inner.read();
        lock.all_servers.clone()
    }

    pub fn get_all_servers_sync(&self) -> Vec<Arc<ServerConfig>> {
        let lock = self.inner.read();
        lock.all_servers.clone()
    }

    pub fn get_all_hosts_sync(&self) -> Vec<String> {
        let lock = self.inner.read();
        lock.servers.keys().cloned().collect()
    }

    pub async fn is_deleted_content(&self, url: &str) -> bool {
        let lock = self.inner.read();
        lock.deleted_contents
            .iter()
            .any(|banned| url == banned || url.starts_with(banned))
    }

    pub fn is_deleted_content_exact_sync(&self, url: &str) -> bool {
        self.inner.read().deleted_content_urls.contains(url)
    }

    pub async fn is_updating_server(&self, server_id: i64) -> bool {
        let lock = self.inner.read();
        lock.updating_server_ids.contains(&server_id)
    }

    pub async fn set_updating_servers(&self, ids: Vec<i64>) {
        let _update = self.update_gate.lock();
        let mut lock = self.inner.write();
        lock.updating_server_ids = ids.into_iter().collect();
    }

    pub async fn get_global_pages(&self) -> Vec<HTTPPageConfig> {
        let lock = self.inner.read();
        lock.global_pages.clone()
    }

    pub async fn get_server_id_by_host(&self, host: &str) -> Option<i64> {
        let lock = self.inner.read();
        lock.servers.get(host).and_then(|s| s.id)
    }

    pub async fn get_lb_by_id(
        &self,
        server_id: i64,
    ) -> Option<Arc<crate::lb_factory::AnyLoadBalancer>> {
        let lock = self.inner.read();
        lock.id_to_lb.get(&server_id).cloned()
    }

    pub async fn find_upstream_by_server_id(
        &self,
        server_id: i64,
    ) -> Option<Arc<crate::lb_factory::AnyLoadBalancer>> {
        self.get_lb_by_id(server_id).await
    }

    pub async fn get_metric_items(&self) -> Vec<MetricItemConfig> {
        let lock = self.inner.read();
        lock.metric_items.clone()
    }

    pub async fn get_plan_ids(&self) -> Vec<i64> {
        let lock = self.inner.read();
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

    pub async fn get_tiered_origin_info(&self) -> (i32, Arc<HashMap<i64, Vec<ParentNodeConfig>>>) {
        let lock = self.inner.read();
        (lock.level, Arc::clone(&lock.parent_nodes))
    }

    pub async fn get_origin_runtime_context(
        &self,
    ) -> (i32, Arc<HashMap<i64, Vec<ParentNodeConfig>>>, bool, bool) {
        let lock = self.inner.read();
        (
            lock.level,
            Arc::clone(&lock.parent_nodes),
            lock.tiered_origin_bypass,
            lock.allow_lan_ip,
        )
    }

    pub async fn is_tiered_origin_bypass(&self) -> bool {
        let lock = self.inner.read();
        lock.tiered_origin_bypass
    }

    pub async fn allow_lan_ip(&self) -> bool {
        let lock = self.inner.read();
        lock.allow_lan_ip
    }

    pub async fn set_tiered_origin_bypass(&self, bypass: bool) {
        let _update = self.update_gate.lock();
        let mut lock = self.inner.write();
        if lock.tiered_origin_bypass == bypass {
            return;
        }
        lock.tiered_origin_bypass = bypass;
        drop(lock);
        self.notify_runtime_reload();
    }

    pub async fn get_node_id(&self) -> i64 {
        let lock = self.inner.read();
        lock.id
    }

    pub async fn get_node_region_id(&self) -> i64 {
        let lock = self.inner.read();
        lock.node_region_id
    }

    pub async fn update_id(&self, id: i64) {
        let _update = self.update_gate.lock();
        let mut lock = self.inner.write();
        lock.id = id;
    }

    pub async fn get_config_version(&self) -> i64 {
        let lock = self.inner.read();
        lock.version
    }

    pub async fn update_config_version(&self, version: i64) {
        let _update = self.update_gate.lock();
        let mut lock = self.inner.write();
        lock.version = version;
    }

    pub async fn get_updating_server_list_id(&self) -> i64 {
        let lock = self.inner.read();
        lock.updating_server_list_id
    }

    pub async fn collect_ssl_config(&self) -> Vec<SSLCertConfig> {
        let lock = self.inner.read();
        let mut certs = lock.ssl_certs.clone();

        if let Some(policy) = lock.ssl_policy.as_ref().filter(|policy| policy.is_on) {
            certs.extend(policy.certs.iter().cloned());
        }

        for server in &lock.all_servers {
            if let Some(https) = &server.https
                && https.is_on
                && let Some(policy) = &https.ssl_policy
                && policy.is_on
            {
                certs.extend(policy.certs.iter().cloned());
            }
        }

        dedup_ssl_certs(certs)
    }

    pub async fn get_cache_policy(&self) -> Arc<Vec<Arc<HTTPCachePolicy>>> {
        self.get_cache_policy_sync()
    }

    pub async fn get_deleted_contents(&self) -> Vec<String> {
        let lock = self.inner.read();
        lock.deleted_contents.clone()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_config(
        &self,
        id: i64,
        version: i64,
        node_region_id: i64,
        node_cluster_id: i64,
        all_servers: Vec<Arc<ServerConfig>>,
        servers: HashMap<String, Arc<ServerConfig>>,
        routes: HashMap<String, Arc<crate::lb_factory::AnyLoadBalancer>>,
        id_to_lb: HashMap<i64, Arc<crate::lb_factory::AnyLoadBalancer>>,
        deleted_contents: Vec<String>,
        global_pages: Vec<HTTPPageConfig>,
        metric_items: Vec<MetricItemConfig>,
        ssl_certs: Vec<SSLCertConfig>,
        ssl_policy: Option<SSLPolicyConfig>,
        updating_server_list_id: i64,
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
        match_domain_strictly: bool,
        node_ip_show_page: bool,
        node_ip_page_html: String,
        domain_mismatch_action: Option<crate::config_models::DomainMismatchActionConfig>,
        global_http_config: Option<crate::config_models::GlobalHTTPAllConfig>,
        cache_policy: Vec<Arc<HTTPCachePolicy>>,
        firewall_policies: Vec<HTTPFirewallPolicy>,
        waf_actions: Vec<crate::config_models::WAFActionConfig>,
        uam_policies: HashMap<i64, UAMPolicy>,
        http_cc_policies: HashMap<i64, HTTPCCPolicy>,
        http3_policies: HashMap<i64, HTTP3Policy>,
        http_pages_policies: HashMap<i64, HTTPPagesPolicy>,
        webp_image_policies: HashMap<i64, WebPImagePolicy>,
        toa: Option<TOAConfig>,
        global_access_log: Option<crate::config_models::GlobalHTTPAccessLogConfig>,
    ) {
        let _update = self.update_gate.lock();
        for server in &all_servers {
            server.compile_url_patterns();
        }
        for policy in &firewall_policies {
            policy.compile_url_patterns();
        }
        for policy in uam_policies.values() {
            policy.compile_url_patterns();
        }
        crate::routing::location::clear_compiled_locations();
        // Pre-compile plans outside the write lock to avoid blocking request processing.
        let compiled_plans = crate::compiled::CompiledPlanSet::compile(
            &firewall_policies,
            &cache_policy,
            &all_servers,
        );
        let mut lock = self.inner.write();
        lock.id = id;
        lock.version = version;
        lock.node_region_id = node_region_id;
        lock.node_cluster_id = node_cluster_id;
        lock.all_servers = all_servers;
        lock.servers = servers;
        lock.routes = routes;
        lock.id_to_lb = id_to_lb;
        lock.deleted_content_urls = deleted_contents.iter().cloned().collect();
        lock.deleted_contents = deleted_contents;
        lock.global_pages = global_pages;
        lock.metric_items = metric_items;
        lock.ssl_certs = ssl_certs;
        lock.ssl_policy = ssl_policy;
        lock.updating_server_list_id = updating_server_list_id;
        lock.level = level;
        lock.is_on = is_on;
        lock.enable_ip_lists = enable_ip_lists;
        lock.parent_nodes = Arc::new(parent_nodes);
        lock.tiered_origin_bypass = tiered_origin_bypass;
        lock.force_ln_request = force_ln_request;
        lock.parent_routes = parent_routes;
        lock.grpc_policy = grpc_policy.map(Arc::new);
        let mut global_http = global_http_config.unwrap_or_default();
        global_http.force_ln_request = force_ln_request;
        global_http.ln_request_scheduling_method = ln_method;
        global_http.supports_low_version_http = supports_low_version_http;
        global_http.match_cert_from_all_servers = match_cert_from_all_servers;
        global_http.server_name = server_name;
        global_http.enable_server_addr_variable = enable_server_addr_variable;
        global_http.request_origins_with_encodings = request_origins_with_encodings;
        global_http.xff_max_addresses = xff_max_addresses;
        global_http.allow_lan_ip = allow_lan_ip;
        global_http.match_domain_strictly = match_domain_strictly;
        global_http.node_ip_show_page = node_ip_show_page;
        global_http.node_ip_page_html = node_ip_page_html;
        global_http.domain_mismatch_action = domain_mismatch_action;
        let global_http = Arc::new(global_http);
        lock.ln_request_scheduling_method = global_http.ln_request_scheduling_method.clone();
        lock.supports_low_version_http = global_http.supports_low_version_http;
        lock.match_cert_from_all_servers = global_http.match_cert_from_all_servers;
        lock.server_name = global_http.server_name.clone();
        lock.enable_server_addr_variable = global_http.enable_server_addr_variable;
        lock.request_origins_with_encodings = global_http.request_origins_with_encodings;
        lock.xff_max_addresses = global_http.xff_max_addresses;
        lock.allow_lan_ip = global_http.allow_lan_ip;
        lock.global_http_config = global_http;
        lock.cache_policies = Arc::new(cache_policy);
        lock.firewall_policies = Arc::new(firewall_policies);
        lock.compiled_plans = Arc::new(compiled_plans);
        lock.global_waf_block_options = waf_actions
            .iter()
            .find(|action| action.code == "block")
            .and_then(|action| {
                serde_json::from_value::<WAFBlockOptions>(action.options.clone()).ok()
            })
            .map(Arc::new);
        lock.waf_actions = Arc::new(waf_actions);
        lock.uam_policies = uam_policies;
        lock.http_cc_policies = http_cc_policies;
        lock.http3_policies = http3_policies;
        lock.http_pages_policies = http_pages_policies;
        lock.webp_image_policies = webp_image_policies;
        lock.toa = toa;
        lock.global_access_log = global_access_log.map(Arc::new);
        crate::logging::set_global_access_log_on(
            lock.global_access_log
                .as_ref()
                .map(|cfg| cfg.is_on)
                .unwrap_or(false),
        );
        Self::refresh_passthrough_indexes(&mut lock);
        Self::refresh_cluster_policy_indexes(&mut lock);
        drop(lock);
        self.notify_runtime_reload();
    }

    pub async fn replace_server(
        &self,
        server_id: i64,
        all_servers: Vec<Arc<ServerConfig>>,
        servers: HashMap<String, Arc<ServerConfig>>,
        routes: HashMap<String, Arc<crate::lb_factory::AnyLoadBalancer>>,
    ) {
        let _update = self.update_gate.lock();
        for server in &all_servers {
            server.compile_url_patterns();
        }
        crate::routing::location::clear_compiled_locations();
        let mut candidate = self.inner.read().clone();
        candidate
            .all_servers
            .retain(|server| server.numeric_id() != server_id);
        let stale_hosts = candidate
            .servers
            .iter()
            .filter_map(|(host, server)| (server.numeric_id() == server_id).then_some(host.clone()))
            .collect::<Vec<_>>();

        for host in &stale_hosts {
            candidate.servers.remove(host);
            candidate.routes.remove(host);
        }
        if server_id > 0 {
            candidate.id_to_lb.remove(&server_id);
        }

        candidate.all_servers.extend(all_servers);
        for (host, config) in servers {
            candidate.servers.insert(host, config);
        }
        for (host, lb) in routes {
            if server_id > 0 {
                candidate.id_to_lb.insert(server_id, lb.clone());
            }
            candidate.routes.insert(host, lb);
        }
        candidate.compiled_plans = Arc::new(crate::compiled::CompiledPlanSet::compile(
            candidate.firewall_policies.as_ref().as_slice(),
            candidate.cache_policies.as_ref().as_slice(),
            &candidate.all_servers,
        ));
        Self::refresh_passthrough_indexes(&mut candidate);
        Self::refresh_cluster_policy_indexes(&mut candidate);
        *self.inner.write() = candidate;
        self.notify_runtime_reload();
        drop(_update);
    }

    pub async fn replace_user_servers(
        &self,
        user_id: i64,
        all_servers: Vec<Arc<ServerConfig>>,
        servers: HashMap<String, Arc<ServerConfig>>,
        routes: HashMap<String, Arc<crate::lb_factory::AnyLoadBalancer>>,
    ) {
        let _update = self.update_gate.lock();
        for server in &all_servers {
            server.compile_url_patterns();
        }
        crate::routing::location::clear_compiled_locations();
        let mut candidate = self.inner.read().clone();
        let stale_server_ids = candidate
            .all_servers
            .iter()
            .filter_map(|server| (server.user_id == user_id).then_some(server.numeric_id()))
            .collect::<std::collections::HashSet<_>>();
        candidate
            .all_servers
            .retain(|server| server.user_id != user_id);
        let stale_hosts = candidate
            .servers
            .iter()
            .filter_map(|(host, server)| (server.user_id == user_id).then_some(host.clone()))
            .collect::<Vec<_>>();

        for host in &stale_hosts {
            candidate.servers.remove(host);
            candidate.routes.remove(host);
        }
        for server_id in stale_server_ids {
            if server_id > 0 {
                candidate.id_to_lb.remove(&server_id);
            }
        }

        candidate.all_servers.extend(all_servers);
        for (host, config) in servers {
            if let Some(sid) = config.id
                && let Some(lb) = routes.get(&host)
            {
                candidate.id_to_lb.insert(sid, lb.clone());
            }
            candidate.servers.insert(host, config);
        }
        for (host, lb) in routes {
            candidate.routes.insert(host, lb);
        }
        candidate.compiled_plans = Arc::new(crate::compiled::CompiledPlanSet::compile(
            candidate.firewall_policies.as_ref().as_slice(),
            candidate.cache_policies.as_ref().as_slice(),
            &candidate.all_servers,
        ));
        Self::refresh_passthrough_indexes(&mut candidate);
        Self::refresh_cluster_policy_indexes(&mut candidate);
        *self.inner.write() = candidate;
        self.notify_runtime_reload();
        drop(_update);
    }

    pub async fn remove_user_servers(&self, user_id: i64) {
        let _update = self.update_gate.lock();
        crate::routing::location::clear_compiled_locations();
        let mut candidate = self.inner.read().clone();
        let stale_server_ids = candidate
            .all_servers
            .iter()
            .filter_map(|server| (server.user_id == user_id).then_some(server.numeric_id()))
            .collect::<std::collections::HashSet<_>>();
        candidate
            .all_servers
            .retain(|server| server.user_id != user_id);
        let stale_hosts = candidate
            .servers
            .iter()
            .filter_map(|(host, server)| (server.user_id == user_id).then_some(host.clone()))
            .collect::<Vec<_>>();

        for host in stale_hosts {
            candidate.servers.remove(&host);
            candidate.routes.remove(&host);
        }
        for server_id in stale_server_ids {
            if server_id > 0 {
                candidate.id_to_lb.remove(&server_id);
            }
        }
        candidate.compiled_plans = Arc::new(crate::compiled::CompiledPlanSet::compile(
            candidate.firewall_policies.as_ref().as_slice(),
            candidate.cache_policies.as_ref().as_slice(),
            &candidate.all_servers,
        ));
        Self::refresh_passthrough_indexes(&mut candidate);
        Self::refresh_cluster_policy_indexes(&mut candidate);
        *self.inner.write() = candidate;
        self.notify_runtime_reload();
        drop(_update);
    }

    pub async fn remove_server(&self, server_id: i64) {
        let _update = self.update_gate.lock();
        crate::routing::location::clear_compiled_locations();
        let mut candidate = self.inner.read().clone();
        candidate
            .all_servers
            .retain(|server| server.numeric_id() != server_id);
        let stale_hosts = candidate
            .servers
            .iter()
            .filter_map(|(host, server)| (server.numeric_id() == server_id).then_some(host.clone()))
            .collect::<Vec<_>>();

        for host in stale_hosts {
            candidate.servers.remove(&host);
            candidate.routes.remove(&host);
        }
        if server_id > 0 {
            candidate.id_to_lb.remove(&server_id);
        }
        candidate.compiled_plans = Arc::new(crate::compiled::CompiledPlanSet::compile(
            candidate.firewall_policies.as_ref().as_slice(),
            candidate.cache_policies.as_ref().as_slice(),
            &candidate.all_servers,
        ));
        Self::refresh_passthrough_indexes(&mut candidate);
        Self::refresh_cluster_policy_indexes(&mut candidate);
        *self.inner.write() = candidate;
        self.notify_runtime_reload();
        drop(_update);
    }

    pub async fn cache_server_route(
        &self,
        host: String,
        server: Arc<ServerConfig>,
        lb: Arc<crate::lb_factory::AnyLoadBalancer>,
    ) {
        let _update = self.update_gate.lock();
        server.compile_url_patterns();
        crate::routing::location::clear_compiled_locations();
        let mut candidate = self.inner.read().clone();
        let server_id = server.numeric_id();
        if server_id > 0 {
            candidate.id_to_lb.insert(server_id, lb.clone());
            candidate
                .all_servers
                .retain(|existing| existing.numeric_id() != server_id);
        }
        candidate.all_servers.push(server.clone());
        candidate.servers.insert(host.clone(), server);
        candidate.routes.insert(host, lb);
        candidate.compiled_plans = Arc::new(crate::compiled::CompiledPlanSet::compile(
            candidate.firewall_policies.as_ref().as_slice(),
            candidate.cache_policies.as_ref().as_slice(),
            &candidate.all_servers,
        ));
        Self::refresh_passthrough_indexes(&mut candidate);
        Self::refresh_cluster_policy_indexes(&mut candidate);
        *self.inner.write() = candidate;
        self.notify_runtime_reload();
        drop(_update);
    }

    pub async fn apply_server_runtime_mutations_batch(
        &self,
        expected_generation: u64,
        mutations: Vec<ServerRuntimeMutation>,
    ) -> bool {
        if mutations.is_empty() {
            return true;
        }

        let _update = self.update_gate.lock();
        if self.runtime_reload_generation() != expected_generation {
            return false;
        }

        crate::routing::location::clear_compiled_locations();

        let mut candidate = self.inner.read().clone();
        let mut changed_server_ids = HashSet::new();

        for mutation in mutations {
            match mutation {
                ServerRuntimeMutation::ReplaceServer {
                    server_id,
                    all_servers,
                    servers,
                    routes,
                } => {
                    Self::remove_server_from_candidate(
                        &mut candidate,
                        server_id,
                        &mut changed_server_ids,
                    );
                    for server in &all_servers {
                        changed_server_ids.insert(server.numeric_id());
                    }
                    candidate.all_servers.extend(all_servers);
                    for (host, config) in servers {
                        candidate.servers.insert(host, config);
                    }
                    for (host, lb) in routes {
                        if server_id > 0 {
                            candidate.id_to_lb.insert(server_id, lb.clone());
                        }
                        candidate.routes.insert(host, lb);
                    }
                }
                ServerRuntimeMutation::ReplaceUserServers {
                    user_id,
                    all_servers,
                    servers,
                    routes,
                } => {
                    Self::remove_user_servers_from_candidate(
                        &mut candidate,
                        user_id,
                        &mut changed_server_ids,
                    );
                    for server in &all_servers {
                        changed_server_ids.insert(server.numeric_id());
                    }
                    candidate.all_servers.extend(all_servers);
                    for (host, config) in servers {
                        if let Some(server_id) = config.id
                            && let Some(lb) = routes.get(&host)
                        {
                            candidate.id_to_lb.insert(server_id, lb.clone());
                        }
                        candidate.servers.insert(host, config);
                    }
                    for (host, lb) in routes {
                        candidate.routes.insert(host, lb);
                    }
                }
                ServerRuntimeMutation::RemoveServer { server_id } => {
                    Self::remove_server_from_candidate(
                        &mut candidate,
                        server_id,
                        &mut changed_server_ids,
                    );
                }
                ServerRuntimeMutation::RemoveUserServers { user_id } => {
                    Self::remove_user_servers_from_candidate(
                        &mut candidate,
                        user_id,
                        &mut changed_server_ids,
                    );
                }
            }
        }

        let changed_servers = candidate
            .all_servers
            .iter()
            .filter(|server| changed_server_ids.contains(&server.numeric_id()))
            .cloned()
            .collect::<Vec<_>>();
        candidate.compiled_plans = Arc::new(crate::compiled::CompiledPlanSet::with_server_updates(
            candidate.compiled_plans.as_ref(),
            &changed_server_ids,
            &changed_servers,
        ));
        Self::refresh_passthrough_indexes(&mut candidate);
        Self::refresh_cluster_policy_indexes(&mut candidate);
        *self.inner.write() = candidate;
        self.notify_runtime_reload();
        drop(_update);
        true
    }

    fn remove_server_from_candidate(
        candidate: &mut NodeConfig,
        server_id: i64,
        changed_server_ids: &mut HashSet<i64>,
    ) {
        changed_server_ids.insert(server_id);
        candidate
            .all_servers
            .retain(|server| server.numeric_id() != server_id);
        let stale_hosts = candidate
            .servers
            .iter()
            .filter_map(|(host, server)| (server.numeric_id() == server_id).then_some(host.clone()))
            .collect::<Vec<_>>();
        for host in stale_hosts {
            candidate.servers.remove(&host);
            candidate.routes.remove(&host);
        }
        if server_id > 0 {
            candidate.id_to_lb.remove(&server_id);
        }
    }

    fn remove_user_servers_from_candidate(
        candidate: &mut NodeConfig,
        user_id: i64,
        changed_server_ids: &mut HashSet<i64>,
    ) {
        let stale_server_ids = candidate
            .all_servers
            .iter()
            .filter_map(|server| (server.user_id == user_id).then_some(server.numeric_id()))
            .collect::<HashSet<_>>();
        changed_server_ids.extend(stale_server_ids.iter().copied());
        candidate
            .all_servers
            .retain(|server| server.user_id != user_id);
        let stale_hosts = candidate
            .servers
            .iter()
            .filter_map(|(host, server)| (server.user_id == user_id).then_some(host.clone()))
            .collect::<Vec<_>>();
        for host in stale_hosts {
            candidate.servers.remove(&host);
            candidate.routes.remove(&host);
        }
        for server_id in stale_server_ids {
            if server_id > 0 {
                candidate.id_to_lb.remove(&server_id);
            }
        }
    }

    fn refresh_plan_derived(lock: &mut NodeConfig) {
        lock.plan_derived = lock
            .user_plans
            .iter()
            .filter_map(|(&user_plan_id, user_plan)| {
                let plan = lock.plans.get(&user_plan.plan_id)?;
                Some((user_plan_id, compile_plan_derived(plan)))
            })
            .collect();
    }

    fn refresh_cluster_policy_indexes(lock: &mut NodeConfig) {
        lock.firewall_policies_by_cluster = Self::build_firewall_policies_by_cluster(lock);
    }

    fn build_firewall_policies_by_cluster(
        lock: &NodeConfig,
    ) -> HashMap<i64, Arc<Vec<HTTPFirewallPolicy>>> {
        let mut policy_by_id = HashMap::<i64, HTTPFirewallPolicy>::new();
        for policy in lock.firewall_policies.iter() {
            if policy.id > 0 {
                policy_by_id.insert(policy.id, policy.clone());
            }
        }
        for server in &lock.all_servers {
            if let Some(policy) = server.http_firewall_policy.as_ref().filter(|p| p.id > 0) {
                policy_by_id
                    .entry(policy.id)
                    .or_insert_with(|| policy.clone());
            }
            if let Some(policy) = server
                .web
                .as_ref()
                .and_then(|web| web.firewall_policy.as_ref())
                .filter(|p| p.id > 0)
            {
                policy_by_id
                    .entry(policy.id)
                    .or_insert_with(|| policy.clone());
            }
        }

        let mut by_cluster = HashMap::<i64, Vec<HTTPFirewallPolicy>>::new();
        let mut seen_by_cluster = HashMap::<i64, HashSet<i64>>::new();
        let mut synthetic_id = -1_i64;

        for server in &lock.all_servers {
            let cluster_id = server.cluster_id;
            if cluster_id <= 0 {
                continue;
            }

            Self::add_cluster_policy_by_id(
                &mut by_cluster,
                &mut seen_by_cluster,
                cluster_id,
                server.http_firewall_policy_id,
                &policy_by_id,
            );

            if let Some(policy) = &server.http_firewall_policy {
                let policy = policy_by_id
                    .get(&policy.id)
                    .cloned()
                    .unwrap_or_else(|| policy.clone());
                Self::add_cluster_policy(
                    &mut by_cluster,
                    &mut seen_by_cluster,
                    cluster_id,
                    policy,
                    &mut synthetic_id,
                );
            }

            if let Some(web) = &server.web {
                let firewall_ref_id = web
                    .firewall_ref
                    .as_ref()
                    .map(|firewall_ref| firewall_ref.id)
                    .unwrap_or(0);
                Self::add_cluster_policy_by_id(
                    &mut by_cluster,
                    &mut seen_by_cluster,
                    cluster_id,
                    firewall_ref_id,
                    &policy_by_id,
                );

                if let Some(policy) = &web.firewall_policy {
                    let policy = policy_by_id
                        .get(&policy.id)
                        .cloned()
                        .unwrap_or_else(|| policy.clone());
                    Self::add_cluster_policy(
                        &mut by_cluster,
                        &mut seen_by_cluster,
                        cluster_id,
                        policy,
                        &mut synthetic_id,
                    );
                }
            }
        }

        by_cluster
            .into_iter()
            .map(|(cluster_id, policies)| (cluster_id, Arc::new(policies)))
            .collect()
    }

    fn add_cluster_policy_by_id(
        by_cluster: &mut HashMap<i64, Vec<HTTPFirewallPolicy>>,
        seen_by_cluster: &mut HashMap<i64, HashSet<i64>>,
        cluster_id: i64,
        policy_id: i64,
        policy_by_id: &HashMap<i64, HTTPFirewallPolicy>,
    ) {
        if policy_id <= 0 {
            return;
        }
        if let Some(policy) = policy_by_id.get(&policy_id) {
            let mut ignored_synthetic_id = -1;
            Self::add_cluster_policy(
                by_cluster,
                seen_by_cluster,
                cluster_id,
                policy.clone(),
                &mut ignored_synthetic_id,
            );
        }
    }

    fn add_cluster_policy(
        by_cluster: &mut HashMap<i64, Vec<HTTPFirewallPolicy>>,
        seen_by_cluster: &mut HashMap<i64, HashSet<i64>>,
        cluster_id: i64,
        policy: HTTPFirewallPolicy,
        synthetic_id: &mut i64,
    ) {
        if cluster_id <= 0 {
            return;
        }
        let policy_key = if policy.id > 0 {
            policy.id
        } else {
            let id = *synthetic_id;
            *synthetic_id -= 1;
            id
        };
        if seen_by_cluster
            .entry(cluster_id)
            .or_default()
            .insert(policy_key)
        {
            by_cluster.entry(cluster_id).or_default().push(policy);
        }
    }

    fn refresh_passthrough_indexes(lock: &mut NodeConfig) {
        lock.sni_passthrough_exact.clear();
        lock.sni_passthrough_wildcard.clear();
        lock.quic_passthrough_exact.clear();
        lock.quic_passthrough_wildcard.clear();
        lock.unique_quic_passthrough_by_port.clear();
        lock.udp_server_by_port.clear();

        for server in &lock.all_servers {
            if !server.is_quic_passthrough() {
                for port in Self::server_udp_ports(server, false) {
                    if let Some(existing) = lock.udp_server_by_port.get(&port) {
                        if existing.numeric_id() != server.numeric_id() {
                            warn!(
                                "multiple ordinary UDP servers share port {}; server {} keeps routing precedence over server {}. Use @quic for SNI-aware QUIC/hy2 passthrough on a shared port.",
                                port,
                                existing.numeric_id(),
                                server.numeric_id()
                            );
                        }
                    } else {
                        lock.udp_server_by_port.insert(port, server.clone());
                    }
                }
            }
            if server.is_sni_passthrough() {
                let ports = Self::server_https_ports(server);
                Self::index_passthrough_server(
                    &mut lock.sni_passthrough_exact,
                    &mut lock.sni_passthrough_wildcard,
                    server,
                    ports,
                );
            }
            if server.is_quic_passthrough() {
                let ports = Self::server_quic_passthrough_ports(server);
                Self::index_passthrough_server(
                    &mut lock.quic_passthrough_exact,
                    &mut lock.quic_passthrough_wildcard,
                    server,
                    ports,
                );
            }
        }

        lock.unique_quic_passthrough_by_port = Self::build_unique_quic_passthrough_by_port(lock);
        lock.has_any_sni_passthrough =
            !lock.sni_passthrough_exact.is_empty() || !lock.sni_passthrough_wildcard.is_empty();
        lock.has_any_quic_passthrough =
            !lock.quic_passthrough_exact.is_empty() || !lock.quic_passthrough_wildcard.is_empty();
    }

    fn build_unique_quic_passthrough_by_port(
        lock: &NodeConfig,
    ) -> HashMap<u16, Option<Arc<ServerConfig>>> {
        let mut unique = HashMap::<u16, Option<Arc<ServerConfig>>>::new();
        for ((port, _), server) in lock
            .quic_passthrough_exact
            .iter()
            .chain(lock.quic_passthrough_wildcard.iter())
        {
            unique
                .entry(*port)
                .and_modify(|matched| {
                    if matched
                        .as_ref()
                        .is_some_and(|existing| existing.numeric_id() != server.numeric_id())
                    {
                        *matched = None;
                    }
                })
                .or_insert_with(|| Some(server.clone()));
        }
        unique
    }

    fn server_https_ports(server: &Arc<ServerConfig>) -> Vec<u16> {
        let mut ports = server
            .https
            .as_ref()
            .filter(|https| https.is_on)
            .map(|https| {
                https
                    .listen
                    .iter()
                    .filter_map(|addr| addr.port_range.as_deref())
                    .flat_map(crate::config_models::ports_in_range)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        ports.push(0);
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    fn server_udp_ports(server: &Arc<ServerConfig>, include_fallback: bool) -> Vec<u16> {
        let mut ports = server
            .udp
            .as_ref()
            .filter(|udp| udp.is_on)
            .map(|udp| {
                udp.listen
                    .iter()
                    .filter_map(|addr| addr.port_range.as_deref())
                    .flat_map(crate::config_models::ports_in_range)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if include_fallback {
            ports.push(0);
        }
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    fn server_quic_passthrough_ports(server: &Arc<ServerConfig>) -> Vec<u16> {
        let mut ports = Self::server_udp_ports(server, false);
        ports.extend(
            Self::server_https_ports(server)
                .into_iter()
                .filter(|port| *port != 0),
        );
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    fn index_passthrough_server(
        exact: &mut HashMap<(u16, String), Arc<ServerConfig>>,
        wildcard: &mut HashMap<(u16, String), Arc<ServerConfig>>,
        server: &Arc<ServerConfig>,
        ports: Vec<u16>,
    ) {
        for name in server.get_plain_server_names() {
            let name = Self::normalize_host(&name);
            if name.is_empty() {
                continue;
            }
            let (is_wildcard, key_name) = if let Some(suffix) = name.strip_prefix("*.") {
                (true, suffix.to_string())
            } else {
                (false, name)
            };
            for port in &ports {
                let key = (*port, key_name.clone());
                if is_wildcard {
                    wildcard.entry(key).or_insert_with(|| server.clone());
                } else {
                    exact.entry(key).or_insert_with(|| server.clone());
                }
            }
        }
    }

    pub async fn set_deleted_contents(&self, deleted_contents: Vec<String>) {
        let _update = self.update_gate.lock();
        let mut lock = self.inner.write();
        lock.deleted_content_urls = deleted_contents.iter().cloned().collect();
        lock.deleted_contents = deleted_contents;
    }

    pub async fn set_plans(&self, plans: HashMap<i64, crate::pb::Plan>) {
        let _update = self.update_gate.lock();
        let mut lock = self.inner.write();
        lock.plans = plans;
        Self::refresh_plan_derived(&mut lock);
    }

    pub async fn set_user_plans(&self, user_plans: HashMap<i64, crate::pb::UserPlan>) {
        let _update = self.update_gate.lock();
        let mut lock = self.inner.write();
        lock.user_plans = user_plans;
        Self::refresh_plan_derived(&mut lock);
    }

    pub async fn set_active_plans_if_generation(
        &self,
        expected_generation: u64,
        user_plans: HashMap<i64, crate::pb::UserPlan>,
        plans: HashMap<i64, crate::pb::Plan>,
    ) -> bool {
        let _update = self.update_gate.lock();
        if self.runtime_reload_generation() != expected_generation {
            return false;
        }
        let mut lock = self.inner.write();
        lock.user_plans = user_plans;
        lock.plans = plans;
        Self::refresh_plan_derived(&mut lock);
        true
    }

    pub async fn update_node_level_info(
        &self,
        level: i32,
        parent_nodes: HashMap<i64, Vec<ParentNodeConfig>>,
    ) {
        let _update = self.update_gate.lock();
        let allow_lan_ip = {
            let lock = self.inner.read();
            lock.allow_lan_ip
        };

        let mut parent_routes = HashMap::new();
        for (cluster_id, nodes) in &parent_nodes {
            let lb = crate::lb_factory::build_parent_lb(*cluster_id, nodes, allow_lan_ip);
            parent_routes.insert(*cluster_id, lb);
        }

        let mut lock = self.inner.write();
        lock.level = level;
        lock.parent_nodes = Arc::new(parent_nodes);
        lock.parent_routes = parent_routes;
        drop(lock);
        self.notify_runtime_reload();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_models::{
        EmptyConnectionFloodConfig, HTTPSConfig, NetworkAddressConfig, ServerNameConfig,
        TLSExhaustionAttackConfig, UDPConfig,
    };
    use serde_json::json;

    fn test_firewall_policy(id: i64) -> HTTPFirewallPolicy {
        HTTPFirewallPolicy {
            id,
            is_on: true,
            name: format!("policy-{id}"),
            inbound: None,
            outbound: None,
            empty_connection_flood: Some(EmptyConnectionFloodConfig {
                is_on: true,
                max_empty_connections: 1,
                period: 60,
                block_seconds: 60,
            }),
            tls_exhaustion_attack: Some(TLSExhaustionAttackConfig {
                is_on: true,
                max_handshake_fails: 1,
                period: 60,
                block_seconds: 60,
            }),
            cc_config: None,
            block_options: None,
            page_options: None,
            captcha_options: None,
            js_cookie_options: None,
            max_request_body_size: 0,
            deny_country_html: String::new(),
            deny_province_html: String::new(),
            use_local_firewall: false,
            syn_flood: None,
            mode: String::new(),
            candidate_rules: None,
            candidate_traffic_pct: 0,
            candidate_version: 0,
        }
    }

    async fn update_store_for_cluster_policy_test(
        store: &ConfigStore,
        node_cluster_id: i64,
        all_servers: Vec<Arc<ServerConfig>>,
        firewall_policies: Vec<HTTPFirewallPolicy>,
        http_cc_policies: HashMap<i64, HTTPCCPolicy>,
    ) {
        store
            .update_config(
                1,
                1,
                0,
                node_cluster_id,
                all_servers,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                0,
                1,
                true,
                true,
                HashMap::new(),
                false,
                false,
                "random".to_string(),
                HashMap::new(),
                None,
                false,
                false,
                String::new(),
                false,
                false,
                0,
                false,
                false,
                false,
                String::new(),
                None,
                None,
                Vec::new(),
                firewall_policies,
                Vec::new(),
                HashMap::new(),
                http_cc_policies,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                None,
                None,
            )
            .await;
    }

    #[tokio::test]
    async fn batch_server_mutations_publish_once_and_reject_stale_generation() {
        let store = ConfigStore::new();
        let mutations = [101_i64, 102]
            .into_iter()
            .map(|server_id| ServerRuntimeMutation::ReplaceServer {
                server_id,
                all_servers: vec![Arc::new(ServerConfig {
                    id: Some(server_id),
                    ..Default::default()
                })],
                servers: HashMap::new(),
                routes: HashMap::new(),
            })
            .collect();

        assert!(
            store
                .apply_server_runtime_mutations_batch(0, mutations)
                .await
        );
        assert_eq!(store.runtime_reload_generation(), 1);
        let mut ids = store
            .get_all_servers()
            .await
            .into_iter()
            .map(|server| server.numeric_id())
            .collect::<Vec<_>>();
        ids.sort_unstable();
        assert_eq!(ids, vec![101, 102]);

        assert!(
            !store
                .apply_server_runtime_mutations_batch(
                    0,
                    vec![ServerRuntimeMutation::RemoveServer { server_id: 101 }],
                )
                .await
        );
        assert_eq!(store.runtime_reload_generation(), 1);
        assert_eq!(store.get_all_servers().await.len(), 2);
        assert!(
            !store
                .set_active_plans_if_generation(0, HashMap::new(), HashMap::new())
                .await
        );
    }

    #[tokio::test]
    async fn firewall_policies_are_indexed_by_referenced_server_cluster() {
        let store = ConfigStore::new();
        let server = Arc::new(ServerConfig {
            id: Some(100),
            cluster_id: 12,
            http_firewall_policy_id: 1,
            ..Default::default()
        });

        update_store_for_cluster_policy_test(
            &store,
            12,
            vec![server],
            vec![test_firewall_policy(1), test_firewall_policy(2)],
            HashMap::new(),
        )
        .await;

        let cluster_12 = store.get_firewall_policies_for_cluster_sync(12);
        assert_eq!(
            cluster_12
                .iter()
                .map(|policy| policy.id)
                .collect::<Vec<_>>(),
            vec![1]
        );
        assert!(store.get_firewall_policies_for_cluster_sync(15).is_empty());
        assert!(
            store
                .get_tls_exhaustion_config_for_cluster_sync(12)
                .is_some()
        );
        assert!(
            store
                .get_tls_exhaustion_config_for_cluster_sync(15)
                .is_none()
        );
        assert!(
            store
                .get_empty_connection_flood_config_for_cluster_sync(12)
                .is_some()
        );
    }

    #[tokio::test]
    async fn same_firewall_policy_can_belong_to_multiple_clusters() {
        let store = ConfigStore::new();
        let server_12 = Arc::new(ServerConfig {
            id: Some(120),
            cluster_id: 12,
            http_firewall_policy_id: 1,
            ..Default::default()
        });
        let server_15 = Arc::new(ServerConfig {
            id: Some(150),
            cluster_id: 15,
            http_firewall_policy_id: 1,
            ..Default::default()
        });

        update_store_for_cluster_policy_test(
            &store,
            12,
            vec![server_12, server_15],
            vec![test_firewall_policy(1)],
            HashMap::new(),
        )
        .await;

        assert_eq!(
            store
                .get_firewall_policies_for_cluster_sync(12)
                .iter()
                .map(|policy| policy.id)
                .collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(
            store
                .get_firewall_policies_for_cluster_sync(15)
                .iter()
                .map(|policy| policy.id)
                .collect::<Vec<_>>(),
            vec![1]
        );
    }

    #[tokio::test]
    async fn main_cluster_defense_config_ignores_other_cluster_references() {
        let store = ConfigStore::new();
        let slave_cluster_server = Arc::new(ServerConfig {
            id: Some(150),
            cluster_id: 15,
            http_firewall_policy_id: 1,
            ..Default::default()
        });

        update_store_for_cluster_policy_test(
            &store,
            12,
            vec![slave_cluster_server],
            vec![test_firewall_policy(1)],
            {
                let mut policies = HashMap::new();
                policies.insert(
                    15,
                    HTTPCCPolicy {
                        is_on: true,
                        max_qps: 1,
                        max_qps_per_ip: 1,
                        ..Default::default()
                    },
                );
                policies
            },
        )
        .await;

        assert_eq!(store.get_node_cluster_id_sync(), 12);
        assert!(
            store
                .get_tls_exhaustion_config_for_cluster_sync(store.get_node_cluster_id_sync())
                .is_none()
        );
        assert!(
            store
                .get_empty_connection_flood_config_for_cluster_sync(
                    store.get_node_cluster_id_sync()
                )
                .is_none()
        );
        assert!(
            store
                .get_tls_exhaustion_config_for_cluster_sync(15)
                .is_some()
        );
        assert!(
            store
                .get_http_cc_policy_for_cluster_sync(store.get_node_cluster_id_sync())
                .is_none()
        );
        assert!(store.get_http_cc_policy_for_cluster_sync(15).is_some());
    }

    #[tokio::test]
    async fn update_config_applies_global_http_compat_fields_to_hot_path() {
        let store = ConfigStore::new();
        store
            .update_config(
                10,
                20,
                30,
                40,
                Vec::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                55,
                1,
                true,
                true,
                HashMap::new(),
                false,
                true,
                "urlMapping".to_string(),
                HashMap::new(),
                None,
                true,
                true,
                "edge-node".to_string(),
                true,
                true,
                2,
                true,
                true,
                true,
                "<h1>${host}</h1>".to_string(),
                Some(crate::config_models::DomainMismatchActionConfig {
                    code: "redirect".to_string(),
                    options: json!({"url": "https://example.com"}),
                }),
                Some(crate::config_models::GlobalHTTPAllConfig {
                    conn_timeout: Some(json!(50)),
                    read_timeout: Some(json!({"count": 10, "unit": "s"})),
                    auto_read_timeout: Some(json!(15)),
                    auto_write_timeout: Some(json!(20)),
                    ..Default::default()
                }),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                None,
                Some(crate::config_models::GlobalHTTPAccessLogConfig {
                    is_on: true,
                    enable_request_headers: false,
                    common_request_headers_only: true,
                    enable_response_headers: false,
                    enable_cookies: false,
                    enable_server_not_found: true,
                    firewall_only: false,
                    enable_client_closed: false,
                }),
            )
            .await;

        let snapshot = store.get_hot_path_snapshot_sync();
        assert!(snapshot.is_on);
        assert!(snapshot.global_http.force_ln_request);
        assert_eq!(
            snapshot.global_http.ln_request_scheduling_method,
            "urlMapping"
        );
        assert_eq!(snapshot.global_http.server_name, "edge-node");
        assert!(snapshot.global_http.match_domain_strictly);
        assert!(snapshot.global_http.node_ip_show_page);
        assert_eq!(snapshot.global_http.node_ip_page_html, "<h1>${host}</h1>");
        assert_eq!(
            snapshot
                .global_http
                .domain_mismatch_action
                .as_ref()
                .expect("domain mismatch action should be applied")
                .code,
            "redirect"
        );
        assert_eq!(
            snapshot
                .global_http
                .conn_timeout
                .as_ref()
                .and_then(|v| v.as_u64()),
            Some(50)
        );
        assert_eq!(
            crate::utils::non_zero_duration(
                snapshot
                    .global_http
                    .read_timeout
                    .as_ref()
                    .expect("read timeout")
            ),
            Some(std::time::Duration::from_secs(10))
        );
        assert_eq!(
            snapshot
                .global_http
                .auto_read_timeout
                .as_ref()
                .and_then(|v| v.as_u64()),
            Some(15)
        );
        assert_eq!(
            snapshot
                .global_http
                .auto_write_timeout
                .as_ref()
                .and_then(|v| v.as_u64()),
            Some(20)
        );
        assert!(snapshot.global_access_log.is_some());
        assert_eq!(store.get_updating_server_list_id().await, 55);
    }

    #[tokio::test]
    async fn l7_wildcard_route_matches_root_and_nested_subdomains() {
        let store = ConfigStore::new();
        let server = Arc::new(ServerConfig {
            id: Some(11),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "*.example.com".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        });
        let (lb, _) = crate::rpc::utils::fallback_runtime_lb();

        store
            .cache_server_route("*.example.com".to_string(), server, lb)
            .await;

        for host in ["example.com", "www.example.com", "a.b.example.com"] {
            assert_eq!(
                store
                    .get_server_sync(host)
                    .map(|server| server.numeric_id()),
                Some(11),
                "host should match wildcard route: {host}"
            );
            assert!(
                store.get_upstream_sync(host).is_some(),
                "host should resolve wildcard upstream: {host}"
            );
        }
    }

    #[tokio::test]
    async fn l7_tls_wildcard_route_matches_root_and_nested_subdomains() {
        let store = ConfigStore::new();
        let server = Arc::new(ServerConfig {
            id: Some(12),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "*.example.com".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        });
        let (lb, _) = crate::rpc::utils::fallback_runtime_lb();

        store
            .cache_server_route("*.example.com".to_string(), server, lb)
            .await;

        for host in ["example.com", "www.example.com", "a.b.example.com"] {
            assert_eq!(
                store
                    .get_l7_server_for_tls_name_sync(host)
                    .map(|server| server.numeric_id()),
                Some(12),
                "TLS host should match L7 wildcard route: {host}"
            );
        }
    }

    #[tokio::test]
    async fn l7_https_server_takes_precedence_over_sni_passthrough_wildcard() {
        let store = ConfigStore::new();
        let l7_server = Arc::new(ServerConfig {
            id: Some(1),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "rancher.mymya.cn".to_string(),
                ..Default::default()
            }],
            https: Some(HTTPSConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("https".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("443".to_string()),
                }],
                ssl_policy: None,
                supports_http3: None,
            }),
            ..Default::default()
        });
        let passthrough_server = Arc::new(ServerConfig {
            id: Some(2),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "*.mymya.cn@sni_passthrough".to_string(),
                ..Default::default()
            }],
            https: Some(HTTPSConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("https".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("443".to_string()),
                }],
                ssl_policy: None,
                supports_http3: None,
            }),
            ..Default::default()
        });

        let mut servers = HashMap::new();
        servers.insert("rancher.mymya.cn".to_string(), l7_server.clone());
        servers.insert("*.mymya.cn".to_string(), passthrough_server.clone());
        let all_servers = vec![l7_server.clone(), passthrough_server.clone()];
        store
            .update_config(
                1,
                1,
                0,
                0,
                all_servers,
                servers,
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                0,
                1,
                true,
                true,
                HashMap::new(),
                false,
                false,
                "random".to_string(),
                HashMap::new(),
                None,
                false,
                false,
                String::new(),
                false,
                false,
                0,
                false,
                false,
                false,
                String::new(),
                None,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                None,
                None,
            )
            .await;

        assert_eq!(
            store
                .get_l7_server_for_tls_name_sync("rancher.mymya.cn")
                .map(|server| server.numeric_id()),
            Some(1)
        );
        assert_eq!(
            store
                .find_sni_passthrough_server_sync("rancher.mymya.cn", 443)
                .map(|server| server.numeric_id()),
            Some(2)
        );
        let route = store
            .inspect_tls_route_sync("rancher.mymya.cn", 443)
            .expect("TLS route should inspect configured host");
        assert!(route.has_l7_server);
        assert!(route.sni_passthrough_server.is_none());
    }

    #[tokio::test]
    async fn exact_sni_passthrough_takes_precedence_over_l7_wildcard() {
        let store = ConfigStore::new();
        let l7_server = Arc::new(ServerConfig {
            id: Some(1),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "*.mymya.cn".to_string(),
                ..Default::default()
            }],
            https: Some(HTTPSConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("https".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("443".to_string()),
                }],
                ssl_policy: None,
                supports_http3: None,
            }),
            ..Default::default()
        });
        let passthrough_server = Arc::new(ServerConfig {
            id: Some(2),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "rancher.mymya.cn@sni_passthrough".to_string(),
                ..Default::default()
            }],
            https: Some(HTTPSConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("https".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("443".to_string()),
                }],
                ssl_policy: None,
                supports_http3: None,
            }),
            ..Default::default()
        });

        let mut servers = HashMap::new();
        servers.insert("*.mymya.cn".to_string(), l7_server.clone());
        servers.insert("rancher.mymya.cn".to_string(), passthrough_server.clone());
        store
            .update_config(
                1,
                1,
                0,
                0,
                vec![l7_server, passthrough_server],
                servers,
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                0,
                1,
                true,
                true,
                HashMap::new(),
                false,
                false,
                "random".to_string(),
                HashMap::new(),
                None,
                false,
                false,
                String::new(),
                false,
                false,
                0,
                false,
                false,
                false,
                String::new(),
                None,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                None,
                None,
            )
            .await;

        let route = store
            .inspect_tls_route_sync("rancher.mymya.cn", 443)
            .expect("TLS route should inspect configured host");
        assert!(!route.has_l7_server);
        assert_eq!(
            route
                .sni_passthrough_server
                .map(|server| server.numeric_id()),
            Some(2)
        );
    }

    #[tokio::test]
    async fn quic_passthrough_marker_indexes_udp_listener_names() {
        let store = ConfigStore::new();
        let quic_server = Arc::new(ServerConfig {
            id: Some(4),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "*.qq.com@quic".to_string(),
                ..Default::default()
            }],
            udp: Some(UDPConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("udp".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("443-444".to_string()),
                }],
            }),
            ..Default::default()
        });
        let mut servers = HashMap::new();
        servers.insert("*.qq.com".to_string(), quic_server.clone());
        store
            .update_config(
                1,
                1,
                0,
                0,
                vec![quic_server],
                servers,
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                0,
                1,
                true,
                true,
                HashMap::new(),
                false,
                false,
                "random".to_string(),
                HashMap::new(),
                None,
                false,
                false,
                String::new(),
                false,
                false,
                0,
                false,
                false,
                false,
                String::new(),
                None,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                None,
                None,
            )
            .await;

        assert!(store.has_any_quic_passthrough_sync());
        assert_eq!(
            store
                .find_quic_passthrough_server_sync("a.qq.com", 443)
                .map(|server| server.numeric_id()),
            Some(4)
        );
        assert_eq!(
            store
                .find_quic_passthrough_server_sync("a.qq.com", 444)
                .map(|server| server.numeric_id()),
            Some(4)
        );
        assert_eq!(
            store
                .find_quic_passthrough_server_sync("a.qq.com", 8443)
                .map(|server| server.numeric_id()),
            None
        );
    }

    #[tokio::test]
    async fn quic_passthrough_marker_falls_back_to_https_listener_ports() {
        let store = ConfigStore::new();
        let quic_server = Arc::new(ServerConfig {
            id: Some(7),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "quic-only.example.com@quic".to_string(),
                ..Default::default()
            }],
            https: Some(HTTPSConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("https".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("443".to_string()),
                }],
                ssl_policy: None,
                supports_http3: Some(true),
            }),
            ..Default::default()
        });
        let mut servers = HashMap::new();
        servers.insert("quic-only.example.com".to_string(), quic_server.clone());
        store
            .update_config(
                1,
                1,
                0,
                0,
                vec![quic_server],
                servers,
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                0,
                1,
                true,
                true,
                HashMap::new(),
                false,
                false,
                "random".to_string(),
                HashMap::new(),
                None,
                false,
                false,
                String::new(),
                false,
                false,
                0,
                false,
                false,
                false,
                String::new(),
                None,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                None,
                None,
            )
            .await;

        assert!(store.has_any_quic_passthrough_sync());
        assert_eq!(
            store
                .find_quic_passthrough_server_sync("quic-only.example.com", 443)
                .map(|server| server.numeric_id()),
            Some(7)
        );
    }

    #[tokio::test]
    async fn quic_passthrough_indexes_udp_and_https_listener_ports() {
        let store = ConfigStore::new();
        let quic_server = Arc::new(ServerConfig {
            id: Some(8),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "mixed-quic.example.com@quic".to_string(),
                ..Default::default()
            }],
            udp: Some(UDPConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("udp".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("8443".to_string()),
                }],
            }),
            https: Some(HTTPSConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("https".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("443".to_string()),
                }],
                ssl_policy: None,
                supports_http3: Some(true),
            }),
            ..Default::default()
        });
        let mut servers = HashMap::new();
        servers.insert("mixed-quic.example.com".to_string(), quic_server.clone());
        store
            .update_config(
                1,
                1,
                0,
                0,
                vec![quic_server],
                servers,
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                0,
                1,
                true,
                true,
                HashMap::new(),
                false,
                false,
                "random".to_string(),
                HashMap::new(),
                None,
                false,
                false,
                String::new(),
                false,
                false,
                0,
                false,
                false,
                false,
                String::new(),
                None,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                None,
                None,
            )
            .await;

        assert_eq!(
            store
                .find_quic_passthrough_server_sync("mixed-quic.example.com", 443)
                .map(|server| server.numeric_id()),
            Some(8)
        );
        assert_eq!(
            store
                .find_quic_passthrough_server_sync("mixed-quic.example.com", 8443)
                .map(|server| server.numeric_id()),
            Some(8)
        );
    }

    #[tokio::test]
    async fn unique_quic_passthrough_by_port_requires_single_server() {
        let store = ConfigStore::new();
        let first = Arc::new(ServerConfig {
            id: Some(4),
            is_on: true,
            server_names: vec![
                ServerNameConfig {
                    name: "a.example.com@quic".to_string(),
                    ..Default::default()
                },
                ServerNameConfig {
                    name: "b.example.com@quic".to_string(),
                    ..Default::default()
                },
            ],
            udp: Some(UDPConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("udp".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("443".to_string()),
                }],
            }),
            ..Default::default()
        });
        let second = Arc::new(ServerConfig {
            id: Some(5),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "c.example.com@quic".to_string(),
                ..Default::default()
            }],
            udp: Some(UDPConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("udp".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("8443".to_string()),
                }],
            }),
            ..Default::default()
        });
        let mut servers = HashMap::new();
        servers.insert("a.example.com".to_string(), first.clone());
        servers.insert("b.example.com".to_string(), first.clone());
        servers.insert("c.example.com".to_string(), second.clone());
        store
            .update_config(
                1,
                1,
                0,
                0,
                vec![first.clone(), second.clone()],
                servers,
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                0,
                1,
                true,
                true,
                HashMap::new(),
                false,
                false,
                "random".to_string(),
                HashMap::new(),
                None,
                false,
                false,
                String::new(),
                false,
                false,
                0,
                false,
                false,
                false,
                String::new(),
                None,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                None,
                None,
            )
            .await;

        assert_eq!(
            store
                .find_unique_quic_passthrough_server_by_port_sync(443)
                .map(|server| server.numeric_id()),
            Some(4)
        );
        assert_eq!(
            store
                .find_unique_quic_passthrough_server_by_port_sync(8443)
                .map(|server| server.numeric_id()),
            Some(5)
        );

        let third = Arc::new(ServerConfig {
            id: Some(6),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "d.example.com@quic".to_string(),
                ..Default::default()
            }],
            udp: Some(UDPConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("udp".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("443".to_string()),
                }],
            }),
            ..Default::default()
        });
        let mut servers = HashMap::new();
        servers.insert("a.example.com".to_string(), first.clone());
        servers.insert("b.example.com".to_string(), first.clone());
        servers.insert("c.example.com".to_string(), second.clone());
        servers.insert("d.example.com".to_string(), third.clone());
        store
            .update_config(
                1,
                2,
                0,
                0,
                vec![first, second, third],
                servers,
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                0,
                1,
                true,
                true,
                HashMap::new(),
                false,
                false,
                "random".to_string(),
                HashMap::new(),
                None,
                false,
                false,
                String::new(),
                false,
                false,
                0,
                false,
                false,
                false,
                String::new(),
                None,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                None,
                None,
            )
            .await;

        assert_eq!(
            store
                .find_unique_quic_passthrough_server_by_port_sync(443)
                .map(|server| server.numeric_id()),
            None
        );
    }

    #[test]
    fn http_https_listen_ports_come_from_configured_port_ranges() {
        let server = ServerConfig {
            id: Some(3),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "ports.example.com".to_string(),
                ..Default::default()
            }],
            http: Some(crate::config_models::HTTPConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("http".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("8080".to_string()),
                }],
            }),
            https: Some(HTTPSConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("https".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("8443-8444".to_string()),
                }],
                ssl_policy: None,
                supports_http3: None,
            }),
            ..Default::default()
        };

        let http_ports: Vec<_> = server
            .http
            .as_ref()
            .into_iter()
            .flat_map(|http| &http.listen)
            .filter_map(|addr| addr.port_range.as_deref())
            .flat_map(crate::config_models::ports_in_range)
            .collect();
        let https_ports: Vec<_> = server
            .https
            .as_ref()
            .into_iter()
            .flat_map(|https| &https.listen)
            .filter_map(|addr| addr.port_range.as_deref())
            .flat_map(crate::config_models::ports_in_range)
            .collect();

        assert_eq!(http_ports, vec![8080]);
        assert_eq!(https_ports, vec![8443, 8444]);
        assert!(!server.listens_on_https_port(443));
        assert!(server.listens_on_https_port(8443));
        assert!(server.listens_on_https_port(8444));
    }

    #[test]
    fn site_http3_requires_explicit_enable() {
        let default_https = HTTPSConfig {
            is_on: true,
            listen: vec![NetworkAddressConfig {
                protocol: Some("https".to_string()),
                host: Some("0.0.0.0".to_string()),
                port_range: Some("443".to_string()),
            }],
            ssl_policy: None,
            supports_http3: None,
        };
        assert!(!default_https.http3_enabled());

        let server = ServerConfig {
            id: Some(4),
            is_on: true,
            https: Some(default_https),
            ..Default::default()
        };
        assert!(!server.http3_enabled());
        assert!(!server.supports_http3_on_port(443));

        let enabled_server = ServerConfig {
            https: Some(HTTPSConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("https".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("443".to_string()),
                }],
                ssl_policy: None,
                supports_http3: Some(true),
            }),
            ..Default::default()
        };
        assert!(enabled_server.http3_enabled());
        assert!(enabled_server.supports_http3_on_port(443));
    }
}
