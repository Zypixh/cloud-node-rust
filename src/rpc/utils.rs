use crate::api_config::ApiConfig;
use crate::config_models::{ParentNodeConfig, ProxyProtocolConfig, ServerConfig};
use crate::health_manager::GlobalHealthManager;
use futures_util::FutureExt;
use pingora_load_balancing::{Backends, LoadBalancer, discovery::Static, selection::RoundRobin};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub fn server_runtime_names(server: &ServerConfig) -> Vec<String> {
    let mut names = server.get_plain_server_names();
    if server_has_subdomain_oss_origin(server) {
        let mut seen: HashSet<String> = names.iter().cloned().collect();
        for name in server.get_plain_server_names() {
            if name.starts_with("*.") || name.starts_with("*") || name.is_empty() {
                continue;
            }
            let wildcard = format!("*.{}", name.trim_start_matches('.'));
            if seen.insert(wildcard.clone()) {
                names.push(wildcard);
            }
        }
    }
    names
}

fn server_has_subdomain_oss_origin(server: &ServerConfig) -> bool {
    let Some(rp) = &server.reverse_proxy else {
        return false;
    };
    rp.primary_origins
        .iter()
        .chain(rp.backup_origins.iter())
        .filter(|origin| origin.is_on && origin.is_oss())
        .any(|origin| {
            crate::oss_origin::OssBackend::from_origin(origin)
                .map(|backend| backend.bucket_source == crate::oss_origin::BucketSource::Subdomain)
                .unwrap_or(false)
        })
}

pub async fn build_runtime_maps(
    servers: Vec<ServerConfig>,
    health_manager: &GlobalHealthManager,
    node_level: i32,
    parent_nodes: Arc<HashMap<i64, Vec<ParentNodeConfig>>>,
    tiered_origin_bypass: bool,
    allow_lan: bool,
    global_http: Option<crate::config_models::GlobalHTTPAllConfig>,
) -> crate::config_apply::RuntimeServerMaps {
    crate::config_apply::materialize_runtime_servers(
        crate::config_apply::MaterializeRuntimeServersArgs {
            servers,
            health_manager,
            node_level,
            parent_nodes,
            tiered_origin_bypass,
            allow_lan,
            global_http: global_http.map(Arc::new),
            limits: crate::config_apply::ConfigApplyLimits::from_governor(),
        },
    )
    .await
}

pub(crate) fn fallback_runtime_lb() -> (Arc<crate::lb_factory::AnyLoadBalancer>, bool) {
    let mut b = pingora_load_balancing::Backend::new("127.0.0.1:80").unwrap();
    let mut ext = http::Extensions::new();
    ext.insert(crate::lb_factory::BackendExtension {
        origin_role: crate::lb_factory::OriginRole::Fallback,
        use_tls: false,
        host: String::new(),
        rp_host: String::new(),
        origin_id: 0,
        origin_host: String::new(),
        origin_host_normalized: String::new(),
        explicit_tls_host_normalized: None,
        follow_port: false,
        follow_host: false,
        http2_enabled: false,
        http3_enabled: false,
        tls_security_verify_mode: crate::config_models::OriginTlsSecurityVerifyMode::Force,
        legacy_tls_verify: None,
        request_host_excluding_port: false,
        proxy_protocol: ProxyProtocolConfig::default(),
        connection_timeout: None,
        read_timeout: None,
        idle_timeout: None,
        write_timeout: None,
        client_cert: None,
        unsupported_reason: None,
        oss_backend: None,
    });
    b.ext = ext;
    let mut set = std::collections::BTreeSet::new();
    set.insert(b);
    let backends = Backends::new(Static::new(set));
    let lb: LoadBalancer<RoundRobin> = LoadBalancer::from_backends(backends);
    lb.update()
        .now_or_never()
        .expect("static fallback load balancer update should not block")
        .expect("static fallback load balancer update should not fail");
    (
        Arc::new(crate::lb_factory::AnyLoadBalancer::RoundRobin(Arc::new(lb))),
        false,
    )
}

pub async fn sync_deleted_contents(
    api_config: &ApiConfig,
    config_store: &crate::config::ConfigStore,
    version: &mut i64,
) {
    let client = match crate::rpc::client::SharedRpcClient::get(api_config).await {
        Ok(s) => s.as_rpc_client(),
        Err(err) => {
            tracing::debug!("Failed to connect for deleted content sync: {}", err);
            return;
        }
    };

    let mut service = client.deleted_content_service();
    match service
        .list_server_deleted_contents_after_version(
            crate::pb::ListServerDeletedContentsAfterVersionRequest {
                version: *version,
                size: 5000,
            },
        )
        .await
    {
        Ok(resp) => {
            let items = resp.into_inner().server_deleted_contents;
            if items.is_empty() {
                return;
            }

            let mut deleted_contents = config_store.get_deleted_contents().await;
            for item in items {
                if item.is_deleted {
                    deleted_contents.retain(|url| url != &item.url);
                } else if !item.url.is_empty()
                    && !deleted_contents.iter().any(|url| url == &item.url)
                {
                    deleted_contents.push(item.url.clone());
                }

                if item.version > *version {
                    *version = item.version;
                }
            }

            config_store.set_deleted_contents(deleted_contents).await;
        }
        Err(err) => {
            tracing::debug!("Failed to sync deleted contents: {}", err);
        }
    }
}
