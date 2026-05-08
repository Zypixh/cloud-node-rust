use crate::api_config::ApiConfig;
use crate::config_models::ServerConfig;
use crate::health_manager::GlobalHealthManager;
use futures_util::FutureExt;
use pingora_load_balancing::{Backends, LoadBalancer, discovery::Static, selection::RoundRobin};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

#[allow(clippy::type_complexity)]
pub async fn build_runtime_maps(
    servers: Vec<ServerConfig>,
    health_manager: &GlobalHealthManager,
) -> (
    HashMap<String, Arc<ServerConfig>>,
    HashMap<String, Arc<crate::lb_factory::AnyLoadBalancer>>,
) {
    let mut new_servers = HashMap::new();
    let mut new_routes = HashMap::new();

    for server in servers {
        server.compile_url_patterns();
        if !server.is_on {
            continue;
        }

        let server_id = server.numeric_id();
        let (lb_arc, has_hc) = if let Some(rp) = &server.reverse_proxy {
            match crate::lb_factory::build_lb_blocking(
                server_id,
                rp.clone(),
                1,
                Arc::new(HashMap::new()),
                false,
                false,
            )
            .await
            {
                Ok(result) => result,
                Err(err) => {
                    tracing::warn!(
                        "failed to build runtime LB for server {}: {}",
                        server_id,
                        err
                    );
                    fallback_runtime_lb()
                }
            }
        } else {
            fallback_runtime_lb()
        };

        if let Some(id) = server.id {
            if has_hc {
                health_manager.register(id, lb_arc.clone(), Duration::from_secs(30));
            }
        }

        let names = server.get_plain_server_names();
        let server_arc = Arc::new(server);
        if names.is_empty() {
            let synthetic = format!("__id_{}", server_arc.numeric_id());
            new_servers.insert(synthetic.clone(), server_arc.clone());
            new_routes.insert(synthetic, lb_arc.clone());
        } else {
            for name in names {
                new_servers.insert(name.clone(), server_arc.clone());
                new_routes.insert(name.clone(), lb_arc.clone());
            }
        }
    }

    (new_servers, new_routes)
}

pub(crate) fn fallback_runtime_lb() -> (Arc<crate::lb_factory::AnyLoadBalancer>, bool) {
    let mut b = pingora_load_balancing::Backend::new("127.0.0.1:80").unwrap();
    let mut ext = http::Extensions::new();
    ext.insert(crate::lb_factory::BackendExtension {
        use_tls: false,
        host: String::new(),
        rp_host: String::new(),
        origin_id: 0,
        origin_host: String::new(),
        follow_port: false,
        follow_host: false,
        http2_enabled: false,
        tls_verify: true,
        request_host_excluding_port: false,
        connection_timeout: None,
        read_timeout: None,
        idle_timeout: None,
        client_cert: None,
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
    let client = match crate::rpc::client::RpcClient::new(api_config).await {
        Ok(client) => client,
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
