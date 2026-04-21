use std::collections::HashMap;
use std::sync::Arc;
use pingora_load_balancing::{LoadBalancer, selection::RoundRobin};
use crate::config_models::ServerConfig;
use crate::health_manager::GlobalHealthManager;
use crate::api_config::ApiConfig;
use std::time::Duration;

#[allow(clippy::type_complexity)]
pub fn build_runtime_maps(
    servers: Vec<ServerConfig>,
    health_manager: &GlobalHealthManager,
) -> (
    HashMap<String, ServerConfig>,
    HashMap<String, Arc<LoadBalancer<RoundRobin>>>,
) {
    let mut new_servers = HashMap::new();
    let mut new_routes = HashMap::new();

    for server in servers {
        if !server.is_on {
            continue;
        }

        let server_id = server.numeric_id();
        let (lb_arc, has_hc) = if let Some(rp) = &server.reverse_proxy {
            crate::lb_factory::build_lb(server_id, rp, 1, &HashMap::new(), false, false)
        } else {
             // Fallback if no reverse proxy config
             let mut b = pingora_load_balancing::Backend::new("127.0.0.1:80").unwrap();
             let mut ext = http::Extensions::new();
             ext.insert(crate::lb_factory::BackendExtension {
                use_tls: false,
                host: String::new(),
                follow_host: false,
                tls_verify: true,
                client_cert: None,
             });
             b.ext = ext;
             let mut set = std::collections::BTreeSet::new();
             set.insert(b);
             let backends = pingora_load_balancing::Backends::new(pingora_load_balancing::discovery::Static::new(set));
             (Arc::new(LoadBalancer::from_backends(backends)), false)
        };
        
        if let Some(id) = server.id {
            if has_hc {
                health_manager.register(id, lb_arc.clone(), Duration::from_secs(30));
            }
        }

        for name in server.get_plain_server_names() {
            new_servers.insert(name.clone(), server.clone());
            new_routes.insert(name.clone(), lb_arc.clone());
        }
    }

    (new_servers, new_routes)
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
                } else if !item.url.is_empty() && !deleted_contents.iter().any(|url| url == &item.url)
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
