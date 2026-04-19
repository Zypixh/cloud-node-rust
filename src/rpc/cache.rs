#![allow(clippy::result_large_err)]

use crate::api_config::ApiConfig;
use crate::auth::generate_token;
use crate::pb;
use tonic::transport::Channel;
use tonic::Request;
use tracing::{error, info};

pub async fn sync_cache_tasks(channel: Channel, api_config: &ApiConfig) -> bool {
    let node_id_clone = api_config.node_id.clone();
    let secret_clone = api_config.secret.clone();
    let mut client =
        pb::http_cache_task_key_service_client::HttpCacheTaskKeyServiceClient::with_interceptor(
            channel,
            move |mut req: Request<()>| {
                let token = generate_token(&node_id_clone, &secret_clone, "edge").unwrap_or_default();
                req.metadata_mut()
                    .insert("nodeid", node_id_clone.parse().unwrap());
                req.metadata_mut().insert("token", token.parse().unwrap());
                Ok(req)
            },
        );

    match client
        .find_doing_http_cache_task_keys(pb::FindDoingHttpCacheTaskKeysRequest { size: 100 })
        .await
    {
        Ok(resp) => {
            let keys = resp.into_inner().http_cache_task_keys;
            let mut results = vec![];

            let http_client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap_or_default();

            for key_task in keys {
                let mut error = String::new();

                if key_task.r#type == "purge" {
                    info!("Purging cache key: {}", key_task.key);
                    let purge_ok = if key_task.key.contains('*') {
                        crate::cache_manager::CACHE
                            .purge_prefix(&key_task.key)
                            .await
                            .is_ok()
                    } else {
                        crate::cache_manager::CACHE
                            .purge_key(&key_task.key)
                            .await
                            .is_ok()
                    };
                    if !purge_ok {
                        error = "Purge failed".to_string();
                    }
                } else if key_task.r#type == "preheat" {
                    info!("Preheating cache key (URL): {}", key_task.key);
                    if let Ok(url) = key_task.key.parse::<reqwest::Url>() {
                        let host = url.host_str().unwrap_or("localhost");
                        let is_https = url.scheme() == "https";
                        let port = url.port().unwrap_or(if is_https { 443 } else { 80 });

                        let scheme = if is_https { "https" } else { "http" };
                        let preheat_url = format!("{}://127.0.0.1:{}{}", scheme, port, url.path());
                        let query = url.query().map(|q| format!("?{}", q)).unwrap_or_default();
                        let final_url = format!("{}{}", preheat_url, query);

                        match http_client
                            .get(&final_url)
                            .header("host", host)
                            .header("x-cloud-cache-action", "fetch")
                            .header("x-cloud-preheat", "1")
                            .header("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
                            .header("accept-encoding", "gzip, deflate, br")
                            .send()
                            .await
                        {
                            Ok(resp) => {
                                if !resp.status().is_success() {
                                    error!(
                                        "Preheat returned status: {} for {}",
                                        resp.status(),
                                        key_task.key
                                    );
                                } else {
                                    info!("Preheat success: {}", key_task.key);
                                }
                            }
                            Err(e) => {
                                error!("Preheat request failed for {}: {}", key_task.key, e);
                                error = e.to_string();
                            }
                        }
                    } else {
                        error!("Invalid preheat URL: {}", key_task.key);
                        error = "Invalid preheat URL".to_string();
                    }
                }

                results.push(pb::update_http_cache_task_keys_status_request::KeyResult {
                    id: key_task.id,
                    node_cluster_id: 0,
                    error,
                });
            }
            if !results.is_empty() {
                let _ = client
                    .update_http_cache_task_keys_status(pb::UpdateHttpCacheTaskKeysStatusRequest {
                        key_results: results,
                    })
                    .await;
            }
            true
        }
        Err(e) => {
            error!("Failed to fetch cache tasks: {}", e);
            false
        }
    }
}
