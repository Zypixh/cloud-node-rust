#![allow(clippy::result_large_err)]

use crate::api_config::ApiConfig;
use crate::auth::generate_token;
use crate::pb;
use tonic::Request;
use tonic::transport::Channel;
use tracing::{error, info};

pub(crate) fn normalize_purge_prefix(key: &str) -> String {
    let trimmed = key.trim();
    if let Some((prefix, _)) = trimmed.split_once('*') {
        return format!("{}*", prefix);
    }

    if trimmed.ends_with('/') {
        format!("{}*", trimmed)
    } else {
        format!("{}/*", trimmed)
    }
}

pub(crate) fn is_prefix_purge(key_type: &str, key: &str) -> bool {
    let key_type = key_type.to_ascii_lowercase();
    key.contains('*')
        || key_type == "dir"
        || key_type == "directory"
        || key_type == "urlprefix"
        || key_type == "url_prefix"
        || key_type == "prefix"
        || key_type == "all"
        || key_type == "allurl"
        || key_type == "all_url"
        || key_type == "allurls"
        || key_type == "all_urls"
        || key_type == "site"
        || key_type == "server"
}

pub(crate) fn is_tag_purge(key_type: &str) -> bool {
    let kt = key_type.to_ascii_lowercase();
    kt == "tag" || kt == "surrogate-key" || kt == "surrogatekey" || kt == "surrogate_key"
}

pub async fn sync_cache_tasks(channel: Channel, api_config: &ApiConfig) -> bool {
    let node_id_clone = api_config.node_id.clone();
    let secret_clone = api_config.secret.clone();
    let mut client =
        pb::http_cache_task_key_service_client::HttpCacheTaskKeyServiceClient::with_interceptor(
            channel,
            move |mut req: Request<()>| {
                let token =
                    generate_token(&node_id_clone, &secret_clone, "node").unwrap_or_default();
                // node_id / token come from runtime config; defensively avoid
                // .unwrap() so a stray non-ASCII byte cannot panic the whole
                // interceptor task.
                let node_id_val = node_id_clone
                    .parse()
                    .unwrap_or_else(|_| tonic::metadata::MetadataValue::from_static("0"));
                let token_val = token
                    .parse()
                    .unwrap_or_else(|_| tonic::metadata::MetadataValue::from_static(""));
                req.metadata_mut().insert("nodeid", node_id_val);
                req.metadata_mut().insert("token", token_val);
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
                .build()
                .unwrap_or_default();

            for key_task in keys {
                let mut error = String::new();

                if key_task.r#type == "purge" && is_tag_purge(&key_task.key_type) {
                    info!(
                        "Purging cache by surrogate tag: {}",
                        key_task.key
                    );
                    let purge_ok = crate::cache_manager::CACHE
                        .storage
                        .purge_by_tag(key_task.key.trim())
                        .await;
                    if purge_ok && crate::runtime_mode::RuntimeConfig::current_is_rke2() {
                        let purge_id = format!("{}:{}", key_task.id, uuid::Uuid::new_v4());
                        if let Err(err) = crate::cluster::purge::fanout(
                            crate::cluster::purge::PurgeFanoutRequest {
                                purge_id,
                                task_id: key_task.id,
                                key: key_task.key.trim().to_string(),
                                key_type: key_task.key_type.clone(),
                                prefix: String::new(),
                                leader_epoch: crate::cluster::leader::ROLE_STATE.epoch(),
                            },
                        )
                        .await
                        {
                            error!("Tag purge fanout failed for {}: {}", key_task.key, err);
                        }
                    }
                    if !purge_ok {
                        error = "Tag purge failed".to_string();
                    }
                } else if key_task.r#type == "purge" {
                    info!(
                        "Purging cache key: {} (keyType: {})",
                        key_task.key, key_task.key_type
                    );
                    let purge_ok = if is_prefix_purge(&key_task.key_type, &key_task.key) {
                        let prefix = normalize_purge_prefix(&key_task.key);
                        crate::cache_manager::CACHE
                            .purge_prefix(&prefix)
                            .await
                            .is_ok()
                    } else {
                        crate::cache_manager::CACHE
                            .purge_key(key_task.key.trim())
                            .await
                            .is_ok()
                    };
                    if purge_ok && crate::runtime_mode::RuntimeConfig::current_is_rke2() {
                        let prefix = if is_prefix_purge(&key_task.key_type, &key_task.key) {
                            normalize_purge_prefix(&key_task.key)
                        } else {
                            String::new()
                        };
                        let purge_id = format!("{}:{}", key_task.id, uuid::Uuid::new_v4());
                        if let Err(err) = crate::cluster::purge::fanout(
                            crate::cluster::purge::PurgeFanoutRequest {
                                purge_id,
                                task_id: key_task.id,
                                key: key_task.key.trim().to_string(),
                                key_type: key_task.key_type.clone(),
                                prefix,
                                leader_epoch: crate::cluster::leader::ROLE_STATE.epoch(),
                            },
                        )
                        .await
                        {
                            error!("Purge fanout failed for {}: {}", key_task.key, err);
                        }
                    }
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
                    node_cluster_id: key_task.node_cluster_id,
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
