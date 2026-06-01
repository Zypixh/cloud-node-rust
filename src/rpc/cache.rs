#![allow(clippy::result_large_err)]

use crate::api_config::ApiConfig;
use crate::auth::generate_token;
use crate::config::ConfigStore;
use crate::config_models::{LocationConfig, ServerConfig, WebCacheConfig};
use crate::pb;
use futures_util::StreamExt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tonic::Request;
use tonic::transport::Channel;
use tracing::{error, info, warn};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PurgeTarget {
    Key(String),
    Prefix(String),
}

pub(crate) fn is_dangerous_purge_prefix(prefix: &str) -> bool {
    let clean = prefix.trim().trim_end_matches('*').trim();
    if clean.is_empty()
        || clean == "/"
        || clean.eq_ignore_ascii_case("http://")
        || clean.eq_ignore_ascii_case("https://")
    {
        return true;
    }

    let lower = clean.to_ascii_lowercase();
    if let Some(after_scheme) = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
    {
        return after_scheme.find('/').is_none_or(|index| index == 0);
    }

    false
}

fn is_all_site_purge(key_type: &str) -> bool {
    let key_type = key_type.to_ascii_lowercase();
    matches!(
        key_type.as_str(),
        "all" | "allurl" | "all_url" | "allurls" | "all_urls" | "site" | "server"
    )
}

fn normalize_host(host: &str) -> String {
    crate::lb_factory::strip_addr_port(host)
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn parse_purge_url(raw_key: &str) -> Result<reqwest::Url, String> {
    let trimmed = raw_key.trim();
    let without_wildcard = trimmed
        .split_once('*')
        .map(|(prefix, _)| prefix.trim())
        .unwrap_or(trimmed);
    if without_wildcard.is_empty() {
        return Err("purge URL is empty".to_string());
    }
    if without_wildcard == "*" {
        return Err("wildcard-only purge is not allowed".to_string());
    }

    let candidate = if without_wildcard.contains("://") {
        without_wildcard.to_string()
    } else {
        format!("https://{without_wildcard}")
    };
    let url = reqwest::Url::parse(&candidate)
        .map_err(|err| format!("invalid purge URL '{}': {}", raw_key, err))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("unsupported purge URL scheme '{}'", url.scheme()));
    }
    if url.host_str().unwrap_or_default().is_empty() {
        return Err(format!("purge URL '{}' has no host", raw_key));
    }
    Ok(url)
}

fn url_host(url: &reqwest::Url) -> String {
    normalize_host(url.host_str().unwrap_or_default())
}

fn wildcard_host_matches(pattern: &str, host: &str) -> bool {
    let pattern = normalize_host(pattern);
    let host = normalize_host(host);
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    if pattern == host {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    if !pattern.contains('*') {
        return false;
    }

    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let mut remainder = host.as_str();
    let mut first = true;
    for part in pattern.split('*').filter(|part| !part.is_empty()) {
        if first && anchored_start {
            let Some(next) = remainder.strip_prefix(part) else {
                return false;
            };
            remainder = next;
        } else if let Some(index) = remainder.find(part) {
            remainder = &remainder[index + part.len()..];
        } else {
            return false;
        }
        first = false;
    }
    !anchored_end || remainder.is_empty()
}

fn cache_key_host(cache: &WebCacheConfig) -> Option<String> {
    cache
        .key
        .as_ref()
        .filter(|key| key.is_on && !key.host.trim().is_empty())
        .map(|key| normalize_host(&key.host))
        .filter(|host| !host.is_empty())
}

fn server_has_cache_key_host(server: &ServerConfig, host: &str) -> bool {
    if server
        .web
        .as_ref()
        .and_then(|web| web.cache.as_ref())
        .and_then(cache_key_host)
        .is_some_and(|cache_host| cache_host == host)
    {
        return true;
    }

    server.locations.iter().any(|location| {
        location
            .cache
            .as_ref()
            .and_then(cache_key_host)
            .is_some_and(|cache_host| cache_host == host)
    })
}

fn server_accepts_purge_host(server: &ServerConfig, host: &str) -> bool {
    let host = normalize_host(host);
    server
        .get_plain_server_names()
        .iter()
        .any(|name| wildcard_host_matches(name, &host))
        || server_has_cache_key_host(server, &host)
}

fn find_purge_server(
    config_store: &ConfigStore,
    scope_server_id: i64,
    host: &str,
) -> Result<Arc<ServerConfig>, String> {
    let host = normalize_host(host);
    if scope_server_id > 0 {
        let server = config_store
            .get_server_by_id_sync(scope_server_id)
            .ok_or_else(|| format!("server {} is not loaded", scope_server_id))?;
        if !server_accepts_purge_host(&server, &host) {
            return Err(format!(
                "purge URL host '{}' does not belong to server {}",
                host, scope_server_id
            ));
        }
        return Ok(server);
    }

    if let Some(server) = config_store.get_server_sync(&host) {
        return Ok(server);
    }

    let matches = config_store
        .get_all_servers_sync()
        .into_iter()
        .filter(|server| server_accepts_purge_host(server, &host))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [server] => Ok(server.clone()),
        [] => Err(format!(
            "purge URL host '{}' does not match any loaded server",
            host
        )),
        _ => Err(format!(
            "purge URL host '{}' matches multiple servers; refusing unsafe purge",
            host
        )),
    }
}

fn location_rank(location: &LocationConfig, path: &str) -> Option<(u8, usize, i32)> {
    if !location.is_on || location.pattern.is_empty() {
        return None;
    }
    match location.pattern_type.as_str() {
        "exact" => (location.pattern == path).then_some((0, 0, location.priority)),
        "regex" => regex::Regex::new(&location.pattern)
            .ok()
            .filter(|regex| regex.is_match(path))
            .map(|_| (1, 0, location.priority)),
        _ => path.starts_with(&location.pattern).then_some((
            2,
            location.pattern.len(),
            location.priority,
        )),
    }
}

fn rank_is_better(new_rank: (u8, usize, i32), old_rank: (u8, usize, i32)) -> bool {
    if new_rank.0 != old_rank.0 {
        return new_rank.0 < old_rank.0;
    }
    if new_rank.0 == 2 && new_rank.1 != old_rank.1 {
        return new_rank.1 > old_rank.1;
    }
    new_rank.2 > old_rank.2
}

fn matching_location_cache<'a>(server: &'a ServerConfig, path: &str) -> Option<&'a WebCacheConfig> {
    let mut best: Option<((u8, usize, i32), &LocationConfig)> = None;
    for location in &server.locations {
        let Some(rank) = location_rank(location, path) else {
            continue;
        };
        if best
            .map(|(old_rank, _)| rank_is_better(rank, old_rank))
            .unwrap_or(true)
        {
            best = Some((rank, location));
        }
    }
    best.and_then(|(_, location)| location.cache.as_ref())
}

fn server_cache_for_path<'a>(server: &'a ServerConfig, path: &str) -> Option<&'a WebCacheConfig> {
    matching_location_cache(server, path)
        .or_else(|| server.web.as_ref().and_then(|web| web.cache.as_ref()))
}

fn cache_key_base_for_url(
    server: &ServerConfig,
    url: &reqwest::Url,
    site_root: bool,
    include_query: bool,
) -> String {
    let mut scheme = url.scheme().to_ascii_lowercase();
    let mut host = url_host(url);
    if let Some(cache) = server_cache_for_path(server, url.path())
        && let Some(key_config) = cache
            .key
            .as_ref()
            .filter(|key| key.is_on && !key.host.trim().is_empty())
    {
        let configured_scheme = key_config.scheme.trim();
        if !configured_scheme.is_empty() {
            scheme = configured_scheme.to_ascii_lowercase();
        }
        host = normalize_host(&key_config.host);
    }

    let path = if site_root { "/" } else { url.path() };
    let mut key = format!("{scheme}://{host}{path}");
    if include_query
        && !site_root
        && let Some(query) = url.query()
    {
        key.push('?');
        key.push_str(query);
    }
    key
}

fn with_scheme_counterpart(value: String) -> Vec<String> {
    let mut values = vec![value.clone()];
    if let Some(rest) = value.strip_prefix("http://") {
        values.push(format!("https://{rest}"));
    } else if let Some(rest) = value.strip_prefix("https://") {
        values.push(format!("http://{rest}"));
    }
    values.sort_unstable();
    values.dedup();
    values
}

fn primary_request_host_for_server(server: &ServerConfig) -> Option<String> {
    server
        .get_plain_server_names()
        .into_iter()
        .map(|name| normalize_host(name.strip_prefix("*.").unwrap_or(&name)))
        .find(|host| !host.is_empty() && !host.contains('*'))
}

fn server_has_exact_plain_name(server: &ServerConfig, host: &str) -> bool {
    let host = normalize_host(host);
    server
        .get_plain_server_names()
        .iter()
        .any(|name| normalize_host(name) == host)
}

fn preheat_fetch_url_for_server(
    server: &ServerConfig,
    url: &reqwest::Url,
) -> Result<reqwest::Url, String> {
    let raw_host = url_host(url);
    if server_has_exact_plain_name(server, &raw_host) {
        return Ok(url.clone());
    }
    let raw_is_cache_key_host = server_has_cache_key_host(server, &raw_host);
    let host_matches_server_name = server
        .get_plain_server_names()
        .iter()
        .any(|name| wildcard_host_matches(name, &raw_host));
    if host_matches_server_name && !raw_is_cache_key_host {
        return Ok(url.clone());
    }

    let Some(request_host) = primary_request_host_for_server(server) else {
        return Err(format!(
            "server {} has no routable hostname for preheat URL host '{}'",
            server.numeric_id(),
            raw_host
        ));
    };

    let mut fetch_url = url.clone();
    fetch_url
        .set_host(Some(&request_host))
        .map_err(|_| format!("failed to set preheat request host '{}'", request_host))?;
    Ok(fetch_url)
}

pub(crate) fn purge_targets_for_server(
    server: &ServerConfig,
    key_type: &str,
    raw_key: &str,
) -> Result<Vec<PurgeTarget>, String> {
    let url = parse_purge_url(raw_key)?;
    let targets = if is_all_site_purge(key_type) {
        let base = cache_key_base_for_url(server, &url, true, false);
        vec![PurgeTarget::Prefix(normalize_purge_prefix(&base))]
    } else if is_prefix_purge(key_type, raw_key) {
        let base = cache_key_base_for_url(server, &url, false, false);
        vec![PurgeTarget::Prefix(normalize_purge_prefix(&base))]
    } else {
        let base = cache_key_base_for_url(server, &url, false, true);
        vec![PurgeTarget::Key(base)]
    };

    let mut expanded = Vec::new();
    for target in targets {
        match target {
            PurgeTarget::Key(key) => {
                expanded.extend(
                    with_scheme_counterpart(key)
                        .into_iter()
                        .map(PurgeTarget::Key),
                );
            }
            PurgeTarget::Prefix(prefix) => {
                if is_dangerous_purge_prefix(&prefix) {
                    return Err(format!("refusing dangerous purge prefix '{}'", prefix));
                }
                expanded.extend(
                    with_scheme_counterpart(prefix)
                        .into_iter()
                        .map(PurgeTarget::Prefix),
                );
            }
        }
    }
    expanded.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));
    expanded.dedup();
    Ok(expanded)
}

pub(crate) fn purge_targets_for_config(
    config_store: &ConfigStore,
    scope_server_id: i64,
    key_type: &str,
    raw_key: &str,
) -> Result<Vec<PurgeTarget>, String> {
    let url = parse_purge_url(raw_key)?;
    let server = find_purge_server(config_store, scope_server_id, &url_host(&url))?;
    purge_targets_for_server(&server, key_type, raw_key)
}

fn is_preheat_task_type(task_type: &str) -> bool {
    matches!(task_type.to_ascii_lowercase().as_str(), "preheat" | "fetch")
}

async fn preheat_cache_url(
    raw_url: &str,
    config_store: &ConfigStore,
    scope_server_id: i64,
) -> Result<(), String> {
    let url = reqwest::Url::parse(raw_url)
        .map_err(|err| format!("invalid preheat URL '{}': {}", raw_url, err))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("unsupported preheat URL scheme '{}'", url.scheme()));
    }
    let raw_host = url
        .host_str()
        .ok_or_else(|| format!("preheat URL '{}' has no host", raw_url))?;
    let server = find_purge_server(config_store, scope_server_id, raw_host)?;
    let fetch_url = preheat_fetch_url_for_server(&server, &url)?;
    let fetch_host = fetch_url
        .host_str()
        .ok_or_else(|| format!("preheat URL '{}' has no host", raw_url))?;
    let port = fetch_url
        .port_or_known_default()
        .ok_or_else(|| format!("preheat URL '{}' has no default port", raw_url))?;
    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        // Preheat is pinned to the local proxy via `resolve()`. The local TLS
        // listener may serve a default/self-signed cert in dev or before OCSP
        // sync, but the request still must exercise the same HTTPS route/key.
        .danger_accept_invalid_certs(true)
        .resolve(fetch_host, loopback)
        .build()
        .map_err(|err| format!("build preheat HTTP client failed: {}", err))?;

    let resp = client
        .get(fetch_url)
        .header("x-edge-cache-action", "fetch")
        .header("x-cloud-cache-action", "fetch")
        .header("x-edge-preheat", "1")
        .header("x-cloud-preheat", "1")
        .header(
            "user-agent",
            "Mozilla/5.0 (compatible; CloudNodePreheat/1.0)",
        )
        .header("accept-encoding", "gzip, deflate, br")
        .send()
        .await
        .map_err(|err| format!("preheat request failed: {}", err))?;
    let status = resp.status();
    let mut body = resp.bytes_stream();
    while let Some(chunk) = body.next().await {
        chunk.map_err(|err| format!("preheat body read failed: {}", err))?;
    }
    if !status.is_success() {
        return Err(format!("preheat returned status {}", status));
    }
    Ok(())
}

pub async fn sync_cache_tasks(
    channel: Channel,
    api_config: &ApiConfig,
    config_store: &ConfigStore,
    task_id: i64,
    scope_server_id: i64,
) -> bool {
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

            for key_task in keys {
                if task_id > 0 && key_task.task_id > 0 && key_task.task_id != task_id {
                    continue;
                }
                let mut error = String::new();

                if key_task.r#type == "purge" && is_tag_purge(&key_task.key_type) {
                    info!("Purging cache by surrogate tag: {}", key_task.key);
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
                    let targets = match purge_targets_for_config(
                        config_store,
                        scope_server_id,
                        &key_task.key_type,
                        &key_task.key,
                    ) {
                        Ok(targets) => targets,
                        Err(err) => {
                            warn!(
                                "Rejecting unsafe purge task {} key={} keyType={}: {}",
                                key_task.id, key_task.key, key_task.key_type, err
                            );
                            error = err;
                            Vec::new()
                        }
                    };
                    let mut purge_ok = !targets.is_empty();
                    for target in &targets {
                        let target_ok = match target {
                            PurgeTarget::Key(key) => {
                                crate::cache_manager::CACHE.purge_key(key).await.is_ok()
                            }
                            PurgeTarget::Prefix(prefix) => crate::cache_manager::CACHE
                                .purge_prefix(prefix)
                                .await
                                .is_ok(),
                        };
                        purge_ok &= target_ok;
                    }
                    if purge_ok && crate::runtime_mode::RuntimeConfig::current_is_rke2() {
                        for target in &targets {
                            let purge_id = format!("{}:{}", key_task.id, uuid::Uuid::new_v4());
                            let (key, key_type, prefix) = match target {
                                PurgeTarget::Key(key) => {
                                    (key.clone(), "key".to_string(), String::new())
                                }
                                PurgeTarget::Prefix(prefix) => {
                                    (String::new(), "prefix".to_string(), prefix.clone())
                                }
                            };
                            if let Err(err) = crate::cluster::purge::fanout(
                                crate::cluster::purge::PurgeFanoutRequest {
                                    purge_id,
                                    task_id: key_task.id,
                                    key,
                                    key_type,
                                    prefix,
                                    leader_epoch: crate::cluster::leader::ROLE_STATE.epoch(),
                                },
                            )
                            .await
                            {
                                error!("Purge fanout failed for {}: {}", key_task.key, err);
                            }
                        }
                    }
                    if !purge_ok && error.is_empty() {
                        error = "Purge failed".to_string();
                    }
                } else if is_preheat_task_type(&key_task.r#type) {
                    info!("Preheating cache key (URL): {}", key_task.key);
                    match preheat_cache_url(&key_task.key, config_store, scope_server_id).await {
                        Ok(()) => {
                            info!("Preheat success: {}", key_task.key);
                        }
                        Err(err) => {
                            error!("Preheat failed for {}: {}", key_task.key, err);
                            error = err;
                        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn server_with_cache_key() -> ServerConfig {
        serde_json::from_value(json!({
            "id": 7,
            "serverNames": [
                {"name": "*.example.com"}
            ],
            "web": {
                "cache": {
                    "isOn": true,
                    "key": {
                        "isOn": true,
                        "scheme": "https",
                        "host": "cache.example.com"
                    },
                    "cacheRefs": []
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn purge_url_uses_configured_cache_key_host_for_wildcard_site() {
        let server = server_with_cache_key();
        let targets =
            purge_targets_for_server(&server, "key", "https://a.example.com/live/seg.ts?token=1")
                .unwrap();

        assert_eq!(
            targets,
            vec![
                PurgeTarget::Key("http://cache.example.com/live/seg.ts?token=1".to_string()),
                PurgeTarget::Key("https://cache.example.com/live/seg.ts?token=1".to_string()),
            ]
        );
    }

    #[test]
    fn purge_directory_and_all_url_are_bounded_to_site_prefix() {
        let server = server_with_cache_key();

        let dir_targets =
            purge_targets_for_server(&server, "directory", "https://b.example.com/live/").unwrap();
        assert_eq!(
            dir_targets,
            vec![
                PurgeTarget::Prefix("http://cache.example.com/live/*".to_string()),
                PurgeTarget::Prefix("https://cache.example.com/live/*".to_string()),
            ]
        );

        let all_targets =
            purge_targets_for_server(&server, "all_url", "https://b.example.com/").unwrap();
        assert_eq!(
            all_targets,
            vec![
                PurgeTarget::Prefix("http://cache.example.com/*".to_string()),
                PurgeTarget::Prefix("https://cache.example.com/*".to_string()),
            ]
        );
    }

    #[test]
    fn purge_rejects_wildcard_only_global_delete() {
        let server = server_with_cache_key();
        assert!(purge_targets_for_server(&server, "all_url", "*").is_err());
        assert!(is_dangerous_purge_prefix("*"));
        assert!(is_dangerous_purge_prefix(""));
        assert!(is_dangerous_purge_prefix("https://cache.example.com*"));
        assert!(is_dangerous_purge_prefix("https://cache.example.com"));
        assert!(!is_dangerous_purge_prefix("https://cache.example.com/*"));
    }

    #[test]
    fn location_cache_key_overrides_site_cache_key_for_matching_path() {
        let server: ServerConfig = serde_json::from_value(json!({
            "id": 8,
            "serverNames": [
                {"name": "media.example.com"}
            ],
            "locations": [
                {
                    "isOn": true,
                    "pattern": "/vod/",
                    "patternType": "prefix",
                    "cache": {
                        "isOn": true,
                        "key": {
                            "isOn": true,
                            "scheme": "https",
                            "host": "vod-cache.example.com"
                        },
                        "cacheRefs": []
                    }
                }
            ],
            "web": {
                "cache": {
                    "isOn": true,
                    "key": {
                        "isOn": true,
                        "scheme": "https",
                        "host": "site-cache.example.com"
                    },
                    "cacheRefs": []
                }
            }
        }))
        .unwrap();

        let targets =
            purge_targets_for_server(&server, "key", "https://media.example.com/vod/seg.ts")
                .unwrap();
        assert_eq!(
            targets,
            vec![
                PurgeTarget::Key("http://vod-cache.example.com/vod/seg.ts".to_string()),
                PurgeTarget::Key("https://vod-cache.example.com/vod/seg.ts".to_string()),
            ]
        );
    }

    #[test]
    fn scoped_server_host_validation_accepts_wildcard_and_cache_key_host() {
        let server = server_with_cache_key();
        assert!(server_accepts_purge_host(&server, "a.example.com"));
        assert!(server_accepts_purge_host(&server, "example.com"));
        assert!(server_accepts_purge_host(&server, "cache.example.com"));
        assert!(!server_accepts_purge_host(&server, "other.test"));
    }

    #[test]
    fn preheat_uses_routable_host_when_task_key_is_cache_main_domain() {
        let server = server_with_cache_key();
        let raw = reqwest::Url::parse("https://cache.example.com/live/seg.ts?token=1").unwrap();
        let fetch = preheat_fetch_url_for_server(&server, &raw).unwrap();

        assert_eq!(fetch.as_str(), "https://example.com/live/seg.ts?token=1");
    }

    #[test]
    fn preheat_keeps_cache_main_domain_when_it_is_an_exact_site_name() {
        let server: ServerConfig = serde_json::from_value(json!({
            "id": 9,
            "serverNames": [
                {"name": "*.example.com"},
                {"name": "cache.example.com"}
            ],
            "web": {
                "cache": {
                    "isOn": true,
                    "key": {
                        "isOn": true,
                        "scheme": "https",
                        "host": "cache.example.com"
                    },
                    "cacheRefs": []
                }
            }
        }))
        .unwrap();
        let raw = reqwest::Url::parse("https://cache.example.com/live/seg.ts?token=1").unwrap();
        let fetch = preheat_fetch_url_for_server(&server, &raw).unwrap();

        assert_eq!(
            fetch.as_str(),
            "https://cache.example.com/live/seg.ts?token=1"
        );
    }

    #[test]
    fn preheat_task_type_accepts_fetch_for_edge_compatibility() {
        assert!(is_preheat_task_type("preheat"));
        assert!(is_preheat_task_type("fetch"));
        assert!(is_preheat_task_type("FETCH"));
        assert!(!is_preheat_task_type("purge"));
    }
}
