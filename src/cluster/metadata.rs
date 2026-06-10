use serde::{Deserialize, Serialize};
use std::sync::OnceLock as OnceCell;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, warn};

const METADATA_EVENT_QUEUE_CAPACITY: usize = 65_536;

static METADATA_EVENT_TX: OnceCell<mpsc::Sender<CacheMetaEvent>> = OnceCell::new();

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheMetaEvent {
    pub event_id: String,
    pub event_type: CacheMetaEventType,
    pub pod_name: String,
    pub hash: String,
    pub cache_key: String,
    pub shard_id: Option<String>,
    pub relative_path: Option<String>,
    pub size: u64,
    pub expires: i64,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub compressed: bool,
    pub created_at: i64,
    pub version: u64,
    // SWR window propagated to other pods in cluster mode so they can keep
    // serving stale while the new leader-side revalidation happens.
    // Older event payloads (without this field) default to 0 via serde(default).
    #[serde(default)]
    pub stale_while_revalidate_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheMetaEventType {
    Upsert,
    Delete,
    Purge,
}

pub struct CacheMetaUpsertEvent<'a> {
    pub hash: &'a str,
    pub cache_key: &'a str,
    pub shard_id: Option<&'a str>,
    pub relative_path: Option<&'a str>,
    pub size: u64,
    pub expires: i64,
    pub status: u16,
    pub headers: &'a [(String, String)],
    pub compressed: bool,
    pub stale_while_revalidate_secs: u64,
}

pub fn emit_upsert(event: CacheMetaUpsertEvent<'_>) {
    if !crate::runtime_mode::RuntimeConfig::current_is_rke2() {
        return;
    }

    let now = crate::utils::time::now_timestamp();
    let version = crate::utils::time::now_timestamp_millis() as u64;
    let pod_name = crate::runtime_mode::RuntimeConfig::current()
        .and_then(|config| std::env::var(&config.cluster.pod_name_env).ok())
        .unwrap_or_default();
    let event = CacheMetaEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        event_type: CacheMetaEventType::Upsert,
        pod_name,
        hash: event.hash.to_string(),
        cache_key: event.cache_key.to_string(),
        shard_id: event.shard_id.map(str::to_string),
        relative_path: event.relative_path.map(str::to_string),
        size: event.size,
        expires: event.expires,
        status: event.status,
        headers: event.headers.to_vec(),
        compressed: event.compressed,
        created_at: now,
        version,
        stale_while_revalidate_secs: event.stale_while_revalidate_secs,
    };

    let Some(tx) = METADATA_EVENT_TX.get() else {
        return;
    };
    if let Err(err) = tx.try_send(event) {
        warn!("CLUSTER_METADATA: dropping cache metadata event: {}", err);
    }
}

pub fn apply_remote_event(event: CacheMetaEvent) {
    match event.event_type {
        CacheMetaEventType::Upsert => {
            if let Some(existing) = crate::metrics::storage::STORAGE.get_cache_meta(&event.hash)
                && existing.event_version.unwrap_or(0) > event.version
            {
                return;
            }
            crate::metrics::storage::STORAGE.upsert_cache_meta_absolute(
                crate::metrics::storage::CacheMetaUpsert {
                    hash: &event.hash,
                    cache_key: &event.cache_key,
                    size: event.size,
                    expires: event.expires,
                    access_time: event.created_at,
                    access_count: 0,
                    status: event.status,
                    headers: &event.headers,
                    compressed: event.compressed,
                    shard_id: event.shard_id.as_deref(),
                    relative_path: event.relative_path.as_deref(),
                    event_version: Some(event.version),
                    updated_at: Some(event.created_at),
                    stale_while_revalidate_secs: event.stale_while_revalidate_secs,
                    created_at: event.created_at,
                },
            );
        }
        CacheMetaEventType::Delete | CacheMetaEventType::Purge => {
            crate::metrics::storage::STORAGE.delete_cache_meta(&event.hash);
        }
    }
}

pub fn start_event_worker() {
    let (tx, mut rx) = mpsc::channel(METADATA_EVENT_QUEUE_CAPACITY);
    if METADATA_EVENT_TX.set(tx).is_err() {
        return;
    }

    tokio::spawn(async move {
        while let Some(first) = rx.recv().await {
            let mut batch = vec![first];
            while batch.len() < 256 {
                match rx.try_recv() {
                    Ok(event) => batch.push(event),
                    Err(_) => break,
                }
            }
            fanout_batch(batch).await;
        }
    });
}

async fn fanout_batch(events: Vec<CacheMetaEvent>) {
    if events.is_empty() {
        return;
    }
    let Some(config) = crate::runtime_mode::RuntimeConfig::current() else {
        return;
    };
    if !config.is_rke2() {
        return;
    }
    let Ok(token) = std::env::var(&config.cluster.internal_api.token_env) else {
        warn!("CLUSTER_METADATA: internal token is unavailable; dropping metadata fanout batch");
        return;
    };
    let peers = crate::cluster::peers::discover_peer_urls();
    if peers.is_empty() {
        debug!(
            "CLUSTER_METADATA: no peers discovered for {} events",
            events.len()
        );
        return;
    }

    let body = match serde_json::to_vec(&events) {
        Ok(body) => body,
        Err(err) => {
            warn!(
                "CLUSTER_METADATA: failed to serialize metadata events: {}",
                err
            );
            return;
        }
    };
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            warn!("CLUSTER_METADATA: failed to create HTTP client: {}", err);
            return;
        }
    };

    for peer in peers {
        let url = format!("{}/internal/v1/metadata/events", peer);
        match client
            .post(&url)
            .bearer_auth(token.trim())
            .header("content-type", "application/json")
            .header("x-cloud-node-cluster", &config.cluster.name)
            .body(body.clone())
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => warn!("CLUSTER_METADATA: peer {} returned {}", url, resp.status()),
            Err(err) => warn!("CLUSTER_METADATA: peer {} failed: {}", url, err),
        }
    }
}
