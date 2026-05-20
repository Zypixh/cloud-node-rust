use serde::Serialize;
use tracing::warn;

#[derive(Clone, Debug, Serialize)]
pub struct PurgeFanoutRequest {
    pub purge_id: String,
    pub task_id: i64,
    pub key: String,
    pub key_type: String,
    pub prefix: String,
    pub leader_epoch: u64,
}

pub async fn fanout(request: PurgeFanoutRequest) -> anyhow::Result<()> {
    if !crate::runtime_mode::RuntimeConfig::current_is_rke2() {
        return Ok(());
    }

    let Some(config) = crate::runtime_mode::RuntimeConfig::current() else {
        return Ok(());
    };
    let token = std::env::var(&config.cluster.internal_api.token_env)?;
    let peers = crate::cluster::peers::discover_peer_urls();
    if peers.is_empty() {
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let body = serde_json::to_vec(&request)?;
    for peer in peers {
        let url = format!("{}/internal/v1/purge", peer);
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
            Ok(resp) => warn!("CLUSTER_PURGE: peer {} returned {}", url, resp.status()),
            Err(err) => warn!("CLUSTER_PURGE: peer {} failed: {}", url, err),
        }
    }

    Ok(())
}
