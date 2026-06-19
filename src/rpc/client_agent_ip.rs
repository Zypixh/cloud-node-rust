use crate::api_config::ApiConfig;
use crate::client_agent::{self, ClientAgentIpRecord};
use crate::pb;
use crate::rpc::client::SharedRpcClient;
use std::sync::Arc;
use tokio::time::{Duration, timeout};
use tracing::debug;

const CLIENT_AGENT_SYNC_INTERVAL: Duration = Duration::from_secs(60);
const CLIENT_AGENT_SYNC_BATCH_SIZE: i64 = 5_000;
const CLIENT_AGENT_SYNC_MAX_PAGES_PER_TICK: usize = 5;
const CLIENT_AGENT_SYNC_RPC_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn start_client_agent_ip_syncer(api_config: Arc<ApiConfig>) {
    let mut interval = tokio::time::interval(CLIENT_AGENT_SYNC_INTERVAL);
    loop {
        interval.tick().await;
        sync_client_agent_ips_incremental(&api_config).await;
    }
}

pub async fn sync_client_agent_ips_incremental(api_config: &Arc<ApiConfig>) -> bool {
    let client = match timeout(
        CLIENT_AGENT_SYNC_RPC_TIMEOUT,
        SharedRpcClient::get(api_config),
    )
    .await
    {
        Ok(Ok(shared)) => shared.as_rpc_client(),
        Ok(Err(err)) => {
            debug!("Failed to connect for client agent IP sync: {}", err);
            return false;
        }
        Err(_) => {
            debug!("Timed out connecting for client agent IP sync");
            return false;
        }
    };

    let mut service = client.client_agent_ip_service();
    for _ in 0..CLIENT_AGENT_SYNC_MAX_PAGES_PER_TICK {
        let cursor = client_agent::last_sync_id();
        let response =
            service.list_client_agent_i_ps_after_id(pb::ListClientAgentIPsAfterIdRequest {
                id: cursor,
                size: CLIENT_AGENT_SYNC_BATCH_SIZE,
            });
        let response = match timeout(CLIENT_AGENT_SYNC_RPC_TIMEOUT, response).await {
            Ok(Ok(response)) => response.into_inner(),
            Ok(Err(err)) => {
                debug!("Failed to sync client agent IPs: {}", err);
                return false;
            }
            Err(_) => {
                debug!("Timed out syncing client agent IPs");
                return false;
            }
        };

        let fetched = response.client_agent_i_ps.len();
        let mut records = Vec::new();
        let mut max_id = cursor;
        for item in response.client_agent_i_ps {
            max_id = max_id.max(item.id);
            if let Some(record) = record_from_pb(item) {
                records.push(record);
            }
        }

        if max_id <= cursor {
            return true;
        }

        if !crate::metrics::storage::STORAGE.save_client_agent_ip_batch(&records, max_id) {
            debug!("Failed to persist client agent IP sync batch");
            return false;
        }
        client_agent::apply_synced_client_agent_ip_records(&records, max_id);

        if fetched < CLIENT_AGENT_SYNC_BATCH_SIZE as usize {
            return true;
        }
    }
    true
}

fn record_from_pb(item: pb::ClientAgentIp) -> Option<ClientAgentIpRecord> {
    item.ip.parse::<std::net::IpAddr>().ok()?;
    let agent_code = item.client_agent?.code;
    if !client_agent::is_known_agent_code(&agent_code) {
        return None;
    }
    Some(ClientAgentIpRecord {
        id: item.id,
        ip: item.ip,
        ptr: item.ptr,
        agent_code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_valid_record() {
        let record = record_from_pb(pb::ClientAgentIp {
            id: 7,
            ip: "66.249.66.1".to_string(),
            ptr: "crawl-1.googlebot.com.".to_string(),
            client_agent: Some(pb::ClientAgent {
                code: "google".to_string(),
                ..Default::default()
            }),
        })
        .unwrap();
        assert_eq!(record.id, 7);
        assert_eq!(record.agent_code, "google");
    }

    #[test]
    fn rejects_invalid_record() {
        assert!(
            record_from_pb(pb::ClientAgentIp {
                id: 7,
                ip: "not-ip".to_string(),
                ptr: String::new(),
                client_agent: Some(pb::ClientAgent {
                    code: "google".to_string(),
                    ..Default::default()
                }),
            })
            .is_none()
        );
        assert!(
            record_from_pb(pb::ClientAgentIp {
                id: 7,
                ip: "66.249.66.1".to_string(),
                ptr: String::new(),
                client_agent: Some(pb::ClientAgent {
                    code: "unknown".to_string(),
                    ..Default::default()
                }),
            })
            .is_none()
        );
    }
}
