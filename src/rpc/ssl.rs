use crate::api_config::ApiConfig;
use crate::pb;
use crate::rpc::client::SharedRpcClient;
use crate::rpc::logs::report_node_log_with_context;
use crate::ssl::DynamicCertSelector;
use std::sync::Arc;
use tracing::{info, warn};

const OCSP_PAGE_SIZE: i32 = 100;

pub async fn start_ocsp_syncer(api_config: ApiConfig, cert_selector: Arc<DynamicCertSelector>) {
    let mut version: i64 = 0;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    info!("Starting OCSP syncer...");

    loop {
        interval.tick().await;

        let client = match SharedRpcClient::get(&api_config).await {
            Ok(shared) => shared.as_rpc_client(),
            Err(e) => {
                warn!("Failed to connect for OCSP sync: {}", e);
                report_node_log_with_context(
                    &api_config,
                    "warn",
                    "SSL",
                    &format!("failed to connect for OCSP sync: {}", e),
                    None,
                    Some("ocspSyncConnectFailed"),
                    None,
                )
                .await;
                continue;
            }
        };

        let mut ssl_client = client.ssl_cert_service();
        let mut page_version = version;

        loop {
            match ssl_client
                .list_updated_ssl_cert_ocsp(pb::ListUpdatedSslCertOcspRequest {
                    version: page_version,
                    size: OCSP_PAGE_SIZE,
                })
                .await
            {
                Ok(resp) => {
                    let inner = resp.into_inner();
                    let batch = inner.ssl_cert_ocsp;
                    if batch.is_empty() {
                        break;
                    }

                    for ocsp in &batch {
                        cert_selector
                            .update_ocsp(ocsp.ssl_cert_id, ocsp.data.clone())
                            .await;
                        if ocsp.version > version {
                            version = ocsp.version;
                        }
                        if ocsp.version > page_version {
                            page_version = ocsp.version;
                        }
                    }

                    if batch.len() < OCSP_PAGE_SIZE as usize {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Failed to list updated OCSP: {}", e);
                    report_node_log_with_context(
                        &api_config,
                        "warn",
                        "SSL",
                        &format!("failed to list updated OCSP: {}", e),
                        None,
                        Some("ocspListFailed"),
                        None,
                    )
                    .await;
                    break;
                }
            }
        }
    }
}
