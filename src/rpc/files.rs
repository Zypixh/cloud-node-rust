use crate::api_config::ApiConfig;
use crate::pb;
use crate::rpc::client::RpcClient;
use crate::rpc::logs::report_node_log_with_context;
use std::fs;
use tracing::{error, info, warn};

pub async fn start_ip_library_syncer(api_config: ApiConfig) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Check every hour
    let mut last_file_id: i64 = 0;

    info!("Starting IP library syncer...");

    loop {
        interval.tick().await;

        let client = match RpcClient::new(&api_config).await {
            Ok(client) => client,
            Err(e) => {
                warn!("Failed to connect for IP library sync: {}", e);
                report_node_log_with_context(
                    &api_config,
                    "warn",
                    "IP_LIBRARY",
                    &format!("failed to connect for IP library sync: {}", e),
                    None,
                    Some("ipLibrarySyncConnectFailed"),
                    None,
                )
                .await;
                continue;
            }
        };

        let mut artifact_client = client.ip_library_artifact_service();
        match artifact_client
            .find_public_ip_library_artifact(pb::FindPublicIpLibraryArtifactRequest {})
            .await
        {
            Ok(resp) => {
                let artifact = resp.into_inner();
                if let Some(artifact_item) = artifact.ip_library_artifact {
                    let file_id = artifact_item.file_id;
                    if file_id > 0 && file_id != last_file_id {
                        let target_path = "GeoLite2-City.mmdb"; // Default target

                        info!(
                            "New IP library version found (FileId: {}). Starting download...",
                            file_id
                        );
                        match download_file(&client, file_id, target_path).await {
                            Ok(_) => {
                                info!("IP library updated successfully to FileId: {}.", file_id);
                                last_file_id = file_id;
                            }
                            Err(e) => {
                                error!(
                                    "Failed to download IP library (FileId: {}): {}",
                                    file_id, e
                                );
                                report_node_log_with_context(
                                    &api_config,
                                    "error",
                                    "IP_LIBRARY",
                                    &format!(
                                        "failed to download IP library file {}: {}",
                                        file_id, e
                                    ),
                                    None,
                                    Some("ipLibraryDownloadFailed"),
                                    Some(serde_json::json!({ "fileId": file_id })),
                                )
                                .await;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to check IP library artifact: {}", e);
                report_node_log_with_context(
                    &api_config,
                    "warn",
                    "IP_LIBRARY",
                    &format!("failed to check IP library artifact: {}", e),
                    None,
                    Some("ipLibraryArtifactCheckFailed"),
                    None,
                )
                .await;
            }
        }
    }
}

async fn download_file(client: &RpcClient, file_id: i64, target_path: &str) -> anyhow::Result<()> {
    let mut chunk_client = client.file_chunk_service();
    let resp = chunk_client
        .find_all_file_chunk_ids(pb::FindAllFileChunkIdsRequest {
            file_id,
            access_ticket: "".to_string(),
        })
        .await?;

    let chunk_ids = resp.into_inner().file_chunk_ids;
    let tmp_path = format!("{}.tmp", target_path);
    let mut file_content = Vec::new();

    for chunk_id in chunk_ids {
        let chunk_resp = chunk_client
            .download_file_chunk(pb::DownloadFileChunkRequest {
                file_chunk_id: chunk_id,
                access_ticket: "".to_string(),
            })
            .await?;
        if let Some(chunk) = chunk_resp.into_inner().file_chunk {
            file_content.extend(chunk.data);
        }
    }

    fs::write(&tmp_path, file_content)?;
    fs::rename(tmp_path, target_path)?;
    Ok(())
}
