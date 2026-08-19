use crate::api_config::ApiConfig;
use crate::pb;
use crate::rpc::client::RpcClient;
use crate::rpc::logs::report_node_log_with_context;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

pub async fn start_ip_library_syncer(api_config: ApiConfig) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Check every hour

    info!("Starting IP library syncer...");

    loop {
        interval.tick().await;

        let client = match crate::rpc::client::SharedRpcClient::get(&api_config).await {
            Ok(s) => s.as_rpc_client(),
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
                    let installed = crate::utils::persistence::load_state();
                    let installed_matches = file_id > 0
                        && file_id == installed.geoip_city_file_id
                        && target_path_matches_marker(
                            &crate::paths::NodePaths::current().geoip_city_file(),
                            &installed,
                        )
                        .await;
                    if file_id > 0 && !installed_matches {
                        let node_paths = crate::paths::NodePaths::current();
                        let target_path = node_paths.geoip_city_file();

                        info!(
                            "New IP library version found (FileId: {}). Starting download...",
                            file_id
                        );
                        match download_file(&client, &artifact_item, &target_path).await {
                            Ok(installed_artifact) => {
                                let mut state = crate::utils::persistence::load_state();
                                state.geoip_city_file_id = file_id;
                                state.geoip_city_file_size = installed_artifact.size;
                                state.geoip_city_sha256 = installed_artifact.sha256;
                                match crate::utils::persistence::save_state(&state) {
                                    Ok(()) => info!(
                                        "IP library updated successfully to FileId: {}.",
                                        file_id
                                    ),
                                    Err(err) => warn!(
                                        "IP library FileId {} installed but marker persistence failed: {}",
                                        file_id, err
                                    ),
                                }
                            }
                            Err(e) => {
                                warn!("Failed to download IP library (FileId: {}): {}", file_id, e);
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

struct InstalledArtifact {
    size: u64,
    sha256: String,
}

async fn download_file(
    client: &RpcClient,
    artifact: &pb::IpLibraryArtifact,
    target_path: &Path,
) -> anyhow::Result<InstalledArtifact> {
    let file_id = artifact.file_id;
    anyhow::ensure!(file_id > 0, "invalid IP library file ID");
    let expected_size = artifact
        .file
        .as_ref()
        .map(|file| file.size)
        .filter(|size| *size > 0)
        .ok_or_else(|| anyhow::anyhow!("IP library artifact has no valid size"))? as u64;
    let max_bytes = crate::memory_governor::MEMORY_GOVERNOR
        .snapshot(crate::memory_governor::MEMORY_GOVERNOR.pingora_worker_threads())
        .cardinality_state_budget_bytes
        .min(512 * 1024 * 1024)
        .max(16 * 1024 * 1024);
    anyhow::ensure!(
        expected_size <= max_bytes,
        "IP library size {} exceeds node budget {}",
        expected_size,
        max_bytes
    );

    let mut chunk_client = client.file_chunk_service();
    let resp = chunk_client
        .find_all_file_chunk_ids(pb::FindAllFileChunkIdsRequest {
            file_id,
            access_ticket: String::new(),
        })
        .await?;
    let chunk_ids = resp.into_inner().file_chunk_ids;
    anyhow::ensure!(!chunk_ids.is_empty(), "IP library has no chunks");
    anyhow::ensure!(
        chunk_ids.len() as u64 <= expected_size,
        "IP library chunk count exceeds expected file size"
    );
    let mut seen = HashSet::with_capacity(chunk_ids.len());
    anyhow::ensure!(
        chunk_ids.iter().all(|id| *id > 0 && seen.insert(*id)),
        "IP library contains invalid or duplicate chunk IDs"
    );

    if let Some(parent) = target_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp_path = target_path.with_extension(format!("mmdb.{file_id}.tmp"));
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = match options.open(&tmp_path).await {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            tokio::fs::remove_file(&tmp_path).await?;
            options.open(&tmp_path).await?
        }
        Err(err) => return Err(err.into()),
    };

    let result = async {
        let mut written = 0u64;
        let mut digest = Sha256::new();
        for chunk_id in chunk_ids {
            let chunk = chunk_client
                .download_file_chunk(pb::DownloadFileChunkRequest {
                    file_chunk_id: chunk_id,
                    access_ticket: String::new(),
                })
                .await?
                .into_inner()
                .file_chunk
                .ok_or_else(|| anyhow::anyhow!("IP library chunk {chunk_id} is missing"))?;
            written = written
                .checked_add(chunk.data.len() as u64)
                .ok_or_else(|| anyhow::anyhow!("IP library size overflow"))?;
            anyhow::ensure!(
                written <= expected_size && written <= max_bytes,
                "IP library download exceeds advertised or allowed size"
            );
            digest.update(&chunk.data);
            file.write_all(&chunk.data).await?;
        }
        anyhow::ensure!(
            written == expected_size,
            "IP library size mismatch: expected {}, downloaded {}",
            expected_size,
            written
        );
        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        validate_city_database(&tmp_path)?;
        install_city_database(&tmp_path, target_path).await?;
        Ok::<InstalledArtifact, anyhow::Error>(InstalledArtifact {
            size: written,
            sha256: hex::encode(digest.finalize()),
        })
    }
    .await;

    if result.is_err() {
        let _ = tokio::fs::remove_file(&tmp_path).await;
    }
    result
}

async fn install_city_database(tmp_path: &Path, target_path: &Path) -> anyhow::Result<()> {
    let backup_path = sibling_backup_path(target_path);
    let had_previous = tokio::fs::metadata(target_path).await.is_ok();
    if had_previous {
        let _ = tokio::fs::remove_file(&backup_path).await;
        tokio::fs::rename(target_path, &backup_path).await?;
    }

    if let Err(err) = tokio::fs::rename(tmp_path, target_path).await {
        if had_previous {
            let _ = tokio::fs::rename(&backup_path, target_path).await;
        }
        return Err(err.into());
    }
    if let Err(err) = crate::utils::persistence::sync_parent(target_path) {
        return rollback_city_database(target_path, &backup_path, had_previous, err.into()).await;
    }
    if let Err(err) = crate::metrics::analyzer::reload_city_reader(target_path) {
        return rollback_city_database(target_path, &backup_path, had_previous, err).await;
    }
    if had_previous {
        tokio::fs::remove_file(&backup_path).await?;
        crate::utils::persistence::sync_parent(target_path)?;
    }
    Ok(())
}

async fn rollback_city_database(
    target_path: &Path,
    backup_path: &Path,
    had_previous: bool,
    cause: anyhow::Error,
) -> anyhow::Result<()> {
    let _ = tokio::fs::remove_file(target_path).await;
    if had_previous {
        tokio::fs::rename(backup_path, target_path).await?;
        crate::utils::persistence::sync_parent(target_path)?;
        crate::metrics::analyzer::reload_city_reader(target_path)?;
    }
    Err(cause)
}

async fn target_path_matches_marker(
    target_path: &Path,
    state: &crate::utils::persistence::PersistentState,
) -> bool {
    if state.geoip_city_file_size == 0 || state.geoip_city_sha256.is_empty() {
        return false;
    }
    let Ok(mut file) = tokio::fs::File::open(target_path).await else {
        return false;
    };
    let Ok(metadata) = file.metadata().await else {
        return false;
    };
    if metadata.len() != state.geoip_city_file_size {
        return false;
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = match file.read(&mut buffer).await {
            Ok(read) => read,
            Err(_) => return false,
        };
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    hex::encode(digest.finalize()) == state.geoip_city_sha256
}

fn sibling_backup_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(std::ffi::OsString::from)
        .unwrap_or_else(|| std::ffi::OsString::from("GeoLite2-City.mmdb"));
    name.push(".previous");
    path.with_file_name(name)
}

fn validate_city_database(path: &Path) -> anyhow::Result<()> {
    let reader = maxminddb::Reader::open_readfile(path)?;
    reader.verify()?;
    anyhow::ensure!(
        reader
            .metadata()
            .database_type
            .to_ascii_lowercase()
            .contains("city"),
        "IP library is not a City MaxMind database: {}",
        reader.metadata().database_type
    );
    Ok(())
}
