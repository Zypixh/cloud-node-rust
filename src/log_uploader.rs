use crate::api_config::ApiConfig;
use crate::auth::generate_token;
use crate::pb;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tonic::transport::Channel;
use tracing::{debug, error, info};

/// A high-performance uploader for access logs.
/// Batches logs and sends them asynchronously to the Master node.
pub struct LogUploader {
    rx: mpsc::Receiver<pb::HttpAccessLog>,
    api_config: ApiConfig,
    batch_size: usize,
    flush_interval: Duration,
}

impl LogUploader {
    pub fn new(
        rx: mpsc::Receiver<pb::HttpAccessLog>,
        api_config: ApiConfig,
        batch_size: usize,
        flush_interval: Duration,
    ) -> Self {
        Self {
            rx,
            api_config,
            batch_size,
            flush_interval,
        }
    }

    pub async fn start(mut self) {
        info!(
            "Log Uploader service started. Batch size: {}, Interval: {:?}",
            self.batch_size, self.flush_interval
        );

        let mut buffer = Vec::with_capacity(self.batch_size);
        let mut last_flush = Instant::now();

        loop {
            let timeout = tokio::time::sleep_until((last_flush + self.flush_interval).into());

            tokio::select! {
                Some(log) = self.rx.recv() => {
                    buffer.push(log);
                    if buffer.len() >= self.batch_size {
                        self.flush_batch(&mut buffer).await;
                        last_flush = Instant::now();
                    }
                }
                _ = timeout => {
                    if !buffer.is_empty() {
                        self.flush_batch(&mut buffer).await;
                        last_flush = Instant::now();
                    }
                }
            }
        }
    }

    async fn connect_channel(&self) -> Option<Channel> {
        let api_endpoint = self
            .api_config
            .effective_rpc_endpoints()
            .first()
            .cloned()
            .unwrap_or_default();

        let channel = match Channel::from_shared(api_endpoint) {
            Ok(channel) => channel,
            Err(err) => {
                error!("Failed to create gRPC channel for LogUploader: {}", err);
                return None;
            }
        };

        match channel.connect().await {
            Ok(channel) => Some(channel),
            Err(err) => {
                error!("Failed to connect to Master gRPC for LogUploader: {}", err);
                None
            }
        }
    }

    #[allow(clippy::result_large_err)]
    async fn flush_batch(&self, buffer: &mut Vec<pb::HttpAccessLog>) {
        let count = buffer.len();
        debug!("Flushing batch of {} logs to Master", count);

        // Take the logs from buffer
        let logs_to_send = std::mem::replace(buffer, Vec::with_capacity(self.batch_size));

        let Some(channel) = self.connect_channel().await else {
            return;
        };

        // Create gRPC client with interceptor for auth
        let node_id = self.api_config.node_id.clone();
        let secret = self.api_config.secret.clone();

        // We recreate the client here because tonic clients are cheap to clone/recreate from channel
        let mut client =
            pb::http_access_log_service_client::HttpAccessLogServiceClient::with_interceptor(
                channel,
                move |mut req: tonic::Request<()>| {
                    let token = generate_token(&node_id, &secret, "edge").unwrap_or_default();
                    req.metadata_mut()
                        .insert("token", token.parse().unwrap());
                    req.metadata_mut()
                        .insert("nodeid", node_id.parse().unwrap());
                    Ok(req)
                },
            );

        let req = pb::CreateHttpAccessLogsRequest {
            http_access_logs: logs_to_send,
        };

        match client.create_http_access_logs(req).await {
            Ok(_) => {
                debug!("Successfully uploaded {} access logs", count);
            }
            Err(e) => {
                error!("Failed to upload access logs: {}", e);
                // Drop logs on error for now to avoid OOM or retry storm.
                // In production, we might want a small retry buffer.
            }
        }
    }
}

pub struct NodeLogUploader {
    rx: mpsc::Receiver<pb::NodeLog>,
    api_config: ApiConfig,
    batch_size: usize,
    flush_interval: Duration,
}

impl NodeLogUploader {
    pub fn new(
        rx: mpsc::Receiver<pb::NodeLog>,
        api_config: ApiConfig,
        batch_size: usize,
        flush_interval: Duration,
    ) -> Self {
        Self {
            rx,
            api_config,
            batch_size,
            flush_interval,
        }
    }

    pub async fn start(mut self) {
        info!("Node Log Uploader service started.");

        let mut buffer = Vec::with_capacity(self.batch_size);
        let mut last_flush = Instant::now();

        loop {
            let timeout = tokio::time::sleep_until((last_flush + self.flush_interval).into());

            tokio::select! {
                Some(log) = self.rx.recv() => {
                    buffer.push(log);
                    if buffer.len() >= self.batch_size {
                        self.flush_batch(&mut buffer).await;
                        last_flush = Instant::now();
                    }
                }
                _ = timeout => {
                    if !buffer.is_empty() {
                        self.flush_batch(&mut buffer).await;
                        last_flush = Instant::now();
                    }
                }
            }
        }
    }

    async fn connect_channel(&self) -> Option<Channel> {
        let api_endpoint = self
            .api_config
            .effective_rpc_endpoints()
            .first()
            .cloned()
            .unwrap_or_default();

        let channel = match Channel::from_shared(api_endpoint) {
            Ok(channel) => channel,
            Err(err) => {
                error!("Invalid API endpoint for NodeLogUploader: {}", err);
                return None;
            }
        };

        match channel.connect().await {
            Ok(channel) => Some(channel),
            Err(err) => {
                error!("Failed to connect for NodeLogUploader: {}", err);
                None
            }
        }
    }

    #[allow(clippy::result_large_err)]
    async fn flush_batch(&self, buffer: &mut Vec<pb::NodeLog>) {
        let count = buffer.len();
        let logs_to_send = std::mem::replace(buffer, Vec::with_capacity(self.batch_size));

        let Some(channel) = self.connect_channel().await else {
            return;
        };

        let node_id = self.api_config.node_id.clone();
        let secret = self.api_config.secret.clone();

        let mut client = pb::node_log_service_client::NodeLogServiceClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                let token = generate_token(&node_id, &secret, "edge").unwrap_or_default();
                req.metadata_mut().insert("token", token.parse().unwrap());
                req.metadata_mut()
                    .insert("nodeid", node_id.parse().unwrap());
                Ok(req)
            },
        );

        match client
            .create_node_logs(pb::CreateNodeLogsRequest {
                node_logs: logs_to_send,
            })
            .await
        {
            Ok(_) => debug!("Successfully uploaded {} node logs", count),
            Err(e) => error!("Failed to upload node logs: {}", e),
        }
    }
}
