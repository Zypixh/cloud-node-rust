use crate::api_config::ApiConfig;
use crate::auth::generate_token;
use crate::pb;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tonic::transport::Channel;
use tracing::{error, info};

/// A high-performance uploader for access logs.
/// Batches logs and sends them asynchronously to the Master node.
pub struct LogUploader {
    rx: mpsc::Receiver<pb::HttpAccessLog>,
    api_config: ApiConfig,
    batch_size: usize,
    flush_interval: Duration,
    channel: Option<Channel>,
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
            channel: None,
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
                    }
                    last_flush = Instant::now();
                }
            }
        }
    }

    async fn get_or_connect_channel(&mut self) -> Option<&Channel> {
        if self.channel.is_some() {
            return self.channel.as_ref();
        }

        let api_endpoint = self
            .api_config
            .effective_rpc_endpoints()
            .first()
            .cloned()
            .unwrap_or_default();

        let endpoint = match tonic::transport::Endpoint::from_shared(api_endpoint) {
            Ok(ep) => ep
                .keep_alive_timeout(Duration::from_secs(10))
                .tcp_keepalive(Some(Duration::from_secs(30))),
            Err(err) => {
                error!("Failed to create gRPC channel for LogUploader: {}", err);
                return None;
            }
        };

        match endpoint.connect().await {
            Ok(channel) => {
                self.channel = Some(channel);
                self.channel.as_ref()
            }
            Err(err) => {
                error!("Failed to connect to Master gRPC for LogUploader: {}", err);
                None
            }
        }
    }

    #[allow(clippy::result_large_err)]
    async fn flush_batch(&mut self, buffer: &mut Vec<pb::HttpAccessLog>) {
        let count = buffer.len();
        info!("Flushing batch of {} access logs to Master", count);

        let logs_to_send = std::mem::replace(buffer, Vec::with_capacity(self.batch_size));

        let Some(channel) = self.get_or_connect_channel().await.cloned() else {
            return;
        };

        let node_id = self.api_config.node_id.clone();
        let secret = self.api_config.secret.clone();

        let mut client =
            pb::http_access_log_service_client::HttpAccessLogServiceClient::with_interceptor(
                channel,
                move |mut req: tonic::Request<()>| {
                    let token = generate_token(&node_id, &secret, "edge").unwrap_or_default();
                    let val = node_id
                        .parse()
                        .unwrap_or(tonic::metadata::MetadataValue::from_static("0"));
                    req.metadata_mut().insert("nodeid", val.clone());
                    req.metadata_mut().insert(
                        "type",
                        tonic::metadata::MetadataValue::from_static("edge"),
                    );
                    if let Ok(key) =
                        tonic::metadata::MetadataKey::from_bytes(b"nodeId")
                    {
                        req.metadata_mut().insert(key, val);
                    }
                    req.metadata_mut().insert(
                        "token",
                        token
                            .parse()
                            .unwrap_or(tonic::metadata::MetadataValue::from_static("")),
                    );
                    Ok(req)
                },
            );

        let req = pb::CreateHttpAccessLogsRequest {
            http_access_logs: logs_to_send,
        };

        match client.create_http_access_logs(req).await {
            Ok(_) => {
                info!("Successfully uploaded {} access logs", count);
            }
            Err(e) => {
                error!("Failed to upload access logs: {}", e);
                self.channel = None;
            }
        }
    }
}

pub struct NodeLogUploader {
    rx: mpsc::Receiver<pb::NodeLog>,
    api_config: ApiConfig,
    batch_size: usize,
    flush_interval: Duration,
    channel: Option<Channel>,
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
            channel: None,
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
                    }
                    last_flush = Instant::now();
                }
            }
        }
    }

    async fn get_or_connect_channel(&mut self) -> Option<&Channel> {
        if self.channel.is_some() {
            return self.channel.as_ref();
        }

        let api_endpoint = self
            .api_config
            .effective_rpc_endpoints()
            .first()
            .cloned()
            .unwrap_or_default();

        let endpoint = match tonic::transport::Endpoint::from_shared(api_endpoint) {
            Ok(ep) => ep
                .keep_alive_timeout(Duration::from_secs(10))
                .tcp_keepalive(Some(Duration::from_secs(30))),
            Err(err) => {
                error!("Invalid API endpoint for NodeLogUploader: {}", err);
                return None;
            }
        };

        match endpoint.connect().await {
            Ok(channel) => {
                self.channel = Some(channel);
                self.channel.as_ref()
            }
            Err(err) => {
                error!("Failed to connect for NodeLogUploader: {}", err);
                None
            }
        }
    }

    #[allow(clippy::result_large_err)]
    async fn flush_batch(&mut self, buffer: &mut Vec<pb::NodeLog>) {
        let count = buffer.len();
        let logs_to_send = std::mem::replace(buffer, Vec::with_capacity(self.batch_size));

        let Some(channel) = self.get_or_connect_channel().await.cloned() else {
            return;
        };

        let node_id = self.api_config.node_id.clone();
        let secret = self.api_config.secret.clone();

        let mut client = pb::node_log_service_client::NodeLogServiceClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                let token = generate_token(&node_id, &secret, "edge").unwrap_or_default();
                let val = node_id
                    .parse()
                    .unwrap_or(tonic::metadata::MetadataValue::from_static("0"));
                req.metadata_mut().insert("nodeid", val.clone());
                req.metadata_mut().insert(
                    "type",
                    tonic::metadata::MetadataValue::from_static("edge"),
                );
                if let Ok(key) =
                    tonic::metadata::MetadataKey::from_bytes(b"nodeId")
                {
                    req.metadata_mut().insert(key, val);
                }
                req.metadata_mut().insert(
                    "token",
                    token
                        .parse()
                        .unwrap_or(tonic::metadata::MetadataValue::from_static("")),
                );
                Ok(req)
            },
        );

        match client
            .create_node_logs(pb::CreateNodeLogsRequest {
                node_logs: logs_to_send,
            })
            .await
        {
            Ok(_) => info!("Successfully uploaded {} node logs", count),
            Err(e) => {
                error!("Failed to upload node logs: {}", e);
                self.channel = None;
            }
        }
    }
}
