use crate::api_config::ApiConfig;
use crate::auth::generate_token;
use crate::pb;
use crate::rpc::client::RPC_MAX_MESSAGE_BYTES;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tonic::Code;
use tonic::codec::CompressionEncoding;
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
    retry_buffer: VecDeque<pb::HttpAccessLog>,
    max_retry_logs: usize,
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
            retry_buffer: VecDeque::new(),
            max_retry_logs: batch_size.saturating_mul(10).max(batch_size),
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
                    if buffer.len() + self.retry_buffer.len() >= self.batch_size {
                        self.flush_batch(&mut buffer).await;
                        last_flush = Instant::now();
                    }
                }
                _ = timeout => {
                    if !buffer.is_empty() || !self.retry_buffer.is_empty() {
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

    fn take_logs_to_send(&mut self, buffer: &mut Vec<pb::HttpAccessLog>) -> Vec<pb::HttpAccessLog> {
        let mut logs = Vec::with_capacity(self.batch_size);
        while logs.len() < self.batch_size {
            let Some(log) = self.retry_buffer.pop_front() else {
                break;
            };
            logs.push(log);
        }

        let remaining = self.batch_size.saturating_sub(logs.len());
        let take_from_buffer = remaining.min(buffer.len());
        logs.extend(buffer.drain(..take_from_buffer));
        logs
    }

    fn requeue_failed_logs(&mut self, mut logs: Vec<pb::HttpAccessLog>) {
        let available = self.max_retry_logs.saturating_sub(self.retry_buffer.len());
        if logs.len() > available {
            let drop_count = logs.len() - available;
            logs.drain(..drop_count);
            tracing::warn!(
                "ACCESS_LOG: retry buffer full, dropped {} oldest failed access logs",
                drop_count
            );
        }

        for log in logs.into_iter().rev() {
            self.retry_buffer.push_front(log);
        }
    }

    #[allow(clippy::result_large_err)]
    async fn flush_batch(&mut self, buffer: &mut Vec<pb::HttpAccessLog>) {
        let mut logs_to_send = self.take_logs_to_send(buffer);
        let count = logs_to_send.len();
        if count == 0 {
            return;
        }
        info!("Flushing batch of {} access logs to Master", count);

        let Some(channel) = self.get_or_connect_channel().await.cloned() else {
            self.requeue_failed_logs(logs_to_send);
            return;
        };

        let node_id = self.api_config.node_id.clone();
        let secret = self.api_config.secret.clone();

        let mut client =
            pb::http_access_log_service_client::HttpAccessLogServiceClient::with_interceptor(
                channel,
                move |mut req: tonic::Request<()>| {
                    let token = generate_token(&node_id, &secret, "node").unwrap_or_default();
                    let val = node_id
                        .parse()
                        .unwrap_or(tonic::metadata::MetadataValue::from_static("0"));
                    req.metadata_mut().insert("nodeid", val.clone());
                    if let Ok(key) = tonic::metadata::MetadataKey::from_bytes(b"nodeId") {
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
            )
            .send_compressed(CompressionEncoding::Gzip)
            .accept_compressed(CompressionEncoding::Gzip)
            .max_decoding_message_size(RPC_MAX_MESSAGE_BYTES)
            .max_encoding_message_size(RPC_MAX_MESSAGE_BYTES);

        let req = pb::CreateHttpAccessLogsRequest {
            http_access_logs: logs_to_send.clone(),
        };

        match client.create_http_access_logs(req).await {
            Ok(_) => {
                info!("Successfully uploaded {} access logs", count);
            }
            Err(e) => {
                if e.code() == Code::ResourceExhausted {
                    for log in &mut logs_to_send {
                        log.request_body.clear();
                    }
                    let retry_req = pb::CreateHttpAccessLogsRequest {
                        http_access_logs: logs_to_send.clone(),
                    };
                    match client.create_http_access_logs(retry_req).await {
                        Ok(_) => {
                            info!(
                                "Successfully uploaded {} access logs after stripping request bodies",
                                count
                            );
                            return;
                        }
                        Err(retry_err) => {
                            error!(
                                "Failed to upload access logs after ResourceExhausted retry: {}",
                                retry_err
                            );
                        }
                    }
                }
                error!("Failed to upload access logs: {}", e);
                self.requeue_failed_logs(logs_to_send);
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
                let token = generate_token(&node_id, &secret, "node").unwrap_or_default();
                let val = node_id
                    .parse()
                    .unwrap_or(tonic::metadata::MetadataValue::from_static("0"));
                req.metadata_mut().insert("nodeid", val.clone());
                if let Ok(key) = tonic::metadata::MetadataKey::from_bytes(b"nodeId") {
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
        )
        .send_compressed(CompressionEncoding::Gzip)
        .accept_compressed(CompressionEncoding::Gzip)
        .max_decoding_message_size(RPC_MAX_MESSAGE_BYTES)
        .max_encoding_message_size(RPC_MAX_MESSAGE_BYTES);

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
