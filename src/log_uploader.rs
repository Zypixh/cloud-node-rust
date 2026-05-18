use crate::api_config::ApiConfig;
use crate::auth::generate_token;
use crate::pb;
use crate::rpc::client::RPC_MAX_MESSAGE_BYTES;
use prost::Message;
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

enum AccessLogUploadError {
    Retry(Vec<pb::HttpAccessLog>),
    Split {
        left: Vec<pb::HttpAccessLog>,
        right: Vec<pb::HttpAccessLog>,
    },
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
        let logs_to_send = self.take_logs_to_send(buffer);
        let count = logs_to_send.len();
        if count == 0 {
            return;
        }
        info!("Flushing batch of {} access logs to Master", count);

        let Some(channel) = self.get_or_connect_channel().await.cloned() else {
            self.requeue_failed_logs(logs_to_send);
            return;
        };

        let mut chunks: VecDeque<Vec<pb::HttpAccessLog>> =
            Self::split_logs_by_encoded_size(logs_to_send).into();
        while let Some(chunk) = chunks.pop_front() {
            match self.upload_access_log_chunk(&channel, chunk).await {
                Ok(()) => {}
                Err(AccessLogUploadError::Split { left, right }) => {
                    chunks.push_front(right);
                    chunks.push_front(left);
                }
                Err(AccessLogUploadError::Retry(logs)) => {
                    let logs_to_requeue = Self::collect_logs_to_requeue(logs, chunks);
                    self.requeue_failed_logs(logs_to_requeue);
                    self.channel = None;
                    break;
                }
            }
        }
    }

    fn collect_logs_to_requeue(
        failed_logs: Vec<pb::HttpAccessLog>,
        remaining_chunks: VecDeque<Vec<pb::HttpAccessLog>>,
    ) -> Vec<pb::HttpAccessLog> {
        let total = failed_logs.len() + remaining_chunks.iter().map(Vec::len).sum::<usize>();
        let mut logs = Vec::with_capacity(total);
        logs.extend(failed_logs);
        for chunk in remaining_chunks {
            logs.extend(chunk);
        }
        logs
    }

    fn access_log_request_size(logs: &[pb::HttpAccessLog]) -> usize {
        pb::CreateHttpAccessLogsRequest {
            http_access_logs: logs.to_vec(),
        }
        .encoded_len()
    }

    fn split_logs_by_encoded_size(logs: Vec<pb::HttpAccessLog>) -> Vec<Vec<pb::HttpAccessLog>> {
        let max_size = RPC_MAX_MESSAGE_BYTES.saturating_mul(3) / 4;
        let mut chunks = Vec::new();
        let mut current = Vec::new();
        let mut current_size: usize = 0;

        for log in logs {
            let log_size = log.encoded_len().saturating_add(8);
            if !current.is_empty() && current_size.saturating_add(log_size) > max_size {
                chunks.push(current);
                current = Vec::new();
                current_size = 0;
            }
            current_size = current_size.saturating_add(log_size);
            current.push(log);
        }

        if !current.is_empty() {
            chunks.push(current);
        }
        chunks
    }

    fn shrink_access_logs(logs: &mut [pb::HttpAccessLog]) -> bool {
        let mut changed = false;
        for log in logs {
            if !log.request_body.is_empty() {
                log.request_body.clear();
                changed = true;
            }
            if !log.header.is_empty() {
                log.header.clear();
                changed = true;
            }
            if !log.sent_header.is_empty() {
                log.sent_header.clear();
                changed = true;
            }
            if !log.cookie.is_empty() {
                log.cookie.clear();
                changed = true;
            }
            if !log.attrs.is_empty() {
                log.attrs.clear();
                changed = true;
            }
        }
        changed
    }

    async fn send_access_log_chunk(
        &self,
        channel: &Channel,
        logs: &[pb::HttpAccessLog],
    ) -> std::result::Result<(), tonic::Status> {
        let req = pb::CreateHttpAccessLogsRequest {
            http_access_logs: logs.to_vec(),
        };
        let mut client = self.http_access_log_client(channel.clone());
        client.create_http_access_logs(req).await.map(|_| ())
    }

    async fn upload_access_log_chunk(
        &self,
        channel: &Channel,
        mut logs: Vec<pb::HttpAccessLog>,
    ) -> std::result::Result<(), AccessLogUploadError> {
        let count = logs.len();
        let encoded_size = Self::access_log_request_size(&logs);
        match self.send_access_log_chunk(channel, &logs).await {
            Ok(_) => {
                info!(
                    "Successfully uploaded {} access logs ({} bytes)",
                    count, encoded_size
                );
                Ok(())
            }
            Err(e) if e.code() == Code::ResourceExhausted => {
                if Self::shrink_access_logs(&mut logs) {
                    let shrunk_size = Self::access_log_request_size(&logs);
                    match self.send_access_log_chunk(channel, &logs).await {
                        Ok(_) => {
                            info!(
                                "Successfully uploaded {} access logs after stripping large fields ({} bytes)",
                                count, shrunk_size
                            );
                            return Ok(());
                        }
                        Err(retry_err) if retry_err.code() == Code::ResourceExhausted => {}
                        Err(retry_err) => {
                            error!(
                                "Failed to upload access logs after shrink retry: {}",
                                retry_err
                            );
                            return Err(AccessLogUploadError::Retry(logs));
                        }
                    }
                }

                if logs.len() > 1 {
                    let right = logs.split_off(logs.len() / 2);
                    Err(AccessLogUploadError::Split { left: logs, right })
                } else {
                    tracing::warn!(
                        "ACCESS_LOG: dropping single oversized access log after shrink attempts"
                    );
                    Ok(())
                }
            }
            Err(e) => {
                error!("Failed to upload access logs: {}", e);
                Err(AccessLogUploadError::Retry(logs))
            }
        }
    }

    fn http_access_log_client(
        &self,
        channel: Channel,
    ) -> pb::http_access_log_service_client::HttpAccessLogServiceClient<
        tonic::service::interceptor::InterceptedService<Channel, impl tonic::service::Interceptor>,
    > {
        let node_id = self.api_config.node_id.clone();
        let secret = self.api_config.secret.clone();
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
        .max_encoding_message_size(RPC_MAX_MESSAGE_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_config() -> ApiConfig {
        ApiConfig {
            rpc_endpoints: vec!["http://127.0.0.1:1".to_string()],
            rpc_disable_update: false,
            node_id: "1".to_string(),
            secret: "secret".to_string(),
            billing_count_inbound_traffic: false,
        }
    }

    fn access_log(request_id: &str) -> pb::HttpAccessLog {
        pb::HttpAccessLog {
            request_id: request_id.to_string(),
            ..Default::default()
        }
    }

    fn access_logs(ids: &[&str]) -> Vec<pb::HttpAccessLog> {
        ids.iter().map(|id| access_log(id)).collect()
    }

    fn request_ids(logs: impl IntoIterator<Item = pb::HttpAccessLog>) -> Vec<String> {
        logs.into_iter().map(|log| log.request_id).collect()
    }

    #[test]
    fn collect_logs_to_requeue_keeps_failed_then_remaining_order() {
        let mut remaining = VecDeque::new();
        remaining.push_back(access_logs(&["c", "d"]));
        remaining.push_back(access_logs(&["e"]));

        let logs = LogUploader::collect_logs_to_requeue(access_logs(&["b"]), remaining);

        assert_eq!(request_ids(logs), ["b", "c", "d", "e"]);
    }

    #[test]
    fn requeue_failed_logs_preserves_order_and_drops_oldest_over_capacity() {
        let (_tx, rx) = mpsc::channel(1);
        let mut uploader = LogUploader::new(rx, api_config(), 10, Duration::from_secs(1));
        uploader.max_retry_logs = 3;

        uploader.requeue_failed_logs(access_logs(&["b", "c", "d", "e"]));

        let queued = uploader.retry_buffer.into_iter().map(|log| log.request_id);
        assert_eq!(queued.collect::<Vec<_>>(), ["c", "d", "e"]);
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
