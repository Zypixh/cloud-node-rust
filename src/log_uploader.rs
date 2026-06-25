use crate::api_config::{AccessLogPipelineConfig, ApiConfig};
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
use tracing::{debug, error, info, warn};

pub struct LogUploader {
    rx: mpsc::Receiver<pb::HttpAccessLog>,
    api_config: ApiConfig,
    config: AccessLogPipelineConfig,
}

struct AccessLogUploadWorker {
    api_config: ApiConfig,
    channel: Option<Channel>,
    request_timeout: Duration,
    target_chunk_bytes: usize,
    retry_queue: VecDeque<pb::HttpAccessLog>,
    retry_queue_capacity: usize,
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
        config: AccessLogPipelineConfig,
    ) -> Self {
        Self {
            rx,
            api_config,
            config: config.normalized(),
        }
    }

    pub async fn start(mut self) {
        let batch_queue_capacity = self.config.batch_queue_capacity();
        info!(
            "Log Uploader service started. Batch size: {}, Interval: {:?}, Workers: {}, Queue: {}, Batch queue: {}",
            self.config.batch_size,
            Duration::from_millis(self.config.flush_interval_ms),
            self.config.upload_concurrency,
            self.config.queue_capacity,
            batch_queue_capacity
        );

        let (batch_tx, batch_rx) = mpsc::channel::<Vec<pb::HttpAccessLog>>(batch_queue_capacity);
        self.start_upload_workers(batch_rx);
        self.drain_to_batches(batch_tx).await;
    }

    fn start_upload_workers(&self, mut batch_rx: mpsc::Receiver<Vec<pb::HttpAccessLog>>) {
        let worker_count = self.config.upload_concurrency.max(1);
        let mut worker_txs = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let (worker_tx, worker_rx) = mpsc::channel::<Vec<pb::HttpAccessLog>>(1);
            worker_txs.push(worker_tx);
            let worker = AccessLogUploadWorker::new(self.api_config.clone(), &self.config);
            tokio::spawn(async move {
                worker.start(worker_rx).await;
            });
        }

        tokio::spawn(async move {
            let mut next_worker = 0usize;
            while let Some(batch) = batch_rx.recv().await {
                if worker_txs.is_empty() {
                    break;
                }
                let mut batch = Some(batch);
                for _ in 0..worker_txs.len() {
                    let index = next_worker % worker_txs.len();
                    next_worker = next_worker.wrapping_add(1);
                    let Some(candidate) = batch.take() else {
                        break;
                    };
                    match worker_txs[index].send(candidate).await {
                        Ok(()) => break,
                        Err(err) => {
                            worker_txs.remove(index);
                            if worker_txs.is_empty() {
                                tracing::error!(
                                    "ACCESS_LOG: all upload workers closed, dropped {} logs",
                                    err.0.len()
                                );
                                break;
                            }
                            batch = Some(err.0);
                            next_worker = index % worker_txs.len();
                        }
                    }
                }
            }
        });
    }

    async fn drain_to_batches(&mut self, batch_tx: mpsc::Sender<Vec<pb::HttpAccessLog>>) {
        let batch_size = self.config.batch_size;
        let flush_interval = Duration::from_millis(self.config.flush_interval_ms);
        let mut buffer = Vec::with_capacity(batch_size);
        let mut last_flush = Instant::now();

        loop {
            let timeout = tokio::time::sleep_until((last_flush + flush_interval).into());
            tokio::select! {
                msg = self.rx.recv() => {
                    // recv() returning None means every sender has been dropped;
                    // the previous `Some(log) = ...` pattern silently disabled this
                    // arm in select! and let `timeout` fire forever, pegging a
                    // worker at 100%.
                    let Some(log) = msg else {
                        if !buffer.is_empty() {
                            Self::send_batch(&batch_tx, &mut buffer).await;
                        }
                        return;
                    };
                    buffer.push(log);
                    while buffer.len() < batch_size {
                        match self.rx.try_recv() {
                            Ok(log) => buffer.push(log),
                            Err(_) => break,
                        }
                    }
                    if buffer.len() >= batch_size {
                        Self::send_batch(&batch_tx, &mut buffer).await;
                        last_flush = Instant::now();
                    }
                }
                _ = timeout => {
                    if !buffer.is_empty() {
                        Self::send_batch(&batch_tx, &mut buffer).await;
                    }
                    last_flush = Instant::now();
                }
            }
        }
    }

    async fn send_batch(
        batch_tx: &mpsc::Sender<Vec<pb::HttpAccessLog>>,
        buffer: &mut Vec<pb::HttpAccessLog>,
    ) {
        let batch = std::mem::take(buffer);
        if let Err(err) = batch_tx.send(batch).await {
            tracing::error!(
                "ACCESS_LOG: upload worker queue closed, dropped {} buffered access logs",
                err.0.len()
            );
        }
    }
}

impl AccessLogUploadWorker {
    fn new(api_config: ApiConfig, config: &AccessLogPipelineConfig) -> Self {
        let config = config.normalized();
        let target_chunk_bytes = if config.target_chunk_bytes == 0 {
            RPC_MAX_MESSAGE_BYTES.saturating_mul(3) / 4
        } else {
            config.target_chunk_bytes.min(RPC_MAX_MESSAGE_BYTES)
        };
        Self {
            api_config,
            channel: None,
            request_timeout: Duration::from_millis(config.request_timeout_ms),
            target_chunk_bytes,
            retry_queue: VecDeque::with_capacity(config.retry_queue_capacity.min(1024)),
            retry_queue_capacity: config.retry_queue_capacity,
        }
    }

    async fn start(mut self, mut rx: mpsc::Receiver<Vec<pb::HttpAccessLog>>) {
        while let Some(logs) = rx.recv().await {
            self.upload_batch(logs).await;
        }
    }

    async fn get_or_connect_channel(&mut self) -> Option<&Channel> {
        if self.channel.is_some() {
            return self.channel.as_ref();
        }

        for api_endpoint in self.api_config.effective_rpc_endpoints() {
            let endpoint = match tonic::transport::Endpoint::from_shared(api_endpoint.clone()) {
                Ok(ep) => ep
                    .keep_alive_timeout(Duration::from_secs(10))
                    .tcp_keepalive(Some(Duration::from_secs(30))),
                Err(err) => {
                    error!("Failed to create gRPC channel for LogUploader: {}", err);
                    continue;
                }
            };

            match endpoint.connect().await {
                Ok(channel) => {
                    self.channel = Some(channel);
                    return self.channel.as_ref();
                }
                Err(err) => {
                    warn!(
                        "Failed to connect to Master gRPC for LogUploader endpoint {}: {}",
                        api_endpoint, err
                    );
                }
            }
        }

        None
    }

    async fn upload_batch(&mut self, logs: Vec<pb::HttpAccessLog>) {
        self.push_retry_logs(logs);
        if self.retry_queue.is_empty() {
            return;
        }

        let logs_to_send = self.take_retry_logs();
        let count = logs_to_send.len();
        debug!("Flushing batch of {} access logs to Master", count);

        let Some(channel) = self.get_or_connect_channel().await.cloned() else {
            self.requeue_front(logs_to_send);
            return;
        };

        let mut chunks: VecDeque<Vec<pb::HttpAccessLog>> =
            Self::split_logs_by_encoded_size(logs_to_send, self.target_chunk_bytes).into();
        while let Some(chunk) = chunks.pop_front() {
            match self.upload_access_log_chunk(&channel, chunk).await {
                Ok(()) => {}
                Err(AccessLogUploadError::Split { left, right }) => {
                    chunks.push_front(right);
                    chunks.push_front(left);
                }
                Err(AccessLogUploadError::Retry(logs)) => {
                    let logs_to_requeue = Self::collect_logs_to_requeue(logs, chunks);
                    self.requeue_front(logs_to_requeue);
                    self.channel = None;
                    break;
                }
            }
        }
    }

    fn push_retry_logs(&mut self, mut logs: Vec<pb::HttpAccessLog>) {
        let available = self
            .retry_queue_capacity
            .saturating_sub(self.retry_queue.len());
        if logs.len() > available {
            let drop_count = logs.len() - available;
            logs.drain(..drop_count);
            tracing::warn!(
                "ACCESS_LOG: retry queue full, dropped {} oldest pending access logs",
                drop_count
            );
        }
        self.retry_queue.extend(logs);
    }

    fn take_retry_logs(&mut self) -> Vec<pb::HttpAccessLog> {
        self.retry_queue.drain(..).collect()
    }

    fn requeue_front(&mut self, mut logs: Vec<pb::HttpAccessLog>) {
        let available = self
            .retry_queue_capacity
            .saturating_sub(self.retry_queue.len());
        if logs.len() > available {
            let drop_count = logs.len() - available;
            logs.drain(..drop_count);
            tracing::warn!(
                "ACCESS_LOG: retry queue full, dropped {} oldest failed access logs",
                drop_count
            );
        }

        for log in logs.into_iter().rev() {
            self.retry_queue.push_front(log);
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
        let logs_size = logs.iter().map(Message::encoded_len).sum::<usize>();
        logs_size.saturating_add(logs.len().saturating_mul(8))
    }

    fn split_logs_by_encoded_size(
        logs: Vec<pb::HttpAccessLog>,
        target_chunk_bytes: usize,
    ) -> Vec<Vec<pb::HttpAccessLog>> {
        let mut chunks = Vec::new();
        let mut current = Vec::new();
        let mut current_size: usize = 0;

        for log in logs {
            let log_size = log.encoded_len().saturating_add(8);
            if !current.is_empty() && current_size.saturating_add(log_size) > target_chunk_bytes {
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

    async fn send_access_log_chunk(
        &self,
        channel: &Channel,
        logs: &[pb::HttpAccessLog],
    ) -> std::result::Result<(), tonic::Status> {
        let req = pb::CreateHttpAccessLogsRequest {
            http_access_logs: logs.to_vec(),
        };
        let mut client = self.http_access_log_client(channel.clone());
        match tokio::time::timeout(self.request_timeout, client.create_http_access_logs(req)).await
        {
            Ok(result) => result.map(|_| ()),
            Err(_) => Err(tonic::Status::deadline_exceeded(
                "access log upload request timed out",
            )),
        }
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
                debug!(
                    "Successfully uploaded {} access logs ({} bytes)",
                    count, encoded_size
                );
                Ok(())
            }
            Err(e) if e.code() == Code::ResourceExhausted => {
                if logs.iter().any(|log| !log.request_body.is_empty()) {
                    for log in &mut logs {
                        log.request_body.clear();
                    }
                    return match self.send_access_log_chunk(channel, &logs).await {
                        Ok(_) => Ok(()),
                        Err(err) => {
                            warn!(
                                "Failed to upload access logs after dropping request bodies: {}",
                                err
                            );
                            Err(AccessLogUploadError::Retry(logs))
                        }
                    };
                }
                if count > 1 {
                    let right = logs.split_off(count / 2);
                    Err(AccessLogUploadError::Split { left: logs, right })
                } else {
                    tracing::warn!(
                        "ACCESS_LOG: dropping single oversized access log ({} bytes)",
                        encoded_size
                    );
                    Ok(())
                }
            }
            Err(e) => {
                warn!("Failed to upload access logs: {}", e);
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
            access_log_pipeline: Default::default(),
            relay: Default::default(),
            kernel_tuning: Default::default(),
        }
    }

    fn pipeline_config() -> AccessLogPipelineConfig {
        AccessLogPipelineConfig {
            queue_capacity: 3,
            batch_size: 3,
            flush_interval_ms: 1_000,
            upload_concurrency: 1,
            retry_queue_capacity: 3,
            target_chunk_bytes: 0,
            request_timeout_ms: 1_000,
            warning_interval_ms: 1_000,
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

        let logs = AccessLogUploadWorker::collect_logs_to_requeue(access_logs(&["b"]), remaining);

        assert_eq!(request_ids(logs), ["b", "c", "d", "e"]);
    }

    #[test]
    fn requeue_front_preserves_order_and_drops_oldest_over_capacity() {
        let mut worker = AccessLogUploadWorker::new(api_config(), &pipeline_config());

        worker.requeue_front(access_logs(&["b", "c", "d", "e"]));

        let queued = worker.retry_queue.into_iter().map(|log| log.request_id);
        assert_eq!(queued.collect::<Vec<_>>(), ["c", "d", "e"]);
    }

    #[test]
    fn split_logs_by_encoded_size_preserves_full_log_fields() {
        let mut log = pb::HttpAccessLog {
            request_id: "a".to_string(),
            request_body: b"body".to_vec(),
            ..Default::default()
        };
        log.cookie.insert("cookie".to_string(), "value".to_string());
        log.attrs.insert("attr".to_string(), "value".to_string());
        log.header.insert(
            "header".to_string(),
            pb::Strings {
                values: vec!["value".to_string()],
            },
        );
        log.sent_header.insert(
            "sent".to_string(),
            pb::Strings {
                values: vec!["value".to_string()],
            },
        );

        let mut chunks = AccessLogUploadWorker::split_logs_by_encoded_size(vec![log], 1);
        let log = chunks.pop().unwrap().pop().unwrap();

        assert_eq!(log.request_body, b"body".to_vec());
        assert!(log.header.contains_key("header"));
        assert!(log.sent_header.contains_key("sent"));
        assert_eq!(log.cookie.get("cookie"), Some(&"value".to_string()));
        assert_eq!(log.attrs.get("attr"), Some(&"value".to_string()));
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
                msg = self.rx.recv() => {
                    let Some(log) = msg else {
                        // All senders dropped; flush remaining and exit so we
                        // don't busy-loop on the timeout arm.
                        if !buffer.is_empty() {
                            self.flush_batch(&mut buffer).await;
                        }
                        return;
                    };
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
                warn!("Failed to connect for NodeLogUploader: {}", err);
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
                warn!("Failed to upload node logs: {}", e);
                self.channel = None;
            }
        }
    }
}
