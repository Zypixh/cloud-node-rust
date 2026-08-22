use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PipelineMetricsSnapshot {
    pub access_log_ingress_dropped: u64,
    pub access_log_retry_evicted: u64,
    pub access_log_upload_failed: u64,
    pub node_log_ingress_dropped: u64,
    pub node_log_throttled: u64,
    pub node_log_upload_failed: u64,
    pub http_dimension_dropped: u64,
    pub ip_report_dropped: u64,
    pub local_log_dropped: u64,
    pub local_log_write_failed: u64,
    pub local_log_rotation_failed: u64,
    pub kernel_sync_coalesced: u64,
    pub kernel_sync_reconcile_requested: u64,
    pub kernel_sync_failed: u64,
    pub xdp_map_sync_failed: u64,
    pub internal_api_rejected: u64,
    pub rpc_stream_command_rejected: u64,
    pub rpc_stream_reply_dropped: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipelineCounter {
    AccessLogIngressDropped,
    AccessLogRetryEvicted,
    AccessLogUploadFailed,
    NodeLogIngressDropped,
    NodeLogThrottled,
    NodeLogUploadFailed,
    HttpDimensionDropped,
    IpReportDropped,
    LocalLogDropped,
    LocalLogWriteFailed,
    LocalLogRotationFailed,
    KernelSyncCoalesced,
    KernelSyncReconcileRequested,
    KernelSyncFailed,
    XdpMapSyncFailed,
    InternalApiRejected,
    RpcStreamCommandRejected,
    RpcStreamReplyDropped,
}

struct PipelineMetrics {
    access_log_ingress_dropped: AtomicU64,
    access_log_retry_evicted: AtomicU64,
    access_log_upload_failed: AtomicU64,
    node_log_ingress_dropped: AtomicU64,
    node_log_throttled: AtomicU64,
    node_log_upload_failed: AtomicU64,
    http_dimension_dropped: AtomicU64,
    ip_report_dropped: AtomicU64,
    local_log_dropped: AtomicU64,
    local_log_write_failed: AtomicU64,
    local_log_rotation_failed: AtomicU64,
    kernel_sync_coalesced: AtomicU64,
    kernel_sync_reconcile_requested: AtomicU64,
    kernel_sync_failed: AtomicU64,
    xdp_map_sync_failed: AtomicU64,
    internal_api_rejected: AtomicU64,
    rpc_stream_command_rejected: AtomicU64,
    rpc_stream_reply_dropped: AtomicU64,
}

impl PipelineMetrics {
    const fn new() -> Self {
        Self {
            access_log_ingress_dropped: AtomicU64::new(0),
            access_log_retry_evicted: AtomicU64::new(0),
            access_log_upload_failed: AtomicU64::new(0),
            node_log_ingress_dropped: AtomicU64::new(0),
            node_log_throttled: AtomicU64::new(0),
            node_log_upload_failed: AtomicU64::new(0),
            http_dimension_dropped: AtomicU64::new(0),
            ip_report_dropped: AtomicU64::new(0),
            local_log_dropped: AtomicU64::new(0),
            local_log_write_failed: AtomicU64::new(0),
            local_log_rotation_failed: AtomicU64::new(0),
            kernel_sync_coalesced: AtomicU64::new(0),
            kernel_sync_reconcile_requested: AtomicU64::new(0),
            kernel_sync_failed: AtomicU64::new(0),
            xdp_map_sync_failed: AtomicU64::new(0),
            internal_api_rejected: AtomicU64::new(0),
            rpc_stream_command_rejected: AtomicU64::new(0),
            rpc_stream_reply_dropped: AtomicU64::new(0),
        }
    }

    fn counter(&self, counter: PipelineCounter) -> &AtomicU64 {
        match counter {
            PipelineCounter::AccessLogIngressDropped => &self.access_log_ingress_dropped,
            PipelineCounter::AccessLogRetryEvicted => &self.access_log_retry_evicted,
            PipelineCounter::AccessLogUploadFailed => &self.access_log_upload_failed,
            PipelineCounter::NodeLogIngressDropped => &self.node_log_ingress_dropped,
            PipelineCounter::NodeLogThrottled => &self.node_log_throttled,
            PipelineCounter::NodeLogUploadFailed => &self.node_log_upload_failed,
            PipelineCounter::HttpDimensionDropped => &self.http_dimension_dropped,
            PipelineCounter::IpReportDropped => &self.ip_report_dropped,
            PipelineCounter::LocalLogDropped => &self.local_log_dropped,
            PipelineCounter::LocalLogWriteFailed => &self.local_log_write_failed,
            PipelineCounter::LocalLogRotationFailed => &self.local_log_rotation_failed,
            PipelineCounter::KernelSyncCoalesced => &self.kernel_sync_coalesced,
            PipelineCounter::KernelSyncReconcileRequested => {
                &self.kernel_sync_reconcile_requested
            }
            PipelineCounter::KernelSyncFailed => &self.kernel_sync_failed,
            PipelineCounter::XdpMapSyncFailed => &self.xdp_map_sync_failed,
            PipelineCounter::InternalApiRejected => &self.internal_api_rejected,
            PipelineCounter::RpcStreamCommandRejected => &self.rpc_stream_command_rejected,
            PipelineCounter::RpcStreamReplyDropped => &self.rpc_stream_reply_dropped,
        }
    }

    fn snapshot(&self) -> PipelineMetricsSnapshot {
        PipelineMetricsSnapshot {
            access_log_ingress_dropped: self.access_log_ingress_dropped.load(Ordering::Relaxed),
            access_log_retry_evicted: self.access_log_retry_evicted.load(Ordering::Relaxed),
            access_log_upload_failed: self.access_log_upload_failed.load(Ordering::Relaxed),
            node_log_ingress_dropped: self.node_log_ingress_dropped.load(Ordering::Relaxed),
            node_log_throttled: self.node_log_throttled.load(Ordering::Relaxed),
            node_log_upload_failed: self.node_log_upload_failed.load(Ordering::Relaxed),
            http_dimension_dropped: self.http_dimension_dropped.load(Ordering::Relaxed),
            ip_report_dropped: self.ip_report_dropped.load(Ordering::Relaxed),
            local_log_dropped: self.local_log_dropped.load(Ordering::Relaxed),
            local_log_write_failed: self.local_log_write_failed.load(Ordering::Relaxed),
            local_log_rotation_failed: self.local_log_rotation_failed.load(Ordering::Relaxed),
            kernel_sync_coalesced: self.kernel_sync_coalesced.load(Ordering::Relaxed),
            kernel_sync_reconcile_requested: self
                .kernel_sync_reconcile_requested
                .load(Ordering::Relaxed),
            kernel_sync_failed: self.kernel_sync_failed.load(Ordering::Relaxed),
            xdp_map_sync_failed: self.xdp_map_sync_failed.load(Ordering::Relaxed),
            internal_api_rejected: self.internal_api_rejected.load(Ordering::Relaxed),
            rpc_stream_command_rejected: self
                .rpc_stream_command_rejected
                .load(Ordering::Relaxed),
            rpc_stream_reply_dropped: self.rpc_stream_reply_dropped.load(Ordering::Relaxed),
        }
    }
}

static PIPELINE_METRICS: PipelineMetrics = PipelineMetrics::new();

pub fn increment(counter: PipelineCounter) -> u64 {
    PIPELINE_METRICS
        .counter(counter)
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1)
}

pub fn add(counter: PipelineCounter, value: u64) -> u64 {
    PIPELINE_METRICS
        .counter(counter)
        .fetch_add(value, Ordering::Relaxed)
        .saturating_add(value)
}

pub fn snapshot() -> PipelineMetricsSnapshot {
    PIPELINE_METRICS.snapshot()
}
