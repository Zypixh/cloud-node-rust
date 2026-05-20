use crate::runtime_mode::RuntimeConfig;

pub fn start(runtime_config: &RuntimeConfig) {
    if !runtime_config.is_rke2() {
        return;
    }

    crate::cluster::leader::init(runtime_config);
    crate::cluster::leader::start(runtime_config);
    metadata::start_event_worker();
    crate::cluster::stats::start(runtime_config);
    if let Err(err) = crate::cluster::internal_api::start(runtime_config) {
        tracing::error!("CLUSTER: failed to start internal API: {}", err);
    }
    tracing::info!(
        "CLUSTER: RKE2 cluster runtime initialized for {} in namespace {}.",
        runtime_config.cluster.name,
        runtime_config.cluster.namespace
    );
}

mod metadata {
    pub fn start_event_worker() {
        crate::cluster::metadata::start_event_worker();
    }
}
