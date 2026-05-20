use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, error, info, warn};

const SERVICE_ACCOUNT_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const SERVICE_ACCOUNT_CA: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

pub static ROLE_STATE: Lazy<ClusterRoleState> = Lazy::new(ClusterRoleState::default);

pub struct ClusterRoleState {
    is_leader: AtomicBool,
    epoch: AtomicU64,
}

impl Default for ClusterRoleState {
    fn default() -> Self {
        Self {
            is_leader: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
        }
    }
}

impl ClusterRoleState {
    pub fn set_leader(&self, is_leader: bool, epoch: u64) {
        let previous = self.is_leader.swap(is_leader, Ordering::AcqRel);
        self.epoch.store(epoch, Ordering::Release);
        if previous != is_leader {
            if is_leader {
                info!("CLUSTER_LEADER: this pod became leader at epoch {}", epoch);
            } else {
                info!("CLUSTER_LEADER: this pod is follower at epoch {}", epoch);
            }
        }
    }

    pub fn is_leader(&self) -> bool {
        self.is_leader.load(Ordering::Acquire)
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }
}

pub fn init(runtime_config: &crate::runtime_mode::RuntimeConfig) {
    if runtime_config.is_rke2() {
        ROLE_STATE.set_leader(false, 0);
        tracing::info!(
            "CLUSTER_LEADER: RKE2 pod starts as follower until Lease election is active."
        );
    } else {
        ROLE_STATE.set_leader(true, 0);
    }
}

pub fn start(runtime_config: &crate::runtime_mode::RuntimeConfig) {
    if !runtime_config.is_rke2() {
        return;
    }

    let config = runtime_config.clone();
    tokio::spawn(async move {
        if let Err(err) = run_election(config).await {
            ROLE_STATE.set_leader(false, ROLE_STATE.epoch());
            error!("CLUSTER_LEADER: election stopped: {}", err);
        }
    });
}

async fn run_election(config: crate::runtime_mode::RuntimeConfig) -> anyhow::Result<()> {
    let namespace = config.cluster.namespace.clone();
    let lease_name = config.cluster.leader_election.lease_name.clone();
    let pod_name = env_value(&config.cluster.pod_name_env)?;
    let pod_uid = std::env::var("POD_UID").unwrap_or_default();
    let holder = if pod_uid.is_empty() {
        pod_name
    } else {
        format!("{pod_name}/{pod_uid}")
    };
    let retry_period =
        Duration::from_secs(config.cluster.leader_election.retry_period_seconds.max(1));
    let renew_deadline_seconds = config.cluster.leader_election.renew_deadline_seconds as i64;
    let lease_duration_seconds = config.cluster.leader_election.lease_duration_seconds as i64;
    let client = KubernetesLeaseClient::new(namespace, lease_name).await?;

    info!("CLUSTER_LEADER: starting Lease election as {}", holder);

    loop {
        let now = chrono::Utc::now();
        let now_micro = lease_time(now);
        match client.get_lease().await {
            Ok(Some(mut lease)) => {
                let can_acquire = lease
                    .spec
                    .holder_identity
                    .as_deref()
                    .map(|current| current == holder)
                    .unwrap_or(true)
                    || lease.is_expired(now, lease_duration_seconds);

                if can_acquire {
                    let transitions = if lease.spec.holder_identity.as_deref() == Some(&holder) {
                        lease.spec.lease_transitions.unwrap_or(0)
                    } else {
                        lease.spec.lease_transitions.unwrap_or(0).saturating_add(1)
                    };
                    lease.spec.holder_identity = Some(holder.clone());
                    lease
                        .spec
                        .acquire_time
                        .get_or_insert_with(|| now_micro.clone());
                    lease.spec.renew_time = Some(now_micro.clone());
                    lease.spec.lease_duration_seconds = Some(lease_duration_seconds);
                    lease.spec.lease_transitions = Some(transitions);
                    match client.update_lease(&lease).await {
                        Ok(updated) => ROLE_STATE.set_leader(
                            true,
                            updated.spec.lease_transitions.unwrap_or(transitions),
                        ),
                        Err(err) => {
                            ROLE_STATE.set_leader(false, ROLE_STATE.epoch());
                            warn!("CLUSTER_LEADER: failed to update Lease: {}", err);
                        }
                    }
                } else {
                    ROLE_STATE.set_leader(false, lease.spec.lease_transitions.unwrap_or(0));
                    debug!(
                        "CLUSTER_LEADER: Lease held by {:?}",
                        lease.spec.holder_identity
                    );
                }
            }
            Ok(None) => match client.create_lease(&holder, lease_duration_seconds).await {
                Ok(lease) => ROLE_STATE.set_leader(true, lease.spec.lease_transitions.unwrap_or(1)),
                Err(err) => {
                    ROLE_STATE.set_leader(false, ROLE_STATE.epoch());
                    warn!("CLUSTER_LEADER: failed to create Lease: {}", err);
                }
            },
            Err(err) => {
                ROLE_STATE.set_leader(false, ROLE_STATE.epoch());
                warn!("CLUSTER_LEADER: failed to read Lease: {}", err);
            }
        }

        tokio::time::sleep(
            retry_period.min(Duration::from_secs(renew_deadline_seconds.max(1) as u64)),
        )
        .await;
    }
}

pub fn is_leader() -> bool {
    !crate::runtime_mode::RuntimeConfig::current_is_rke2() || ROLE_STATE.is_leader()
}

pub fn require_leader(task: &str) -> bool {
    let allowed = is_leader();
    if !allowed {
        tracing::debug!(
            "CLUSTER_LEADER: skipping leader-only task {} on follower",
            task
        );
    }
    allowed
}

fn env_value(name: &str) -> anyhow::Result<String> {
    let value = std::env::var(name)?;
    if value.trim().is_empty() {
        anyhow::bail!("{name} is empty");
    }
    Ok(value)
}

fn lease_time(time: chrono::DateTime<chrono::Utc>) -> String {
    time.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

struct KubernetesLeaseClient {
    client: reqwest::Client,
    api_base: String,
    token: String,
    namespace: String,
    lease_name: String,
}

impl KubernetesLeaseClient {
    async fn new(namespace: String, lease_name: String) -> anyhow::Result<Self> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());
        let token = tokio::fs::read_to_string(SERVICE_ACCOUNT_TOKEN).await?;
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(5));
        if let Ok(ca) = tokio::fs::read(SERVICE_ACCOUNT_CA).await {
            if let Ok(cert) = reqwest::Certificate::from_pem(&ca) {
                builder = builder.add_root_certificate(cert);
            }
        }
        let client = builder.build()?;
        Ok(Self {
            client,
            api_base: format!("https://{host}:{port}"),
            token,
            namespace,
            lease_name,
        })
    }

    async fn get_lease(&self) -> anyhow::Result<Option<Lease>> {
        let resp = self
            .client
            .get(self.lease_url())
            .bearer_auth(self.token.trim())
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!("Kubernetes Lease GET failed: {}", resp.status());
        }
        Ok(Some(serde_json::from_slice(&resp.bytes().await?)?))
    }

    async fn create_lease(&self, holder: &str, duration_seconds: i64) -> anyhow::Result<Lease> {
        let now = lease_time(chrono::Utc::now());
        let lease = Lease {
            api_version: "coordination.k8s.io/v1".to_string(),
            kind: "Lease".to_string(),
            metadata: LeaseMetadata {
                name: self.lease_name.clone(),
                namespace: self.namespace.clone(),
                resource_version: None,
            },
            spec: LeaseSpec {
                holder_identity: Some(holder.to_string()),
                lease_duration_seconds: Some(duration_seconds),
                acquire_time: Some(now.clone()),
                renew_time: Some(now),
                lease_transitions: Some(1),
            },
        };
        let resp = self
            .client
            .post(self.leases_url())
            .bearer_auth(self.token.trim())
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&lease)?)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Kubernetes Lease CREATE failed: {} {}", status, body);
        }
        Ok(serde_json::from_slice(&resp.bytes().await?)?)
    }

    async fn update_lease(&self, lease: &Lease) -> anyhow::Result<Lease> {
        let resp = self
            .client
            .put(self.lease_url())
            .bearer_auth(self.token.trim())
            .header("content-type", "application/json")
            .body(serde_json::to_vec(lease)?)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Kubernetes Lease UPDATE failed: {} {}", status, body);
        }
        Ok(serde_json::from_slice(&resp.bytes().await?)?)
    }

    fn leases_url(&self) -> String {
        format!(
            "{}/apis/coordination.k8s.io/v1/namespaces/{}/leases",
            self.api_base, self.namespace
        )
    }

    fn lease_url(&self) -> String {
        format!("{}/{}", self.leases_url(), self.lease_name)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Lease {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    metadata: LeaseMetadata,
    spec: LeaseSpec,
}

impl Lease {
    fn is_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        default_duration_seconds: i64,
    ) -> bool {
        let Some(renew_time) = self.spec.renew_time.as_deref() else {
            return true;
        };
        let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(renew_time) else {
            return true;
        };
        let duration = self
            .spec
            .lease_duration_seconds
            .unwrap_or(default_duration_seconds)
            .max(1);
        now.signed_duration_since(parsed.with_timezone(&chrono::Utc))
            .num_seconds()
            > duration
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LeaseMetadata {
    name: String,
    namespace: String,
    #[serde(rename = "resourceVersion", skip_serializing_if = "Option::is_none")]
    resource_version: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LeaseSpec {
    #[serde(rename = "holderIdentity", skip_serializing_if = "Option::is_none")]
    holder_identity: Option<String>,
    #[serde(
        rename = "leaseDurationSeconds",
        skip_serializing_if = "Option::is_none"
    )]
    lease_duration_seconds: Option<i64>,
    #[serde(rename = "acquireTime", skip_serializing_if = "Option::is_none")]
    acquire_time: Option<String>,
    #[serde(rename = "renewTime", skip_serializing_if = "Option::is_none")]
    renew_time: Option<String>,
    #[serde(rename = "leaseTransitions", skip_serializing_if = "Option::is_none")]
    lease_transitions: Option<u64>,
}
