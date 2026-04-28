#![allow(clippy::type_complexity, clippy::result_large_err)]

use crate::api_config::ApiConfig;
use crate::auth::generate_token;
use crate::pb;
use tonic::transport::Channel;
use tonic::{Request, Status};

use std::time::Duration;

#[derive(Clone)]
pub struct RpcClient {
    channel: Channel,
    api_config: ApiConfig,
}

impl RpcClient {
    pub async fn new(api_config: &ApiConfig) -> anyhow::Result<Self> {
        let endpoints = api_config.effective_rpc_endpoints();
        Self::connect(api_config, &endpoints).await
    }

    /// Create a client for a stream, attempting all endpoints. If `force` is
    /// false, uses the exact list given; if true, re-reads from api_config.
    pub async fn new_with_endpoints(
        api_config: &ApiConfig,
        endpoints: &[String],
        force: bool,
    ) -> anyhow::Result<Self> {
        let list: Vec<String> = if force || endpoints.is_empty() {
            api_config.effective_rpc_endpoints()
        } else {
            endpoints.to_vec()
        };
        Self::connect(api_config, &list).await
    }

    async fn connect(api_config: &ApiConfig, endpoints: &[String]) -> anyhow::Result<Self> {
        if endpoints.is_empty() {
            anyhow::bail!("No RPC endpoints configured");
        }
        let mut last_err = None;
        for api_endpoint in endpoints {
            let endpoint = match Channel::from_shared(api_endpoint.clone()) {
                Ok(e) => e,
                Err(e) => {
                    last_err = Some(anyhow::anyhow!("Invalid URI {}: {}", api_endpoint, e));
                    continue;
                }
            };

            let channel = endpoint
                .connect_timeout(Duration::from_secs(10))
                .tcp_keepalive(Some(Duration::from_secs(15)))
                .http2_keep_alive_interval(Duration::from_secs(30))
                .keep_alive_timeout(Duration::from_secs(10))
                .keep_alive_while_idle(true)
                .connect()
                .await;

            match channel {
                Ok(channel) => {
                    return Ok(Self {
                        channel,
                        api_config: api_config.clone(),
                    });
                }
                Err(err) => {
                    last_err = Some(anyhow::anyhow!(
                        "Failed to connect to {}: {}",
                        api_endpoint,
                        err
                    ));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Unable to connect to any RPC endpoint")))
    }

    pub async fn ping_endpoint(api_config: &ApiConfig, endpoint: &str) -> bool {
        let endpoint = match Channel::from_shared(endpoint.to_string()) {
            Ok(endpoint) => endpoint,
            Err(_) => return false,
        };

        let channel = match endpoint
            .connect_timeout(Duration::from_secs(5))
            .tcp_keepalive(Some(Duration::from_secs(15)))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10))
            .keep_alive_while_idle(true)
            .connect()
            .await
        {
            Ok(channel) => channel,
            Err(_) => return false,
        };

        let mut service = pb::ping_service_client::PingServiceClient::with_interceptor(
            channel,
            Self::interceptor(api_config, None),
        );

        service.ping(pb::PingRequest {}).await.is_ok()
    }

    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }

    fn interceptor(
        api_config: &ApiConfig,
        node_type: Option<&'static str>,
    ) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static {
        let node_id = api_config.node_id.clone();
        let secret = api_config.secret.clone();
        let type_str = node_type.unwrap_or("node");
        move |mut req: Request<()>| {
            let token = generate_token(&node_id, &secret, type_str).unwrap_or_default();

            let val = node_id
                .parse()
                .unwrap_or(tonic::metadata::MetadataValue::from_static("0"));

            // Standard lowercase keys (canonical gRPC)
            req.metadata_mut().insert("nodeid", val.clone());
            req.metadata_mut().insert(
                "type",
                tonic::metadata::MetadataValue::from_static(type_str),
            );

            // Go-style CamelCase key
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
        }
    }

    pub fn node_service(
        &self,
    ) -> pb::node_service_client::NodeServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::node_service_client::NodeServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn node_service_with_type(
        &self,
    ) -> pb::node_service_client::NodeServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::node_service_client::NodeServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, Some("edge")),
        )
    }

    pub fn server_service(
        &self,
    ) -> pb::server_service_client::ServerServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::server_service_client::ServerServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn node_task_service(
        &self,
    ) -> pb::node_task_service_client::NodeTaskServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::node_task_service_client::NodeTaskServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn user_service(
        &self,
    ) -> pb::user_service_client::UserServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::user_service_client::UserServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn node_value_service(
        &self,
    ) -> pb::node_value_service_client::NodeValueServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::node_value_service_client::NodeValueServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn node_value_service_with_type(
        &self,
    ) -> pb::node_value_service_client::NodeValueServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::node_value_service_client::NodeValueServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, Some("edge")),
        )
    }

    pub fn node_log_service(
        &self,
    ) -> pb::node_log_service_client::NodeLogServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::node_log_service_client::NodeLogServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn bandwidth_stat_service(
        &self,
    ) -> pb::server_bandwidth_stat_service_client::ServerBandwidthStatServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::server_bandwidth_stat_service_client::ServerBandwidthStatServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn daily_stat_service(
        &self,
    ) -> pb::server_daily_stat_service_client::ServerDailyStatServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::server_daily_stat_service_client::ServerDailyStatServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn metric_stat_service(
        &self,
    ) -> pb::metric_stat_service_client::MetricStatServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::metric_stat_service_client::MetricStatServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn ip_item_service(
        &self,
    ) -> pb::ip_item_service_client::IpItemServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::ip_item_service_client::IpItemServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn ip_item_service_with_type(
        &self,
    ) -> pb::ip_item_service_client::IpItemServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::ip_item_service_client::IpItemServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, Some("edge")),
        )
    }

    pub fn ip_list_service(
        &self,
    ) -> pb::ip_list_service_client::IpListServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::ip_list_service_client::IpListServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn deleted_content_service(
        &self,
    ) -> pb::server_deleted_content_service_client::ServerDeletedContentServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::server_deleted_content_service_client::ServerDeletedContentServiceClient::with_interceptor(self.channel.clone(), Self::interceptor(&self.api_config, None))
    }

    pub fn api_node_service(
        &self,
    ) -> pb::api_node_service_client::ApiNodeServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::api_node_service_client::ApiNodeServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn firewall_service(
        &self,
    ) -> pb::firewall_service_client::FirewallServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::firewall_service_client::FirewallServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn acme_service(
        &self,
    ) -> pb::acme_authentication_service_client::AcmeAuthenticationServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::acme_authentication_service_client::AcmeAuthenticationServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn ip_library_artifact_service(
        &self,
    ) -> pb::ip_library_artifact_service_client::IpLibraryArtifactServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::ip_library_artifact_service_client::IpLibraryArtifactServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn file_chunk_service(
        &self,
    ) -> pb::file_chunk_service_client::FileChunkServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::file_chunk_service_client::FileChunkServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn ssl_cert_service(
        &self,
    ) -> pb::ssl_cert_service_client::SslCertServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::ssl_cert_service_client::SslCertServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn cache_task_service(
        &self,
    ) -> pb::http_cache_task_key_service_client::HttpCacheTaskKeyServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::http_cache_task_key_service_client::HttpCacheTaskKeyServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn ping_service(
        &self,
    ) -> pb::ping_service_client::PingServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::ping_service_client::PingServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn plan_service(
        &self,
    ) -> pb::plan_service_client::PlanServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::plan_service_client::PlanServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn updating_server_list_service(
        &self,
    ) -> pb::updating_server_list_service_client::UpdatingServerListServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::updating_server_list_service_client::UpdatingServerListServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn authority_key_service(
        &self,
    ) -> pb::authority_key_service_client::AuthorityKeyServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::authority_key_service_client::AuthorityKeyServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn client_agent_ip_service(
        &self,
    ) -> pb::client_agent_ip_service_client::ClientAgentIpServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::client_agent_ip_service_client::ClientAgentIpServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn file_service(
        &self,
    ) -> pb::file_service_client::FileServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::file_service_client::FileServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn script_service(
        &self,
    ) -> pb::script_service_client::ScriptServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::script_service_client::ScriptServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    /*pub fn index_service(&self) -> pb::index_service_client::IndexServiceClient<tonic::service::interceptor::InterceptedService<Channel, impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static>> {
        pb::index_service_client::IndexServiceClient::with_interceptor(self.channel.clone(), Self::interceptor(&self.api_config, true))
    }*/

    pub fn server_event_service(
        &self,
    ) -> pb::server_event_service_client::ServerEventServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::server_event_service_client::ServerEventServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }

    pub fn server_top_ip_stat_service(
        &self,
    ) -> pb::server_top_ip_stat_service_client::ServerTopIpStatServiceClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static,
        >,
    > {
        pb::server_top_ip_stat_service_client::ServerTopIpStatServiceClient::with_interceptor(
            self.channel.clone(),
            Self::interceptor(&self.api_config, None),
        )
    }
}
