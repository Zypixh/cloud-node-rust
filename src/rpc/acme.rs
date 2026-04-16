use crate::api_config::ApiConfig;
use crate::pb;
use crate::rpc::client::RpcClient;

pub async fn find_acme_key(api_config: &ApiConfig, token: &str) -> Option<String> {
    let client = match RpcClient::new(api_config).await {
        Ok(c) => c,
        Err(_) => return None,
    };
    let mut service = client.acme_service();

    match service
        .find_acme_authentication_key_with_token(pb::FindAcmeAuthenticationKeyWithTokenRequest {
            token: token.to_string(),
        })
        .await
    {
        Ok(resp) => Some(resp.into_inner().key),
        Err(_) => None,
    }
}
