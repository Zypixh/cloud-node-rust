use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiConfig {
    #[serde(rename = "rpc.endpoints", default)]
    pub rpc_endpoints: Vec<String>,
    #[serde(rename = "nodeId")]
    pub node_id: String,
    #[serde(rename = "secret")]
    pub secret: String,
}

fn main() {
    let content = r#"
rpc.endpoints: [ "http://127.0.0.1:8001" ]
nodeId: "your-node-id"
secret: "your-node-secret"
"#;
    let config: Result<ApiConfig, _> = serde_yaml::from_str(content);
    println!("{:?}", config);
}
