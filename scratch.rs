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
rpc.endpoints: [ "http://47.97.60.155:8001" ]
nodeId: "01f5632b3239fba4911f43fbdc4bd661"
secret: "XMz3OqJicVJE6uhmCoam1AwUKBI24VXR"
"#;
    let config: Result<ApiConfig, _> = serde_yaml::from_str(content);
    println!("{:?}", config);
}
