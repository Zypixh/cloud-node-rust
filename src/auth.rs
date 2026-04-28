use aes::Aes256;
use base64::{Engine as _, engine::general_purpose};
use cfb_mode::Encryptor;
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use md5::{Digest, Md5};
use serde_json::json;

type Aes256CfbEnc = Encryptor<Aes256>;

/// Generates the base64 AES256-CFB encrypted token required by GoEdge API Node.
/// Uses deterministic key/IV derivation compatible with the Go master's decodeToken().
pub fn generate_token(node_id: &str, secret: &str, _node_type: &str) -> anyhow::Result<String> {
    // Key: secret padded/truncated to 32 bytes (matching Go master)
    let mut key = [b' '; 32];
    let secret_bytes = secret.as_bytes();
    let copy_len = secret_bytes.len().min(32);
    key[..copy_len].copy_from_slice(&secret_bytes[..copy_len]);

    // IV: node_id padded/truncated to 16 bytes (matching Go master)
    let mut iv = [b' '; 16];
    let id_bytes = node_id.as_bytes();
    let id_copy_len = id_bytes.len().min(16);
    iv[..id_copy_len].copy_from_slice(&id_bytes[..id_copy_len]);

    let timestamp = crate::utils::time::now_timestamp();
    let payload = json!({
        "timestamp": timestamp,
        "type": "node",
        "userId": 0,
    });

    let mut data = payload.to_string().into_bytes();
    let cipher = Aes256CfbEnc::new_from_slices(&key, &iv)
        .map_err(|e| anyhow::anyhow!("Invalid cipher init: {}", e))?;

    cipher.encrypt(&mut data);

    Ok(general_purpose::STANDARD.encode(&data))
}

/// URL Auth Verification (Types A, B, C, D)
/// This module implements GoEdge / CDN compatible URL authentication signatures.
pub struct UrlAuthConfig {
    pub auth_type: String, // "A", "B", "C", "D"
    pub secret: String,
    pub param_name: String, // e.g. "auth_key"
    pub life: i64,
}

pub fn verify_url_auth(path: &str, query: &str, config: &UrlAuthConfig) -> bool {
    match config.auth_type.as_str() {
        "A" => verify_type_a(path, query, config),
        "B" => verify_type_b(path, query, config),
        "C" => verify_type_c(path, query, config),
        "D" => verify_type_d(path, query, config),
        "F" => verify_type_f(path, query, config),
        _ => true,
    }
}

fn verify_type_a(path: &str, query: &str, config: &UrlAuthConfig) -> bool {
    // Type A: timestamp-rand-uid-md5hash
    let auth_token = get_query_param(query, &config.param_name).unwrap_or("");
    let parts: Vec<&str> = auth_token.split('-').collect();
    if parts.len() < 4 {
        return false;
    }

    let timestamp = parts[0].parse::<i64>().unwrap_or(0);
    let rand = parts[1];
    let uid = parts[2];
    let md5hash = parts[3];

    let now = crate::utils::time::now_timestamp();
    if (now - timestamp).abs() > config.life {
        return false;
    }

    let mut hasher = Md5::new();
    hasher.update(format!("{}-{}-{}-{}", path, timestamp, rand, uid).as_bytes());
    hasher.update(config.secret.as_bytes());
    let result = hasher.finalize();
    hex::encode(result) == md5hash
}

fn verify_type_b(path: &str, _query: &str, config: &UrlAuthConfig) -> bool {
    // Type B: /timestamp/md5hash/path
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 4 {
        return false;
    }

    let timestamp_str = parts[1];
    let md5hash = parts[2];
    let real_path = &path[timestamp_str.len() + md5hash.len() + 2..];

    let timestamp = i64::from_str_radix(timestamp_str, 16).unwrap_or(0);
    let now = crate::utils::time::now_timestamp();
    if (now - timestamp).abs() > config.life {
        return false;
    }

    let mut hasher = Md5::new();
    hasher.update(config.secret.as_bytes());
    hasher.update(timestamp_str.as_bytes());
    hasher.update(real_path.as_bytes());
    let result = hasher.finalize();
    hex::encode(result) == md5hash
}

fn verify_type_c(path: &str, _query: &str, config: &UrlAuthConfig) -> bool {
    // Type C: /md5hash/timestamp/path
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 4 {
        return false;
    }

    let md5hash = parts[1];
    let timestamp_str = parts[2];
    let real_path = &path[md5hash.len() + timestamp_str.len() + 2..];

    let mut hasher = Md5::new();
    hasher.update(config.secret.as_bytes());
    hasher.update(real_path.as_bytes());
    hasher.update(timestamp_str.as_bytes());
    let result = hasher.finalize();
    hex::encode(result) == md5hash
}

fn verify_type_d(path: &str, query: &str, config: &UrlAuthConfig) -> bool {
    // Type D: ?sign=md5(secret + path + timestamp)&t=timestamp
    let sign = get_query_param(query, "sign").unwrap_or("");
    let timestamp_str = get_query_param(query, "t").unwrap_or("");
    if sign.is_empty() || timestamp_str.is_empty() {
        return false;
    }

    let timestamp = timestamp_str.parse::<i64>().unwrap_or(0);
    let now = crate::utils::time::now_timestamp();
    if (now - timestamp).abs() > config.life {
        return false;
    }

    let mut hasher = Md5::new();
    hasher.update(config.secret.as_bytes());
    hasher.update(path.as_bytes());
    hasher.update(timestamp_str.as_bytes());
    let result = hasher.finalize();
    hex::encode(result) == sign
}

fn verify_type_f(path: &str, query: &str, config: &UrlAuthConfig) -> bool {
    // Type F: variation with custom param name
    let auth_key = get_query_param(query, &config.param_name).unwrap_or("");
    let timestamp_str = get_query_param(query, "timestamp").unwrap_or("");
    if auth_key.is_empty() || timestamp_str.is_empty() {
        return false;
    }

    let timestamp = timestamp_str.parse::<i64>().unwrap_or(0);
    let now = crate::utils::time::now_timestamp();
    if (now - timestamp).abs() > config.life {
        return false;
    }

    let mut hasher = Md5::new();
    hasher.update(path.as_bytes());
    hasher.update(config.secret.as_bytes());
    hasher.update(timestamp_str.as_bytes());
    let result = hasher.finalize();
    hex::encode(result) == auth_key
}

fn get_query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    for part in query.split('&') {
        let mut kv = part.splitn(2, '=');
        let k = kv.next()?;
        if k == name {
            return kv.next();
        }
    }
    None
}

/// WAF Challenges
pub fn generate_waf_challenge_token(ip: &str, timestamp: i64, secret: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(ip.as_bytes());
    hasher.update(timestamp.to_string().as_bytes());
    hasher.update(secret.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

pub fn verify_waf_challenge_token(ip: &str, token: &str, secret: &str, _window_secs: i64) -> bool {
    let now = crate::utils::time::now_timestamp();
    // Check current and previous 10-second windows to allow some clock drift/delay
    for offset in -1..=1 {
        let ts = (now / 10 + offset) * 10;
        if generate_waf_challenge_token(ip, ts, secret) == token {
            return true;
        }
    }
    false
}
