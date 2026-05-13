use aes::Aes256;
use base64::{Engine as _, engine::general_purpose};
use cfb_mode::Encryptor;
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use md5::{Digest, Md5};
use std::fmt::Write;

type Aes256CfbEnc = Encryptor<Aes256>;

fn lower_hex_eq(digest: &[u8], expected: &str) -> bool {
    if expected.len() != digest.len() * 2 {
        return false;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let expected = expected.as_bytes();
    for (i, &byte) in digest.iter().enumerate() {
        if expected[i * 2] != HEX[(byte >> 4) as usize]
            || expected[i * 2 + 1] != HEX[(byte & 0x0f) as usize]
        {
            return false;
        }
    }
    true
}

/// Generates the base64 AES256-CFB encrypted token required by the API node.
/// Uses deterministic key/IV derivation compatible with the control-plane decodeToken().
pub fn generate_token(node_id: &str, secret: &str, node_type: &str) -> anyhow::Result<String> {
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
    let mut payload = String::with_capacity(48);
    write!(
        &mut payload,
        r#"{{"timestamp":{},"type":"{}","userId":0}}"#,
        timestamp, node_type
    )
    .expect("writing to String should not fail");

    let mut data = payload.into_bytes();
    let cipher = Aes256CfbEnc::new_from_slices(&key, &iv)
        .map_err(|e| anyhow::anyhow!("Invalid cipher init: {}", e))?;

    cipher.encrypt(&mut data);

    Ok(general_purpose::STANDARD.encode(&data))
}

/// URL Auth Verification (Types A, B, C, D)
/// This module implements CDN-compatible URL authentication signatures.
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
    let mut parts = auth_token.split('-');
    let Some(timestamp_str) = parts.next() else {
        return false;
    };
    let Some(rand) = parts.next() else {
        return false;
    };
    let Some(uid) = parts.next() else {
        return false;
    };
    let Some(md5hash) = parts.next() else {
        return false;
    };

    let timestamp = timestamp_str.parse::<i64>().unwrap_or(0);
    let now = crate::utils::time::now_timestamp();
    if (now - timestamp).abs() > config.life {
        return false;
    }

    let mut hasher = Md5::new();
    hasher.update(path.as_bytes());
    hasher.update(b"-");
    hasher.update(timestamp_str.as_bytes());
    hasher.update(b"-");
    hasher.update(rand.as_bytes());
    hasher.update(b"-");
    hasher.update(uid.as_bytes());
    hasher.update(config.secret.as_bytes());
    let result = hasher.finalize();
    lower_hex_eq(&result, md5hash)
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
    lower_hex_eq(&result, md5hash)
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
    lower_hex_eq(&result, md5hash)
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
    lower_hex_eq(&result, sign)
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
    lower_hex_eq(&result, auth_key)
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
        let mut hasher = Md5::new();
        hasher.update(ip.as_bytes());
        hasher.update(ts.to_string().as_bytes());
        hasher.update(secret.as_bytes());
        let result = hasher.finalize();
        if lower_hex_eq(&result, token) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn md5_hex(parts: &[&[u8]]) -> String {
        let mut hasher = Md5::new();
        for part in parts {
            hasher.update(part);
        }
        hex::encode(hasher.finalize())
    }

    fn md5_digest(parts: &[&[u8]]) -> md5::digest::Output<Md5> {
        let mut hasher = Md5::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize()
    }

    #[test]
    fn lower_hex_eq_matches_lowercase_md5_only() {
        let digest = md5_digest(&[b"hello"]);
        assert!(lower_hex_eq(&digest, "5d41402abc4b2a76b9719d911017c592"));
        assert!(!lower_hex_eq(&digest, "5D41402ABC4B2A76B9719D911017C592"));
        assert!(!lower_hex_eq(&digest, "short"));
    }

    #[test]
    fn verify_type_a_preserves_signature_formula() {
        let now = crate::utils::time::now_timestamp();
        let path = "/video/test.mp4";
        let secret = "very-secret-key";
        let timestamp = now.to_string();
        let hash = md5_hex(&[
            path.as_bytes(),
            b"-",
            timestamp.as_bytes(),
            b"-",
            b"rand",
            b"-",
            b"123",
            secret.as_bytes(),
        ]);
        let query = format!("auth_key={timestamp}-rand-123-{hash}");
        let config = UrlAuthConfig {
            auth_type: "A".to_string(),
            secret: secret.to_string(),
            param_name: "auth_key".to_string(),
            life: 3600,
        };

        assert!(verify_url_auth(path, &query, &config));

        let uppercase_query = format!(
            "auth_key={timestamp}-rand-123-{}",
            hash.to_ascii_uppercase()
        );
        assert!(!verify_url_auth(path, &uppercase_query, &config));

        let expired = now - config.life - 1;
        let expired_str = expired.to_string();
        let expired_hash = md5_hex(&[
            path.as_bytes(),
            b"-",
            expired_str.as_bytes(),
            b"-",
            b"rand",
            b"-",
            b"123",
            secret.as_bytes(),
        ]);
        let expired_query = format!("auth_key={expired_str}-rand-123-{expired_hash}");
        assert!(!verify_url_auth(path, &expired_query, &config));
    }

    #[test]
    fn verify_type_b_c_d_f_preserve_signature_formulas() {
        let now = crate::utils::time::now_timestamp();
        let timestamp_hex = format!("{now:x}");
        let real_path = "/video/test.mp4";
        let secret = "very-secret-key";

        let b_hash = md5_hex(&[
            secret.as_bytes(),
            timestamp_hex.as_bytes(),
            real_path.as_bytes(),
        ]);
        let b_path = format!("/{timestamp_hex}/{b_hash}{real_path}");
        let b_config = UrlAuthConfig {
            auth_type: "B".to_string(),
            secret: secret.to_string(),
            param_name: "auth_key".to_string(),
            life: 3600,
        };
        assert!(verify_url_auth(&b_path, "", &b_config));

        let timestamp = now.to_string();
        let c_hash = md5_hex(&[
            secret.as_bytes(),
            real_path.as_bytes(),
            timestamp.as_bytes(),
        ]);
        let c_path = format!("/{c_hash}/{timestamp}{real_path}");
        let c_config = UrlAuthConfig {
            auth_type: "C".to_string(),
            secret: secret.to_string(),
            param_name: "auth_key".to_string(),
            life: 3600,
        };
        assert!(verify_url_auth(&c_path, "", &c_config));

        let d_hash = md5_hex(&[
            secret.as_bytes(),
            real_path.as_bytes(),
            timestamp.as_bytes(),
        ]);
        let d_query = format!("sign={d_hash}&t={timestamp}");
        let d_config = UrlAuthConfig {
            auth_type: "D".to_string(),
            secret: secret.to_string(),
            param_name: "auth_key".to_string(),
            life: 3600,
        };
        assert!(verify_url_auth(real_path, &d_query, &d_config));

        let f_hash = md5_hex(&[
            real_path.as_bytes(),
            secret.as_bytes(),
            timestamp.as_bytes(),
        ]);
        let f_query = format!("auth_key={f_hash}&timestamp={timestamp}");
        let f_config = UrlAuthConfig {
            auth_type: "F".to_string(),
            secret: secret.to_string(),
            param_name: "auth_key".to_string(),
            life: 3600,
        };
        assert!(verify_url_auth(real_path, &f_query, &f_config));
    }

    #[test]
    fn unknown_auth_type_still_allows() {
        let config = UrlAuthConfig {
            auth_type: "unknown".to_string(),
            secret: "secret".to_string(),
            param_name: "auth_key".to_string(),
            life: 3600,
        };

        assert!(verify_url_auth("/path", "", &config));
    }
}
