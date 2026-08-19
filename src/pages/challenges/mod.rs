pub mod captcha;
pub mod click;
pub mod jscookie;
pub mod slider;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::Engine;
use rand::RngExt;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Type of challenge served to the user-agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    Slider,
    Click,
    Captcha,
    Pow,
    JsCookie,
}

impl ChallengeType {
    pub fn from_method(method: &str) -> Self {
        match method {
            "slider" => Self::Slider,
            "click" => Self::Click,
            "captcha" => Self::Captcha,
            "pow" => Self::Pow,
            "jscookie" => Self::JsCookie,
            _ => Self::Slider,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Slider => "slider",
            Self::Click => "click",
            Self::Captcha => "captcha",
            Self::Pow => "pow",
            Self::JsCookie => "jscookie",
        }
    }
}

// ── Token encode / decode (AES-256-GCM) ─────────────────────────

/// Encode a payload JSON into an encrypted, URL-safe token.
///
/// Format: `base64_urlsafe_nopad( 12-byte-AES-nonce ‖ AES-256-GCM-ciphertext )`
pub(crate) fn encode_challenge_token(payload: &Value, secret: &[u8]) -> String {
    let key = Sha256::digest(secret);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("valid AES-256 key");

    let mut aes_nonce = [0u8; 12];
    rand::rng().fill(&mut aes_nonce);
    let nonce = Nonce::from(aes_nonce);

    let plaintext = serde_json::to_string(payload).expect("payload serialization");
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .expect("AES-GCM encryption");

    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&aes_nonce);
    combined.extend_from_slice(&ciphertext);

    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&combined)
}

/// Decrypt and decode a challenge token back to its JSON payload.
///
/// Returns `None` when the token is malformed, tampered, or decryption fails.
pub(crate) fn decode_challenge_token(token: &str, secret: &[u8]) -> Option<Value> {
    let key = Sha256::digest(secret);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("valid AES-256 key");

    let combined = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .ok()?;
    if combined.len() < 12 {
        return None;
    }

    let (aes_nonce, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from(<[u8; 12]>::try_from(aes_nonce).ok()?);

    let plaintext = cipher.decrypt(&nonce, ciphertext).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

/// Check whether the payload's `e` (expiry unix-seconds) field has passed.
pub(crate) fn is_token_expired(payload: &Value) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    payload
        .get("e")
        .and_then(|v| v.as_u64())
        .map_or(true, |exp| now > exp)
}

/// Generate an 8-character random alphanumeric suffix for JS obfuscation.
pub(crate) fn random_suffix() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    (0..8)
        .map(|_| {
            let idx = rng.random_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}
