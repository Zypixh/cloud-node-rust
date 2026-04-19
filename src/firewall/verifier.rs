use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct ChallengePayload {
    ip: String,
    ua_hash: String,
    ts: u64,
    nonce: String,
}

pub struct WafVerifier {
    key: [u8; 32],
}

impl WafVerifier {
    pub fn new(secret: &str) -> Self {
        let mut key = [0u8; 32];
        let secret_bytes = secret.as_bytes();
        let len = secret_bytes.len().min(32);
        key[..len].copy_from_slice(&secret_bytes[..len]);
        Self { key }
    }

    /// Generates a cryptographically strong, authenticated WAF token
    pub fn generate_token(&self, ip: &str, ua: &str) -> String {
        let cipher = Aes256Gcm::new(&self.key.into());
        let nonce_bytes = rand::random::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut hasher = Sha256::new();
        hasher.update(ua.as_bytes());
        let ua_hash = hex::encode(hasher.finalize());

        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let payload = ChallengePayload {
            ip: ip.to_string(),
            ua_hash,
            ts,
            nonce: hex::encode(rand::random::<[u8; 8]>()),
        };

        let plaintext = serde_json::to_vec(&payload).unwrap();
        if let Ok(ciphertext) = cipher.encrypt(nonce, plaintext.as_ref()) {
            let mut combined = nonce_bytes.to_vec();
            combined.extend_from_slice(&ciphertext);
            let token_str = general_purpose::URL_SAFE_NO_PAD.encode(combined);
            
            // Persist for node restarts
            crate::metrics::storage::STORAGE.save_waf_token(&token_str, ip, &payload.ua_hash, ts + 3600);
            
            return token_str;
        }
        "".to_string()
    }

    /// Verifies the token and ensures it matches the requester's context
    pub fn verify_token(&self, ip: &str, ua: &str, token: &str, window_secs: u64) -> bool {
        // 1. Try local decryption (fast, stateless part)
        let mut hasher = Sha256::new();
        hasher.update(ua.as_bytes());
        let current_ua_hash = hex::encode(hasher.finalize());

        let cipher = Aes256Gcm::new(&self.key.into());
        let decoded = match general_purpose::URL_SAFE_NO_PAD.decode(token) {
            Ok(d) => d,
            Err(_) => {
                // FALLBACK: maybe it's only in RocksDB (e.g. if key rotated, though unlikely here)
                return self.verify_token_from_storage(ip, &current_ua_hash, token, window_secs);
            }
        };

        if decoded.len() < 12 { return self.verify_token_from_storage(ip, &current_ua_hash, token, window_secs); }
        let (nonce_bytes, ciphertext) = decoded.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = match cipher.decrypt(nonce, ciphertext) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let payload: ChallengePayload = match serde_json::from_slice(&plaintext) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Context Verification
        if payload.ip != ip { return false; }

        let mut hasher = Sha256::new();
        hasher.update(ua.as_bytes());
        let current_ua_hash = hex::encode(hasher.finalize());
        if payload.ua_hash != current_ua_hash { return false; }

        // Time Window Verification
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if now < payload.ts || now - payload.ts > window_secs {
            return false;
        }

        true
    }

    fn verify_token_from_storage(&self, ip: &str, ua_hash: &str, token: &str, _window_secs: u64) -> bool {
        if let Some(meta) = crate::metrics::storage::STORAGE.get_waf_token(token) {
            let stored_ip = meta["ip"].as_str().unwrap_or("");
            let stored_ua = meta["ua"].as_str().unwrap_or("");
            let exp = meta["exp"].as_u64().unwrap_or(0);
            
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            if stored_ip == ip && stored_ua == ua_hash && now < exp {
                return true;
            }
        }
        false
    }

    /// Validates a Proof-of-Work solution
    pub fn verify_pow(&self, challenge: &str, nonce: &str, difficulty: u32) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(challenge.as_bytes());
        hasher.update(nonce.as_bytes());
        let result = hex::encode(hasher.finalize());

        // Check if result starts with 'difficulty' number of zeros
        let prefix = "0".repeat(difficulty as usize);
        result.starts_with(&prefix)
    }

    /// Generates a JS-based PoW challenge
    pub fn get_pow_script(&self, challenge: &str, difficulty: u32) -> String {
        format!(
            r#"
            (function() {{
                const challenge = "{challenge}";
                const difficulty = {difficulty};
                const prefix = "0".repeat(difficulty);
                let nonce = 0;
                let start = Date.now();
                console.log("Antigravity WAF: Starting PoW challenge...");
                
                async fn solve() {{
                    while (true) {{
                        const check = challenge + nonce;
                        const encoder = new TextEncoder();
                        const data = encoder.encode(check);
                        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                        const hashArray = Array.from(new Uint8Array(hashBuffer));
                        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                        
                        if (hashHex.startsWith(prefix)) {{
                            console.log("Antigravity WAF: Solved in " + (Date.now() - start) + "ms");
                            document.cookie = "WAF-PoW=" + nonce + "; Path=/; Max-Age=3600";
                            window.location.reload();
                            return;
                        }}
                        nonce++;
                        if (nonce % 1000 === 0 && Date.now() - start > 10000) {{
                             // Fallback if taking too long (optional)
                        }}
                    }}
                }}
                solve();
            }})();
            "#
        )
    }
}
