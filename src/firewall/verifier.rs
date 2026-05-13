use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub struct ChallengeFailureConfig {
    pub max_fails: i32,
    pub fail_block_timeout: i64,
    pub fail_global: bool,
}

#[derive(Serialize, Deserialize)]
struct ChallengePayload {
    ip: String,
    ua_hash: String,
    ts: u64,
    #[serde(default)]
    exp: Option<u64>,
    nonce: String,
    #[serde(default)]
    version: u8,
    #[serde(default)]
    max_fails: i32,
    #[serde(default)]
    fail_block_timeout: i64,
    #[serde(default)]
    fail_global: bool,
}

pub struct WafVerifier {
    key: [u8; 32],
    legacy_key: [u8; 32],
}

impl WafVerifier {
    pub fn new(secret: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let digest = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);

        let mut legacy_key = [0u8; 32];
        let secret_bytes = secret.as_bytes();
        let len = secret_bytes.len().min(32);
        legacy_key[..len].copy_from_slice(&secret_bytes[..len]);
        Self { key, legacy_key }
    }

    /// Generates a cryptographically strong, authenticated WAF token
    pub fn generate_token(&self, ip: &str, ua: &str) -> String {
        self.generate_token_with_life(ip, ua, 3600)
    }

    pub fn generate_token_with_life(&self, ip: &str, ua: &str, life_seconds: u64) -> String {
        self.generate_token_with_config(
            ip,
            ua,
            life_seconds,
            ChallengeFailureConfig {
                max_fails: 0,
                fail_block_timeout: 0,
                fail_global: false,
            },
        )
    }

    pub fn generate_token_with_config(
        &self,
        ip: &str,
        ua: &str,
        life_seconds: u64,
        failure_config: ChallengeFailureConfig,
    ) -> String {
        let cipher = Aes256Gcm::new(&self.key.into());
        let nonce_bytes = rand::random::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut hasher = Sha256::new();
        hasher.update(ua.as_bytes());
        let ua_hash = hex::encode(hasher.finalize());

        let ts = crate::utils::time::now_timestamp() as u64;
        let exp = ts.saturating_add(life_seconds.max(1));
        let payload = ChallengePayload {
            ip: ip.to_string(),
            ua_hash,
            ts,
            exp: Some(exp),
            nonce: hex::encode(rand::random::<[u8; 8]>()),
            version: 1,
            max_fails: failure_config.max_fails.max(0),
            fail_block_timeout: failure_config.fail_block_timeout.max(0),
            fail_global: failure_config.fail_global,
        };

        let plaintext = serde_json::to_vec(&payload).unwrap();
        if let Ok(ciphertext) = cipher.encrypt(nonce, plaintext.as_ref()) {
            let mut combined = nonce_bytes.to_vec();
            combined.extend_from_slice(&ciphertext);
            let token_str = general_purpose::URL_SAFE_NO_PAD.encode(combined);

            crate::metrics::storage::STORAGE.save_waf_token(&token_str, ip, &payload.ua_hash, exp);

            return token_str;
        }
        "".to_string()
    }

    /// Verifies the token and ensures it matches the requester's context
    pub fn verify_token(&self, ip: &str, ua: &str, token: &str, window_secs: u64) -> bool {
        self.token_seconds_remaining(ip, ua, token, window_secs)
            .is_some()
    }

    pub fn token_seconds_remaining(
        &self,
        ip: &str,
        ua: &str,
        token: &str,
        window_secs: u64,
    ) -> Option<u64> {
        let current_ua_hash = Self::ua_hash(ua);
        let decoded = match general_purpose::URL_SAFE_NO_PAD.decode(token) {
            Ok(d) => d,
            Err(_) => {
                return self.token_seconds_remaining_from_storage(ip, &current_ua_hash, token);
            }
        };

        if decoded.len() < 12 {
            return self.token_seconds_remaining_from_storage(ip, &current_ua_hash, token);
        }
        let (nonce_bytes, ciphertext) = decoded.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let payload = self
            .decrypt_payload(&self.key, nonce, ciphertext)
            .or_else(|| self.decrypt_payload(&self.legacy_key, nonce, ciphertext))?;

        if payload.ip != ip || payload.ua_hash != current_ua_hash {
            return None;
        }

        let now = crate::utils::time::now_timestamp() as u64;
        if now < payload.ts {
            return None;
        }
        if let Some(exp) = payload.exp {
            return (now <= exp).then_some(exp.saturating_sub(now).max(1));
        }
        (now - payload.ts <= window_secs)
            .then_some(window_secs.saturating_sub(now - payload.ts).max(1))
    }

    pub fn token_failure_config(
        &self,
        ip: &str,
        ua: &str,
        token: &str,
    ) -> Option<ChallengeFailureConfig> {
        let current_ua_hash = Self::ua_hash(ua);
        let decoded = general_purpose::URL_SAFE_NO_PAD.decode(token).ok()?;
        if decoded.len() < 12 {
            return None;
        }
        let (nonce_bytes, ciphertext) = decoded.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let payload = self
            .decrypt_payload(&self.key, nonce, ciphertext)
            .or_else(|| self.decrypt_payload(&self.legacy_key, nonce, ciphertext))?;
        if payload.ip != ip || payload.ua_hash != current_ua_hash {
            return None;
        }
        if let Some(exp) = payload.exp
            && crate::utils::time::now_timestamp() as u64 > exp
        {
            return None;
        }
        Some(ChallengeFailureConfig {
            max_fails: payload.max_fails.max(0),
            fail_block_timeout: payload.fail_block_timeout.max(0),
            fail_global: payload.fail_global,
        })
    }

    fn decrypt_payload(
        &self,
        key: &[u8; 32],
        nonce: &Nonce<aes_gcm::aead::consts::U12>,
        ciphertext: &[u8],
    ) -> Option<ChallengePayload> {
        let cipher = Aes256Gcm::new(key.into());
        let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;
        serde_json::from_slice(&plaintext).ok()
    }

    fn ua_hash(ua: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(ua.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn token_seconds_remaining_from_storage(
        &self,
        ip: &str,
        ua_hash: &str,
        token: &str,
    ) -> Option<u64> {
        let meta = crate::metrics::storage::STORAGE.get_waf_token(token)?;
        let stored_ip = meta["ip"].as_str().unwrap_or("");
        let stored_ua = meta["ua"].as_str().unwrap_or("");
        let exp = meta["exp"].as_u64().unwrap_or(0);
        let now = crate::utils::time::now_timestamp() as u64;

        (stored_ip == ip && stored_ua == ua_hash && now <= exp)
            .then_some(exp.saturating_sub(now).max(1))
    }

    /// Validates a Proof-of-Work solution
    pub fn verify_pow(&self, challenge: &str, nonce: &str, difficulty: u32) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(challenge.as_bytes());
        hasher.update(nonce.as_bytes());
        let result = hex::encode(hasher.finalize());

        let prefix = "0".repeat(difficulty.min(8) as usize);
        result.starts_with(&prefix)
    }

    pub fn slider_target(&self, token: &str) -> u32 {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hasher.update(b":slider-target");
        let digest = hasher.finalize();
        44 + (u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 173)
    }

    pub fn verify_slider_trace(
        &self,
        token: &str,
        final_x: i32,
        elapsed_ms: u64,
        trace: &str,
    ) -> bool {
        if elapsed_ms < 650 || elapsed_ms > 120_000 {
            return false;
        }
        let target = self.slider_target(token) as i32;
        if (final_x - target).abs() > 12 {
            return false;
        }
        let samples: Vec<(i32, u64)> = trace
            .split(';')
            .filter_map(|sample| {
                let mut parts = sample.split(',');
                let x = parts.next()?.parse::<i32>().ok()?;
                let t = parts.next()?.parse::<u64>().ok()?;
                Some((x, t))
            })
            .take(96)
            .collect();
        if samples.len() < 6 {
            return false;
        }
        let first_t = samples.first().map(|(_, t)| *t).unwrap_or(0);
        let last_t = samples.last().map(|(_, t)| *t).unwrap_or(0);
        if last_t <= first_t || last_t.saturating_sub(first_t) < 500 {
            return false;
        }
        let mut direction_changes = 0;
        let mut speed_changes = 0;
        let mut last_dx = 0i32;
        let mut last_speed = 0i64;
        for window in samples.windows(2) {
            let dx = window[1].0 - window[0].0;
            let dt = window[1].1.saturating_sub(window[0].1).max(1);
            if dx.signum() != 0 && last_dx.signum() != 0 && dx.signum() != last_dx.signum() {
                direction_changes += 1;
            }
            let speed = (dx.abs() as i64 * 1000) / dt as i64;
            if last_speed > 0 && (speed - last_speed).abs() > 80 {
                speed_changes += 1;
            }
            if dx != 0 {
                last_dx = dx;
            }
            last_speed = speed;
        }
        speed_changes >= 2 || direction_changes >= 1
    }

    /// Generates a JS-based PoW challenge
    pub fn get_pow_script(&self, challenge: &str, difficulty: u32) -> String {
        self.get_pow_script_with_life(challenge, difficulty, 3600)
    }

    pub fn get_pow_script_with_life(
        &self,
        challenge: &str,
        difficulty: u32,
        life_seconds: i64,
    ) -> String {
        let challenge = serde_json::to_string(challenge).unwrap_or_else(|_| "\"\"".to_string());
        let life_seconds = life_seconds.max(1);
        format!(
            r#"
            (function() {{
                const challenge = {challenge};
                const difficulty = {difficulty};
                const prefix = "0".repeat(difficulty);
                const encoder = new TextEncoder();
                let nonce = 0;
                let start = Date.now();

                async function solve() {{
                    while (true) {{
                        const data = encoder.encode(challenge + nonce);
                        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                        const hashArray = Array.from(new Uint8Array(hashBuffer));
                        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                        if (hashHex.startsWith(prefix)) {{
                            document.cookie = "WAF-PoW=" + nonce + "; Path=/; Max-Age={life_seconds}; SameSite=Lax";
                            window.location.reload();
                            return;
                        }}
                        nonce++;
                        if (nonce % 200 === 0) {{
                            await new Promise(resolve => setTimeout(resolve, 0));
                        }}
                    }}
                }}
                solve();
            }})();
            "#
        )
    }
}
