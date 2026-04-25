use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use pingora_core::protocols::tls::TlsRef as SslRef;
use pingora_core::tls::ext;
use pingora_core::tls::pkey::{PKey, Private};
use pingora_core::tls::ssl::NameType;
use pingora_core::tls::x509::X509;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::config_models::{SSLCertConfig, SSLPolicyConfig};

#[derive(Clone)]
pub struct DynamicCertSelector {
    pub exact: Arc<RwLock<HashMap<String, Arc<CertPair>>>>,
    pub wildcard: Arc<RwLock<HashMap<String, Arc<CertPair>>>>,
    pub default: Arc<RwLock<Option<Arc<CertPair>>>>,
    // Internal cache: ID -> (PEM_Hash, ParsedPair)
    cache: Arc<RwLock<HashMap<i64, (String, Arc<CertPair>)>>>,
}

#[derive(Clone)]
pub struct CertPair {
    pub id: i64,
    pub cert: X509,
    pub key: PKey<Private>,
    pub chain: Vec<X509>,
    pub ocsp: Arc<std::sync::RwLock<Vec<u8>>>,
}

impl DynamicCertSelector {
    pub fn new() -> Self {
        Self {
            exact: Arc::new(RwLock::new(HashMap::new())),
            wildcard: Arc::new(RwLock::new(HashMap::new())),
            default: Arc::new(RwLock::new(None)),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn update_config(&self, _servers: &[crate::config_models::ServerConfig]) {}

    pub async fn update_ocsp(&self, cert_id: i64, data: Vec<u8>) {
        let cache = self.cache.read().unwrap();
        for (_, pair) in cache.values() {
            if pair.id == cert_id {
                if let Ok(mut ocsp) = pair.ocsp.write() {
                    *ocsp = data.clone();
                }
            }
        }
    }

    pub async fn export_default_pem(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let default = self.default.read().unwrap();
        let pair = default.as_ref()?.clone();
        let cert_pem = pair.cert.to_pem().ok()?;
        let key_pem = pair.key.private_key_to_pem_pkcs8().ok()?;
        Some((cert_pem, key_pem))
    }

    pub async fn export_snapshot_pem(
        &self,
    ) -> Option<(
        std::collections::HashMap<String, (Vec<u8>, Vec<u8>, Vec<u8>)>,
        std::collections::HashMap<String, (Vec<u8>, Vec<u8>, Vec<u8>)>,
        (Vec<u8>, Vec<u8>, Vec<u8>),
    )> {
        let exact = self.exact.read().unwrap();
        let wildcard = self.wildcard.read().unwrap();
        let default = self.default.read().unwrap();

        let serialize = |pair: &Arc<CertPair>| -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            Some((
                pair.cert.to_pem().ok()?,
                pair.key.private_key_to_pem_pkcs8().ok()?,
                pair.ocsp.read().ok().map(|v| v.clone()).unwrap_or_default(),
            ))
        };

        let mut exact_out = std::collections::HashMap::new();
        for (name, pair) in exact.iter() {
            if let Some(serialized) = serialize(pair) {
                exact_out.insert(name.clone(), serialized);
            }
        }

        let mut wildcard_out = std::collections::HashMap::new();
        for (name, pair) in wildcard.iter() {
            if let Some(serialized) = serialize(pair) {
                wildcard_out.insert(name.clone(), serialized);
            }
        }

        let default_pair = serialize(default.as_ref()?)?;
        Some((exact_out, wildcard_out, default_pair))
    }

    pub fn apply_ocsp_for_ssl_blocking(&self, ssl: &mut SslRef) {
        let host = ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or("")
            .to_lowercase();
        if let Some(pair) = self.find_pair_blocking(&host) {
            if let Ok(ocsp) = pair.ocsp.read()
                && !ocsp.is_empty()
            {
                let _ = ssl.set_ocsp_status(&ocsp);
            }
        }
    }

    fn find_pair_blocking(&self, host: &str) -> Option<Arc<CertPair>> {
        if !host.is_empty() {
            let exact = self.exact.read().unwrap();
            if let Some(pair) = exact.get(host) {
                return Some(pair.clone());
            }
            drop(exact);

            if let Some(pos) = host.find('.') {
                let suffix = &host[pos..];
                let wildcard_key = format!("*{}", suffix);
                let wildcard = self.wildcard.read().unwrap();
                if let Some(pair) = wildcard.get(&wildcard_key) {
                    return Some(pair.clone());
                }
            }
        }

        self.default.read().unwrap().clone()
    }
}

pub async fn sync_certs(
    cert_selector: &DynamicCertSelector,
    certs: &[SSLCertConfig],
    ssl_policy: Option<&SSLPolicyConfig>,
) {
    if let Some(policy) = ssl_policy {
        if !policy.is_on {
            tracing::warn!("SSL policy is OFF, skipping certificate sync");
            return;
        }
    }

    let mut new_exact = HashMap::new();
    let mut new_wildcard = HashMap::new();
    let mut first_pair: Option<Arc<CertPair>> = None;

    // We'll prepare a new cache map based on existing one
    // We'll prepare a new cache map based on existing one
    let mut new_cache = HashMap::new();

    // Scoped read to avoid holding it during the whole loop if not needed,
    // but we need it for fingerprint comparison.
    // To fix the deadlock, we must ensure old_cache is dropped before write_lock.
    let (stats_parsed, stats_reused) = {
        let old_cache = cert_selector.cache.read().unwrap();

        let mut parsed = 0;
        let mut reused = 0;

        for cert_cfg in certs {
            if !cert_cfg.is_on {
                continue;
            }

            let cert_id = cert_cfg.id;

            if let (Some(c), Some(k)) = (&cert_cfg.cert_data_json, &cert_cfg.key_data_json) {
                if let (Some(cert_pem_raw), Some(key_pem_raw)) = (c.as_str(), k.as_str()) {
                    // --- FINGERPRINT CHECK ---
                    let current_fingerprint =
                        crate::utils::fnv_hash64(&format!("{}{}", cert_pem_raw, key_pem_raw))
                            .to_string();

                    let pair = if let Some((old_fp, old_pair)) = old_cache.get(&cert_id)
                        && *old_fp == current_fingerprint
                    {
                        reused += 1;
                        old_pair.clone()
                    } else {
                        // FULL/MISS: Parse the PEM data
                        let clean_pem = |s: &str| -> Vec<u8> {
                            if let Ok(decoded) = general_purpose::STANDARD.decode(s.trim()) {
                                return decoded;
                            }
                            s.replace("\\n", "\n").into_bytes()
                        };

                        let cert_bytes = clean_pem(cert_pem_raw);
                        let key_bytes = clean_pem(key_pem_raw);

                        let cert_chain = X509::stack_from_pem(&cert_bytes).ok();
                        let cert_res = X509::from_pem(&cert_bytes);
                        let key_res = PKey::private_key_from_pem(&key_bytes);

                        match (cert_res, key_res) {
                            (Ok(cert), Ok(key)) => Arc::new(CertPair {
                                id: cert_id,
                                cert,
                                key,
                                chain: cert_chain.unwrap_or_default(),
                                ocsp: Arc::new(std::sync::RwLock::new(Vec::new())),
                            }),
                            _ => {
                                tracing::error!(
                                    "SSL Parse Error for ID {}: Cert data invalid",
                                    cert_id
                                );
                                continue;
                            }
                        }
                    };

                    parsed += 1;
                    new_cache.insert(cert_id, (current_fingerprint, pair.clone()));

                    if first_pair.is_none() {
                        first_pair = Some(pair.clone());
                    }

                    // Map to domain lookups
                    let mut names = Vec::new();
                    if let Some(cn) = pair
                        .cert
                        .subject_name()
                        .entries_by_nid(pingora_core::tls::nid::Nid::COMMONNAME)
                        .next()
                        .and_then(|e| e.data().as_utf8().ok())
                    {
                        names.push(cn.to_string());
                    }
                    if let Some(sans) = pair.cert.subject_alt_names() {
                        for san in sans {
                            if let Some(dns) = san.dnsname() {
                                names.push(dns.to_string());
                            }
                        }
                    }

                    for name in names {
                        let name_low = name.to_lowercase();
                        if name_low.starts_with("*.") {
                            new_wildcard.insert(name_low, pair.clone());
                        } else {
                            new_exact.insert(name_low, pair.clone());
                        }
                    }
                }
            }
        }
        (parsed, reused)
    }; // old_cache dropped here

    {
        let mut exact_lock = cert_selector.exact.write().unwrap();
        let mut wildcard_lock = cert_selector.wildcard.write().unwrap();
        let mut default_lock = cert_selector.default.write().unwrap();
        let mut cache_lock = cert_selector.cache.write().unwrap();

        *exact_lock = new_exact;
        *wildcard_lock = new_wildcard;
        *default_lock = first_pair;
        *cache_lock = new_cache;
    }

    tracing::info!(
        "SSL Sync Result: {} certs processed (Reused: {}, Parsed: {}). Default Cert present: {}",
        stats_parsed,
        stats_reused,
        stats_parsed - stats_reused,
        cert_selector.default.read().unwrap().is_some()
    );
}

#[async_trait]
impl pingora_core::listeners::TlsAccept for DynamicCertSelector {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let host = ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or("")
            .to_lowercase();

        if !host.is_empty() {
            // 1. Exact Match
            {
                let exact = self.exact.read().unwrap();
                if let Some(pair) = exact.get(&host) {
                    let _ = ext::ssl_use_certificate(ssl, &pair.cert);
                    let _ = ext::ssl_use_private_key(ssl, &pair.key);
                    for cert in pair.chain.iter().skip(1) {
                        let _ = ext::ssl_add_chain_cert(ssl, cert);
                    }
                    if let Ok(ocsp) = pair.ocsp.read()
                        && !ocsp.is_empty()
                    {
                        let _ = ssl.set_ocsp_status(&ocsp);
                    }
                    return;
                }
            }

            // 2. Wildcard Match
            {
                if let Some(pos) = host.find('.') {
                    let suffix = &host[pos..];
                    let wildcard_key = format!("*{}", suffix);

                    let wildcard = self.wildcard.read().unwrap();
                    if let Some(pair) = wildcard.get(&wildcard_key) {
                        let _ = ext::ssl_use_certificate(ssl, &pair.cert);
                        let _ = ext::ssl_use_private_key(ssl, &pair.key);
                        for cert in pair.chain.iter().skip(1) {
                            let _ = ext::ssl_add_chain_cert(ssl, cert);
                        }
                        if let Ok(ocsp) = pair.ocsp.read()
                            && !ocsp.is_empty()
                        {
                            let _ = ssl.set_ocsp_status(&ocsp);
                        }
                        return;
                    }
                }
            }
            tracing::debug!(
                "No certificate match for SNI: {}, falling back to default",
                host
            );
        } else {
            tracing::debug!("No SNI provided, using default certificate");
        }

        // 3. Fallback to Default Certificate
        {
            let default = self.default.read().unwrap();
            if let Some(pair) = &*default {
                let _ = ext::ssl_use_certificate(ssl, &pair.cert);
                let _ = ext::ssl_use_private_key(ssl, &pair.key);
                for cert in pair.chain.iter().skip(1) {
                    let _ = ext::ssl_add_chain_cert(ssl, cert);
                }
                if let Ok(ocsp) = pair.ocsp.read()
                    && !ocsp.is_empty()
                {
                    let _ = ssl.set_ocsp_status(&ocsp);
                }
            } else {
                tracing::error!(
                    "No default certificate available for request (SNI: {})",
                    host
                );
            }
        }
    }
}
