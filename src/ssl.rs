use base64::{engine::general_purpose, Engine as _};
use pingora_core::tls::pkey::{PKey, Private};
use pingora_core::tls::x509::X509;
use pingora_core::tls::ssl::NameType;
use pingora_core::protocols::tls::TlsRef as SslRef;
use pingora_core::tls::ext;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use async_trait::async_trait;

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
    pub cert: X509,
    pub key: PKey<Private>,
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

    pub async fn update_config(&self, _servers: &[crate::config_models::ServerConfig]) {
    }

    pub async fn update_ocsp(&self, _cert_id: i64, _data: Vec<u8>) {
    }
}

pub async fn start_ocsp_syncer(_api_config: crate::api_config::ApiConfig, _selector: Arc<DynamicCertSelector>) {
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
        let old_cache = cert_selector.cache.read().await;

        let mut parsed = 0;
        let mut reused = 0;

        for cert_cfg in certs {
            if !cert_cfg.is_on { continue; }

            let cert_id = cert_cfg.id;

            if let (Some(c), Some(k)) = (&cert_cfg.cert_data_json, &cert_cfg.key_data_json) {
                if let (Some(cert_pem_raw), Some(key_pem_raw)) = (c.as_str(), k.as_str()) {

                    // --- FINGERPRINT CHECK ---
                    let current_fingerprint = crate::utils::fnv_hash64(&format!("{}{}", cert_pem_raw, key_pem_raw)).to_string();

                    let pair = if let Some((old_fp, old_pair)) = old_cache.get(&cert_id) && *old_fp == current_fingerprint {
                        reused += 1;
                        old_pair.clone()
                    } else {
                        // FULL/MISS: Parse the PEM data
                        let clean_pem = |s: &str| -> Vec<u8> {
                            if let Ok(decoded) = general_purpose::STANDARD.decode(s.trim()) { return decoded; }
                            s.replace("\\n", "\n").into_bytes()
                        };

                        let cert_bytes = clean_pem(cert_pem_raw);
                        let key_bytes = clean_pem(key_pem_raw);

                        let cert_res = X509::from_pem(&cert_bytes);
                        let key_res = PKey::private_key_from_pem(&key_bytes);

                        match (cert_res, key_res) {
                            (Ok(cert), Ok(key)) => Arc::new(CertPair { cert, key }),
                            _ => {
                                tracing::error!("SSL Parse Error for ID {}: Cert data invalid", cert_id);
                                continue;
                            }
                        }
                    };

                    parsed += 1;
                    new_cache.insert(cert_id, (current_fingerprint, pair.clone()));

                    if first_pair.is_none() { first_pair = Some(pair.clone()); }

                    // Map to domain lookups
                    let mut names = Vec::new();
                    if let Some(cn) = pair.cert.subject_name().entries_by_nid(pingora_core::tls::nid::Nid::COMMONNAME)
                        .next().and_then(|e| e.data().as_utf8().ok()) {
                        names.push(cn.to_string());
                    }
                    if let Some(sans) = pair.cert.subject_alt_names() {
                        for san in sans { if let Some(dns) = san.dnsname() { names.push(dns.to_string()); } }
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
        let mut exact_lock = cert_selector.exact.write().await;
        let mut wildcard_lock = cert_selector.wildcard.write().await;
        let mut default_lock = cert_selector.default.write().await;
        let mut cache_lock = cert_selector.cache.write().await;

        *exact_lock = new_exact;
        *wildcard_lock = new_wildcard;
        *default_lock = first_pair;
        *cache_lock = new_cache;
    }

    tracing::info!("SSL Sync Result: {} certs processed (Reused: {}, Parsed: {}). Default Cert present: {}", 
        stats_parsed, stats_reused, stats_parsed - stats_reused, cert_selector.default.read().await.is_some());
}

#[async_trait]
impl pingora_core::listeners::TlsAccept for DynamicCertSelector {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let host = ssl.servername(NameType::HOST_NAME).unwrap_or("").to_lowercase();
        
        if !host.is_empty() {
            // 1. Exact Match
            {
                let exact = self.exact.read().await;
                if let Some(pair) = exact.get(&host) {
                    let _ = ext::ssl_use_certificate(ssl, &pair.cert);
                    let _ = ext::ssl_use_private_key(ssl, &pair.key);
                    return;
                }
            }

            // 2. Wildcard Match
            {
                if let Some(pos) = host.find('.') {
                    let suffix = &host[pos..];
                    let wildcard_key = format!("*{}", suffix);
                    
                    let wildcard = self.wildcard.read().await;
                    if let Some(pair) = wildcard.get(&wildcard_key) {
                        let _ = ext::ssl_use_certificate(ssl, &pair.cert);
                        let _ = ext::ssl_use_private_key(ssl, &pair.key);
                        return;
                    }
                }
            }
            tracing::warn!("No certificate match for SNI: {}, falling back to default", host);
        } else {
            tracing::debug!("No SNI provided, using default certificate");
        }

        // 3. Fallback to Default Certificate
        {
            let default = self.default.read().await;
            if let Some(pair) = &*default {
                let _ = ext::ssl_use_certificate(ssl, &pair.cert);
                let _ = ext::ssl_use_private_key(ssl, &pair.key);
            } else {
                tracing::error!("No default certificate available for request (SNI: {})", host);
            }
        }
    }
}
