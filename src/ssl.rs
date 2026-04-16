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

use crate::config_models::SSLCertConfig;

#[derive(Clone)]
pub struct DynamicCertSelector {
    pub exact: Arc<RwLock<HashMap<String, CertPair>>>,
    pub wildcard: Arc<RwLock<HashMap<String, CertPair>>>,
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
    ssl_policy: &serde_json::Value,
) {
    if let Some(is_on) = ssl_policy.get("isOn").and_then(|v| v.as_bool()) {
        if !is_on { return; }
    }

    let mut new_exact = HashMap::new();
    let mut new_wildcard = HashMap::new();

    for cert_cfg in certs {
        if !cert_cfg.is_on { continue; }
        if let (Some(c), Some(k)) = (&cert_cfg.cert_data_json, &cert_cfg.key_data_json) {
            if let (Some(cert_pem_b64), Some(key_pem_b64)) = (c.as_str(), k.as_str()) {
                let cert_res = match general_purpose::STANDARD.decode(cert_pem_b64) {
                    Ok(data) => X509::from_pem(&data),
                    Err(_) => X509::from_pem(cert_pem_b64.as_bytes()),
                };

                let key_res = match general_purpose::STANDARD.decode(key_pem_b64) {
                    Ok(data) => PKey::private_key_from_pem(&data),
                    Err(_) => PKey::private_key_from_pem(key_pem_b64.as_bytes()),
                };

                if let (Ok(cert), Ok(key)) = (cert_res, key_res) {
                    let name = cert.subject_name().entries_by_nid(pingora_core::tls::nid::Nid::COMMONNAME)
                        .next()
                        .and_then(|e| e.data().as_utf8().ok())
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    
                    let pair = CertPair { cert, key };
                    if name.starts_with("*.") {
                        new_wildcard.insert(name, pair);
                    } else {
                        new_exact.insert(name, pair);
                    }
                }
            }
        }
    }

    let mut exact_lock = cert_selector.exact.write().await;
    let mut wildcard_lock = cert_selector.wildcard.write().await;
    *exact_lock = new_exact;
    *wildcard_lock = new_wildcard;
}

#[async_trait]
impl pingora_core::listeners::TlsAccept for DynamicCertSelector {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        // Pingora uses SslRef from openssl/boringssl under the hood.
        let host = ssl.servername(NameType::HOST_NAME).unwrap_or("");
        let exact = self.exact.read().await;
        
        if let Some(pair) = exact.get(host) {
            let _ = ext::ssl_use_certificate(ssl, &pair.cert);
            let _ = ext::ssl_use_private_key(ssl, &pair.key);
        }
    }
}
