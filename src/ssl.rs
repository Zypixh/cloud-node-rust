use arc_swap::ArcSwap;
use base64::{Engine as _, engine::general_purpose};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, RwLock};
use x509_parser::prelude::*;

use crate::config_models::SSLCertConfig;

#[derive(Clone)]
pub struct DynamicCertSelector {
    snapshot: Arc<ArcSwap<CertSnapshot>>,
    cache: Arc<RwLock<HashMap<i64, (String, Arc<CertPair>)>>>,
}

impl std::fmt::Debug for DynamicCertSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicCertSelector")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
struct CertSnapshot {
    exact: HashMap<String, Arc<CertPair>>,
    wildcard: HashMap<String, Arc<CertPair>>,
    default: Option<Arc<CertPair>>,
}

#[derive(Clone, Debug)]
pub struct CertPair {
    pub id: i64,
    certified_key: Arc<CertifiedKey>,
    cert_bytes: Vec<u8>,
    key_bytes: Vec<u8>,
    ocsp: Arc<ArcSwap<Vec<u8>>>,
}

impl DynamicCertSelector {
    pub fn new() -> Self {
        let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());
        Self {
            snapshot: Arc::new(ArcSwap::from_pointee(CertSnapshot::default())),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn update_config(&self, _servers: &[crate::config_models::ServerConfig]) {}

    pub async fn update_ocsp(&self, cert_id: i64, data: Vec<u8>) {
        let cache = self.cache.read().unwrap();
        for (_, pair) in cache.values() {
            if pair.id == cert_id {
                pair.ocsp.store(Arc::new(data.clone()));
            }
        }
    }

    pub async fn export_default_pem(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let snapshot = self.snapshot.load();
        let pair = snapshot.default.as_ref()?.clone();
        Some((pair.cert_bytes.clone(), pair.key_bytes.clone()))
    }

    pub fn export_pair_pem_for_host(&self, host: &str) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        self.find_pair_blocking(&host.to_ascii_lowercase())
            .map(|pair| serialize_pair_pem(&pair))
    }

    pub fn export_default_pair_pem(&self) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let snapshot = self.snapshot.load();
        Some(serialize_pair_pem(snapshot.default.as_ref()?))
    }

    pub async fn export_snapshot_pem(
        &self,
    ) -> Option<(
        std::collections::HashMap<String, (Vec<u8>, Vec<u8>, Vec<u8>)>,
        std::collections::HashMap<String, (Vec<u8>, Vec<u8>, Vec<u8>)>,
        (Vec<u8>, Vec<u8>, Vec<u8>),
    )> {
        let snapshot = self.snapshot.load();

        let mut exact_out = std::collections::HashMap::new();
        for (name, pair) in snapshot.exact.iter() {
            exact_out.insert(name.clone(), serialize_pair_pem(pair));
        }

        let mut wildcard_out = std::collections::HashMap::new();
        for (name, pair) in snapshot.wildcard.iter() {
            wildcard_out.insert(name.clone(), serialize_pair_pem(pair));
        }

        let default_pair = serialize_pair_pem(snapshot.default.as_ref()?);
        Some((exact_out, wildcard_out, default_pair))
    }

    pub fn resolve_certified_key_for_host(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        self.find_pair_blocking(&host.to_ascii_lowercase())
            .map(|pair| pair.certified_key_with_ocsp())
    }

    pub fn has_default_cert(&self) -> bool {
        self.snapshot.load().default.is_some()
    }

    fn find_pair_blocking(&self, host: &str) -> Option<Arc<CertPair>> {
        let snapshot = self.snapshot.load();
        if !host.is_empty() {
            if let Some(pair) = snapshot.exact.get(host) {
                return Some(pair.clone());
            }

            if let Some(pos) = host.find('.') {
                let suffix = &host[pos..];
                let wildcard_key = format!("*{}", suffix);
                if let Some(pair) = snapshot.wildcard.get(&wildcard_key) {
                    return Some(pair.clone());
                }
            }
        }

        snapshot.default.clone()
    }

    #[doc(hidden)]
    pub fn bench_find_pair(&self, host: &str) -> bool {
        self.find_pair_blocking(host).is_some()
    }
}

impl ResolvesServerCert for DynamicCertSelector {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolve_certified_key_for_host(client_hello.server_name().unwrap_or(""))
    }
}

pub fn build_rustls_server_config(
    cert_selector: Arc<DynamicCertSelector>,
    alpn_protocols: Vec<Vec<u8>>,
    tls13_only: bool,
) -> anyhow::Result<rustls::ServerConfig> {
    anyhow::ensure!(
        cert_selector.has_default_cert(),
        "no certificate snapshot available for TLS listener"
    );

    let provider = rustls::crypto::ring::default_provider();
    let builder = rustls::ServerConfig::builder_with_provider(provider.into());
    let builder = if tls13_only {
        builder.with_protocol_versions(&[&rustls::version::TLS13])?
    } else {
        builder.with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])?
    };
    let resolver: Arc<dyn ResolvesServerCert> = cert_selector;
    let mut config = builder.with_no_client_auth().with_cert_resolver(resolver);
    config.alpn_protocols = alpn_protocols;
    Ok(config)
}

impl CertPair {
    fn certified_key_with_ocsp(&self) -> Arc<CertifiedKey> {
        let ocsp = self.ocsp.load();
        if ocsp.is_empty() {
            return Arc::clone(&self.certified_key);
        }

        let mut certified_key = (*self.certified_key).clone();
        certified_key.ocsp = Some(ocsp.as_ref().clone());
        Arc::new(certified_key)
    }
}

fn serialize_pair_pem(pair: &Arc<CertPair>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        pair.cert_bytes.clone(),
        pair.key_bytes.clone(),
        pair.ocsp.load().as_ref().clone(),
    )
}

pub async fn sync_certs(cert_selector: &DynamicCertSelector, certs: &[SSLCertConfig]) {
    let mut new_exact = HashMap::new();
    let mut new_wildcard = HashMap::new();
    let mut first_pair: Option<Arc<CertPair>> = None;
    let mut new_cache = HashMap::new();

    let (stats_parsed, stats_reused) = {
        let old_cache = cert_selector.cache.read().unwrap();
        let mut parsed = 0;
        let mut reused = 0;

        for cert_cfg in certs {
            if !cert_cfg.is_on {
                continue;
            }

            let cert_id = cert_cfg.id;
            let (Some(c), Some(k)) = (&cert_cfg.cert_data_json, &cert_cfg.key_data_json) else {
                continue;
            };
            let (Some(cert_bytes), Some(key_bytes)) =
                (cert_value_to_bytes(c), cert_value_to_bytes(k))
            else {
                tracing::error!(
                    "SSL Parse Error for ID {}: unsupported certificate/key JSON shape (cert_type={}, key_type={})",
                    cert_id,
                    json_value_kind(c),
                    json_value_kind(k)
                );
                continue;
            };

            let current_fingerprint =
                fnv_hash64_bytes([cert_bytes.as_slice(), key_bytes.as_slice()].as_slice())
                    .to_string();

            let pair = if let Some((old_fp, old_pair)) = old_cache.get(&cert_id)
                && *old_fp == current_fingerprint
            {
                reused += 1;
                old_pair.clone()
            } else {
                match parse_cert_pair(cert_id, cert_bytes.clone(), key_bytes.clone()) {
                    Ok(pair) => Arc::new(pair),
                    Err(err) => {
                        tracing::error!(
                            "SSL Parse Error for ID {}: certificate/key data invalid (cert_type={}, key_type={}): {}",
                            cert_id,
                            json_value_kind(c),
                            json_value_kind(k),
                            err
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

            let mut names = certificate_names_from_der(pair.certified_key.cert.first());
            names.extend(
                cert_cfg
                    .dns_names
                    .iter()
                    .map(|name| name.trim())
                    .filter(|name| !name.is_empty())
                    .map(ToString::to_string),
            );

            for name in names {
                let name_low = name.to_lowercase();
                if name_low.starts_with("*.") {
                    new_wildcard.insert(name_low, pair.clone());
                } else {
                    new_exact.insert(name_low, pair.clone());
                }
            }
        }
        (parsed, reused)
    };

    let new_snapshot = CertSnapshot {
        exact: new_exact,
        wildcard: new_wildcard,
        default: first_pair,
    };
    let default_present = new_snapshot.default.is_some();
    let mut cache_lock = cert_selector.cache.write().unwrap();
    *cache_lock = new_cache;
    cert_selector.snapshot.store(Arc::new(new_snapshot));

    tracing::info!(
        "SSL Sync Result: {} certs processed (Reused: {}, Parsed: {}). Default Cert present: {}",
        stats_parsed,
        stats_reused,
        stats_parsed - stats_reused,
        default_present
    );
}

fn parse_cert_pair(
    cert_id: i64,
    cert_bytes: Vec<u8>,
    key_bytes: Vec<u8>,
) -> anyhow::Result<CertPair> {
    let cert_chain = parse_cert_chain(&cert_bytes)?;
    let key = parse_private_key(&key_bytes)?;
    let provider = rustls::crypto::ring::default_provider();
    let certified_key = CertifiedKey::from_der(cert_chain, key, &provider)?;

    Ok(CertPair {
        id: cert_id,
        certified_key: Arc::new(certified_key),
        cert_bytes,
        key_bytes,
        ocsp: Arc::new(ArcSwap::from_pointee(Vec::new())),
    })
}

pub(crate) fn parse_cert_chain(bytes: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    if looks_like_pem(bytes) {
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut Cursor::new(bytes)).collect::<Result<_, _>>()?;
        anyhow::ensure!(!certs.is_empty(), "certificate chain is empty");
        return Ok(certs);
    }

    Ok(vec![CertificateDer::from(bytes.to_vec())])
}

pub(crate) fn parse_private_key(bytes: &[u8]) -> anyhow::Result<PrivateKeyDer<'static>> {
    if looks_like_pem(bytes) {
        return rustls_pemfile::private_key(&mut Cursor::new(bytes))?
            .ok_or_else(|| anyhow::anyhow!("private key is missing from PEM"));
    }

    PrivateKeyDer::try_from(bytes.to_vec()).map_err(|err| anyhow::anyhow!(err))
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    bytes
        .windows(b"-----BEGIN ".len())
        .any(|w| w == b"-----BEGIN ")
}

fn certificate_names_from_der(cert: Option<&CertificateDer<'static>>) -> Vec<String> {
    let Some(cert) = cert else {
        return Vec::new();
    };
    let Ok((_, parsed)) = X509Certificate::from_der(cert.as_ref()) else {
        return Vec::new();
    };

    let mut names = Vec::new();
    if let Some(cn) = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
    {
        names.push(cn.to_string());
    }

    if let Ok(Some(sans)) = parsed.subject_alternative_name() {
        for name in &sans.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                names.push((*dns).to_string());
            }
        }
    }

    names
}

fn cert_value_to_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::String(raw) => cert_string_to_bytes(raw),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let byte = item.as_u64()?;
                if byte > u8::MAX as u64 {
                    return None;
                }
                out.push(byte as u8);
            }
            if out.is_empty() { None } else { Some(out) }
        }
        Value::Object(map) => {
            for key in [
                "data", "value", "bytes", "pem", "content", "certData", "keyData",
            ] {
                if let Some(inner) = map.get(key)
                    && let Some(bytes) = cert_value_to_bytes(inner)
                {
                    return Some(bytes);
                }
            }
            None
        }
        _ => None,
    }
}

fn cert_string_to_bytes(raw: &str) -> Option<Vec<u8>> {
    let normalized = raw.replace("\\n", "\n");
    let trimmed = normalized.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(encoded) = trimmed.strip_prefix("base64:") {
        return decode_base64(encoded.trim()).or_else(|| Some(trimmed.as_bytes().to_vec()));
    }

    if trimmed.contains("-----BEGIN ") {
        return Some(normalized.into_bytes());
    }

    decode_base64(trimmed).or_else(|| Some(normalized.into_bytes()))
}

fn decode_base64(raw: &str) -> Option<Vec<u8>> {
    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    general_purpose::STANDARD
        .decode(compact.as_bytes())
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(compact.as_bytes()))
        .ok()
}

fn json_value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn fnv_hash64_bytes(chunks: &[&[u8]]) -> u64 {
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;
    let mut hash = FNV_OFFSET;
    for chunk in chunks {
        for byte in *chunk {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    hash
}
