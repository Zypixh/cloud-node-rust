use rustls::crypto::CryptoProvider;
use std::sync::LazyLock;

static DEFAULT_PROVIDER: LazyLock<CryptoProvider> =
    LazyLock::new(rustls::crypto::aws_lc_rs::default_provider);

/// Shared process-wide rustls CryptoProvider (aws-lc-rs).
pub fn default_crypto_provider() -> CryptoProvider {
    DEFAULT_PROVIDER.clone()
}

/// Install the default CryptoProvider once per process.
pub fn install_default_crypto_provider() {
    let _ = CryptoProvider::install_default(default_crypto_provider());
}
