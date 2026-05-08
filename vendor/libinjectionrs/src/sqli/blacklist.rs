// SQL injection blacklist checker - matches C implementation exactly

use super::sqli_data;

/// Check if a fingerprint is blacklisted
/// This matches libinjection_sqli_blacklist from the C version
pub fn is_blacklisted(fingerprint: &str) -> bool {
    // Match the C version: convert v0 fingerprint to v1 format
    // v0: up to 5 chars, mixed case  
    // v1: '0' prefix, up to 5 more chars, upper case
    
    if fingerprint.is_empty() {
        return false;
    }
    
    let mut fp2 = [0u8; 8];
    fp2[0] = b'0';
    let mut len = 1;
    for ch in fingerprint.bytes().take(7) {
        fp2[len] = ch.to_ascii_uppercase();
        len += 1;
    }

    core::str::from_utf8(&fp2[..len])
        .map(|fp| sqli_data::lookup_word(fp) == crate::sqli::TokenType::Fingerprint)
        .unwrap_or(false)
}