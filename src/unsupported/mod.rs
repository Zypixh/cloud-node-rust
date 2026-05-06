//! Explicit placeholders for intentionally unsupported compatibility features.
//!
//! These modules are code-level markers. They prevent unsupported legacy features
//! from being mistaken for accidental omissions during future compatibility work.

pub mod auto_upgrade;
pub mod ip_library_update;
pub mod request_scripts;
pub mod static_files;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedFeature {
    pub code: &'static str,
    pub reason: &'static str,
}
