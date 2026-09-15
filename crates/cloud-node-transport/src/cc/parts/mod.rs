//! Reusable congestion-control parts (plan §2: EdgeCC composes these;
//! the `reference` controllers consume the same code so bookkeeping
//! stays consistent between validation modes and the production path).

pub mod hystart;
pub mod prr;

pub use hystart::{HyStart, HystartVerdict};
pub use prr::Prr;
