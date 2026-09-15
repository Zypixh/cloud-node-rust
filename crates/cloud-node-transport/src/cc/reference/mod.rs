//! Reference controllers — **validation modes, not production
//! algorithms** (plan §2.9). They exist to prove the bookkeeping
//! (RateSample/PRR/HyStart++) is correct and to serve as in-stack
//! baselines for the EdgeCC comparisons in T5/T10. There is no
//! production "algorithm selection" — the dataplane ships EdgeCC.

pub mod cubic;
pub mod new_reno;

pub use cubic::CubicRef;
pub use new_reno::NewRenoRef;
