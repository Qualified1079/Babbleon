//! Per-host mapping: real_name -> scrambled compound, with rotation by epoch.
//!
//! - `fpe`: bijective permutation of `[0, N)` keyed by (host_secret, epoch).
//! - `mapper`: build a mapping table for a given tracked list + honey set.

pub mod fpe;
pub mod kdf;
mod mapper;

pub use mapper::{Mapper, MappingTable, COMPOUND_N, HONEY_COUNT, STALE_RETAIN_EPOCHS};
