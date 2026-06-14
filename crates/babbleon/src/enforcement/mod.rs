//! Enforcement subsystem: drivers, views, wrappers.

pub mod driver;
pub mod factory;
pub mod simulated;
pub mod view;
pub mod wrapper;

#[cfg(target_os = "linux")]
pub mod linux_ns;
#[cfg(target_os = "linux")]
mod syscalls;

pub use driver::{EnforcementDriver, EnforcementResult};
pub use simulated::SimulatedDriver;
pub use view::View;
