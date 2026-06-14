//! Enforcement subsystem: drivers, views, wrappers.

pub mod driver;
pub mod factory;
pub mod simulated;
pub mod view;
pub mod wrapper;

#[cfg(target_os = "linux")]
pub mod landlock;
#[cfg(target_os = "linux")]
pub mod linux_ns;
#[cfg(target_os = "linux")]
pub mod seccomp;
#[cfg(target_os = "linux")]
pub(crate) mod syscalls;

pub use driver::{EnforcementDriver, EnforcementResult};
pub use simulated::SimulatedDriver;
pub use view::View;
