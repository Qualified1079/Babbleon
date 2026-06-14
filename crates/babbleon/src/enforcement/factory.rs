//! Driver selection: enterprise > linux-ns > simulated fallback.
//!
//! The fallback policy is deliberately *narrowing*: the most-isolating
//! driver the platform supports wins.  We never silently downgrade to
//! `SimulatedDriver` on Linux — if a real driver is unavailable the
//! caller sees that explicitly (via `driver_for(name)` returning `None`)
//! and decides whether to abort or proceed unsafely.

use super::driver::EnforcementDriver;
use super::simulated::SimulatedDriver;

pub fn default_driver() -> Box<dyn EnforcementDriver> {
    #[cfg(target_os = "linux")]
    {
        if crate::platform::has_unshare() {
            return Box::new(super::linux_ns::LinuxNamespaceDriver::default());
        }
    }
    Box::new(SimulatedDriver)
}

pub fn driver_for(name: &str) -> Option<Box<dyn EnforcementDriver>> {
    match name {
        "simulated" => Some(Box::new(SimulatedDriver)),
        #[cfg(target_os = "linux")]
        "linux-ns" => Some(Box::new(super::linux_ns::LinuxNamespaceDriver::default())),
        _ => None,
    }
}
