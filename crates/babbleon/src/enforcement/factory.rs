//! Driver selection: enterprise > linux-ns > simulated fallback.

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
