//! Backend factory: select the right KEK backend for this platform/tier.
//!
//! Hardware backends are gated behind cargo features and never linked
//! into builds that don't request them.

use crate::errors::{BabbleonError, Result};
use crate::vault::backend::KekBackend;
use crate::vault::soft::SoftBackend;
use crate::vault::usb::UsbBackend;
use std::path::Path;

pub enum Tier {
    Soft,
    Usb,
    #[cfg(feature = "tpm")]
    Tpm,
    #[cfg(feature = "fido2")]
    Fido2,
}

pub fn for_tier(tier: Tier, keyfile: Option<&Path>) -> Result<Box<dyn KekBackend>> {
    match tier {
        Tier::Soft => Ok(Box::new(SoftBackend::default())),
        Tier::Usb => {
            let p = keyfile
                .ok_or_else(|| BabbleonError::HardwareUnavailable("usb requires keyfile".into()))?;
            Ok(Box::new(UsbBackend::new(p)))
        }
        #[cfg(feature = "tpm")]
        Tier::Tpm => Ok(Box::new(crate::vault::tpm::TpmBackend::new())),
        #[cfg(feature = "fido2")]
        Tier::Fido2 => Ok(Box::new(crate::vault::fido2::Fido2Backend::new())),
    }
}
