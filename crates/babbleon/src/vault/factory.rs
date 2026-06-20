//! Backend factory: select the right KEK backend for this host/tier.
//!
//! All variants always compile — hardware backends return
//! `BabbleonError::HardwareUnavailable` when the corresponding cargo
//! feature is off.  This keeps `Tier` a stable enum across builds so
//! vault headers can name the tier without conditional compilation
//! contaminating the API.

use crate::errors::{BabbleonError, Result};
use crate::vault::backend::KekBackend;
use crate::vault::fido2::Fido2Backend;
use crate::vault::soft::SoftBackend;
use crate::vault::tpm::TpmBackend;
use crate::vault::usb::UsbBackend;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Soft,
    SoftHeadless,
    Usb,
    Tpm,
    Fido2,
}

impl Tier {
    pub fn name(self) -> &'static str {
        match self {
            Tier::Soft => "soft",
            Tier::SoftHeadless => "soft-headless",
            Tier::Usb => "usb",
            Tier::Tpm => "tpm",
            Tier::Fido2 => "fido2",
        }
    }
}

pub fn for_tier(tier: Tier, keyfile: Option<&Path>) -> Result<Box<dyn KekBackend>> {
    match tier {
        Tier::Soft => Ok(Box::new(SoftBackend::with_profile(
            crate::vault::soft::Profile::Laptop,
        ))),
        Tier::SoftHeadless => Ok(Box::new(SoftBackend::with_profile(
            crate::vault::soft::Profile::Headless,
        ))),
        Tier::Usb => {
            let p = keyfile
                .ok_or_else(|| BabbleonError::HardwareUnavailable("usb requires keyfile".into()))?;
            Ok(Box::new(UsbBackend::new(p)))
        }
        Tier::Tpm => Ok(Box::new(TpmBackend)),
        Tier::Fido2 => {
            // Salt is normally read from the vault header; for factory dispatch
            // we use a zero salt and rely on the caller to wire the real one.
            Ok(Box::new(Fido2Backend::new("0".repeat(64))))
        }
    }
}
