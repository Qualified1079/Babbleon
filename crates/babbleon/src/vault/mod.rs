//! Vault: sealed payload with pluggable KEK backends.

pub mod backend;
pub mod core;
pub mod factory;
pub mod soft;
pub mod usb;

#[cfg(feature = "tpm")]
pub mod tpm;
#[cfg(feature = "fido2")]
pub mod fido2;

pub use backend::KekBackend;
pub use core::{Vault, VaultPayload};
pub use soft::SoftBackend;
pub use usb::UsbBackend;
