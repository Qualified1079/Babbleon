//! Vault: sealed payload with pluggable KEK backends.

pub mod attempts;
pub mod backend;
pub mod core;
pub mod factory;
pub mod fido2;
pub mod soft;
pub mod tpm;
pub mod usb;

pub use attempts::AttemptTracker;
pub use backend::KekBackend;
pub use core::{Vault, VaultPayload};
pub use fido2::Fido2Backend;
pub use soft::{Profile as SoftProfile, SoftBackend};
pub use tpm::TpmBackend;
pub use usb::UsbBackend;
