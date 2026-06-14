//! Vault: sealed payload with pluggable KEK backends.

pub mod backend;
pub mod core;
pub mod factory;
pub mod soft;
pub mod usb;
pub mod tpm;
pub mod fido2;

pub use backend::KekBackend;
pub use core::{Vault, VaultPayload};
pub use soft::{Profile as SoftProfile, SoftBackend};
pub use usb::UsbBackend;
pub use tpm::TpmBackend;
pub use fido2::Fido2Backend;
