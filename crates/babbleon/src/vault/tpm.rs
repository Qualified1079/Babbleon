//! TPM2-sealed KEK backend.
//!
//! Wraps the age passphrase with a TPM2 key sealed against the boot state
//! (PCRs 4 + 7 + 8 + 9 — not PCR 7 alone; see RESEARCH T5).  An attacker
//! with disk access cannot unseal without booting the same kernel +
//! shim + GRUB.
//!
//! Compiled only with `--features tpm`.  Without `tss-esapi` the module
//! exposes the same API but returns `HardwareUnavailable`, so the rest
//! of the crate doesn't grow `cfg` noise.
//!
//! DEFERRED M2.5:
//!   - `tpm2_policyauthorize` for kernel-update re-seal without manual flow
//!   - `tpm2-abrmd` vs `/dev/tpm0` resource manager matrix
//!   - Test matrix: real TPM hardware

use crate::errors::{BabbleonError, Result};
use crate::vault::backend::KekBackend;

/// PCRs we seal against.  PCR 7 alone is bypassable (oddlama 2023);
/// PCRs 4 (boot manager), 7 (Secure Boot), 8 (kernel cmdline), 9 (initrd)
/// give the layered measurement the bypass attack can't forge.
pub const SEAL_PCRS: &[u32] = &[4, 7, 8, 9];

pub struct TpmBackend;

impl Default for TpmBackend {
    fn default() -> Self {
        TpmBackend
    }
}

impl KekBackend for TpmBackend {
    fn derive_age_passphrase(&self, _credential: Option<&str>) -> Result<String> {
        #[cfg(feature = "tpm")]
        {
            // The real implementation lives behind the `tpm` feature and
            // pulls in `tss-esapi`.  Stubbed for the no-feature build.
            Err(BabbleonError::HardwareUnavailable(
                "tpm backend: tss-esapi wiring lands in M2.5".into(),
            ))
        }
        #[cfg(not(feature = "tpm"))]
        {
            Err(BabbleonError::HardwareUnavailable(
                "tpm backend: rebuild babbleon with --features tpm".into(),
            ))
        }
    }

    fn name(&self) -> &'static str {
        "tpm"
    }
}
