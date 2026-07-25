//! The reusable core: an owned per-device name table.
//!
//! # What this defeats
//!
//! An on-device LLM agent that plans using canonical Android identifiers
//! (service/property/package names).  [`MobileMapping`] holds the
//! per-device [`EpochMapping`] that renames those identifiers, so the
//! agent cannot name what it cannot see, and the same table lets the
//! runtime reveal a scrambled name back to its canonical form before
//! dispatch.
//!
//! This is identical math to the Linux tier: a device and a server that
//! share the same 32-byte secret and epoch derive byte-identical tables,
//! so a scrambled name minted on one reveals on the other.

use babbleon_scramble_v2::{
    errors::Result, mapping::EpochMapping, MappingBuilder, PerHostSecret,
    Wordlist,
};

/// An owned, per-device name table for one epoch.
///
/// Construction derives the table from the device secret; the secret is
/// not retained (only the derived, non-secret mapping is).  Deliberately
/// does **not** derive `Debug`: printing the full `real ↔ scrambled`
/// table would defeat the obfuscation if it reached logcat.  See the
/// hand-written [`std::fmt::Debug`] impl, which prints only the epoch and
/// entry counts.
pub struct MobileMapping {
    mapping: EpochMapping,
}

impl MobileMapping {
    /// Derive the per-device table from a 32-byte device secret, the set
    /// of canonical identifiers to track, and an epoch.
    ///
    /// Uses the built-in English wordlist ([`Wordlist::english_baseline`]);
    /// the mobile tier ships the same wordlist as the server so the
    /// derived compounds match.  The secret is copied into a
    /// zeroize-on-drop [`PerHostSecret`] for the duration of the build
    /// and wiped when this call returns.
    ///
    /// # Errors
    ///
    /// - The secret is not exactly [`PerHostSecret`]'s required length.
    /// - The wordlist is too small for the number of tracked identifiers
    ///   (cannot happen with the baseline wordlist at realistic sizes).
    pub fn from_device_secret(
        secret_bytes: &[u8],
        tracked_identifiers: &[String],
        epoch: u64,
    ) -> Result<Self> {
        let secret = PerHostSecret::from_bytes(secret_bytes)?;
        let wordlist = Wordlist::english_baseline();
        let mapping =
            MappingBuilder::new(&secret, wordlist).build(tracked_identifiers, epoch)?;
        Ok(Self { mapping })
    }

    /// The canonical → scrambled direction: the name the agent should
    /// see for a canonical identifier, or `None` if it was not tracked.
    #[must_use]
    pub fn scramble<'a>(&'a self, canonical: &str) -> Option<&'a str> {
        self.mapping.scramble(canonical)
    }

    /// The scrambled → canonical direction: the real identifier behind a
    /// scrambled compound, or `None` for decoys, stale-epoch names, and
    /// unknown compounds alike.
    #[must_use]
    pub fn reveal<'a>(&'a self, scrambled: &str) -> Option<&'a str> {
        self.mapping.reveal(scrambled)
    }

    /// True iff `name` is one of this epoch's decoy (honey) names.
    ///
    /// Constant-time per-entry, inherited from the scramble engine.
    #[must_use]
    pub fn is_decoy(&self, name: &str) -> bool {
        self.mapping.is_honey(name)
    }

    /// The epoch this table was derived for.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.mapping.epoch
    }
}

impl std::fmt::Debug for MobileMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted on purpose — never print the table contents.
        f.debug_struct("MobileMapping")
            .field("epoch", &self.mapping.epoch)
            .field("tracked", &self.mapping.real_to_scrambled.len())
            .field("decoys", &self.mapping.honey_names.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools() -> Vec<String> {
        ["activity", "package", "netd", "wifi"]
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }

    fn mapping(epoch: u64) -> MobileMapping {
        MobileMapping::from_device_secret(&[7u8; 32], &tools(), epoch).unwrap()
    }

    #[test]
    fn scramble_then_reveal_round_trips() {
        let m = mapping(3);
        for canonical in tools() {
            let scrambled = m.scramble(&canonical).expect("tracked");
            assert_eq!(m.reveal(scrambled), Some(canonical.as_str()));
        }
    }

    #[test]
    fn untracked_canonical_name_does_not_scramble() {
        let m = mapping(3);
        assert_eq!(m.scramble("not-a-tracked-service"), None);
    }

    #[test]
    fn scrambled_name_is_not_the_canonical_name() {
        let m = mapping(3);
        let scrambled = m.scramble("netd").expect("tracked");
        assert_ne!(scrambled, "netd");
    }

    #[test]
    fn same_secret_and_epoch_derive_identical_tables() {
        // The device/server-parity property, mobile-side.
        let a = mapping(9);
        let b = mapping(9);
        for canonical in tools() {
            assert_eq!(a.scramble(&canonical), b.scramble(&canonical));
        }
    }

    #[test]
    fn different_epochs_derive_different_tables() {
        let a = mapping(1);
        let b = mapping(2);
        // At least one identifier must map differently across epochs.
        let any_different = tools()
            .iter()
            .any(|c| a.scramble(c) != b.scramble(c));
        assert!(any_different);
    }

    #[test]
    fn wrong_length_secret_errors() {
        assert!(MobileMapping::from_device_secret(&[0u8; 16], &tools(), 1).is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let m = mapping(4);
        let s = format!("{m:?}");
        assert!(s.contains("epoch"));
        // The redacted Debug must not leak a scrambled compound.
        let scrambled = m.scramble("wifi").unwrap().to_string();
        assert!(!s.contains(&scrambled));
    }
}
