//! Bridge: build a `launch_artefacts::ActivatedTable` from a core
//! `EpochMapping`.
//!
//! # What this defeats
//!
//! Compartmentalization.  The activated-table type and its strict
//! parser live in `v2-babbleon-launch-artefacts`, which carries no
//! crypto dependencies; the launcher and PAM depend on the
//! artefacts crate, never on core.
//!
//! Building an `ActivatedTable` *from* an `EpochMapping`, however,
//! requires both — and `EpochMapping` lives in core because it
//! depends on the HKDF-seeded permutation primitives.  So the
//! bridge itself lives here, in core, where both ends are visible.
//!
//! # Mechanism
//!
//! Iterates `EpochMapping::real_to_scrambled` in canonical-name
//! order so the JSONL output is reproducible across builds.
//! Joins `wrapper_dir` with each scrambled name — the daemon's
//! wrapper-output layout (`write_all_wrappers`) puts each per-
//! name binary at exactly that path.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** launcher / PAM inadvertently importing the
//!   crypto stack via the activated-table types.
//! - **Does NOT defeat:** the daemon's audit surface (the daemon
//!   must depend on core to build mappings, so it pulls in the
//!   crypto stack by necessity).

use std::path::Path;

use babbleon_launch_artefacts_v2::{ActivatedTable, ActivatedTableBuilder};

use crate::errors::{Error, Result};
use crate::mapping::EpochMapping;

/// Build an [`ActivatedTable`] from an [`EpochMapping`] and a
/// wrapper directory.
///
/// `wrapper_dir` MUST be absolute; relative paths are rejected by
/// [`ActivatedTableBuilder::push_entry`] (defense in depth even
/// though a real daemon would never produce one).
///
/// # Errors
///
/// - [`Error::Internal`] if any entry fails the artefacts crate's
///   validation (e.g. relative `wrapper_dir`, non-`[a-z]`
///   scrambled name from a malformed wordlist).
pub fn build_activated_table_from_mapping(
    mapping: &EpochMapping,
    wrapper_dir: &Path,
) -> Result<ActivatedTable> {
    let mut builder = ActivatedTableBuilder::new(mapping.epoch);
    // Deterministic order: sort by real name so the JSONL output is
    // reproducible across builds.  Bind-mount order is not
    // security-relevant, but reproducibility helps audit.
    let mut entries: Vec<(&String, &String)> =
        mapping.real_to_scrambled.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (_real, scrambled) in entries {
        let wrapper_path = wrapper_dir.join(scrambled);
        builder = builder
            .push_entry(scrambled.clone(), wrapper_path)
            .map_err(|e| Error::Internal(e.to_string()))?;
    }
    for honey in &mapping.honey_names {
        builder = builder
            .push_honey(honey.clone())
            .map_err(|e| Error::Internal(e.to_string()))?;
    }
    builder
        .finish()
        .map_err(|e| Error::Internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::build_activated_table_from_mapping;
    use crate::{MappingBuilder, PerHostSecret, Wordlist};

    #[test]
    fn build_from_mapping_produces_table_for_every_tracked_tool() {
        let secret = PerHostSecret::from_bytes(&[7u8; 32]).unwrap();
        let wl = Wordlist::english_baseline();
        let tracked = vec!["curl".to_string(), "git".to_string()];
        let m = MappingBuilder::new(&secret, wl).build(&tracked, 5).unwrap();
        let table = build_activated_table_from_mapping(
            &m,
            std::path::Path::new("/usr/local/libexec/babbleon/wrappers"),
        )
        .unwrap();
        assert_eq!(table.epoch, 5);
        assert_eq!(table.entries.len(), tracked.len());
        for tool in &tracked {
            let scrambled = m.scramble(tool).unwrap();
            let expected_path = std::path::PathBuf::from(
                "/usr/local/libexec/babbleon/wrappers",
            )
            .join(scrambled);
            let entry = table
                .entries
                .iter()
                .find(|e| e.scrambled == scrambled)
                .unwrap();
            assert_eq!(entry.wrapper_path, expected_path);
        }
        assert_eq!(table.honey_names.len(), m.honey_names.len());
    }

    #[test]
    fn build_from_mapping_rejects_relative_wrapper_dir() {
        let secret = PerHostSecret::from_bytes(&[7u8; 32]).unwrap();
        let wl = Wordlist::english_baseline();
        let m = MappingBuilder::new(&secret, wl)
            .build(&["curl".to_string()], 0)
            .unwrap();
        let err = build_activated_table_from_mapping(
            &m,
            std::path::Path::new("relative/wrappers"),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("not absolute"));
    }

    #[test]
    fn build_from_mapping_is_deterministic_per_input() {
        let secret = PerHostSecret::from_bytes(&[7u8; 32]).unwrap();
        let wl = Wordlist::english_baseline();
        let m = MappingBuilder::new(&secret, wl)
            .build(
                &["curl".to_string(), "git".to_string(), "ssh".to_string()],
                0,
            )
            .unwrap();
        let a = build_activated_table_from_mapping(
            &m,
            std::path::Path::new("/wrappers"),
        )
        .unwrap();
        let b = build_activated_table_from_mapping(
            &m,
            std::path::Path::new("/wrappers"),
        )
        .unwrap();
        assert_eq!(a, b);
    }
}
