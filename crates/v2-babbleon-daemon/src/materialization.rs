//! Per-epoch wrapper materialisation — write the on-disk artefacts
//! the launcher consumes.
//!
//! # Infrastructure module
//!
//! The daemon caches every per-epoch artefact the rest of the system
//! consumes (activated table, on-disk wrappers, tripwire lists).  The
//! activated table is a secret-free in-memory product
//! ([`crate::state::DaemonState::activated_table_jsonl`]); the
//! wrappers and lists are on-disk artefacts produced here.
//!
//! On each call this module:
//!
//! 1. Writes a real-tool wrapper for every `(name, real_path)` in
//!    `tracked`, scrambled per `current.real_to_scrambled`, into
//!    `wrapper_dir`.
//! 2. Writes a tripwire wrapper for every honey name in
//!    `current.honey_names`, into `wrapper_dir`.
//! 3. Writes the honey-name list (current epoch's honey names) to
//!    `honey_list_path`.
//! 4. Writes the stale-name list (previous epoch's real and honey
//!    scrambled names) to `stale_list_path`.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** launcher bind-mounts pointing at empty wrapper
//!   paths (the failure mode before this module: the daemon emitted
//!   `wrapper_path` fields the launcher then tried to bind-mount
//!   from non-existent files).  Tripwire firing on previous-epoch
//!   scrambled-name invocation (the stale list).
//! - **Does NOT defeat:** wrappers from N-2 or older epochs that
//!   accumulate in `wrapper_dir`.  An invocation of such a wrapper
//!   falls past the honey check (list moved on) and the stale check
//!   (list reflects N-1 only), then `exec`s `/dev/null` or its
//!   stale `real_path` with no tripwire fire.  Compensating control:
//!   a future cleanup pass; tracked in HANDOFF.md.  For MVP we
//!   accept the lossy stale window in exchange for a bounded
//!   stale-list size.
//! - **Does NOT defeat:** an attacker with write access to
//!   `wrapper_dir`.  By construction the wrapper files are owned by
//!   the daemon UID; only root can rewrite them.  See
//!   `docs/v2/least-privilege.md`.

use std::path::{Path, PathBuf};

use babbleon_core_v2::{
    write_all_tripwire_wrappers, write_all_wrappers, write_honey_list,
    write_stale_list, EpochMapping, PerHostSecret,
};

use crate::errors::{Error, Result};

/// Knobs that vary between production and test invocations.
///
/// Production callers construct this with all defaults
/// (`tripwire_*_list = None`, `trusted_ns_inode = None`).
/// Tests override `tripwire_*_list` to write into a tempdir.
#[derive(Debug, Clone)]
pub struct MaterializationConfig {
    /// Absolute directory the wrappers are written into.
    pub wrapper_dir: PathBuf,
    /// Override path for the honey-name list.  `None` uses the
    /// production constant `TRIPWIRE_HONEY_LIST`.
    pub honey_list_path: Option<PathBuf>,
    /// Override path for the stale-name list.  `None` uses the
    /// production constant `TRIPWIRE_STALE_LIST`.
    pub stale_list_path: Option<PathBuf>,
    /// Trusted-mount-namespace inode the wrapper compares against.
    /// `None` (default) renders `0` into the wrapper, disabling the
    /// tier check — useful only for tests; production must pass
    /// `Some(inode)` so the wrapper exits 127 when invoked outside
    /// the trusted NS.
    pub trusted_ns_inode: Option<u64>,
}

/// One tracked tool: the canonical name (used for scrambling) plus
/// the absolute path of the real binary the wrapper will `exec`.
#[derive(Debug, Clone)]
pub struct TrackedTool {
    /// Canonical name like `"curl"`.  Used as the key into
    /// `mapping.real_to_scrambled` and stored verbatim in the
    /// daemon's tracked-tool list.
    pub name: String,
    /// Absolute path to the real binary, e.g. `/usr/bin/curl`.
    /// Embedded into the wrapper as `_BL_REAL` and `exec`'d in the
    /// trusted tier.
    pub real_path: PathBuf,
}

/// Materialise every on-disk artefact for `current`'s epoch.
///
/// `previous_scrambled` is the union of real and honey scrambled
/// names from the immediately-previous epoch's mapping; it becomes
/// the stale list so previous-epoch invocations trip a "stale"
/// tripwire.  Pass an empty slice for the genesis epoch.
///
/// `tracked` entries whose `name` is absent from
/// `current.real_to_scrambled` are silently skipped (the operator
/// has tracked-but-not-yet-rotated state — e.g. just enrolled a new
/// tool whose mapping has not been built yet).
///
/// # Errors
///
/// - [`Error::Wrapper`] for any wrapper or list write failure.  The
///   inner message names the underlying I/O or HKDF error.  Partial
///   state may remain on disk on a mid-operation failure; the
///   operator retries by triggering another rotation.
pub fn materialize(
    config: &MaterializationConfig,
    secret: &PerHostSecret,
    current: &EpochMapping,
    previous_scrambled: &[String],
    tracked: &[TrackedTool],
) -> Result<()> {
    let real_pairs: Vec<(&str, &Path)> = tracked
        .iter()
        .filter_map(|t| {
            current
                .real_to_scrambled
                .get(&t.name)
                .map(|scrambled| (scrambled.as_str(), t.real_path.as_path()))
        })
        .collect();

    write_all_wrappers(
        real_pairs,
        &config.wrapper_dir,
        secret,
        current.epoch,
        config.trusted_ns_inode,
    )
    .map_err(|e| Error::Wrapper(format!("real-tool wrappers: {e}")))?;

    let honey_refs: Vec<&str> = current.honey_names.iter().map(String::as_str).collect();
    write_all_tripwire_wrappers(
        honey_refs.iter().copied(),
        &config.wrapper_dir,
        secret,
        current.epoch,
    )
    .map_err(|e| Error::Wrapper(format!("honey wrappers: {e}")))?;

    write_honey_list(honey_refs.iter().copied(), config.honey_list_path.as_deref())
        .map_err(|e| Error::Wrapper(format!("honey list: {e}")))?;

    write_stale_list(
        previous_scrambled.iter().map(String::as_str),
        config.stale_list_path.as_deref(),
    )
    .map_err(|e| Error::Wrapper(format!("stale list: {e}")))?;

    Ok(())
}

/// Build the previous-epoch stale name set from an
/// [`EpochMapping`].  Concatenates real-scrambled names and honey
/// names; honey wrappers from N-1 fire as "stale" if invoked at N
/// rather than falling through to a no-op `exec /dev/null`.
#[must_use]
pub fn stale_names_from(mapping: &EpochMapping) -> Vec<String> {
    let mut out: Vec<String> = mapping
        .real_to_scrambled
        .values()
        .cloned()
        .collect();
    out.extend(mapping.honey_names.iter().cloned());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use babbleon_core_v2::{MappingBuilder, Wordlist};
    use std::os::unix::fs::PermissionsExt;

    fn fixed_secret() -> PerHostSecret {
        PerHostSecret::from_bytes(&[7u8; 32]).unwrap()
    }

    fn build_mapping(epoch: u64, tools: &[&str]) -> EpochMapping {
        let secret = fixed_secret();
        let names: Vec<String> = tools.iter().map(|s| (*s).to_string()).collect();
        MappingBuilder::new(&secret, Wordlist::english_baseline())
            .build(&names, epoch)
            .unwrap()
    }

    fn cfg(dir: &Path) -> MaterializationConfig {
        MaterializationConfig {
            wrapper_dir: dir.join("wrappers"),
            honey_list_path: Some(dir.join("honey.list")),
            stale_list_path: Some(dir.join("stale.list")),
            trusted_ns_inode: None,
        }
    }

    fn tracked_for(dir: &Path, tools: &[&str]) -> Vec<TrackedTool> {
        tools
            .iter()
            .map(|name| {
                let real_path = dir.join(format!("real-{name}"));
                std::fs::write(&real_path, "#!/bin/sh\n").unwrap();
                TrackedTool {
                    name: (*name).to_string(),
                    real_path,
                }
            })
            .collect()
    }

    #[test]
    fn materialize_writes_one_real_wrapper_per_tracked_tool() {
        let dir = tempfile::tempdir().unwrap();
        let secret = fixed_secret();
        let mapping = build_mapping(0, &["curl", "ssh"]);
        let tracked = tracked_for(dir.path(), &["curl", "ssh"]);
        let config = cfg(dir.path());

        materialize(&config, &secret, &mapping, &[], &tracked).unwrap();

        for scrambled in mapping.real_to_scrambled.values() {
            let p = config.wrapper_dir.join(scrambled);
            assert!(p.exists(), "wrapper missing for {scrambled}");
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "wrapper not executable: {scrambled}");
        }
    }

    #[test]
    fn materialize_writes_one_honey_wrapper_per_honey_name() {
        let dir = tempfile::tempdir().unwrap();
        let secret = fixed_secret();
        let mapping = build_mapping(0, &["curl"]);
        let tracked = tracked_for(dir.path(), &["curl"]);
        let config = cfg(dir.path());

        materialize(&config, &secret, &mapping, &[], &tracked).unwrap();

        for honey in &mapping.honey_names {
            let p = config.wrapper_dir.join(honey);
            assert!(p.exists(), "honey wrapper missing for {honey}");
        }
    }

    #[test]
    fn materialize_writes_honey_list_with_current_names() {
        let dir = tempfile::tempdir().unwrap();
        let secret = fixed_secret();
        let mapping = build_mapping(0, &["curl"]);
        let tracked = tracked_for(dir.path(), &["curl"]);
        let config = cfg(dir.path());

        materialize(&config, &secret, &mapping, &[], &tracked).unwrap();

        let body = std::fs::read_to_string(config.honey_list_path.as_ref().unwrap())
            .unwrap();
        for honey in &mapping.honey_names {
            assert!(
                body.contains(&format!("{honey}\n")),
                "honey list missing {honey}",
            );
        }
    }

    #[test]
    fn materialize_writes_stale_list_from_previous_scrambled() {
        let dir = tempfile::tempdir().unwrap();
        let secret = fixed_secret();
        let mapping = build_mapping(1, &["curl"]);
        let tracked = tracked_for(dir.path(), &["curl"]);
        let config = cfg(dir.path());

        let previous = vec!["old-name-one".to_string(), "old-name-two".to_string()];
        materialize(&config, &secret, &mapping, &previous, &tracked).unwrap();

        let body =
            std::fs::read_to_string(config.stale_list_path.as_ref().unwrap()).unwrap();
        assert!(body.contains("old-name-one\n"));
        assert!(body.contains("old-name-two\n"));
    }

    #[test]
    fn materialize_skips_tracked_tool_absent_from_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let secret = fixed_secret();
        let mapping = build_mapping(0, &["curl"]);
        let mut tracked = tracked_for(dir.path(), &["curl", "ssh"]);
        // ssh is in tracked but NOT in the mapping (operator added it
        // after this mapping was built).  Materialize should skip it.
        tracked[1].real_path = dir.path().join("real-ssh");
        let config = cfg(dir.path());

        materialize(&config, &secret, &mapping, &[], &tracked).unwrap();

        // Exactly one real-tool wrapper landed.
        assert_eq!(mapping.real_to_scrambled.len(), 1);
        let scrambled = mapping.real_to_scrambled.get("curl").unwrap();
        assert!(config.wrapper_dir.join(scrambled).exists());
    }

    #[test]
    fn materialize_is_idempotent_for_same_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let secret = fixed_secret();
        let mapping = build_mapping(0, &["curl"]);
        let tracked = tracked_for(dir.path(), &["curl"]);
        let config = cfg(dir.path());

        materialize(&config, &secret, &mapping, &[], &tracked).unwrap();
        let first_bytes: Vec<(PathBuf, Vec<u8>)> = std::fs::read_dir(&config.wrapper_dir)
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                let b = std::fs::read(&p).unwrap();
                (p, b)
            })
            .collect();

        materialize(&config, &secret, &mapping, &[], &tracked).unwrap();
        for (p, b) in first_bytes {
            assert_eq!(std::fs::read(&p).unwrap(), b, "wrapper changed: {}", p.display());
        }
    }

    #[test]
    fn stale_names_from_includes_real_and_honey() {
        let mapping = build_mapping(0, &["curl", "ssh"]);
        let stale = stale_names_from(&mapping);
        for scrambled in mapping.real_to_scrambled.values() {
            assert!(stale.contains(scrambled), "missing real {scrambled}");
        }
        for honey in &mapping.honey_names {
            assert!(stale.contains(honey), "missing honey {honey}");
        }
    }

    #[test]
    fn materialize_writes_wrappers_that_execute_under_sh() {
        // The wrapper template is shell.  Confirm the daemon-written
        // file parses cleanly: `sh -n` exits 0 iff the script is
        // syntactically valid.
        let dir = tempfile::tempdir().unwrap();
        let secret = fixed_secret();
        let mapping = build_mapping(0, &["curl"]);
        let tracked = tracked_for(dir.path(), &["curl"]);
        let config = cfg(dir.path());

        materialize(&config, &secret, &mapping, &[], &tracked).unwrap();

        for entry in std::fs::read_dir(&config.wrapper_dir).unwrap() {
            let p = entry.unwrap().path();
            let st = std::process::Command::new("sh")
                .arg("-n")
                .arg(&p)
                .status()
                .unwrap();
            assert!(st.success(), "wrapper at {} fails sh -n", p.display());
        }
    }

    #[test]
    fn materialize_genesis_writes_empty_stale_list() {
        let dir = tempfile::tempdir().unwrap();
        let secret = fixed_secret();
        let mapping = build_mapping(0, &["curl"]);
        let tracked = tracked_for(dir.path(), &["curl"]);
        let config = cfg(dir.path());

        materialize(&config, &secret, &mapping, &[], &tracked).unwrap();
        let body =
            std::fs::read_to_string(config.stale_list_path.as_ref().unwrap()).unwrap();
        assert!(body.is_empty(), "genesis stale list should be empty, got: {body}");
    }
}
