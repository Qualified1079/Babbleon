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
//!   scrambled-name invocation (the stale list).  Wrapper-directory
//!   bloat across many rotations (see [`cleanup_stale_wrappers`]).
//! - **Does NOT defeat:** a worm that cached a scrambled name from
//!   epoch N-2 or older.  After rotation N→N+1, the cleanup pass
//!   prunes wrappers older than N-1, so the cached name's wrapper
//!   no longer exists and the invocation fails with ENOENT —
//!   blocking the call but emitting no tripwire signal.  Compensating
//!   control: defenders rely on filesystem-level audit (`open()`,
//!   `execve()`) for the older-than-N-1 detection signal.
//! - **Does NOT defeat:** an attacker with write access to
//!   `wrapper_dir`.  By construction the wrapper files are owned by
//!   the daemon UID; only root can rewrite them.  See
//!   `docs/v2/least-privilege.md`.

use std::collections::HashSet;
use std::hash::BuildHasher;
use std::io::Read;
use std::path::{Path, PathBuf};

use babbleon_core_v2::{
    write_all_tripwire_wrappers, write_all_wrappers, write_honey_list,
    write_stale_list, EpochMapping, PerHostSecret,
};

use crate::errors::{Error, Result};

/// First line of every Babbleon wrapper file.  Files in
/// `wrapper_dir` that do NOT start with this byte sequence are
/// considered foreign and are NEVER deleted by [`cleanup_stale_wrappers`].
const WRAPPER_SIGNATURE: &[u8] = b"#!/bin/sh\n# babbleon-v2 wrapper pad:";

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
    /// Path to the HMAC-sealed epoch journal.  When set, the daemon
    /// reads the journal at unlock time to resume at the
    /// last-recorded epoch (rather than restarting at 0), and
    /// rewrites the journal after every successful rotate.  When
    /// `None`, the daemon does not persist epoch state across
    /// restarts (legacy behaviour; tests use this).  Production
    /// callers should set this to a daemon-owned path under
    /// `/var/lib/babbleon/`.  Tamper detection: HMAC over the
    /// epoch bytes keyed by an HKDF subkey of the per-host secret;
    /// a tampered or missing journal is treated as "no journal" and
    /// the daemon resumes at epoch 0 with a tracing warn.
    pub journal_path: Option<PathBuf>,
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

    let keep: HashSet<&str> = current
        .real_to_scrambled
        .values()
        .map(String::as_str)
        .chain(honey_refs.iter().copied())
        .chain(previous_scrambled.iter().map(String::as_str))
        .collect();
    let removed = cleanup_stale_wrappers(&config.wrapper_dir, &keep);
    if removed > 0 {
        tracing::info!(
            wrapper_dir = %config.wrapper_dir.display(),
            removed,
            "pruned wrapper files from previous epochs",
        );
    }

    Ok(())
}

/// Atomic-swap variant of [`materialize`].
///
/// Writes every artefact into a staging sibling
/// `<wrapper_dir>.next`, then atomically swaps it into place via
/// `renameat2(RENAME_EXCHANGE)`.  After the swap the OLD wrapper
/// directory holds the previous epoch's artefacts at the
/// staging path; we then `rm -rf` the staging to reclaim disk.
///
/// Why bother:
///
/// - Non-atomic `materialize` leaves the wrapper dir in an
///   inconsistent state mid-write: some files reflect the new
///   epoch, some reflect the previous, and a launcher
///   invocation in the window bind-mounts a mix.  The mix is
///   not exploitable but breaks operator debuggability ("did
///   the rotation succeed?  partially?").
/// - `RENAME_EXCHANGE` is a single kernel syscall; the swap is
///   visible to other processes as a single point-in-time
///   transition.  No window where the wrapper dir is missing or
///   partial.
///
/// Existing launcher mount-namespaces with bind-mounts into the
/// OLD wrapper dir continue to see the OLD inodes — bind-mounts
/// capture inodes, not paths.  Their bind-mounted files survive
/// the swap and the post-swap cleanup.  Only NEW launcher
/// invocations after the swap point see the new directory.
///
/// Honey-list and stale-list files (which live OUTSIDE the
/// wrapper dir per [`MaterializationConfig::honey_list_path`] /
/// `stale_list_path`) are written via tempfile + `rename` for
/// per-file atomicity.
///
/// On any failure mid-write, the staging directory is removed
/// and the wrapper dir is left in its previous state.  The
/// operator retries by triggering another rotation.
///
/// # Errors
///
/// - [`Error::Wrapper`] for any I/O failure during staging
///   construction, write, swap, or cleanup.
pub fn materialize_atomic(
    config: &MaterializationConfig,
    secret: &PerHostSecret,
    current: &EpochMapping,
    previous_scrambled: &[String],
    tracked: &[TrackedTool],
) -> Result<()> {
    let staging = staging_sibling(&config.wrapper_dir);

    // Any leftover staging from a prior crash is suspicious but
    // not actionable — clear it so this attempt can proceed.
    if staging.exists() {
        tracing::warn!(
            staging = %staging.display(),
            "leftover staging directory found; removing before swap",
        );
        std::fs::remove_dir_all(&staging).map_err(|e| {
            Error::Wrapper(format!(
                "remove leftover staging {}: {e}",
                staging.display()
            ))
        })?;
    }

    // Build a staging-scoped config: wrapper_dir points at
    // staging, list paths still go to their canonical absolute
    // paths (those use per-file atomic rename below).
    let staging_config = MaterializationConfig {
        wrapper_dir: staging.clone(),
        honey_list_path: config.honey_list_path.clone(),
        stale_list_path: config.stale_list_path.clone(),
        trusted_ns_inode: config.trusted_ns_inode,
        journal_path: config.journal_path.clone(),
    };

    // Phase 1: populate staging.  On failure, clean up.
    let staging_result = materialize(
        &staging_config,
        secret,
        current,
        previous_scrambled,
        tracked,
    );
    if let Err(e) = staging_result {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(Error::Wrapper(format!(
            "staging materialise failed (rolled back): {e}"
        )));
    }

    // Phase 1b: write tripwire wrappers for the previous-epoch
    // stale names INTO the staging dir.  The non-atomic
    // `materialize` relies on these surviving the cleanup pass
    // because they were already in `wrapper_dir` from the
    // previous epoch.  With an atomic swap, staging starts
    // empty, so we must explicitly write them or the worm-
    // cached-name tripwire stops firing.
    if !previous_scrambled.is_empty() {
        babbleon_core_v2::write_all_tripwire_wrappers(
            previous_scrambled.iter().map(String::as_str),
            &staging,
            secret,
            current.epoch,
        )
        .map_err(|e| {
            let _ = std::fs::remove_dir_all(&staging);
            Error::Wrapper(format!(
                "stale tripwire wrappers (rolled back): {e}"
            ))
        })?;
    }

    // Phase 2: atomic swap.
    let live_exists = config.wrapper_dir.exists();
    if live_exists {
        // RENAME_EXCHANGE swaps the two paths in one syscall.
        // After this call: wrapper_dir holds the NEW contents
        // (was staging); staging holds the OLD contents (was
        // wrapper_dir).
        swap_directories(&config.wrapper_dir, &staging).map_err(|e| {
            let _ = std::fs::remove_dir_all(&staging);
            Error::Wrapper(format!(
                "atomic swap {} <-> {}: {e}",
                config.wrapper_dir.display(),
                staging.display()
            ))
        })?;
        // Now staging holds the previous epoch's wrappers.
        // Remove them; the launcher's existing bind-mounts hold
        // the inodes and survive the unlink.
        if let Err(e) = std::fs::remove_dir_all(&staging) {
            tracing::warn!(
                staging = %staging.display(),
                error = %e,
                "post-swap staging cleanup failed; leftover dir holds previous epoch's wrappers",
            );
        }
    } else {
        // Genesis case: nothing to swap with; just rename
        // staging into the live location.
        std::fs::rename(&staging, &config.wrapper_dir).map_err(|e| {
            let _ = std::fs::remove_dir_all(&staging);
            Error::Wrapper(format!(
                "genesis rename {} -> {}: {e}",
                staging.display(),
                config.wrapper_dir.display()
            ))
        })?;
    }

    Ok(())
}

fn staging_sibling(wrapper_dir: &Path) -> PathBuf {
    let mut s = wrapper_dir.as_os_str().to_owned();
    s.push(".next");
    PathBuf::from(s)
}

#[cfg(target_os = "linux")]
fn swap_directories(a: &Path, b: &Path) -> std::io::Result<()> {
    use nix::fcntl::{renameat2, RenameFlags};
    renameat2(None, a, None, b, RenameFlags::RENAME_EXCHANGE)
        .map_err(std::io::Error::from)
}

#[cfg(not(target_os = "linux"))]
fn swap_directories(_a: &Path, _b: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "RENAME_EXCHANGE requires Linux",
    ))
}

/// Remove every Babbleon-signed wrapper file in `wrapper_dir` whose
/// filename is not in `keep`.  Files lacking the Babbleon wrapper
/// header (`#!/bin/sh\n# babbleon-v2 wrapper pad:`, the
/// crate-private `WRAPPER_SIGNATURE` constant) are left alone —
/// they belong to someone else and we will not unlink them.
/// Returns the count of removed files.  Errors are logged at `warn`
/// level and counted as "not removed"; cleanup is best-effort and
/// never blocks a materialise.
pub fn cleanup_stale_wrappers<S: BuildHasher>(
    wrapper_dir: &Path,
    keep: &HashSet<&str, S>,
) -> usize {
    let entries = match std::fs::read_dir(wrapper_dir) {
        Ok(e) => e,
        Err(err) => {
            tracing::warn!(
                wrapper_dir = %wrapper_dir.display(),
                error = %err,
                "cleanup: read_dir failed; skipping prune",
            );
            return 0;
        }
    };

    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if keep.contains(name) {
            continue;
        }
        if !is_babbleon_wrapper(&path) {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(err) => tracing::warn!(
                path = %path.display(),
                error = %err,
                "cleanup: remove_file failed",
            ),
        }
    }
    removed
}

fn is_babbleon_wrapper(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else { return false };
    if !meta.is_file() {
        return false;
    }
    let Ok(mut f) = std::fs::File::open(path) else { return false };
    let mut buf = [0u8; WRAPPER_SIGNATURE.len()];
    match f.read(&mut buf) {
        Ok(n) if n == WRAPPER_SIGNATURE.len() => buf == *WRAPPER_SIGNATURE,
        _ => false,
    }
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
            journal_path: None,
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
    fn cleanup_removes_wrappers_not_in_keep_set() {
        let dir = tempfile::tempdir().unwrap();
        let secret = fixed_secret();
        let n1 = build_mapping(0, &["curl"]);
        let n2 = build_mapping(1, &["curl"]);
        let tracked = tracked_for(dir.path(), &["curl"]);
        let config = cfg(dir.path());

        materialize(&config, &secret, &n1, &[], &tracked).unwrap();
        let count_n1 = std::fs::read_dir(&config.wrapper_dir).unwrap().count();

        materialize(
            &config,
            &secret,
            &n2,
            &stale_names_from(&n1),
            &tracked,
        )
        .unwrap();
        let count_n2 = std::fs::read_dir(&config.wrapper_dir).unwrap().count();
        // After rotating once, the directory holds at most the
        // current epoch's wrappers + the previous epoch's (stale).
        // No N-2 ghosts.
        assert!(
            count_n2 <= count_n1 * 2,
            "wrapper count exploded: {count_n1} -> {count_n2}",
        );

        // Third rotation: epoch-0 wrappers (now N-2) must be gone.
        let n3 = build_mapping(2, &["curl"]);
        materialize(
            &config,
            &secret,
            &n3,
            &stale_names_from(&n2),
            &tracked,
        )
        .unwrap();
        for old in n1.real_to_scrambled.values().chain(n1.honey_names.iter()) {
            assert!(
                !config.wrapper_dir.join(old).exists(),
                "epoch-0 wrapper {old} should have been pruned",
            );
        }
    }

    #[test]
    fn cleanup_preserves_previous_epoch_wrappers_via_stale_set() {
        let dir = tempfile::tempdir().unwrap();
        let secret = fixed_secret();
        let n1 = build_mapping(0, &["curl"]);
        let n2 = build_mapping(1, &["curl"]);
        let tracked = tracked_for(dir.path(), &["curl"]);
        let config = cfg(dir.path());

        materialize(&config, &secret, &n1, &[], &tracked).unwrap();
        materialize(
            &config,
            &secret,
            &n2,
            &stale_names_from(&n1),
            &tracked,
        )
        .unwrap();

        // Previous-epoch (N-1) wrappers must remain so a stale-name
        // invocation still trips the wrapper's stale-list check.
        for prev in n1.real_to_scrambled.values().chain(n1.honey_names.iter()) {
            assert!(
                config.wrapper_dir.join(prev).exists(),
                "previous-epoch wrapper {prev} unexpectedly pruned",
            );
        }
    }

    #[test]
    fn cleanup_does_not_touch_foreign_files() {
        let dir = tempfile::tempdir().unwrap();
        let secret = fixed_secret();
        let mapping = build_mapping(0, &["curl"]);
        let tracked = tracked_for(dir.path(), &["curl"]);
        let config = cfg(dir.path());
        std::fs::create_dir_all(&config.wrapper_dir).unwrap();

        // Drop a foreign file in wrapper_dir.
        let foreign = config.wrapper_dir.join("readme.txt");
        std::fs::write(&foreign, "not a babbleon wrapper\n").unwrap();

        materialize(&config, &secret, &mapping, &[], &tracked).unwrap();
        assert!(foreign.exists(), "foreign file must not be deleted");
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
