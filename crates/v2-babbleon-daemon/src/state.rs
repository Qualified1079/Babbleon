//! Daemon in-memory state — the only owner of the per-host secret.
//!
//! # What this defeats
//!
//! The daemon is the only process on the host that holds the per-host
//! secret in memory.  Every artefact the rest of the system consumes
//! (activated table, wrappers, audit-chain signatures) is derived
//! from the secret; nothing else needs to hold it.  Without a single,
//! audit-traceable owner for the secret, key material would leak
//! into the CLI, the launcher, or the PAM module on every code-path
//! that "just needs the epoch number" — exactly the failure mode v1
//! had with `host_secret_hex: String` lingering in deserialized
//! payloads.
//!
//! [`DaemonState`] is that owner.  Construction requires a
//! [`PerHostSecret`] by move; the secret is held in
//! `PerHostSecret`'s `Zeroizing<[u8; 32]>` and is never re-exposed
//! through the public API.  All mapping construction happens inside
//! this module; callers receive the secret-free
//! [`babbleon_core_v2::EpochMapping`] / [`babbleon_core_v2::ActivatedTable`]
//! products.
//!
//! # Mechanism
//!
//! The state machine is single-threaded by design.  The daemon's
//! socket loop is single-connection-at-a-time in phase 2; phase 4+
//! parallelism (if any) lands as a worker-pool that takes
//! `&DaemonState` for read-only queries and serializes mutations
//! through a single owner.
//!
//! Methods:
//!
//! - [`DaemonState::new`] — construct with the secret, wordlist,
//!   tracked-tool list, and wrapper directory.  Builds the epoch-0
//!   mapping eagerly.
//! - [`DaemonState::status`] — read-only snapshot.
//! - [`DaemonState::activated_table_jsonl`] — serialize the cached
//!   mapping as JSONL (validated through
//!   [`babbleon_core_v2::build_activated_table_from_mapping`]).
//! - [`DaemonState::rotate`] — bump the epoch counter and rebuild
//!   the cached mapping.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** secret leakage via the daemon's public API
//!   (nothing public exposes secret bytes); secret leakage via Drop
//!   (`PerHostSecret`'s zeroize); stale-mapping race (cached
//!   mapping is a `Clone` of the last build, never a live reference
//!   into the builder's transient state).
//! - **Does NOT defeat:** in-process memory disclosure
//!   (`ptrace_scope`, kernel CVE, side channel).  Compensating
//!   controls: process hardening (rule 8); seccomp profile pinning
//!   `process_vm_readv` to deny; landlock confinement of the
//!   daemon's filesystem reach.
//! - **Does NOT defeat:** a compromised wordlist.  The wordlist is
//!   public-domain English; an attacker who replaces it on disk
//!   between daemon restarts can predict scrambled names.
//!   Compensating control: wordlist is in the daemon binary's RSS
//!   via `english_baseline`, not loaded at runtime.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use babbleon_core_v2::{
    build_activated_table_from_mapping, EpochMapping, MappingBuilder,
    PerHostSecret, Wordlist,
};

use crate::errors::{Error, Result};

/// In-memory daemon state.
///
/// Holds the per-host secret, the current epoch, the tracked-tool
/// list, and the cached [`EpochMapping`] for the current epoch.
///
/// Single-owner, mutate through `&mut self`.  Send-safe (every
/// member is `Send`) so a future worker-pool can move it across
/// threads if needed, but no Sync — the state machine is not lock-
/// free.
pub struct DaemonState {
    secret: PerHostSecret,
    wordlist: &'static Wordlist,
    tracked_tools: Vec<String>,
    wrapper_dir: PathBuf,
    epoch: u64,
    cached_mapping: EpochMapping,
    last_rotation: SystemTime,
}

impl DaemonState {
    /// Construct a daemon state from a freshly-loaded secret and a
    /// tracked-tool list.
    ///
    /// `wrapper_dir` MUST be an absolute path.  Every entry of
    /// `tracked_tools` MUST be a non-empty string (canonical names
    /// like `"curl"`); duplicates are not enforced here (the
    /// downstream
    /// [`babbleon_core_v2::build_activated_table_from_mapping`]
    /// would catch them at table-build time).
    ///
    /// Builds the epoch-0 mapping eagerly so a `status` call right
    /// after `new` returns a populated snapshot.
    ///
    /// # Errors
    ///
    /// - [`Error::Cli`] if `wrapper_dir` is not absolute or if any
    ///   tracked tool name is empty.
    /// - [`Error::Mapping`] (via `From`) if mapping construction
    ///   fails.
    pub fn new(
        secret: PerHostSecret,
        wordlist: &'static Wordlist,
        tracked_tools: Vec<String>,
        wrapper_dir: PathBuf,
    ) -> Result<Self> {
        if !wrapper_dir.is_absolute() {
            return Err(Error::Cli(format!(
                "wrapper_dir must be absolute (got {})",
                wrapper_dir.display()
            )));
        }
        for t in &tracked_tools {
            if t.is_empty() {
                return Err(Error::Cli(
                    "tracked-tool list contains an empty name".into(),
                ));
            }
        }
        let initial_mapping =
            MappingBuilder::new(&secret, wordlist).build(&tracked_tools, 0)?;
        Ok(Self {
            secret,
            wordlist,
            tracked_tools,
            wrapper_dir,
            epoch: 0,
            cached_mapping: initial_mapping,
            last_rotation: SystemTime::now(),
        })
    }

    /// Current epoch number.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Number of currently tracked tools.
    #[must_use]
    pub fn tracked_count(&self) -> usize {
        self.tracked_tools.len()
    }

    /// `UNIX_EPOCH`-relative seconds of the last successful rotation.
    /// Returns `None` if the system clock is set before `UNIX_EPOCH`
    /// (catastrophe state; not a hard error).
    #[must_use]
    pub fn last_rotation_unix_secs(&self) -> Option<u64> {
        self.last_rotation
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs())
    }

    /// Build the activated table JSONL for the current epoch.
    ///
    /// Returns the validated, byte-ready JSONL payload the launcher
    /// consumes.  The mapping itself is cached so repeated calls
    /// within an epoch are O(activated-table-size), not O(wordlist).
    ///
    /// # Errors
    ///
    /// - [`Error::ActivatedTable`] (via `From`) if table construction
    ///   or JSONL serialization fails (cannot happen in practice for
    ///   a well-formed mapping; the validators only reject malformed
    ///   names or relative paths).
    pub fn activated_table_jsonl(&self) -> Result<Vec<u8>> {
        let table = build_activated_table_from_mapping(
            &self.cached_mapping,
            &self.wrapper_dir,
        )
        .map_err(|e| Error::ActivatedTable(e.to_string()))?;
        let bytes = table
            .write_jsonl()
            .map_err(|e| Error::ActivatedTable(e.to_string()))?;
        Ok(bytes)
    }

    /// Bump the epoch and rebuild the cached mapping.  Returns the
    /// new epoch number.
    ///
    /// # Errors
    ///
    /// - [`Error::Mapping`] if mapping construction fails.
    pub fn rotate(&mut self) -> Result<u64> {
        let new_epoch = self.epoch.checked_add(1).ok_or_else(|| {
            Error::Mapping(
                "epoch counter overflow; daemon refuses to wrap u64::MAX"
                    .into(),
            )
        })?;
        let new_mapping = MappingBuilder::new(&self.secret, self.wordlist)
            .build(&self.tracked_tools, new_epoch)?;
        self.epoch = new_epoch;
        self.cached_mapping = new_mapping;
        self.last_rotation = SystemTime::now();
        Ok(new_epoch)
    }

    /// Read-only view of the wrapper directory.  Used by the daemon
    /// for `write_all_wrappers`-side flows (filed for the next
    /// commit; not yet wired in).
    #[must_use]
    pub fn wrapper_dir(&self) -> &Path {
        &self.wrapper_dir
    }

    /// Read-only view of the cached mapping for the current epoch.
    ///
    /// Exposed for diagnostic / test use; the
    /// [`Self::activated_table_jsonl`] path is the production
    /// consumer surface.  The returned reference does NOT carry
    /// secret bytes — `EpochMapping` only holds names and honey
    /// strings.
    #[must_use]
    pub fn current_mapping(&self) -> &EpochMapping {
        &self.cached_mapping
    }
}

// `DaemonState` is intentionally not `Clone`, not `Copy`, not
// `Debug`.  Clone would defeat `PerHostSecret`'s zeroize-on-drop
// guarantee; Debug would risk a careless `dbg!(state)` printing the
// tracked-tool list and wrapper path to logs.  See security-baseline
// rule 3.

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_secret() -> PerHostSecret {
        PerHostSecret::from_bytes(&[9u8; 32]).unwrap()
    }

    fn tracked() -> Vec<String> {
        ["curl", "ssh", "git"].iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn new_eagerly_builds_epoch_zero_mapping() {
        let s = DaemonState::new(
            fixed_secret(),
            Wordlist::english_baseline(),
            tracked(),
            PathBuf::from("/var/lib/babbleon/wrappers"),
        )
        .unwrap();
        assert_eq!(s.epoch(), 0);
        assert_eq!(s.tracked_count(), 3);
        assert!(s.last_rotation_unix_secs().is_some());
    }

    #[test]
    fn new_rejects_relative_wrapper_dir() {
        // `DaemonState` deliberately omits `Debug` (rule 3), so we
        // cannot `.unwrap_err()`; match the Result by hand.
        let r = DaemonState::new(
            fixed_secret(),
            Wordlist::english_baseline(),
            tracked(),
            PathBuf::from("relative/wrappers"),
        );
        match r {
            Ok(_) => panic!("expected Err for relative wrapper_dir"),
            Err(e) => assert!(format!("{e}").contains("absolute")),
        }
    }

    #[test]
    fn new_rejects_empty_tracked_name() {
        let mut t = tracked();
        t.push(String::new());
        let r = DaemonState::new(
            fixed_secret(),
            Wordlist::english_baseline(),
            t,
            PathBuf::from("/x"),
        );
        match r {
            Ok(_) => panic!("expected Err for empty tracked name"),
            Err(e) => assert!(format!("{e}").contains("empty name")),
        }
    }

    #[test]
    fn activated_table_jsonl_contains_every_tracked_tool() {
        let s = DaemonState::new(
            fixed_secret(),
            Wordlist::english_baseline(),
            tracked(),
            PathBuf::from("/wrappers"),
        )
        .unwrap();
        let jsonl = s.activated_table_jsonl().unwrap();
        let parsed = babbleon_core_v2::ActivatedTable::read_jsonl(
            std::io::Cursor::new(&jsonl),
        )
        .unwrap();
        assert_eq!(parsed.epoch, 0);
        assert_eq!(parsed.entries.len(), 3);
        // Each entry's scrambled name appears in the cached mapping.
        for e in &parsed.entries {
            assert!(s.current_mapping().reveal(&e.scrambled).is_some());
        }
    }

    #[test]
    fn rotate_bumps_epoch_and_changes_scrambled_names() {
        let mut s = DaemonState::new(
            fixed_secret(),
            Wordlist::english_baseline(),
            tracked(),
            PathBuf::from("/wrappers"),
        )
        .unwrap();
        let before: Vec<String> = s
            .current_mapping()
            .real_to_scrambled
            .values()
            .cloned()
            .collect();
        let new_epoch = s.rotate().unwrap();
        assert_eq!(new_epoch, 1);
        assert_eq!(s.epoch(), 1);
        let after: Vec<String> = s
            .current_mapping()
            .real_to_scrambled
            .values()
            .cloned()
            .collect();
        // Every scrambled name should change across rotation.
        for b in &before {
            assert!(
                !after.contains(b),
                "scrambled name {b} persisted across rotation",
            );
        }
    }

    #[test]
    fn rotate_updates_last_rotation_timestamp() {
        let mut s = DaemonState::new(
            fixed_secret(),
            Wordlist::english_baseline(),
            tracked(),
            PathBuf::from("/wrappers"),
        )
        .unwrap();
        let before = s.last_rotation_unix_secs().unwrap();
        // System clock has 1-second resolution on some platforms; sleep
        // a hair so the after-stamp is strictly greater.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        s.rotate().unwrap();
        let after = s.last_rotation_unix_secs().unwrap();
        assert!(
            after > before,
            "last_rotation_unix_secs did not advance: before={before} after={after}",
        );
    }

    #[test]
    fn repeated_activated_table_calls_yield_identical_bytes() {
        // Property: emit-activated-table is pure over (state, epoch).
        // A peer that retries the call within an epoch must observe
        // the same bytes.
        let s = DaemonState::new(
            fixed_secret(),
            Wordlist::english_baseline(),
            tracked(),
            PathBuf::from("/wrappers"),
        )
        .unwrap();
        let a = s.activated_table_jsonl().unwrap();
        let b = s.activated_table_jsonl().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn empty_tracked_list_is_accepted() {
        // The launcher needs to be able to come up against a state
        // with no tools yet enrolled (`babbleon init` shipped, no
        // `babbleon track` yet).  The mapping is empty but honey
        // names are still produced.
        let s = DaemonState::new(
            fixed_secret(),
            Wordlist::english_baseline(),
            Vec::new(),
            PathBuf::from("/wrappers"),
        )
        .unwrap();
        assert_eq!(s.tracked_count(), 0);
        let jsonl = s.activated_table_jsonl().unwrap();
        let parsed = babbleon_core_v2::ActivatedTable::read_jsonl(
            std::io::Cursor::new(&jsonl),
        )
        .unwrap();
        assert_eq!(parsed.entries.len(), 0);
        assert!(!parsed.honey_names.is_empty());
    }

    #[test]
    fn current_mapping_is_for_current_epoch() {
        let mut s = DaemonState::new(
            fixed_secret(),
            Wordlist::english_baseline(),
            tracked(),
            PathBuf::from("/wrappers"),
        )
        .unwrap();
        assert_eq!(s.current_mapping().epoch, 0);
        s.rotate().unwrap();
        assert_eq!(s.current_mapping().epoch, 1);
        s.rotate().unwrap();
        assert_eq!(s.current_mapping().epoch, 2);
    }

    #[test]
    fn wrapper_dir_round_trips_through_activated_table() {
        let s = DaemonState::new(
            fixed_secret(),
            Wordlist::english_baseline(),
            tracked(),
            PathBuf::from("/usr/local/libexec/babbleon/wrappers"),
        )
        .unwrap();
        let jsonl = s.activated_table_jsonl().unwrap();
        let parsed = babbleon_core_v2::ActivatedTable::read_jsonl(
            std::io::Cursor::new(&jsonl),
        )
        .unwrap();
        for e in &parsed.entries {
            assert!(
                e.wrapper_path
                    .starts_with("/usr/local/libexec/babbleon/wrappers"),
                "wrapper_path {:?} not under wrapper_dir",
                e.wrapper_path
            );
        }
    }
}
