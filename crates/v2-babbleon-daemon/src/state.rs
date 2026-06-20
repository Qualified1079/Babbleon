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
//! - [`DaemonState::epoch`] / [`DaemonState::tracked_count`] /
//!   [`DaemonState::last_rotation_unix_secs`] — read-only snapshot
//!   accessors used by the `Status` handler.
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

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use babbleon_core_v2::{
    build_activated_table_from_mapping, EpochMapping, MappingBuilder,
    PerHostSecret, Wordlist,
};

use crate::errors::{Error, Result};
use crate::materialization::{
    materialize, stale_names_from, MaterializationConfig, TrackedTool,
};

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
    tracked_tools: Vec<TrackedTool>,
    materialization: MaterializationConfig,
    epoch: u64,
    cached_mapping: EpochMapping,
    last_rotation: SystemTime,
    skip_materialization: bool,
}

impl DaemonState {
    /// Construct a daemon state from a freshly-loaded secret and a
    /// tracked-tool list.  Builds the epoch-0 mapping eagerly and
    /// materialises the corresponding on-disk wrappers and tripwire
    /// lists.
    ///
    /// `materialization.wrapper_dir` MUST be an absolute path.
    /// Every entry of `tracked_tools` MUST have a non-empty name and
    /// an absolute `real_path`.
    ///
    /// # Errors
    ///
    /// - [`Error::Cli`] if `wrapper_dir` or any `real_path` is not
    ///   absolute, or if any tracked tool name is empty.
    /// - [`Error::Mapping`] if mapping construction fails.
    /// - [`Error::Wrapper`] if on-disk materialisation fails.
    pub fn new(
        secret: PerHostSecret,
        wordlist: &'static Wordlist,
        tracked_tools: Vec<TrackedTool>,
        materialization: MaterializationConfig,
    ) -> Result<Self> {
        Self::construct(secret, wordlist, tracked_tools, materialization, false)
    }

    /// Like [`Self::new`] but skips on-disk materialisation.  Used
    /// in unit tests that do not want wrapper files on the host
    /// filesystem; production paths always go through `new`.
    ///
    /// # Errors
    ///
    /// Same as [`Self::new`] minus [`Error::Wrapper`].
    pub fn new_without_materialization(
        secret: PerHostSecret,
        wordlist: &'static Wordlist,
        tracked_tools: Vec<TrackedTool>,
        materialization: MaterializationConfig,
    ) -> Result<Self> {
        Self::construct(secret, wordlist, tracked_tools, materialization, true)
    }

    fn construct(
        secret: PerHostSecret,
        wordlist: &'static Wordlist,
        tracked_tools: Vec<TrackedTool>,
        materialization: MaterializationConfig,
        skip_materialization: bool,
    ) -> Result<Self> {
        if !materialization.wrapper_dir.is_absolute() {
            return Err(Error::Cli(format!(
                "wrapper_dir must be absolute (got {})",
                materialization.wrapper_dir.display()
            )));
        }
        for t in &tracked_tools {
            if t.name.is_empty() {
                return Err(Error::Cli(
                    "tracked-tool list contains an empty name".into(),
                ));
            }
            if !t.real_path.is_absolute() {
                return Err(Error::Cli(format!(
                    "tracked-tool {:?}: real_path must be absolute (got {})",
                    t.name,
                    t.real_path.display(),
                )));
            }
        }
        let names: Vec<String> =
            tracked_tools.iter().map(|t| t.name.clone()).collect();
        let initial_mapping =
            MappingBuilder::new(&secret, wordlist).build(&names, 0)?;
        if !skip_materialization {
            materialize(
                &materialization,
                &secret,
                &initial_mapping,
                &[],
                &tracked_tools,
            )?;
        }
        Ok(Self {
            secret,
            wordlist,
            tracked_tools,
            materialization,
            epoch: 0,
            cached_mapping: initial_mapping,
            last_rotation: SystemTime::now(),
            skip_materialization,
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
            &self.materialization.wrapper_dir,
        )
        .map_err(|e| Error::ActivatedTable(e.to_string()))?;
        let bytes = table
            .write_jsonl()
            .map_err(|e| Error::ActivatedTable(e.to_string()))?;
        Ok(bytes)
    }

    /// Bump the epoch, rebuild the cached mapping, and re-materialise
    /// the on-disk wrapper + tripwire-list artefacts.  Returns the
    /// new epoch number.
    ///
    /// The previous epoch's real and honey scrambled names become
    /// the new stale list so a worm that cached a name from the
    /// prior epoch trips a stale tripwire on its next invocation.
    ///
    /// # Errors
    ///
    /// - [`Error::Mapping`] if mapping construction fails.
    /// - [`Error::Wrapper`] if on-disk materialisation fails.  When
    ///   this fires the in-memory state still reflects the new
    ///   epoch (the mapping has already been swapped) but the
    ///   on-disk wrappers are in an inconsistent state; operator
    ///   should re-issue `rotate-mapping`.
    pub fn rotate(&mut self) -> Result<u64> {
        let new_epoch = self.epoch.checked_add(1).ok_or_else(|| {
            Error::Mapping(
                "epoch counter overflow; daemon refuses to wrap u64::MAX"
                    .into(),
            )
        })?;
        let names: Vec<String> =
            self.tracked_tools.iter().map(|t| t.name.clone()).collect();
        let new_mapping = MappingBuilder::new(&self.secret, self.wordlist)
            .build(&names, new_epoch)?;
        let stale = stale_names_from(&self.cached_mapping);
        self.epoch = new_epoch;
        self.cached_mapping = new_mapping;
        self.last_rotation = SystemTime::now();
        if !self.skip_materialization {
            materialize(
                &self.materialization,
                &self.secret,
                &self.cached_mapping,
                &stale,
                &self.tracked_tools,
            )?;
        }
        Ok(new_epoch)
    }

    /// Read-only view of the wrapper directory.  This is the
    /// directory the daemon materialises wrappers into on every
    /// rotation, and the prefix that every activated-table
    /// `wrapper_path` is rooted at.
    #[must_use]
    pub fn wrapper_dir(&self) -> &Path {
        &self.materialization.wrapper_dir
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
    use std::path::PathBuf;

    fn fixed_secret() -> PerHostSecret {
        PerHostSecret::from_bytes(&[9u8; 32]).unwrap()
    }

    fn tracked() -> Vec<TrackedTool> {
        ["curl", "ssh", "git"]
            .iter()
            .map(|n| TrackedTool {
                name: (*n).to_string(),
                real_path: PathBuf::from(format!("/usr/bin/{n}")),
            })
            .collect()
    }

    fn cfg(dir: impl Into<PathBuf>) -> MaterializationConfig {
        MaterializationConfig {
            wrapper_dir: dir.into(),
            honey_list_path: None,
            stale_list_path: None,
            trusted_ns_inode: None,
        }
    }

    fn build_state(tools: Vec<TrackedTool>, wrapper_dir: &str) -> DaemonState {
        DaemonState::new_without_materialization(
            fixed_secret(),
            Wordlist::english_baseline(),
            tools,
            cfg(wrapper_dir),
        )
        .unwrap()
    }

    #[test]
    fn new_eagerly_builds_epoch_zero_mapping() {
        let s = build_state(tracked(), "/var/lib/babbleon/wrappers");
        assert_eq!(s.epoch(), 0);
        assert_eq!(s.tracked_count(), 3);
        assert!(s.last_rotation_unix_secs().is_some());
    }

    #[test]
    fn new_rejects_relative_wrapper_dir() {
        let r = DaemonState::new_without_materialization(
            fixed_secret(),
            Wordlist::english_baseline(),
            tracked(),
            cfg("relative/wrappers"),
        );
        match r {
            Ok(_) => panic!("expected Err for relative wrapper_dir"),
            Err(e) => assert!(format!("{e}").contains("absolute")),
        }
    }

    #[test]
    fn new_rejects_empty_tracked_name() {
        let mut t = tracked();
        t.push(TrackedTool {
            name: String::new(),
            real_path: PathBuf::from("/usr/bin/zzz"),
        });
        let r = DaemonState::new_without_materialization(
            fixed_secret(),
            Wordlist::english_baseline(),
            t,
            cfg("/x"),
        );
        match r {
            Ok(_) => panic!("expected Err for empty tracked name"),
            Err(e) => assert!(format!("{e}").contains("empty name")),
        }
    }

    #[test]
    fn new_rejects_relative_real_path() {
        let r = DaemonState::new_without_materialization(
            fixed_secret(),
            Wordlist::english_baseline(),
            vec![TrackedTool {
                name: "curl".into(),
                real_path: PathBuf::from("bin/curl"),
            }],
            cfg("/x"),
        );
        match r {
            Ok(_) => panic!("expected Err for relative real_path"),
            Err(e) => {
                let m = format!("{e}");
                assert!(m.contains("real_path") && m.contains("absolute"), "{m}");
            }
        }
    }

    #[test]
    fn activated_table_jsonl_contains_every_tracked_tool() {
        let s = build_state(tracked(), "/wrappers");
        let jsonl = s.activated_table_jsonl().unwrap();
        let parsed = babbleon_core_v2::ActivatedTable::read_jsonl(
            std::io::Cursor::new(&jsonl),
        )
        .unwrap();
        assert_eq!(parsed.epoch, 0);
        assert_eq!(parsed.entries.len(), 3);
        for e in &parsed.entries {
            assert!(s.current_mapping().reveal(&e.scrambled).is_some());
        }
    }

    #[test]
    fn rotate_bumps_epoch_and_changes_scrambled_names() {
        let mut s = build_state(tracked(), "/wrappers");
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
        for b in &before {
            assert!(
                !after.contains(b),
                "scrambled name {b} persisted across rotation",
            );
        }
    }

    #[test]
    fn rotate_updates_last_rotation_timestamp() {
        let mut s = build_state(tracked(), "/wrappers");
        let before = s.last_rotation_unix_secs().unwrap();
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
        let s = build_state(tracked(), "/wrappers");
        let a = s.activated_table_jsonl().unwrap();
        let b = s.activated_table_jsonl().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn empty_tracked_list_is_accepted() {
        let s = build_state(Vec::new(), "/wrappers");
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
        let mut s = build_state(tracked(), "/wrappers");
        assert_eq!(s.current_mapping().epoch, 0);
        s.rotate().unwrap();
        assert_eq!(s.current_mapping().epoch, 1);
        s.rotate().unwrap();
        assert_eq!(s.current_mapping().epoch, 2);
    }

    #[test]
    fn wrapper_dir_round_trips_through_activated_table() {
        let s = build_state(tracked(), "/usr/local/libexec/babbleon/wrappers");
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

    fn tracked_in(dir: &Path, names: &[&str]) -> Vec<TrackedTool> {
        names
            .iter()
            .map(|n| {
                let p = dir.join(format!("real-{n}"));
                std::fs::write(&p, "#!/bin/sh\n").unwrap();
                TrackedTool {
                    name: (*n).to_string(),
                    real_path: p,
                }
            })
            .collect()
    }

    fn cfg_in_tmp(dir: &Path) -> MaterializationConfig {
        MaterializationConfig {
            wrapper_dir: dir.join("wrappers"),
            honey_list_path: Some(dir.join("honey.list")),
            stale_list_path: Some(dir.join("stale.list")),
            trusted_ns_inode: None,
        }
    }

    #[test]
    fn new_materialises_real_and_honey_wrappers_on_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = tracked_in(tmp.path(), &["curl", "ssh"]);
        let cfg = cfg_in_tmp(tmp.path());
        let s = DaemonState::new(
            fixed_secret(),
            Wordlist::english_baseline(),
            tools,
            cfg.clone(),
        )
        .unwrap();
        for scrambled in s.current_mapping().real_to_scrambled.values() {
            assert!(
                cfg.wrapper_dir.join(scrambled).exists(),
                "missing real wrapper {scrambled}",
            );
        }
        for honey in &s.current_mapping().honey_names {
            assert!(
                cfg.wrapper_dir.join(honey).exists(),
                "missing honey wrapper {honey}",
            );
        }
    }

    #[test]
    fn rotate_materialises_new_wrappers_and_writes_stale_list_from_previous_epoch() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = tracked_in(tmp.path(), &["curl"]);
        let cfg = cfg_in_tmp(tmp.path());
        let mut s = DaemonState::new(
            fixed_secret(),
            Wordlist::english_baseline(),
            tools,
            cfg.clone(),
        )
        .unwrap();
        let prev_real: Vec<String> = s
            .current_mapping()
            .real_to_scrambled
            .values()
            .cloned()
            .collect();
        let prev_honey: Vec<String> = s.current_mapping().honey_names.clone();

        s.rotate().unwrap();

        let stale_body =
            std::fs::read_to_string(cfg.stale_list_path.as_ref().unwrap()).unwrap();
        for name in prev_real.iter().chain(prev_honey.iter()) {
            assert!(
                stale_body.contains(&format!("{name}\n")),
                "stale list missing {name}",
            );
        }
        for scrambled in s.current_mapping().real_to_scrambled.values() {
            assert!(
                cfg.wrapper_dir.join(scrambled).exists(),
                "missing new-epoch real wrapper {scrambled}",
            );
        }
    }

    #[test]
    fn new_genesis_stale_list_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = tracked_in(tmp.path(), &["curl"]);
        let cfg = cfg_in_tmp(tmp.path());
        DaemonState::new(
            fixed_secret(),
            Wordlist::english_baseline(),
            tools,
            cfg.clone(),
        )
        .unwrap();
        let body =
            std::fs::read_to_string(cfg.stale_list_path.as_ref().unwrap()).unwrap();
        assert!(body.is_empty(), "genesis stale list must be empty, got: {body}");
    }
}
