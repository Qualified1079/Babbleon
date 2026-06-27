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
//! [`DaemonState`] is that owner.  It has two life-cycle states:
//!
//! - **Locked.**  Daemon has started but no operator has unlocked
//!   the vault.  State carries only the static configuration
//!   (wordlist, tracked-tool list, materialisation paths); no secret
//!   bytes are in memory.  `Status` works (returns
//!   `vault_locked = true`); every mutator and every secret-derived
//!   read (`EmitActivatedTable`, `RotateMapping`) errors with
//!   `Error::Vault("vault locked")`.
//! - **Unlocked.**  Operator has sent `Request::Unlock`; the daemon
//!   has installed a `PerHostSecret` and built the epoch-0 mapping.
//!   All operations work.
//!
//! Transitions are one-way for now: Locked -> Unlocked.  A future
//! `Lock` request (operator-driven re-sealing) can transition the
//! other direction, but it is filed for phase 4+ and is not yet on
//! the wire schema.
//!
//! # Mechanism
//!
//! The state machine is single-threaded by design.  The daemon's
//! socket loop is single-connection-at-a-time in phase 2; phase 4+
//! parallelism (if any) lands as a worker-pool that takes
//! `&DaemonState` for read-only queries and serializes mutations
//! through a single owner.
//!
//! Internal layout splits configuration from secret-bearing state so
//! the unlock transition is one local mutation, not a struct rebuild:
//!
//! - `DaemonConfig` — wordlist, tracked tools, materialisation
//!   config, test-only `skip_materialization` flag.  Shared across
//!   both lifecycle states.
//! - `SecretState::Locked` — empty.
//! - `SecretState::Unlocked` — secret, epoch counter, cached
//!   mapping, last-rotation timestamp.
//!
//! Methods:
//!
//! - [`DaemonState::new_locked`] — construct in the Locked state.
//!   Used by the production daemon startup path; the operator must
//!   subsequently issue an `Unlock` request to install a secret.
//! - [`DaemonState::new_unlocked`] — construct directly in the
//!   Unlocked state (eagerly builds the epoch-0 mapping).  Used by
//!   tests and by the `--insecure-stub-secret` startup path until it
//!   retires in a later phase.
//! - [`DaemonState::unlock`] — Locked -> Unlocked transition.
//!   Returns `Error::Vault` if the daemon is already Unlocked
//!   (re-unlock would re-mlock the new bytes without zeroizing the
//!   old; operators must restart the daemon to load a different
//!   secret).
//! - [`DaemonState::epoch`] / [`DaemonState::vault_locked`] /
//!   [`DaemonState::tracked_count`] /
//!   [`DaemonState::last_rotation_unix_secs`] — accessors used by
//!   the `Status` handler.
//! - [`DaemonState::activated_table_jsonl`] — serialize the cached
//!   mapping as JSONL.  Errors with `Error::Vault` when Locked.
//! - [`DaemonState::rotate`] — bump the epoch counter and rebuild
//!   the cached mapping.  Errors with `Error::Vault` when Locked.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** secret leakage via the daemon's public API
//!   (nothing public exposes secret bytes); secret leakage via Drop
//!   (`PerHostSecret`'s zeroize); stale-mapping race (cached
//!   mapping is a `Clone` of the last build, never a live reference
//!   into the builder's transient state); pre-unlock mutator
//!   surface (the Locked state refuses every mutator with a single
//!   error variant, no half-success paths).
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
    PerHostSecret, PermutationCache, Wordlist,
};
use babbleon_daemon_protocol_v2::{
    ALIAS_COUNT_VARIABLE_FROM_VERSION_WIRE, ALIAS_COUNT_WIRE,
    MAX_ALIAS_COUNT_WIRE,
};
use babbleon_preprocessor_v2::alias_count_for_epoch;

use crate::errors::{Error, Result};
use crate::materialization::{
    materialize_atomic, stale_names_from, MaterializationConfig, TrackedTool,
};

/// Static configuration shared across both lifecycle states.
struct DaemonConfig {
    wordlist: &'static Wordlist,
    tracked_tools: Vec<TrackedTool>,
    materialization: MaterializationConfig,
    /// Test-only knob: skip on-disk materialisation.  Production
    /// paths always set this to false.
    skip_materialization: bool,
}

/// Lifecycle state of the per-host secret.
enum SecretState {
    /// No secret in memory.  Daemon waits for an `Unlock` request.
    Locked,
    /// Secret installed; mapping built.
    Unlocked {
        secret: PerHostSecret,
        epoch: u64,
        cached_mapping: EpochMapping,
        last_rotation: SystemTime,
    },
}

/// In-memory daemon state.
///
/// Single-owner, mutate through `&mut self`.  Send-safe (every
/// member is `Send`) so a future worker-pool can move it across
/// threads if needed, but no Sync — the state machine is not lock-
/// free.
///
/// `DaemonState` is intentionally NOT Clone, NOT Copy, NOT Debug
/// (security-baseline rule 3).
pub struct DaemonState {
    config: DaemonConfig,
    secret_state: SecretState,
    /// LRU cache for [`Permutation`]s consumed by the
    /// `MappingBuilder` hot path ([`Self::token_mapping`]).  Sized
    /// to the production daemon's worst-case fan-out
    /// (`ALIAS_COUNT_WIRE` virtual epochs x identifier + honey).
    /// Cleared on any state transition that could change the
    /// per-host secret; today only `unlock` does that, and it
    /// refuses re-unlock without a daemon restart so a fresh cache
    /// at construction is always consistent.
    permutation_cache: PermutationCache,
}

impl DaemonState {
    /// Construct a daemon in the Locked state.  No secret in memory
    /// yet; the operator must issue an `Unlock` request to install
    /// one.
    ///
    /// `materialization.wrapper_dir` MUST be an absolute path.
    /// Every entry of `tracked_tools` MUST have a non-empty name and
    /// an absolute `real_path`.
    ///
    /// # Errors
    ///
    /// - [`Error::Cli`] if `wrapper_dir` or any `real_path` is not
    ///   absolute, or if any tracked tool name is empty.
    pub fn new_locked(
        wordlist: &'static Wordlist,
        tracked_tools: Vec<TrackedTool>,
        materialization: MaterializationConfig,
    ) -> Result<Self> {
        let config = build_config(
            wordlist,
            tracked_tools,
            materialization,
            false,
        )?;
        Ok(Self {
            config,
            secret_state: SecretState::Locked,
            permutation_cache: PermutationCache::with_default_capacity(),
        })
    }

    /// Construct a daemon directly in the Unlocked state with the
    /// supplied secret.  Eagerly builds the epoch-0 mapping and
    /// materialises wrappers on disk.
    ///
    /// Used by tests and by the `--insecure-stub-secret` startup
    /// path; production restarts go Locked first, then receive an
    /// Unlock request.
    ///
    /// # Errors
    ///
    /// - [`Error::Cli`] for the same reasons as [`Self::new_locked`].
    /// - [`Error::Mapping`] if mapping construction fails.
    /// - [`Error::Wrapper`] if on-disk materialisation fails.
    pub fn new_unlocked(
        secret: PerHostSecret,
        wordlist: &'static Wordlist,
        tracked_tools: Vec<TrackedTool>,
        materialization: MaterializationConfig,
    ) -> Result<Self> {
        let config = build_config(
            wordlist,
            tracked_tools,
            materialization,
            false,
        )?;
        let unlocked = build_unlocked_state(&config, secret, 0)?;
        Ok(Self {
            config,
            secret_state: unlocked,
            permutation_cache: PermutationCache::with_default_capacity(),
        })
    }

    /// Like [`Self::new_unlocked`] but skips on-disk materialisation.
    /// Used in unit tests that do not want wrapper files on the host
    /// filesystem.
    ///
    /// # Errors
    ///
    /// Same as [`Self::new_unlocked`] minus [`Error::Wrapper`].
    pub fn new_without_materialization(
        secret: PerHostSecret,
        wordlist: &'static Wordlist,
        tracked_tools: Vec<TrackedTool>,
        materialization: MaterializationConfig,
    ) -> Result<Self> {
        let config = build_config(
            wordlist,
            tracked_tools,
            materialization,
            true,
        )?;
        let unlocked = build_unlocked_state(&config, secret, 0)?;
        Ok(Self {
            config,
            secret_state: unlocked,
            permutation_cache: PermutationCache::with_default_capacity(),
        })
    }

    /// Locked -> Unlocked transition.  Installs `secret`, builds the
    /// epoch-0 mapping, materialises wrappers on disk.  Returns the
    /// epoch the daemon is now serving (always 0 today; phase 4+
    /// will accept an epoch hint from the vault payload).
    ///
    /// # Errors
    ///
    /// - [`Error::Vault`] if the daemon is already Unlocked.  Re-
    ///   unlocking would risk leaving the prior secret's mapping
    ///   live alongside the new one; operators must restart the
    ///   daemon to swap secrets.
    /// - [`Error::Mapping`] / [`Error::Wrapper`] from mapping build
    ///   or materialisation.
    pub fn unlock(&mut self, secret: PerHostSecret) -> Result<u64> {
        if matches!(self.secret_state, SecretState::Unlocked { .. }) {
            return Err(Error::Vault(
                "vault is already unlocked; restart the daemon to install \
                 a different secret"
                    .into(),
            ));
        }
        // Resume from the HMAC-sealed epoch journal if one is
        // configured.  A valid journal supplies the last-rotated
        // epoch; a missing journal resumes at 0 (genesis); a
        // tampered journal logs a warn and resumes at 0 — never
        // crash the unlock path because the journal can always
        // be reconstructed by one rotate after start.
        let starting_epoch = self.resume_epoch_from_journal(&secret);
        let unlocked = build_unlocked_state(&self.config, secret, starting_epoch)?;
        self.secret_state = unlocked;
        // After mapping is built and materialised, persist the
        // resumed epoch so a subsequent restart-without-rotate
        // doesn't lose its place.  Failure to write is non-fatal
        // (logged warn); the daemon is still functional.
        self.persist_epoch_to_journal_if_configured(starting_epoch);
        Ok(self.epoch().unwrap_or(0))
    }

    /// Read the journal, returning the resumed epoch or 0 on any
    /// missing-or-bad-journal condition.  Tamper detection logs a
    /// `warn` so operator-side audit can spot the event.
    fn resume_epoch_from_journal(&self, secret: &PerHostSecret) -> u64 {
        let Some(path) = self.config.materialization.journal_path.as_deref() else {
            return 0;
        };
        match crate::epoch_journal::read_journal(secret, path) {
            Ok(Some(epoch)) => {
                tracing::info!(
                    journal_path = %path.display(),
                    resumed_epoch = epoch,
                    "epoch journal verified; resuming",
                );
                epoch
            }
            Ok(None) => {
                tracing::info!(
                    journal_path = %path.display(),
                    "epoch journal absent; starting at 0 (genesis)",
                );
                0
            }
            Err(e) => {
                tracing::warn!(
                    journal_path = %path.display(),
                    error = %e,
                    "epoch journal failed validation; resuming at 0",
                );
                0
            }
        }
    }

    /// Write `epoch` to the journal if one is configured.  Errors
    /// are logged at `warn` and otherwise swallowed — a failed
    /// write does not abort the operation that triggered it
    /// (unlock or rotate).  Operator can re-trigger a rotate to
    /// retry the write.
    fn persist_epoch_to_journal_if_configured(&self, epoch: u64) {
        let Some(path) = self.config.materialization.journal_path.as_deref() else {
            return;
        };
        let SecretState::Unlocked { secret, .. } = &self.secret_state else {
            return;
        };
        if let Err(e) = crate::epoch_journal::write_journal(epoch, secret, path) {
            tracing::warn!(
                journal_path = %path.display(),
                error = %e,
                "epoch journal write failed; subsequent restart will lose this rotation's place",
            );
        }
    }

    /// Current epoch number, or `None` when the vault is locked.
    #[must_use]
    pub fn epoch(&self) -> Option<u64> {
        match &self.secret_state {
            SecretState::Locked => None,
            SecretState::Unlocked { epoch, .. } => Some(*epoch),
        }
    }

    /// Whether the per-host secret is loaded.
    #[must_use]
    pub fn vault_locked(&self) -> bool {
        matches!(self.secret_state, SecretState::Locked)
    }

    /// Number of currently tracked tools.
    #[must_use]
    pub fn tracked_count(&self) -> usize {
        self.config.tracked_tools.len()
    }

    /// `UNIX_EPOCH`-relative seconds of the last successful rotation,
    /// or `None` when the vault is locked or the system clock is set
    /// before `UNIX_EPOCH` (catastrophe state; not a hard error).
    #[must_use]
    pub fn last_rotation_unix_secs(&self) -> Option<u64> {
        match &self.secret_state {
            SecretState::Locked => None,
            SecretState::Unlocked { last_rotation, .. } => last_rotation
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs()),
        }
    }

    /// Build the activated table JSONL for the current epoch.
    ///
    /// Returns the validated, byte-ready JSONL payload the launcher
    /// consumes.  The mapping itself is cached so repeated calls
    /// within an epoch are O(activated-table-size), not O(wordlist).
    ///
    /// # Errors
    ///
    /// - [`Error::Vault`] when the daemon is Locked.
    /// - [`Error::ActivatedTable`] (via `From`) if table construction
    ///   or JSONL serialization fails (cannot happen in practice for
    ///   a well-formed mapping; the validators only reject malformed
    ///   names or relative paths).
    pub fn activated_table_jsonl(&self) -> Result<Vec<u8>> {
        let SecretState::Unlocked { cached_mapping, .. } = &self.secret_state
        else {
            return Err(Error::Vault(
                "activated-table requires an unlocked vault; \
                 send Unlock first"
                    .into(),
            ));
        };
        let table = build_activated_table_from_mapping(
            cached_mapping,
            &self.config.materialization.wrapper_dir,
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
    /// - [`Error::Vault`] when the daemon is Locked.
    /// - [`Error::Mapping`] if mapping construction fails.
    /// - [`Error::Wrapper`] if on-disk materialisation fails.  When
    ///   this fires the in-memory state still reflects the new
    ///   epoch (the mapping has already been swapped) but the
    ///   on-disk wrappers are in an inconsistent state; operator
    ///   should re-issue `rotate-mapping`.
    pub fn rotate(&mut self) -> Result<u64> {
        let SecretState::Unlocked {
            secret,
            epoch,
            cached_mapping,
            last_rotation,
        } = &mut self.secret_state
        else {
            return Err(Error::Vault(
                "rotate-mapping requires an unlocked vault; \
                 send Unlock first"
                    .into(),
            ));
        };
        let new_epoch = epoch.checked_add(1).ok_or_else(|| {
            Error::Mapping(
                "epoch counter overflow; daemon refuses to wrap u64::MAX"
                    .into(),
            )
        })?;
        let names: Vec<String> = self
            .config
            .tracked_tools
            .iter()
            .map(|t| t.name.clone())
            .collect();
        // Route through the cache so the resume-after-restart or
        // double-rotate edge cases (rare but possible operationally)
        // hit a warm permutation instead of re-doing Fisher-Yates.
        // First rotation of a fresh epoch is still cold; this is
        // about idempotency, not steady-state hit rate.
        let new_mapping = MappingBuilder::with_cache(
            secret,
            self.config.wordlist,
            &self.permutation_cache,
        )
        .build(&names, new_epoch)?;
        let stale = stale_names_from(cached_mapping);
        *epoch = new_epoch;
        *cached_mapping = new_mapping;
        *last_rotation = SystemTime::now();
        if !self.config.skip_materialization {
            materialize_atomic(
                &self.config.materialization,
                secret,
                cached_mapping,
                &stale,
                &self.config.tracked_tools,
            )?;
        }
        // Persist the new epoch to the journal so a restart
        // resumes here rather than rewinding to 0.  Logged-warn
        // on failure but not fatal — see persist helper.
        self.persist_epoch_to_journal_if_configured(new_epoch);
        Ok(new_epoch)
    }

    /// Read-only view of the wrapper directory.  This is the
    /// directory the daemon materialises wrappers into on every
    /// rotation, and the prefix that every activated-table
    /// `wrapper_path` is rooted at.
    #[must_use]
    pub fn wrapper_dir(&self) -> &Path {
        &self.config.materialization.wrapper_dir
    }

    /// Read-only view of the cached mapping for the current epoch.
    /// Returns `None` when the daemon is Locked.
    ///
    /// Exposed for diagnostic / test use; the
    /// [`Self::activated_table_jsonl`] path is the production
    /// consumer surface.  The returned reference does NOT carry
    /// secret bytes — `EpochMapping` only holds names and honey
    /// strings.
    #[must_use]
    pub fn current_mapping(&self) -> Option<&EpochMapping> {
        match &self.secret_state {
            SecretState::Locked => None,
            SecretState::Unlocked { cached_mapping, .. } => Some(cached_mapping),
        }
    }

    /// Derive the five per-epoch whitespace compounds the operator
    /// CLI's `scramble` / `unscramble` subcommands consume.
    ///
    /// Returns the current epoch and the compound array in
    /// `WhitespaceKind::ALL` slot order
    /// (`Newline`, `Space`, `Tab`, `IndentOpen`, `IndentClose`).  The
    /// daemon's `PerHostSecret` stays inside this `DaemonState` for
    /// the call; only the HKDF-derived output crosses the wire to
    /// the trust-tier CLI peer.
    ///
    /// # Errors
    ///
    /// - [`Error::Vault`] when the daemon is Locked (the secret
    ///   needed to derive the whitespace permutation is not in
    ///   memory).
    /// - [`Error::Mapping`] if the whitespace derivation fails.  In
    ///   practice unreachable: the v2 baseline wordlist is 369 652
    ///   entries (well above the 20-entry minimum the derivation
    ///   needs) and HKDF/Permutation only fail at zero-size or
    ///   `u32::MAX`; the error path exists so a future smaller
    ///   wordlist swap surfaces loudly rather than panicking.
    pub fn whitespace_compounds(
        &self,
    ) -> Result<(
        u64,
        [String; babbleon_preprocessor_v2::whitespace_wordlist::WHITESPACE_COMPOUND_COUNT],
    )> {
        let SecretState::Unlocked { secret, epoch, .. } = &self.secret_state else {
            return Err(Error::Vault(
                "whitespace-compounds requires an unlocked vault; \
                 send Unlock first"
                    .into(),
            ));
        };
        let wl = babbleon_preprocessor_v2::WhitespaceWordlist::build(
            secret,
            self.config.wordlist,
            *epoch,
        )
        .map_err(|e| Error::Mapping(e.to_string()))?;
        // Take ownership of the compounds array by cloning out of
        // the builder's owned strings (the builder is borrow-only
        // after construction).  The 5×~25-byte string clone is
        // microseconds; the cost is negligible against the HKDF +
        // Fisher-Yates above.
        Ok((*epoch, wl.all_compounds().clone()))
    }

    /// Derive per-epoch scramble aliases for a caller-supplied token
    /// list (language-agnostic dynamic identifier scramble).
    ///
    /// Returns the current epoch and an `aliases[token_idx][alias_idx]`
    /// matrix where each element is the compound for that token at
    /// that alias index.
    ///
    /// `format_version` selects the alias-count regime:
    ///
    /// - `format_version < ALIAS_COUNT_VARIABLE_FROM_VERSION_WIRE`:
    ///   legacy mode.  Returns
    ///   [`babbleon_daemon_protocol_v2::ALIAS_COUNT_WIRE`] aliases per
    ///   token using virtual epochs
    ///   `epoch * ALIAS_COUNT_WIRE + i` (unchanged from the
    ///   pre-Phase-B daemon — files at format v0/v1 unscramble
    ///   correctly).
    /// - `format_version >= ALIAS_COUNT_VARIABLE_FROM_VERSION_WIRE`:
    ///   variable mode.  Returns
    ///   `alias_count_for_epoch(format_version, epoch)` aliases per
    ///   token using virtual epochs
    ///   `epoch * MAX_ALIAS_COUNT_WIRE + i`.  The MAX-strided math
    ///   keeps cache keys non-colliding across host-epochs whose
    ///   alias counts differ.
    ///
    /// The daemon's `PerHostSecret` stays inside this `DaemonState`
    /// for the call; only the HKDF-derived output crosses the wire.
    ///
    /// # Errors
    ///
    /// - [`Error::Vault`] when the daemon is Locked.
    /// - [`Error::Mapping`] if compound derivation fails (unreachable
    ///   with the v2 baseline wordlist in practice).
    pub fn token_mapping(
        &self,
        tokens: &[String],
        format_version: u32,
    ) -> Result<(u64, Vec<Vec<String>>)> {
        let SecretState::Unlocked { secret, epoch, .. } = &self.secret_state else {
            return Err(Error::Vault(
                "token-mapping requires an unlocked vault; \
                 send Unlock first"
                    .into(),
            ));
        };
        let wl = self.config.wordlist;
        // Cache-backed builder: each (virtual_epoch, purpose) pair
        // is built once per daemon lifetime; subsequent requests at
        // the same epoch hit the cache and skip the ~35 ms Fisher-
        // Yates pass.  See `DaemonState::permutation_cache`.
        let builder =
            MappingBuilder::with_cache(secret, wl, &self.permutation_cache);
        let (alias_count, stride) = if format_version
            < ALIAS_COUNT_VARIABLE_FROM_VERSION_WIRE
        {
            (ALIAS_COUNT_WIRE, ALIAS_COUNT_WIRE)
        } else {
            // Variable mode: alias count is per-epoch, stride is the
            // wire-imposed maximum so cache keys are non-colliding
            // across the range.
            (
                alias_count_for_epoch(format_version, *epoch),
                MAX_ALIAS_COUNT_WIRE,
            )
        };
        let base = epoch.saturating_mul(stride as u64);
        // Build each alias mapping and extract compounds per token.
        let mut per_alias_compounds: Vec<Vec<String>> =
            Vec::with_capacity(alias_count);
        for ai in 0..alias_count {
            let virtual_epoch = base + ai as u64;
            let mapping = builder
                .build(tokens, virtual_epoch)
                .map_err(|e| Error::Mapping(e.to_string()))?;
            let compounds: Vec<String> = tokens
                .iter()
                .map(|t| {
                    mapping
                        .scramble(t)
                        .map(str::to_owned)
                        .unwrap_or_default()
                })
                .collect();
            per_alias_compounds.push(compounds);
        }
        // Transpose: per_alias_compounds[alias][token] →
        // aliases[token][alias].
        let mut aliases: Vec<Vec<String>> =
            tokens.iter().map(|_| Vec::with_capacity(alias_count)).collect();
        for alias_compounds in per_alias_compounds {
            for (ti, compound) in alias_compounds.into_iter().enumerate() {
                aliases[ti].push(compound);
            }
        }
        Ok((*epoch, aliases))
    }
}

/// Validate and pack the static configuration shared across lifecycle
/// states.  Mirrors v1's `DaemonState::new`'s validation pass.
fn build_config(
    wordlist: &'static Wordlist,
    tracked_tools: Vec<TrackedTool>,
    materialization: MaterializationConfig,
    skip_materialization: bool,
) -> Result<DaemonConfig> {
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
    Ok(DaemonConfig {
        wordlist,
        tracked_tools,
        materialization,
        skip_materialization,
    })
}

/// Build the epoch-N Unlocked state (mapping + cached metadata) and
/// materialise on-disk artefacts if the config permits.  Used by
/// `new_unlocked` (genesis at boot for the stub-secret path), by
/// `new_without_materialization` (test path), and by `unlock` (real
/// unlock path).
fn build_unlocked_state(
    config: &DaemonConfig,
    secret: PerHostSecret,
    epoch: u64,
) -> Result<SecretState> {
    let names: Vec<String> = config
        .tracked_tools
        .iter()
        .map(|t| t.name.clone())
        .collect();
    let cached_mapping =
        MappingBuilder::new(&secret, config.wordlist).build(&names, epoch)?;
    if !config.skip_materialization {
        materialize_atomic(
            &config.materialization,
            &secret,
            &cached_mapping,
            &[],
            &config.tracked_tools,
        )?;
    }
    Ok(SecretState::Unlocked {
        secret,
        epoch,
        cached_mapping,
        last_rotation: SystemTime::now(),
    })
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
            journal_path: None,
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

    fn build_locked(tools: Vec<TrackedTool>, wrapper_dir: &str) -> DaemonState {
        DaemonState::new_locked(
            Wordlist::english_baseline(),
            tools,
            cfg(wrapper_dir),
        )
        .unwrap()
    }

    // ----- new_locked / new_unlocked invariants -----

    #[test]
    fn new_locked_reports_locked_state() {
        let s = build_locked(tracked(), "/wrappers");
        assert!(s.vault_locked());
        assert_eq!(s.epoch(), None);
        assert_eq!(s.tracked_count(), 3);
        assert!(s.last_rotation_unix_secs().is_none());
        assert!(s.current_mapping().is_none());
    }

    #[test]
    fn new_unlocked_eagerly_builds_epoch_zero_mapping() {
        let s = build_state(tracked(), "/var/lib/babbleon/wrappers");
        assert!(!s.vault_locked());
        assert_eq!(s.epoch(), Some(0));
        assert_eq!(s.tracked_count(), 3);
        assert!(s.last_rotation_unix_secs().is_some());
        assert!(s.current_mapping().is_some());
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
    fn new_locked_rejects_relative_wrapper_dir() {
        let r = DaemonState::new_locked(
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

    // ----- Locked-state mutator rejection -----

    #[test]
    fn locked_emit_activated_table_returns_vault_error() {
        let s = build_locked(tracked(), "/wrappers");
        let r = s.activated_table_jsonl();
        match r {
            Err(Error::Vault(m)) => assert!(m.contains("locked"), "{m}"),
            Err(other) => panic!("expected Error::Vault, got {other:?}"),
            Ok(_) => panic!("locked state must refuse activated-table"),
        }
    }

    #[test]
    fn locked_rotate_returns_vault_error() {
        let mut s = build_locked(tracked(), "/wrappers");
        let r = s.rotate();
        match r {
            Err(Error::Vault(m)) => assert!(m.contains("locked"), "{m}"),
            Err(other) => panic!("expected Error::Vault, got {other:?}"),
            Ok(_) => panic!("locked state must refuse rotate"),
        }
    }

    // ----- unlock transition -----

    #[test]
    fn unlock_transitions_locked_to_unlocked() {
        let mut s = build_locked(tracked(), "/wrappers");
        let mut s = with_skip_materialization(&mut s);
        let epoch = s.unlock(fixed_secret()).unwrap();
        assert_eq!(epoch, 0);
        assert!(!s.vault_locked());
        assert_eq!(s.epoch(), Some(0));
        assert!(s.current_mapping().is_some());
    }

    #[test]
    fn unlock_then_emit_returns_jsonl_for_epoch_zero() {
        let mut s = build_locked(tracked(), "/wrappers");
        let mut s = with_skip_materialization(&mut s);
        s.unlock(fixed_secret()).unwrap();
        let jsonl = s.activated_table_jsonl().unwrap();
        let parsed = babbleon_core_v2::ActivatedTable::read_jsonl(
            std::io::Cursor::new(&jsonl),
        )
        .unwrap();
        assert_eq!(parsed.epoch, 0);
        assert_eq!(parsed.entries.len(), 3);
    }

    #[test]
    fn unlock_then_rotate_bumps_epoch() {
        let mut s = build_locked(tracked(), "/wrappers");
        let mut s = with_skip_materialization(&mut s);
        s.unlock(fixed_secret()).unwrap();
        assert_eq!(s.rotate().unwrap(), 1);
        assert_eq!(s.epoch(), Some(1));
    }

    #[test]
    fn double_unlock_is_rejected() {
        let mut s = build_locked(tracked(), "/wrappers");
        let mut s = with_skip_materialization(&mut s);
        s.unlock(fixed_secret()).unwrap();
        match s.unlock(PerHostSecret::from_bytes(&[7u8; 32]).unwrap()) {
            Err(Error::Vault(m)) => assert!(m.contains("already"), "{m}"),
            Err(other) => panic!("expected Error::Vault, got {other:?}"),
            Ok(_) => panic!("double unlock must be rejected"),
        }
    }

    #[test]
    fn unlock_distinct_secret_yields_distinct_mapping() {
        // Build two Locked states, unlock each with a different
        // secret, confirm the cached mappings disagree.
        let mut a = build_locked(tracked(), "/wrappers");
        let mut a = with_skip_materialization(&mut a);
        a.unlock(PerHostSecret::from_bytes(&[1u8; 32]).unwrap())
            .unwrap();
        let mut b = build_locked(tracked(), "/wrappers");
        let mut b = with_skip_materialization(&mut b);
        b.unlock(PerHostSecret::from_bytes(&[2u8; 32]).unwrap())
            .unwrap();
        let names_a: Vec<String> = a
            .current_mapping()
            .unwrap()
            .real_to_scrambled
            .values()
            .cloned()
            .collect();
        let names_b: Vec<String> = b
            .current_mapping()
            .unwrap()
            .real_to_scrambled
            .values()
            .cloned()
            .collect();
        assert_ne!(names_a, names_b);
    }

    // ----- existing Unlocked-state invariants (regression) -----

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
            assert!(s.current_mapping().unwrap().reveal(&e.scrambled).is_some());
        }
    }

    #[test]
    fn rotate_bumps_epoch_and_changes_scrambled_names() {
        let mut s = build_state(tracked(), "/wrappers");
        let before: Vec<String> = s
            .current_mapping()
            .unwrap()
            .real_to_scrambled
            .values()
            .cloned()
            .collect();
        let new_epoch = s.rotate().unwrap();
        assert_eq!(new_epoch, 1);
        assert_eq!(s.epoch(), Some(1));
        let after: Vec<String> = s
            .current_mapping()
            .unwrap()
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
        assert_eq!(s.current_mapping().unwrap().epoch, 0);
        s.rotate().unwrap();
        assert_eq!(s.current_mapping().unwrap().epoch, 1);
        s.rotate().unwrap();
        assert_eq!(s.current_mapping().unwrap().epoch, 2);
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

    /// Replace the [`DaemonState`] with a fresh Locked state whose
    /// config's `skip_materialization = true`, so unit tests can
    /// exercise unlock without touching the host filesystem.
    /// Returns a brand-new state because we cannot mutate the
    /// private `config` field directly from outside `super`.
    fn with_skip_materialization(s: &mut DaemonState) -> DaemonState {
        let tools = s.config.tracked_tools.clone();
        let mat = s.config.materialization.clone();
        DaemonState::new_locked_skip_for_tests(s.config.wordlist, tools, mat)
            .unwrap()
    }

    // ----- private test-only constructor surfaced via super::DaemonState -----

    impl DaemonState {
        fn new_locked_skip_for_tests(
            wordlist: &'static Wordlist,
            tracked_tools: Vec<TrackedTool>,
            materialization: MaterializationConfig,
        ) -> Result<Self> {
            let config = build_config(
                wordlist,
                tracked_tools,
                materialization,
                true,
            )?;
            Ok(Self {
                config,
                secret_state: SecretState::Locked,
                permutation_cache: PermutationCache::with_default_capacity(),
            })
        }
    }

    // ----- on-disk materialization (Unlocked path) -----

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
            journal_path: None,
        }
    }

    #[test]
    fn new_unlocked_materialises_real_and_honey_wrappers_on_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = tracked_in(tmp.path(), &["curl", "ssh"]);
        let cfg = cfg_in_tmp(tmp.path());
        let s = DaemonState::new_unlocked(
            fixed_secret(),
            Wordlist::english_baseline(),
            tools,
            cfg.clone(),
        )
        .unwrap();
        let mapping = s.current_mapping().unwrap();
        for scrambled in mapping.real_to_scrambled.values() {
            assert!(
                cfg.wrapper_dir.join(scrambled).exists(),
                "missing real wrapper {scrambled}",
            );
        }
        for honey in &mapping.honey_names {
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
        let mut s = DaemonState::new_unlocked(
            fixed_secret(),
            Wordlist::english_baseline(),
            tools,
            cfg.clone(),
        )
        .unwrap();
        let prev_real: Vec<String> = s
            .current_mapping()
            .unwrap()
            .real_to_scrambled
            .values()
            .cloned()
            .collect();
        let prev_honey: Vec<String> =
            s.current_mapping().unwrap().honey_names.clone();

        s.rotate().unwrap();

        let stale_body =
            std::fs::read_to_string(cfg.stale_list_path.as_ref().unwrap()).unwrap();
        for name in prev_real.iter().chain(prev_honey.iter()) {
            assert!(
                stale_body.contains(&format!("{name}\n")),
                "stale list missing {name}",
            );
        }
        for scrambled in s.current_mapping().unwrap().real_to_scrambled.values() {
            assert!(
                cfg.wrapper_dir.join(scrambled).exists(),
                "missing new-epoch real wrapper {scrambled}",
            );
        }
    }

    #[test]
    fn new_unlocked_genesis_stale_list_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = tracked_in(tmp.path(), &["curl"]);
        let cfg = cfg_in_tmp(tmp.path());
        DaemonState::new_unlocked(
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

    // ----- whitespace_compounds (preprocessor-bridge) -----

    #[test]
    fn whitespace_compounds_returns_five_distinct_lowercase_strings() {
        let s = build_state(tracked(), "/wrappers");
        let (epoch, compounds) = s.whitespace_compounds().unwrap();
        assert_eq!(epoch, 0);
        // Five compounds, all non-empty, all ASCII lowercase.
        for c in &compounds {
            assert!(!c.is_empty(), "compound is empty");
            assert!(
                c.bytes().all(|b| b.is_ascii_lowercase()),
                "compound contains non-lowercase byte: {c:?}",
            );
        }
        // Pairwise distinct.
        let mut sorted: Vec<&str> = compounds.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        let len = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), len, "compounds must be pairwise distinct");
    }

    #[test]
    fn whitespace_compounds_locked_returns_vault_error() {
        let s = build_locked(tracked(), "/wrappers");
        match s.whitespace_compounds() {
            Err(Error::Vault(m)) => assert!(m.contains("locked"), "{m}"),
            Err(other) => panic!("expected Error::Vault, got {other:?}"),
            Ok(_) => panic!("locked state must refuse whitespace-compounds"),
        }
    }

    #[test]
    fn whitespace_compounds_after_unlock_returns_compounds_for_epoch_zero() {
        let mut s = build_locked(tracked(), "/wrappers");
        let mut s = with_skip_materialization(&mut s);
        s.unlock(fixed_secret()).unwrap();
        let (epoch, compounds) = s.whitespace_compounds().unwrap();
        assert_eq!(epoch, 0);
        assert_eq!(compounds.len(), 5);
    }

    #[test]
    fn whitespace_compounds_change_across_rotation() {
        let mut s = build_state(tracked(), "/wrappers");
        let (e0, c0) = s.whitespace_compounds().unwrap();
        assert_eq!(e0, 0);
        s.rotate().unwrap();
        let (e1, c1) = s.whitespace_compounds().unwrap();
        assert_eq!(e1, 1);
        // Every compound moves across rotation.
        for (i, (a, b)) in c0.iter().zip(c1.iter()).enumerate() {
            assert_ne!(a, b, "compound at slot {i} did not move across rotation");
        }
    }

    #[test]
    fn whitespace_compounds_are_deterministic_for_same_secret_and_epoch() {
        let a = build_state(tracked(), "/wrappers");
        let b = build_state(tracked(), "/wrappers");
        let (_, ca) = a.whitespace_compounds().unwrap();
        let (_, cb) = b.whitespace_compounds().unwrap();
        assert_eq!(ca, cb);
    }

    #[test]
    fn whitespace_compounds_round_trip_through_preprocessor() {
        // End-to-end seam test: take the daemon's compounds, feed
        // them into the preprocessor's from_compounds, and assert
        // the resulting wordlist's match_prefix recognises each
        // compound at its slot.  This is what the CLI does on the
        // wire side.
        use babbleon_preprocessor_v2::tokens::WhitespaceKind;
        use babbleon_preprocessor_v2::WhitespaceWordlist;
        let s = build_state(tracked(), "/wrappers");
        let (epoch, compounds) = s.whitespace_compounds().unwrap();
        let reconstructed =
            WhitespaceWordlist::from_compounds(epoch, compounds.clone())
                .unwrap();
        for kind in WhitespaceKind::ALL {
            assert_eq!(
                reconstructed.compound_for(kind),
                compounds[kind.slot()].as_str(),
            );
            let with_trailer = format!("{}xyz", compounds[kind.slot()]);
            let (matched, len) =
                reconstructed.match_prefix(&with_trailer).unwrap();
            assert_eq!(matched, kind);
            assert_eq!(len, compounds[kind.slot()].len());
        }
    }

    // ----- token_mapping (dynamic identifier scramble) -----

    #[test]
    fn token_mapping_returns_aliases_for_each_token() {
        use babbleon_daemon_protocol_v2::ALIAS_COUNT_WIRE;
        let s = build_state(tracked(), "/wrappers");
        let tokens =
            vec!["def".to_string(), "foo".to_string(), "return".to_string()];
        let (epoch, aliases) = s.token_mapping(
            &tokens,
            babbleon_daemon_protocol_v2::LEGACY_FORMAT_VERSION_WIRE,
        )
        .unwrap();
        assert_eq!(epoch, 0);
        assert_eq!(aliases.len(), tokens.len());
        for token_aliases in &aliases {
            assert_eq!(token_aliases.len(), ALIAS_COUNT_WIRE);
            for c in token_aliases {
                assert!(!c.is_empty(), "alias compound is empty");
                assert!(
                    c.bytes().all(|b| b.is_ascii_lowercase()),
                    "alias compound has non-lowercase byte: {c:?}",
                );
            }
        }
        // All compounds across all tokens and all aliases must be distinct.
        let mut all: Vec<&str> = aliases
            .iter()
            .flat_map(|v| v.iter().map(String::as_str))
            .collect();
        all.sort_unstable();
        let len = all.len();
        all.dedup();
        assert_eq!(all.len(), len, "compounds must be globally distinct");
    }

    #[test]
    fn token_mapping_locked_returns_vault_error() {
        let s = build_locked(tracked(), "/wrappers");
        match s.token_mapping(
            &["x".to_string()],
            babbleon_daemon_protocol_v2::LEGACY_FORMAT_VERSION_WIRE,
        ) {
            Err(Error::Vault(m)) => assert!(m.contains("locked"), "{m}"),
            Err(other) => panic!("expected Error::Vault, got {other:?}"),
            Ok(_) => panic!("locked state must refuse token_mapping"),
        }
    }

    #[test]
    fn token_mapping_changes_across_rotation() {
        use babbleon_daemon_protocol_v2::ALIAS_COUNT_WIRE;
        let mut s = build_state(tracked(), "/wrappers");
        let tokens = vec!["alpha".to_string(), "beta".to_string()];
        let (e0, a0) = s.token_mapping(
            &tokens,
            babbleon_daemon_protocol_v2::LEGACY_FORMAT_VERSION_WIRE,
        )
        .unwrap();
        assert_eq!(e0, 0);
        s.rotate().unwrap();
        let (e1, a1) = s.token_mapping(
            &tokens,
            babbleon_daemon_protocol_v2::LEGACY_FORMAT_VERSION_WIRE,
        )
        .unwrap();
        assert_eq!(e1, 1);
        // After rotation, at least one alias changes (almost certainly all).
        let changed = a0.iter().zip(a1.iter()).any(|(v0, v1)| v0 != v1);
        assert!(changed, "all aliases unchanged after rotation");
        let _ = ALIAS_COUNT_WIRE;
    }

    #[test]
    fn token_mapping_is_deterministic_for_same_secret_and_epoch() {
        let a = build_state(tracked(), "/wrappers");
        let b = build_state(tracked(), "/wrappers");
        let tokens = vec!["x".to_string(), "y".to_string()];
        let (_, aliases_a) = a
            .token_mapping(
                &tokens,
                babbleon_daemon_protocol_v2::LEGACY_FORMAT_VERSION_WIRE,
            )
            .unwrap();
        let (_, aliases_b) = b
            .token_mapping(
                &tokens,
                babbleon_daemon_protocol_v2::LEGACY_FORMAT_VERSION_WIRE,
            )
            .unwrap();
        assert_eq!(aliases_a, aliases_b);
    }

    #[test]
    fn token_mapping_round_trips_through_identifier_mapping() {
        use babbleon_preprocessor_v2::identifier_scrambler::IdentifierMapping;
        let s = build_state(tracked(), "/wrappers");
        let tokens =
            vec!["def".to_string(), "foo".to_string(), "return".to_string()];
        let (epoch, aliases) = s.token_mapping(
            &tokens,
            babbleon_daemon_protocol_v2::LEGACY_FORMAT_VERSION_WIRE,
        )
        .unwrap();
        let mapping =
            IdentifierMapping::from_tokens_and_aliases(tokens.clone(), epoch, aliases)
                .expect("daemon-derived aliases must satisfy from_tokens_and_aliases");
        // Every token can be scrambled and unscrambled back.
        for (i, tok) in tokens.iter().enumerate() {
            let compound = mapping.scramble(tok, i).expect("scramble must succeed");
            let recovered =
                mapping.unscramble(compound).expect("unscramble must succeed");
            assert_eq!(recovered, tok.as_str());
        }
    }

    #[test]
    fn token_mapping_repeats_warm_the_permutation_cache() {
        // Property: the daemon's `permutation_cache` field is
        // exercised by `token_mapping`.  After the first call the
        // cache holds ALIAS_COUNT_WIRE * 2 entries (identifier +
        // honey per virtual epoch); a second call at the same
        // host-epoch hits without growing the cache.
        use babbleon_daemon_protocol_v2::ALIAS_COUNT_WIRE;
        let s = build_state(tracked(), "/wrappers");
        assert!(s.permutation_cache.is_empty());
        let tokens = vec!["alpha".to_string(), "beta".to_string()];
        let (_, first) = s.token_mapping(
            &tokens,
            babbleon_daemon_protocol_v2::LEGACY_FORMAT_VERSION_WIRE,
        )
        .unwrap();
        // ALIAS_COUNT_WIRE distinct virtual epochs * (identifier + honey).
        assert_eq!(s.permutation_cache.len(), ALIAS_COUNT_WIRE * 2);

        let (_, second) = s.token_mapping(
            &tokens,
            babbleon_daemon_protocol_v2::LEGACY_FORMAT_VERSION_WIRE,
        )
        .unwrap();
        // Repeat call: cache stays the same size; outputs identical.
        assert_eq!(s.permutation_cache.len(), ALIAS_COUNT_WIRE * 2);
        assert_eq!(first, second);
    }

    #[test]
    fn token_mapping_at_variable_format_returns_per_epoch_alias_count() {
        // For format_version >= ALIAS_COUNT_VARIABLE_FROM_VERSION_WIRE
        // the daemon's response width follows
        // `alias_count_for_epoch(format_version, epoch)`.  The legacy
        // path is exercised by the `token_mapping_returns_aliases_for_each_token`
        // test above.
        use babbleon_daemon_protocol_v2::ALIAS_COUNT_VARIABLE_FROM_VERSION_WIRE;
        use babbleon_preprocessor_v2::alias_count_for_epoch;
        let s = build_state(tracked(), "/wrappers");
        let tokens = vec!["q".to_string(), "r".to_string()];
        let (epoch, aliases) = s
            .token_mapping(&tokens, ALIAS_COUNT_VARIABLE_FROM_VERSION_WIRE)
            .unwrap();
        let expected =
            alias_count_for_epoch(ALIAS_COUNT_VARIABLE_FROM_VERSION_WIRE, epoch);
        assert_eq!(aliases.len(), tokens.len());
        for row in &aliases {
            assert_eq!(
                row.len(),
                expected,
                "variable-mode alias row width must match alias_count_for_epoch",
            );
        }
    }

    #[test]
    fn token_mapping_variable_mode_globally_distinct_compounds() {
        // Even when the alias count varies, every compound across every
        // (token, alias_idx) pair must be globally distinct — otherwise
        // the unscrambler's reverse-map build would collide.
        use babbleon_daemon_protocol_v2::ALIAS_COUNT_VARIABLE_FROM_VERSION_WIRE;
        let s = build_state(tracked(), "/wrappers");
        let tokens =
            vec!["uno".to_string(), "dos".to_string(), "tres".to_string()];
        let (_, aliases) = s
            .token_mapping(&tokens, ALIAS_COUNT_VARIABLE_FROM_VERSION_WIRE)
            .unwrap();
        let mut all: Vec<&str> = aliases
            .iter()
            .flat_map(|v| v.iter().map(String::as_str))
            .collect();
        all.sort_unstable();
        let len = all.len();
        all.dedup();
        assert_eq!(
            all.len(),
            len,
            "variable-mode compounds must be globally distinct",
        );
    }

    #[test]
    fn token_mapping_legacy_and_variable_use_independent_virtual_epochs() {
        // The two regimes use different strides
        // (`ALIAS_COUNT_WIRE` vs `MAX_ALIAS_COUNT_WIRE`) so at any
        // host-epoch >= 1 they land on different virtual_epoch IDs and
        // therefore different compounds.  At host_epoch == 0 both
        // strides yield virtual_epoch == 0, so the property only holds
        // for the second (and later) compound positions.  Rotate the
        // daemon to host_epoch = 1 before comparing.
        use babbleon_daemon_protocol_v2::{
            ALIAS_COUNT_VARIABLE_FROM_VERSION_WIRE, LEGACY_FORMAT_VERSION_WIRE,
        };
        let mut s = build_state(tracked(), "/wrappers");
        s.rotate().unwrap();
        let tokens = vec!["zeta".to_string()];
        let (_, legacy) = s
            .token_mapping(&tokens, LEGACY_FORMAT_VERSION_WIRE)
            .unwrap();
        let (_, variable) = s
            .token_mapping(&tokens, ALIAS_COUNT_VARIABLE_FROM_VERSION_WIRE)
            .unwrap();
        // host_epoch=1: legacy first virtual_epoch = 3; variable first
        // virtual_epoch = 5.  Distinct → distinct compounds.
        assert_ne!(
            legacy[0][0], variable[0][0],
            "regimes must use independent virtual-epoch IDs at host_epoch>=1",
        );
    }

    #[test]
    fn token_mapping_legacy_and_variable_share_genesis_first_alias() {
        // Documents the genesis-epoch boundary:  the legacy and
        // variable regimes BOTH derive virtual_epoch == 0 for the
        // first alias at host_epoch == 0.  This is a documented,
        // accepted cache-key collision — the compound is identical
        // and the cache hit is correct.  Not a defect; making this
        // explicit so a future cache rework does not silently break
        // the property.
        use babbleon_daemon_protocol_v2::{
            ALIAS_COUNT_VARIABLE_FROM_VERSION_WIRE, LEGACY_FORMAT_VERSION_WIRE,
        };
        let s = build_state(tracked(), "/wrappers");
        let tokens = vec!["genesis".to_string()];
        let (_, legacy) = s
            .token_mapping(&tokens, LEGACY_FORMAT_VERSION_WIRE)
            .unwrap();
        let (_, variable) = s
            .token_mapping(&tokens, ALIAS_COUNT_VARIABLE_FROM_VERSION_WIRE)
            .unwrap();
        assert_eq!(
            legacy[0][0], variable[0][0],
            "host_epoch=0 first alias coincides under both regimes",
        );
    }

    #[test]

    #[test]
    fn token_mapping_after_rotation_keeps_results_correct() {
        // Property: rotation changes the host-epoch and therefore
        // the virtual epochs used by `token_mapping`.  The cache
        // happily co-exists with old + new entries (LRU eviction
        // under the DEFAULT_CAPACITY limit), and every call still
        // returns the correct fresh mapping (no stale-data
        // bleed-through).
        use babbleon_preprocessor_v2::identifier_scrambler::IdentifierMapping;
        let mut s = build_state(tracked(), "/wrappers");
        let tokens = vec!["gamma".to_string()];

        let (_, a0) = s.token_mapping(
            &tokens,
            babbleon_daemon_protocol_v2::LEGACY_FORMAT_VERSION_WIRE,
        )
        .unwrap();
        s.rotate().unwrap();
        let (e1, a1) = s.token_mapping(
            &tokens,
            babbleon_daemon_protocol_v2::LEGACY_FORMAT_VERSION_WIRE,
        )
        .unwrap();
        s.rotate().unwrap();
        let (e2, a2) = s.token_mapping(
            &tokens,
            babbleon_daemon_protocol_v2::LEGACY_FORMAT_VERSION_WIRE,
        )
        .unwrap();

        assert_ne!(a0, a1, "rotation must change the alias set");
        assert_ne!(a1, a2, "rotation must change the alias set");

        // Cached-mapping outputs are still recoverable round-trip.
        let m1 =
            IdentifierMapping::from_tokens_and_aliases(tokens.clone(), e1, a1)
                .unwrap();
        let m2 =
            IdentifierMapping::from_tokens_and_aliases(tokens.clone(), e2, a2)
                .unwrap();
        let c1 = m1.scramble("gamma", 0).unwrap();
        assert_eq!(m1.unscramble(c1).unwrap(), "gamma");
        let c2 = m2.scramble("gamma", 0).unwrap();
        assert_eq!(m2.unscramble(c2).unwrap(), "gamma");
    }

    // -----------------------------------------------------------
    // Epoch-journal end-to-end behaviour
    // -----------------------------------------------------------

    fn cfg_with_journal(dir: &Path) -> MaterializationConfig {
        let mut cfg = cfg_in_tmp(dir);
        cfg.journal_path = Some(dir.join("epoch.bin"));
        cfg
    }

    #[test]
    fn unlock_then_rotate_then_restart_resumes_at_rotated_epoch() {
        // Lifecycle: unlock at 0 → rotate (→1) → rotate (→2) →
        // simulate restart (new DaemonState with same journal path)
        // → unlock → epoch must be 2.
        let tmp = tempfile::tempdir().unwrap();
        let tools = tracked_in(tmp.path(), &["curl"]);
        let cfg = cfg_with_journal(tmp.path());

        let mut state_1 = DaemonState::new_locked(
            Wordlist::english_baseline(),
            tools.clone(),
            cfg.clone(),
        )
        .unwrap();
        state_1.unlock(fixed_secret()).unwrap();
        state_1.rotate().unwrap();
        state_1.rotate().unwrap();
        assert_eq!(state_1.epoch(), Some(2));
        drop(state_1);

        // "Restart" — fresh DaemonState backed by the same journal.
        let mut state_2 = DaemonState::new_locked(
            Wordlist::english_baseline(),
            tools,
            cfg,
        )
        .unwrap();
        state_2.unlock(fixed_secret()).unwrap();
        assert_eq!(state_2.epoch(), Some(2), "journal must restore epoch");
    }

    #[test]
    fn restart_with_no_journal_starts_at_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = tracked_in(tmp.path(), &["curl"]);
        let cfg = cfg_in_tmp(tmp.path()); // no journal_path
        let mut state = DaemonState::new_locked(
            Wordlist::english_baseline(),
            tools,
            cfg,
        )
        .unwrap();
        state.unlock(fixed_secret()).unwrap();
        assert_eq!(state.epoch(), Some(0));
    }

    #[test]
    fn restart_with_tampered_journal_resumes_at_zero_and_does_not_crash() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = tracked_in(tmp.path(), &["curl"]);
        let cfg = cfg_with_journal(tmp.path());
        let journal_path = cfg.journal_path.clone().unwrap();

        let mut state = DaemonState::new_locked(
            Wordlist::english_baseline(),
            tools.clone(),
            cfg.clone(),
        )
        .unwrap();
        state.unlock(fixed_secret()).unwrap();
        state.rotate().unwrap();
        state.rotate().unwrap();
        state.rotate().unwrap();
        assert_eq!(state.epoch(), Some(3));
        drop(state);

        // Tamper.
        let mut bytes = std::fs::read(&journal_path).unwrap();
        bytes[0] ^= 1;
        std::fs::write(&journal_path, &bytes).unwrap();

        // Restart should not crash and should resume at 0.
        let mut state_2 = DaemonState::new_locked(
            Wordlist::english_baseline(),
            tools,
            cfg,
        )
        .unwrap();
        state_2.unlock(fixed_secret()).unwrap();
        assert_eq!(
            state_2.epoch(),
            Some(0),
            "tampered journal must safe-fail to epoch 0",
        );
    }

    #[test]
    fn restart_with_journal_from_different_secret_resumes_at_zero() {
        // A journal sealed under secret_a must NOT be honoured when
        // the daemon unlocks under secret_b.  HMAC verification
        // rejects; daemon resumes at 0.  This is the cross-host
        // safety net.
        let tmp = tempfile::tempdir().unwrap();
        let tools = tracked_in(tmp.path(), &["curl"]);
        let cfg = cfg_with_journal(tmp.path());

        let other_secret = PerHostSecret::from_bytes(&[123u8; 32]).unwrap();

        let mut state = DaemonState::new_locked(
            Wordlist::english_baseline(),
            tools.clone(),
            cfg.clone(),
        )
        .unwrap();
        state.unlock(fixed_secret()).unwrap();
        state.rotate().unwrap();
        assert_eq!(state.epoch(), Some(1));
        drop(state);

        let mut state_2 = DaemonState::new_locked(
            Wordlist::english_baseline(),
            tools,
            cfg,
        )
        .unwrap();
        state_2.unlock(other_secret).unwrap();
        assert_eq!(state_2.epoch(), Some(0));
    }
}

