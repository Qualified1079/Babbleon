//! Unified wrapper template generator.
//!
//! # What this defeats
//!
//! Every scrambled name on disk is a shell script wrapper (later: a stripped
//! static binary).  The unified template serves three purposes:
//!
//! 1. **Tier dispatch** — in the trusted mount namespace the wrapper `exec`s
//!    the real binary; in the untrusted namespace it exits 127 with no output.
//!    Silence (not fake help text) is the untrusted response — see
//!    `docs/v2/gui-design.md` for the rationale.
//!
//! 2. **Tripwire detection** — if the wrapper's own name appears in the
//!    honey list or the stale-mapping list it emits a JSON event to the
//!    tripwire FIFO and exits 127 unconditionally, regardless of tier.
//!
//! 3. **Fingerprint resistance** — every wrapper carries per-host,
//!    per-name HKDF-derived padding (16 bytes, hex-encoded) so no two
//!    wrappers on any two hosts hash to the same value.  Honey and
//!    real-tool wrappers use the SAME template so `ls -la` cannot
//!    distinguish them by size.
//!
//! # PPID PID-reuse guard
//!
//! The wrapper reads `/proc/$$/stat` (its own PID) to find PPID, then reads
//! `/proc/<ppid>/stat` to capture PPID's start-time (field 22, clock ticks
//! since boot).  Both values are written into the FIFO JSON.  The daemon-side
//! responder MUST re-read the start-time before acting on the PPID; if the
//! recorded value differs, the process has been recycled and the action MUST
//! be suppressed.
//!
//! # v2 changes vs v1
//!
//! - Padding derived from HKDF-SHA-256 (`v2-wrapper-pad`, per `key_derivation`)
//!   instead of raw SHA-256(secret||name).
//! - `decoy_banner` / fake help text dropped entirely: untrusted tier exits 127
//!   with no output.
//! - Runtime paths renamed: `tripwire-honey.list`, `tripwire-stale.list`,
//!   `tripwire-events.fifo` (per `docs/v2/naming-conventions.md`).
//! - FIFO JSON uses `"source":"honey"` / `"source":"stale"` (matches
//!   `TripwireSource` serde form).

use std::path::{Path, PathBuf};

use crate::errors::{Error, Result};
use crate::key_derivation::derive_subkey;
use crate::per_host_secret::PerHostSecret;

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

/// Validate that a wrapper name is safe to embed in the shell template.
///
/// Allows `[a-z0-9-]` only; rejects anything that could break shell
/// variable assignment, `grep -xF` comparison, or filename semantics.
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Internal(
            "wrapper name must not be empty".into(),
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(Error::Internal(format!(
            "wrapper name {name:?} contains characters outside [a-z0-9-]"
        )));
    }
    Ok(())
}

/// Validate that a filesystem path is safe to embed in the shell template.
///
/// Rejects bytes that would break the surrounding double-quoted shell
/// assignment: `"`, `$`, backtick, `\`, and newline / NUL.
fn validate_path(path: &str) -> Result<()> {
    const UNSAFE: &[u8] = b"\"$`\\\n\r\0";
    if path
        .bytes()
        .any(|b| UNSAFE.contains(&b))
    {
        return Err(Error::Internal(format!(
            "path contains character(s) unsafe for shell embedding: {path:?}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Runtime paths
// ---------------------------------------------------------------------------

/// FIFO where wrappers report tripwire events.  Renamed from v1's
/// `honey.fifo` to make the stale-vs-honey duality visible in the path.
pub const TRIPWIRE_EVENTS_FIFO: &str = "/run/babbleon/tripwire-events.fifo";

/// Honey-name list (one name per line).  Wrapper checks this at exec time.
pub const TRIPWIRE_HONEY_LIST: &str = "/run/babbleon/tripwire-honey.list";

/// Stale-mapping list (one name per line).  Names that were real-tool
/// scrambled names in a previous epoch.
pub const TRIPWIRE_STALE_LIST: &str = "/run/babbleon/tripwire-stale.list";

// ---------------------------------------------------------------------------
// HKDF info label
// ---------------------------------------------------------------------------

/// Domain label for per-wrapper HKDF padding.
///
/// Produces 16 distinct bytes per (`host_secret`, epoch, name) triple.
const HKDF_PURPOSE_WRAPPER_PAD: &[u8] = b"v2-wrapper-pad";

// ---------------------------------------------------------------------------
// Shell template
// ---------------------------------------------------------------------------

/// Unified shell wrapper.  Honey wrappers and real-tool wrappers share this
/// identical template — the runtime branch on the honey/stale lists is what
/// distinguishes them, not the file size or structure.
///
/// Substitution fields (must all be replaced before writing to disk):
/// - `{padding}`        16-byte HKDF-derived hex; unique per host × epoch × name.
/// - `{self_name}`      The scrambled (or honey) name of this wrapper.
/// - `{real_path}`      Absolute path to the real binary (/dev/null for honey).
/// - `{ns_inode}`       Trusted mount-NS inode as decimal string; 0 disables tier check.
/// - `{honey_list}`     Path to tripwire-honey.list.
/// - `{stale_list}`     Path to tripwire-stale.list.
/// - `{events_fifo}`    Path to tripwire-events.fifo.
const TEMPLATE: &str = r#"#!/bin/sh
# babbleon-v2 wrapper pad:{padding}
_BL_NAME="{self_name}"
_BL_REAL="{real_path}"
_BL_NS_INODE="{ns_inode}"
_BL_HONEY_LIST="{honey_list}"
_BL_STALE_LIST="{stale_list}"
_BL_FIFO="{events_fifo}"
_bl_in_trusted_ns() {
    _cur=$(stat -Lc '%i' /proc/self/ns/mnt 2>/dev/null) || return 1
    [ "$_cur" = "$_BL_NS_INODE" ]
}
_bl_is_honey() {
    grep -qxF "$_BL_NAME" "$_BL_HONEY_LIST" 2>/dev/null
}
_bl_is_stale() {
    grep -qxF "$_BL_NAME" "$_BL_STALE_LIST" 2>/dev/null
}
_bl_fire_tripwire() {
    # $1 = "honey" or "stale" (matches TripwireSource serde form).
    _ts=$(date -u +%s 2>/dev/null || echo 0)
    # PPID identity — what the responder may act on.  Capture start-time
    # so the responder can guard against PID reuse before signalling.
    _ppid=$(awk '{print $4}' /proc/$$/stat 2>/dev/null || echo 0)
    _ppid_start=$(awk '{print $22}' "/proc/$_ppid/stat" 2>/dev/null || echo 0)
    printf '{"ts":%s,"wrapper_pid":%s,"triggering_pid":%s,"triggering_pid_start":%s,"source":"%s","name":"%s"}\n' \
        "$_ts" "$$" "$_ppid" "$_ppid_start" "$1" "$_BL_NAME" \
        >> "$_BL_FIFO" 2>/dev/null || true
}
if _bl_is_honey; then
    _bl_fire_tripwire honey
    exit 127
fi
if _bl_is_stale; then
    _bl_fire_tripwire stale
    exit 127
fi
# Untrusted tier: exit silently.  No fake help text, no banner spoofing.
# See docs/v2/gui-design.md — legitimate tools get a trust grant, not a
# deception wrapper.
if [ "$_BL_NS_INODE" != "0" ] && ! _bl_in_trusted_ns; then
    exit 127
fi
exec "$_BL_REAL" "$@"
"#;

// ---------------------------------------------------------------------------
// Padding derivation
// ---------------------------------------------------------------------------

/// Derive 16 bytes of per-wrapper HKDF padding and return as a hex string.
///
/// Info = `HKDF_PURPOSE_WRAPPER_PAD || name_bytes`.  This binds the padding
/// to the wrapper name so two wrappers on the same host at the same epoch
/// still differ — foiling content-hash fingerprinting even when `ls -la`
/// sizes match.
fn wrapper_padding_hex(
    secret: &PerHostSecret,
    epoch: u64,
    name: &str,
) -> Result<String> {
    // Append the wrapper name to the purpose label to produce a
    // name-scoped info value within the same HKDF invocation.
    let mut info = HKDF_PURPOSE_WRAPPER_PAD.to_vec();
    info.extend_from_slice(name.as_bytes());
    let key = derive_subkey(secret, epoch, &info, 32)?;
    // Only first 16 bytes for the comment; output is non-secret (in the
    // wrapper script body), so taking a prefix is safe.
    Ok(hex::encode(&key[..16]))
}

// ---------------------------------------------------------------------------
// Template rendering
// ---------------------------------------------------------------------------

fn render(
    name: &str,
    real_path: &str,
    ns_inode: &str,
    honey_list: &str,
    stale_list: &str,
    events_fifo: &str,
    padding_hex: &str,
) -> String {
    TEMPLATE
        .replace("{padding}", padding_hex)
        .replace("{self_name}", name)
        .replace("{real_path}", real_path)
        .replace("{ns_inode}", ns_inode)
        .replace("{honey_list}", honey_list)
        .replace("{stale_list}", stale_list)
        .replace("{events_fifo}", events_fifo)
}

// ---------------------------------------------------------------------------
// File I/O helpers
// ---------------------------------------------------------------------------

fn write_executable(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents)
        .map_err(|e| crate::errors::Error::Internal(format!("I/O failed: {}", e.kind())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(0o755),
        )
        .map_err(|e| crate::errors::Error::Internal(format!("I/O failed: {}", e.kind())))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Write a real-tool wrapper for `scrambled_name` that execs `real_path`
/// in the trusted tier and exits 127 silently in the untrusted tier.
///
/// # Errors
///
/// - `Error::Internal` if `scrambled_name` contains characters outside
///   `[a-z0-9-]`, or if `real_path` contains characters unsafe for
///   shell embedding (`"`, `$`, backtick, `\`, newline, NUL).
/// - `Error::Internal` if the output directory cannot be created or the
///   wrapper file cannot be written.
/// - `Error::Crypto` if HKDF subkey derivation fails (not reachable
///   in practice for our 32-byte keys).
pub fn write_wrapper(
    scrambled_name: &str,
    real_path: &Path,
    output_dir: &Path,
    secret: &PerHostSecret,
    epoch: u64,
    trusted_ns_inode: Option<u64>,
) -> Result<PathBuf> {
    validate_name(scrambled_name)?;
    let real_path_str = real_path.to_string_lossy();
    validate_path(&real_path_str)?;
    std::fs::create_dir_all(output_dir)
        .map_err(|e| crate::errors::Error::Internal(format!("I/O failed: {}", e.kind())))?;
    let padding = wrapper_padding_hex(secret, epoch, scrambled_name)?;
    let inode = trusted_ns_inode.map_or_else(|| "0".into(), |i| i.to_string());
    let contents = render(
        scrambled_name,
        &real_path.display().to_string(),
        &inode,
        TRIPWIRE_HONEY_LIST,
        TRIPWIRE_STALE_LIST,
        TRIPWIRE_EVENTS_FIFO,
        &padding,
    );
    let dest = output_dir.join(scrambled_name);
    write_executable(&dest, &contents)?;
    Ok(dest)
}

/// Write a honey / stale-mapping tripwire wrapper.  Shares the identical
/// template as a real-tool wrapper; the runtime dispatches on the list files.
///
/// `events_fifo` overrides the default FIFO path (useful in tests).
///
/// # Errors
///
/// - `Error::Internal` if `honey_name` contains characters outside
///   `[a-z0-9-]`, or if `events_fifo` contains shell-unsafe characters.
/// - `Error::Internal` if the output directory cannot be created or the
///   wrapper file cannot be written.
/// - `Error::Crypto` if HKDF subkey derivation fails.
pub fn write_tripwire_wrapper(
    honey_name: &str,
    output_dir: &Path,
    secret: &PerHostSecret,
    epoch: u64,
    events_fifo: Option<&str>,
) -> Result<PathBuf> {
    validate_name(honey_name)?;
    if let Some(fifo) = events_fifo {
        validate_path(fifo)?;
    }
    std::fs::create_dir_all(output_dir)
        .map_err(|e| crate::errors::Error::Internal(format!("I/O failed: {}", e.kind())))?;
    let padding = wrapper_padding_hex(secret, epoch, honey_name)?;
    let fifo = events_fifo.unwrap_or(TRIPWIRE_EVENTS_FIFO);
    let contents = render(
        honey_name,
        "/dev/null",
        "0",
        TRIPWIRE_HONEY_LIST,
        TRIPWIRE_STALE_LIST,
        fifo,
        &padding,
    );
    let dest = output_dir.join(honey_name);
    write_executable(&dest, &contents)?;
    Ok(dest)
}

/// Write tripwire wrappers for all names in `honey_names`.
///
/// # Errors
///
/// Propagates errors from [`write_tripwire_wrapper`]; the first failure
/// stops iteration and returns the error.
pub fn write_all_tripwire_wrappers<'a>(
    honey_names: impl IntoIterator<Item = &'a str>,
    output_dir: &Path,
    secret: &PerHostSecret,
    epoch: u64,
) -> Result<Vec<PathBuf>> {
    honey_names
        .into_iter()
        .map(|n| write_tripwire_wrapper(n, output_dir, secret, epoch, None))
        .collect()
}

/// Write real-tool wrappers for every `(scrambled, real_path)` pair.
///
/// Entries where `real_path` does not exist on disk are silently skipped
/// so the caller can pass the full mapping without pre-filtering.
///
/// # Errors
///
/// Propagates errors from [`write_wrapper`]; the first failure stops
/// iteration and returns the error.
pub fn write_all_wrappers<'a, 'b>(
    mapping: impl IntoIterator<Item = (&'a str, &'b Path)>,
    output_dir: &Path,
    secret: &PerHostSecret,
    epoch: u64,
    trusted_ns_inode: Option<u64>,
) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for (scrambled, real_path) in mapping {
        if !real_path.exists() {
            tracing::debug!(
                scrambled,
                real_path = %real_path.display(),
                "real path missing; skipping wrapper",
            );
            continue;
        }
        out.push(write_wrapper(
            scrambled,
            real_path,
            output_dir,
            secret,
            epoch,
            trusted_ns_inode,
        )?);
    }
    Ok(out)
}

/// Write the honey-name list to `path` (or default FIFO path).
///
/// # Errors
///
/// - `Error::Internal` if the parent directory cannot be created or the
///   file cannot be written.
pub fn write_honey_list<'a>(
    names: impl IntoIterator<Item = &'a str>,
    path: Option<&Path>,
) -> Result<()> {
    write_name_list(
        names,
        path.unwrap_or_else(|| Path::new(TRIPWIRE_HONEY_LIST)),
    )
}

/// Write the stale-mapping list to `path`.
///
/// # Errors
///
/// - `Error::Internal` if the parent directory cannot be created or the
///   file cannot be written.
pub fn write_stale_list<'a>(
    names: impl IntoIterator<Item = &'a str>,
    path: Option<&Path>,
) -> Result<()> {
    write_name_list(
        names,
        path.unwrap_or_else(|| Path::new(TRIPWIRE_STALE_LIST)),
    )
}

fn write_name_list<'a>(
    names: impl IntoIterator<Item = &'a str>,
    dest: &Path,
) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| crate::errors::Error::Internal(format!("I/O failed: {}", e.kind())))?;
    }
    let content: String = names.into_iter().flat_map(|n| [n, "\n"]).collect();
    std::fs::write(dest, content)
        .map_err(|e| crate::errors::Error::Internal(format!("I/O failed: {}", e.kind())))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::per_host_secret::PerHostSecret;

    fn secret(byte: u8) -> PerHostSecret {
        PerHostSecret::from_bytes(&[byte; 32]).unwrap()
    }

    /// Execute a script under `/bin/sh`; return exit code.
    fn sh(path: &Path) -> i32 {
        std::process::Command::new("sh")
            .arg(path)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/local/bin")
            .status()
            .unwrap()
            .code()
            .unwrap_or(-1)
    }

    #[test]
    fn padding_differs_between_hosts() {
        let s1 = secret(1);
        let s2 = secret(2);
        let p1 = wrapper_padding_hex(&s1, 0, "curl").unwrap();
        let p2 = wrapper_padding_hex(&s2, 0, "curl").unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn padding_differs_between_names_same_host() {
        let s = secret(3);
        let p1 = wrapper_padding_hex(&s, 0, "curl").unwrap();
        let p2 = wrapper_padding_hex(&s, 0, "ssh").unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn padding_differs_between_epochs() {
        let s = secret(4);
        let p0 = wrapper_padding_hex(&s, 0, "curl").unwrap();
        let p1 = wrapper_padding_hex(&s, 1, "curl").unwrap();
        assert_ne!(p0, p1);
    }

    #[test]
    fn honey_and_real_wrapper_same_line_count() {
        let dir = tempfile::tempdir().unwrap();
        let s = secret(5);
        let real_bin = dir.path().join("curl");
        std::fs::write(&real_bin, "#!/bin/sh\n").unwrap();

        let honey = write_tripwire_wrapper("honey-name", dir.path(), &s, 0, None)
            .unwrap();
        let real = write_wrapper("scrambled-name", &real_bin, dir.path(), &s, 0, None)
            .unwrap();

        let hl = std::fs::read_to_string(&honey).unwrap().lines().count();
        let rl = std::fs::read_to_string(&real).unwrap().lines().count();
        assert_eq!(hl, rl, "honey and real wrappers must share the same line count");
    }

    #[test]
    fn trusted_ns_inode_embedded_in_wrapper() {
        let dir = tempfile::tempdir().unwrap();
        let s = secret(6);
        let real_bin = dir.path().join("curl");
        std::fs::write(&real_bin, "#!/bin/sh\n").unwrap();
        let wp =
            write_wrapper("name", &real_bin, dir.path(), &s, 0, Some(99_999))
                .unwrap();
        let text = std::fs::read_to_string(wp).unwrap();
        assert!(text.contains("99999"), "inode must appear in wrapper body");
    }

    #[test]
    fn honey_wrapper_exits_127() {
        let dir = tempfile::tempdir().unwrap();
        let s = secret(7);

        // Put the honey name in the honey list and point the FIFO to a
        // plain file so the test doesn't need a real FIFO.
        let honey_list = dir.path().join("honey.list");
        std::fs::write(&honey_list, "testname\n").unwrap();
        let stale_list = dir.path().join("stale.list");
        std::fs::write(&stale_list, "").unwrap();
        let log = dir.path().join("events.log");

        // Render with custom list/fifo paths.
        let pad = wrapper_padding_hex(&s, 0, "testname").unwrap();
        let script = render(
            "testname",
            "/dev/null",
            "0",
            honey_list.to_str().unwrap(),
            stale_list.to_str().unwrap(),
            log.to_str().unwrap(),
            &pad,
        );
        let wp = dir.path().join("testname");
        write_executable(&wp, &script).unwrap();

        assert_eq!(sh(&wp), 127);
    }

    #[test]
    fn honey_wrapper_writes_source_honey_to_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let s = secret(8);
        let honey_list = dir.path().join("honey.list");
        std::fs::write(&honey_list, "testname\n").unwrap();
        let stale_list = dir.path().join("stale.list");
        std::fs::write(&stale_list, "").unwrap();
        let log = dir.path().join("events.log");

        let pad = wrapper_padding_hex(&s, 0, "testname").unwrap();
        let script = render(
            "testname",
            "/dev/null",
            "0",
            honey_list.to_str().unwrap(),
            stale_list.to_str().unwrap(),
            log.to_str().unwrap(),
            &pad,
        );
        let wp = dir.path().join("testname");
        write_executable(&wp, &script).unwrap();

        std::process::Command::new("sh")
            .arg(&wp)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/local/bin")
            .status()
            .unwrap();

        let content = std::fs::read_to_string(&log).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(content.trim()).expect("must be valid JSON");
        assert_eq!(v["source"], "honey", "source field must be honey");
        assert_eq!(v["name"], "testname");
        // PPID start-time must be present (may be 0 in CI with no /proc).
        assert!(v["triggering_pid_start"].is_number());
    }

    #[test]
    fn stale_wrapper_writes_source_stale_and_exits_127() {
        let dir = tempfile::tempdir().unwrap();
        let s = secret(9);
        let honey_list = dir.path().join("honey.list");
        std::fs::write(&honey_list, "").unwrap();
        let stale_list = dir.path().join("stale.list");
        std::fs::write(&stale_list, "stalename\n").unwrap();
        let log = dir.path().join("events.log");

        let pad = wrapper_padding_hex(&s, 0, "stalename").unwrap();
        let script = render(
            "stalename",
            "/dev/null",
            "0",
            honey_list.to_str().unwrap(),
            stale_list.to_str().unwrap(),
            log.to_str().unwrap(),
            &pad,
        );
        let wp = dir.path().join("stalename");
        write_executable(&wp, &script).unwrap();

        assert_eq!(sh(&wp), 127);

        let content = std::fs::read_to_string(&log).unwrap();
        let v: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(v["source"], "stale");
    }

    #[test]
    fn honey_takes_precedence_over_stale() {
        let dir = tempfile::tempdir().unwrap();
        let s = secret(10);
        let honey_list = dir.path().join("honey.list");
        std::fs::write(&honey_list, "shared\n").unwrap();
        let stale_list = dir.path().join("stale.list");
        std::fs::write(&stale_list, "shared\n").unwrap();
        let log = dir.path().join("events.log");

        let pad = wrapper_padding_hex(&s, 0, "shared").unwrap();
        let script = render(
            "shared",
            "/dev/null",
            "0",
            honey_list.to_str().unwrap(),
            stale_list.to_str().unwrap(),
            log.to_str().unwrap(),
            &pad,
        );
        let wp = dir.path().join("shared");
        write_executable(&wp, &script).unwrap();
        sh(&wp);

        let content = std::fs::read_to_string(&log).unwrap();
        let v: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(v["source"], "honey");
    }

    #[test]
    fn honey_list_written_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("honey.list");
        write_honey_list(["alpha", "beta", "gamma"], Some(&p)).unwrap();
        let content = std::fs::read_to_string(&p).unwrap();
        assert!(content.contains("alpha\n"));
        assert!(content.contains("beta\n"));
        assert!(content.contains("gamma\n"));
    }

    #[test]
    fn stale_list_written_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("stale.list");
        write_stale_list(["old-curl", "old-ssh"], Some(&p)).unwrap();
        let content = std::fs::read_to_string(&p).unwrap();
        assert!(content.contains("old-curl\n"));
        assert!(content.contains("old-ssh\n"));
    }

    #[test]
    fn write_all_wrappers_skips_missing_real_paths() {
        let dir = tempfile::tempdir().unwrap();
        let s = secret(11);
        let existing = dir.path().join("real-tool");
        std::fs::write(&existing, "#!/bin/sh\n").unwrap();

        let mapping: Vec<(&str, &Path)> = vec![
            ("scrambled-exists", existing.as_path()),
            ("scrambled-missing", Path::new("/nonexistent/tool")),
        ];
        let written =
            write_all_wrappers(mapping, dir.path(), &s, 0, None).unwrap();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].file_name().unwrap(), "scrambled-exists");
    }
}
