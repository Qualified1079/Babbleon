//! Per-epoch scrambled-name → wrapper-path table for the launcher.
//!
//! # What this defeats
//!
//! The launcher (`v2-babbleon-launch-untrusted`) holds
//! `CAP_SYS_ADMIN` long enough to bind-mount the per-epoch scrambled
//! view, but it MUST NOT hold the per-host secret.  A compromise of
//! the launcher (e.g. parser-crash exploit, capability-window
//! abuse) must not yield the secret material that derives the
//! mapping.  Without this compartmentalization, the launcher's
//! attack surface would include the entire secret-key chain.
//!
//! [`ActivatedTable`] is the daemon's product: a per-epoch artefact
//! that contains every `(scrambled_name, wrapper_path)` pair the
//! launcher needs, plus the honey-name list, plus the epoch number.
//! It contains **no** secret bytes.  The daemon writes it to a
//! pre-validated pipe; the launcher consumes it post-unshare and
//! before any bind-mount syscall.
//!
//! # Mechanism
//!
//! Wire format: JSONL.  First line is the header
//! `{"epoch":<u64>,"honey":[<scrambled>,...]}`; subsequent lines
//! are one entry each:
//! `{"scrambled":"<lower-ascii>","wrapper_path":"<abs-posix>"}`.
//!
//! Strict validation on every field, applied at parse time:
//!
//! - `scrambled` matches `[a-z]+` (matches the wordlist constraint
//!   in [`crate::wordlist`]).
//! - `wrapper_path` is an absolute POSIX path, no NUL bytes, no
//!   `..` path components, no embedded newlines.
//! - Total stream size is capped at [`MAX_TABLE_BYTES`] so the
//!   launcher's parser work is bounded even under an adversarial
//!   daemon.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** launcher-side secret exposure
//!   (compartmentalization); JSON-injection-style path traversal
//!   (every path is reject-on-`..`).
//! - **Does NOT defeat:** a compromised daemon that ships a
//!   malicious table whose honey list points at real binaries.
//!   Compensating control: the daemon runs under its own UID
//!   with seccomp + landlock; its trust is rooted in the vault,
//!   not the launcher.

use std::io::BufRead;
use std::path::PathBuf;

use crate::errors::{Error, Result};

/// Hard cap on the size of a serialized activated table.  Sized to
/// fit ~1M entries with slack (each entry is ~100 B serialized);
/// far above any realistic tracked-tool count (v1 ships ~30).  A
/// hostile daemon trying to OOM the launcher hits this ceiling
/// first.
pub const MAX_TABLE_BYTES: usize = 16 * 1024 * 1024;

/// One row of the table: a scrambled name and the wrapper binary
/// path the launcher should bind-mount over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivatedEntry {
    /// Per-epoch scrambled compound (lowercase ASCII).
    pub scrambled: String,
    /// Absolute POSIX path to the wrapper binary the daemon
    /// produced for this entry.  The launcher bind-mounts this
    /// file over `<scrambled-root>/<scrambled>`.
    pub wrapper_path: PathBuf,
}

/// The daemon's per-epoch product, consumed by the launcher.
///
/// Carries no secret material.  Cloneable, debuggable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivatedTable {
    /// Epoch number this table was produced for.  Used by the
    /// launcher only for diagnostic logging; the launcher does
    /// not enforce epoch policy.
    pub epoch: u64,
    /// `(scrambled, wrapper_path)` pairs to bind-mount.
    pub entries: Vec<ActivatedEntry>,
    /// Per-epoch honey names.  Forwarded to the tripwire
    /// subsystem via the launcher's environment so the wrappers
    /// know which names should fire a tripwire on invocation.
    pub honey_names: Vec<String>,
}

impl ActivatedTable {
    /// Parse a JSONL stream into a validated table.
    ///
    /// Reads up to [`MAX_TABLE_BYTES`] from `reader`; any further
    /// bytes (or a stream that lies about its length) yield
    /// [`Error::Internal`].  Every field is validated; the first
    /// rejection short-circuits and the partially-constructed
    /// table is dropped.
    ///
    /// # Errors
    ///
    /// - [`Error::Internal`] for I/O, oversize input, JSON parse
    ///   errors, schema mismatches, and validation failures.
    pub fn read_jsonl<R: BufRead>(reader: R) -> Result<Self> {
        let mut bytes_read: usize = 0;
        let mut header: Option<HeaderRaw> = None;
        let mut entries: Vec<ActivatedEntry> = Vec::new();

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| {
                Error::Internal(format!(
                    "activated-table read at line {}: {e}",
                    line_no + 1
                ))
            })?;
            bytes_read = bytes_read.saturating_add(line.len()).saturating_add(1);
            if bytes_read > MAX_TABLE_BYTES {
                return Err(Error::Internal(format!(
                    "activated-table exceeds {MAX_TABLE_BYTES}-byte cap"
                )));
            }
            // Permit blank trailing lines for editor friendliness;
            // any leading blank line is also harmless.
            if line.trim().is_empty() {
                continue;
            }

            if header.is_none() {
                header = Some(parse_header(&line, line_no + 1)?);
            } else {
                entries.push(parse_entry(&line, line_no + 1)?);
            }
        }

        let header = header.ok_or_else(|| {
            Error::Internal("activated-table missing header line".into())
        })?;

        for h in &header.honey_names {
            validate_scrambled(h, "honey-name")?;
        }

        // Reject duplicate scrambled names.  A duplicate would
        // make the second bind-mount silently shadow the first;
        // we'd rather hard-error than misroute exec traffic.
        let mut seen = std::collections::HashSet::new();
        for e in &entries {
            if !seen.insert(e.scrambled.as_str()) {
                return Err(Error::Internal(format!(
                    "activated-table contains duplicate scrambled name {:?}",
                    e.scrambled
                )));
            }
        }

        Ok(Self {
            epoch: header.epoch,
            entries,
            honey_names: header.honey_names,
        })
    }

    /// Serialize to a JSONL byte vector for transport.
    ///
    /// Pure function over self.  Used by the daemon side and by
    /// tests; the launcher never serializes.
    ///
    /// # Errors
    ///
    /// Cannot fail in practice (writes to `Vec<u8>`); returns a
    /// `Result` for forward-compatibility with future on-wire
    /// formats.
    pub fn write_jsonl(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(256 + 64 * self.entries.len());
        write_header(&mut out, self.epoch, &self.honey_names);
        for e in &self.entries {
            write_entry(&mut out, &e.scrambled, &e.wrapper_path);
        }
        Ok(out)
    }
}

/// Builder helper for the daemon side.  Keeps the construction
/// shape compartmentalized from the parse path so a regression
/// in the writer can't degrade reader-side strictness.
#[derive(Debug, Default)]
pub struct ActivatedTableBuilder {
    epoch: u64,
    entries: Vec<ActivatedEntry>,
    honey_names: Vec<String>,
}

impl ActivatedTableBuilder {
    /// Start a builder for `epoch`.
    #[must_use]
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            entries: Vec::new(),
            honey_names: Vec::new(),
        }
    }

    /// Append one validated entry.  Returns the builder by value
    /// so callers can chain.
    ///
    /// # Errors
    ///
    /// - [`Error::Internal`] if `scrambled` or `wrapper_path`
    ///   fails validation.
    pub fn push_entry(
        mut self,
        scrambled: impl Into<String>,
        wrapper_path: impl Into<PathBuf>,
    ) -> Result<Self> {
        let scrambled = scrambled.into();
        let wrapper_path = wrapper_path.into();
        validate_scrambled(&scrambled, "scrambled")?;
        validate_wrapper_path(&wrapper_path)?;
        self.entries.push(ActivatedEntry {
            scrambled,
            wrapper_path,
        });
        Ok(self)
    }

    /// Append a honey name.  Same validation as a real entry's
    /// scrambled name (they share the wordlist alphabet).
    ///
    /// # Errors
    ///
    /// - [`Error::Internal`] if the name fails validation.
    pub fn push_honey(mut self, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_scrambled(&name, "honey-name")?;
        self.honey_names.push(name);
        Ok(self)
    }

    /// Finalize the builder.  Re-runs the duplicate-name check.
    ///
    /// # Errors
    ///
    /// - [`Error::Internal`] on duplicate scrambled names.
    pub fn finish(self) -> Result<ActivatedTable> {
        let mut seen = std::collections::HashSet::new();
        for e in &self.entries {
            if !seen.insert(e.scrambled.as_str()) {
                return Err(Error::Internal(format!(
                    "activated-table builder: duplicate scrambled name {:?}",
                    e.scrambled
                )));
            }
        }
        Ok(ActivatedTable {
            epoch: self.epoch,
            entries: self.entries,
            honey_names: self.honey_names,
        })
    }
}

/// Build an [`ActivatedTable`] from a per-epoch
/// [`crate::EpochMapping`] and a wrapper directory.
///
/// For each `(real, scrambled)` entry in the mapping, the wrapper
/// path is `wrapper_dir/<scrambled>` — the daemon's wrapper
/// generator (see [`crate::wrapper::write_all_wrappers`]) writes
/// the per-name binaries under exactly that layout, so this
/// function is the inverse-direction read.
///
/// `wrapper_dir` MUST be absolute; relative wrapper directories
/// are rejected at validation time inside
/// [`ActivatedTableBuilder::push_entry`].
///
/// The honey names from the mapping are forwarded verbatim.  The
/// builder re-validates them so a future mapping-side bug cannot
/// ship an invalid name through this path.
///
/// # Errors
///
/// - [`Error::Internal`] if `wrapper_dir` is relative, contains
///   path-traversal components, or any scrambled/honey name fails
///   the lowercase-ASCII check.
pub fn build_activated_table_from_mapping(
    mapping: &crate::EpochMapping,
    wrapper_dir: &std::path::Path,
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
        builder = builder.push_entry(scrambled.clone(), wrapper_path)?;
    }
    for honey in &mapping.honey_names {
        builder = builder.push_honey(honey.clone())?;
    }
    builder.finish()
}

/// Validate a scrambled or honey name.
///
/// Rules: non-empty, every byte is lowercase ASCII (`a..=z`).
/// Names with digits, punctuation, slashes, or non-ASCII bytes
/// are rejected — the wordlist baseline shipped with v2 is
/// lowercase-ASCII only, and any other byte would indicate
/// either a daemon bug or an injection attempt.
fn validate_scrambled(s: &str, kind: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::Internal(format!(
            "activated-table: empty {kind}"
        )));
    }
    if !s.bytes().all(|b| b.is_ascii_lowercase()) {
        return Err(Error::Internal(format!(
            "activated-table: {kind} {s:?} contains non-[a-z] bytes"
        )));
    }
    Ok(())
}

/// Validate a wrapper path.
///
/// Rules: absolute POSIX path, no NUL bytes, no `..` components,
/// no embedded newlines (newlines would corrupt the JSONL frame
/// even after JSON encoding — defense in depth).
fn validate_wrapper_path(p: &std::path::Path) -> Result<()> {
    let s = p.to_str().ok_or_else(|| {
        Error::Internal("activated-table: wrapper_path is not UTF-8".into())
    })?;
    if !p.is_absolute() {
        return Err(Error::Internal(format!(
            "activated-table: wrapper_path {s:?} is not absolute"
        )));
    }
    if s.as_bytes().contains(&0) {
        return Err(Error::Internal(
            "activated-table: wrapper_path contains a NUL byte".into(),
        ));
    }
    if s.contains('\n') || s.contains('\r') {
        return Err(Error::Internal(
            "activated-table: wrapper_path contains a newline".into(),
        ));
    }
    for comp in p.components() {
        if let std::path::Component::ParentDir = comp {
            return Err(Error::Internal(format!(
                "activated-table: wrapper_path {s:?} contains '..' \
                 component (path traversal)"
            )));
        }
    }
    Ok(())
}

struct HeaderRaw {
    epoch: u64,
    honey_names: Vec<String>,
}

fn parse_header(line: &str, line_no: usize) -> Result<HeaderRaw> {
    let v: serde_json::Value = serde_json::from_str(line).map_err(|e| {
        Error::Internal(format!(
            "activated-table header at line {line_no}: parse: {e}"
        ))
    })?;
    let obj = v.as_object().ok_or_else(|| {
        Error::Internal(format!(
            "activated-table header at line {line_no}: not a JSON object"
        ))
    })?;

    let epoch = obj
        .get("epoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            Error::Internal(format!(
                "activated-table header at line {line_no}: missing or non-u64 epoch"
            ))
        })?;

    let honey_array = obj
        .get("honey")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            Error::Internal(format!(
                "activated-table header at line {line_no}: missing or non-array honey"
            ))
        })?;

    let mut honey_names = Vec::with_capacity(honey_array.len());
    for h in honey_array {
        let s = h.as_str().ok_or_else(|| {
            Error::Internal(format!(
                "activated-table header at line {line_no}: honey entry is not a string"
            ))
        })?;
        honey_names.push(s.to_owned());
    }

    Ok(HeaderRaw { epoch, honey_names })
}

fn parse_entry(line: &str, line_no: usize) -> Result<ActivatedEntry> {
    let v: serde_json::Value = serde_json::from_str(line).map_err(|e| {
        Error::Internal(format!(
            "activated-table entry at line {line_no}: parse: {e}"
        ))
    })?;
    let obj = v.as_object().ok_or_else(|| {
        Error::Internal(format!(
            "activated-table entry at line {line_no}: not a JSON object"
        ))
    })?;
    let scrambled = obj
        .get("scrambled")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::Internal(format!(
                "activated-table entry at line {line_no}: missing scrambled"
            ))
        })?
        .to_owned();
    validate_scrambled(&scrambled, "scrambled")?;
    let wrapper_path_str = obj
        .get("wrapper_path")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::Internal(format!(
                "activated-table entry at line {line_no}: missing wrapper_path"
            ))
        })?;
    let wrapper_path = PathBuf::from(wrapper_path_str);
    validate_wrapper_path(&wrapper_path)?;
    Ok(ActivatedEntry {
        scrambled,
        wrapper_path,
    })
}

fn write_header(buf: &mut Vec<u8>, epoch: u64, honey_names: &[String]) {
    let value = serde_json::json!({
        "epoch": epoch,
        "honey": honey_names,
    });
    let line = serde_json::to_string(&value).expect("serializing a JSON object cannot fail");
    buf.extend_from_slice(line.as_bytes());
    buf.push(b'\n');
}

fn write_entry(buf: &mut Vec<u8>, scrambled: &str, wrapper_path: &std::path::Path) {
    let value = serde_json::json!({
        "scrambled": scrambled,
        "wrapper_path": wrapper_path.to_string_lossy(),
    });
    let line = serde_json::to_string(&value).expect("serializing a JSON object cannot fail");
    buf.extend_from_slice(line.as_bytes());
    buf.push(b'\n');
}

#[cfg(test)]
mod tests {
    use super::{ActivatedTable, ActivatedTableBuilder, MAX_TABLE_BYTES};
    use std::io::Cursor;
    use std::path::PathBuf;

    fn sample_table() -> ActivatedTable {
        ActivatedTableBuilder::new(42)
            .push_entry("flibsnortglarp", "/usr/local/libexec/babbleon/wrapper")
            .unwrap()
            .push_entry("breedstammergaze", "/usr/local/libexec/babbleon/wrapper")
            .unwrap()
            .push_honey("zinkdroopflarp")
            .unwrap()
            .push_honey("queltacobeam")
            .unwrap()
            .finish()
            .unwrap()
    }

    #[test]
    fn builder_roundtrip_serialises_and_parses_back() {
        let t = sample_table();
        let bytes = t.write_jsonl().unwrap();
        let parsed =
            ActivatedTable::read_jsonl(Cursor::new(bytes)).unwrap();
        assert_eq!(parsed, t);
    }

    #[test]
    fn builder_rejects_non_ascii_scrambled() {
        let err = ActivatedTableBuilder::new(0)
            .push_entry("flib\u{1F600}snort", "/usr/local/libexec/wrapper")
            .unwrap_err();
        assert!(format!("{err}").contains("non-[a-z]"));
    }

    #[test]
    fn builder_rejects_uppercase_scrambled() {
        let err = ActivatedTableBuilder::new(0)
            .push_entry("FlibSnortGlarp", "/usr/local/libexec/wrapper")
            .unwrap_err();
        assert!(format!("{err}").contains("non-[a-z]"));
    }

    #[test]
    fn builder_rejects_digits_in_scrambled() {
        let err = ActivatedTableBuilder::new(0)
            .push_entry("flib7glarp", "/usr/local/libexec/wrapper")
            .unwrap_err();
        assert!(format!("{err}").contains("non-[a-z]"));
    }

    #[test]
    fn builder_rejects_empty_scrambled() {
        let err = ActivatedTableBuilder::new(0)
            .push_entry("", "/usr/local/libexec/wrapper")
            .unwrap_err();
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn builder_rejects_relative_wrapper_path() {
        let err = ActivatedTableBuilder::new(0)
            .push_entry("flibsnortglarp", "usr/local/libexec/wrapper")
            .unwrap_err();
        assert!(format!("{err}").contains("not absolute"));
    }

    #[test]
    fn builder_rejects_path_traversal_in_wrapper_path() {
        let err = ActivatedTableBuilder::new(0)
            .push_entry("flibsnortglarp", "/usr/local/../etc/shadow")
            .unwrap_err();
        assert!(format!("{err}").contains("path traversal"));
    }

    #[test]
    fn builder_rejects_newline_in_wrapper_path() {
        let err = ActivatedTableBuilder::new(0)
            .push_entry(
                "flibsnortglarp",
                "/usr/local/libexec/wrap\nper",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("newline"));
    }

    #[test]
    fn builder_rejects_duplicate_scrambled() {
        let err = ActivatedTableBuilder::new(0)
            .push_entry("flibsnortglarp", "/usr/local/libexec/wrapper")
            .unwrap()
            .push_entry("flibsnortglarp", "/usr/local/libexec/wrapper")
            .unwrap()
            .finish()
            .unwrap_err();
        assert!(format!("{err}").contains("duplicate"));
    }

    #[test]
    fn parser_rejects_missing_header() {
        let bytes = br#"{"scrambled":"flibsnortglarp","wrapper_path":"/usr/local/libexec/wrapper"}
"#;
        let err = ActivatedTable::read_jsonl(Cursor::new(bytes)).unwrap_err();
        // Without a header, the first line is parsed AS the header
        // and fails the schema check.  Either error path is OK; we
        // just want this to be a hard error.
        assert!(format!("{err}").contains("epoch") || format!("{err}").contains("missing"));
    }

    #[test]
    fn parser_rejects_oversize_stream() {
        let bytes = vec![b'a'; MAX_TABLE_BYTES + 1];
        let err = ActivatedTable::read_jsonl(Cursor::new(bytes)).unwrap_err();
        assert!(format!("{err}").contains("cap"));
    }

    #[test]
    fn parser_rejects_non_json_line() {
        let bytes = br#"{"epoch":0,"honey":[]}
not-json-at-all
"#;
        let err = ActivatedTable::read_jsonl(Cursor::new(bytes)).unwrap_err();
        assert!(format!("{err}").contains("parse"));
    }

    #[test]
    fn parser_rejects_honey_name_with_non_ascii() {
        // JSON \u escape decodes to U+00FF inside the string.
        let bytes = b"{\"epoch\":0,\"honey\":[\"zink\\u00ffflarp\"]}\n";
        let err = ActivatedTable::read_jsonl(Cursor::new(bytes)).unwrap_err();
        assert!(format!("{err}").contains("non-[a-z]"));
    }

    #[test]
    fn parser_tolerates_blank_trailing_lines() {
        let bytes = br#"{"epoch":3,"honey":["zinkdroopflarp"]}
{"scrambled":"flibsnortglarp","wrapper_path":"/wrap"}

"#;
        let t = ActivatedTable::read_jsonl(Cursor::new(bytes)).unwrap();
        assert_eq!(t.epoch, 3);
        assert_eq!(t.entries.len(), 1);
        assert_eq!(t.honey_names.len(), 1);
    }

    #[test]
    fn parser_rejects_duplicate_scrambled_across_lines() {
        let bytes = br#"{"epoch":0,"honey":[]}
{"scrambled":"flibsnortglarp","wrapper_path":"/wrap"}
{"scrambled":"flibsnortglarp","wrapper_path":"/wrap2"}
"#;
        let err = ActivatedTable::read_jsonl(Cursor::new(bytes)).unwrap_err();
        assert!(format!("{err}").contains("duplicate"));
    }

    #[test]
    fn parser_rejects_entry_with_missing_scrambled() {
        let bytes = br#"{"epoch":0,"honey":[]}
{"wrapper_path":"/wrap"}
"#;
        let err = ActivatedTable::read_jsonl(Cursor::new(bytes)).unwrap_err();
        assert!(format!("{err}").contains("missing scrambled"));
    }

    #[test]
    fn parser_rejects_entry_with_missing_wrapper_path() {
        let bytes = br#"{"epoch":0,"honey":[]}
{"scrambled":"flibsnortglarp"}
"#;
        let err = ActivatedTable::read_jsonl(Cursor::new(bytes)).unwrap_err();
        assert!(format!("{err}").contains("missing wrapper_path"));
    }

    #[test]
    fn empty_table_with_just_header_parses() {
        let bytes = br#"{"epoch":99,"honey":[]}
"#;
        let t = ActivatedTable::read_jsonl(Cursor::new(bytes)).unwrap();
        assert_eq!(t.epoch, 99);
        assert!(t.entries.is_empty());
        assert!(t.honey_names.is_empty());
    }

    #[test]
    fn build_from_mapping_produces_table_for_every_tracked_tool() {
        use crate::{MappingBuilder, PerHostSecret, Wordlist};
        let secret = PerHostSecret::from_bytes(&[7u8; 32]).unwrap();
        let wl = Wordlist::english_baseline();
        let tracked = vec!["curl".to_string(), "git".to_string()];
        let m = MappingBuilder::new(&secret, wl).build(&tracked, 5).unwrap();
        let table = super::build_activated_table_from_mapping(
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
        // Honey names round-trip.
        assert_eq!(table.honey_names.len(), m.honey_names.len());
    }

    #[test]
    fn build_from_mapping_rejects_relative_wrapper_dir() {
        use crate::{MappingBuilder, PerHostSecret, Wordlist};
        let secret = PerHostSecret::from_bytes(&[7u8; 32]).unwrap();
        let wl = Wordlist::english_baseline();
        let m = MappingBuilder::new(&secret, wl)
            .build(&["curl".to_string()], 0)
            .unwrap();
        let err = super::build_activated_table_from_mapping(
            &m,
            std::path::Path::new("relative/wrappers"),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("not absolute"));
    }

    #[test]
    fn build_from_mapping_is_deterministic_per_input() {
        use crate::{MappingBuilder, PerHostSecret, Wordlist};
        let secret = PerHostSecret::from_bytes(&[7u8; 32]).unwrap();
        let wl = Wordlist::english_baseline();
        let m = MappingBuilder::new(&secret, wl)
            .build(
                &["curl".to_string(), "git".to_string(), "ssh".to_string()],
                0,
            )
            .unwrap();
        let a = super::build_activated_table_from_mapping(
            &m,
            std::path::Path::new("/wrappers"),
        )
        .unwrap();
        let b = super::build_activated_table_from_mapping(
            &m,
            std::path::Path::new("/wrappers"),
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn entry_paths_preserved_exactly_through_roundtrip() {
        let t = ActivatedTableBuilder::new(1)
            .push_entry(
                "alpha",
                PathBuf::from("/usr/local/libexec/babbleon/wrapper"),
            )
            .unwrap()
            .finish()
            .unwrap();
        let bytes = t.write_jsonl().unwrap();
        let parsed = ActivatedTable::read_jsonl(Cursor::new(bytes)).unwrap();
        assert_eq!(
            parsed.entries[0].wrapper_path,
            PathBuf::from("/usr/local/libexec/babbleon/wrapper")
        );
    }
}
