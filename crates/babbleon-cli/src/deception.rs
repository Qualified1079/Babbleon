//! M3.5 banner deception table.
//!
//! When the wrapper is invoked with `--help` or `--version` from an
//! *untrusted* namespace, it returns a plausible-wrong response rather than
//! silence.  This defeats fingerprinters that distinguish "empty response"
//! (blocked tool) from "has output" (tool found).
//!
//! The table maps a real tool name to a *decoy* tool whose help text the
//! wrapper will imitate.  The decoy help text is embedded verbatim so the
//! wrapper emits it without exec'ing the real binary.

use std::collections::HashMap;

/// Returns the decoy tool name for a given real tool, if one is configured.
#[allow(dead_code)]
pub fn decoy_for(real: &str) -> Option<&'static str> {
    deception_map().get(real).copied()
}

/// Returns the deceptive banner text for a decoy tool name.
#[allow(dead_code)]
pub fn banner_for_decoy(decoy: &str) -> Option<&'static str> {
    deception_snippets().get(decoy).copied()
}

/// Map: real tool → decoy tool.
///
/// Goals:
///   1. The decoy must be plausible — a tool that *could* exist on the system.
///   2. The decoy must not be another Babbleon-tracked tool (would give
///      the attacker a cross-reference).
///   3. The decoy categories should be diverse: text tools, dev tools, sysadmin.
fn deception_map() -> &'static HashMap<&'static str, &'static str> {
    static MAP: std::sync::OnceLock<HashMap<&'static str, &'static str>> =
        std::sync::OnceLock::new();
    MAP.get_or_init(|| {
        let pairs: &[(&str, &str)] = &[
            ("curl", "less"),
            ("wget", "man"),
            ("ssh", "sort"),
            ("nc", "uniq"),
            ("python3", "diff"),
            ("bash", "date"),
            ("aws", "file"),
            ("gh", "head"),
            ("kubectl", "wc"),
            ("docker", "cut"),
            ("terraform", "tee"),
            ("npm", "tr"),
            ("pip", "od"),
            ("git", "nl"),
        ];
        pairs.iter().copied().collect()
    })
}

/// Truncated but representative help snippets for common text-processing
/// tools.  Just enough to fool a pattern-matching fingerprinter.
fn deception_snippets() -> &'static HashMap<&'static str, &'static str> {
    static SNIPPETS: std::sync::OnceLock<HashMap<&'static str, &'static str>> =
        std::sync::OnceLock::new();
    SNIPPETS.get_or_init(|| {
        let pairs: &[(&str, &str)] = &[
            ("less",
             "less [OPTION]... [FILE]...\nFile pager.\n  -N  number lines\n  -S  chop long lines\n"),
            ("man",
             "man [OPTION...] [SECTION] PAGE...\nFormat and display manual pages.\n  -k  output formatted for terminal\n  -H  HTML output format\n"),
            ("sort",
             "sort [OPTION]... [FILE]...\nSort lines of text.\n  -n  numeric sort\n  -r  reverse\n  -k  key field\n"),
            ("uniq",
             "uniq [OPTION]... [INPUT [OUTPUT]]\nReport or omit repeated lines.\n  -c  prefix count\n  -d  only duplicates\n"),
            ("diff",
             "diff [OPTION]... FILES\nCompare files line by line.\n  -u  unified format\n  -r  recursive\n"),
            ("date",
             "date [OPTION]... [+FORMAT]\nPrint or set the system date.\n  -u  UTC\n  -I  ISO 8601\n"),
            ("file",
             "file [-bchiLNnprsSvzZ0] [--apple] [--extension] [--mime-encoding]\n     [--mime-type] [-e testname] [-F separator] [-f namefile]\n     [-m magicfiles] [-P name=value] file...\n"),
            ("head",
             "head [OPTION]... [FILE]...\nPrint the first 10 lines.\n  -n K  print first K lines\n  -c K  print first K bytes\n"),
            ("wc",
             "wc [OPTION]... [FILE]...\nPrint newline, word, and byte counts.\n  -l  line count\n  -w  word count\n  -c  byte count\n"),
            ("cut",
             "cut OPTION... [FILE]...\nPrint selected parts of lines.\n  -b  byte positions\n  -c  character positions\n  -d  delimiter\n  -f  fields\n"),
            ("tee",
             "tee [OPTION]... [FILE]...\nCopy stdin to stdout and FILE.\n  -a  append\n  -i  ignore interrupts\n"),
            ("tr",
             "tr [OPTION]... SET1 [SET2]\nTranslate or delete characters.\n  -d  delete\n  -s  squeeze repeats\n"),
            ("od",
             "od [OPTION]... [FILE]...\nDump files in octal and other formats.\n  -c  ASCII chars\n  -x  hex bytes\n"),
            ("nl",
             "nl [OPTION]... [FILE]...\nNumber lines of files.\n  -b  body numbering\n  -n  numbering format\n"),
        ];
        pairs.iter().copied().collect()
    })
}

/// Generate the deceptive response for a real tool.  Returns None if the tool
/// has no deception entry (wrapper falls back to silence).
pub fn deceptive_response(real_tool: &str) -> Option<&'static str> {
    let decoy = deception_map().get(real_tool)?;
    deception_snippets().get(decoy).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_tracked_tools_have_deception_entries() {
        use babbleon::manifest::DEFAULT_TRACKED;
        let missing: Vec<_> = DEFAULT_TRACKED
            .iter()
            .filter(|t| deceptive_response(t).is_none())
            .collect();
        assert!(
            missing.is_empty(),
            "tools missing deception entry: {missing:?}"
        );
    }

    #[test]
    fn deceptive_response_is_not_empty() {
        for tool in babbleon::manifest::DEFAULT_TRACKED {
            let r = deceptive_response(tool);
            assert!(r.is_some(), "no deceptive response for {tool}");
            let s = r.unwrap();
            assert!(!s.is_empty(), "empty response for {tool}");
            assert!(s.len() > 20, "response too short for {tool}: {s:?}");
        }
    }

    #[test]
    fn decoy_does_not_equal_real_name() {
        for tool in babbleon::manifest::DEFAULT_TRACKED {
            if let Some(decoy) = decoy_for(tool) {
                assert_ne!(*tool, decoy, "decoy for {tool} must not be the tool itself");
            }
        }
    }
}
