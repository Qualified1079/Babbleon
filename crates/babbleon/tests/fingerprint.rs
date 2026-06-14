//! Adversarial fingerprint test harness.
//!
//! Simulates the signature-matching approach used by tools like ObserverWard,
//! WhatWeb, and Wappalyzer when probing `--help` output.
//!
//! Strategy:
//!   1. Build wrapper scripts for every DEFAULT_TRACKED tool with deceptive banners.
//!   2. Run each wrapper with --help from an "untrusted" environment (NS inode=0
//!      so the `_in_trusted_ns` check always returns false).
//!   3. Assert the output does NOT match any signature from a simulated fingerprint
//!      DB for the real tools.
//!   4. Assert the output DOES look like a plausible text-processing tool (positive
//!      signal that the deception is working rather than silent).

use babbleon::enforcement::wrapper::write_wrapper;
use babbleon::manifest::DEFAULT_TRACKED;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::TempDir;

// ──────────────────────────────────────────────────────────────────────────────
// Simulated fingerprint database
// These are simplified regex-free patterns extracted from real ObserverWard /
// WhatWeb signature styles.  If any of these appear in the deceptive --help
// output, the banner deception has failed.
// ──────────────────────────────────────────────────────────────────────────────

/// (tool_name, &[signature_fragments])
static FINGERPRINTS: &[(&str, &[&str])] = &[
    ("curl", &["curl ", "URL", "Transfer a URL", "libcurl", "curl/"]),
    ("wget", &["wget ", "GNU Wget", "recursive download", "FTP, HTTP"]),
    (
        "ssh",
        &[
            "ssh [",
            "OpenSSH",
            "StrictHostKeyChecking",
            "identity file",
            "SSH protocol",
        ],
    ),
    ("nc", &["netcat", "nc [", "port scanning", "arbitrary TCP"]),
    (
        "python3",
        &[
            "python3 [",
            "Python 3",
            "PYTHONPATH",
            "interactive mode",
            "python.org",
        ],
    ),
    (
        "bash",
        &[
            "bash [",
            "GNU bash",
            "BASH_VERSION",
            "shell builtin",
            "command interpreter",
        ],
    ),
    ("aws", &["aws [", "AWS CLI", "Amazon Web Services", "configure", "s3"]),
    (
        "gh",
        &[
            "gh [",
            "GitHub CLI",
            "github.com",
            "pull request",
            "GITHUB_TOKEN",
        ],
    ),
    (
        "kubectl",
        &[
            "kubectl [",
            "Kubernetes",
            "kubeconfig",
            "cluster",
            "kubectl controls",
        ],
    ),
    (
        "docker",
        &[
            "docker [",
            "Docker",
            "container",
            "image",
            "docker.io",
            "DOCKER_HOST",
        ],
    ),
    (
        "terraform",
        &[
            "terraform [",
            "Terraform",
            "HashiCorp",
            "infrastructure",
            "plan/apply",
        ],
    ),
    (
        "npm",
        &[
            "npm [",
            "npm install",
            "node_modules",
            "package.json",
            "registry",
        ],
    ),
    (
        "pip",
        &[
            "pip [",
            "pip install",
            "PyPI",
            "requirements",
            "Python packages",
        ],
    ),
    ("git", &["git [", "git-", "repository", "commit", "branch", "index"]),
];

/// Patterns that a plausible text-tool banner should contain (any one suffices).
/// This verifies the deceptive response is non-empty and plausible.
static PLAUSIBLE_PATTERNS: &[&str] = &[
    "[OPTION]",
    "FILE",
    "stdin",
    "stdout",
    "lines",
    "bytes",
    "format",
    "print",
    "output",
    "input",
    "sort",
    "filter",
    "append",
    "delete",
    "separator",
    "encoding",
    "magicfiles",
    "namefile",
    "[SECTION]",
];

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Build a minimal deception map from the babbleon-cli table.
/// We inline the same pairs here so this test crate doesn't need to depend on
/// babbleon-cli (which pulls in clap etc.).
fn build_deception_map() -> HashMap<&'static str, &'static str> {
    let pairs: &[(&str, &str)] = &[
        (
            "curl",
            "less [OPTION]... [FILE]...\nFile pager.\n  -N  number lines\n  -S  chop long lines\n",
        ),
        (
            "wget",
            "man [OPTION...] [SECTION] PAGE...\nFormat and display manual pages.\n  -k  output formatted for terminal\n  -H  HTML output format\n",
        ),
        (
            "ssh",
            "sort [OPTION]... [FILE]...\nSort lines of text.\n  -n  numeric sort\n  -r  reverse\n  -k  key field\n",
        ),
        (
            "nc",
            "uniq [OPTION]... [INPUT [OUTPUT]]\nReport or omit repeated lines.\n  -c  prefix count\n  -d  only duplicates\n",
        ),
        (
            "python3",
            "diff [OPTION]... FILES\nCompare files line by line.\n  -u  unified format\n  -r  recursive\n",
        ),
        (
            "bash",
            "date [OPTION]... [+FORMAT]\nPrint or set the system date.\n  -u  UTC\n  -I  ISO 8601\n",
        ),
        (
            "aws",
            "file [-bchiLNnprsSvzZ0] [--apple] [--extension] [--mime-encoding]\n     [--mime-type] [-e testname] [-F separator] [-f namefile]\n     [-m magicfiles] [-P name=value] file...\n",
        ),
        (
            "gh",
            "head [OPTION]... [FILE]...\nPrint the first 10 lines.\n  -n K  print first K lines\n  -c K  print first K bytes\n",
        ),
        (
            "kubectl",
            "wc [OPTION]... [FILE]...\nPrint newline, word, and byte counts.\n  -l  line count\n  -w  word count\n  -c  byte count\n",
        ),
        (
            "docker",
            "cut OPTION... [FILE]...\nPrint selected parts of lines.\n  -b  byte positions\n  -c  character positions\n  -d  delimiter\n  -f  fields\n",
        ),
        (
            "terraform",
            "tee [OPTION]... [FILE]...\nCopy stdin to stdout and FILE.\n  -a  append\n  -i  ignore interrupts\n",
        ),
        (
            "npm",
            "tr [OPTION]... SET1 [SET2]\nTranslate or delete characters.\n  -d  delete\n  -s  squeeze repeats\n",
        ),
        (
            "pip",
            "od [OPTION]... [FILE]...\nDump files in octal and other formats.\n  -c  ASCII chars\n  -x  hex bytes\n",
        ),
        (
            "git",
            "nl [OPTION]... [FILE]...\nNumber lines of files.\n  -b  body numbering\n  -n  numbering format\n",
        ),
    ];
    pairs.iter().copied().collect()
}

/// Write a stub "real" binary that would print its own help text in the trusted NS.
fn write_stub_binary(dir: &std::path::Path, name: &str) {
    let path = dir.join(name);
    std::fs::write(&path, "#!/bin/sh\necho REAL_BINARY_OUTPUT\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Execute a script with `--help` and return stdout.
fn probe_help(script: &std::path::Path) -> String {
    let out = Command::new("sh")
        .arg(script)
        .arg("--help")
        // Zero out the NS inode env — irrelevant since we force inode=0 in the script
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("failed to exec wrapper");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn no_real_tool_signatures_in_deceptive_output() {
    let dir = TempDir::new().unwrap();
    let real_root = dir.path().join("real");
    let wrapper_root = dir.path().join("wrappers");
    std::fs::create_dir_all(&real_root).unwrap();
    std::fs::create_dir_all(&wrapper_root).unwrap();

    let deception = build_deception_map();
    let fp: HashMap<&str, &[&str]> = FINGERPRINTS.iter().copied().collect();

    for tool in DEFAULT_TRACKED {
        write_stub_binary(&real_root, tool);
        let real_path = real_root.join(tool);
        let banner = deception.get(tool).copied();

        let wp = write_wrapper(
            tool,
            &format!("sc-{tool}"), // scrambled name
            &real_path,
            &wrapper_root,
            b"test-host-secret",
            Some(0), // NS inode = 0 → _in_trusted_ns always returns false
            banner,
        )
        .unwrap();

        let output = probe_help(&wp);

        // Must not expose the real binary output
        assert!(
            !output.contains("REAL_BINARY_OUTPUT"),
            "wrapper for {tool} leaked real binary output in untrusted NS"
        );

        // Must not match any real-tool fingerprint
        if let Some(sigs) = fp.get(tool) {
            for sig in *sigs {
                assert!(
                    !output.to_lowercase().contains(&sig.to_lowercase()),
                    "wrapper for {tool} exposes fingerprint signature {sig:?}\noutput: {output:?}"
                );
            }
        }
    }
}

#[test]
fn deceptive_output_looks_plausible() {
    let dir = TempDir::new().unwrap();
    let real_root = dir.path().join("real");
    let wrapper_root = dir.path().join("wrappers");
    std::fs::create_dir_all(&real_root).unwrap();
    std::fs::create_dir_all(&wrapper_root).unwrap();

    let deception = build_deception_map();

    for tool in DEFAULT_TRACKED {
        write_stub_binary(&real_root, tool);
        let real_path = real_root.join(tool);
        let banner = deception.get(tool).copied();

        let wp = write_wrapper(
            tool,
            &format!("sc-{tool}"),
            &real_path,
            &wrapper_root,
            b"test-host-secret",
            Some(0), // force untrusted
            banner,
        )
        .unwrap();

        let output = probe_help(&wp);

        // Output must be non-empty
        assert!(
            !output.trim().is_empty(),
            "wrapper for {tool} returned empty output — fingerprinter will flag as blocked tool"
        );

        // Output must contain at least one plausible text-tool pattern
        let plausible = PLAUSIBLE_PATTERNS.iter().any(|p| output.contains(p));
        assert!(
            plausible,
            "wrapper for {tool} does not look like a plausible text tool\noutput: {output:?}"
        );
    }
}

#[test]
fn trusted_ns_inode_match_exposes_real_binary() {
    // When the NS inode in the wrapper matches the current mnt NS, the wrapper
    // should pass through to the real binary.  We fake this by using the actual
    // inode of /proc/self/ns/mnt.
    let dir = TempDir::new().unwrap();
    let real_root = dir.path().join("real");
    let wrapper_root = dir.path().join("wrappers");
    std::fs::create_dir_all(&real_root).unwrap();
    std::fs::create_dir_all(&wrapper_root).unwrap();

    // Real binary that echos a known string
    let real_path = real_root.join("curl");
    std::fs::write(&real_path, "#!/bin/sh\necho REAL_OUTPUT_OK\n").unwrap();
    std::fs::set_permissions(&real_path, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Get the actual mnt NS inode of this process
    let meta = std::fs::metadata("/proc/self/ns/mnt").unwrap();
    use std::os::unix::fs::MetadataExt;
    let my_inode = meta.ino();

    let wp = write_wrapper(
        "curl",
        "sc-curl",
        &real_path,
        &wrapper_root,
        b"test-host-secret",
        Some(my_inode), // matches current NS → trusted
        Some("less [OPTION]... deceptive banner"),
    )
    .unwrap();

    let out = Command::new("sh")
        .arg(&wp)
        .arg("--help")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        stdout.contains("REAL_OUTPUT_OK"),
        "trusted NS should pass through to real binary, got: {stdout:?}"
    );
    assert!(
        !stdout.contains("deceptive banner"),
        "trusted NS must not show deceptive banner"
    );
}

#[test]
fn wrapper_padding_differs_per_tool_and_secret() {
    let dir = TempDir::new().unwrap();
    let real_root = dir.path().join("real");
    std::fs::create_dir_all(&real_root).unwrap();

    let real = real_root.join("curl");
    std::fs::write(&real, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();

    let wp1 = write_wrapper(
        "curl",
        "abc",
        &real,
        &dir.path().join("w1"),
        b"secret-A",
        None,
        None,
    )
    .unwrap();
    let wp2 = write_wrapper(
        "curl",
        "abc",
        &real,
        &dir.path().join("w2"),
        b"secret-B",
        None,
        None,
    )
    .unwrap();
    let wp3 = write_wrapper(
        "curl",
        "xyz", // different scrambled name, same secret
        &real,
        &dir.path().join("w3"),
        b"secret-A",
        None,
        None,
    )
    .unwrap();

    let c1 = std::fs::read_to_string(&wp1).unwrap();
    let c2 = std::fs::read_to_string(&wp2).unwrap();
    let c3 = std::fs::read_to_string(&wp3).unwrap();

    assert_ne!(c1, c2, "different secrets must produce different padding");
    assert_ne!(c1, c3, "different scrambled names must produce different padding");
}
