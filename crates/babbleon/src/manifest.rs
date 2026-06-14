//! Tracked-tool manifest.
//!
//! Community edition: static default or local TOML. Enterprise edition:
//! MDM-pushed manifest via the plugin registry. Same `Manifest` type either way.

use crate::Result;
use serde::Deserialize;
use std::path::Path;

pub const DEFAULT_TRACKED: &[&str] = &[
    "curl", "ssh", "nc", "python3", "bash", "wget", "git",
    "aws", "gh", "kubectl", "docker", "terraform", "npm", "pip",
];

#[derive(Debug, Clone)]
pub struct Manifest {
    pub tracked: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ManifestFile {
    manifest: ManifestSection,
}

#[derive(Debug, Deserialize)]
struct ManifestSection {
    #[serde(default)]
    tracked: Vec<String>,
}

impl Manifest {
    pub fn default_tracked() -> Self {
        Self {
            tracked: DEFAULT_TRACKED.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let f: ManifestFile = toml::from_str(&text)?;
        let tracked = if f.manifest.tracked.is_empty() {
            DEFAULT_TRACKED.iter().map(|s| s.to_string()).collect()
        } else {
            f.manifest.tracked
        };
        Ok(Self { tracked })
    }

    /// Load from file if present, otherwise return defaults.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) if p.exists() => Self::from_file(p),
            _ => Ok(Self::default_tracked()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_nonempty() {
        let m = Manifest::default_tracked();
        assert!(!m.tracked.is_empty());
    }

    #[test]
    fn load_falls_back_to_default() {
        let m = Manifest::load(Some(Path::new("/nonexistent.toml"))).unwrap();
        assert_eq!(m.tracked.len(), DEFAULT_TRACKED.len());
    }

    #[test]
    fn from_file_parses_toml() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("m.toml");
        std::fs::write(
            &p,
            "[manifest]\nversion = 1\ntracked = [\"foo\", \"bar\"]\n",
        )
        .unwrap();
        let m = Manifest::from_file(&p).unwrap();
        assert_eq!(m.tracked, vec!["foo", "bar"]);
    }
}
