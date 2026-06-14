//! Trusted/untrusted view abstraction.

use crate::mapping::MappingTable;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct View {
    pub tier: String,
    pub entries: HashMap<String, PathBuf>,
}

impl View {
    pub fn trusted(tracked: &[String], real_root: &Path) -> Self {
        let entries = tracked
            .iter()
            .filter_map(|name| {
                let p = real_root.join(name);
                p.exists().then_some((name.clone(), p))
            })
            .collect();
        Self {
            tier: "trusted".into(),
            entries,
        }
    }

    pub fn untrusted(mapping: &MappingTable, real_root: &Path) -> Self {
        let entries = mapping
            .real_to_scrambled
            .iter()
            .filter_map(|(real, scrambled)| {
                let p = real_root.join(real);
                p.exists().then_some((scrambled.clone(), p))
            })
            .collect();
        Self {
            tier: "untrusted".into(),
            entries,
        }
    }

    pub fn names(&self) -> Vec<&str> {
        let mut n: Vec<&str> = self.entries.keys().map(|s| s.as_str()).collect();
        n.sort();
        n
    }

    pub fn resolve(&self, name: &str) -> Option<&PathBuf> {
        self.entries.get(name)
    }
}
