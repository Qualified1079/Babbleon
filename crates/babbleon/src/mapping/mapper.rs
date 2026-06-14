//! Builds per-epoch MappingTable instances.

use super::fpe;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const COMPOUND_N: usize = 4;
pub const HONEY_COUNT: usize = 50;

/// Wordlist embedded at compile time.
const WORDLIST_RAW: &str = include_str!("../../wordlist/words.txt");

fn words() -> &'static [&'static str] {
    use once_cell::sync::Lazy;
    static WORDS: Lazy<Vec<&'static str>> = Lazy::new(|| WORDLIST_RAW.lines().collect());
    &WORDS
}

#[derive(Debug, Clone)]
pub struct MappingTable {
    pub epoch: u64,
    pub real_to_scrambled: HashMap<String, String>,
    pub scrambled_to_real: HashMap<String, String>,
    pub honey_names: Vec<String>,
}

impl MappingTable {
    pub fn scramble(&self, real: &str) -> Option<&str> {
        self.real_to_scrambled.get(real).map(|s| s.as_str())
    }

    pub fn reveal(&self, scrambled: &str) -> Option<&str> {
        self.scrambled_to_real.get(scrambled).map(|s| s.as_str())
    }

    pub fn is_honey(&self, name: &str) -> bool {
        self.honey_names.iter().any(|h| h == name)
    }
}

pub struct Mapper {
    host_secret: Vec<u8>,
}

impl Mapper {
    pub fn new(host_secret: &[u8]) -> Self {
        Self {
            host_secret: host_secret.to_vec(),
        }
    }

    fn purpose_seed(&self, purpose: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.host_secret);
        h.update(purpose);
        let bytes = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn compound(seed: &[u8], epoch: u64, slot_base: usize) -> String {
        let ws = words();
        let n = ws.len();
        let mut s = String::new();
        for i in 0..COMPOUND_N {
            let idx_in = (slot_base + i) % n;
            let idx_out = fpe::encrypt(seed, epoch, n, idx_in).unwrap();
            s.push_str(ws[idx_out]);
        }
        s
    }

    pub fn build_table(&self, tracked: &[String], epoch: u64) -> MappingTable {
        let map_seed = self.purpose_seed(b"babbleon-mapping-v1");
        let honey_seed = self.purpose_seed(b"babbleon-honey-v1");

        let mut r2s = HashMap::new();
        let mut s2r = HashMap::new();
        for (i, real) in tracked.iter().enumerate() {
            let s = Self::compound(&map_seed, epoch, i * COMPOUND_N);
            r2s.insert(real.clone(), s.clone());
            s2r.insert(s, real.clone());
        }

        let honey: Vec<String> = (0..HONEY_COUNT)
            .map(|i| Self::compound(&honey_seed, epoch, i * COMPOUND_N))
            .collect();

        MappingTable {
            epoch,
            real_to_scrambled: r2s,
            scrambled_to_real: s2r,
            honey_names: honey,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools() -> Vec<String> {
        ["curl", "ssh", "git", "aws", "docker", "kubectl"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn no_collisions() {
        let t = Mapper::new(&[5u8; 32]).build_table(&tools(), 0);
        let mut s: Vec<&str> = t.real_to_scrambled.values().map(|s| s.as_str()).collect();
        s.sort();
        let len = s.len();
        s.dedup();
        assert_eq!(s.len(), len);
    }

    #[test]
    fn roundtrip() {
        let t = Mapper::new(&[5u8; 32]).build_table(&tools(), 0);
        for tool in tools() {
            let s = t.scramble(&tool).unwrap();
            assert_eq!(t.reveal(s).unwrap(), tool);
        }
    }

    #[test]
    fn rotation_changes_all_names() {
        let m = Mapper::new(&[5u8; 32]);
        let t0 = m.build_table(&tools(), 0);
        let t1 = m.build_table(&tools(), 1);
        for tool in tools() {
            assert_ne!(t0.scramble(&tool), t1.scramble(&tool));
        }
    }

    #[test]
    fn honey_disjoint_from_real() {
        let t = Mapper::new(&[5u8; 32]).build_table(&tools(), 0);
        for h in &t.honey_names {
            assert!(t.reveal(h).is_none());
        }
    }

    #[test]
    fn different_secrets_diverge() {
        let t1 = Mapper::new(&[1u8; 32]).build_table(&tools(), 0);
        let t2 = Mapper::new(&[2u8; 32]).build_table(&tools(), 0);
        for tool in tools() {
            assert_ne!(t1.scramble(&tool), t2.scramble(&tool));
        }
    }
}
