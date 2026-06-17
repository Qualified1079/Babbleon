//! Builds per-epoch MappingTable instances.

use super::fpe;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zeroize::Zeroizing;

pub const COMPOUND_N: usize = 4;
pub const HONEY_COUNT: usize = 50;

/// How many prior epochs of scrambled names to retain as stale-mapping
/// tripwires.  Any scrambled name from one of the last K epochs that an
/// untrusted process attempts to execute fires a high-confidence
/// `HoneyTriggered` (legitimate users have no source for these names —
/// they are by definition things only a prior reconnaissance pass would
/// know).  Independent of the random honey set: catches the *cached
/// intel* attacker rather than the *random guess* attacker.
pub const STALE_RETAIN_EPOCHS: u64 = 8;

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

/// Holder for the per-host secret.
///
/// The secret is the *only* thing standing between a public-knowledge
/// attacker and the mapping; we therefore hold it in `Zeroizing<Vec<u8>>`
/// so it is wiped on drop instead of lingering in heap pages until the
/// allocator hands them back out.  Closes the "core-dump / paged-out /
/// heap-reuse" leakage class for the `Mapper`'s copy of the secret.
pub struct Mapper {
    host_secret: Zeroizing<Vec<u8>>,
}

impl Mapper {
    pub fn new(host_secret: &[u8]) -> Self {
        Self {
            host_secret: Zeroizing::new(host_secret.to_vec()),
        }
    }

    fn purpose_seed(&self, purpose: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.host_secret.as_slice());
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

    /// Return the scrambled names that this `tracked` set received in
    /// the `retain` most recent epochs strictly before `current_epoch`.
    ///
    /// Used to populate the stale-mapping tripwire list at rotation
    /// time.  Any name in this set, executed against the untrusted
    /// view, is a high-confidence tripwire — the only sources for such
    /// a name are a prior reconnaissance pass or the kept-around state
    /// of an attacker that has been on the host across rotations.
    ///
    /// Skips the current epoch's names by construction (we don't
    /// trip-wire the live mapping).
    pub fn stale_names_for_previous_epochs(
        &self,
        tracked: &[String],
        current_epoch: u64,
        retain: u64,
    ) -> Vec<String> {
        let map_seed = self.purpose_seed(b"babbleon-mapping-v1");
        let start = current_epoch.saturating_sub(retain);
        let mut out = Vec::with_capacity(tracked.len() * retain as usize);
        for past_epoch in start..current_epoch {
            for (i, _real) in tracked.iter().enumerate() {
                out.push(Self::compound(&map_seed, past_epoch, i * COMPOUND_N));
            }
        }
        out
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

    #[test]
    fn stale_names_cover_previous_epochs() {
        let m = Mapper::new(&[7u8; 32]);
        let tools = tools();
        let current = 5u64;
        let retain = 3u64;
        let stale = m.stale_names_for_previous_epochs(&tools, current, retain);
        assert_eq!(stale.len(), tools.len() * retain as usize);

        // Each stale name must be the scrambled output for some past
        // epoch — i.e. it must equal what `build_table(... past_epoch)`
        // produced for one of the tracked tools.
        let mut expected: Vec<String> = Vec::new();
        for past in (current - retain)..current {
            let t = m.build_table(&tools, past);
            for tool in &tools {
                expected.push(t.scramble(tool).unwrap().to_string());
            }
        }
        expected.sort();
        let mut got = stale.clone();
        got.sort();
        assert_eq!(got, expected);
    }

    #[test]
    fn stale_names_disjoint_from_current() {
        let m = Mapper::new(&[9u8; 32]);
        let tools = tools();
        let current = 4u64;
        let stale = m.stale_names_for_previous_epochs(&tools, current, 4);
        let curr = m.build_table(&tools, current);
        let curr_scrambled: std::collections::HashSet<&str> =
            curr.real_to_scrambled.values().map(|s| s.as_str()).collect();
        for name in &stale {
            assert!(
                !curr_scrambled.contains(name.as_str()),
                "stale name {name:?} collides with a current scrambled name"
            );
        }
    }

    #[test]
    fn stale_names_clamp_at_epoch_zero() {
        // retain larger than current_epoch must not panic; just produce
        // fewer entries.
        let m = Mapper::new(&[3u8; 32]);
        let tools = tools();
        let stale = m.stale_names_for_previous_epochs(&tools, 2, 100);
        assert_eq!(stale.len(), tools.len() * 2);
    }
}
