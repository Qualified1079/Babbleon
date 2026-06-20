//! Seeded permutation of `[0, N)`.
//!
//! Implementation: Fisher-Yates shuffle driven by ChaCha20 seeded with
//! HKDF-SHA-256 (RFC 5869) over (host-derived seed, epoch). This replaces
//! the broken Feistel prototype; same security properties (per-host
//! secret, bijective, epoch-rotatable), simpler correctness story.
//!
//! Tables are cached in-memory per (seed, epoch, n) tuple. For N=370k the
//! table is ~3 MiB.
//!
//! ## Cache bound (CWE-770 fix)
//!
//! Each rotation introduces one new (seed, epoch, n) entry; without a
//! bound the cache grows linearly with daemon lifetime.  At
//! `CACHE_MAX_ENTRIES` entries the oldest insertion is evicted (FIFO
//! against the insertion order; same as LRU for our access pattern
//! since each table is used heavily during its rotation and never
//! again).  The bound is generous: at the default N=370k that's
//! `~3 MiB × CACHE_MAX_ENTRIES` of working set — a daemon holding the
//! current epoch, the pre-build for next epoch, and the previous
//! epoch's table comfortably fits without hitting the eviction loop.

use super::kdf;
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// Maximum cached permutation tables before the oldest is evicted.
/// `STALE_RETAIN_EPOCHS` (8) plus current + pre-build plus a small
/// per-tier buffer.
pub const CACHE_MAX_ENTRIES: usize = 32;

/// Cache key: (seed bytes, epoch, n).
type Key = ([u8; 32], u64, usize);

/// (permutation, inverse) for a given key.
type Tables = (Vec<u32>, Vec<u32>);

struct Cache {
    map: HashMap<Key, Tables>,
    /// Insertion order; front is oldest.  Bounded to the same size as
    /// `map` because every map entry has exactly one queue entry.
    order: VecDeque<Key>,
    max_entries: usize,
}

impl Cache {
    fn new(max_entries: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            max_entries,
        }
    }

    fn insert(&mut self, key: Key, tables: Tables) {
        if self.map.insert(key, tables).is_none() {
            self.order.push_back(key);
        }
        while self.map.len() > self.max_entries {
            if let Some(evict) = self.order.pop_front() {
                self.map.remove(&evict);
            } else {
                break;
            }
        }
    }

    fn get(&self, key: &Key) -> Option<&Tables> {
        self.map.get(key)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

static CACHE: Lazy<Mutex<Cache>> = Lazy::new(|| Mutex::new(Cache::new(CACHE_MAX_ENTRIES)));

/// Force-evict every cached permutation table.  Test-only helper —
/// production code should let the FIFO bound do its work.
#[cfg(test)]
fn clear_cache() {
    let mut c = CACHE.lock().unwrap();
    c.map.clear();
    c.order.clear();
}

/// Derive the ChaCha20 stream seed for a given (purpose-seed, epoch).
///
/// `info = b"fpe-v1" || epoch_be` makes each epoch's permutation
/// independently keyed; the purpose-seed itself was already
/// domain-separated upstream by `mapper::purpose_seed`.
fn derive_chacha_seed(seed: &[u8], epoch: u64) -> [u8; 32] {
    let mut info = [0u8; 6 + 8];
    info[..6].copy_from_slice(b"fpe-v1");
    info[6..].copy_from_slice(&epoch.to_be_bytes());
    kdf::derive_subkey_32(seed, &info)
}

fn build(seed: &[u8], epoch: u64, n: usize) -> (Vec<u32>, Vec<u32>) {
    assert!(n > 0, "n must be positive");
    assert!(
        n <= u32::MAX as usize,
        "n must fit in u32 for cache compaction"
    );

    let chacha_seed = derive_chacha_seed(seed, epoch);
    let mut rng = ChaCha20Rng::from_seed(chacha_seed);

    let mut perm: Vec<u32> = (0..n as u32).collect();
    perm.shuffle(&mut rng);

    let mut inverse = vec![0u32; n];
    for (i, &v) in perm.iter().enumerate() {
        inverse[v as usize] = i as u32;
    }
    (perm, inverse)
}

fn with_perm<F, R>(seed: &[u8], epoch: u64, n: usize, f: F) -> R
where
    F: FnOnce(&[u32], &[u32]) -> R,
{
    let mut key = [0u8; 32];
    // collapse seed to 32 bytes via hash if needed
    if seed.len() == 32 {
        key.copy_from_slice(seed);
    } else {
        let h = derive_chacha_seed(seed, 0);
        key.copy_from_slice(&h);
    }
    let cache_key: Key = (key, epoch, n);

    let mut cache = CACHE.lock().unwrap();
    if cache.get(&cache_key).is_none() {
        let built = build(seed, epoch, n);
        cache.insert(cache_key, built);
    }
    let (p, inv) = cache.get(&cache_key).expect("just inserted");
    f(p, inv)
}

/// Encrypt index `x` to a value in `[0, n)`.
pub fn encrypt(seed: &[u8], epoch: u64, n: usize, x: usize) -> Option<usize> {
    if x >= n {
        return None;
    }
    Some(with_perm(seed, epoch, n, |p, _| p[x] as usize))
}

/// Decrypt index `y` to its preimage in `[0, n)`.
pub fn decrypt(seed: &[u8], epoch: u64, n: usize, y: usize) -> Option<usize> {
    if y >= n {
        return None;
    }
    Some(with_perm(seed, epoch, n, |_, inv| inv[y] as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_permutation_is_bijection() {
        let seed = [7u8; 32];
        let n = 100;
        let mut out: Vec<usize> = (0..n).map(|i| encrypt(&seed, 0, n, i).unwrap()).collect();
        out.sort();
        assert_eq!(out, (0..n).collect::<Vec<_>>());
    }

    #[test]
    fn roundtrip() {
        let seed = b"some-other-seed-length";
        for x in (0..1000).step_by(17) {
            let y = encrypt(seed, 0, 1000, x).unwrap();
            assert_eq!(decrypt(seed, 0, 1000, y).unwrap(), x);
        }
    }

    #[test]
    fn epoch_changes_mapping() {
        let seed = [3u8; 32];
        let n = 1000;
        let e0: Vec<usize> = (0..n).map(|i| encrypt(&seed, 0, n, i).unwrap()).collect();
        let e1: Vec<usize> = (0..n).map(|i| encrypt(&seed, 1, n, i).unwrap()).collect();
        let diff = e0.iter().zip(&e1).filter(|(a, b)| a != b).count();
        assert!(diff > n * 9 / 10, "rotation should move >90% indices");
    }

    #[test]
    fn out_of_range_is_none() {
        assert!(encrypt(&[0u8; 32], 0, 100, 100).is_none());
        assert!(decrypt(&[0u8; 32], 0, 100, 100).is_none());
    }

    #[test]
    fn cache_evicts_oldest_when_full() {
        // The global CACHE is shared across tests, so we drive a fresh
        // local cache with our test parameters instead — same logic,
        // no cross-test interference.
        let mut c = Cache::new(3);
        for i in 0..5u64 {
            let key: Key = ([i as u8; 32], i, 64);
            let dummy = (vec![0u32; 64], vec![0u32; 64]);
            c.insert(key, dummy);
        }
        // Cache holds the three most recently inserted keys; the first
        // two are evicted.
        assert_eq!(c.len(), 3);
        for i in 0..2u64 {
            let key: Key = ([i as u8; 32], i, 64);
            assert!(c.get(&key).is_none(), "expected {i} to be evicted");
        }
        for i in 2..5u64 {
            let key: Key = ([i as u8; 32], i, 64);
            assert!(c.get(&key).is_some(), "expected {i} to be retained");
        }
    }

    #[test]
    fn global_cache_stays_within_bound() {
        clear_cache();
        // Insert 2 × CACHE_MAX_ENTRIES via the real with_perm path.
        let n = 64;
        for i in 0..(CACHE_MAX_ENTRIES * 2) as u64 {
            let _ = encrypt(&[i as u8; 32], i, n, 0).unwrap();
        }
        let c = CACHE.lock().unwrap();
        assert!(
            c.len() <= CACHE_MAX_ENTRIES,
            "cache len {} exceeded bound {}",
            c.len(),
            CACHE_MAX_ENTRIES
        );
    }

    #[test]
    fn re_inserting_existing_key_is_idempotent() {
        // Same key inserted twice doesn't grow `order` past one entry
        // (otherwise eviction would drop a live key prematurely).
        let mut c = Cache::new(2);
        let key: Key = ([1u8; 32], 0, 64);
        c.insert(key, (vec![0u32; 64], vec![0u32; 64]));
        c.insert(key, (vec![1u32; 64], vec![1u32; 64]));
        assert_eq!(c.len(), 1);
        assert_eq!(c.order.len(), 1);
    }
}
