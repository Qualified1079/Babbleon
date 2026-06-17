//! Seeded permutation of `[0, N)`.
//!
//! Implementation: Fisher-Yates shuffle driven by ChaCha20 seeded with
//! HKDF-SHA-256 (RFC 5869) over (host-derived seed, epoch). This replaces
//! the broken Feistel prototype; same security properties (per-host
//! secret, bijective, epoch-rotatable), simpler correctness story.
//!
//! Tables are cached in-memory per (seed, epoch, n) tuple. For N=370k the
//! table is ~3 MiB — fine for a daemon, trivial for a one-shot CLI.

use super::kdf;
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::sync::Mutex;

/// Cache key: (seed bytes, epoch, n).
type Key = ([u8; 32], u64, usize);

/// (permutation, inverse) for a given key.
type Tables = (Vec<u32>, Vec<u32>);

static CACHE: Lazy<Mutex<HashMap<Key, Tables>>> = Lazy::new(|| Mutex::new(HashMap::new()));

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
    cache.entry(cache_key).or_insert_with(|| {
        let (p, inv) = build(seed, epoch, n);
        (p, inv)
    });
    let (p, inv) = cache.get(&cache_key).unwrap();
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
}
