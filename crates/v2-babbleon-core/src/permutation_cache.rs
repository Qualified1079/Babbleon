//! Small LRU cache for [`Permutation`] instances keyed by
//! `(epoch, purpose)`.
//!
//! # What this defeats
//!
//! Without a cache, every [`crate::mapping::MappingBuilder::build`]
//! call rebuilds two `Permutation` instances — the identifier
//! permutation and the honey-name permutation — from scratch via
//! Fisher-Yates over the full wordlist.  On the 370k-entry English
//! baseline that is ~35 ms per `Permutation` (`ALIAS_COUNT * 2 = 6`
//! shuffles in the production daemon's hot path), or ~70 ms per
//! `build` call.
//!
//! Hot paths that build mappings repeatedly for a small set of
//! recently-used `(epoch, purpose)` pairs amortize this cost via the
//! cache:
//!
//! - **Corpus CLI (per-file walk).**  One epoch, N files — N×
//!   speedup at the limit.
//! - **Daemon `token_mapping`.**  `ALIAS_COUNT_WIRE` virtual epochs
//!   per request, same epochs reused across requests — caps cost at
//!   the first request of each `(host-epoch, alias)` pair.
//! - **`tools/preprocessor-benchmark --mode full`.**  Same
//!   `ALIAS_COUNT` virtual epochs every iteration.
//!
//! # Mechanism
//!
//! Bounded LRU keyed by `(epoch, purpose_id)`.  On a hit the entry
//! moves to the front; on a miss the back entry is evicted to make
//! room.  Permutations are held behind [`Arc`] so callers receive a
//! refcount bump on a hit, not a Fisher-Yates copy.
//!
//! Capacity is chosen at construction.  The default —
//! [`DEFAULT_CAPACITY`] — sizes for the production daemon's worst
//! case (`ALIAS_COUNT_WIRE = 3` × two purposes = six entries) with a
//! two-entry slack for misaligned consumers.
//!
//! # What this does NOT defeat
//!
//! - **Cache pollution from very high epoch fan-out.**  Workloads
//!   that churn through more distinct epochs than the cache holds
//!   degrade to no-cache behavior; sizing the cache up is the fix.
//! - **Side-channel attacks against the permutation cache.**  Cache
//!   contents leak via memory disclosure exactly like a
//!   freshly-built `Permutation` would; the cache holds the same
//!   bytes longer.  Defense-in-depth (mlockall + Landlock + seccomp)
//!   stays the launcher's responsibility.
//! - **Cross-thread sharing scaling.**  The cache uses a [`Mutex`];
//!   uncontended the lock is sub-microsecond, so single-thread
//!   consumers (corpus walk, bench, daemon socket handler) pay
//!   nothing.  Heavy concurrent contention would serialize; no
//!   current consumer hits this.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::permutation::Permutation;

/// Default capacity sized for the production daemon's worst-case
/// fan-out (`ALIAS_COUNT_WIRE = 3` virtual epochs × two purposes =
/// six entries) with a two-entry slack for misaligned consumers.
pub const DEFAULT_CAPACITY: usize = 8;

/// Stable purpose discriminator for the identifier permutation.
///
/// Internal to the `MappingBuilder` ↔ `PermutationCache` contract;
/// chosen as `u8` (not `&[u8]`) so the cache key is `Copy + Eq` and
/// the linear scan stays a register comparison.
pub(crate) const PURPOSE_ID_IDENTIFIER: u8 = 0;

/// Stable purpose discriminator for the honey-name permutation.
pub(crate) const PURPOSE_ID_HONEY: u8 = 1;

#[derive(Clone)]
struct Entry {
    epoch: u64,
    purpose_id: u8,
    perm: Arc<Permutation>,
}

/// Bounded LRU cache for [`Permutation`] instances.
///
/// Construct once for the lifetime of a `MappingBuilder` series and
/// hand to [`crate::mapping::MappingBuilder::with_cache`].  The cache
/// is `Send + Sync`; sharing across threads is safe (a `Mutex` guards
/// the entry list).
pub struct PermutationCache {
    inner: Mutex<VecDeque<Entry>>,
    capacity: usize,
}

impl std::fmt::Debug for PermutationCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Skip the inner `Mutex<VecDeque<Entry>>` field deliberately:
        // dumping every cached Permutation would print megabytes of
        // index vectors per call, defeating the purpose of Debug.
        // `len()` already conveys the meaningful state.
        f.debug_struct("PermutationCache")
            .field("capacity", &self.capacity)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl PermutationCache {
    /// Construct a new cache with the given capacity.
    ///
    /// `capacity` is clamped at the lower bound of 1 — a zero-capacity
    /// cache would always miss; callers that do not want caching
    /// should drop the cache field via [`crate::mapping::MappingBuilder::new`]
    /// instead.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    /// Construct a cache sized to [`DEFAULT_CAPACITY`].
    #[must_use]
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }

    /// Look up the permutation for `(epoch, purpose_id)`.
    ///
    /// Returns `Some(perm)` on hit (moving the entry to the front)
    /// and `None` on miss.  Hidden behind `pub(crate)` because the
    /// `purpose_id` constants are an implementation contract with
    /// `MappingBuilder`; external consumers reach the cache via the
    /// builder, never directly.
    pub(crate) fn get(
        &self,
        epoch: u64,
        purpose_id: u8,
    ) -> Option<Arc<Permutation>> {
        let mut entries = self.inner.lock().ok()?;
        let idx = entries
            .iter()
            .position(|e| e.epoch == epoch && e.purpose_id == purpose_id)?;
        let entry =
            entries.remove(idx).expect("position returned a valid index");
        let perm = Arc::clone(&entry.perm);
        entries.push_front(entry);
        Some(perm)
    }

    /// Insert a permutation into the cache.
    ///
    /// If an entry for the same `(epoch, purpose_id)` already exists
    /// it is replaced.  When the cache is at capacity the
    /// least-recently-used entry is evicted to make room.
    pub(crate) fn insert(
        &self,
        epoch: u64,
        purpose_id: u8,
        perm: Arc<Permutation>,
    ) {
        let Ok(mut entries) = self.inner.lock() else { return };
        if let Some(idx) = entries
            .iter()
            .position(|e| e.epoch == epoch && e.purpose_id == purpose_id)
        {
            entries.remove(idx);
        }
        if entries.len() >= self.capacity {
            entries.pop_back();
        }
        entries.push_front(Entry {
            epoch,
            purpose_id,
            perm,
        });
    }

    /// Current entry count.  Exposed primarily for tests + telemetry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map(|e| e.len()).unwrap_or(0)
    }

    /// True iff the cache currently holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().map(|e| e.is_empty()).unwrap_or(true)
    }

    /// Capacity (max entries before LRU eviction).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Drop every cached entry without dropping the cache itself.
    /// Provided for operator-driven `lock`-like flows where the
    /// `MappingBuilder`'s secret may rotate independently of the
    /// cache's lifetime — clearing avoids serving permutations that
    /// were derived under a stale secret.
    pub fn clear(&self) {
        if let Ok(mut entries) = self.inner.lock() {
            entries.clear();
        }
    }
}

impl Default for PermutationCache {
    /// Defaults to [`Self::with_default_capacity`].
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::{PermutationCache, PURPOSE_ID_HONEY, PURPOSE_ID_IDENTIFIER};
    use crate::per_host_secret::PerHostSecret;
    use crate::permutation::Permutation;
    use std::sync::Arc;

    fn perm_for(epoch: u64, purpose: &[u8]) -> Arc<Permutation> {
        let secret = PerHostSecret::from_bytes(&[7u8; 32]).unwrap();
        Arc::new(Permutation::build(&secret, epoch, purpose, 64).unwrap())
    }

    #[test]
    fn empty_cache_misses() {
        let c = PermutationCache::new(4);
        assert!(c.get(0, PURPOSE_ID_IDENTIFIER).is_none());
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn insert_then_get_hits() {
        let c = PermutationCache::new(4);
        let p = perm_for(0, b"v2-test");
        c.insert(0, PURPOSE_ID_IDENTIFIER, Arc::clone(&p));
        let got = c.get(0, PURPOSE_ID_IDENTIFIER).unwrap();
        assert!(Arc::ptr_eq(&p, &got));
    }

    #[test]
    fn purpose_partitions_the_keyspace() {
        let c = PermutationCache::new(4);
        let p_id = perm_for(0, b"v2-id");
        let p_honey = perm_for(0, b"v2-honey");
        c.insert(0, PURPOSE_ID_IDENTIFIER, Arc::clone(&p_id));
        c.insert(0, PURPOSE_ID_HONEY, Arc::clone(&p_honey));
        assert!(Arc::ptr_eq(
            &c.get(0, PURPOSE_ID_IDENTIFIER).unwrap(),
            &p_id
        ));
        assert!(Arc::ptr_eq(&c.get(0, PURPOSE_ID_HONEY).unwrap(), &p_honey));
    }

    #[test]
    fn epoch_partitions_the_keyspace() {
        let c = PermutationCache::new(4);
        let p0 = perm_for(0, b"v2-test");
        let p1 = perm_for(1, b"v2-test");
        c.insert(0, PURPOSE_ID_IDENTIFIER, Arc::clone(&p0));
        c.insert(1, PURPOSE_ID_IDENTIFIER, Arc::clone(&p1));
        assert!(Arc::ptr_eq(&c.get(0, PURPOSE_ID_IDENTIFIER).unwrap(), &p0));
        assert!(Arc::ptr_eq(&c.get(1, PURPOSE_ID_IDENTIFIER).unwrap(), &p1));
    }

    #[test]
    fn lru_eviction_drops_least_recently_used() {
        let c = PermutationCache::new(2);
        let p0 = perm_for(0, b"v2-test");
        let p1 = perm_for(1, b"v2-test");
        let p2 = perm_for(2, b"v2-test");

        c.insert(0, PURPOSE_ID_IDENTIFIER, Arc::clone(&p0));
        c.insert(1, PURPOSE_ID_IDENTIFIER, Arc::clone(&p1));
        // Touch p0 so it stays MRU.
        let _ = c.get(0, PURPOSE_ID_IDENTIFIER);
        c.insert(2, PURPOSE_ID_IDENTIFIER, Arc::clone(&p2));

        // p1 was the LRU at insertion of p2; it must be gone.
        assert!(c.get(1, PURPOSE_ID_IDENTIFIER).is_none());
        // p0 and p2 must still be present.
        assert!(c.get(0, PURPOSE_ID_IDENTIFIER).is_some());
        assert!(c.get(2, PURPOSE_ID_IDENTIFIER).is_some());
    }

    #[test]
    fn duplicate_insert_replaces_in_place() {
        let c = PermutationCache::new(4);
        let p_first = perm_for(0, b"v2-test");
        let p_second = perm_for(0, b"v2-test-different-purpose-so-perm-differs");

        c.insert(0, PURPOSE_ID_IDENTIFIER, Arc::clone(&p_first));
        c.insert(0, PURPOSE_ID_IDENTIFIER, Arc::clone(&p_second));

        // Only one entry for the key — the replacement.
        assert_eq!(c.len(), 1);
        assert!(Arc::ptr_eq(
            &c.get(0, PURPOSE_ID_IDENTIFIER).unwrap(),
            &p_second
        ));
    }

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let c = PermutationCache::new(0);
        assert_eq!(c.capacity(), 1);
        let p = perm_for(0, b"v2-test");
        c.insert(0, PURPOSE_ID_IDENTIFIER, Arc::clone(&p));
        assert!(c.get(0, PURPOSE_ID_IDENTIFIER).is_some());
        // Second insert should evict the first.
        let p2 = perm_for(1, b"v2-test");
        c.insert(1, PURPOSE_ID_IDENTIFIER, Arc::clone(&p2));
        assert!(c.get(0, PURPOSE_ID_IDENTIFIER).is_none());
        assert!(c.get(1, PURPOSE_ID_IDENTIFIER).is_some());
    }

    #[test]
    fn clear_drops_every_entry() {
        let c = PermutationCache::new(4);
        c.insert(0, PURPOSE_ID_IDENTIFIER, perm_for(0, b"v2-test"));
        c.insert(1, PURPOSE_ID_IDENTIFIER, perm_for(1, b"v2-test"));
        assert_eq!(c.len(), 2);
        c.clear();
        assert!(c.is_empty());
    }

    #[test]
    fn default_constructs_with_default_capacity() {
        let c: PermutationCache = PermutationCache::default();
        assert_eq!(c.capacity(), super::DEFAULT_CAPACITY);
    }

    #[test]
    fn cache_is_send_and_sync() {
        // Compile-time assertion: PermutationCache is Send + Sync.
        // The Mutex<VecDeque<Entry>> guards us; this test compiles
        // iff that property still holds.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PermutationCache>();
    }

    #[test]
    fn concurrent_inserts_do_not_corrupt() {
        // Property: two threads inserting different keys concurrently
        // leave the cache in a consistent state (every successfully-
        // inserted key is recoverable, no double-counting).
        use std::sync::Arc as StdArc;
        use std::thread;

        let c = StdArc::new(PermutationCache::new(64));
        let mut handles = Vec::new();
        for tid in 0..4u64 {
            let c = StdArc::clone(&c);
            handles.push(thread::spawn(move || {
                for i in 0..8u64 {
                    let epoch = tid * 100 + i;
                    let p = perm_for(epoch, b"v2-concurrent");
                    c.insert(epoch, PURPOSE_ID_IDENTIFIER, p);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Cache capacity is 64; all 4*8=32 entries fit.
        assert_eq!(c.len(), 32);
        for tid in 0..4u64 {
            for i in 0..8u64 {
                let epoch = tid * 100 + i;
                assert!(
                    c.get(epoch, PURPOSE_ID_IDENTIFIER).is_some(),
                    "missing entry for epoch {epoch}",
                );
            }
        }
    }
}
