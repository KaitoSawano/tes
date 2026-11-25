// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Xephash v1: the XEPAY memory-hard proof-of-work function.
//!
//! # Design
//!
//! Xephash keeps SHA3-256 (already used everywhere in XEPAY) as its only
//! hash and adds a memory-hard structure on top of it:
//!
//! 1. A small **cache** is derived from an epoch seed (sequential SHA3-256
//!    chain plus three rounds of random mixing).
//! 2. A large **dataset** is derived item by item from the cache. A node
//!    can compute any single item from the cache alone ("light" mode), a
//!    miner stores all items ("full" mode) to be fast.
//! 3. For every nonce, 64 pseudo-random pages of the dataset are read and
//!    folded into a 128-byte mix, which is compressed to 32 bytes and
//!    hashed once more. The final 32 bytes are compared with the target.
//!
//! Verification needs only the cache (about 1 ms), mining needs the full
//! dataset and is limited by memory bandwidth, not by raw hash speed.
//!
//! # Rules that make the function unambiguous
//!
//! * `H(x)` is SHA3-256. All words are `u32` and **little-endian** when
//!   converted from or to bytes; the nonce is a little-endian `u64`.
//! * `fnv(a, b) = (a * 0x01000193 mod 2^32) xor b`.
//! * `reduce(x, n) = (x * n) >> 32` (computed in `u64`): an unbiased map of
//!   a 32-bit value into `0..n` that uses the HIGH bits (the low bits of an
//!   FNV result are weak, so a plain `%` is avoided).
//! * Epoch of a block = `block_number / epoch_length`; the seed of epoch
//!   `e` is `H` applied `e` times to 32 zero bytes.
//! * The final PoW value is compared big-endian with the 256-bit target.
//!
//! Nothing here panics on bad input: every failure is a `XephashError`.

use std::fmt; // Display implementation for the error type
use std::sync::{Arc, Mutex, MutexGuard}; // shared caches across threads

use crate::sha3::sha3_256; // the only hash function used by Xephash

/// Size of one cache/dataset item in bytes (one SHA3-256 output).
pub const ITEM_BYTES: usize = 32;
/// Number of 32-bit words in one item.
const ITEM_WORDS: usize = 8;
/// Number of 32-bit words in the mix (128 bytes).
const MIX_WORDS: usize = 32;
/// Dataset items fetched per access (4 items = one 128-byte page).
const ITEMS_PER_ACCESS: usize = 4;
/// Number of dataset page reads per hash.
pub const ACCESSES: u32 = 64;
/// Number of cache items folded into each dataset item.
pub const DATASET_PARENTS: u32 = 128;
/// Number of random-mixing rounds when building the cache.
pub const CACHE_ROUNDS: u32 = 3;
/// FNV prime used by `fnv`.
const FNV_PRIME: u32 = 0x0100_0193;
/// Domain separation tag mixed into the seed and the final hash.
const DOMAIN_TAG: &[u8; 8] = b"XEPHASH1";
/// Largest epoch accepted (bounds the seed computation loop).
pub const MAX_EPOCH: u64 = 1_000_000;
/// Largest cache item count (2^24 items = 512 MiB).
pub const MAX_CACHE_ITEMS: u32 = 1 << 24;
/// Largest dataset item count (2^27 items = 4 GiB).
pub const MAX_DATASET_ITEMS: u32 = 1 << 27;
/// Smallest cache / dataset item count accepted.
const MIN_ITEMS: u32 = 16;

/// One 32-byte cache or dataset item.
pub type Item = [u8; ITEM_BYTES];

/// Everything that can go wrong inside Xephash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XephashError {
    /// A parameter is outside the supported range.
    InvalidParams(&'static str),
    /// The epoch is above `MAX_EPOCH`.
    EpochTooLarge,
    /// The cache or dataset memory could not be allocated.
    OutOfMemory,
}

impl fmt::Display for XephashError {
    // Human readable messages for logs and RPC errors.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XephashError::InvalidParams(m) => write!(f, "invalid xephash parameters: {}", m),
            XephashError::EpochTooLarge => write!(f, "xephash epoch is too large"),
            XephashError::OutOfMemory => write!(f, "not enough memory for xephash data"),
        }
    }
}

impl std::error::Error for XephashError {}

/// Size parameters of one network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// Number of 32-byte items in the cache.
    pub cache_items: u32,
    /// Number of 32-byte items in the full dataset (multiple of 4).
    pub dataset_items: u32,
    /// Number of blocks that share one epoch (one seed, one dataset).
    pub epoch_length: u64,
}

impl Params {
    /// Production parameters: 4 MiB cache, 128 MiB dataset.
    pub const MAIN: Params = Params {
        cache_items: 131_072,
        dataset_items: 4_194_304,
        epoch_length: 30_000,
    };
    /// Public test network: 512 KiB cache, 8 MiB dataset.
    pub const TEST: Params = Params {
        cache_items: 16_384,
        dataset_items: 262_144,
        epoch_length: 30_000,
    };
    /// Local regression network: tiny data, short epochs.
    pub const REGTEST: Params = Params {
        cache_items: 256,
        dataset_items: 4_096,
        epoch_length: 100,
    };

    /// Check that all values are inside the supported ranges.
    pub fn validate(&self) -> Result<(), XephashError> {
        // The cache must be large enough for the mixing rounds to be meaningful.
        if self.cache_items < MIN_ITEMS || self.cache_items > MAX_CACHE_ITEMS {
            return Err(XephashError::InvalidParams("cache_items out of range"));
        }
        // The dataset is read in pages of 4 items, so its size must be a multiple of 4.
        if self.dataset_items < MIN_ITEMS
            || self.dataset_items > MAX_DATASET_ITEMS
            || self.dataset_items % ITEMS_PER_ACCESS as u32 != 0
        {
            return Err(XephashError::InvalidParams("dataset_items out of range"));
        }
        // An epoch length of zero would divide by zero.
        if self.epoch_length == 0 {
            return Err(XephashError::InvalidParams("epoch_length must be positive"));
        }
        Ok(())
    }

    /// Epoch number of `block_number`.
    pub fn epoch_of(&self, block_number: u64) -> Result<u64, XephashError> {
        // Guard against a zero epoch length (unvalidated parameters).
        if self.epoch_length == 0 {
            return Err(XephashError::InvalidParams("epoch_length must be positive"));
        }
        // Integer division gives the epoch.
        let epoch = block_number / self.epoch_length;
        // Reject absurd epochs so the seed loop stays bounded.
        if epoch > MAX_EPOCH {
            return Err(XephashError::EpochTooLarge);
        }
        Ok(epoch)
    }
}

/// FNV-style mixing step on 32-bit words.
fn fnv(a: u32, b: u32) -> u32 {
    a.wrapping_mul(FNV_PRIME) ^ b // multiply with wrap-around, then xor
}

/// Map a 32-bit value into `0..n` using its high bits (`n` must be > 0).
fn reduce(x: u32, n: u32) -> u32 {
    ((x as u64 * n as u64) >> 32) as u32 // 64-bit product cannot overflow
}

/// Split an item into eight little-endian words.
fn item_to_words(item: &Item) -> [u32; ITEM_WORDS] {
    let mut words = [0u32; ITEM_WORDS]; // output words
    for (i, chunk) in item.chunks_exact(4).enumerate() {
        // Each chunk has exactly four bytes, so the array below is exact.
        words[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    words
}

/// Join eight words into an item using little-endian byte order.
fn words_to_item(words: &[u32; ITEM_WORDS]) -> Item {
    let mut item = [0u8; ITEM_BYTES]; // output bytes
    for (i, word) in words.iter().enumerate() {
        // Write the four bytes of this word at its position.
        item[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    item
}

/// Seed of `epoch`: SHA3-256 applied `epoch` times to 32 zero bytes.
pub fn epoch_seed(epoch: u64) -> Result<Item, XephashError> {
    // Bound the loop below.
    if epoch > MAX_EPOCH {
        return Err(XephashError::EpochTooLarge);
    }
    let mut seed = [0u8; ITEM_BYTES]; // epoch 0 seed
    for _ in 0..epoch {
        seed = sha3_256(&seed); // one hash per epoch step
    }
    Ok(seed)
}

/// The small per-epoch cache (light verification data).
pub struct Cache {
    items: Vec<Item>, // cache items, at least MIN_ITEMS long
}

impl Cache {
    /// Build the cache of `cache_items` items from `seed`.
    pub fn generate(seed: &Item, cache_items: u32) -> Result<Cache, XephashError> {
        // Reject sizes outside the supported range.
        if cache_items < MIN_ITEMS || cache_items > MAX_CACHE_ITEMS {
            return Err(XephashError::InvalidParams("cache_items out of range"));
        }
        let n = cache_items as usize; // item count as usize
        let mut items: Vec<Item> = Vec::new(); // the cache
        // Reserve memory without aborting the process when it is unavailable.
        items
            .try_reserve_exact(n)
            .map_err(|_| XephashError::OutOfMemory)?;
        // First item: hash of the seed.
        items.push(sha3_256(seed));
        // Sequential chain: every item is the hash of the previous one.
        for i in 1..n {
            let prev = items[i - 1]; // copy of the previous item (i >= 1)
            items.push(sha3_256(&prev));
        }
        // Random mixing rounds (in place, in index order).
        for _ in 0..CACHE_ROUNDS {
            for i in 0..n {
                // First word of the current item picks the partner item.
                let v = u32::from_le_bytes([items[i][0], items[i][1], items[i][2], items[i][3]]);
                let j = reduce(v, cache_items) as usize; // partner index, always < n
                let a = items[(i + n - 1) % n]; // previous item (wrapping around)
                let b = items[j]; // partner item
                let mut x = [0u8; ITEM_BYTES]; // a xor b
                for k in 0..ITEM_BYTES {
                    x[k] = a[k] ^ b[k]; // byte-wise xor
                }
                items[i] = sha3_256(&x); // replace the item by the hash of the xor
            }
        }
        Ok(Cache { items })
    }

    /// Number of items in the cache.
    pub fn len(&self) -> usize {
        self.items.len() // item count
    }

    /// True when the cache has no items (never true for a generated cache).
    pub fn is_empty(&self) -> bool {
        self.items.is_empty() // see len()
    }

    /// Fetch one cache item; an out-of-range index cannot happen by design.
    fn item(&self, index: usize) -> Item {
        self.items.get(index).copied().unwrap_or([0u8; ITEM_BYTES])
    }

    /// Compute dataset item `index` from the cache (works in light mode).
    pub fn dataset_item(&self, index: u32) -> Item {
        let n = self.items.len(); // cache size
        if n == 0 {
            return [0u8; ITEM_BYTES]; // unreachable for a generated cache
        }
        let n32 = n as u32; // cache size as u32 (<= MAX_CACHE_ITEMS)
        // Start from the cache item at the same position (wrapping).
        let mut mix = item_to_words(&self.item(index as usize % n));
        mix[0] ^= index; // bind the item to its index
        // Hash the start value so the walk begins at a pseudo-random point.
        mix = item_to_words(&sha3_256(&words_to_item(&mix)));
        // Fold DATASET_PARENTS pseudo-random cache items into the mix.
        for j in 0..DATASET_PARENTS {
            // Parent index from the current mix; always < n.
            let parent_index = reduce(fnv(index ^ j, mix[j as usize % ITEM_WORDS]), n32) as usize;
            let parent = item_to_words(&self.item(parent_index)); // parent as words
            for k in 0..ITEM_WORDS {
                mix[k] = fnv(mix[k], parent[k]); // word-wise fold
            }
        }
        sha3_256(&words_to_item(&mix)) // final hash is the dataset item
    }
}

/// The full dataset (miner data), derived from a cache.
pub struct Dataset {
    items: Vec<Item>, // all dataset items
}

impl Dataset {
    /// Generate `dataset_items` items from `cache` using `threads` threads.
    pub fn generate(
        cache: &Cache,
        dataset_items: u32,
        threads: usize,
    ) -> Result<Dataset, XephashError> {
        // The dataset is read in pages of 4 items.
        if dataset_items < MIN_ITEMS
            || dataset_items > MAX_DATASET_ITEMS
            || dataset_items % ITEMS_PER_ACCESS as u32 != 0
        {
            return Err(XephashError::InvalidParams("dataset_items out of range"));
        }
        // An empty cache cannot produce items.
        if cache.is_empty() {
            return Err(XephashError::InvalidParams("cache is empty"));
        }
        let n = dataset_items as usize; // item count as usize
        let mut items: Vec<Item> = Vec::new(); // the dataset
        // Reserve memory without aborting the process when it is unavailable.
        items
            .try_reserve_exact(n)
            .map_err(|_| XephashError::OutOfMemory)?;
        items.resize(n, [0u8; ITEM_BYTES]); // zero-filled, capacity already reserved
        let threads = threads.clamp(1, 64); // sane thread count
        let chunk = (n + threads - 1) / threads; // items per thread (>= 1 because n >= 16)
        // Scoped threads borrow `cache` and their own slice of `items`.
        std::thread::scope(|scope| {
            for (ci, slice) in items.chunks_mut(chunk).enumerate() {
                let base = ci * chunk; // index of the first item of this chunk
                scope.spawn(move || {
                    for (k, slot) in slice.iter_mut().enumerate() {
                        // Item index is below dataset_items (<= 2^27), so it fits in u32.
                        *slot = cache.dataset_item((base + k) as u32);
                    }
                });
            }
        });
        Ok(Dataset { items })
    }

    /// Number of items in the dataset.
    pub fn len(&self) -> usize {
        self.items.len() // item count
    }

    /// True when the dataset has no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty() // see len()
    }
}

/// Result of one Xephash evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Output {
    /// Compressed mix (32 bytes); can be stored in a header for quick checks.
    pub mix_digest: Item,
    /// Final PoW value, compared big-endian with the target.
    pub result: Item,
}

/// Core of the function: works with any source of dataset items.
fn hashimoto_with<F: FnMut(u32) -> Item>(
    dataset_items: u32,
    header_hash: &Item,
    nonce: u64,
    mut fetch: F,
) -> Result<Output, XephashError> {
    // Same size rules as everywhere else.
    if dataset_items < MIN_ITEMS || dataset_items % ITEMS_PER_ACCESS as u32 != 0 {
        return Err(XephashError::InvalidParams("dataset_items out of range"));
    }
    let pages = dataset_items / ITEMS_PER_ACCESS as u32; // number of 4-item pages (>= 4)

    // seed = H(tag || header_hash || nonce_le)
    let mut input: Vec<u8> = Vec::with_capacity(DOMAIN_TAG.len() + ITEM_BYTES + 8);
    input.extend_from_slice(DOMAIN_TAG); // domain separation
    input.extend_from_slice(header_hash); // 32-byte header hash without nonce
    input.extend_from_slice(&nonce.to_le_bytes()); // nonce, little-endian
    let seed = sha3_256(&input); // 32-byte seed
    let s0 = u32::from_le_bytes([seed[0], seed[1], seed[2], seed[3]]); // first seed word
    let seed_words = item_to_words(&seed); // seed as 8 words

    // The 128-byte mix starts as the seed repeated four times.
    let mut mix = [0u32; MIX_WORDS];
    for (i, slot) in mix.iter_mut().enumerate() {
        *slot = seed_words[i % ITEM_WORDS];
    }

    // 64 pseudo-random page reads folded into the mix.
    for a in 0..ACCESSES {
        // Page number from the current mix word; always < pages.
        let page = reduce(fnv(a ^ s0, mix[a as usize % MIX_WORDS]), pages);
        let first_item = page * ITEMS_PER_ACCESS as u32; // first item of the page
        for t in 0..ITEMS_PER_ACCESS {
            let item = fetch(first_item + t as u32); // dataset item (full or computed)
            let words = item_to_words(&item); // item as words
            for k in 0..ITEM_WORDS {
                let idx = t * ITEM_WORDS + k; // position inside the 32-word mix
                mix[idx] = fnv(mix[idx], words[k]); // fold the word in
            }
        }
    }

    // Compress 32 words into 8 words (4 words -> 1 word).
    let mut cmix = [0u32; ITEM_WORDS];
    for j in 0..ITEM_WORDS {
        let b = 4 * j; // first of the four source words
        cmix[j] = fnv(fnv(fnv(mix[b], mix[b + 1]), mix[b + 2]), mix[b + 3]);
    }
    let mix_digest = words_to_item(&cmix); // compressed mix as bytes

    // result = H(tag || seed || mix_digest)
    let mut fin: Vec<u8> = Vec::with_capacity(DOMAIN_TAG.len() + 2 * ITEM_BYTES);
    fin.extend_from_slice(DOMAIN_TAG);
    fin.extend_from_slice(&seed);
    fin.extend_from_slice(&mix_digest);
    Ok(Output {
        mix_digest,
        result: sha3_256(&fin),
    })
}

/// Evaluate Xephash with only the cache (verification, slower per hash).
pub fn hashimoto_light(
    cache: &Cache,
    dataset_items: u32,
    header_hash: &Item,
    nonce: u64,
) -> Result<Output, XephashError> {
    // Items are computed on demand from the cache.
    hashimoto_with(dataset_items, header_hash, nonce, |i| cache.dataset_item(i))
}

/// Evaluate Xephash with the full dataset (mining, fast per hash).
pub fn hashimoto_full(
    dataset: &Dataset,
    header_hash: &Item,
    nonce: u64,
) -> Result<Output, XephashError> {
    // The dataset size must fit in u32 (guaranteed by Dataset::generate).
    let n = u32::try_from(dataset.len())
        .map_err(|_| XephashError::InvalidParams("dataset too large"))?;
    // Items are read straight from memory.
    hashimoto_with(n, header_hash, nonce, |i| {
        dataset
            .items
            .get(i as usize)
            .copied()
            .unwrap_or([0u8; ITEM_BYTES])
    })
}

/// True when `result` is not above `target` (both read as big-endian numbers).
pub fn meets_target(result: &Item, target: &[u8; 32]) -> bool {
    // Lexicographic order of equal-length byte strings equals numeric order.
    result.as_slice() <= target.as_slice()
}

/// Lock a mutex and keep going even if another thread panicked while holding it.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Thread-safe holder of the per-epoch cache and the optional full dataset.
pub struct Engine {
    params: Params,                          // size parameters of this network
    caches: Mutex<Vec<(u64, Arc<Cache>)>>,   // at most two epochs kept (current + neighbour)
    full: Mutex<Option<(u64, Arc<Dataset>)>>, // full dataset of one epoch (miners only)
}

impl Engine {
    /// Create an engine; fails when the parameters are invalid.
    pub fn new(params: Params) -> Result<Engine, XephashError> {
        params.validate()?; // reject unusable parameters early
        Ok(Engine {
            params,
            caches: Mutex::new(Vec::new()),
            full: Mutex::new(None),
        })
    }

    /// The parameters this engine was created with.
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Get (or build) the cache of `epoch`.
    pub fn cache_for_epoch(&self, epoch: u64) -> Result<Arc<Cache>, XephashError> {
        {
            // Fast path: the cache is already built.
            let guard = lock(&self.caches);
            if let Some((_, c)) = guard.iter().find(|(e, _)| *e == epoch) {
                return Ok(Arc::clone(c));
            }
        } // lock released while the (slow) cache is generated
        let seed = epoch_seed(epoch)?; // seed of this epoch
        let cache = Arc::new(Cache::generate(&seed, self.params.cache_items)?);
        let mut guard = lock(&self.caches);
        // Another thread may have inserted the same epoch meanwhile.
        if let Some((_, c)) = guard.iter().find(|(e, _)| *e == epoch) {
            return Ok(Arc::clone(c));
        }
        guard.push((epoch, Arc::clone(&cache))); // remember the new cache
        if guard.len() > 2 {
            guard.remove(0); // drop the oldest entry (keeps memory bounded)
        }
        Ok(cache)
    }

    /// Verify-mode evaluation for the block at `block_number` (light, no dataset).
    pub fn verify(
        &self,
        block_number: u64,
        header_hash: &Item,
        nonce: u64,
    ) -> Result<Output, XephashError> {
        let epoch = self.params.epoch_of(block_number)?; // epoch of the block
        let cache = self.cache_for_epoch(epoch)?; // its cache
        hashimoto_light(&cache, self.params.dataset_items, header_hash, nonce)
    }

    /// Get (or build) the full dataset for the epoch of `block_number`.
    pub fn full_dataset(
        &self,
        block_number: u64,
        threads: usize,
    ) -> Result<Arc<Dataset>, XephashError> {
        let epoch = self.params.epoch_of(block_number)?; // epoch of the block
        // The lock is held while generating so only one thread builds it.
        let mut guard = lock(&self.full);
        if let Some((e, d)) = guard.as_ref() {
            if *e == epoch {
                return Ok(Arc::clone(d)); // already built
            }
        }
        *guard = None; // free the old dataset before allocating the new one
        let cache = self.cache_for_epoch(epoch)?; // cache of the epoch
        let dataset = Arc::new(Dataset::generate(
            &cache,
            self.params.dataset_items,
            threads,
        )?);
        *guard = Some((epoch, Arc::clone(&dataset))); // remember it
        Ok(dataset)
    }
}

#[cfg(test)]
mod tests {
    use super::*; // everything above

    /// Small parameters so the tests run in milliseconds.
    const SMALL: Params = Params {
        cache_items: 64,
        dataset_items: 256,
        epoch_length: 10,
    };

    /// Hex string of 32 bytes.
    fn hx(b: &[u8]) -> String {
        hex::encode(b)
    }

    /// Fixed header hash used by the vectors: SHA3-256("xephash test header").
    fn header() -> Item {
        sha3_256(b"xephash test header")
    }

    /// Hash of all items glued together (compact fingerprint of a whole table).
    fn fingerprint(items: &[Item]) -> String {
        let mut all: Vec<u8> = Vec::new();
        for it in items {
            all.extend_from_slice(it);
        }
        hx(&sha3_256(&all))
    }

    #[test]
    fn epoch_seeds_match_reference() {
        // Epoch 0 is 32 zero bytes, epoch 1 is SHA3-256 of them.
        assert_eq!(hx(&epoch_seed(0).unwrap()), "00".repeat(32));
        assert_eq!(
            hx(&epoch_seed(1).unwrap()),
            "9e6291970cb44dd94008c79bcaf9d86f18b4b49ba5b2a04781db7199ed3b9e4e"
        );
        assert_eq!(epoch_seed(MAX_EPOCH + 1), Err(XephashError::EpochTooLarge));
    }

    #[test]
    fn epoch_zero_vectors() {
        let cache = Cache::generate(&epoch_seed(0).unwrap(), 64).unwrap();
        assert_eq!(
            fingerprint(&cache.items),
            "39800b1b766bdc50dc650526838b42c506a2de3bc2b2058c2625fa1899747377"
        );
        assert_eq!(
            hx(&cache.dataset_item(0)),
            "83364ef4d834afe573ae46935f15df707c55e93079532923d5ffd408eb1037b0"
        );
        assert_eq!(
            hx(&cache.dataset_item(255)),
            "69818ff0b99d5759a1ac9cfa7043cedcb123b16b1ce13c2e4ecab0f65f556567"
        );
        let ds = Dataset::generate(&cache, 256, 1).unwrap();
        assert_eq!(
            fingerprint(&ds.items),
            "fa6cd43f50f909f51c9e63256bfa2b3ce33fcdd0e32b9cf888aadc253714c2e0"
        );
        let out = hashimoto_full(&ds, &header(), 0x0123_4567_89ab_cdef).unwrap();
        assert_eq!(
            hx(&out.mix_digest),
            "bc739f4eb449f0c8f8d168f8cc7f55b1978120dd4e795082b4d16d7bd4b6417d"
        );
        assert_eq!(
            hx(&out.result),
            "670a354f99282c7017db57e6f0fd3f13c311e854ddcd17fbdd212c3206c35d0d"
        );
    }

    #[test]
    fn epoch_one_vectors() {
        let cache = Cache::generate(&epoch_seed(1).unwrap(), 64).unwrap();
        assert_eq!(
            fingerprint(&cache.items),
            "453ddef5d68a9b80111c39b80110d90bb943249b47e4a53bffdf4f99cf716dd9"
        );
        let ds = Dataset::generate(&cache, 256, 1).unwrap();
        assert_eq!(
            fingerprint(&ds.items),
            "3f9c03c9cde8c5544e2fe04a2d1d53e0b8133763588e1785572b527199c0fbc9"
        );
        let out = hashimoto_full(&ds, &header(), 0x0123_4567_89ab_cdef).unwrap();
        assert_eq!(
            hx(&out.result),
            "1bf2f97f3fefd5d12eb9d3be8eb6be0deda6e9980c7ab8186b41cc06daf7b97b"
        );
        // A different nonce gives a different, pinned result.
        let out1 = hashimoto_full(&ds, &header(), 1).unwrap();
        assert_eq!(
            hx(&out1.result),
            "41a38c82cbe94a833d78b92d3dae663938c7452a35a8754f9aefa04cab5d43fe"
        );
    }

    #[test]
    fn light_and_full_agree_for_many_nonces() {
        let cache = Cache::generate(&epoch_seed(3).unwrap(), 64).unwrap();
        let ds = Dataset::generate(&cache, 256, 2).unwrap();
        for nonce in [0u64, 1, 2, 255, 65_536, u64::MAX] {
            let l = hashimoto_light(&cache, 256, &header(), nonce).unwrap();
            let f = hashimoto_full(&ds, &header(), nonce).unwrap();
            assert_eq!(l, f, "light and full must match for nonce {}", nonce);
        }
    }

    #[test]
    fn dataset_is_independent_of_thread_count() {
        let cache = Cache::generate(&epoch_seed(0).unwrap(), 64).unwrap();
        let a = Dataset::generate(&cache, 256, 1).unwrap();
        let b = Dataset::generate(&cache, 256, 3).unwrap(); // uneven chunks
        let c = Dataset::generate(&cache, 256, 64).unwrap(); // more threads than needed
        assert_eq!(a.items, b.items);
        assert_eq!(a.items, c.items);
    }

    #[test]
    fn header_and_nonce_both_change_the_result() {
        let cache = Cache::generate(&epoch_seed(0).unwrap(), 64).unwrap();
        let h1 = header();
        let mut h2 = header();
        h2[0] ^= 1; // flip one bit of the header hash
        let a = hashimoto_light(&cache, 256, &h1, 5).unwrap();
        let b = hashimoto_light(&cache, 256, &h2, 5).unwrap();
        let c = hashimoto_light(&cache, 256, &h1, 6).unwrap();
        assert_ne!(a.result, b.result);
        assert_ne!(a.result, c.result);
    }

    #[test]
    fn engine_uses_the_right_epoch() {
        let engine = Engine::new(SMALL).unwrap();
        let e0 = engine.verify(0, &header(), 0x0123_4567_89ab_cdef).unwrap();
        let e0b = engine.verify(9, &header(), 0x0123_4567_89ab_cdef).unwrap();
        let e1 = engine.verify(10, &header(), 0x0123_4567_89ab_cdef).unwrap();
        // Blocks 0..=9 share epoch 0, block 10 starts epoch 1.
        assert_eq!(
            hx(&e0.result),
            "670a354f99282c7017db57e6f0fd3f13c311e854ddcd17fbdd212c3206c35d0d"
        );
        assert_eq!(e0, e0b);
        assert_eq!(
            hx(&e1.result),
            "1bf2f97f3fefd5d12eb9d3be8eb6be0deda6e9980c7ab8186b41cc06daf7b97b"
        );
    }

    #[test]
    fn engine_full_dataset_matches_light_verification() {
        let engine = Engine::new(SMALL).unwrap();
        let ds = engine.full_dataset(0, 2).unwrap();
        let again = engine.full_dataset(5, 2).unwrap(); // same epoch: same Arc
        assert!(Arc::ptr_eq(&ds, &again));
        let f = hashimoto_full(&ds, &header(), 42).unwrap();
        let l = engine.verify(0, &header(), 42).unwrap();
        assert_eq!(f, l);
    }

    #[test]
    fn engine_keeps_only_two_caches() {
        let engine = Engine::new(SMALL).unwrap();
        for epoch in 0..5u64 {
            engine.cache_for_epoch(epoch).unwrap();
        }
        assert_eq!(engine.caches.lock().unwrap().len(), 2);
    }

    #[test]
    fn invalid_parameters_are_rejected_without_panic() {
        let bad = |p: Params| p.validate().is_err();
        assert!(bad(Params { cache_items: 8, ..SMALL })); // cache too small
        assert!(bad(Params { cache_items: MAX_CACHE_ITEMS + 1, ..SMALL })); // cache too big
        assert!(bad(Params { dataset_items: 250, ..SMALL })); // not a multiple of 4
        assert!(bad(Params { dataset_items: 8, ..SMALL })); // dataset too small
        assert!(bad(Params { dataset_items: MAX_DATASET_ITEMS + 4, ..SMALL })); // too big
        assert!(bad(Params { epoch_length: 0, ..SMALL })); // zero epoch length
        assert!(Engine::new(Params { epoch_length: 0, ..SMALL }).is_err());
        assert!(Params { epoch_length: 0, ..SMALL }.epoch_of(5).is_err());
        assert!(Cache::generate(&[0u8; 32], 4).is_err());
        let cache = Cache::generate(&[0u8; 32], 16).unwrap();
        assert!(Dataset::generate(&cache, 10, 1).is_err());
        assert!(hashimoto_light(&cache, 10, &header(), 0).is_err());
        assert!(SMALL.epoch_of(u64::MAX).is_err()); // epoch above MAX_EPOCH
        // The shipped network parameters are valid.
        assert!(Params::MAIN.validate().is_ok());
        assert!(Params::TEST.validate().is_ok());
        assert!(Params::REGTEST.validate().is_ok());
    }

    #[test]
    fn reduce_stays_in_range() {
        for n in [1u32, 2, 3, 16, 1_000_003, u32::MAX] {
            for x in [0u32, 1, 12_345, u32::MAX / 2, u32::MAX] {
                assert!(reduce(x, n) < n, "reduce({}, {}) must be < n", x, n);
            }
        }
    }

    #[test]
    fn target_comparison_is_big_endian() {
        let mut target = [0u8; 32];
        target[1] = 0x10; // 0x0010 00.. (big-endian)
        let mut low = [0u8; 32];
        low[2] = 0xff; // smaller than target
        let mut high = [0u8; 32];
        high[1] = 0x11; // bigger than target
        assert!(meets_target(&low, &target));
        assert!(meets_target(&target, &target)); // equal is allowed
        assert!(!meets_target(&high, &target));
    }
}
