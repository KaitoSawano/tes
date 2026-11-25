// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Hexary Merkle Patricia Trie used for the state root.
//!
//! Design: keys are hashed (secure trie), paths are nibbles,
//! nodes are leaf / extension / branch with hex-prefix encoding and RLP.
//! Differences from other tries: SHA3-256 is the hash, nodes are always
//! referenced by hash (no inlining of small nodes), and the leaf value
//! is SHA3-256(RLP(account)).
//!
//! The root is canonical: it depends only on the set of (key, value)
//! pairs, never on insertion order. Subtree hashes are cached per nibble
//! prefix and only the prefixes of a changed key are invalidated, so an
//! update costs O(depth * 16) instead of O(accounts).

use std::collections::{BTreeMap, HashMap}; // ordered map for leaves, hash map for the cache

use rlp::RlpStream; // RLP encoder used to serialize trie nodes
use xepay_crypto::sha3_256; // the hash function of the whole project

pub type Hash32 = [u8; 32]; // a 256-bit hash value

/// Root of an empty trie: the hash of the RLP encoding of empty data.
pub fn empty_root() -> Hash32 {
    sha3_256(&[0x80]) // 0x80 is the RLP encoding of an empty byte string
}

/// Return the i-th nibble (4 bits) of a 32-byte key.
fn nibble(key: &Hash32, i: usize) -> u8 {
    if i % 2 == 0 {
        key[i / 2] >> 4 // even index: high nibble of the byte
    } else {
        key[i / 2] & 0x0f // odd index: low nibble of the byte
    }
}

/// Expand a 32-byte key into its 64 nibbles.
fn key_nibbles(key: &Hash32) -> Vec<u8> {
    (0..64).map(|i| nibble(key, i)).collect() // one entry per nibble
}

/// Hex-prefix encoding: packs nibbles into bytes and marks leaf/odd length.
fn hex_prefix(nibbles: &[u8], leaf: bool) -> Vec<u8> {
    let flag: u8 = if leaf { 2 } else { 0 }; // bit 1 of the flag marks a leaf node
    let mut out = Vec::with_capacity(nibbles.len() / 2 + 1); // output buffer
    let mut i = 0; // read position inside `nibbles`
    if nibbles.len() % 2 == 1 {
        out.push(((flag | 1) << 4) | nibbles[0]); // odd length: flag nibble + first nibble
        i = 1; // first nibble is already consumed
    } else {
        out.push(flag << 4); // even length: flag nibble + zero padding nibble
    }
    while i + 1 < nibbles.len() {
        out.push((nibbles[i] << 4) | nibbles[i + 1]); // pack two nibbles per byte
        i += 2; // advance by one byte worth of nibbles
    }
    out // the encoded path
}

/// Smallest and largest 32-byte key that start with the nibble `prefix`.
fn bounds(prefix: &[u8]) -> (Hash32, Hash32) {
    let mut lo = [0u8; 32]; // lower bound: prefix followed by zeros
    let mut hi = [0u8; 32]; // upper bound: prefix followed by 0xf nibbles
    for i in 0..64 {
        let (l, h) = if i < prefix.len() {
            (prefix[i], prefix[i]) // inside the prefix both bounds agree
        } else {
            (0u8, 15u8) // after the prefix: lowest and highest nibble
        };
        if i % 2 == 0 {
            lo[i / 2] |= l << 4; // write the high nibble of the byte
            hi[i / 2] |= h << 4; // write the high nibble of the byte
        } else {
            lo[i / 2] |= l; // write the low nibble of the byte
            hi[i / 2] |= h; // write the low nibble of the byte
        }
    }
    (lo, hi) // inclusive range of keys below this prefix
}

/// Hash of a leaf node: [hex-prefix(rest of path), value].
fn leaf_hash(rest: &[u8], value: &Hash32) -> Hash32 {
    let mut s = RlpStream::new_list(2); // a leaf is a list of two items
    s.append(&hex_prefix(rest, true)); // item 1: remaining path, leaf flag set
    s.append(&value.to_vec()); // item 2: the value hash
    sha3_256(&s.out()) // node hash = hash of its RLP encoding
}

/// Hash of an extension node: [hex-prefix(shared path), child hash].
fn ext_hash(path: &[u8], child: &Hash32) -> Hash32 {
    let mut s = RlpStream::new_list(2); // an extension is a list of two items
    s.append(&hex_prefix(path, false)); // item 1: shared path, leaf flag clear
    s.append(&child.to_vec()); // item 2: hash of the child node
    sha3_256(&s.out()) // node hash = hash of its RLP encoding
}

/// Hash of a branch node: 16 child slots plus an (always empty) value slot.
fn branch_hash(items: &[Option<Hash32>; 16]) -> Hash32 {
    let mut s = RlpStream::new_list(17); // 16 children + 1 value slot
    for it in items.iter() {
        match it {
            Some(h) => {
                s.append(&h.to_vec()); // existing child: its hash
            }
            None => {
                s.append_empty_data(); // missing child: empty string
            }
        }
    }
    s.append_empty_data(); // the value slot is never used (keys have fixed length)
    sha3_256(&s.out()) // node hash = hash of its RLP encoding
}

/// The state trie: all leaves in memory plus a cache of subtree hashes.
#[derive(Default)]
pub struct StateTrie {
    leaves: BTreeMap<Hash32, Hash32>, // hashed key -> hashed value, sorted by key
    cache: HashMap<Vec<u8>, Hash32>,  // nibble prefix -> hash of the subtree below it
}

impl StateTrie {
    /// Create an empty trie.
    pub fn new() -> Self {
        Self::default() // empty leaves, empty cache
    }

    /// Number of leaves stored.
    pub fn len(&self) -> usize {
        self.leaves.len() // count of (key, value) pairs
    }

    /// Drop every cached subtree hash on the path of `key`.
    fn invalidate(&mut self, key: &Hash32) {
        let nibs = key_nibbles(key); // the full path of the key
        for len in 0..=64 {
            self.cache.remove(&nibs[..len]); // every prefix of the path is now stale
        }
    }

    /// Insert or replace a leaf. Returns the previous value.
    pub fn set(&mut self, key: Hash32, value: Hash32) -> Option<Hash32> {
        self.invalidate(&key); // cached hashes on this path are no longer valid
        self.leaves.insert(key, value) // store the leaf, return the old value
    }

    /// Remove a leaf. Returns the previous value.
    pub fn remove(&mut self, key: &Hash32) -> Option<Hash32> {
        self.invalidate(key); // cached hashes on this path are no longer valid
        self.leaves.remove(key) // delete the leaf, return the old value
    }

    /// Remove everything.
    pub fn clear(&mut self) {
        self.leaves.clear(); // forget all leaves
        self.cache.clear(); // forget all cached hashes
    }

    /// Compute the root hash of the whole trie.
    pub fn root(&mut self) -> Hash32 {
        match self.node(&[]) {
            Some(h) => h,           // non-empty trie: hash of the top node
            None => empty_root(),   // no leaves: the constant empty root
        }
    }

    /// Hash of the subtree that contains all leaves below `prefix`.
    fn node(&mut self, prefix: &[u8]) -> Option<Hash32> {
        if let Some(h) = self.cache.get(prefix) {
            return Some(*h); // unchanged subtree: reuse the cached hash
        }
        let (lo, hi) = bounds(prefix); // key range covered by this prefix
        let (first, second) = {
            let mut it = self.leaves.range(lo..=hi); // iterate leaves in the range
            let f = match it.next() {
                Some((k, v)) => (*k, *v), // first leaf in the range
                None => return None,      // empty subtree has no hash
            };
            let s = it.next().map(|(k, _)| *k); // second leaf, if any
            (f, s) // only "none / one / many" matters, not the full list
        };

        let h = if second.is_none() {
            // Exactly one leaf below this prefix: it becomes a leaf node.
            let rest: Vec<u8> = (prefix.len()..64).map(|i| nibble(&first.0, i)).collect(); // path after the prefix
            leaf_hash(&rest, &first.1) // hash of the leaf node
        } else {
            // Several leaves: find the longest path they all share.
            let last = *self
                .leaves
                .range(lo..=hi)
                .next_back() // largest key in the range
                .map(|(k, _)| k)
                .unwrap_or(&first.0);
            let mut e = prefix.len(); // end of the shared path (exclusive)
            while e < 64 && nibble(&first.0, e) == nibble(&last, e) {
                e += 1; // smallest and largest key agree here, so all keys do
            }
            let mut branch_prefix: Vec<u8> = prefix.to_vec(); // prefix of the branch node
            for i in prefix.len()..e {
                branch_prefix.push(nibble(&first.0, i)); // append the shared nibbles
            }
            let mut items: [Option<Hash32>; 16] = [None; 16]; // one slot per child nibble
            for n in 0..16u8 {
                let mut p = branch_prefix.clone(); // child prefix = branch prefix + nibble
                p.push(n);
                items[n as usize] = self.node(&p); // hash of that child subtree
            }
            let bh = branch_hash(&items); // hash of the branch node
            if e > prefix.len() {
                ext_hash(&branch_prefix[prefix.len()..], &bh) // shared path: wrap in an extension node
            } else {
                bh // no shared path: the branch node itself
            }
        };
        self.cache.insert(prefix.to_vec(), h); // remember the result for next time
        Some(h) // hash of this subtree
    }
}

#[cfg(test)]
mod tests {
    use super::*; // bring the trie into scope

    fn k(i: u64) -> Hash32 {
        sha3_256(&i.to_be_bytes()) // deterministic test key
    }
    fn v(i: u64) -> Hash32 {
        sha3_256(&(i ^ 0xdead_beef).to_be_bytes()) // deterministic test value
    }

    #[test]
    fn empty_is_constant() {
        let mut t = StateTrie::new(); // trie without leaves
        assert_eq!(t.root(), empty_root()); // must equal the empty root
    }

    #[test]
    fn order_independent() {
        let mut a = StateTrie::new(); // filled in ascending order
        let mut b = StateTrie::new(); // filled in descending order
        for i in 0..200 {
            a.set(k(i), v(i)); // ascending inserts
        }
        for i in (0..200).rev() {
            b.set(k(i), v(i)); // descending inserts
        }
        assert_eq!(a.root(), b.root()); // same set => same root
    }

    #[test]
    fn value_change_changes_root_and_revert_restores() {
        let mut t = StateTrie::new(); // base trie
        for i in 0..50 {
            t.set(k(i), v(i)); // fill with 50 leaves
        }
        let r0 = t.root(); // root before the change
        let old = t.set(k(7), v(999)); // change one value
        assert_ne!(t.root(), r0); // the root must change
        t.set(k(7), old.unwrap()); // restore the old value
        assert_eq!(t.root(), r0); // the root must be back
    }

    #[test]
    fn remove_new_key_restores() {
        let mut t = StateTrie::new(); // base trie
        for i in 0..30 {
            t.set(k(i), v(i)); // fill with 30 leaves
        }
        let r0 = t.root(); // root before adding a key
        t.set(k(1000), v(1000)); // add a new key
        assert_ne!(t.root(), r0); // the root must change
        t.remove(&k(1000)); // remove it again
        assert_eq!(t.root(), r0); // the root must be back
    }

    #[test]
    fn incremental_matches_fresh_build() {
        let mut inc = StateTrie::new(); // trie updated step by step (uses the cache)
        let mut seed: u64 = 12345; // simple deterministic random generator
        for _ in 0..500 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); // next random value
            let id = (seed >> 33) % 80; // pick one of 80 keys
            if (seed >> 20) % 5 == 0 {
                inc.remove(&k(id)); // sometimes delete
            } else {
                inc.set(k(id), v(seed >> 40)); // otherwise insert or update
            }
            let r = inc.root(); // root with warm cache
            let mut fresh = StateTrie::new(); // trie built from scratch
            for (kk, vv) in inc.leaves.clone() {
                fresh.set(kk, vv); // copy the same leaves
            }
            assert_eq!(r, fresh.root()); // cache must not change the result
        }
    }

    #[test]
    fn hex_prefix_vectors() {
        assert_eq!(hex_prefix(&[1, 2, 3, 4], false), vec![0x00, 0x12, 0x34]); // even extension
        assert_eq!(hex_prefix(&[1, 2, 3], false), vec![0x11, 0x23]); // odd extension
        assert_eq!(hex_prefix(&[1, 2, 3, 4], true), vec![0x20, 0x12, 0x34]); // even leaf
        assert_eq!(hex_prefix(&[1, 2, 3], true), vec![0x31, 0x23]); // odd leaf
    }
}
