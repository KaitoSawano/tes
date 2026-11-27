// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Block structure and related operations.

use crate::blockchain::Blockchain;
use crate::consensus::spec::{self, Network};
use crate::consensus::{genesis, rules};
use crate::datadir;
use crate::pow;
use crate::transaction::Transaction;
use crate::utils::{format_datetime, now_millis};
use serde::{Deserialize, Serialize};
use xepay_crypto::sha3_256_hex;

pub const BLOCK_VERSION: u32 = rules::BLOCK_VERSION;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub nversion: u32,
    pub index: u64,
    pub timestamp: u128,
    pub mined_at: String,
    pub mined_for: String,
    pub previous_hash: String,
    pub merkle_root: String,
    pub hash: String,
    pub nonce: u64,
    pub nbits: u32,
    pub reward: u64,
    pub subsidy: u64,
    pub total_fees: u64,
    pub coinbase_txid: String,
    pub blockchain_size: u64,
    pub genesis_output_script: String,
    pub miner_pubkey: String,
    pub miner_signature: String,
    #[serde(with = "crate::utils::u128_string")]
    pub chainwork: u128,
    pub transactions: Vec<Transaction>,
    /// Merkle-trie state root after applying this block (hex). Empty
    /// for blocks below `rules::state_root_activation_height()`.
    #[serde(default)]
    pub state_root: String,
}

/// Block layout written before `state_root` existed (bincode is not
/// self-describing, so old block files need their own decoder).
#[derive(Deserialize)]
struct BlockV0 {
    nversion: u32,
    index: u64,
    timestamp: u128,
    mined_at: String,
    mined_for: String,
    previous_hash: String,
    merkle_root: String,
    hash: String,
    nonce: u64,
    nbits: u32,
    reward: u64,
    subsidy: u64,
    total_fees: u64,
    coinbase_txid: String,
    blockchain_size: u64,
    genesis_output_script: String,
    miner_pubkey: String,
    miner_signature: String,
    #[serde(with = "crate::utils::u128_string")]
    chainwork: u128,
    transactions: Vec<Transaction>,
}

impl Block {
    /// Decode a bincode block, accepting the pre-state-root layout.
    pub fn from_bincode(data: &[u8]) -> Result<Block, String> {
        if let Ok(b) = bincode::deserialize::<Block>(data) {
            return Ok(b);
        }
        let o: BlockV0 = bincode::deserialize(data).map_err(|e| e.to_string())?;
        Ok(Block {
            nversion: o.nversion,
            index: o.index,
            timestamp: o.timestamp,
            mined_at: o.mined_at,
            mined_for: o.mined_for,
            previous_hash: o.previous_hash,
            merkle_root: o.merkle_root,
            hash: o.hash,
            nonce: o.nonce,
            nbits: o.nbits,
            reward: o.reward,
            subsidy: o.subsidy,
            total_fees: o.total_fees,
            coinbase_txid: o.coinbase_txid,
            blockchain_size: o.blockchain_size,
            genesis_output_script: o.genesis_output_script,
            miner_pubkey: o.miner_pubkey,
            miner_signature: o.miner_signature,
            chainwork: o.chainwork,
            transactions: o.transactions,
            state_root: String::new(),
        })
    }

    /// Set the state root and refresh the hash.
    pub fn with_state_root(mut self, root: String) -> Self {
        if !rules::state_root_active(self.index) {
            return self;
        }
        self.state_root = root;
        self.hash = self.calculate_hash();
        self
    }

    /// Hash of the header WITHOUT the nonce: the input of Xephash.
    /// Only meaningful from the Xephash activation height (header-only layout).
    pub fn seal_hash(&self) -> [u8; 32] {
        let mut h = self.header_only(); // header without transactions
        h.nonce = 0; // the nonce is what the miner varies, so it is excluded
        let digest_hex = h.calculate_hash(); // header hash with nonce = 0 (hex)
        let mut raw = [0u8; 32]; // decoded digest
        if let Ok(bytes) = hex::decode(&digest_hex) {
            if bytes.len() == 32 {
                raw.copy_from_slice(&bytes); // exactly 32 bytes: copy
            }
        }
        // Domain separation: a seal hash can never equal a block hash.
        let mut input: Vec<u8> = Vec::with_capacity(8 + 32);
        input.extend_from_slice(b"XEPSEAL1");
        input.extend_from_slice(&raw);
        xepay_crypto::sha3_256(&input)
    }

    /// Header-only copy (no transactions). From the activation height the
    /// hash does not depend on the transactions, so it can be verified.
    pub fn header_only(&self) -> Block {
        let mut h = self.clone();
        h.transactions.clear();
        h
    }

    /// True when `hash` can be recomputed from the header alone.
    pub fn hash_is_header_only(&self) -> bool {
        rules::state_root_active(self.index)
    }

    pub fn compute_merkle_root(transactions: &[Transaction]) -> String {
        if transactions.is_empty() {
            return sha3_256_hex(b"empty");
        }

        // FIX BUG AG: Use explicit loop and propagate error for invalid txids
        // instead of silently skipping them, which causes a DoS via merkle mismatch.
        let mut layer: Vec<[u8; 32]> = Vec::with_capacity(transactions.len());
        for tx in transactions {
            let bytes = match hex::decode(&tx.txid) {
                Ok(b) if b.len() == 32 => b,
                _ => return sha3_256_hex(b"invalid_txid"),
            };
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            layer.push(arr);
        }

        while layer.len() > 1 {
            if layer.len() % 2 == 1 {
                let last = *layer.last().unwrap();
                layer.push(last);
            }

            let mut next: Vec<[u8; 32]> = Vec::with_capacity(layer.len() / 2);
            for pair in layer.chunks(2) {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0]);
                buf[32..].copy_from_slice(&pair[1]);
                let hash = sha3_256_hex(&buf);
                let bytes = hex::decode(&hash).unwrap();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                next.push(arr);
            }
            layer = next;
        }

        hex::encode(layer[0])
    }

    /// Work of one block: floor(2^256 / (target + 1)), saturated to u128.
    ///
    /// SECURITY FIX: the old code returned 1 for every target above 2^128, so
    /// on mainnet each block counted as the same work and the "heaviest"
    /// chain was simply the longest one. A cheap long chain could beat the
    /// real chain. The work is now computed on the full 256-bit target.
    pub fn compute_work(nbits: u32) -> u128 {
        let target = pow::nbits_to_target(nbits); // 256-bit big-endian target

        // A zero target is not a valid difficulty: report maximum work.
        if target.iter().all(|&b| b == 0) {
            return u128::MAX;
        }

        // Load the target into four 64-bit limbs (limb 0 is the most significant).
        let mut t = [0u64; 4];
        for i in 0..4 {
            let mut limb = [0u8; 8]; // eight bytes of the target
            limb.copy_from_slice(&target[i * 8..i * 8 + 8]);
            t[i] = u64::from_be_bytes(limb);
        }

        // Target = 2^256 - 1 means work 1 (and target + 1 would overflow).
        if t == [u64::MAX; 4] {
            return 1;
        }

        // divisor = target + 1 (cannot overflow, checked above).
        let mut d = t;
        for i in (0..4).rev() {
            let (v, carry) = d[i].overflowing_add(1); // add one with carry
            d[i] = v;
            if !carry {
                break; // no further carry: done
            }
        }

        // numerator = 2^256 - 1 - target = bitwise NOT of the target.
        let n = [!t[0], !t[1], !t[2], !t[3]];

        // Bitwise long division of n by d: q = n / d. work = q + 1, because
        // 2^256 / (target + 1) == (2^256 - 1 - target) / (target + 1) + 1.
        let mut q = [0u64; 4]; // quotient
        let mut rem = [0u64; 4]; // remainder (a 257th bit is tracked by `top`)
        for bit in 0..256usize {
            let top = rem[0] >> 63; // bit that falls out when shifting left
            for i in 0..3 {
                rem[i] = (rem[i] << 1) | (rem[i + 1] >> 63); // shift remainder left by one
            }
            rem[3] = (rem[3] << 1) | ((n[bit / 64] >> (63 - (bit % 64))) & 1); // bring in next numerator bit
            // Compare rem >= d (a set `top` bit means rem is certainly larger).
            let ge = top == 1 || {
                let mut ord = std::cmp::Ordering::Equal; // limb-wise comparison
                for i in 0..4 {
                    if rem[i] != d[i] {
                        ord = rem[i].cmp(&d[i]);
                        break;
                    }
                }
                ord != std::cmp::Ordering::Less
            };
            if ge {
                // rem -= d (wrapping subtraction is correct even with the 257th bit)
                let mut borrow = false;
                for i in (0..4).rev() {
                    let (v1, b1) = rem[i].overflowing_sub(d[i]);
                    let (v2, b2) = v1.overflowing_sub(borrow as u64);
                    rem[i] = v2;
                    borrow = b1 || b2;
                }
                q[bit / 64] |= 1u64 << (63 - (bit % 64)); // set this quotient bit
            }
        }

        // Saturate: if the quotient does not fit in 128 bits, return u128::MAX.
        if q[0] != 0 || q[1] != 0 {
            return u128::MAX;
        }
        let low = ((q[2] as u128) << 64) | (q[3] as u128); // low 128 bits of the quotient
        low.saturating_add(1) // work = quotient + 1
    }

    /// Build a block with zero subsidy, zero fees, and no reward. This
    /// wrapper returns a `Result` instead of panicking so that callers
    /// that receive untrusted data (for example, a peer message) can
    /// handle the error without crashing the node.
    pub fn new(
        index: u64,
        previous_hash: String,
        reward: u64,
        nbits: u32,
        transactions: Vec<Transaction>,
    ) -> Result<Self, String> {
        Self::new_for(
            index,
            previous_hash,
            reward,
            0,
            nbits,
            transactions,
            String::new(),
            0,
        )
    }

    pub fn new_for(
        index: u64,
        previous_hash: String,
        subsidy: u64,
        total_fees: u64,
        nbits: u32,
        transactions: Vec<Transaction>,
        mined_for: String,
        previous_chainwork: u128,
    ) -> Result<Self, String> {
        let ts = now_millis();
        let coinbase_txid = sha3_256_hex(format!("{}|{}|{}", index, mined_for, ts).as_bytes());
        let merkle_root = Self::compute_merkle_root(&transactions);

        let reward = subsidy
            .checked_add(total_fees)
            .ok_or_else(|| "block reward overflow".to_string())?;

        let size = (previous_hash.len()
            + merkle_root.len()
            + coinbase_txid.len()
            + transactions.iter().map(|t| t.txid.len()).sum::<usize>()
            + 256) as u64;

        let block_work = Self::compute_work(nbits);

        let chainwork = previous_chainwork
            .checked_add(block_work)
            .unwrap_or(u128::MAX);

        let mut b = Block {
            nversion: rules::block_version_at(index),
            index,
            timestamp: ts,
            mined_at: format_datetime(ts),
            mined_for,
            previous_hash,
            merkle_root,
            hash: String::new(),
            nonce: 0,
            nbits,
            reward,
            subsidy,
            total_fees,
            coinbase_txid,
            blockchain_size: size,
            genesis_output_script: String::new(),
            miner_pubkey: String::new(),
            miner_signature: String::new(),
            chainwork,
            transactions,
            state_root: String::new(),
        };
        b.hash = b.calculate_hash();
        Ok(b)
    }

    pub fn genesis_unchecked() -> Self {
        Self::genesis_mined_for(spec::current_network()).expect("genesis mining failed")
    }

    pub fn genesis_unchecked_for(network: Network) -> Self {
        Self::genesis_mined_for(network).expect("genesis mining failed")
    }

    // GENESIS-BEGIN
    // Everything between GENESIS-BEGIN and GENESIS-END may only use the
    // genesis parameters of `consensus::genesis`. It must never read a rule
    // parameter (`rules::...`): rule changes are scheduled by activation
    // height and must not be able to change the genesis block.

    /// The genesis block of `network` without nonce and hash (all fields are
    /// derived from the immutable genesis parameters only).
    pub fn genesis_unmined_for(network: Network) -> Self {
        Self::genesis_from_params(&genesis::GenesisParams::for_network(network))
    }

    /// Build an unmined genesis block from explicit genesis parameters.
    /// Used by `genesis_unmined_for` and by the tests that prove which
    /// parameters change the genesis hash.
    pub fn genesis_from_params(params: &genesis::GenesisParams) -> Self {
        // The genesis commitment replaces the former coinbase txid seed: it is
        // derived from genesis parameters only.
        let coinbase_txid = params.commitment();
        // The two genesis transactions carry the genesis message and secret.
        let transactions = vec![
            Transaction::coinbase(params.message.clone()),
            Transaction::secret(params.secret.clone()),
        ];
        let merkle_root = Self::compute_merkle_root(&transactions);
        // Serialized size estimate of the header strings plus a fixed padding.
        let size = (params.output_script.len()
            + merkle_root.len()
            + coinbase_txid.len()
            + transactions.iter().map(|t| t.txid.len()).sum::<usize>()) as u64
            + genesis::GENESIS_SIZE_PADDING;
        Block {
            nversion: genesis::GENESIS_BLOCK_VERSION,
            index: 0,
            timestamp: params.timestamp,
            mined_at: params.mined_at.clone(),
            mined_for: genesis::GENESIS_MINED_FOR.to_string(),
            previous_hash: genesis::GENESIS_PREVIOUS_HASH.to_string(),
            merkle_root,
            hash: String::new(),
            nonce: 0,
            nbits: params.nbits,
            reward: params.initial_reward,
            subsidy: params.initial_reward,
            total_fees: 0,
            coinbase_txid,
            blockchain_size: size,
            genesis_output_script: params.output_script.clone(),
            miner_pubkey: String::new(),
            miner_signature: String::new(),
            chainwork: params.chainwork,
            transactions,
            state_root: String::new(),
        }
    }

    fn genesis_mined_for(network: Network) -> Result<Self, String> {
        let mut b = Self::genesis_unmined_for(network);
        let nbits = b.nbits;
        if !pow::mine(&mut b, nbits) {
            return Err("genesis mining failed: nonce exhausted".to_string());
        }

        Ok(b)
    }

    pub fn genesis() -> Self {
        Self::genesis_for(spec::current_network())
    }

    #[cfg(feature = "skip-pow")]
    fn is_test_mode() -> bool {
        true
    }

    pub fn genesis_for(network: Network) -> Self {
        #[cfg(feature = "skip-pow")]
        {
            if Self::is_test_mode() {
                return Self::genesis_precomputed_for(network);
            }
        }

        let b = Self::genesis_mined_for(network).unwrap_or_else(|e| {
            eprintln!("FATAL: genesis mining failed: {}", e);
            std::process::exit(1);
        });

        let hash_ok = b.hash == genesis::expected_genesis_hash_for(network);
        let merkle_ok = b.merkle_root == genesis::expected_genesis_merkle_root_for(network);
        let ts_ok = b.timestamp == genesis::expected_genesis_timestamp_for(network);
        let nonce_ok = b.nonce == genesis::expected_genesis_nonce_for(network);

        if hash_ok && merkle_ok && ts_ok && nonce_ok {
            return b;
        }

        eprintln!();
        eprintln!("genesis mismatch for network '{}'", network.name());
        eprintln!();
        eprintln!("pub const EXPECTED_GENESIS_HASH: &str =");
        eprintln!("    \"{}\";", b.hash);
        eprintln!();
        eprintln!("pub const EXPECTED_GENESIS_MERKLE_ROOT: &str =");
        eprintln!("    \"{}\";", b.merkle_root);
        eprintln!();
        eprintln!(
            "pub const EXPECTED_GENESIS_TIMESTAMP: u128 = {};",
            b.timestamp
        );
        eprintln!();
        eprintln!("pub const EXPECTED_GENESIS_NONCE: u64 = {};", b.nonce);
        eprintln!();

        std::process::exit(1);
    }

    #[cfg(feature = "skip-pow")]
    fn genesis_precomputed_for(network: Network) -> Self {
        let mut b = Self::genesis_unmined_for(network);
        b.nonce = genesis::expected_genesis_nonce_for(network);
        b.hash = genesis::expected_genesis_hash_for(network).to_string();
        b
    }
    // GENESIS-END

    pub fn calculate_hash(&self) -> String {
        let mut payload = Vec::new();

        // Header fields
        payload.extend_from_slice(&self.nversion.to_be_bytes());
        payload.extend_from_slice(&self.index.to_be_bytes());
        payload.extend_from_slice(&self.timestamp.to_be_bytes());
        payload.extend_from_slice(self.mined_at.as_bytes());
        payload.push(0);
        payload.extend_from_slice(self.mined_for.as_bytes());
        payload.push(0);
        payload.extend_from_slice(self.previous_hash.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&self.merkle_root.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&self.nonce.to_be_bytes());
        payload.extend_from_slice(&self.nbits.to_be_bytes());
        payload.extend_from_slice(&self.reward.to_be_bytes());
        payload.extend_from_slice(&self.subsidy.to_be_bytes());
        payload.extend_from_slice(&self.total_fees.to_be_bytes());
        payload.extend_from_slice(self.coinbase_txid.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&self.blockchain_size.to_be_bytes());
        payload.extend_from_slice(self.genesis_output_script.as_bytes());
        payload.push(0);
        payload.extend_from_slice(self.miner_pubkey.as_bytes());
        payload.push(0);
        payload.extend_from_slice(self.miner_signature.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&self.chainwork.to_be_bytes());

        if rules::state_root_active(self.index) {
            // The header commits to the transactions through merkle_root
            // (txid covers the full tx incl. signature) and to the state
            // through state_root, so headers verify without bodies.
            payload.extend_from_slice(self.state_root.as_bytes());
            payload.push(0);
            return sha3_256_hex(&payload);
        }

        // Legacy layout: Transactions
        payload.extend_from_slice(&(self.transactions.len() as u64).to_be_bytes());
        for tx in &self.transactions {
            payload.extend_from_slice(tx.from.as_bytes());
            payload.push(0);
            payload.extend_from_slice(tx.to.as_bytes());
            payload.push(0);
            payload.extend_from_slice(&tx.amount.to_be_bytes());
            payload.extend_from_slice(&tx.fee.to_be_bytes());
            payload.extend_from_slice(&tx.nonce.to_be_bytes());
            payload.extend_from_slice(tx.note.as_bytes());
            payload.push(0);
            payload.extend_from_slice(tx.output_script.as_bytes());
            payload.push(0);
            payload.extend_from_slice(&tx.public_key);
            payload.extend_from_slice(&tx.signature);
        }

        sha3_256_hex(&payload)
    }

    pub fn reward_at(height: u64) -> u64 {
        Blockchain::calculate_reward(height)
    }

    pub fn log_add_to_wallet(&self) {
        let entry = format!(
            "AddToWallet\n  mined_at : {}\n  txid     : {}\n  hash     : {}",
            self.mined_at, self.coinbase_txid, self.hash
        );

        println!("{}", entry);
        datadir::append_debug_log(&entry);
    }
}
