// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Blockchain state and consensus-related operations.

use std::collections::BTreeMap;

use crate::block::Block;
use crate::consensus::{self, genesis, pow as cpow, rules, spec};
use crate::pow;
use crate::storage::{Account, StateDB};
use crate::transaction::Transaction;
use crate::validation;

pub const LEGACY_PREFIX_MAIN: u8 = 0x4b; // HARD FORK: "X" prefix
pub const LEGACY_PREFIX_TEST: u8 = 0x6f;
pub const LEGACY_PREFIX_REGTEST: u8 = 0x6f;

pub const BECH32_HRP_MAIN: &str = "xepay";
pub const BECH32_HRP_TEST: &str = "xtes";
pub const BECH32_HRP_REGTEST: &str = "xreg";

pub fn legacy_prefix_byte() -> u8 {
    match spec::current_network() {
        spec::Network::Main => LEGACY_PREFIX_MAIN,
        spec::Network::Test => LEGACY_PREFIX_TEST,
        spec::Network::Regtest => LEGACY_PREFIX_REGTEST,
    }
}

pub fn bech32_hrp() -> &'static str {
    match spec::current_network() {
        spec::Network::Main => BECH32_HRP_MAIN,
        spec::Network::Test => BECH32_HRP_TEST,
        spec::Network::Regtest => BECH32_HRP_REGTEST,
    }
}

pub fn legacy_prefix_byte_for(network: spec::Network) -> u8 {
    match network {
        spec::Network::Main => LEGACY_PREFIX_MAIN,
        spec::Network::Test => LEGACY_PREFIX_TEST,
        spec::Network::Regtest => LEGACY_PREFIX_REGTEST,
    }
}

pub fn bech32_hrp_for(network: spec::Network) -> &'static str {
    match network {
        spec::Network::Main => BECH32_HRP_MAIN,
        spec::Network::Test => BECH32_HRP_TEST,
        spec::Network::Regtest => BECH32_HRP_REGTEST,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SoftForkDeployment {
    pub bit: u8,
    pub start_time: i64,
    pub timeout: i64,
    pub min_activation_height: u64,
    pub period: u32,
    pub threshold: u32,
}

pub const NEVER_ACTIVE: i64 = -2;
pub const ALWAYS_ACTIVE: i64 = -1;
pub const NO_TIMEOUT: i64 = i64::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftForkState {
    Defined,
    Started,
    LockedIn,
    Active,
    Failed,
}

pub const SOFT_FORK_DEPLOYMENTS: &[(&str, SoftForkDeployment)] = &[
    (
        "disable_legacy_addresses",
        SoftForkDeployment {
            bit: 0,
            start_time: NEVER_ACTIVE,
            timeout: NO_TIMEOUT,
            min_activation_height: 0,
            period: 2016,
            threshold: 1916,
        },
    ),
];

pub fn get_softfork_deployment(name: &str) -> Option<&'static SoftForkDeployment> {
    SOFT_FORK_DEPLOYMENTS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, d)| d)
}

pub fn median_time_past(chain: &Blockchain) -> i64 {
    let mut timestamps: Vec<i64> = chain
        .chain
        .iter()
        .rev()
        .take(11)
        .map(|b| (b.timestamp / 1000) as i64)
        .collect();
    if timestamps.is_empty() {
        return 0;
    }
    timestamps.sort();
    timestamps[timestamps.len() / 2]
}

pub fn count_signals(chain: &Blockchain, bit: u8, period: u32) -> u32 {
    let start = chain.chain.len().saturating_sub(period as usize);
    let mut count = 0;
    for block in &chain.chain[start..] {
        if (block.nversion & (1u32 << bit)) != 0 {
            count += 1;
        }
    }
    count
}

pub fn get_softfork_state(name: &str, chain: &Blockchain) -> SoftForkState {
    let deployment = match get_softfork_deployment(name) {
        Some(d) => d,
        None => return SoftForkState::Defined,
    };

    let height = chain.height();
    let mtp = median_time_past(chain);

    if deployment.start_time == NEVER_ACTIVE {
        return SoftForkState::Defined;
    }

    if deployment.start_time == ALWAYS_ACTIVE {
        if height >= deployment.min_activation_height {
            return SoftForkState::Active;
        } else {
            return SoftForkState::LockedIn;
        }
    }

    if mtp < deployment.start_time {
        return SoftForkState::Defined;
    }

    if mtp >= deployment.timeout {
        return SoftForkState::Failed;
    }

    let signals = count_signals(chain, deployment.bit, deployment.period);

    if signals >= deployment.threshold {
        if height >= deployment.min_activation_height {
            return SoftForkState::Active;
        } else {
            return SoftForkState::LockedIn;
        }
    }

    SoftForkState::Started
}

pub fn is_softfork_active(name: &str, chain: &Blockchain) -> bool {
    get_softfork_state(name, chain) == SoftForkState::Active
}

pub const MAX_MEMPOOL_SIZE_BYTES: usize = 300 * 1024 * 1024;
pub const MIN_RELAY_FEE_PER_BYTE: u64 = 1;

/// Default wallet fee: 0.01 XEPC (1 XEPC = 100_000_000 ald). It is the
/// floor of the suggested fee; under congestion the suggestion rises above
/// it, like a classic fee market.
pub const DEFAULT_FEE_ALD: u64 = 1_000_000;
/// Typical size of a signed transfer (ML-DSA-65 key + signature + fields).
pub const TYPICAL_TX_SIZE_BYTES: u64 = 5_400;
/// The mempool holds a backlog of up to 20 blocks worth of transactions.
/// Beyond that a new transaction has to outbid the cheapest one.
pub const MEMPOOL_MAX_TXS: usize = rules::MAX_TX_PER_BLOCK * 20;
pub const MEMPOOL_EXPIRY_SECS: u64 = 336 * 3600;
pub const RBF_MIN_FEE_BUMP_PERCENT: u64 = 10;

/// Hard-coded checkpoints (height -> block hash), one list per network.
///
/// What they do:
/// * a block (or header) at a checkpoint height with a different hash is
///   rejected (`rule_block_checkpoint`, header validation);
/// * the chain can never be reorganized below the highest checkpoint that
///   is already part of the active chain (`reorg_allowed`);
/// * peers cannot feed a node a fake long history that conflicts with them.
///
/// How to add one: on a synced node run `xepay getcheckpoint` and paste the
/// printed line into the list of the right network. Use a block that is deep
/// enough (hundreds of blocks) that it can never be reorganized.
pub mod checkpoint {
    use crate::consensus::spec::{self, Network};

    /// One trusted (height, hash) pair.
    pub struct Checkpoint {
        pub height: u64,
        pub hash: &'static str,
    }

    /// Mainnet checkpoints (the genesis block is verified separately).
    pub const MAIN_CHECKPOINTS: &[Checkpoint] = &[];
    /// Testnet checkpoints.
    pub const TEST_CHECKPOINTS: &[Checkpoint] = &[];
    /// Regtest checkpoints (none: regtest chains are disposable).
    pub const REGTEST_CHECKPOINTS: &[Checkpoint] = &[];

    /// Checkpoints of the running network.
    pub fn list() -> &'static [Checkpoint] {
        match spec::current_network() {
            Network::Main => MAIN_CHECKPOINTS,
            Network::Test => TEST_CHECKPOINTS,
            Network::Regtest => REGTEST_CHECKPOINTS,
        }
    }

    /// Hash expected at `height`, if a checkpoint exists there.
    pub fn find(height: u64) -> Option<&'static str> {
        list().iter().find(|c| c.height == height).map(|c| c.hash)
    }

    /// True when a checkpoint exists at `height`.
    pub fn is_checkpoint(height: u64) -> bool {
        list().iter().any(|c| c.height == height)
    }

    /// Height of the highest checkpoint (0 when there is none).
    pub fn highest() -> u64 {
        list().iter().map(|c| c.height).max().unwrap_or(0)
    }

    /// False when a checkpoint at `height` in `list` expects a different hash.
    pub fn verify_in(list: &[Checkpoint], height: u64, hash: &str) -> bool {
        match list.iter().find(|c| c.height == height) {
            Some(c) => c.hash.eq_ignore_ascii_case(hash),
            None => true,
        }
    }

    /// False when a checkpoint of this network expects a different hash.
    pub fn verify(height: u64, hash: &str) -> bool {
        verify_in(list(), height, hash)
    }

    /// Highest checkpoint height in `list` at or below `tip_height`
    /// (0 when none): blocks up to there are final.
    pub fn locked_height_in(list: &[Checkpoint], tip_height: u64) -> u64 {
        list.iter()
            .map(|c| c.height)
            .filter(|h| *h <= tip_height)
            .max()
            .unwrap_or(0)
    }

    /// Same as `locked_height_in` for the checkpoints of this network.
    pub fn locked_height(tip_height: u64) -> u64 {
        locked_height_in(list(), tip_height)
    }

    /// A reorganization that keeps blocks up to `fork_point` (the common
    /// ancestor) is allowed only if it does not replace a checkpointed block.
    pub fn reorg_allowed_in(list: &[Checkpoint], fork_point: u64, tip_height: u64) -> bool {
        fork_point >= locked_height_in(list, tip_height)
    }

    /// Same as `reorg_allowed_in` for the checkpoints of this network.
    pub fn reorg_allowed(fork_point: u64, tip_height: u64) -> bool {
        reorg_allowed_in(list(), fork_point, tip_height)
    }

    /// Hash of the genesis block of the running network (checkpoint 0).
    pub fn genesis_hash() -> &'static str {
        use crate::consensus::genesis;
        match spec::current_network() {
            Network::Main => genesis::EXPECTED_GENESIS_HASH,
            Network::Test => genesis::TESTNET_EXPECTED_GENESIS_HASH,
            Network::Regtest => genesis::REGTEST_EXPECTED_GENESIS_HASH,
        }
    }

    /// Reject a malformed table: heights must start above 0 and strictly
    /// increase, hashes must be 64 lowercase hex characters. A typo in a
    /// checkpoint would otherwise silently lock a node out of the real chain.
    pub fn validate_table(list: &[Checkpoint]) -> Result<(), String> {
        let mut previous: Option<u64> = None;
        for c in list {
            if c.height == 0 {
                return Err("checkpoint height 0 is the genesis block (implicit)".to_string());
            }
            if let Some(p) = previous {
                if c.height <= p {
                    return Err(format!("checkpoint {} is not above the previous one", c.height));
                }
            }
            let ok = c.hash.len() == 64
                && c.hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            if !ok {
                return Err(format!("checkpoint {} has a malformed hash", c.height));
            }
            previous = Some(c.height);
        }
        Ok(())
    }

    /// Check every shipped table. Called at node start.
    pub fn self_check() -> Result<(), String> {
        validate_table(MAIN_CHECKPOINTS)?;
        validate_table(TEST_CHECKPOINTS)?;
        validate_table(REGTEST_CHECKPOINTS)
    }

    /// Verify a loaded chain against the genesis hash and every checkpoint
    /// that is already inside it. A mismatch means the data directory was
    /// tampered with or belongs to a different fork.
    pub fn verify_chain(blocks: &[crate::block::Block]) -> Result<(), String> {
        verify_chain_in(list(), genesis_hash(), blocks)
    }

    /// Same as `verify_chain` with an explicit table and genesis hash. It never
    /// panics: a missing block (the chain is shorter than a checkpoint height)
    /// is not an error, a different hash is reported as `Err`.
    pub fn verify_chain_in(
        list: &[Checkpoint],
        genesis_hash: &str,
        blocks: &[crate::block::Block],
    ) -> Result<(), String> {
        if let Some(g) = blocks.first() {
            if !genesis_hash.eq_ignore_ascii_case(&g.hash) {
                return Err(format!(
                    "genesis block {} does not match the network genesis {}",
                    g.hash, genesis_hash
                ));
            }
        }
        for c in list {
            if let Some(b) = blocks.get(c.height as usize) {
                if b.index != c.height || !c.hash.eq_ignore_ascii_case(&b.hash) {
                    return Err(format!(
                        "block at height {} is {} but the checkpoint requires {}",
                        c.height, b.hash, c.hash
                    ));
                }
            }
        }
        Ok(())
    }
}

pub mod dns_seed {
    use crate::consensus::spec;

    pub const MAINNET_SEEDS: &[&str] = &["seed.xepay.io", "dnsseed.xepay.io"];
    pub const TESTNET_SEEDS: &[&str] = &["testnet-seed.xepay.io"];
    pub const REGTEST_SEEDS: &[&str] = &[];

    pub fn seeds_for_current_network() -> &'static [&'static str] {
        match spec::current_network() {
            spec::Network::Main => MAINNET_SEEDS,
            spec::Network::Test => TESTNET_SEEDS,
            spec::Network::Regtest => REGTEST_SEEDS,
        }
    }
}

pub mod network {
    use crate::consensus::spec;

    pub const PRUNE_AFTER_HEIGHT: u64 = 100_000;
    pub const ASSUMED_BLOCKCHAIN_SIZE: u64 = 496;
    pub const ASSUMED_CHAIN_STATE_SIZE: u64 = 6;

    pub fn network_name() -> &'static str {
        spec::current_network().name()
    }

    pub fn default_port() -> u16 {
        spec::current_network().default_port()
    }

    pub fn network_magic_hex() -> String {
        spec::current_network().magic_hex()
    }
}

pub use consensus::consensus_fingerprint;
pub use consensus::consensus_fingerprint_for;
pub use consensus::genesis_coinbase_txid;
pub use consensus::genesis_coinbase_txid_for;
pub use genesis::genesis_message;
pub use genesis::genesis_output_script;
pub use genesis::genesis_secret;
pub use genesis::genesis_timestamp;
pub use spec::coin_name;
pub use spec::decimals;
pub use spec::difficulty_adjust_interval;
pub use spec::hash_algo;
pub use spec::initial_reward;
pub use spec::initial_reward_xepc;
pub use spec::max_eras;
pub use spec::max_supply;
pub use spec::max_supply_xepc;
pub use spec::miner_confirmation_window;
pub use spec::pow_target_spacing_secs;
pub use spec::pow_target_timespan_secs;
pub use spec::protocol_version;
pub use spec::reward_reduction_denominator;
pub use spec::reward_reduction_numerator;
pub use spec::signature_algo;
pub use spec::subsidy_halving_interval;
pub use spec::symbol;
pub use spec::version;

pub use spec::ald_per_xepc;
pub use spec::UNIT_NAME;
pub use spec::UNIT_SYMBOL;
pub use spec::ALD_PER_XEPC;

pub fn max_tx_per_block() -> usize {
    rules::MAX_TX_PER_BLOCK
}

pub fn pow_limit() -> &'static str {
    cpow::pow_limit()
}

pub fn genesis_nbits() -> u32 {
    spec::current_network().genesis_nbits()
}

#[derive(Debug)]
pub struct Blockchain {
    pub chain: Vec<Block>,
    pub nbits: u32,
    pub mempool: Vec<Transaction>,
    pub balances: std::collections::HashMap<String, u64>,
    pub nonces: std::collections::HashMap<String, u64>,
    pub mempool_timestamps: std::collections::HashMap<String, u64>,
    pub addresses: Vec<String>,
    pub state: StateDB,
}

impl Blockchain {
    pub fn new() -> Self {
        let genesis = Block::genesis();

        let db_path = crate::datadir::state_db_path();
        let mut state = StateDB::open(&db_path).expect("failed to open state db");

        let genesis_acc = state.get_account("GENESIS").unwrap_or(None);
        if genesis_acc.is_none() {
            state
                .update_account(
                    "GENESIS",
                    &Account {
                        nonce: 0,
                        balance: genesis.reward,
                        immature_rewards: BTreeMap::new(),
                        code: Vec::new(),
                        storage: BTreeMap::new(),
                    },
                )
                .expect("failed to init genesis account");
        }

        Blockchain {
            chain: vec![genesis],
            nbits: spec::current_network().genesis_nbits(),
            mempool: Vec::new(),
            balances: std::collections::HashMap::new(),
            nonces: std::collections::HashMap::new(),
            mempool_timestamps: std::collections::HashMap::new(),
            addresses: vec!["GENESIS".to_string()],
            state,
        }
    }

    pub fn height(&self) -> u64 {
        self.chain.last().unwrap().index
    }

    pub fn height_from_state(state: &StateDB) -> u64 {
        match state.get_account("GENESIS") {
            Ok(Some(acc)) => acc.nonce,
            _ => 0,
        }
    }

    pub fn circulating_supply(&self) -> u64 {
        self.chain.iter().fold(0u64, |acc, b| acc.saturating_add(b.reward))
    }

    pub fn calculate_reward(height: u64) -> u64 {
        // Compare in u64 BEFORE narrowing: `as u32` would wrap for huge
        // heights and make a far-future era look like era 0.
        let era_u64 = height / spec::SUBSIDY_HALVING_INTERVAL;
        if era_u64 >= spec::MAX_ERAS as u64 {
            return 0;
        }
        let era = era_u64 as u32;

        let mut reward = spec::INITIAL_REWARD;

        for _ in 0..era {
            reward = match reward.checked_mul(spec::REWARD_REDUCTION_NUMERATOR) {
                Some(v) => v / spec::REWARD_REDUCTION_DENOMINATOR,
                None => return 0,
            };
            if reward == 0 {
                return 0;
            }
        }

        reward
    }

    pub fn current_era(&self) -> u64 {
        self.height() / spec::SUBSIDY_HALVING_INTERVAL
    }

    pub fn blocks_until_halving(&self) -> u64 {
        let next = (self.current_era() + 1)
            .checked_mul(spec::SUBSIDY_HALVING_INTERVAL)
            .unwrap_or(u64::MAX);
        next.saturating_sub(self.height())
    }

    pub fn balance_of(&self, addr: &str) -> u64 {
        self.state.balance_of(addr)
    }

    pub fn mature_balance_at(&self, addr: &str, height: u64) -> u64 {
        self.state.mature_balance_at(addr, height)
    }

    pub fn mature_balance(&self, addr: &str) -> u64 {
        self.state.mature_balance_at(addr, self.height())
    }

    pub fn mature_balance_of(&self, addr: &str) -> u64 {
        self.state.mature_balance_of(addr, self.height())
    }

    pub fn immature_balance_of(&self, addr: &str) -> u64 {
        self.state.immature_balance_of(addr, self.height())
    }

    pub fn nonce_of(&self, addr: &str) -> u64 {
        self.state.nonce_of(addr)
    }

    pub fn next_nonce_for(&self, addr: &str) -> u64 {
        let base = self.state.nonce_of(addr);
        let mut next = base;
        loop {
            let has = self.mempool.iter().any(|tx| tx.from == addr && tx.nonce == next);
            if !has {
                return next;
            }
            match next.checked_add(1) {
                Some(v) => next = v,
                None => return next,
            }
        }
    }

    /// Return true if the given txid is already included in any block of
    /// the active chain. This is used by `add_transaction` to reject a
    /// transaction that was already mined, even when the mempool no
    /// longer contains it.
    pub fn is_txid_in_chain(&self, txid: &str) -> bool {
        for block in &self.chain {
            if block.coinbase_txid == txid {
                return true;
            }
            for tx in &block.transactions {
                if tx.txid == txid {
                    return true;
                }
            }
        }
        false
    }

    pub fn apply_and_execute_transaction(&mut self, tx: &Transaction) -> Result<(), String> {
        if validation::is_special_tx(tx) {
            return Ok(());
        }

        if !self.addresses.contains(&tx.from) {
            self.addresses.push(tx.from.clone());
        }
        if !self.addresses.contains(&tx.to) {
            self.addresses.push(tx.to.clone());
        }

        let current_nonce = self.state.nonce_of(&tx.from);
        if tx.nonce != current_nonce {
            return Err(format!(
                "invalid nonce for {}: got {}, expected {}",
                tx.from, tx.nonce, current_nonce
            ));
        }

        self.state.apply_transaction(
            &tx.from,
            &tx.to,
            tx.amount,
            tx.fee,
            tx.nonce,
            self.height(),
        )?;

        Ok(())
    }

    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), String> {
        if !self.addresses.contains(&tx.from) {
            self.addresses.push(tx.from.clone());
        }
        if !self.addresses.contains(&tx.to) {
            self.addresses.push(tx.to.clone());
        }
        self.state.apply_transaction(
            &tx.from,
            &tx.to,
            tx.amount,
            tx.fee,
            tx.nonce,
            self.height(),
        )
    }

    pub fn credit_reward(&mut self, miner: &str, reward: u64, block_height: u64) -> Result<(), String> {
        if !self.addresses.contains(&miner.to_string()) {
            self.addresses.push(miner.to_string());
        }
        self.state.credit_reward(miner, reward, block_height)
    }

    pub fn total_chainwork(&self) -> u128 {
        self.chain.last().map(|b| b.chainwork).unwrap_or(0)
    }

    pub fn tx_size_bytes(tx: &Transaction) -> usize {
        let base = 32 + tx.from.len() + tx.to.len() + 8 + 8 + 8 + tx.public_key.len() + tx.signature.len();
        base + tx.note.len()
    }

    pub fn mempool_size_bytes(&self) -> usize {
        self.mempool.iter().map(|tx| Self::tx_size_bytes(tx)).sum()
    }

    pub fn fee_rate(tx: &Transaction) -> u64 {
        let size = Self::tx_size_bytes(tx).max(1) as u64;
        tx.fee / size
    }

    pub fn current_min_fee_per_byte(&mut self) -> u64 {
        self.evict_expired_transactions();

        // Fullness is the larger of the byte fill and the count fill.
        let max = MAX_MEMPOOL_SIZE_BYTES;
        let by_count =
            (self.mempool.len() as u128 * max as u128 / MEMPOOL_MAX_TXS as u128) as usize;
        let size = self.mempool_size_bytes().max(by_count);

        if size < max / 2 {
            MIN_RELAY_FEE_PER_BYTE
        } else if size < (max * 3) / 4 {
            MIN_RELAY_FEE_PER_BYTE * 2
        } else if size < (max * 9) / 10 {
            MIN_RELAY_FEE_PER_BYTE * 5
        } else {
            MIN_RELAY_FEE_PER_BYTE * 10
        }
    }

    /// Fee rate (ald per byte) a new transaction must pay to be mined in
    /// the NEXT block. While the mempool holds less than one block of
    /// transactions this is 0 (the default fee suffices). Once there is a
    /// backlog it is the rate of the marginal transaction that just fits
    /// in a block, plus a 10% margin to outbid it. This is what makes
    /// fees rise when the mempool fills up.
    pub fn next_block_fee_rate(&self) -> u64 {
        let cap = rules::max_tx_per_block_at(self.height().saturating_add(1));
        if self.mempool.len() < cap {
            return 0;
        }
        let mut rates: Vec<u64> = self.mempool.iter().map(Self::fee_rate).collect();
        rates.sort_unstable_by(|a, b| b.cmp(a));
        let marginal = rates[cap - 1];
        marginal.saturating_add((marginal / 10).max(1))
    }

    /// Suggested fee (ald) for a transaction of `size_bytes`: never below
    /// the 0.01 XEPC default, higher when the mempool is congested.
    pub fn suggested_fee(&self, size_bytes: u64) -> u64 {
        self.next_block_fee_rate()
            .saturating_mul(size_bytes)
            .max(DEFAULT_FEE_ALD)
    }

    /// Make room for `tx` in a full mempool as a fee market normally does: evict
    /// the cheapest transaction, but only if the newcomer pays clearly
    /// more (at least the RBF bump). Only the LAST transaction of a
    /// sender is evictable (evicting an earlier nonce would invalidate the
    /// ones after it), and never one of the newcomer's own sender.
    fn make_room_for(&mut self, tx: &Transaction, tx_size: usize) -> bool {
        let new_rate = Self::fee_rate(tx);
        let mut guard = self.mempool.len() + 1;
        while (self.mempool.len() >= MEMPOOL_MAX_TXS
            || self.mempool_size_bytes() + tx_size > MAX_MEMPOOL_SIZE_BYTES)
            && guard > 0
        {
            guard -= 1;
            let victim = {
                let mut tail: std::collections::HashMap<&str, usize> =
                    std::collections::HashMap::new();
                for (i, t) in self.mempool.iter().enumerate() {
                    if t.from == tx.from {
                        continue;
                    }
                    match tail.get(t.from.as_str()) {
                        Some(&j) if self.mempool[j].nonce >= t.nonce => {}
                        _ => {
                            tail.insert(t.from.as_str(), i);
                        }
                    }
                }
                tail.values()
                    .map(|&i| (i, Self::fee_rate(&self.mempool[i])))
                    .min_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
            };
            let (idx, rate) = match victim {
                Some(v) => v,
                None => return false,
            };
            let bump = (rate.saturating_mul(RBF_MIN_FEE_BUMP_PERCENT) / 100).max(1);
            if new_rate < rate.saturating_add(bump) {
                return false;
            }
            let removed = self.mempool.remove(idx);
            self.mempool_timestamps.remove(&removed.txid);
            println!(
                "[mempool] Evicted tx {} (fee rate {}) for a higher-paying tx ({})",
                removed.txid, rate, new_rate
            );
        }
        self.mempool.len() < MEMPOOL_MAX_TXS
            && self.mempool_size_bytes() + tx_size <= MAX_MEMPOOL_SIZE_BYTES
    }

    pub fn evict_lowest_fee_transactions(&mut self, needed_space: usize) {
        self.mempool.sort_by(|a, b| {
            let fee_a = Self::fee_rate(a).saturating_mul(Self::tx_size_bytes(a) as u64);
            let fee_b = Self::fee_rate(b).saturating_mul(Self::tx_size_bytes(b) as u64);
            fee_a.cmp(&fee_b)
        });

        let mut freed = 0;
        let mut to_remove = Vec::new();

        for (i, tx) in self.mempool.iter().enumerate() {
            if freed >= needed_space {
                break;
            }
            freed += Self::tx_size_bytes(tx);
            to_remove.push(i);
        }

        for i in to_remove.into_iter().rev() {
            let removed = self.mempool.remove(i);
            self.mempool_timestamps.remove(&removed.txid);
            println!(
                "[mempool] Evicted tx {} (fee rate {}) to make room",
                removed.txid,
                Self::fee_rate(&removed)
            );
        }
    }

    pub fn evict_expired_transactions(&mut self) {
        let now = (crate::utils::now_millis() / 1000) as u64;
        let mut to_remove = Vec::new();

        for tx in &self.mempool {
            if let Some(&ts) = self.mempool_timestamps.get(&tx.txid) {
                if now.saturating_sub(ts) > MEMPOOL_EXPIRY_SECS {
                    to_remove.push(tx.txid.clone());
                }
            }
        }

        for txid in to_remove {
            self.mempool.retain(|tx| tx.txid != txid);
            self.mempool_timestamps.remove(&txid);
            println!("[mempool] Evicted expired tx {}", txid);
        }
    }

    /// Put back a mempool entry that was taken out for a replace-by-fee
    /// attempt which then failed. (SECURITY FIX: see `add_transaction`.)
    fn restore_replaced(&mut self, replaced: Option<(usize, Transaction, Option<u64>)>) {
        if let Some((pos, old_tx, old_ts)) = replaced {
            let old_txid = old_tx.txid.clone(); // keep the id for the timestamp map
            let at = pos.min(self.mempool.len()); // never insert past the end
            self.mempool.insert(at, old_tx); // restore the original position
            if let Some(ts) = old_ts {
                self.mempool_timestamps.insert(old_txid, ts); // restore its arrival time
            }
        }
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> bool {
        self.evict_expired_transactions();

        // SECURITY FIX: coinbase / genesis transactions must never enter the
        // mempool (validate_transaction treats them as valid special cases).
        if validation::is_special_tx(&tx) {
            return false;
        }

        // SECURITY FIX (cheap early reject): a nonce below the account nonce
        // was already used, so the transaction is stale or a replay. This
        // avoids the expensive full-chain scan below for such spam.
        if tx.nonce < self.nonce_of(&tx.from) {
            return false;
        }

        // A transaction that was already mined has a used nonce, so the check
        // above rejects it. The former full-chain scan (`is_txid_in_chain`,
        // O(chain length) per transaction) was a CPU DoS and is not needed.

        if self.mempool.iter().any(|t| t.txid == tx.txid) {
            return false;
        }

        let rbf_pos = self.mempool.iter().position(|t| t.from == tx.from && t.nonce == tx.nonce);

        // Holds the entry removed for replacement so it can be restored if the
        // new transaction turns out to be invalid.
        let mut replaced: Option<(usize, Transaction, Option<u64>)> = None;

        if let Some(pos) = rbf_pos {
            let old_tx = &self.mempool[pos];
            let old_fee_rate = Self::fee_rate(old_tx);
            let new_fee_rate = Self::fee_rate(&tx);

            let min_bump = old_fee_rate
                .checked_mul(RBF_MIN_FEE_BUMP_PERCENT)
                .unwrap_or(u64::MAX) / 100;
            let min_new_fee_rate = old_fee_rate.saturating_add(min_bump.max(1));

            if new_fee_rate >= min_new_fee_rate {
                println!(
                    "[mempool] RBF: Replacing tx {} (fee rate {}) with {} (fee rate {})",
                    old_tx.txid, old_fee_rate, tx.txid, new_fee_rate
                );
                // SECURITY FIX: the old transaction used to be deleted here,
                // BEFORE the replacement was validated. Anyone could evict a
                // victim's pending transaction by sending an unsigned
                // look-alike with a higher fee. Now it is only taken out
                // temporarily and restored when validation fails.
                let old_txid = old_tx.txid.clone(); // id of the entry being replaced
                let old_ts = self.mempool_timestamps.remove(&old_txid); // remember arrival time
                let removed = self.mempool.remove(pos); // take the old entry out for now
                replaced = Some((pos, removed, old_ts)); // keep it for a possible restore
            } else {
                println!(
                    "[mempool] Rejected RBF attempt: new fee rate {} < required {}",
                    new_fee_rate, min_new_fee_rate
                );
                return false;
            }
        }

        match validation::validate_transaction(self, &tx) {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "[mempool] Rejected tx {}: [{}] {}",
                    tx.txid, e.code, e.message
                );
                self.restore_replaced(replaced); // the replacement is invalid: keep the original
                return false;
            }
        }

        let tx_size = Self::tx_size_bytes(&tx);
        let fee_rate = Self::fee_rate(&tx);

        let current_min_fee = self.current_min_fee_per_byte();
        if fee_rate < current_min_fee {
            println!(
                "[mempool] Rejected tx {}: fee rate {} < dynamic minRelayTxFee {} (mempool size: {} bytes)",
                tx.txid, fee_rate, current_min_fee, self.mempool_size_bytes()
            );
            self.restore_replaced(replaced); // keep the original entry
            return false;
        }

        if self.mempool.len() >= MEMPOOL_MAX_TXS
            || self.mempool_size_bytes() + tx_size > MAX_MEMPOOL_SIZE_BYTES
        {
            if !self.make_room_for(&tx, tx_size) {
                println!(
                    "[mempool] Rejected tx {}: mempool full and fee rate {} is too low",
                    tx.txid, fee_rate
                );
                self.restore_replaced(replaced); // keep the original entry
                return false;
            }
        }

        let now = (crate::utils::now_millis() / 1000) as u64;
        self.mempool_timestamps.insert(tx.txid.clone(), now);
        self.mempool.push(tx);
        true
    }

    /// Build the next block from the mempool. Every transaction is
    /// validated against an overlay that starts from the live state and
    /// is updated as each transaction is applied. This makes the
    /// selection robust to a mempool that contains a transaction whose
    /// txid is already in the chain, or whose nonce has already been
    /// consumed by a previous block. Such a transaction is skipped
    /// instead of aborting the whole mining attempt.
    fn note_address(&mut self, a: &str) {
        if !self.addresses.iter().any(|x| x == a) {
            self.addresses.push(a.to_string());
        }
    }

    /// Apply a block to the open state batch and return the resulting
    /// state root. Uses `block.index` as the maturity height everywhere,
    /// the same value the validation rules and the reindex path use.
    fn stage_block(&mut self, block: &Block) -> Result<String, String> {
        for tx in &block.transactions {
            if validation::is_special_tx(tx) {
                return Err(format!(
                    "special transaction {} in block {}",
                    tx.txid, block.index
                ));
            }
            self.note_address(&tx.from);
            self.note_address(&tx.to);
            self.state
                .apply_transaction(&tx.from, &tx.to, tx.amount, tx.fee, tx.nonce, block.index)
                .map_err(|e| {
                    format!("failed to apply tx {} in block {}: {}", tx.txid, block.index, e)
                })?;
            // First spend reveals the public key: remember it so that later
            // transactions of this sender can leave the key out.
            if rules::pubkey_registry_active(block.index) && !tx.public_key.is_empty() {
                self.state.register_pubkey(&tx.from, &tx.public_key)?;
            }
        }
        self.note_address(&block.mined_for);
        self.state
            .credit_reward(&block.mined_for, block.reward, block.index)
            .map_err(|e| format!("failed to credit reward for block {}: {}", block.index, e))?;
        self.state.pending_root()
    }

    /// Atomically connect a validated block to the state.
    ///
    /// Everything happens in an in-memory batch. The computed state root
    /// is compared with the one in the header (from the activation
    /// height). Only if all checks pass is the batch written to disk in
    /// one synced write together with the undo data. On any error the
    /// state on disk and in memory is untouched, so a bad block or a
    /// crash can never leave a half-applied state.
    pub fn connect_block(&mut self, block: &Block) -> Result<(), String> {
        self.state.abort_block();
        self.state.begin_block()?;
        let root = match self.stage_block(block) {
            Ok(r) => r,
            Err(e) => {
                self.state.abort_block();
                return Err(e);
            }
        };
        // Conservation of money: the block may create exactly its subsidy.
        // This catches any arithmetic bug before it can reach the disk.
        let expected = Self::calculate_reward(block.index) as i128;
        match self.state.pending_supply_delta() {
            Ok(d) if d == expected => {}
            Ok(d) => {
                self.state.abort_block();
                return Err(format!(
                    "bad-supply: block {} changes total money by {} (allowed {})",
                    block.index, d, expected
                ));
            }
            Err(e) => {
                self.state.abort_block();
                return Err(e);
            }
        }
        if crate::consensus::rules::state_root_active(block.index) && root != block.state_root {
            self.state.abort_block();
            return Err(format!(
                "bad-state-root: block {} declares {} but the computed root is {}",
                block.index, block.state_root, root
            ));
        }
        self.state.commit_block(block.index, &block.hash, &root)
    }

    /// Select valid transactions from `candidates`, simulate the block on
    /// a throw-away batch and return (txs, total_fees, state_root).
    /// The live state is never modified.
    pub fn build_block_candidate(
        &mut self,
        candidates: Vec<Transaction>,
        miner: &str,
        next_index: u64,
        subsidy: u64,
    ) -> Result<(Vec<Transaction>, u64, String), String> {
        self.state.abort_block();
        self.state.begin_block()?;
        let r = self.build_candidate_inner(candidates, miner, next_index, subsidy);
        self.state.abort_block();
        r
    }

    fn build_candidate_inner(
        &mut self,
        mut candidates: Vec<Transaction>,
        miner: &str,
        next_index: u64,
        subsidy: u64,
    ) -> Result<(Vec<Transaction>, u64, String), String> {
        // Highest fee rate first (as miners normally do). A sender's
        // transactions must stay in nonce order, so each sender has a
        // queue and only its next transaction competes in the heap.
        use std::cmp::Reverse;
        use std::collections::{BinaryHeap, VecDeque};
        candidates.sort_by(|a, b| a.from.cmp(&b.from).then_with(|| a.nonce.cmp(&b.nonce)));
        let mut queues: BTreeMap<String, VecDeque<Transaction>> = BTreeMap::new();
        for tx in candidates {
            queues.entry(tx.from.clone()).or_default().push_back(tx);
        }
        let mut heap: BinaryHeap<(u64, Reverse<String>)> = BinaryHeap::new();
        for (sender, q) in queues.iter() {
            if let Some(t) = q.front() {
                heap.push((Self::fee_rate(t), Reverse(sender.clone())));
            }
        }

        let mut valid: Vec<Transaction> = Vec::new();
        let mut fees: u64 = 0;
        let block_cap = crate::consensus::rules::max_tx_per_block_at(next_index);
        while valid.len() < block_cap {
            let sender = match heap.pop() {
                Some((_, Reverse(s))) => s,
                None => break,
            };
            let tx = match queues.get_mut(&sender).and_then(|q| q.pop_front()) {
                Some(t) => t,
                None => continue,
            };

            let accepted = !(validation::is_special_tx(&tx) || self.is_txid_in_chain(&tx.txid))
                && validation::validate_tx_for_block(self, &tx, next_index).is_ok()
                && match fees.checked_add(tx.fee) {
                    Some(nf) => {
                        if self
                            .state
                            .apply_transaction(
                                &tx.from, &tx.to, tx.amount, tx.fee, tx.nonce, next_index,
                            )
                            .is_ok()
                        {
                            fees = nf;
                            if rules::pubkey_registry_active(next_index)
                                && !tx.public_key.is_empty()
                            {
                                let _ = self.state.register_pubkey(&tx.from, &tx.public_key);
                            }
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                };

            if accepted {
                valid.push(tx);
                if let Some(next) = queues.get(&sender).and_then(|q| q.front()) {
                    heap.push((Self::fee_rate(next), Reverse(sender)));
                }
            } else {
                // Later nonces of this sender cannot be valid either.
                queues.remove(&sender);
            }
        }
        let reward = subsidy
            .checked_add(fees)
            .ok_or_else(|| "block reward overflow".to_string())?;
        self.state.credit_reward(miner, reward, next_index)?;
        let root = self.state.pending_root()?;
        Ok((valid, fees, root))
    }

    pub fn mine_pending(&mut self) -> Result<u64, String> {
        let prev = self.chain.last().unwrap().clone();
        let next_index = prev.index + 1;
        let subsidy = Self::calculate_reward(next_index);
        let miner = prev.mined_for.clone();

        let txs = self.mempool.clone();
        let (valid_txs, total_fees, root) =
            self.build_block_candidate(txs, &miner, next_index, subsidy)?;

        let reward = subsidy
            .checked_add(total_fees)
            .ok_or_else(|| "block reward overflow".to_string())?;
        let new_supply = self
            .circulating_supply()
            .checked_add(reward)
            .ok_or_else(|| "circulating supply overflow".to_string())?;
        if new_supply > spec::MAX_SUPPLY {
            return Err("max supply reached".into());
        }

        let mut new_block = Block::new_for(
            next_index,
            prev.hash.clone(),
            subsidy,
            total_fees,
            self.nbits,
            valid_txs,
            miner,
            prev.chainwork,
        )?
        .with_state_root(root);

        if !pow::mine(&mut new_block, self.nbits) {
            return Err("mining failed: nonce exhausted".into());
        }

        self.connect_block(&new_block)?;
        let nonce = new_block.nonce;
        self.mempool.clear();
        self.mempool_timestamps.clear();
        self.chain.push(new_block);
        self.adjust_difficulty();
        Ok(nonce)
    }

    /// Difficulty after the retarget at `height`: measures the time the last
    /// `interval` blocks took (median-time-past at both ends, so single
    /// timestamps cannot skew it) and applies `compute_retarget`.
    fn retarget_window(&self, height: u64, interval: u64, timespan: u64, current: u32) -> u32 {
        let h = height as usize; // index of the last block of the window
        let n = interval as usize; // window length in blocks
        if h < n || h >= self.chain.len() {
            return current; // not enough history loaded
        }
        let last_mtp = self.median_time_past_at(h); // time at the end of the window
        let first_mtp = self.median_time_past_at(h - n); // time at its start
        let actual = last_mtp.saturating_sub(first_mtp) as u64;
        compute_retarget(current, actual, timespan)
    }

    /// Recompute `self.nbits` purely from the chain (idempotent): correct
    /// after every block, after a restart and after a reorg.
    ///
    /// * Before the Xephash activation: legacy schedule (long interval).
    /// * From the activation: the difficulty restarts at
    ///   `rules::xephash_start_nbits()` and is retargeted every 15 hours
    ///   (`RETARGET_INTERVAL_BLOCKS_V2` blocks, counted from the activation).
    pub fn adjust_difficulty(&mut self) {
        let net = spec::current_network();
        let genesis_nbits = net.genesis_nbits();
        if net == spec::Network::Regtest {
            self.nbits = genesis_nbits; // regtest never retargets
            return;
        }
        let tip = self.height();
        let activation = rules::xephash_activation_height();
        let mut nbits;
        if tip.saturating_add(1) < activation {
            // Legacy schedule.
            nbits = genesis_nbits;
            let interval = spec::DIFFICULTY_ADJUST_INTERVAL;
            let mut h = interval;
            while h <= tip {
                nbits = self.retarget_window(h, interval, spec::POW_TARGET_TIMESPAN_SECS, nbits);
                h = match h.checked_add(interval) {
                    Some(v) => v,
                    None => break,
                };
            }
        } else {
            // Xephash schedule: restart, then one retarget every 15 hours.
            nbits = rules::xephash_start_nbits();
            let interval = spec::RETARGET_INTERVAL_BLOCKS_V2;
            let mut h = activation.saturating_add(interval);
            while h <= tip {
                nbits = self.retarget_window(h, interval, spec::RETARGET_TIMESPAN_SECS_V2, nbits);
                h = match h.checked_add(interval) {
                    Some(v) => v,
                    None => break,
                };
            }
        }
        self.nbits = nbits;
    }

    fn median_time_past_at(&self, height: usize) -> i64 {
        let start = height.saturating_sub(10);
        let mut timestamps: Vec<i64> = self.chain[start..=height]
            .iter()
            .map(|b| (b.timestamp / 1000) as i64)
            .collect();

        if timestamps.is_empty() {
            return 0;
        }

        timestamps.sort();
        timestamps[timestamps.len() / 2]
    }

    pub fn is_valid(&mut self) -> bool {
        validation::validate_chain(self).is_ok()
    }
}

impl Default for Blockchain {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute `target * scale_256 / 256`, saturating at 2^256 - 1.
/// (`scale_256` is a fixed-point ratio: 256 means "unchanged".)
pub(crate) fn scale_target(target: &[u8; 32], scale_256: u128) -> [u8; 32] {
    let mut prod = [0u8; 32]; // low 256 bits of target * scale_256
    let mut carry: u128 = 0; // bits above 2^256
    for i in (0..32).rev() {
        // One byte at a time, least significant byte first (big-endian array).
        let v = (target[i] as u128)
            .saturating_mul(scale_256)
            .saturating_add(carry);
        prod[i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    // Dividing by 256 drops the lowest byte and moves the carry into the top byte.
    if carry >> 8 != 0 {
        return [0xff; 32]; // does not fit in 256 bits after the shift
    }
    let mut out = [0u8; 32];
    out[0] = carry as u8; // bits 248..255 of the result
    out[1..].copy_from_slice(&prod[..31]); // the remaining 31 bytes
    out
}

/// The proof-of-work limit (easiest allowed target) as 32 bytes.
pub(crate) fn pow_limit_bytes() -> [u8; 32] { // pub(crate): also used by header validation
    let mut out = [0xffu8; 32]; // fallback: no limit
    if let Ok(b) = hex::decode(cpow::pow_limit()) {
        if b.len() == 32 {
            out.copy_from_slice(&b);
        }
    }
    out
}

/// Pure retarget rule: the new compact difficulty after a window that took
/// `actual_secs` while `expected_secs` were intended. The change is clamped
/// to 0.25x .. 4x per window and never easier than the proof-of-work limit.
pub fn compute_retarget(current_nbits: u32, actual_secs: u64, expected_secs: u64) -> u32 {
    if actual_secs == 0 || expected_secs == 0 {
        return current_nbits; // no usable measurement: keep the difficulty
    }
    // Fixed point ratio (256 = on schedule), clamped to 64..=1024 (0.25x..4x).
    let ratio = (actual_secs as u128).saturating_mul(256) / expected_secs as u128;
    let ratio = ratio.clamp(64, 1024);
    let current_target = pow::nbits_to_target(current_nbits); // target of the old nbits
    let mut new_target = scale_target(&current_target, ratio); // slow blocks => bigger target
    let limit = pow_limit_bytes();
    if new_target.as_slice() > limit.as_slice() {
        new_target = limit; // never easier than the limit
    }
    target_to_nbits(&new_target)
}

fn target_to_nbits(target: &[u8; 32]) -> u32 {
    let mut i = 0;
    while i < 32 && target[i] == 0 {
        i += 1;
    }
    if i == 32 {
        return spec::current_network().genesis_nbits();
    }

    let size = 32 - i;
    let mut mantissa: u32 = (target[i] as u32) << 16;
    if i + 1 < 32 {
        mantissa |= (target[i + 1] as u32) << 8;
    }
    if i + 2 < 32 {
        mantissa |= target[i + 2] as u32;
    }

    // The compact format reserves bit 23 of the mantissa as a sign bit. When
    // the leading mantissa bit is set, shift the mantissa right by one byte
    // and grow the size so that the value is never read as negative.
    let mut size = size as u32;
    if mantissa & 0x00800000 != 0 {
        mantissa >>= 8;
        size += 1;
    }

    (size << 24) | (mantissa & 0x007fffff)
}
