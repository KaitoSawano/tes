// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Consensus validation rule constants for XEPAY.

// The number of blocks a coinbase reward must mature before it can be spent.
pub const COINBASE_MATURITY: u64 = 100;

// The maximum number of transactions allowed in a single block.
pub const MAX_TX_PER_BLOCK: usize = 1_000;

// The maximum number of inputs per transaction (unused in the account-based model).
pub const MAX_INPUTS_PER_TX: usize = 1_000;

// The maximum number of outputs per transaction (unused in the account-based model).
pub const MAX_OUTPUTS_PER_TX: usize = 1_000;

// The maximum length of a transaction note, in bytes.
// Increased from 256 to 4096 to accommodate smart contract call data.
pub const MAX_NOTE_LEN: usize = 4096;

// The zero hash used as the `previous_hash` of the genesis block.
pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// The block version supported by the current consensus rules.
pub const BLOCK_VERSION: u32 = 1;

// ----------------------------------------------------------------------
// Messaging constants
// ----------------------------------------------------------------------

/// Prefix that marks a transaction note as an on-chain message.
pub const MESSAGE_PREFIX: &str = "[MSG]";

/// Maximum length of the actual message body (after prefix), in bytes.
pub const MAX_MESSAGE_LEN: usize = 512;

/// Minimum self-send amount required for a message transaction.
/// This amount is returned to the sender, but forces the sender to
/// pay a real fee for the on-chain space.
pub const MIN_MESSAGE_AMOUNT: u64 = 1;

// Helper function to return the BASE maximum number of transactions per block.
// Height-aware code must use `max_tx_per_block_at`.
pub fn max_tx_per_block() -> usize {
    MAX_TX_PER_BLOCK // Return the constant value.
}

// ----------------------------------------------------------------------
// Rule schedule: how rule parameters change WITHOUT touching the genesis block
// ----------------------------------------------------------------------
//
// The constants above are the BASE rules: they apply from block 1 and must
// never be edited after launch. A change of a rule parameter is made by adding
// a `RuleEra` to the schedule of the network. The era is valid from its
// `activation_height` on, so older blocks keep being validated with the rules
// they were created under, and the genesis block is never involved.
//
// Process: announce the change, publish a release that contains the new era
// with an activation height far enough in the future, wait until the network
// has upgraded, then the height is reached. Nodes that did not upgrade reject
// the first block that follows the new rules and stay on the old rules (they
// can only follow the majority again after installing the new release).

/// Rule parameters that can change over time (always through an era).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleSet {
    /// Maximum number of transactions in a block.
    pub max_tx_per_block: usize,
    /// Blocks a coinbase reward must mature before it can be spent.
    pub coinbase_maturity: u64,
    /// Maximum length of a transaction note in bytes.
    pub max_note_len: usize,
    /// Version of newly created blocks.
    pub block_version: u32,
}

/// The base rules, valid from block 1 until the first era.
pub const BASE_RULES: RuleSet = RuleSet {
    max_tx_per_block: MAX_TX_PER_BLOCK,
    coinbase_maturity: COINBASE_MATURITY,
    max_note_len: MAX_NOTE_LEN,
    block_version: BLOCK_VERSION,
};

/// A rule change that takes effect at `activation_height`.
#[derive(Clone, Copy, Debug)]
pub struct RuleEra {
    /// First block that must follow `rules` (never 0: block 0 is the genesis).
    pub activation_height: u64,
    /// The complete rule set from that height on.
    pub rules: RuleSet,
}

/// Mainnet schedule (empty: the base rules apply).
pub const MAIN_RULE_SCHEDULE: &[RuleEra] = &[];
/// Testnet schedule.
pub const TEST_RULE_SCHEDULE: &[RuleEra] = &[];
/// Regtest schedule.
pub const REGTEST_RULE_SCHEDULE: &[RuleEra] = &[];

/// Schedule of the running network.
pub fn rule_schedule() -> &'static [RuleEra] {
    use crate::consensus::spec::{self, Network};
    match spec::current_network() {
        Network::Main => MAIN_RULE_SCHEDULE,
        Network::Test => TEST_RULE_SCHEDULE,
        Network::Regtest => REGTEST_RULE_SCHEDULE,
    }
}

/// Rule set that applies at `height` according to `schedule`.
pub fn rules_in(schedule: &[RuleEra], height: u64) -> RuleSet {
    let mut current = BASE_RULES; // before the first era
    for era in schedule {
        if era.activation_height <= height {
            current = era.rules; // the last era that has activated wins
        } else {
            break; // the schedule is sorted, later eras are not active yet
        }
    }
    current
}

/// Rule set that applies at `height` on the running network.
pub fn rules_at(height: u64) -> RuleSet {
    rules_in(rule_schedule(), height)
}

/// The newest rules (what a new transaction or block must follow now).
pub fn rules_latest() -> RuleSet {
    rules_at(u64::MAX)
}

/// Maximum transactions per block at `height`.
pub fn max_tx_per_block_at(height: u64) -> usize {
    rules_at(height).max_tx_per_block
}

/// Coinbase maturity at `height`.
pub fn coinbase_maturity_at(height: u64) -> u64 {
    rules_at(height).coinbase_maturity
}

/// Maximum note length at `height`.
pub fn max_note_len_at(height: u64) -> usize {
    rules_at(height).max_note_len
}

/// Maximum note length of the newest rules.
pub fn max_note_len_latest() -> usize {
    rules_latest().max_note_len
}

/// Version a block at `height` must carry. The genesis block has its own frozen
/// version (`genesis::GENESIS_BLOCK_VERSION`).
pub fn block_version_at(height: u64) -> u32 {
    if height == 0 {
        crate::consensus::genesis::GENESIS_BLOCK_VERSION
    } else {
        rules_at(height).block_version
    }
}

/// Check a schedule: activation heights above 0 and strictly increasing,
/// every rule value usable.
pub fn validate_schedule_in(schedule: &[RuleEra]) -> Result<(), String> {
    let mut previous: Option<u64> = None;
    for era in schedule {
        if era.activation_height == 0 {
            return Err("a rule era cannot activate at height 0 (the genesis block)".to_string());
        }
        if let Some(p) = previous {
            if era.activation_height <= p {
                return Err(format!(
                    "rule era at {} is not above the previous era at {}",
                    era.activation_height, p
                ));
            }
        }
        let r = era.rules;
        if r.max_tx_per_block == 0 || r.max_note_len == 0 || r.block_version == 0 {
            return Err(format!("rule era at {} has an unusable value", era.activation_height));
        }
        previous = Some(era.activation_height);
    }
    Ok(())
}

/// Check the schedules of all networks (called at node start).
pub fn validate_schedule() -> Result<(), String> {
    validate_schedule_in(MAIN_RULE_SCHEDULE)?;
    validate_schedule_in(TEST_RULE_SCHEDULE)?;
    validate_schedule_in(REGTEST_RULE_SCHEDULE)
}

/// Text form of the base rules and the schedule of `network` (informational
/// fingerprint only; it never enters the genesis block).
pub fn schedule_fingerprint_for(network: crate::consensus::spec::Network) -> String {
    use crate::consensus::spec::Network;
    let schedule = match network {
        Network::Main => MAIN_RULE_SCHEDULE,
        Network::Test => TEST_RULE_SCHEDULE,
        Network::Regtest => REGTEST_RULE_SCHEDULE,
    };
    let mut parts: Vec<String> = vec![format!(
        "base:{}:{}:{}:{}",
        BASE_RULES.max_tx_per_block,
        BASE_RULES.coinbase_maturity,
        BASE_RULES.max_note_len,
        BASE_RULES.block_version
    )];
    for era in schedule {
        parts.push(format!(
            "{}:{}:{}:{}:{}",
            era.activation_height,
            era.rules.max_tx_per_block,
            era.rules.coinbase_maturity,
            era.rules.max_note_len,
            era.rules.block_version
        ));
    }
    parts.join(",")
}

// ----------------------------------------------------------------------
// State root (Merkle-trie) activation
// ----------------------------------------------------------------------

/// Height from which block headers commit to the post-block state root.
/// Blocks below this height keep the legacy hash layout, so the existing
/// chain and the genesis hashes stay valid.
///
/// [IMPORTANT] The mainnet value MUST be set above the current tip plus a
/// safety margin before release, and every node must upgrade before it.
pub const STATE_ROOT_ACTIVATION_MAIN: u64 = 50_000;
pub const STATE_ROOT_ACTIVATION_TEST: u64 = 1;
pub const STATE_ROOT_ACTIVATION_REGTEST: u64 = 1;

pub fn state_root_activation_height() -> u64 {
    use crate::consensus::spec::{self, Network};
    // Never 0: an activation must not change how the genesis block is hashed.
    match spec::current_network() {
        Network::Main => STATE_ROOT_ACTIVATION_MAIN,
        Network::Test => STATE_ROOT_ACTIVATION_TEST,
        Network::Regtest => STATE_ROOT_ACTIVATION_REGTEST,
    }
    .max(1)
}

/// True when a block at `height` must carry a valid `state_root`.
pub fn state_root_active(height: u64) -> bool {
    height >= state_root_activation_height()
}

/// True when transactions may omit their public key if the sender's key
/// is already registered on chain (saves ~1.9 KB per transaction).
/// Uses the same activation height as the state root: one hard fork.
pub fn pubkey_registry_active(height: u64) -> bool {
    state_root_active(height)
}

// ----------------------------------------------------------------------
// Xephash (memory-hard proof of work) activation
// ----------------------------------------------------------------------

/// First height whose proof of work is Xephash instead of the plain header
/// hash. [IMPORTANT] Set the mainnet value above the current tip plus a
/// safety margin before release; every node must upgrade before it.
pub const XEPHASH_ACTIVATION_MAIN: u64 = 60_000;
pub const XEPHASH_ACTIVATION_TEST: u64 = 100;
pub const XEPHASH_ACTIVATION_REGTEST: u64 = 100;

/// Activation height of the current network. It is never below the state
/// root activation, because the seal hash needs the header-only layout.
pub fn xephash_activation_height() -> u64 {
    use crate::consensus::spec::{self, Network};
    let own = match spec::current_network() {
        Network::Main => XEPHASH_ACTIVATION_MAIN,
        Network::Test => XEPHASH_ACTIVATION_TEST,
        Network::Regtest => XEPHASH_ACTIVATION_REGTEST,
    };
    own.max(state_root_activation_height()).max(1)
}

/// True when a block at `height` must satisfy Xephash.
pub fn xephash_active(height: u64) -> bool {
    height >= xephash_activation_height()
}

/// Difficulty of the first Xephash block. The memory-hard function has a
/// different hash rate than the old hash, so the difficulty restarts here
/// (then retargets normally). [TUNE] before release for the expected hashrate.
pub fn xephash_start_nbits() -> u32 {
    crate::consensus::spec::current_network().genesis_nbits()
}

/// True when the difficulty is recomputed right AFTER the block at `height`
/// is connected (so block `height + 1` may carry a new `nbits`).
/// Before the Xephash activation the legacy schedule applies; from it, the
/// difficulty restarts and is retargeted every `RETARGET_INTERVAL_BLOCKS_V2`.
pub fn retarget_after(height: u64) -> bool {
    use crate::consensus::spec::{self, Network};
    if spec::current_network() == Network::Regtest || height == 0 {
        return false; // regtest never retargets
    }
    let activation = xephash_activation_height();
    if height >= activation {
        height > activation && (height - activation) % spec::RETARGET_INTERVAL_BLOCKS_V2 == 0
    } else {
        height % spec::DIFFICULTY_ADJUST_INTERVAL == 0
    }
}

/// True when block `height + 1` may legitimately have a different `nbits`
/// than block `height` (a retarget, or the Xephash difficulty restart).
pub fn nbits_may_change_after(height: u64) -> bool {
    use crate::consensus::spec::{self, Network};
    retarget_after(height)
        || (spec::current_network() != Network::Regtest
            && height.saturating_add(1) == xephash_activation_height())
}

/// Number of blocks for which undo data is kept in the state database.
pub const UNDO_RETENTION: u64 = 1_000;
