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

// Helper function to return the maximum number of transactions per block.
pub fn max_tx_per_block() -> usize {
    MAX_TX_PER_BLOCK // Return the constant value.
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
    match spec::current_network() {
        Network::Main => STATE_ROOT_ACTIVATION_MAIN,
        Network::Test => STATE_ROOT_ACTIVATION_TEST,
        Network::Regtest => STATE_ROOT_ACTIVATION_REGTEST,
    }
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
    own.max(state_root_activation_height())
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
