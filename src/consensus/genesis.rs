// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Genesis consensus parameters for XEPAY.
//!
//! Each network has its own genesis block, and every genesis block is
//! immutable. This module is the ONLY place that defines it, and it depends
//! on genesis parameters only: timestamp, nbits, message, secret, output
//! script, network name, hash and signature algorithms and the supply
//! economics. Rule parameters (block size, maturity, note length, block
//! version, difficulty schedule, ...) never influence the genesis hash;
//! they are changed later through activation heights (see `rules.rs`).

use crate::consensus::spec::{self, Network}; // Network selector and parameters.

// ----------------------------------------------------------------------
// Shared genesis messages (same on all networks)
// ----------------------------------------------------------------------

// The message embedded in the genesis coinbase transaction.
pub const GENESIS_MESSAGE: &str = "XEPAY Genesis - 2026";
// The secret embedded in the genesis secret transaction.
pub const GENESIS_SECRET: &str = "ID Today 15/Nov/2026 Aldianokto, Chaos in the Treasury, Order in the Code";

// ----------------------------------------------------------------------
// Genesis output script (P2PK, same format as the reference implementation)
// ----------------------------------------------------------------------
//
// The genesis output script locks the genesis block reward to a specific
// public key. With ML-DSA-65, the public key is 1952 bytes. Because the
// genesis output is never spent, the script is a placeholder that
// documents the intent without committing to a verifiable ML-DSA key.
//
// The 64-character hex string is SHA3-256(public_key), included for
// documentation only. It is not used for consensus verification.
pub const GENESIS_OUTPUT_SCRIPT: &str =
    "ML-DSA-65 OP_CHECKSIG 5f8df2f30478b134cda29c84357bd085a5de0016316ddbd66cf4df9e56662243";

// ----------------------------------------------------------------------
// Mainnet genesis
// ----------------------------------------------------------------------

// The mainnet genesis timestamp (in milliseconds).
pub const GENESIS_TIMESTAMP: u128 = 1794733780684;

// The expected mainnet genesis hash.
//
// NOTE: This value is immutable. Changing any genesis parameter changes the
// genesis hash on purpose: such a build is a different network and is
// rejected by every other node. `xepay-genesis` prints the values for a
// deliberate new network.
pub const EXPECTED_GENESIS_HASH: &str =
    "00000828c058152573d532f6cfbacd535fec17f084a0aadfcc9dfaca6de69a5f";

// The expected mainnet genesis merkle root.
pub const EXPECTED_GENESIS_MERKLE_ROOT: &str =
    "6f011db91548cd152d9c0165bbb9abfb464e5e5ef805806b38d9eb2dad43c2cb";

// The expected mainnet genesis timestamp.
pub const EXPECTED_GENESIS_TIMESTAMP: u128 = 1794733780684;

// The expected mainnet genesis nonce.
pub const EXPECTED_GENESIS_NONCE: u64 = 176217;

// ----------------------------------------------------------------------
// Testnet genesis
// ----------------------------------------------------------------------

// The testnet genesis timestamp (in milliseconds).
pub const TESTNET_GENESIS_TIMESTAMP: u128 = 1794733932120;

// The expected testnet genesis hash.
pub const TESTNET_EXPECTED_GENESIS_HASH: &str =
    "000009e097b67cc9806255f29717695be465077fb2b6693d8bb2cf3720c2a5ef";

// The expected testnet genesis merkle root.
pub const TESTNET_EXPECTED_GENESIS_MERKLE_ROOT: &str =
    "6f011db91548cd152d9c0165bbb9abfb464e5e5ef805806b38d9eb2dad43c2cb";

// The expected testnet genesis timestamp.
pub const TESTNET_EXPECTED_GENESIS_TIMESTAMP: u128 = 1794733932120;

// The expected testnet genesis nonce.
pub const TESTNET_EXPECTED_GENESIS_NONCE: u64 = 3365482;

// ----------------------------------------------------------------------
// Regtest genesis
// ----------------------------------------------------------------------

// The regtest genesis timestamp (in milliseconds).
pub const REGTEST_GENESIS_TIMESTAMP: u128 = 1794734004433;

// The expected regtest genesis hash.
pub const REGTEST_EXPECTED_GENESIS_HASH: &str =
    "7376a1f85b4b34bdb47ba581cbce501a96284560425614764da3082a3e14fa8e";

// The expected regtest genesis merkle root.
pub const REGTEST_EXPECTED_GENESIS_MERKLE_ROOT: &str =
    "6f011db91548cd152d9c0165bbb9abfb464e5e5ef805806b38d9eb2dad43c2cb";

// The expected regtest genesis timestamp.
pub const REGTEST_EXPECTED_GENESIS_TIMESTAMP: u128 = 1794734004433;

// The expected regtest genesis nonce.
pub const REGTEST_EXPECTED_GENESIS_NONCE: u64 = 4;

// ----------------------------------------------------------------------
// Network-aware accessors
// ----------------------------------------------------------------------

// Returns the shared genesis message.
pub fn genesis_message() -> &'static str {
    GENESIS_MESSAGE
}

// Returns the shared genesis secret.
pub fn genesis_secret() -> &'static str {
    GENESIS_SECRET
}

// Returns the genesis timestamp for the active network.
pub fn genesis_timestamp() -> u128 {
    spec::current_network().genesis_timestamp()
}

// Returns the shared genesis output script.
pub fn genesis_output_script() -> String {
    GENESIS_OUTPUT_SCRIPT.to_string()
}

// Returns the expected genesis hash for the given network.
pub fn expected_genesis_hash_for(network: Network) -> &'static str {
    match network {
        Network::Main => EXPECTED_GENESIS_HASH,
        Network::Test => TESTNET_EXPECTED_GENESIS_HASH,
        Network::Regtest => REGTEST_EXPECTED_GENESIS_HASH,
    }
}

// Returns the expected genesis merkle root for the given network.
pub fn expected_genesis_merkle_root_for(network: Network) -> &'static str {
    match network {
        Network::Main => EXPECTED_GENESIS_MERKLE_ROOT,
        Network::Test => TESTNET_EXPECTED_GENESIS_MERKLE_ROOT,
        Network::Regtest => REGTEST_EXPECTED_GENESIS_MERKLE_ROOT,
    }
}

// Returns the expected genesis timestamp for the given network.
pub fn expected_genesis_timestamp_for(network: Network) -> u128 {
    match network {
        Network::Main => EXPECTED_GENESIS_TIMESTAMP,
        Network::Test => TESTNET_EXPECTED_GENESIS_TIMESTAMP,
        Network::Regtest => REGTEST_EXPECTED_GENESIS_TIMESTAMP,
    }
}

// Returns the expected genesis nonce for the given network.
pub fn expected_genesis_nonce_for(network: Network) -> u64 {
    match network {
        Network::Main => EXPECTED_GENESIS_NONCE,
        Network::Test => TESTNET_EXPECTED_GENESIS_NONCE,
        Network::Regtest => REGTEST_EXPECTED_GENESIS_NONCE,
    }
}

// ----------------------------------------------------------------------
// Immutable genesis definition (genesis parameters only)
// ----------------------------------------------------------------------

/// Header version of the genesis block. Frozen: `rules::BLOCK_VERSION` is the
/// version of NEW blocks and can be changed by an activation height without
/// touching the genesis block.
pub const GENESIS_BLOCK_VERSION: u32 = 1;

/// Previous hash of the genesis block (there is no parent). Frozen literal,
/// independent of `rules::ZERO_HASH`.
pub const GENESIS_PREVIOUS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Miner label of the genesis block.
pub const GENESIS_MINED_FOR: &str = "GENESIS";

/// Fixed padding used in the genesis `blockchain_size` field.
pub const GENESIS_SIZE_PADDING: u64 = 256;

/// Version tag of the genesis commitment format.
pub const GENESIS_COMMITMENT_TAG: &str = "xepay-genesis-v1";

/// Human readable genesis time (UTC, `YYYY-MM-DD HH:MM:SS`) of each network.
/// Stored as constants so that a change of a date formatting helper can never
/// alter the genesis block.
pub fn genesis_mined_at_for(network: Network) -> &'static str {
    match network {
        Network::Main => "2026-11-15 09:09:40",
        Network::Test => "2026-11-15 09:12:12",
        Network::Regtest => "2026-11-15 09:13:24",
    }
}

/// Cumulative work stored in the genesis header. Frozen per network, so a
/// later change of the work formula (a rule) cannot alter the genesis block.
pub fn genesis_chainwork_for(network: Network) -> u128 {
    match network {
        Network::Main => 1,
        Network::Test => 1,
        Network::Regtest => 1,
    }
}

/// Every parameter that defines a genesis block. Nothing else may influence
/// the genesis hash, and nothing in this list may be changed after launch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisParams {
    pub network_name: String,
    pub hash_algo: String,
    pub signature_algo: String,
    pub decimals: u32,
    pub ald_per_xepc: u64,
    pub max_supply_xepc: u64,
    pub max_supply: u64,
    pub initial_reward_xepc: u64,
    pub initial_reward: u64,
    pub subsidy_halving_interval: u64,
    pub reward_reduction_numerator: u64,
    pub reward_reduction_denominator: u64,
    pub max_eras: u32,
    pub message: String,
    pub secret: String,
    pub timestamp: u128,
    pub output_script: String,
    pub nbits: u32,
    /// Derived display values of the genesis header (fixed per network).
    pub mined_at: String,
    pub chainwork: u128,
}

impl GenesisParams {
    /// The genesis parameters of `network`.
    pub fn for_network(network: Network) -> GenesisParams {
        GenesisParams {
            network_name: network.name().to_string(),
            hash_algo: spec::HASH_ALGO.to_string(),
            signature_algo: spec::SIGNATURE_ALGO.to_string(),
            decimals: spec::DECIMALS as u32,
            ald_per_xepc: spec::ALD_PER_XEPC as u64,
            max_supply_xepc: spec::MAX_SUPPLY_XEPC as u64,
            max_supply: spec::MAX_SUPPLY as u64,
            initial_reward_xepc: spec::INITIAL_REWARD_XEPC as u64,
            initial_reward: spec::INITIAL_REWARD as u64,
            subsidy_halving_interval: spec::SUBSIDY_HALVING_INTERVAL as u64,
            reward_reduction_numerator: spec::REWARD_REDUCTION_NUMERATOR as u64,
            reward_reduction_denominator: spec::REWARD_REDUCTION_DENOMINATOR as u64,
            max_eras: spec::MAX_ERAS as u32,
            message: GENESIS_MESSAGE.to_string(),
            secret: GENESIS_SECRET.to_string(),
            timestamp: network.genesis_timestamp(),
            output_script: GENESIS_OUTPUT_SCRIPT.to_string(),
            nbits: network.genesis_nbits(),
            mined_at: genesis_mined_at_for(network).to_string(),
            chainwork: genesis_chainwork_for(network),
        }
    }

    /// SHA3-256 commitment over all genesis-defining parameters. It is stored
    /// in the genesis header (`coinbase_txid`), so changing any parameter of
    /// this list changes the genesis hash. Rule parameters are not part of it.
    pub fn commitment(&self) -> String {
        let payload = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            GENESIS_COMMITMENT_TAG,
            self.network_name,
            self.hash_algo,
            self.signature_algo,
            self.decimals,
            self.ald_per_xepc,
            self.max_supply_xepc,
            self.max_supply,
            self.initial_reward_xepc,
            self.initial_reward,
            self.subsidy_halving_interval,
            self.reward_reduction_numerator,
            self.reward_reduction_denominator,
            self.max_eras,
            self.message,
            self.secret,
            self.timestamp,
            self.output_script,
            self.nbits,
        );
        xepay_crypto::sha3_256_hex(payload.as_bytes())
    }
}

/// Genesis commitment of `network` (the `coinbase_txid` of its genesis block).
pub fn genesis_commitment_for(network: Network) -> String {
    GenesisParams::for_network(network).commitment()
}
