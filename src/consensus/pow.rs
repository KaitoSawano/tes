// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Proof-of-work consensus parameters for XEPAY.

/// Genesis nBits. This value is 0x1e0ffff0.
pub const GENESIS_NBITS: u32 = 0x1e0ffff0;

/// The proof-of-work limit for Mainnet and Testnet.
/// This value is 00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
pub const POW_LIMIT_MAIN: &str = "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// The proof-of-work limit for Regtest.
/// This value is very easy: 7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
pub const POW_LIMIT_REGTEST: &str =
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// Genesis difficulty of the RUNNING network (it used to return the mainnet
/// value on every network, which disagreed with the other genesis code).
pub fn genesis_nbits() -> u32 {
    crate::consensus::spec::current_network().genesis_nbits()
}

pub fn pow_limit() -> &'static str {
    match crate::consensus::spec::current_network() {
        crate::consensus::spec::Network::Main => POW_LIMIT_MAIN,
        crate::consensus::spec::Network::Test => POW_LIMIT_MAIN,
        crate::consensus::spec::Network::Regtest => POW_LIMIT_REGTEST,
    }
}
