// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Proof-of-work primitives.

use crate::block::Block;
use std::sync::atomic::{AtomicBool, Ordering};

pub use crate::consensus::pow::GENESIS_NBITS;

/// Convert a compact nBits value into a 256-bit big-endian target.
pub fn nbits_to_target(nbits: u32) -> [u8; 32] {
    let exponent = (nbits >> 24) as usize;
    let mantissa = nbits & 0x007fffff;
    let negative = (nbits & 0x00800000) != 0;

    let mut target = [0u8; 32];

    if negative {
        return target;
    }

    if exponent <= 3 {
        let value = mantissa >> (8 * (3 - exponent));
        let be = value.to_be_bytes();
        target[29] = be[1];
        target[30] = be[2];
        target[31] = be[3];
        return target;
    }

    // An exponent above 32 does not fit in 256 bits. `32 - exponent` would
    // underflow and index out of bounds (remote crash on a crafted header).
    if exponent > 32 {
        return target;
    }
    let shift = 32 - exponent;
    if shift + 3 > 32 {
        return target;
    }
    let be = mantissa.to_be_bytes();
    target[shift] = be[1];
    target[shift + 1] = be[2];
    target[shift + 2] = be[3];
    target
}

/// Convert nBits to a floating-point difficulty value .
pub fn nbits_to_difficulty(nbits: u32) -> f64 {
    let max_target = nbits_to_target(0x1d00ffff);
    let target = nbits_to_target(nbits);

    let mut max_val = 0.0f64;
    for &b in max_target.iter() {
        max_val = max_val * 256.0 + b as f64;
    }

    let mut cur_val = 0.0f64;
    for &b in target.iter() {
        cur_val = cur_val * 256.0 + b as f64;
    }

    if cur_val == 0.0 {
        return 0.0;
    }

    max_val / cur_val
}

/// Return whether `hash_hex` is less than or equal to `target`.
pub fn hash_le_target(hash_hex: &str, target: &[u8; 32]) -> bool {
    let hash_bytes = match hex::decode(hash_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };

    for i in 0..32 {
        if hash_bytes[i] < target[i] {
            return true;
        }
        if hash_bytes[i] > target[i] {
            return false;
        }
    }
    true
}

/// Return whether `hash_hex` meets the target encoded by `nbits`.
pub fn hash_meets_nbits(hash_hex: &str, nbits: u32) -> bool {
    let target = nbits_to_target(nbits);
    // A zero target (negative flag, zero mantissa, oversized exponent) is
    // not a valid difficulty; it must never be satisfiable.
    if target.iter().all(|&b| b == 0) {
        return false;
    }
    hash_le_target(hash_hex, &target)
}

/// Check whether proof-of-work mining should be skipped.
/// This function is only compiled when the `skip-pow` feature is enabled.
/// In release builds, it always returns `false`, ensuring that production
/// binaries (Mainnet, Testnet, Regtest) never skip mining.
#[cfg(feature = "skip-pow")]
fn should_skip_pow() -> bool {
    true
}

/// In non-test builds, mining is never skipped.
#[cfg(not(feature = "skip-pow"))]
fn should_skip_pow() -> bool {
    false
}

/// Mine the block until the hash meets the target or the nonce is exhausted.
pub fn mine(block: &mut Block, nbits: u32) -> bool {
    mine_interruptible(block, nbits, None)
}

/// Mine the block until the hash meets the target, the nonce is exhausted,
/// or the interrupt flag is set. Return `true` on success.
pub fn mine_interruptible(block: &mut Block, nbits: u32, interrupt: Option<&AtomicBool>) -> bool {
    // In test builds with the `skip-pow` feature, skip the mining process.
    // In release builds, `should_skip_pow()` always returns `false`.
    if should_skip_pow() {
        return true;
    }

    // From the activation height the work is Xephash, not the header hash.
    if crate::consensus::rules::xephash_active(block.index) {
        return mine_xephash(block, nbits, interrupt, true);
    }

    let target = nbits_to_target(nbits);
    loop {
        if let Some(flag) = interrupt {
            if flag.load(Ordering::SeqCst) {
                return false;
            }
        }
        block.hash = block.calculate_hash();
        if hash_le_target(&block.hash, &target) {
            return true;
        }
        if block.nonce == u64::MAX {
            return false;
        }
        block.nonce = block.nonce.wrapping_add(1);
    }
}

/// Process-wide Xephash engine (cache of the current epoch, optional dataset).
static XEPHASH_ENGINE: std::sync::OnceLock<Result<xepay_crypto::xephash::Engine, String>> =
    std::sync::OnceLock::new();

/// Xephash size parameters of the running network.
fn xephash_params() -> xepay_crypto::xephash::Params {
    use crate::consensus::spec::{self, Network};
    use xepay_crypto::xephash::Params;
    match spec::current_network() {
        Network::Main => Params::MAIN,
        Network::Test => Params::TEST,
        Network::Regtest => Params::REGTEST,
    }
}

/// The shared engine, created on first use.
pub fn xephash_engine() -> Result<&'static xepay_crypto::xephash::Engine, String> {
    XEPHASH_ENGINE
        .get_or_init(|| {
            xepay_crypto::xephash::Engine::new(xephash_params()).map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| e.clone())
}

/// True when `block` satisfies its proof of work: Xephash from the
/// activation height, the plain header hash before it.
pub fn block_meets_pow(block: &Block) -> bool {
    if !crate::consensus::rules::xephash_active(block.index) {
        return hash_meets_nbits(&block.hash, block.nbits); // legacy rule
    }
    let target = nbits_to_target(block.nbits); // 256-bit target
    if target.iter().all(|&b| b == 0) {
        return false; // a zero target is never valid
    }
    let engine = match xephash_engine() {
        Ok(e) => e,
        Err(_) => return false, // cannot verify => not valid
    };
    // Light verification: only the epoch cache is needed (about 1 ms).
    match engine.verify(block.index, &block.seal_hash(), block.nonce) {
        Ok(out) => xepay_crypto::xephash::meets_target(&out.result, &target),
        Err(_) => false,
    }
}

/// Mine with Xephash. `use_full` builds the full dataset (fast, needs RAM);
/// if that fails, or `use_full` is false, the slower light mode is used.
pub fn mine_xephash(
    block: &mut Block,
    nbits: u32,
    interrupt: Option<&AtomicBool>,
    use_full: bool,
) -> bool {
    let target = nbits_to_target(nbits); // 256-bit target
    if target.iter().all(|&b| b == 0) {
        return false; // impossible difficulty
    }
    let engine = match xephash_engine() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[pow] xephash unavailable: {}", e);
            return false;
        }
    };
    let seal = block.seal_hash(); // fixed for all nonces
    let dataset = if use_full {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        match engine.full_dataset(block.index, threads) {
            Ok(d) => Some(d),
            Err(e) => {
                eprintln!("[pow] full dataset unavailable ({}); using light mode", e);
                None
            }
        }
    } else {
        None
    };
    loop {
        if let Some(flag) = interrupt {
            if flag.load(Ordering::SeqCst) {
                return false; // stop requested
            }
        }
        let out = match &dataset {
            Some(d) => xepay_crypto::xephash::hashimoto_full(d, &seal, block.nonce),
            None => engine.verify(block.index, &seal, block.nonce),
        };
        match out {
            Ok(o) => {
                if xepay_crypto::xephash::meets_target(&o.result, &target) {
                    block.hash = block.calculate_hash(); // block id with the winning nonce
                    return true;
                }
            }
            Err(_) => return false,
        }
        if block.nonce == u64::MAX {
            return false; // nonce space exhausted
        }
        block.nonce = block.nonce.wrapping_add(1);
    }
}

#[cfg(test)]
mod overflow_tests {
    use super::*;

    #[test]
    fn oversized_exponent_does_not_panic() {
        for nbits in [0x21000001u32, 0xff7fffff, 0x7f123456, 0x20ffffff] {
            let _ = nbits_to_target(nbits);
        }
        assert_eq!(nbits_to_target(0xff123456), [0u8; 32]);
    }

    #[test]
    fn zero_target_is_never_met() {
        let zero_hash = "0".repeat(64);
        assert!(!hash_meets_nbits(&zero_hash, 0xff123456));
        assert!(!hash_meets_nbits(&zero_hash, 0x00000000));
        assert!(!hash_meets_nbits(&zero_hash, 0x1d800001));
    }
}
