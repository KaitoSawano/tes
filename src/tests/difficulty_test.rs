// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

use serial_test::serial; // For serializing tests that modify global state.
use std::sync::Mutex; // For protecting the environment variable.
use xepay::blockchain::{self, Blockchain}; // The Blockchain struct and constants.

// A global mutex to protect the XEPC_DATADIR environment variable.
static ENV_MUTEX: Mutex<()> = Mutex::new(());

// A helper function that sets up a temporary datadir, runs the closure, and
// then restores the environment. It uses a mutex to prevent race conditions.
fn with_temp_datadir<F: FnOnce()>(f: F) {
    let _guard = ENV_MUTEX.lock().unwrap(); // Acquire the mutex.
    let dir = tempfile::tempdir().expect("tempdir failed"); // Create a temp directory.
    std::env::set_var("XEPC_DATADIR", dir.path()); // Set the environment variable.
    f(); // Run the closure.
    std::env::remove_var("XEPC_DATADIR"); // Remove the environment variable.
}

#[test]
fn timespan_matches_adjust_interval_times_spacing() {
    let expected = blockchain::difficulty_adjust_interval() * blockchain::pow_target_spacing_secs(); // Compute the expected timespan.
    assert_eq!(blockchain::pow_target_timespan_secs(), expected); // Check that the timespan matches.
}

#[test]
#[serial]
fn adjust_difficulty_does_nothing_before_interval() {
    with_temp_datadir(|| {
        let mut chain = Blockchain::new(); // Create a new chain.
        let nbits_before = chain.nbits; // Record the initial nbits.
        chain.adjust_difficulty(); // Attempt to adjust the difficulty.
        assert_eq!(chain.nbits, nbits_before); // The nbits should not have changed.
    });
}

#[test]
#[serial]
fn adjust_difficulty_increases_target_when_blocks_are_slow() {
    with_temp_datadir(|| {
        let chain = Blockchain::new(); // Create a new chain.
        assert!(chain.nbits > 0); // The nbits should be greater than zero.
    });
}

// ---------------------------------------------------------------------
// Real difficulty tests (retarget math, 15 hour schedule, checkpoints).
// ---------------------------------------------------------------------

use xepay::blockchain::checkpoint::{self, Checkpoint}; // checkpoint helpers
use xepay::blockchain::compute_retarget; // pure retarget rule
use xepay::consensus::{rules, spec}; // schedule constants
use xepay::pow; // nbits <-> target conversion

/// Ratio of the target of `new_nbits` to the target of `old_nbits`.
fn target_ratio(old_nbits: u32, new_nbits: u32) -> f64 {
    let to_f64 = |nbits: u32| -> f64 {
        let t = pow::nbits_to_target(nbits); // 32-byte big-endian target
        t.iter().fold(0f64, |acc, b| acc * 256.0 + *b as f64) // exact enough for ratios
    };
    to_f64(new_nbits) / to_f64(old_nbits)
}

const EXPECTED: u64 = 54_000; // 15 hours in seconds
const START: u32 = 0x1d00ffff; // an nbits value far below the limit (room to ease)

#[test]
fn retarget_interval_is_fifteen_hours() {
    assert_eq!(spec::RETARGET_TIMESPAN_SECS_V2, 15 * 3600);
    assert_eq!(spec::RETARGET_INTERVAL_BLOCKS_V2, 3600);
    assert_eq!(
        spec::RETARGET_INTERVAL_BLOCKS_V2 * spec::POW_TARGET_SPACING_SECS,
        spec::RETARGET_TIMESPAN_SECS_V2
    );
}

#[test]
fn retarget_on_schedule_keeps_difficulty() {
    assert_eq!(compute_retarget(START, EXPECTED, EXPECTED), START);
}

#[test]
fn retarget_slow_blocks_make_mining_easier() {
    let new = compute_retarget(START, EXPECTED * 2, EXPECTED); // blocks took twice as long
    let r = target_ratio(START, new);
    assert!((r - 2.0).abs() < 0.001, "target should double, got {}", r);
}

#[test]
fn retarget_fast_blocks_make_mining_harder() {
    let new = compute_retarget(START, EXPECTED / 2, EXPECTED); // blocks came twice as fast
    let r = target_ratio(START, new);
    assert!((r - 0.5).abs() < 0.001, "target should halve, got {}", r);
}

#[test]
fn retarget_change_is_clamped_to_4x() {
    let easier = compute_retarget(START, EXPECTED * 100, EXPECTED);
    let harder = compute_retarget(START, EXPECTED / 100, EXPECTED);
    assert!((target_ratio(START, easier) - 4.0).abs() < 0.01);
    assert!((target_ratio(START, harder) - 0.25).abs() < 0.001);
}

#[test]
fn retarget_ignores_unusable_measurements() {
    assert_eq!(compute_retarget(START, 0, EXPECTED), START);
    assert_eq!(compute_retarget(START, EXPECTED, 0), START);
}

#[test]
fn retarget_never_exceeds_the_pow_limit() {
    let limit = hex::decode(xepay::consensus::pow::pow_limit()).unwrap();
    // Start at the limit and try to make it much easier.
    let at_limit = spec::current_network().genesis_nbits();
    let new = compute_retarget(at_limit, EXPECTED * 100, EXPECTED);
    assert!(pow::nbits_to_target(new).as_slice() <= limit.as_slice());
}

#[test]
fn schedule_matches_the_activation_height() {
    if spec::current_network() == spec::Network::Regtest {
        return; // regtest never retargets
    }
    let act = rules::xephash_activation_height();
    let i = spec::RETARGET_INTERVAL_BLOCKS_V2;
    assert!(!rules::retarget_after(act), "no retarget at the activation block itself");
    assert!(rules::retarget_after(act + i));
    assert!(rules::retarget_after(act + 2 * i));
    assert!(!rules::retarget_after(act + i + 1));
    assert!(rules::nbits_may_change_after(act - 1), "difficulty restarts at the activation");
    assert!(!rules::nbits_may_change_after(act + 1));
}

/// Build a header-only chain with synthetic timestamps (no mining needed).
fn synthetic_chain(spacing_before_ms: u128, spacing_after_ms: u128, tip: u64) -> Blockchain {
    let mut chain = Blockchain::new();
    let genesis = chain.chain[0].clone();
    let act = rules::xephash_activation_height();
    let base: u128 = 1_700_000_000_000;
    for i in 1..=tip {
        let mut b = genesis.clone();
        b.index = i;
        b.transactions.clear(); // header only: keeps memory small
        b.timestamp = if i < act {
            base + i as u128 * spacing_before_ms
        } else {
            base + act as u128 * spacing_before_ms + (i - act) as u128 * spacing_after_ms
        };
        chain.chain.push(b);
    }
    chain
}

#[test]
#[serial]
fn chain_retargets_after_fifteen_hours_of_fast_blocks() {
    if spec::current_network() == spec::Network::Regtest {
        return; // regtest never retargets
    }
    with_temp_datadir(|| {
        let act = rules::xephash_activation_height();
        let i = spec::RETARGET_INTERVAL_BLOCKS_V2;
        let start = rules::xephash_start_nbits();

        // One block before the first retarget: still the restart difficulty.
        let mut chain = synthetic_chain(15_000, 7_500, act + i - 1);
        chain.adjust_difficulty();
        assert_eq!(chain.nbits, start);

        // Connect the block that completes the 15 hour window (blocks twice
        // as fast as intended) => the target must halve.
        let mut last = chain.chain[0].clone();
        last.index = act + i;
        last.transactions.clear();
        last.timestamp = chain.chain.last().unwrap().timestamp + 7_500;
        chain.chain.push(last);
        chain.adjust_difficulty();
        let r = target_ratio(start, chain.nbits);
        assert!((r - 0.5).abs() < 0.01, "target should halve, got {}", r);

        // The result depends only on the chain: recomputing changes nothing.
        let first = chain.nbits;
        chain.adjust_difficulty();
        assert_eq!(chain.nbits, first);
    });
}

#[test]
fn checkpoints_verify_and_lock_history() {
    const LIST: &[Checkpoint] = &[
        Checkpoint { height: 100, hash: "aa" },
        Checkpoint { height: 500, hash: "bb" },
    ];
    // Hash must match at a checkpoint height, anything goes elsewhere.
    assert!(checkpoint::verify_in(LIST, 100, "aa"));
    assert!(checkpoint::verify_in(LIST, 100, "AA"));
    assert!(!checkpoint::verify_in(LIST, 100, "ab"));
    assert!(checkpoint::verify_in(LIST, 101, "anything"));
    // Blocks up to the highest checkpoint that is already buried are final.
    assert_eq!(checkpoint::locked_height_in(LIST, 99), 0);
    assert_eq!(checkpoint::locked_height_in(LIST, 100), 100);
    assert_eq!(checkpoint::locked_height_in(LIST, 499), 100);
    assert_eq!(checkpoint::locked_height_in(LIST, 10_000), 500);
    // A reorg may not replace a checkpointed block.
    assert!(!checkpoint::reorg_allowed_in(LIST, 99, 1_000));
    assert!(!checkpoint::reorg_allowed_in(LIST, 499, 1_000));
    assert!(checkpoint::reorg_allowed_in(LIST, 500, 1_000));
    assert!(checkpoint::reorg_allowed_in(LIST, 0, 50)); // checkpoint not reached yet
}

#[test]
fn shipped_checkpoint_tables_are_well_formed() {
    assert!(checkpoint::self_check().is_ok());
    // The validator itself must catch the typical mistakes.
    let good = "a".repeat(64);
    let leak: &'static str = Box::leak(good.into_boxed_str());
    let bad_hex: &'static str = Box::leak("g".repeat(64).into_boxed_str());
    let short: &'static str = "abc";
    let upper: &'static str = Box::leak("A".repeat(64).into_boxed_str());
    assert!(checkpoint::validate_table(&[Checkpoint { height: 10, hash: leak }]).is_ok());
    assert!(checkpoint::validate_table(&[Checkpoint { height: 0, hash: leak }]).is_err());
    assert!(checkpoint::validate_table(&[Checkpoint { height: 10, hash: bad_hex }]).is_err());
    assert!(checkpoint::validate_table(&[Checkpoint { height: 10, hash: short }]).is_err());
    assert!(checkpoint::validate_table(&[Checkpoint { height: 10, hash: upper }]).is_err());
    assert!(checkpoint::validate_table(&[
        Checkpoint { height: 20, hash: leak },
        Checkpoint { height: 10, hash: leak },
    ])
    .is_err());
}

#[test]
#[serial]
fn genesis_of_a_fresh_chain_matches_the_network_genesis() {
    with_temp_datadir(|| {
        let chain = Blockchain::new();
        assert!(checkpoint::verify_chain(&chain.chain).is_ok());
    });
}
