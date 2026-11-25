// Integration of Xephash with the block header, mining and validation.

use serial_test::serial;
use xepay::block::Block;
use xepay::blockchain::Blockchain;
use xepay::consensus::rules;
use xepay::pow;
use xepay::validation;

/// Easy-but-not-trivial difficulty: about 1 solution in 256 hashes.
const TEST_NBITS: u32 = 0x2000ffff;

/// Build an (unmined) block at the first Xephash height.
fn xephash_block() -> Block {
    let index = rules::xephash_activation_height();
    Block::new_for(
        index,
        "00".repeat(32),
        Blockchain::calculate_reward(index),
        0,
        TEST_NBITS,
        Vec::new(),
        "xreg1q4t3vtam8l8lz8hzr9fwakycgrm2c2z89yg7n0n".to_string(),
        0,
    )
    .expect("failed to create block")
    .with_state_root("ab".repeat(32))
}

#[test]
fn activation_boundary_is_consistent() {
    let a = rules::xephash_activation_height();
    assert!(!rules::xephash_active(a - 1));
    assert!(rules::xephash_active(a));
    // The seal hash needs the header-only layout, so xephash never starts earlier.
    assert!(a >= rules::state_root_activation_height());
}

#[test]
#[serial]
fn mined_block_passes_and_tampering_fails() {
    let mut b = xephash_block();
    assert!(pow::mine_xephash(&mut b, TEST_NBITS, None, false), "mining failed");
    assert!(pow::block_meets_pow(&b));
    assert!(validation::rule_block_pow(&b).is_ok());
    assert_eq!(b.hash, b.calculate_hash(), "block id must match the header");

    // Changing the nonce must (almost always) break the proof of work.
    let mut failures = 0;
    for d in 1..=40u64 {
        let mut t = b.clone();
        t.nonce = b.nonce.wrapping_add(d);
        t.hash = t.calculate_hash();
        if !pow::block_meets_pow(&t) {
            failures += 1;
        }
    }
    assert!(failures >= 30, "tampered nonces passed too often: {}", failures);

    // Changing the committed state root invalidates the proof of work too.
    let mut s = b.clone().with_state_root("cd".repeat(32));
    s.hash = s.calculate_hash();
    assert_ne!(b.seal_hash(), s.seal_hash());
}

#[test]
fn seal_hash_ignores_nonce_but_not_header_fields() {
    let b = xephash_block();
    let mut n = b.clone();
    n.nonce = 12_345;
    assert_eq!(b.seal_hash(), n.seal_hash(), "nonce must not change the seal");
    let mut t = b.clone();
    t.timestamp += 1;
    assert_ne!(b.seal_hash(), t.seal_hash(), "timestamp must change the seal");
    // The seal never equals the block hash of the same header.
    assert_ne!(hex::encode(b.seal_hash()), b.calculate_hash());
}

#[test]
fn zero_target_is_never_accepted() {
    let mut b = xephash_block();
    b.nbits = 0xff123456; // oversized exponent => zero target
    assert!(!pow::block_meets_pow(&b));
}
