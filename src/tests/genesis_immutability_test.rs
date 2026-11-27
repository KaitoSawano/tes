// The genesis block is immutable: only genesis parameters influence its hash,
// rule parameters never do, and checkpoints can never crash a node.

use xepay::block::Block;
use xepay::blockchain::checkpoint::{self, Checkpoint};
use xepay::consensus::genesis::{self, GenesisParams};
use xepay::consensus::rules::{self, RuleEra, RuleSet};
use xepay::consensus::spec::Network;
use xepay::pow;
use xepay::validation;

const NETWORKS: [Network; 3] = [Network::Main, Network::Test, Network::Regtest];

/// Header hash of an unmined genesis block with the given nonce.
fn genesis_hash_of(params: &GenesisParams, nonce: u64) -> String {
    let mut b = Block::genesis_from_params(params);
    b.nonce = nonce;
    b.calculate_hash()
}

#[test]
fn genesis_constants_reproduce_without_mining() {
    for net in NETWORKS {
        let mut b = Block::genesis_unmined_for(net);
        b.nonce = genesis::expected_genesis_nonce_for(net);
        let hash = b.calculate_hash();
        assert_eq!(hash, genesis::expected_genesis_hash_for(net), "{:?}: genesis hash", net);
        assert_eq!(b.merkle_root, genesis::expected_genesis_merkle_root_for(net));
        assert_eq!(b.timestamp, genesis::expected_genesis_timestamp_for(net));
        assert_eq!(b.coinbase_txid, genesis::genesis_commitment_for(net));
        assert!(pow::hash_meets_nbits(&hash, b.nbits), "{:?}: genesis proof of work", net);
        assert_eq!(b.index, 0);
        assert_eq!(b.nversion, genesis::GENESIS_BLOCK_VERSION);
        assert_eq!(b.previous_hash, genesis::GENESIS_PREVIOUS_HASH);
    }
}

#[test]
fn every_genesis_parameter_changes_the_genesis_hash() {
    for net in NETWORKS {
        let base = GenesisParams::for_network(net);
        let nonce = genesis::expected_genesis_nonce_for(net);
        let base_hash = genesis_hash_of(&base, nonce);
        let base_commitment = base.commitment();

        let mut variants: Vec<(&str, GenesisParams)> = Vec::new();
        let mut add = |name: &'static str, f: &dyn Fn(&mut GenesisParams)| {
            let mut p = base.clone();
            f(&mut p);
            variants.push((name, p));
        };
        add("network name", &|p| p.network_name.push('x'));
        add("hash algorithm", &|p| p.hash_algo.push('x'));
        add("signature algorithm", &|p| p.signature_algo.push('x'));
        add("decimals", &|p| p.decimals += 1);
        add("ald per coin", &|p| p.ald_per_xepc += 1);
        add("max supply (coins)", &|p| p.max_supply_xepc += 1);
        add("max supply (units)", &|p| p.max_supply += 1);
        add("initial reward (coins)", &|p| p.initial_reward_xepc += 1);
        add("initial reward (units)", &|p| p.initial_reward += 1);
        add("subsidy interval", &|p| p.subsidy_halving_interval += 1);
        add("reduction numerator", &|p| p.reward_reduction_numerator += 1);
        add("reduction denominator", &|p| p.reward_reduction_denominator += 1);
        add("max eras", &|p| p.max_eras += 1);
        add("message", &|p| p.message.push('x'));
        add("secret", &|p| p.secret.push('x'));
        add("timestamp", &|p| p.timestamp += 1);
        add("output script", &|p| p.output_script.push('x'));
        add("nbits", &|p| p.nbits ^= 1);

        for (name, p) in variants {
            assert_ne!(p.commitment(), base_commitment, "{:?}: {} must change the commitment", net, name);
            assert_ne!(genesis_hash_of(&p, nonce), base_hash, "{:?}: {} must change the genesis hash", net, name);
        }
    }
}

#[test]
fn genesis_params_list_has_no_rule_parameter() {
    // Adding a field to `GenesisParams` breaks this destructuring on purpose:
    // the author must decide whether the new field really defines the genesis.
    let GenesisParams {
        network_name: _,
        hash_algo: _,
        signature_algo: _,
        decimals: _,
        ald_per_xepc: _,
        max_supply_xepc: _,
        max_supply: _,
        initial_reward_xepc: _,
        initial_reward: _,
        subsidy_halving_interval: _,
        reward_reduction_numerator: _,
        reward_reduction_denominator: _,
        max_eras: _,
        message: _,
        secret: _,
        timestamp: _,
        output_script: _,
        nbits: _,
        mined_at: _,
        chainwork: _,
    } = GenesisParams::for_network(Network::Main);
}

/// Source lines that are not comments.
fn code_lines(src: &str) -> Vec<&str> {
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect()
}

#[test]
fn genesis_code_never_reads_a_rule_parameter() {
    // The genesis module may not touch `rules::`.
    let genesis_src = include_str!("../consensus/genesis.rs");
    for line in code_lines(genesis_src) {
        assert!(!line.contains("rules::"), "genesis.rs reads a rule parameter: {}", line);
    }
    // Neither may the genesis builders of block.rs (between the markers).
    let block_src = include_str!("../block.rs");
    let begin = block_src.find("// GENESIS-BEGIN").expect("GENESIS-BEGIN marker");
    let end = block_src.find("// GENESIS-END").expect("GENESIS-END marker");
    assert!(begin < end);
    for line in code_lines(&block_src[begin..end]) {
        assert!(!line.contains("rules::"), "genesis builder reads a rule parameter: {}", line);
        assert!(!line.contains("BLOCK_VERSION") || line.contains("GENESIS_BLOCK_VERSION"));
    }
    // The genesis commitment is defined in the genesis module only.
    let mod_src = include_str!("../consensus/mod.rs");
    let marker = mod_src.find("pub fn genesis_coinbase_txid_for").expect("txid function");
    let body = &mod_src[marker..mod_src.len().min(marker + 200)];
    assert!(body.contains("genesis::genesis_commitment_for"));
}

#[test]
fn rule_changes_are_scheduled_and_leave_the_genesis_alone() {
    let before: Vec<String> = NETWORKS
        .iter()
        .map(|n| genesis::genesis_commitment_for(*n))
        .collect();

    // A made-up schedule that changes every rule parameter at height 1000.
    let schedule = [RuleEra {
        activation_height: 1000,
        rules: RuleSet {
            max_tx_per_block: 5000,
            coinbase_maturity: 200,
            max_note_len: 1024,
            block_version: 2,
        },
    }];
    assert!(rules::validate_schedule_in(&schedule).is_ok());
    assert_eq!(rules::rules_in(&schedule, 999), rules::BASE_RULES);
    assert_eq!(rules::rules_in(&schedule, 1000).max_tx_per_block, 5000);
    assert_eq!(rules::rules_in(&schedule, u64::MAX).block_version, 2);
    // Old blocks keep the old rules; the genesis block keeps its own version.
    assert_eq!(rules::rules_in(&schedule, 1).coinbase_maturity, rules::COINBASE_MATURITY);
    assert_eq!(rules::block_version_at(0), genesis::GENESIS_BLOCK_VERSION);

    // The genesis commitments did not move.
    let after: Vec<String> = NETWORKS
        .iter()
        .map(|n| genesis::genesis_commitment_for(*n))
        .collect();
    assert_eq!(before, after);
}

#[test]
fn bad_rule_schedules_are_rejected() {
    let era = |h: u64| RuleEra { activation_height: h, rules: rules::BASE_RULES };
    assert!(rules::validate_schedule_in(&[]).is_ok());
    assert!(rules::validate_schedule_in(&[era(0)]).is_err(), "height 0 is the genesis block");
    assert!(rules::validate_schedule_in(&[era(10), era(10)]).is_err());
    assert!(rules::validate_schedule_in(&[era(10), era(5)]).is_err());
    let mut zero = rules::BASE_RULES;
    zero.max_tx_per_block = 0;
    assert!(rules::validate_schedule_in(&[RuleEra { activation_height: 5, rules: zero }]).is_err());
    assert!(rules::validate_schedule().is_ok(), "the shipped schedules must be valid");
}

#[test]
fn activation_heights_never_touch_the_genesis_block() {
    assert!(rules::state_root_activation_height() >= 1);
    assert!(rules::xephash_activation_height() >= 1);
    assert!(!rules::state_root_active(0));
    assert!(!rules::xephash_active(0));
}

#[test]
fn a_different_genesis_isolates_the_node() {
    let a_params = GenesisParams::for_network(Network::Main);
    let mut b_params = a_params.clone();
    b_params.message.push_str(" (modified)"); // someone edits a genesis parameter

    let mut a = Block::genesis_from_params(&a_params);
    a.nonce = genesis::expected_genesis_nonce_for(Network::Main);
    a.hash = a.calculate_hash();
    let mut b = Block::genesis_from_params(&b_params);
    b.hash = b.calculate_hash();
    assert_ne!(a.hash, b.hash, "a modified genesis parameter must give another genesis hash");

    // A block built on the real genesis is rejected by the modified node ...
    let block1 = Block::new_for(
        1,
        a.hash.clone(),
        xepay::blockchain::Blockchain::calculate_reward(1),
        0,
        a.nbits,
        Vec::new(),
        "xreg1q4t3vtam8l8lz8hzr9fwakycgrm2c2z89yg7n0n".to_string(),
        a.chainwork,
    )
    .expect("block 1");
    assert!(validation::rule_block_previous_hash(&a, &block1).is_ok());
    assert!(validation::rule_block_previous_hash(&b, &block1).is_err(), "other genesis => other chain");

    // ... and the modified chain does not pass the genesis check either (no panic).
    assert!(checkpoint::verify_chain_in(&[], &a.hash, &[b.clone()]).is_err());
    assert!(checkpoint::verify_chain_in(&[], &a.hash, &[a.clone()]).is_ok());
}

/// A header-only block for the checkpoint tests.
fn fake_block(index: u64, hash: &str) -> Block {
    let mut b = Block::genesis_unmined_for(Network::Regtest);
    b.index = index;
    b.hash = hash.to_string();
    b
}

#[test]
fn checkpoints_never_panic_on_missing_or_wrong_hashes() {
    const LIST: &[Checkpoint] = &[
        Checkpoint { height: 2, hash: "bb" },
        Checkpoint { height: 1_000_000, hash: "cc" },
    ];
    // Unknown heights, odd inputs and empty strings are plain answers.
    assert!(checkpoint::verify_in(&[], 5, "anything"));
    assert!(checkpoint::verify_in(LIST, u64::MAX, ""));
    assert!(!checkpoint::verify_in(LIST, 2, ""));
    assert!(!checkpoint::verify_in(LIST, 2, "BBB"));
    assert_eq!(checkpoint::locked_height_in(&[], u64::MAX), 0);
    assert!(checkpoint::reorg_allowed_in(&[], 0, u64::MAX));

    let g = "00";
    // An empty chain and a chain shorter than every checkpoint are fine.
    assert!(checkpoint::verify_chain_in(LIST, g, &[]).is_ok());
    assert!(checkpoint::verify_chain_in(LIST, g, &[fake_block(0, g)]).is_ok());
    // A matching checkpoint passes, a different hash is an error (not a crash).
    let ok = [fake_block(0, g), fake_block(1, "aa"), fake_block(2, "bb")];
    assert!(checkpoint::verify_chain_in(LIST, g, &ok).is_ok());
    let bad = [fake_block(0, g), fake_block(1, "aa"), fake_block(2, "ff")];
    assert!(checkpoint::verify_chain_in(LIST, g, &bad).is_err());
    // A block stored at the wrong index is reported as well.
    let wrong_index = [fake_block(0, g), fake_block(1, "aa"), fake_block(7, "bb")];
    assert!(checkpoint::verify_chain_in(LIST, g, &wrong_index).is_err());
}

#[test]
fn a_block_that_violates_a_checkpoint_is_rejected_not_fatal() {
    // With the shipped (empty) tables every block passes ...
    let b = fake_block(5, "deadbeef");
    assert!(validation::rule_block_checkpoint(&b).is_ok());
    // ... and the table logic itself answers with a bool for any hash.
    const LIST: &[Checkpoint] = &[Checkpoint { height: 5, hash: "abcd" }];
    assert!(!checkpoint::verify_in(LIST, 5, "deadbeef"));
}
