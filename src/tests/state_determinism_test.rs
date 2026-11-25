// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Regression tests for state-root determinism.
//!
//! These tests guard the invariants that the state root computed by the
//! live apply path is identical to the root computed by the read-only
//! simulation path, and that the account encoding is stable across
//! different insertion orders.

use serial_test::serial;
use std::sync::Mutex;
use xepay::blockchain::Blockchain;
use xepay::storage::Account;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn with_temp_datadir<F: FnOnce()>(f: F) {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("tempdir failed");
    std::env::set_var("XEPC_DATADIR", dir.path());
    f();
    std::env::remove_var("XEPC_DATADIR");
}

#[test]
fn account_encoding_is_order_independent() {
    let mut a = Account {
        nonce: 1,
        balance: 2,
        immature_rewards: std::collections::BTreeMap::new(),
        code: Vec::new(),
        storage: std::collections::BTreeMap::new(),
    };
    a.immature_rewards.insert(10, 5);
    a.immature_rewards.insert(20, 7);

    let mut b = Account {
        nonce: 1,
        balance: 2,
        immature_rewards: std::collections::BTreeMap::new(),
        code: Vec::new(),
        storage: std::collections::BTreeMap::new(),
    };
    b.immature_rewards.insert(20, 7);
    b.immature_rewards.insert(10, 5);

    let ea = rlp::encode(&a).to_vec();
    let eb = rlp::encode(&b).to_vec();
    assert_eq!(ea, eb, "account encoding must not depend on insertion order");
}

/// The root predicted for an open block batch must equal the root of the
/// state after that batch is committed (what a miner declares in the block
/// header is exactly what every node computes when connecting it).
#[test]
#[serial]
fn pending_root_matches_committed_root() {
    with_temp_datadir(|| {
        let mut chain = Blockchain::new();

        // Fund an account directly (no block batch is open yet).
        let addr = "GENESIS".to_string();
        let mut acc = chain.state.get_account(&addr).unwrap().unwrap();
        acc.balance = 1_000_000;
        chain.state.update_account(&addr, &acc).unwrap();

        // Apply one transfer inside a block batch.
        chain.state.begin_block().unwrap();
        chain
            .state
            .apply_transaction(&addr, "recipient", 1_000, 1_000, 0, 1)
            .unwrap();
        let predicted = chain.state.pending_root().unwrap();

        // Committing must produce exactly the predicted root.
        chain.state.commit_block(1, "hash1", &predicted).unwrap();
        assert_eq!(chain.state.state_root(), predicted);
    });
}
