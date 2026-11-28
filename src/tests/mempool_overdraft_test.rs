// Regression: a sender must not be able to queue more transactions than its
// balance can pay for, nor an unlimited number of them. Before the fix every
// pending transaction was checked against the full balance on its own, so a
// wallet with 0.99 coins could queue any number of 0.9 coin transfers.

use serial_test::serial;
use std::collections::BTreeMap;
use std::sync::Mutex;
use xepay::blockchain::{Blockchain, MAX_PENDING_TXS_PER_SENDER};
use xepay::dilithium::{address, keypair::KeyPair};
use xepay::storage::Account;
use xepay::transaction::Transaction;
use xepay::validation;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

// Run a test body with its own empty data directory.
fn with_temp_datadir<F: FnOnce()>(f: F) {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner()); // one test at a time
    let dir = tempfile::tempdir().expect("tempdir failed"); // throw-away data directory
    std::env::set_var("XEPC_DATADIR", dir.path()); // point the node at it
    f();
    std::env::remove_var("XEPC_DATADIR"); // clean up the environment
}

// Create a funded sender and an empty receiver.
fn funded_pair(chain: &mut Blockchain, balance: u64, nonce: u64) -> (KeyPair, String, String) {
    let kp = KeyPair::generate().expect("keypair"); // sender key
    let to_kp = KeyPair::generate().expect("keypair"); // receiver key
    let from = address::address_from_public_key(&kp.public_key).expect("address"); // sender address
    let to = address::address_from_public_key(&to_kp.public_key).expect("address"); // receiver address
    chain
        .state
        .update_account(
            &from,
            &Account {
                nonce,
                balance,
                immature_rewards: BTreeMap::new(),
                code: Vec::new(),
                storage: BTreeMap::new(),
            },
        )
        .unwrap(); // fund the sender directly in the state
    (kp, from, to)
}

// Build and sign one transfer.
fn signed_tx(kp: &KeyPair, from: &str, to: &str, amount: u64, fee: u64, nonce: u64) -> Transaction {
    let mut tx = Transaction::new(from, to, amount, fee, nonce); // unsigned transfer
    tx.sign(&kp.secret_key_hex()).expect("sign"); // sign with the sender key
    tx
}

#[test]
#[serial]
fn second_transfer_that_overdraws_the_balance_is_rejected() {
    with_temp_datadir(|| {
        let mut chain = Blockchain::new();
        // 0.99 coins: exactly one 0.9 coin transfer plus the 0.01 fee fits.
        let (kp, from, to) = funded_pair(&mut chain, 99_000_000, 0);

        let first = signed_tx(&kp, &from, &to, 90_000_000, 1_000_000, 0);
        assert!(chain.add_transaction_checked(first).is_ok(), "the first transfer is affordable");

        let second = signed_tx(&kp, &from, &to, 90_000_000, 1_000_000, 1);
        let err = chain
            .add_transaction_checked(second)
            .expect_err("the second transfer can never be mined");
        assert!(err.contains("insufficient"), "the reason must name the balance: {}", err);
        assert_eq!(chain.mempool.len(), 1, "only the affordable transfer stays queued");
    });
}

#[test]
#[serial]
fn several_small_transfers_that_fit_are_all_accepted() {
    with_temp_datadir(|| {
        let mut chain = Blockchain::new();
        let (kp, from, to) = funded_pair(&mut chain, 1_000_000_000, 0);

        // Five transfers of 1_000 ald plus 1_000_000 ald fee are far below the balance.
        for nonce in 0..5u64 {
            let tx = signed_tx(&kp, &from, &to, 1_000, 1_000_000, nonce);
            assert!(chain.add_transaction_checked(tx).is_ok(), "nonce {} must be accepted", nonce);
        }
        assert_eq!(chain.mempool.len(), 5);
        assert!(validation::validate_mempool(&chain).is_empty(), "a consistent mempool is valid");
    });
}

#[test]
#[serial]
fn one_sender_cannot_exceed_the_pending_limit() {
    with_temp_datadir(|| {
        let mut chain = Blockchain::new();
        let (kp, from, to) = funded_pair(&mut chain, 1_000_000_000_000, 0);

        // Fill the allowance of the sender.
        for nonce in 0..MAX_PENDING_TXS_PER_SENDER as u64 {
            let tx = signed_tx(&kp, &from, &to, 1_000, 1_000_000, nonce);
            assert!(chain.add_transaction_checked(tx).is_ok(), "nonce {} must be accepted", nonce);
        }

        // One more is refused although the balance would pay for it.
        let extra = signed_tx(&kp, &from, &to, 1_000, 1_000_000, MAX_PENDING_TXS_PER_SENDER as u64);
        let err = chain
            .add_transaction_checked(extra)
            .expect_err("the pending limit must apply");
        assert!(err.contains("too many"), "unexpected reason: {}", err);
        assert_eq!(chain.mempool.len(), MAX_PENDING_TXS_PER_SENDER);
    });
}

#[test]
#[serial]
fn spendable_balance_excludes_pending_transfers() {
    with_temp_datadir(|| {
        let mut chain = Blockchain::new();
        let (kp, from, to) = funded_pair(&mut chain, 99_000_000, 0);
        let height = chain.height();
        assert_eq!(chain.spendable_balance_at(&from, height), 99_000_000);

        let tx = signed_tx(&kp, &from, &to, 90_000_000, 1_000_000, 0);
        assert!(chain.add_transaction_checked(tx).is_ok());

        // 0.99 - (0.90 + 0.01) = 0.08 coins are left to spend.
        assert_eq!(chain.spendable_balance_at(&from, height), 8_000_000);
        assert_eq!(chain.pending_spend_of(&from), 91_000_000);
    });
}

#[test]
#[serial]
fn pruning_drops_entries_the_sender_can_no_longer_afford() {
    with_temp_datadir(|| {
        let mut chain = Blockchain::new();
        let (kp, from, to) = funded_pair(&mut chain, 99_000_000, 0);

        // Put an overdrawn queue straight into the mempool (as an old node would hold it).
        for nonce in 0..3u64 {
            let tx = signed_tx(&kp, &from, &to, 90_000_000, 1_000_000, nonce);
            chain.mempool.push(tx);
        }
        assert_eq!(validation::validate_mempool(&chain).len(), 2, "entries 1 and 2 are overdrawn");

        chain.prune_mempool_after_block();

        assert_eq!(chain.mempool.len(), 1, "only the affordable entry survives");
        assert_eq!(chain.mempool[0].nonce, 0);
        assert!(validation::validate_mempool(&chain).is_empty());
    });
}

#[test]
#[serial]
fn pruning_drops_entries_whose_nonce_was_already_used() {
    with_temp_datadir(|| {
        let mut chain = Blockchain::new();
        // The account nonce is already 1: nonce 0 was mined by an earlier block.
        let (kp, from, to) = funded_pair(&mut chain, 1_000_000_000, 1);

        chain.mempool.push(signed_tx(&kp, &from, &to, 1_000, 1_000_000, 0)); // stale entry
        chain.mempool.push(signed_tx(&kp, &from, &to, 1_000, 1_000_000, 1)); // still valid entry

        chain.prune_mempool_after_block();

        assert_eq!(chain.mempool.len(), 1);
        assert_eq!(chain.mempool[0].nonce, 1, "only the stale entry is removed");
    });
}
