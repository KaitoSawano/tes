// Regression: several pending transactions of ONE sender must all be
// selected into the next block (they used to be rejected, so blocks were
// mined empty and the transactions stayed in the mempool forever).

use serial_test::serial;
use std::collections::BTreeMap;
use std::sync::Mutex;
use xepay::blockchain::Blockchain;
use xepay::dilithium::{address, keypair::KeyPair};
use xepay::storage::Account;
use xepay::transaction::Transaction;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn with_temp_datadir<F: FnOnce()>(f: F) {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("tempdir failed");
    std::env::set_var("XEPC_DATADIR", dir.path());
    f();
    std::env::remove_var("XEPC_DATADIR");
}

#[test]
#[serial]
fn all_pending_txs_of_one_sender_are_mined_in_nonce_order() {
    with_temp_datadir(|| {
        let mut chain = Blockchain::new();
        let kp = KeyPair::generate().expect("keypair");
        let to_kp = KeyPair::generate().expect("keypair");
        let from = address::address_from_public_key(&kp.public_key).expect("address");
        let to = address::address_from_public_key(&to_kp.public_key).expect("address");

        // Fund the sender directly in the state.
        chain
            .state
            .update_account(
                &from,
                &Account {
                    nonce: 0,
                    balance: 1_000_000_000_000,
                    immature_rewards: BTreeMap::new(),
                    code: Vec::new(),
                    storage: BTreeMap::new(),
                },
            )
            .unwrap();

        // Five pending transactions, nonces 0..4 (all signed with the key).
        for nonce in 0..5u64 {
            let mut tx = Transaction::new(&from, &to, 1_000, 1_000_000, nonce);
            tx.sign(&kp.secret_key_hex()).expect("sign");
            chain.mempool.push(tx);
        }

        let next_index = chain.height() + 1;
        let subsidy = Blockchain::calculate_reward(next_index);
        let (txs, fees, _root) = chain
            .build_block_candidate(chain.mempool.clone(), &to, next_index, subsidy)
            .expect("candidate");

        assert_eq!(txs.len(), 5, "every pending transaction must be selected");
        assert_eq!(fees, 5 * 1_000_000);
        let nonces: Vec<u64> = txs.iter().map(|t| t.nonce).collect();
        assert_eq!(nonces, vec![0, 1, 2, 3, 4], "nonce order must be kept");
    });
}
