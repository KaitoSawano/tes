// Fee market: default fee stays 0.01 XEPC, rises when the mempool has a
// backlog of more than one block.

use serial_test::serial;
use std::sync::Mutex;
use xepay::blockchain::{Blockchain, DEFAULT_FEE_ALD, TYPICAL_TX_SIZE_BYTES};
use xepay::transaction::Transaction;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn with_temp_datadir<F: FnOnce()>(f: F) {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("tempdir failed");
    std::env::set_var("XEPC_DATADIR", dir.path());
    f();
    std::env::remove_var("XEPC_DATADIR");
}

fn fake_tx(i: usize, fee: u64) -> Transaction {
    Transaction {
        txid: format!("tx{}", i),
        from: format!("s{}", i),
        to: "dest".to_string(),
        amount: 1,
        fee,
        nonce: 0,
        note: String::new(),
        public_key: Vec::new(),
        signature: Vec::new(),
        output_script: String::new(),
    }
}

#[test]
fn default_fee_is_one_hundredth_xepc() {
    assert_eq!(DEFAULT_FEE_ALD, 1_000_000); // 0.01 XEPC
}

#[test]
#[serial]
fn uncongested_mempool_uses_default_fee() {
    with_temp_datadir(|| {
        let mut chain = Blockchain::new();
        for i in 0..10 {
            chain.mempool.push(fake_tx(i, 5_000_000));
        }
        assert_eq!(chain.next_block_fee_rate(), 0);
        assert_eq!(chain.suggested_fee(TYPICAL_TX_SIZE_BYTES), DEFAULT_FEE_ALD);
    });
}

#[test]
#[serial]
fn backlog_raises_suggested_fee_above_default() {
    with_temp_datadir(|| {
        let mut chain = Blockchain::new();
        // One full block of high-paying transactions (tiny size => high rate).
        for i in 0..xepay::consensus::rules::MAX_TX_PER_BLOCK {
            chain.mempool.push(fake_tx(i, 50_000_000));
        }
        let rate = chain.next_block_fee_rate();
        assert!(rate > 0);
        assert!(chain.suggested_fee(TYPICAL_TX_SIZE_BYTES) > DEFAULT_FEE_ALD);
    });
}
