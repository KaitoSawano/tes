// Tests for the Merkle-trie state root and atomic block commit.

use std::collections::BTreeMap;
use xepay::storage::{Account, StateDB, StateTip};

fn acc(balance: u64) -> Account {
    Account {
        nonce: 0,
        balance,
        immature_rewards: BTreeMap::new(),
        code: Vec::new(),
        storage: BTreeMap::new(),
    }
}

#[test]
fn abort_leaves_state_and_root_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = StateDB::open(&dir.path().join("s")).unwrap();
    db.update_account("alice", &acc(10)).unwrap();
    let r0 = db.state_root();

    db.begin_block().unwrap();
    db.update_account("alice", &acc(1)).unwrap();
    db.update_account("bob", &acc(9)).unwrap();
    let pending = db.pending_root().unwrap();
    assert_ne!(pending, r0);
    db.abort_block();

    assert_eq!(db.state_root(), r0);
    assert_eq!(db.get_account("alice").unwrap().unwrap().balance, 10);
    assert!(db.get_account("bob").unwrap().is_none());
}

#[test]
fn pending_root_equals_committed_root() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = StateDB::open(&dir.path().join("s")).unwrap();
    db.begin_block().unwrap();
    db.update_account("alice", &acc(5)).unwrap();
    db.update_account("bob", &acc(6)).unwrap();
    let pending = db.pending_root().unwrap();
    db.commit_block(1, "h1", &pending).unwrap();
    assert_eq!(db.state_root(), pending);
    assert_eq!(db.tip().unwrap().height, 1);
}

#[test]
fn rollback_restores_root_and_deletes_new_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = StateDB::open(&dir.path().join("s")).unwrap();
    db.begin_block().unwrap();
    db.update_account("alice", &acc(5)).unwrap();
    let r1 = db.pending_root().unwrap();
    db.commit_block(1, "h1", &r1).unwrap();

    db.begin_block().unwrap();
    db.update_account("alice", &acc(1)).unwrap();
    db.update_account("carol", &acc(4)).unwrap();
    let r2 = db.pending_root().unwrap();
    db.commit_block(2, "h2", &r2).unwrap();
    assert_ne!(r1, r2);

    let tip = StateTip { height: 1, hash: "h1".into(), state_root: r1.clone() };
    assert!(db.rollback_block(2, &tip).unwrap());
    assert_eq!(db.state_root(), r1);
    assert!(db.get_account("carol").unwrap().is_none());
    assert_eq!(db.get_account("alice").unwrap().unwrap().balance, 5);
    assert_eq!(db.tip().unwrap().height, 1);
}

#[test]
fn reopen_rebuilds_same_root() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s");
    let root;
    {
        let mut db = StateDB::open(&path).unwrap();
        db.begin_block().unwrap();
        for i in 0..40u64 {
            db.update_account(&format!("addr{}", i), &acc(i + 1)).unwrap();
        }
        root = db.pending_root().unwrap();
        db.commit_block(1, "h1", &root).unwrap();
    }
    let db = StateDB::open(&path).unwrap();
    assert_eq!(db.state_root(), root);
    assert_eq!(db.tip().unwrap().state_root, root);
    assert_eq!(db.account_count(), 40);
}

#[test]
fn supply_delta_counts_only_new_money() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = StateDB::open(&dir.path().join("s")).unwrap();
    db.update_account("alice", &acc(100)).unwrap();

    // Moving value between accounts changes nothing.
    db.begin_block().unwrap();
    db.update_account("alice", &acc(60)).unwrap();
    db.update_account("bob", &acc(40)).unwrap();
    assert_eq!(db.pending_supply_delta().unwrap(), 0);
    db.abort_block();

    // Minting is visible.
    db.begin_block().unwrap();
    db.update_account("alice", &acc(101)).unwrap();
    assert_eq!(db.pending_supply_delta().unwrap(), 1);
    db.abort_block();
}

#[test]
fn reserved_prefix_address_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = StateDB::open(&dir.path().join("s")).unwrap();
    assert!(db.update_account("\u{0}tip", &acc(1)).is_err());
}

#[test]
fn amount_parser_rejects_garbage_and_overflow() {
    use xepay::utils::parse_xepc;
    assert!(parse_xepc("+1").is_err());
    assert!(parse_xepc("1.+5").is_err());
    assert!(parse_xepc("-1").is_err());
    assert!(parse_xepc("184467440737.09551616").is_err());
    assert_eq!(parse_xepc("1.5").unwrap(), 150_000_000);
}

#[test]
fn pubkey_registry_is_atomic_and_part_of_the_root() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = StateDB::open(&dir.path().join("s")).unwrap();
    let r0 = db.state_root();

    // An aborted batch registers nothing.
    db.begin_block().unwrap();
    db.register_pubkey("alice", &[1, 2, 3]).unwrap();
    assert_eq!(db.get_pubkey("alice"), Some(vec![1, 2, 3]));
    assert_ne!(db.pending_root().unwrap(), r0);
    db.abort_block();
    assert!(db.get_pubkey("alice").is_none());
    assert_eq!(db.state_root(), r0);

    // A committed batch persists the key and changes the root.
    db.begin_block().unwrap();
    db.register_pubkey("alice", &[1, 2, 3]).unwrap();
    let r1 = db.pending_root().unwrap();
    db.commit_block(1, "h1", &r1).unwrap();
    assert_eq!(db.get_pubkey("alice"), Some(vec![1, 2, 3]));
    assert_eq!(db.state_root(), r1);

    // Registering twice keeps the first key.
    db.begin_block().unwrap();
    db.register_pubkey("alice", &[9, 9]).unwrap();
    assert_eq!(db.get_pubkey("alice"), Some(vec![1, 2, 3]));
    db.abort_block();

    // Rolling the block back removes the registration again.
    let tip = StateTip { height: 0, hash: "g".into(), state_root: r0.clone() };
    assert!(db.rollback_block(1, &tip).unwrap());
    assert!(db.get_pubkey("alice").is_none());
    assert_eq!(db.state_root(), r0);
}
