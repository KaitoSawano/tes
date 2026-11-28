// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

use std::path::PathBuf;

use xepay::block::Block;
use xepay::datadir;
use xepay::storage::block_index::{is_lock_error, BlockStatus};
use xepay::storage::block_store::BlockStore;

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("xepay_{}_{}_{}", tag, std::process::id(), nanos));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn write_atomic_replaces_file_and_leaves_no_temp_file() {
    let dir = temp_dir("atomic");
    let path = dir.join("data.json");

    datadir::write_atomic(&path, b"first", false).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"first");

    datadir::write_atomic(&path, b"second, longer than the first", false).unwrap();
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"second, longer than the first"
    );

    // Shorter content must not leave a tail of the previous version.
    datadir::write_atomic(&path, b"x", false).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"x");

    assert!(!dir.join("data.json.tmp").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn write_atomic_private_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_dir("private");
    let path = dir.join("wallet.dat");

    // Even over an existing world-readable file the result must be 0600.
    std::fs::write(&path, b"old").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    datadir::write_atomic(&path, b"secret", true).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(std::fs::read(&path).unwrap(), b"secret");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn block_store_roundtrip_and_truncation_is_detected() {
    let dir = temp_dir("blocks");
    let store = BlockStore::open(&dir).unwrap();

    let genesis = Block::genesis();
    store.write_block(&genesis, BlockStatus::Active).unwrap();

    let read = store.read_block(&genesis.hash).unwrap().unwrap();
    assert_eq!(read.hash, genesis.hash);
    assert_eq!(read.index, 0);

    // Cut the block file short: the record now claims more bytes than the
    // file holds, which must be reported as corruption (not panic, not
    // allocate a huge buffer, not return garbage).
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("blk00000.dat"))
        .unwrap();
    file.set_len(10).unwrap();
    drop(file);

    assert!(store.read_block(&genesis.hash).is_err());
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lock_errors_are_recognised_but_corruption_is_not() {
    assert!(is_lock_error("Status { code: LockError, err: \"lock held\" }"));
    assert!(is_lock_error("Resource temporarily unavailable (os error 11)"));
    // The word "block" contains "lock": it must never count as a lock error,
    // otherwise a corrupt database would no longer be rebuilt.
    assert!(!is_lock_error("Status { code: Corruption, err: \"bad block\" }"));
}
