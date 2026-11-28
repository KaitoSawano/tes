// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Storage layer for XEPAY.
//!
//! Legacy storage functions (blocks, mempool, state snapshot) live in this
//! file as well; the submodules are in `src/storage/`.

pub mod account;
pub mod state;
pub mod block_store;
pub mod block_index;
pub mod undo;
pub mod trie;

pub use account::Account;
pub use state::{StateDB, StateTip};
pub use block_store::BlockStore;
pub use block_index::{BlockIndex, BlockIndexEntry, BlockStatus};
pub use undo::{UndoData, UndoEntry};

// P2P-only helper: write the block to disk without touching the state.
// This keeps P2P from interfering with the mining process.
pub fn save_block_only(block: &crate::block::Block) -> Result<(), String> {
    let store = BlockStore::open_default()
        .map_err(|e| format!("failed to open block store: {}", e))?;
    store.write_block(block, BlockStatus::Active)
        .map_err(|e| format!("failed to write block: {}", e))?;
    Ok(())
}

/// Save a block that has been validated but does not extend the current
/// active chain. The block is stored on disk and indexed with the
/// `ValidFork` status, so that it can be connected later if its branch
/// gains more chainwork.
pub fn save_side_chain_block(block: &crate::block::Block) -> Result<(), String> {
    let store = BlockStore::open_default()
        .map_err(|e| format!("failed to open block store: {}", e))?;
    store.write_block(block, BlockStatus::ValidFork)
        .map_err(|e| format!("failed to write side chain block: {}", e))?;
    Ok(())
}

/// Switch the status of a stored block. Used during a reorganization to
/// demote the old active tip to `ValidFork` and promote the new tip to
/// `Active`.
pub fn set_block_status(hash: &str, status: BlockStatus) -> Result<(), String> {
    let store = BlockStore::open_default()
        .map_err(|e| format!("failed to open block store: {}", e))?;
    store.set_status(hash, status)
        .map_err(|e| format!("failed to update block status: {}", e))?;
    Ok(())
}

use std::collections::BTreeMap;
use std::io::{Error, Read, Write};

use crate::block::Block;
use crate::blockchain::Blockchain;
use crate::consensus::genesis;
use crate::consensus::spec;
use crate::datadir;
use crate::validation;

pub const BLOCKS_PER_FILE: usize = 1000;

/// Persist the chain to disk.
///
/// The order of operations is important:
///   1. Flush the state database so that every pending write reaches
///      the backing store.
///   2. Save the mempool and state snapshot.
///   3. Persist every block that is not yet in the append-only block store.
///
/// Blocks are normally written to disk by `save_block_only` as soon as they
/// are accepted through P2P, but blocks produced by the local miner
/// (`generatetoaddress`) or submitted through RPC (`submitblock`) never go
/// through that path. This function closes the gap: it walks the in-memory
/// chain and appends any missing block to the block store. `write_block` is
/// idempotent, so calling it on every save is safe.
pub fn save_chain(chain: &mut Blockchain) -> std::io::Result<()> {
    datadir::ensure_dirs()?;

    // Step 1: flush the state database so that every pending write
    // reaches the backing store.
    chain
        .state
        .flush()
        .map_err(|e| Error::other(format!("failed to flush state: {}", e)))?;

    // Step 2: persist mempool and the state snapshot.
    save_mempool(&chain.mempool)?;
    save_state_snapshot(chain)?;

    // Step 3: persist every block to the append-only block store.
    // `write_block` is idempotent, so re-writing already-stored blocks
    // is harmless and guarantees that locally mined blocks are persisted.
    if let Ok(store) = BlockStore::open_default() {
        for block in &chain.chain {
            if let Err(e) = store.write_block(block, BlockStatus::Active) {
                eprintln!(
                    "[storage] WARNING: failed to persist block {}: {}",
                    block.index, e
                );
            }
        }
    }

    Ok(())
}

pub fn load_chain() -> std::io::Result<Blockchain> {
    let db_path = datadir::state_db_path();

    let store = BlockStore::open_default()
        .map_err(|e| Error::other(format!("failed to open block store: {}", e)))?;

    let mut blocks = store
        .all_blocks()
        .map_err(|e| Error::other(format!("failed to read blocks: {}", e)))?;

    let expected_genesis_hash =
        genesis::expected_genesis_hash_for(spec::current_network());

    // If the block store does not start with genesis, try to find it
    // among the stored blocks and prepend it. This handles datadirs that
    // were created by older versions of the code, which never persisted
    // the genesis block to the append-only store.
    if !blocks.is_empty()
        && (blocks[0].index != 0 || blocks[0].hash != expected_genesis_hash)
    {
        if let Some(pos) = blocks
            .iter()
            .position(|b| b.index == 0 && b.hash == expected_genesis_hash)
        {
            let genesis_block = blocks.remove(pos);
            blocks.insert(0, genesis_block);
            if let Err(e) = store.write_block(&blocks[0], BlockStatus::Active) {
                eprintln!(
                    "[storage] WARNING: failed to persist recovered genesis block: {}",
                    e
                );
            }
        }
    }

    // Fallback: if the block index is empty (for example, because the
    // datadir was created before the append-only block store was
    // introduced), read blocks from the legacy whole-Vec files and
    // re-index them into the block store so that future starts are fast.
    if blocks.is_empty() {
        let legacy = load_blocks()?;
        if !legacy.is_empty() {
            for block in &legacy {
                let _ = store.write_block(block, BlockStatus::Active);
            }
            blocks = legacy;
        }
    }

    if blocks.is_empty() {
        return Ok(Blockchain::new());
    }

    // If the stored chain still does not start with genesis, reconstruct
    // the genesis block from the compiled-in parameters and prepend it.
    // This is safe because the genesis block is deterministic and the
    // first stored block must extend it. Datadirs created before the
    // genesis block was persisted to the block store fall into this
    // branch and are recovered without requiring a full reindex.
    if blocks[0].index != 0 {
        let genesis_block = Block::genesis();
        if blocks[0].index == 1
            && blocks[0].previous_hash == genesis_block.hash
            && genesis_block.hash == expected_genesis_hash
        {
            if let Err(e) = store.write_block(&genesis_block, BlockStatus::Active) {
                eprintln!(
                    "[storage] WARNING: failed to persist reconstructed genesis block: {}",
                    e
                );
            }
            blocks.insert(0, genesis_block);
        } else {
            return Err(Error::other(
                "consensus failure: the first block on disk is not the genesis block.",
            ));
        }
    }
    if blocks[0].previous_hash != crate::consensus::genesis::GENESIS_PREVIOUS_HASH {
        return Err(Error::other(
            "consensus failure: the genesis block previous_hash is not zero.",
        ));
    }

    // ------------------------------------------------------------------
    // Genesis hash validation
    // ------------------------------------------------------------------
    //
    // Verify that the genesis block on disk matches the expected genesis
    // hash for the current network. If it does not match, the on-disk
    // chain was created with a different genesis block (for example,
    // before a hard fork) and must be reindexed or deleted.
    //
    // This check mirrors the behaviour of reference node implementations,
    // which refuse to start when the on-disk genesis block does not match
    // the consensus parameters compiled into the binary.
    if blocks[0].hash != expected_genesis_hash {
        return Err(Error::other(format!(
            "consensus failure: the genesis block on disk (hash {}) does not match \
             the expected genesis hash ({}). The on-disk chain was created with a \
             different genesis block. This usually means the datadir was created \
             before a hard fork. To fix, delete the datadir and restart:\n\
             \n    rm -rf {}\n\
             \nAlternatively, run with -reindex to rebuild the state from the \
             block history. Note that -reindex alone does not replace the genesis \
             block; if the genesis hash does not match, the datadir must be deleted.",
            blocks[0].hash,
            expected_genesis_hash,
            datadir::as_str(&datadir::datadir())
        )));
    }

    // Structural integrity check of the stored chain: every block must sit at
    // its own height and link to its predecessor. A gap, a duplicate height
    // or a broken link means the block data is damaged or incomplete. By
    // default this is reported loudly; set XEPAY_STRICT_CHAIN=1 to refuse to
    // start instead.
    if let Some(problem) = chain_continuity_problem(&blocks) {
        eprintln!(
            "[node] WARNING: block store continuity check failed: {}",
            problem
        );
        eprintln!("[node] The stored chain has a gap, a duplicate height or a broken hash link.");
        if std::env::var("XEPAY_STRICT_CHAIN").is_ok() {
            return Err(Error::other(format!(
                "consensus failure: the block store is not a continuous chain: {}",
                problem
            )));
        }
    }

    let mempool = load_mempool().unwrap_or_default();

    // Check the reindex mode.
    let reindex_requested = std::env::var("XEPAY_REINDEX").is_ok();

    if reindex_requested {
        eprintln!("[node] Manual reindex requested. Deleting state database...");
        let _ = std::fs::remove_dir_all(&db_path);
        let _ = crate::storage::undo::delete_all();
    }

    // A corrupt state database is not fatal: it is derived data, so it is
    // wiped and rebuilt from the block store.
    // A database that is merely LOCKED by another running node is not
    // corrupt and is never wiped (see `open_state_db`).
    let state = open_state_db(&db_path)?;

    let mut chain = Blockchain {
        chain: blocks,
        nbits: crate::consensus::spec::current_network().genesis_nbits(),
        mempool,
        balances: std::collections::HashMap::new(),
        nonces: std::collections::HashMap::new(),
        mempool_timestamps: std::collections::HashMap::new(),
        addresses: Vec::new(),
        state,
    };

    // Populate the address list from the state snapshot and from the
    // block history. The address list is used by GetStateRange to serve
    // accounts to peers during fast sync, so it must be complete even if
    // the snapshot file is missing or empty.
    chain.addresses.push("GENESIS".to_string());

    let snapshot_path = datadir::chainstate_dir().join("state_snapshot.json");
    if let Ok(data) = std::fs::read_to_string(&snapshot_path) {
        if let Ok(map) =
            serde_json::from_str::<std::collections::HashMap<String, serde_json::Value>>(&data)
        {
            for addr in map.keys() {
                if !chain.addresses.contains(addr) {
                    chain.addresses.push(addr.clone());
                }
            }
        }
    }

    // Always walk the block history to recover addresses that are not
    // present in the snapshot. This is cheap because the chain is
    // already loaded in memory.
    for block in chain.chain.iter() {
        if !block.mined_for.is_empty() && !chain.addresses.contains(&block.mined_for) {
            chain.addresses.push(block.mined_for.clone());
        }
        for tx in &block.transactions {
            if validation::is_special_tx(tx) {
                continue;
            }
            if !chain.addresses.contains(&tx.from) {
                chain.addresses.push(tx.from.clone());
            }
            if !chain.addresses.contains(&tx.to) {
                chain.addresses.push(tx.to.clone());
            }
        }
    }

    println!(
        "[node] loaded {} addresses from state snapshot and block history",
        chain.addresses.len()
    );

    // Always verify that the on-disk state matches the chain tip. If it
    // does not, rebuild the state from the block history. This handles
    // three cases that all look the same to the node:
    //   1. The state database was deleted while the block store was kept.
    //   2. The state database was written by a build that did not flush
    //      every update, and the process was killed before the flush.
    //   3. The state database was reset by a reorganization that failed
    //      halfway through, leaving the chain tip ahead of the state.
    //
    // The check runs on every start, not only when the state looks empty,
    // because an empty-looking state with a non-empty chain is exactly
    // the failure mode that produced a state that lags the chain tip.
    // A malformed rule schedule must stop the node before anything else.
    if let Err(e) = crate::consensus::rules::validate_schedule() {
        eprintln!("[node] FATAL: invalid rule schedule: {}", e);
        std::process::exit(1);
    }
    // A malformed checkpoint table must stop the node before anything else.
    if let Err(e) = crate::blockchain::checkpoint::self_check() {
        eprintln!("[node] FATAL: invalid checkpoint table: {}", e);
        std::process::exit(1);
    }
    // An explicit reindex always replays every block (and verifies each
    // declared state root); otherwise the state is recovered from its
    // atomic tip marker.
    let recovered = if reindex_requested {
        rebuild_state_from_blocks(&mut chain).map_err(|e| e.to_string())
    } else {
        recover_state(&mut chain)
    };
    if let Err(e) = recovered {
        eprintln!("[node] FATAL: state recovery failed: {}", e);
        std::process::exit(1);
    }
    // The difficulty is derived from the chain; recompute it after loading.
    chain.adjust_difficulty();
    // Checkpoints are enforced on the stored chain too, not only on new blocks.
    if let Err(e) = crate::blockchain::checkpoint::verify_chain(&chain.chain) {
        eprintln!("[node] FATAL: stored chain violates a checkpoint: {}", e);
        eprintln!("[node] The data directory is corrupt, tampered with or on another fork.");
        eprintln!("[node] Remove the block data and resync from the network.");
        std::process::exit(1);
    }

    if reindex_requested {
        eprintln!("[node] Reindex complete.");
    }

    Ok(chain)
}

/// Return a description of the first structural problem in the loaded
/// chain, or `None` when it is a continuous chain starting at genesis.
fn chain_continuity_problem(blocks: &[Block]) -> Option<String> {
    for i in 1..blocks.len() {
        if blocks[i].index != i as u64 {
            return Some(format!(
                "position {} holds a block with height {}",
                i, blocks[i].index
            ));
        }
        if blocks[i].previous_hash != blocks[i - 1].hash {
            return Some(format!(
                "block {} does not link to block {}",
                i,
                i - 1
            ));
        }
    }
    None
}

/// Open the state database.
///
/// If it is locked by another process (for example a second `xepayd` was
/// started on the same data directory) wait for the lock to be released and
/// then fail WITHOUT touching the files: wiping a database that another node
/// is still using would destroy its state. Only a database that is really
/// unreadable is wiped and rebuilt from the block store (it is derived data).
fn open_state_db(db_path: &std::path::Path) -> std::io::Result<crate::storage::StateDB> {
    let mut waited = 0u32;
    loop {
        match crate::storage::StateDB::open(db_path) {
            Ok(s) => return Ok(s),
            Err(e) if crate::storage::block_index::is_lock_error(&e) => {
                if waited >= 15 {
                    return Err(Error::other(format!(
                        "the state database is locked by another process ({}). \
                         Is another xepayd already running on this data directory? \
                         Stop it first with `./xepay stop`.",
                        e
                    )));
                }
                if waited == 0 {
                    eprintln!(
                        "[node] state db is locked by another process; waiting for it to be released..."
                    );
                }
                waited += 1;
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            Err(e) => {
                eprintln!("[node] state db unreadable ({}); recreating", e);
                let _ = std::fs::remove_dir_all(db_path);
                return crate::storage::StateDB::open(db_path)
                    .map_err(|e| Error::other(format!("failed to open state db: {}", e)));
            }
        }
    }
}

/// Return true when the on-disk state matches the chain tip.
///
/// The check counts the number of distinct addresses that appear in the
/// chain history, and compares that count with the number of accounts
/// currently stored in the state database. A state that was rebuilt from
/// an incomplete block history contains fewer accounts than the chain
/// requires, even when the reward of the tip block is present.
///
/// This is the check that catches the failure mode where the state
/// contains the reward of the tip block but not the transactions that
/// came before it: the reward entry is present, but most of the accounts
/// that the chain history touches are missing.
fn state_matches_chain_tip(chain: &Blockchain) -> bool {
    let tip = match chain.chain.last() {
        Some(t) => t,
        None => return true,
    };

    if tip.index == 0 {
        return true;
    }

    // Count the distinct addresses that the chain history touches.
    let mut expected: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    expected.insert("GENESIS".to_string());
    for block in &chain.chain {
        if !block.mined_for.is_empty() {
            expected.insert(block.mined_for.clone());
        }
        for tx in &block.transactions {
            if validation::is_special_tx(tx) {
                continue;
            }
            expected.insert(tx.from.clone());
            expected.insert(tx.to.clone());
        }
    }

    let actual = chain.state.account_count();
    if actual < expected.len() {
        return false;
    }

    // Verify that the miner of the tip block has the reward of the tip
    // block in the state. A state that lags the chain tip will be
    // missing that entry.
    match chain.state.get_account(&tip.mined_for) {
        Ok(Some(acc)) => acc.immature_rewards.contains_key(&tip.index),
        _ => false,
    }
}

fn rebuild_state_from_blocks(chain: &mut Blockchain) -> std::io::Result<()> {
    rebuild_state_upto(chain, u64::MAX).map_err(Error::other)?;
    println!(
        "[node] reindex populated {} addresses",
        chain.addresses.len()
    );
    Ok(())
}

/// Rebuild the state by replaying blocks 1..=target_height through the
/// same atomic `connect_block` used for live blocks. From the activation
/// height every block's declared state root is verified on the way, so a
/// reindex doubles as a full consistency check.
pub fn rebuild_state_upto(chain: &mut Blockchain, target_height: u64) -> Result<(), String> {
    chain.state.reset()?;
    // Crash marker: if the process dies during the rebuild, the next
    // start sees this impossible height and rebuilds again instead of
    // trusting a half-built state.
    chain.state.set_tip(&crate::storage::StateTip {
        height: u64::MAX,
        hash: "rebuilding".to_string(),
        state_root: String::new(),
    })?;
    let genesis = chain
        .chain
        .first()
        .ok_or_else(|| "chain is empty".to_string())?
        .clone();
    chain.state.update_account(
        "GENESIS",
        &Account {
            nonce: 0,
            balance: genesis.reward,
            immature_rewards: BTreeMap::new(),
            code: Vec::new(),
            storage: BTreeMap::new(),
        },
    )?;
    let end = (target_height.min(usize::MAX as u64) as usize).min(chain.chain.len() - 1);
    for i in 1..=end {
        let b = chain.chain[i].clone();
        chain
            .connect_block(&b)
            .map_err(|e| format!("rebuild failed at block {}: {}", b.index, e))?;
    }
    if end == 0 {
        chain.state.set_tip(&crate::storage::StateTip {
            height: 0,
            hash: genesis.hash.clone(),
            state_root: String::new(),
        })?;
    }
    chain.state.flush()
}

/// Bring the state database in line with the block store after a start.
///
/// The tip marker is written atomically with every block, so after a
/// crash the state is exactly at some block height:
///  - same tip: nothing to do (the trie root is re-checked);
///  - one or more blocks behind: the missing blocks are replayed;
///  - exactly one block ahead (block saved late): rolled back with undo;
///  - anything else, or a root mismatch: full rebuild.
fn recover_state(chain: &mut Blockchain) -> Result<(), String> {
    let tip = chain.chain.last().cloned().ok_or("chain is empty")?;
    let st = match chain.state.tip() {
        Some(t) => t,
        None => {
            // State written by an older build (no tip marker).
            if chain.chain.len() <= 1 || state_matches_chain_tip(chain) {
                let root = chain.state.state_root();
                return chain.state.set_tip(&crate::storage::StateTip {
                    height: tip.index,
                    hash: tip.hash.clone(),
                    state_root: root,
                });
            }
            return rebuild_state_upto(chain, u64::MAX);
        }
    };

    let root_ok = |chain: &Blockchain, t: &crate::storage::StateTip| -> bool {
        let computed = chain.state.state_root();
        computed == t.state_root || !crate::consensus::rules::state_root_active(t.height)
    };

    if st.height == tip.index {
        let declared_ok = !crate::consensus::rules::state_root_active(tip.index)
            || st.state_root == tip.state_root;
        if st.hash == tip.hash && declared_ok && root_ok(chain, &st) {
            return Ok(());
        }
        eprintln!("[node] state tip/root mismatch at height {}", tip.index);
        return rebuild_state_upto(chain, u64::MAX);
    }

    if st.height < tip.index {
        let known = &chain.chain[st.height as usize];
        if known.hash != st.hash || !root_ok(chain, &st) {
            return rebuild_state_upto(chain, u64::MAX);
        }
        eprintln!(
            "[node] state is {} block(s) behind; replaying",
            tip.index - st.height
        );
        for i in (st.height as usize + 1)..chain.chain.len() {
            let b = chain.chain[i].clone();
            if chain.connect_block(&b).is_err() {
                return rebuild_state_upto(chain, u64::MAX);
            }
        }
        return Ok(());
    }

    if st.height == tip.index + 1 {
        let new_tip = crate::storage::StateTip {
            height: tip.index,
            hash: tip.hash.clone(),
            state_root: tip.state_root.clone(),
        };
        if chain.state.rollback_block(st.height, &new_tip)? {
            return Ok(());
        }
    }
    rebuild_state_upto(chain, u64::MAX)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AccountSnapshot {
    nonce: u64,
    balance: u64,
    /// Immature rewards keyed by height. The snapshot mirrors the
    /// in-memory account representation so that a snapshot written by an
    /// older build (which stored a `Vec`) fails to deserialize instead
    /// of silently producing a different state.
    immature_rewards: BTreeMap<u64, u64>,
    code: Vec<u8>,
    storage: Vec<(String, String)>,
}

pub fn save_state_snapshot(chain: &Blockchain) -> std::io::Result<()> {
    // Write the snapshot even if the address list is small, so that
    // load_chain can recover the addresses from it on the next start.
    let mut accounts: std::collections::HashMap<String, AccountSnapshot> =
        std::collections::HashMap::new();

    for addr in &chain.addresses {
        if let Ok(Some(acc)) = chain.state.get_account(addr) {
            let storage_hex: Vec<(String, String)> = acc
                .storage
                .iter()
                .map(|(k, v)| (hex::encode(k), hex::encode(v)))
                .collect();
            accounts.insert(
                addr.clone(),
                AccountSnapshot {
                    nonce: acc.nonce,
                    balance: acc.balance,
                    immature_rewards: acc.immature_rewards,
                    code: acc.code,
                    storage: storage_hex,
                },
            );
        }
    }

    let json = serde_json::to_string_pretty(&accounts).map_err(Error::other)?;
    datadir::write_atomic(
        &datadir::chainstate_dir().join("state_snapshot.json"),
        json.as_bytes(),
        false,
    )
}

/// Write all blocks in the chain to the legacy whole-Vec block files.
///
/// This function is kept for backward compatibility with datadirs
/// created before the append-only block store was introduced. New
/// blocks are written by `save_block_only` through the block store.
pub fn save_blocks(chain: &Blockchain) -> std::io::Result<()> {
    let total = chain.chain.len();
    let mut file_index = 0u32;
    let mut written = 0usize;

    while written < total {
        let end = (written + BLOCKS_PER_FILE).min(total);
        let slice = &chain.chain[written..end];
        let path = datadir::block_file(file_index);

        let encoded = bincode::serialize(slice)
            .map_err(|e| Error::other(format!("bincode serialize error: {}", e)))?;

        let mut file = std::fs::File::create(path)?;
        file.write_all(&encoded)?;
        file.flush()?;

        written = end;
        file_index += 1;
    }
    Ok(())
}

/// Load all blocks from the legacy whole-Vec block files.
///
/// The loader tries the whole-`Vec<Block>` format first, because that is
/// the format written by `save_blocks` and used by datadirs created
/// before the append-only block store was introduced. If that fails, it
/// falls back to the length-prefixed append format written by
/// `crate::storage::save_block_only`.
pub fn load_blocks() -> std::io::Result<Vec<Block>> {
    let mut all: Vec<Block> = Vec::new();
    let mut i = 0u32;

    loop {
        let path = datadir::block_file(i);
        if !path.exists() {
            break;
        }

        let mut file = std::fs::File::open(&path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        if buffer.is_empty() {
            i += 1;
            continue;
        }

        // Try the whole-Vec format first.
        match bincode::deserialize::<Vec<Block>>(&buffer) {
            Ok(mut chunk) => {
                all.append(&mut chunk);
                i += 1;
                continue;
            }
            Err(_) => {}
        }

        // Fall back to the length-prefixed append format.
        let mut offset = 0usize;
        let mut ok = true;
        let mut blocks = Vec::new();
        while offset + 4 <= buffer.len() {
            let len_bytes = &buffer[offset..offset + 4];
            let len = u32::from_le_bytes([
                len_bytes[0],
                len_bytes[1],
                len_bytes[2],
                len_bytes[3],
            ]) as usize;
            offset += 4;
            if offset.checked_add(len).map_or(true, |end| end > buffer.len()) {
                ok = false;
                break;
            }
            match Block::from_bincode(&buffer[offset..offset + len]) {
                Ok(b) => blocks.push(b),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
            offset += len;
        }

        if ok && !blocks.is_empty() {
            all.extend(blocks);
            i += 1;
            continue;
        }

        return Err(Error::other(format!(
            "bincode deserialize error in {}",
            path.display()
        )));
    }
    Ok(all)
}

pub fn save_mempool(mempool: &[crate::transaction::Transaction]) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(mempool).map_err(Error::other)?;
    datadir::write_atomic(&datadir::mempool_path(), json.as_bytes(), false)
}

pub fn load_mempool() -> std::io::Result<Vec<crate::transaction::Transaction>> {
    let data = std::fs::read_to_string(datadir::mempool_path())?;
    let v: Vec<crate::transaction::Transaction> =
        serde_json::from_str(&data).map_err(Error::other)?;
    Ok(v)
}
