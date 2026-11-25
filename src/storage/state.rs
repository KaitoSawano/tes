// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Flat key-value state database backed by LevelDB.
//!
//! Each account is stored under its address bytes. The value is the RLP
//! encoding of the account. On top of the flat store an in-memory Merkle
//! Patricia Trie (`trie.rs`) yields the Merkle-trie state root.
//!
//! Crash safety: a block is applied to an in-memory overlay
//! (`begin_block`), the post-state root is computed and verified, and
//! only then everything (accounts, undo data, tip marker) is written in
//! ONE synced LevelDB WriteBatch (`commit_block`). A crash therefore
//! leaves either the old state or the new one, never a mix.
//! Keys starting with 0x00 are metadata, never accounts.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use rusty_leveldb::{LdbIterator, Options, WriteBatch, DB as LevelDB};

use super::account::Account;
use super::trie::{Hash32, StateTrie};
use super::undo::UndoData;
use xepay_crypto::sha3_256;
use crate::consensus::rules;

/// Move every immature reward whose maturity height has been reached into
/// the spendable balance, and keep the rest in the map. This is the only
/// place where maturity is resolved, so the live path and any other
/// caller cannot disagree about when a reward becomes spendable.
fn settle_maturity(acc: &mut Account, current_height: u64, maturity: u64) -> Result<(), String> {
    let mut still_immature = BTreeMap::new();
    for (height, amount) in std::mem::take(&mut acc.immature_rewards) {
        if current_height >= height.saturating_add(maturity) {
            acc.balance = acc
                .balance
                .checked_add(amount)
                .ok_or_else(|| "balance overflow while maturing reward".to_string())?;
        } else {
            still_immature.insert(height, amount);
        }
    }
    acc.immature_rewards = still_immature;
    Ok(())
}

/// Apply a single transaction to an in-memory account.
///
/// The caller loads the account, calls this function, and stores the
/// result back into the database. The function performs no I/O and reads
/// no global state, so it is the single source of truth for the state
/// transition.
fn apply_tx_to_account(
    from_acc: &mut Account,
    to_acc: Option<&mut Account>,
    tx_from: &str,
    tx_to: &str,
    amount: u64,
    fee: u64,
    nonce: u64,
    current_height: u64,
) -> Result<(), String> {
    let maturity = rules::COINBASE_MATURITY;

    settle_maturity(from_acc, current_height, maturity)?;

    if from_acc.nonce != nonce {
        return Err(format!(
            "invalid nonce: got {}, expected {}",
            nonce, from_acc.nonce
        ));
    }

    let total = amount
        .checked_add(fee)
        .ok_or_else(|| "amount + fee overflows u64".to_string())?;

    if from_acc.balance < total {
        return Err(format!(
            "insufficient mature balance: required {}, available {}",
            total, from_acc.balance
        ));
    }

    from_acc.balance = from_acc
        .balance
        .checked_sub(total)
        .ok_or_else(|| "underflow during deduction".to_string())?;

    from_acc.nonce = from_acc
        .nonce
        .checked_add(1)
        .ok_or_else(|| "sender nonce overflow".to_string())?;

    if tx_from != tx_to {
        let to = to_acc.ok_or_else(|| "recipient account is required".to_string())?;
        to.balance = to
            .balance
            .checked_add(amount)
            .ok_or_else(|| "recipient balance overflow".to_string())?;
    } else {
        from_acc.balance = from_acc
            .balance
            .checked_add(amount)
            .ok_or_else(|| "self-send refund overflow".to_string())?;
    }

    Ok(())
}

/// Record a block reward as an immature reward keyed by the block height.
/// It is moved into the spendable balance lazily by `settle_maturity`
/// when the account is next touched. Because the immature rewards are
/// stored in a `BTreeMap`, the encoding is deterministic.
fn credit_reward_to_account(acc: &mut Account, reward: u64, block_height: u64) -> Result<(), String> {
    let entry = acc.immature_rewards.entry(block_height).or_insert(0u64);
    *entry = entry
        .checked_add(reward)
        .ok_or_else(|| "immature reward overflow".to_string())?;
    Ok(())
}

const META_TIP: &[u8] = b"\x00tip";
const META_UNDO_PREFIX: &[u8] = b"\x00undo";
/// Prefix of the public-key registry entries (address -> public key).
const META_PK_PREFIX: &[u8] = b"\x00pk";

/// Database key of the registry entry of `address`.
fn pk_key(address: &str) -> Vec<u8> {
    let mut k = META_PK_PREFIX.to_vec();
    k.extend_from_slice(address.as_bytes());
    k
}

/// Trie key of a registry entry (separate namespace from accounts).
fn pk_leaf_key(address: &str) -> Hash32 {
    sha3_256(format!("pk|{}", address).as_bytes())
}

fn undo_key(height: u64) -> Vec<u8> {
    let mut k = META_UNDO_PREFIX.to_vec();
    k.extend_from_slice(&height.to_be_bytes());
    k
}

fn is_meta_key(k: &[u8]) -> bool {
    k.first() == Some(&0u8)
}

fn leaf_key(address: &str) -> Hash32 {
    sha3_256(address.as_bytes())
}

fn leaf_value(account: &Account) -> Hash32 {
    sha3_256(&rlp::encode(account))
}

/// Last block whose state was committed atomically.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateTip {
    pub height: u64,
    pub hash: String,
    pub state_root: String,
}

pub struct StateDB {
    db: Mutex<LevelDB>,
    trie: Mutex<StateTrie>,
    /// Pending writes of the block being applied. `None` = no open block.
    overlay: Option<BTreeMap<String, Account>>,
    /// Public keys registered by the block being applied.
    pk_overlay: BTreeMap<String, Vec<u8>>,
}

impl StateDB {
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut opt = Options::default();
        opt.create_if_missing = true;
        let mut db = LevelDB::open(path, opt).map_err(|e| format!("{:?}", e))?;

        // Rebuild the in-memory trie from the flat store.
        let mut trie = StateTrie::new();
        {
            let mut iter = db.new_iter().map_err(|e| format!("{:?}", e))?;
            iter.seek_to_first();
            while let Some((key, value)) = iter.next() {
                if key.starts_with(META_PK_PREFIX) {
                    // Registry entry: goes into the trie under its own key.
                    let addr = String::from_utf8_lossy(&key[META_PK_PREFIX.len()..]).to_string();
                    trie.set(pk_leaf_key(&addr), sha3_256(&value));
                    continue;
                }
                if is_meta_key(&key) {
                    continue;
                }
                let account: Account = rlp::decode(&value)
                    .map_err(|e| format!("corrupt account record: {}", e))?;
                let addr = String::from_utf8_lossy(&key).to_string();
                trie.set(leaf_key(&addr), leaf_value(&account));
            }
        }
        Ok(StateDB {
            db: Mutex::new(db),
            trie: Mutex::new(trie),
            overlay: None,
            pk_overlay: BTreeMap::new(),
        })
    }

    /// Committed state root (hex). Valid only when no block is open.
    pub fn state_root(&self) -> String {
        hex::encode(self.trie.lock().unwrap().root())
    }

    /// Tip marker written by the last atomic commit, if any.
    pub fn tip(&self) -> Option<StateTip> {
        let mut db = self.db.lock().unwrap();
        db.get(META_TIP)
            .and_then(|v| bincode::deserialize::<StateTip>(&v).ok())
    }

    /// Write the tip marker directly (genesis / reindex / migration).
    pub fn set_tip(&mut self, tip: &StateTip) -> Result<(), String> {
        let mut db = self.db.lock().unwrap();
        let bytes = bincode::serialize(tip).map_err(|e| e.to_string())?;
        db.put(META_TIP, &bytes).map_err(|e| format!("{:?}", e))?;
        db.flush().map_err(|e| format!("{:?}", e))
    }

    /// Net change of the total money (balance + immature rewards) over all
    /// accounts the open batch touches. A valid block must change it by
    /// exactly its subsidy: transfers and fees only move value around.
    pub fn pending_supply_delta(&self) -> Result<i128, String> {
        fn total(a: &Account) -> u128 {
            a.immature_rewards
                .values()
                .fold(a.balance as u128, |s, v| s + *v as u128)
        }
        let ov = self
            .overlay
            .as_ref()
            .ok_or_else(|| "no open block batch".to_string())?;
        let mut db = self.db.lock().unwrap();
        let mut delta: i128 = 0;
        for (addr, acc) in ov.iter() {
            let old = match db.get(&Self::address_key(addr)) {
                Some(v) => total(
                    &rlp::decode::<Account>(&v).map_err(|e| format!("RLP decode error: {}", e))?,
                ),
                None => 0,
            };
            delta = delta
                .checked_add(total(acc) as i128 - old as i128)
                .ok_or_else(|| "supply delta overflow".to_string())?;
        }
        Ok(delta)
    }

    /// Open a block batch. All writes go to memory until `commit_block`.
    pub fn begin_block(&mut self) -> Result<(), String> {
        if self.overlay.is_some() {
            return Err("a block batch is already open".to_string());
        }
        self.overlay = Some(BTreeMap::new());
        self.pk_overlay.clear();
        Ok(())
    }

    /// Discard the open batch. Nothing was written to disk.
    pub fn abort_block(&mut self) {
        self.overlay = None;
        self.pk_overlay.clear();
    }

    /// Public key registered for `address`, if any (open batch first).
    pub fn get_pubkey(&self, address: &str) -> Option<Vec<u8>> {
        if let Some(pk) = self.pk_overlay.get(address) {
            return Some(pk.clone());
        }
        let mut db = self.db.lock().unwrap();
        db.get(&pk_key(address))
    }

    /// Remember the public key of `address` (no-op if already registered).
    /// Inside a block batch the entry is committed with the block.
    pub fn register_pubkey(&mut self, address: &str, pk: &[u8]) -> Result<(), String> {
        if pk.is_empty() || self.get_pubkey(address).is_some() {
            return Ok(());
        }
        if self.overlay.is_some() {
            self.pk_overlay.insert(address.to_string(), pk.to_vec());
            return Ok(());
        }
        let mut db = self.db.lock().unwrap();
        db.put(&pk_key(address), pk).map_err(|e| format!("{:?}", e))?;
        drop(db);
        self.trie.lock().unwrap().set(pk_leaf_key(address), sha3_256(pk));
        Ok(())
    }

    pub fn has_open_block(&self) -> bool {
        self.overlay.is_some()
    }

    /// State root as it would be after the open batch (hex).
    pub fn pending_root(&mut self) -> Result<String, String> {
        let overlay = self
            .overlay
            .as_ref()
            .ok_or_else(|| "no open block batch".to_string())?;
        let mut trie = self.trie.lock().unwrap();
        let mut undo: Vec<(Hash32, Option<Hash32>)> = Vec::with_capacity(overlay.len());
        for (addr, acc) in overlay.iter() {
            let k = leaf_key(addr);
            let old = trie.set(k, leaf_value(acc));
            undo.push((k, old));
        }
        for (addr, pk) in self.pk_overlay.iter() {
            let k = pk_leaf_key(addr);
            let old = trie.set(k, sha3_256(pk));
            undo.push((k, old));
        }
        let root = trie.root();
        for (k, old) in undo.into_iter().rev() {
            match old {
                Some(v) => {
                    trie.set(k, v);
                }
                None => {
                    trie.remove(&k);
                }
            }
        }
        Ok(hex::encode(root))
    }

    /// Atomically persist the open batch together with its undo data and
    /// the new tip marker (one synced WriteBatch).
    pub fn commit_block(&mut self, height: u64, hash: &str, state_root: &str) -> Result<(), String> {
        let overlay = self
            .overlay
            .take()
            .ok_or_else(|| "no open block batch".to_string())?;

        let mut db = self.db.lock().unwrap();
        let mut undo = UndoData::new(height);
        let mut batch = WriteBatch::new();
        for (addr, acc) in overlay.iter() {
            let key = Self::address_key(addr);
            let old = match db.get(&key) {
                Some(v) => Some(
                    rlp::decode::<Account>(&v).map_err(|e| format!("RLP decode error: {}", e))?,
                ),
                None => None,
            };
            undo.record(addr, old);
            batch.put(&key, &rlp::encode(acc));
        }
        for (addr, pk) in self.pk_overlay.iter() {
            batch.put(&pk_key(addr), pk);
            undo.registered.push(addr.clone());
        }
        let undo_bytes = bincode::serialize(&undo).map_err(|e| e.to_string())?;
        batch.put(&undo_key(height), &undo_bytes);
        if height > rules::UNDO_RETENTION {
            batch.delete(&undo_key(height - rules::UNDO_RETENTION));
        }
        let tip = StateTip {
            height,
            hash: hash.to_string(),
            state_root: state_root.to_string(),
        };
        batch.put(META_TIP, &bincode::serialize(&tip).map_err(|e| e.to_string())?);
        db.write(batch, true).map_err(|e| format!("{:?}", e))?;
        drop(db);

        let mut trie = self.trie.lock().unwrap();
        for (addr, acc) in overlay.iter() {
            trie.set(leaf_key(addr), leaf_value(acc));
        }
        for (addr, pk) in self.pk_overlay.iter() {
            trie.set(pk_leaf_key(addr), sha3_256(pk));
        }
        self.pk_overlay.clear();
        Ok(())
    }

    /// Atomically undo the block at `height` using the undo data stored
    /// with it. Returns Ok(false) when no undo data exists (the caller
    /// must then rebuild the state from the block history).
    pub fn rollback_block(
        &mut self,
        height: u64,
        new_tip: &StateTip,
    ) -> Result<bool, String> {
        if self.overlay.is_some() {
            return Err("cannot roll back while a block batch is open".to_string());
        }
        let mut db = self.db.lock().unwrap();
        let undo: UndoData = match db.get(&undo_key(height)) {
            Some(v) => bincode::deserialize(&v).map_err(|e| e.to_string())?,
            None => return Ok(false),
        };
        let mut batch = WriteBatch::new();
        for e in &undo.entries {
            let key = Self::address_key(&e.address);
            match &e.account {
                Some(a) => batch.put(&key, &rlp::encode(a)),
                None => batch.delete(&key),
            }
        }
        for addr in &undo.registered {
            batch.delete(&pk_key(addr));
        }
        batch.delete(&undo_key(height));
        batch.put(META_TIP, &bincode::serialize(new_tip).map_err(|e| e.to_string())?);
        db.write(batch, true).map_err(|e| format!("{:?}", e))?;
        drop(db);

        let mut trie = self.trie.lock().unwrap();
        for e in &undo.entries {
            let k = leaf_key(&e.address);
            match &e.account {
                Some(a) => {
                    trie.set(k, leaf_value(a));
                }
                None => {
                    trie.remove(&k);
                }
            }
        }
        for addr in &undo.registered {
            trie.remove(&pk_leaf_key(addr));
        }
        Ok(true)
    }

    fn address_key(address: &str) -> Vec<u8> {
        address.as_bytes().to_vec()
    }

    pub fn update_account(&mut self, address: &str, account: &Account) -> Result<(), String> {
        // Keys starting with 0x00 are reserved for metadata.
        if address.as_bytes().first() == Some(&0u8) {
            return Err("invalid address: reserved prefix".to_string());
        }
        if let Some(ov) = self.overlay.as_mut() {
            ov.insert(address.to_string(), account.clone());
            return Ok(());
        }
        let key = Self::address_key(address);
        let value = rlp::encode(account).to_vec();
        let mut db = self.db.lock().unwrap();
        db.put(&key, &value).map_err(|e| format!("{:?}", e))?;
        drop(db);
        self.trie
            .lock()
            .unwrap()
            .set(leaf_key(address), leaf_value(account));
        Ok(())
    }

    pub fn get_account(&self, address: &str) -> Result<Option<Account>, String> {
        if let Some(ov) = self.overlay.as_ref() {
            if let Some(a) = ov.get(address) {
                return Ok(Some(a.clone()));
            }
        }
        let key = Self::address_key(address);
        let mut db = self.db.lock().unwrap();
        match db.get(&key) {
            Some(value) => {
                let account: Account =
                    rlp::decode(&value).map_err(|e| format!("RLP decode error: {}", e))?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    /// Drop every account from the live state and start from an empty
    /// database. This is used by the reorg path to rebuild the state from
    /// the block history after a rollback, because the block header no
    /// longer commits to a state root and there is no shorter way to
    /// undo a state transition.
    pub fn reset(&mut self) -> Result<(), String> {
        let mut db = self.db.lock().unwrap();
        let keys = collect_keys(&mut db)?;
        for key in keys {
            db.delete(&key).map_err(|e| format!("{:?}", e))?;
        }
        db.flush().map_err(|e| format!("{:?}", e))?;
        drop(db);
        self.overlay = None;
        self.pk_overlay.clear();
        self.trie.lock().unwrap().clear();
        Ok(())
    }

    /// Return the number of accounts currently stored in the database.
    /// This is used by the node to decide whether the state database is
    /// empty and needs to be rebuilt from the block history.
    pub fn account_count(&self) -> usize {
        let mut db = self.db.lock().unwrap();
        match collect_keys(&mut db) {
            Ok(keys) => keys.iter().filter(|k| !is_meta_key(k)).count(),
            Err(_) => 0,
        }
    }

    /// Return the total balance of an address.
    ///
    /// Total balance = `acc.balance` (mature) + sum of all
    /// `immature_rewards` (whether mature or not). This is the amount
    /// that would be available if all immature rewards were mature.
    pub fn balance_of(&self, address: &str) -> u64 {
        match self.get_account(address) {
            Ok(Some(acc)) => {
                let immature: u64 = acc
                    .immature_rewards
                    .values()
                    .copied()
                    .fold(0u64, |acc, x| acc.saturating_add(x));
                acc.balance.saturating_add(immature)
            }
            _ => 0,
        }
    }

    /// Return the mature balance of an address at the given height.
    ///
    /// Mature balance = `acc.balance` + sum of `immature_rewards` whose
    /// maturity height has been reached. Rewards that are still immature
    /// are NOT included.
    pub fn mature_balance_at(&self, address: &str, current_height: u64) -> u64 {
        match self.get_account(address) {
            Ok(Some(acc)) => {
                let maturity = crate::consensus::rules::COINBASE_MATURITY;
                let mut mature = acc.balance;
                for (height, amount) in &acc.immature_rewards {
                    if current_height >= height.saturating_add(maturity) {
                        mature = mature.saturating_add(*amount);
                    }
                }
                mature
            }
            _ => 0,
        }
    }

    /// Return the mature balance of an address using the given height.
    pub fn mature_balance_of(&self, address: &str, current_height: u64) -> u64 {
        self.mature_balance_at(address, current_height)
    }

    /// Return the immature balance of an address at the given height.
    ///
    /// Immature balance = sum of `immature_rewards` whose maturity
    /// height has NOT been reached yet.
    pub fn immature_balance_of(&self, address: &str, current_height: u64) -> u64 {
        match self.get_account(address) {
            Ok(Some(acc)) => {
                let maturity = crate::consensus::rules::COINBASE_MATURITY;
                acc.immature_rewards
                    .iter()
                    .filter(|(height, _)| current_height < height.saturating_add(maturity))
                    .map(|(_, amount)| *amount)
                    .sum()
            }
            _ => 0,
        }
    }

    pub fn nonce_of(&self, address: &str) -> u64 {
        match self.get_account(address) {
            Ok(Some(acc)) => acc.nonce,
            _ => 0,
        }
    }

    pub fn get_code(&self, address: &str) -> Vec<u8> {
        match self.get_account(address) {
            Ok(Some(acc)) => acc.code.clone(),
            _ => Vec::new(),
        }
    }

    pub fn get_storage(&self, address: &str) -> BTreeMap<[u8; 32], [u8; 32]> {
        match self.get_account(address) {
            Ok(Some(acc)) => acc.storage.clone(),
            _ => BTreeMap::new(),
        }
    }

    pub fn set_storage(
        &mut self,
        address: &str,
        storage: BTreeMap<[u8; 32], [u8; 32]>,
    ) -> Result<(), String> {
        let mut acc = self.get_account(address)?.unwrap_or_else(empty_account);
        acc.storage = storage;
        self.update_account(address, &acc)
    }

    pub fn apply_transaction(
        &mut self,
        from: &str,
        to: &str,
        amount: u64,
        fee: u64,
        nonce: u64,
        current_height: u64,
    ) -> Result<(), String> {
        if from == to {
            if amount != rules::MIN_MESSAGE_AMOUNT {
                return Err("self-transfer is only allowed for message transactions".to_string());
            }
        }

        if amount == 0 {
            return Err("amount must be greater than zero".to_string());
        }

        let mut from_acc = self.get_account(from)?.unwrap_or_else(empty_account);

        if from == to {
            apply_tx_to_account(
                &mut from_acc,
                None,
                from,
                to,
                amount,
                fee,
                nonce,
                current_height,
            )?;
            self.update_account(from, &from_acc)?;
        } else {
            let mut to_acc = self.get_account(to)?.unwrap_or_else(empty_account);
            apply_tx_to_account(
                &mut from_acc,
                Some(&mut to_acc),
                from,
                to,
                amount,
                fee,
                nonce,
                current_height,
            )?;
            self.update_account(to, &to_acc)?;
            self.update_account(from, &from_acc)?;
        }

        Ok(())
    }

    /// Credit a block reward to the miner account.
    ///
    /// The reward is added to `immature_rewards` and stays there until
    /// it matures. Maturity is resolved lazily by `settle_maturity`,
    /// which is called here before the new reward is pushed so that the
    /// live path resolves maturity at the same point every time. This
    /// keeps `acc.balance` and `acc.immature_rewards` consistent.
    pub fn credit_reward(
        &mut self,
        miner: &str,
        reward: u64,
        block_height: u64,
    ) -> Result<(), String> {
        let mut acc = self.get_account(miner)?.unwrap_or_else(empty_account);
        settle_maturity(&mut acc, block_height, rules::COINBASE_MATURITY)?;
        credit_reward_to_account(&mut acc, reward, block_height)?;
        self.update_account(miner, &acc)
    }

    pub fn flush(&mut self) -> Result<(), String> {
        let mut db = self.db.lock().unwrap();
        db.flush().map_err(|e| format!("{:?}", e))
    }
}

impl std::fmt::Debug for StateDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateDB").finish()
    }
}

fn empty_account() -> Account {
    Account {
        nonce: 0,
        balance: 0,
        immature_rewards: BTreeMap::new(),
        code: Vec::new(),
        storage: BTreeMap::new(),
    }
}

/// Collect every key currently stored in the database.
///
/// The iterator returned by `rusty-leveldb` does not seek to the first
/// entry automatically. Without an explicit `seek_to_first`, the loop
/// below would either return nothing or start from an arbitrary point,
/// which is why the previous version of `reset` left stale accounts in
/// the database. The explicit seek fixes that.
fn collect_keys(db: &mut LevelDB) -> Result<Vec<Vec<u8>>, String> {
    let mut iter = db.new_iter().map_err(|e| format!("{:?}", e))?;
    iter.seek_to_first();
    let mut keys = Vec::new();
    while let Some((key, _)) = iter.next() {
        keys.push(key);
    }
    Ok(keys)
}
