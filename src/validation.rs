// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Consensus validation rules for XEPAY.

use crate::block::Block;
use crate::blockchain::Blockchain;
use crate::consensus::rules;
use crate::consensus::spec::{self, Network};
use crate::dilithium::{address, verify};
use crate::pow;
use crate::transaction::Transaction;
use std::collections::BTreeMap;
use std::fmt;

pub use rules::BLOCK_VERSION;
pub use rules::COINBASE_MATURITY;
pub use rules::MAX_INPUTS_PER_TX;
pub use rules::MAX_NOTE_LEN;
pub use rules::MAX_OUTPUTS_PER_TX;
pub use rules::MAX_TX_PER_BLOCK;
pub use rules::ZERO_HASH;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub code: &'static str,
    pub message: String,
}

impl ValidationError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        ValidationError {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

pub fn rule_address_format(addr: &str, chain: &Blockchain) -> Result<(), ValidationError> {
    let hrp = crate::blockchain::bech32_hrp();
    let is_bech32 = addr.starts_with(&format!("{}1", hrp));

    if crate::blockchain::is_softfork_active("disable_legacy_addresses", chain) && !is_bech32 {
        return Err(ValidationError::new(
            "E008",
            format!("legacy addresses are no longer accepted: {}", addr),
        ));
    }

    if is_bech32 {
        if !address::verify_bech32_address(addr) {
            return Err(ValidationError::new(
                "E001",
                format!("invalid bech32 address: {}", addr),
            ));
        }
        return Ok(());
    }

    if !address::verify_legacy_address(addr) {
        return Err(ValidationError::new(
            "E001",
            format!("invalid legacy address: {}", addr),
        ));
    }
    Ok(())
}

pub fn rule_self_send(tx: &Transaction) -> Result<(), ValidationError> {
    if tx.from == tx.to {
        // Allow self-send only if it is a message transaction with a
        // minimal amount.
        if tx.is_message_tx() && tx.amount == rules::MIN_MESSAGE_AMOUNT {
            return Ok(());
        }
        return Err(ValidationError::new(
            "E004",
            "sender and recipient addresses are identical",
        ));
    }
    Ok(())
}

pub fn rule_message_format(tx: &Transaction) -> Result<(), ValidationError> {
    if !tx.is_message_tx() {
        return Ok(());
    }

    // Message tx must be self-send.
    if tx.from != tx.to {
        return Err(ValidationError::new(
            "E054",
            "message transaction must be a self-send",
        ));
    }

    // Amount must be exactly MIN_MESSAGE_AMOUNT.
    if tx.amount != rules::MIN_MESSAGE_AMOUNT {
        return Err(ValidationError::new(
            "E054",
            format!(
                "message transaction amount must be exactly {} ALD",
                rules::MIN_MESSAGE_AMOUNT
            ),
        ));
    }

    // Payload must be valid hex and valid UTF-8.
    if tx.extract_message().is_none() {
        return Err(ValidationError::new(
            "E054",
            "message transaction payload is not valid hex-encoded UTF-8",
        ));
    }

    let msg = tx.extract_message().unwrap();
    if msg.len() > rules::MAX_MESSAGE_LEN {
        return Err(ValidationError::new(
            "E054",
            format!("message exceeds {} bytes", rules::MAX_MESSAGE_LEN),
        ));
    }

    Ok(())
}

/// SECURITY FIX: `output_script` is part of the txid but NOT of the signing
/// hash, and the wallet never sets it. A relay node could therefore attach
/// arbitrary (large) data to someone else's transaction, changing its txid
/// without invalidating the signature (malleability, mempool poisoning and
/// block bloat). Normal transactions must leave it empty.
pub fn rule_output_script_empty(tx: &Transaction) -> Result<(), ValidationError> {
    if !tx.output_script.is_empty() {
        // Reject any transaction that carries unsigned script data.
        return Err(ValidationError::new(
            "E013",
            "output_script must be empty for normal transactions",
        ));
    }
    Ok(())
}

/// Strict rule: Ensure the amount is within the valid money range.
/// This prevents integer overflow attacks where a user tries to send
/// an amount larger than the total supply.
pub fn rule_money_range(tx: &Transaction) -> Result<(), ValidationError> {
    let max_money = spec::MAX_SUPPLY;

    if tx.amount > max_money {
        return Err(ValidationError::new(
            "E005",
            format!("amount {} exceeds MAX_MONEY {}", tx.amount, max_money),
        ));
    }

    if tx.fee > max_money {
        return Err(ValidationError::new(
            "E005",
            format!("fee {} exceeds MAX_MONEY {}", tx.fee, max_money),
        ));
    }

    let total = tx.amount.checked_add(tx.fee).ok_or_else(|| {
        ValidationError::new("E005", "amount + fee overflows u64")
    })?;

    if total > max_money {
        return Err(ValidationError::new(
            "E005",
            format!("total amount + fee {} exceeds MAX_MONEY {}", total, max_money),
        ));
    }

    Ok(())
}

pub fn rule_amount_nonzero(tx: &Transaction) -> Result<(), ValidationError> {
    if tx.amount == 0 {
        return Err(ValidationError::new(
            "E005",
            "amount must be greater than zero",
        ));
    }
    Ok(())
}

/// Note length rule at `height` (the limit can change through a rule era).
pub fn rule_note_length_at(tx: &Transaction, height: u64) -> Result<(), ValidationError> {
    let limit = rules::max_note_len_at(height);
    if tx.note.len() > limit {
        return Err(ValidationError::new(
            "E006",
            format!("note exceeds {} bytes", limit),
        ));
    }
    Ok(())
}

/// Note length rule of the newest rules (for building new transactions).
pub fn rule_note_length(tx: &Transaction) -> Result<(), ValidationError> {
    rule_note_length_at(tx, u64::MAX)
}

/// Verify the signature of `tx` against the public key `pk`.
pub fn rule_signature_with(tx: &Transaction, pk: &[u8]) -> Result<(), ValidationError> {
    if is_special_tx(tx) {
        return Ok(());
    }
    if pk.is_empty() {
        return Err(ValidationError::new("E010", "public key is empty"));
    }
    if tx.signature.is_empty() {
        return Err(ValidationError::new("E010", "signature is empty"));
    }

    let msg = hex::decode(tx.signing_hash())
        .map_err(|_| ValidationError::new("E010", "signing hash is not hexadecimal"))?;

    if !verify::verify(pk, &msg, &tx.signature) {
        return Err(ValidationError::new(
            "E010",
            format!("signature is invalid for txid {}", tx.txid),
        ));
    }
    Ok(())
}

/// Signature check using the key carried inside the transaction.
pub fn rule_signature(tx: &Transaction) -> Result<(), ValidationError> {
    rule_signature_with(tx, &tx.public_key)
}

/// The sender address must be derived from the public key `pk`.
pub fn rule_address_matches_with(tx: &Transaction, pk: &[u8]) -> Result<(), ValidationError> {
    if is_special_tx(tx) {
        return Ok(());
    }
    if pk.is_empty() {
        return Err(ValidationError::new("E011", "public key is empty"));
    }

    let hrp = crate::blockchain::bech32_hrp();
    let expected = if tx.from.starts_with(&format!("{}1", hrp)) {
        address::address_from_public_key_bech32(pk).map_err(|_| {
            ValidationError::new("E011", "public key cannot be converted to a bech32 address")
        })?
    } else {
        address::address_from_public_key(pk).map_err(|_| {
            ValidationError::new("E011", "public key cannot be converted to a legacy address")
        })?
    };

    if expected != tx.from {
        return Err(ValidationError::new(
            "E011",
            format!("address {} does not match the public key {}", tx.from, expected),
        ));
    }
    Ok(())
}

/// Address check using the key carried inside the transaction.
pub fn rule_address_matches_pubkey(tx: &Transaction) -> Result<(), ValidationError> {
    rule_address_matches_with(tx, &tx.public_key)
}

/// Find the public key to verify `tx` with: the one inside the transaction
/// or, from the registry activation height, the key registered earlier for
/// the sender (looked up through `lookup`).
pub fn resolve_pubkey<F>(tx: &Transaction, height: u64, lookup: F) -> Result<Vec<u8>, ValidationError>
where
    F: Fn(&str) -> Option<Vec<u8>>,
{
    if !tx.public_key.is_empty() {
        return Ok(tx.public_key.clone());
    }
    if rules::pubkey_registry_active(height) {
        return lookup(&tx.from).ok_or_else(|| {
            ValidationError::new("E014", "public key omitted but the sender has no registered key")
        });
    }
    Err(ValidationError::new("E010", "public key is empty"))
}

pub fn rule_txid_consistent(tx: &Transaction) -> Result<(), ValidationError> {
    if tx.txid != tx.compute_txid() {
        return Err(ValidationError::new(
            "E012",
            format!("txid {} does not match the computed value", tx.txid),
        ));
    }
    Ok(())
}

pub fn rule_nonce(chain: &Blockchain, tx: &Transaction) -> Result<(), ValidationError> {
    if is_special_tx(tx) {
        return Ok(());
    }
    let mut expected = chain.nonce_of(&tx.from);
    loop {
        let has_mempool_tx = chain
            .mempool
            .iter()
            .any(|t| t.from == tx.from && t.nonce == expected);
        if !has_mempool_tx {
            break;
        }
        match expected.checked_add(1) {
            Some(v) => expected = v,
            None => {
                return Err(ValidationError::new(
                    "E023",
                    "nonce sequence has reached the maximum value",
                ));
            }
        }
    }
    if tx.nonce != expected {
        return Err(ValidationError::new(
            "E022",
            format!("invalid nonce: got {}, expected {}", tx.nonce, expected),
        ));
    }
    Ok(())
}

pub fn rule_sufficient_balance(chain: &Blockchain, tx: &Transaction) -> Result<(), ValidationError> {
    if is_special_tx(tx) {
        return Ok(());
    }
    let balance = chain.mature_balance_at(&tx.from, chain.height());
    let need = tx.amount.checked_add(tx.fee).ok_or_else(|| {
        ValidationError::new("E005", "amount + fee overflows u64")
    })?;
    if balance < need {
        return Err(ValidationError::new(
            "E021",
            format!(
                "insufficient mature balance: required {} ald, available {} ald",
                need, balance
            ),
        ));
    }
    Ok(())
}

pub fn rule_block_version(block: &Block) -> Result<(), ValidationError> {
    let expected_version = rules::block_version_at(block.index);
    if block.nversion != expected_version {
        return Err(ValidationError::new(
            "E028",
            format!(
                "unsupported block version {} at index {}: expected {}",
                block.nversion, block.index, expected_version
            ),
        ));
    }
    Ok(())
}

pub fn rule_block_tx_count(block: &Block) -> Result<(), ValidationError> {
    let limit = rules::max_tx_per_block_at(block.index);
    if block.transactions.len() > limit {
        return Err(ValidationError::new(
            "E030",
            format!(
                "block contains {} transactions, exceeding the limit of {}",
                block.transactions.len(),
                limit
            ),
        ));
    }
    Ok(())
}

pub fn rule_block_subsidy(block: &Block) -> Result<(), ValidationError> {
    let expected = Blockchain::calculate_reward(block.index);
    if block.subsidy != expected {
        return Err(ValidationError::new(
            "E031",
            format!(
                "subsidy for block {} does not match the era: got {}, expected {}",
                block.index, block.subsidy, expected
            ),
        ));
    }
    Ok(())
}

pub fn rule_block_reward(block: &Block) -> Result<(), ValidationError> {
    // FIX: Use checked_add to prevent overflow if a miner tries to claim u64::MAX
    let expected = block.subsidy.checked_add(block.total_fees)
        .ok_or_else(|| ValidationError::new("E046", "block reward overflow"))?;

    if block.reward != expected {
        return Err(ValidationError::new(
            "E046",
            format!(
                "reward for block {} is invalid: got {}, expected {} (subsidy {} + fees {})",
                block.index, block.reward, expected, block.subsidy, block.total_fees
            ),
        ));
    }
    Ok(())
}

pub fn rule_block_total_fees(block: &Block) -> Result<(), ValidationError> {
    // Checked sum: a plain `.sum()` wraps in release builds (and panics in
    // debug builds), which is the classic "value out of thin air" bug.
    let mut computed: u64 = 0;
    for tx in &block.transactions {
        computed = computed.checked_add(tx.fee).ok_or_else(|| {
            ValidationError::new("E047", "sum of transaction fees overflows u64")
        })?;
    }
    if block.total_fees != computed {
        return Err(ValidationError::new(
            "E047",
            format!(
                "total_fees for block {} is invalid: got {}, expected {}",
                block.index, block.total_fees, computed
            ),
        ));
    }
    Ok(())
}

pub fn rule_block_coinbase_consistent(block: &Block) -> Result<(), ValidationError> {
    if block.index == 0 {
        return Ok(());
    }
    let expected = xepay_crypto::sha3_256_hex(
        format!("{}|{}|{}", block.index, block.mined_for, block.timestamp).as_bytes(),
    );
    if block.coinbase_txid != expected {
        return Err(ValidationError::new(
            "E048",
            format!(
                "coinbase_txid for block {} is inconsistent with index, mined_for, and timestamp",
                block.index
            ),
        ));
    }
    Ok(())
}

pub fn rule_mined_for_valid(block: &Block, chain: &Blockchain) -> Result<(), ValidationError> {
    if block.index == 0 {
        return Ok(());
    }
    if block.mined_for.is_empty() {
        return Err(ValidationError::new(
            "E049",
            format!("block {} has an empty mined_for address", block.index),
        ));
    }
    rule_address_format(&block.mined_for, chain).map_err(|_| {
        ValidationError::new(
            "E049",
            format!(
                "mined_for address of block {} is invalid: {}",
                block.index, block.mined_for
            ),
        )
    })
}

pub fn rule_block_timestamp_monotonic(prev: &Block, cur: &Block) -> Result<(), ValidationError> {
    if cur.timestamp < prev.timestamp {
        return Err(ValidationError::new(
            "E032",
            format!(
                "timestamp of block {} is earlier than block {}",
                cur.index, prev.index
            ),
        ));
    }

    let now = crate::utils::now_millis();
    let max_future_time = now.saturating_add(2 * 60 * 60 * 1000);

    if cur.timestamp > max_future_time {
        return Err(ValidationError::new(
            "E050",
            format!(
                "timestamp of block {} is too far in the future (max allowed: {}ms ahead)",
                cur.index,
                (cur.timestamp - now) / 1000
            ),
        ));
    }

    Ok(())
}

pub fn rule_block_nbits(chain: &Blockchain, block: &Block) -> Result<(), ValidationError> {
    if block.nbits != chain.nbits {
        return Err(ValidationError::new(
            "E033",
            format!(
                "nbits of block {:#010x} does not match chain nbits {:#010x}",
                block.nbits, chain.nbits
            ),
        ));
    }
    Ok(())
}

pub fn rule_block_hash_consistent(block: &Block) -> Result<(), ValidationError> {
    if block.hash != block.calculate_hash() {
        return Err(ValidationError::new(
            "E034",
            format!(
                "hash of block {} is not consistent with its contents",
                block.index
            ),
        ));
    }
    Ok(())
}

pub fn rule_block_previous_hash(prev: &Block, cur: &Block) -> Result<(), ValidationError> {
    if cur.previous_hash != prev.hash {
        return Err(ValidationError::new(
            "E035",
            format!(
                "previous_hash of block {} does not match the hash of block {}",
                cur.index, prev.index
            ),
        ));
    }
    Ok(())
}

pub fn rule_block_index_sequential(prev: &Block, cur: &Block) -> Result<(), ValidationError> {
    if prev.index.checked_add(1) != Some(cur.index) {
        return Err(ValidationError::new(
            "E036",
            format!(
                "index of block {} is not sequential after block {}",
                cur.index, prev.index
            ),
        ));
    }
    Ok(())
}

pub fn rule_block_pow(block: &Block) -> Result<(), ValidationError> {
    if !pow::block_meets_pow(block) {
        return Err(ValidationError::new(
            "E037",
            format!(
                "hash of block {} does not meet the target nbits {:#010x}",
                block.index, block.nbits
            ),
        ));
    }
    Ok(())
}

pub fn rule_block_checkpoint(block: &Block) -> Result<(), ValidationError> {
    if !crate::blockchain::checkpoint::verify(block.index, &block.hash) {
        return Err(ValidationError::new(
            "E038",
            format!("block {} violates a checkpoint", block.index),
        ));
    }
    Ok(())
}

pub fn rule_genesis(block: &Block) -> Result<(), ValidationError> {
    if block.index != 0 {
        return Err(ValidationError::new(
            "E039",
            "the genesis block must have index 0",
        ));
    }
    if block.previous_hash != crate::consensus::genesis::GENESIS_PREVIOUS_HASH {
        return Err(ValidationError::new(
            "E039",
            "the genesis block previous_hash must be zero",
        ));
    }
    Ok(())
}

pub fn rule_total_supply(chain: &Blockchain) -> Result<(), ValidationError> {
    let total = chain.circulating_supply();
    let max = crate::blockchain::max_supply();
    if total > max {
        return Err(ValidationError::new(
            "E041",
            format!(
                "total supply {} ald exceeds the maximum of {} ald",
                total, max
            ),
        ));
    }
    Ok(())
}

pub fn rule_genesis_fingerprint_for(block: &Block, network: Network) -> Result<(), ValidationError> {
    let expected_txid = crate::blockchain::genesis_coinbase_txid_for(network);
    if block.coinbase_txid != expected_txid {
        return Err(ValidationError::new(
            "E042",
            format!(
                "genesis coinbase_txid does not match the consensus fingerprint: got {}, expected {}",
                block.coinbase_txid, expected_txid
            ),
        ));
    }
    Ok(())
}

/// The state root must be absent before the activation height (it is not
/// hashed there, so it would be malleable) and a 32-byte hex string after.
pub fn rule_block_state_root_format(block: &Block) -> Result<(), ValidationError> {
    if rules::state_root_active(block.index) {
        let ok = block.state_root.len() == 64
            && block.state_root.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
        if !ok {
            return Err(ValidationError::new("E060", "state root missing or malformed"));
        }
    } else if !block.state_root.is_empty() {
        return Err(ValidationError::new(
            "E061",
            "state root not allowed before activation height",
        ));
    }
    Ok(())
}

/// Validate a header without its transactions. From the activation
/// height the hash is recomputed; below it only linkage and the proof of
/// work claim can be checked, the body check happens on block download.
pub fn validate_header_only(prev: &Block, h: &Block) -> Result<(), ValidationError> {
    rule_block_version(h)?;
    rule_block_index_sequential(prev, h)?;
    rule_block_previous_hash(prev, h)?;
    rule_block_state_root_format(h)?;
    if h.hash_is_header_only() && h.hash != h.calculate_hash() {
        return Err(ValidationError::new("E062", "header hash does not match header"));
    }
    rule_header_nbits_path(prev, h)?;
    rule_block_checkpoint(h)?;
    rule_block_pow(h)?;
    rule_block_timestamp_monotonic(prev, h)?;
    rule_block_chainwork(prev, h)?;
    Ok(())
}

/// Difficulty may only follow the real retarget path, otherwise a peer
/// could mint cheap headers with an arbitrarily easy `nbits`. Inside an
/// interval nbits must equal the parent's; right after a retarget block
/// the target may change by at most the clamp used by `adjust_difficulty`
/// (x0.25 .. x4, with slack for nbits rounding). Regtest never retargets.
pub fn rule_header_nbits_path(prev: &Block, h: &Block) -> Result<(), ValidationError> {
    // The first Xephash block restarts the difficulty at a fixed value.
    if spec::current_network() != Network::Regtest
        && h.index == rules::xephash_activation_height()
    {
        if h.nbits != rules::xephash_start_nbits() {
            return Err(ValidationError::new(
                "E064",
                format!("first xephash block must use nbits {:#010x}", rules::xephash_start_nbits()),
            ));
        }
        return Ok(());
    }
    let retarget_boundary = rules::retarget_after(prev.index);
    let ok = if !retarget_boundary {
        h.nbits == prev.nbits
    } else {
        let pt = pow::nbits_to_target(prev.nbits);
        let ht = pow::nbits_to_target(h.nbits);
        let max = crate::blockchain::scale_target(&pt, 1040);
        let min = crate::blockchain::scale_target(&pt, 48);
        // SECURITY FIX: also enforce the proof-of-work limit, otherwise a peer
        // could ratchet up cheap headers with an easier target than allowed.
        ht <= max && ht >= min && ht.as_slice() <= crate::blockchain::pow_limit_bytes().as_slice()
    };
    if !ok {
        return Err(ValidationError::new(
            "E063",
            format!("nbits of header {} does not follow the difficulty rules", h.index),
        ));
    }
    Ok(())
}

pub fn rule_genesis_fingerprint(block: &Block) -> Result<(), ValidationError> {
    rule_genesis_fingerprint_for(block, spec::current_network())
}

pub fn rule_block_merkle_root(block: &Block) -> Result<(), ValidationError> {
    let expected = Block::compute_merkle_root(&block.transactions);
    if block.merkle_root != expected {
        return Err(ValidationError::new(
            "E043",
            format!(
                "merkle root of block {} does not match: got {}, expected {}",
                block.index, block.merkle_root, expected
            ),
        ));
    }
    Ok(())
}

pub fn rule_genesis_output_script(block: &Block) -> Result<(), ValidationError> {
    if block.index != 0 {
        return Ok(());
    }
    let expected = crate::blockchain::genesis_output_script();
    if block.genesis_output_script != expected {
        return Err(ValidationError::new(
            "E044",
            format!(
                "genesis output script does not match: got {}, expected {}",
                block.genesis_output_script, expected
            ),
        ));
    }
    Ok(())
}

pub fn rule_genesis_pow(block: &Block) -> Result<(), ValidationError> {
    if !pow::hash_meets_nbits(&block.hash, block.nbits) {
        return Err(ValidationError::new(
            "E045",
            format!(
                "genesis hash does not meet the target nbits {:#010x}",
                block.nbits
            ),
        ));
    }
    Ok(())
}

pub fn is_special_tx(tx: &Transaction) -> bool {
    // Only the two synthetic transactions embedded in the genesis block
    // are special. The previous implementation also treated the strings
    // "NETWORK" and "MEMPOOL" as special, which let a transaction with
    // `from = "NETWORK"` bypass every validation rule and skip the state
    // transition entirely. That is a consensus hole, so those two
    // markers have been removed.
    tx.from == "COINBASE" || tx.from == "GENESIS"
}

pub fn is_valid_address(addr: &str, chain: &Blockchain) -> bool {
    rule_address_format(addr, chain).is_ok()
}

pub fn validate_transaction(chain: &Blockchain, tx: &Transaction) -> Result<(), ValidationError> {
    if is_special_tx(tx) {
        return Ok(());
    }

    rule_txid_consistent(tx)?;
    rule_output_script_empty(tx)?; // unsigned script data is not allowed
    rule_address_format(&tx.from, chain)?;
    rule_address_format(&tx.to, chain)?;
    rule_self_send(tx)?;
    rule_message_format(tx)?;
    rule_amount_nonzero(tx)?;
    rule_money_range(tx)?;
    let next_height = chain.height().saturating_add(1);
    rule_note_length_at(tx, next_height)?;
    let pk = resolve_pubkey(tx, next_height, |a| chain.state.get_pubkey(a))?;
    rule_signature_with(tx, &pk)?;
    rule_address_matches_with(tx, &pk)?;
    rule_nonce(chain, tx)?;
    rule_sufficient_balance(chain, tx)?;

    Ok(())
}

/// Validate a transaction as a member of the block being built at `height`.
///
/// Unlike `validate_transaction` (which is for NEW mempool entries and
/// therefore expects the nonce after all pending ones), this uses the exact
/// block rule: the nonce must equal the account nonce in the state the block
/// is being built on. Using the mempool rule here made every pending
/// transaction of a sender look invalid, so blocks were mined empty.
pub fn validate_tx_for_block(
    chain: &Blockchain,
    tx: &Transaction,
    height: u64,
) -> Result<(), ValidationError> {
    if is_special_tx(tx) {
        return Err(ValidationError::new("E026", "special transaction in a block"));
    }
    rule_txid_consistent(tx)?;
    rule_output_script_empty(tx)?; // unsigned script data is not allowed
    rule_address_format(&tx.from, chain)?;
    rule_address_format(&tx.to, chain)?;
    rule_self_send(tx)?;
    rule_message_format(tx)?;
    rule_amount_nonzero(tx)?;
    rule_money_range(tx)?;
    rule_note_length_at(tx, height)?;
    let pk = resolve_pubkey(tx, height, |a| chain.state.get_pubkey(a))?;
    rule_signature_with(tx, &pk)?;
    rule_address_matches_with(tx, &pk)?;

    let expected = chain.nonce_of(&tx.from);
    if tx.nonce != expected {
        return Err(ValidationError::new(
            "E022",
            format!("invalid nonce for {}: got {}, expected {}", tx.from, tx.nonce, expected),
        ));
    }
    let need = tx
        .amount
        .checked_add(tx.fee)
        .ok_or_else(|| ValidationError::new("E005", "amount + fee overflows u64"))?;
    let balance = chain.mature_balance_at(&tx.from, height);
    if balance < need {
        return Err(ValidationError::new(
            "E021",
            format!("insufficient mature balance: required {} ald, available {} ald", need, balance),
        ));
    }
    Ok(())
}

pub fn validate_block_transactions(
    chain: &mut Blockchain,
    transactions: &[Transaction],
    height: u64,
) -> Result<(), ValidationError> {
    let mut overlay_balances: BTreeMap<String, u64> = BTreeMap::new();
    let mut overlay_nonces: BTreeMap<String, u64> = BTreeMap::new();
    let mut seen_txids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut registered_in_block: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    for tx in transactions {
        if is_special_tx(tx) {
            continue;
        }

        // Strict rule: reject a block that contains the same txid twice.
        // Without this check, a miner could include the same transaction
        // multiple times and inflate the effective supply.
        if !seen_txids.insert(tx.txid.clone()) {
            return Err(ValidationError::new(
                "E025",
                format!("duplicate txid in block: {}", tx.txid),
            ));
        }

        // Structural checks that do not depend on the chain state.
        rule_txid_consistent(tx)?;
        rule_output_script_empty(tx)?; // unsigned script data is not allowed
        rule_address_format(&tx.from, chain)?;
        rule_address_format(&tx.to, chain)?;
        rule_self_send(tx)?;
        rule_message_format(tx)?;
        rule_amount_nonzero(tx)?;
        rule_money_range(tx)?;
        rule_note_length_at(tx, height)?;
        // Key resolution: carried key, else one registered by an earlier
        // transaction of this block, else the on-chain registry.
        let pk = if !tx.public_key.is_empty() {
            tx.public_key.clone()
        } else if rules::pubkey_registry_active(height) {
            registered_in_block
                .get(&tx.from)
                .cloned()
                .or_else(|| chain.state.get_pubkey(&tx.from))
                .ok_or_else(|| {
                    ValidationError::new(
                        "E014",
                        "public key omitted but the sender has no registered key",
                    )
                })?
        } else {
            return Err(ValidationError::new("E010", "public key is empty"));
        };
        rule_signature_with(tx, &pk)?;
        rule_address_matches_with(tx, &pk)?;
        if rules::pubkey_registry_active(height) && !tx.public_key.is_empty() {
            registered_in_block
                .entry(tx.from.clone())
                .or_insert_with(|| tx.public_key.clone());
        }

        let base_nonce = overlay_nonces
            .get(&tx.from)
            .copied()
            .unwrap_or_else(|| chain.nonce_of(&tx.from));
        if tx.nonce != base_nonce {
            return Err(ValidationError::new(
                "E022",
                format!("invalid nonce for {}: got {}, expected {}", tx.from, tx.nonce, base_nonce),
            ));
        }

        let base_balance = overlay_balances
            .get(&tx.from)
            .copied()
            .unwrap_or_else(|| chain.mature_balance_at(&tx.from, height));

        let need = match tx.amount.checked_add(tx.fee) {
            Some(v) => v,
            None => return Err(ValidationError::new("E023", "amount + fee overflows u64")),
        };
        if base_balance < need {
            return Err(ValidationError::new(
                "E021",
                format!("insufficient mature balance for {}: required {} ald, available {} ald", tx.from, need, base_balance),
            ));
        }

        let new_from = base_balance.checked_sub(need)
            .ok_or_else(|| ValidationError::new("E023", "underflow during overlay balance calculation"))?;
        overlay_balances.insert(tx.from.clone(), new_from);

        // For self-send, the amount is returned to the sender.
        if tx.from != tx.to {
            let to_balance = overlay_balances
                .get(&tx.to)
                .copied()
                .unwrap_or_else(|| chain.mature_balance_at(&tx.to, height)); // SECURITY FIX: balance_of() counted immature coinbase, letting a block spend it
            let new_to = match to_balance.checked_add(tx.amount) {
                Some(v) => v,
                None => return Err(ValidationError::new("E024", "recipient balance overflows u64")),
            };
            overlay_balances.insert(tx.to.clone(), new_to);
        } else {
            // Refund the self-send amount back to sender (fee is burned).
            let refunded = new_from.checked_add(tx.amount)
                .ok_or_else(|| ValidationError::new("E024", "self-send refund overflow"))?;
            overlay_balances.insert(tx.from.clone(), refunded);
        }

        let next_nonce = base_nonce.checked_add(1)
            .ok_or_else(|| ValidationError::new("E023", "nonce overflow in overlay"))?;
        overlay_nonces.insert(tx.from.clone(), next_nonce);
    }

    Ok(())
}

pub fn rule_block_chainwork(prev: &Block, cur: &Block) -> Result<(), ValidationError> {
    let expected_block_work = Block::compute_work(cur.nbits);
    let expected_chainwork = prev.chainwork.checked_add(expected_block_work).ok_or_else(|| {
        ValidationError::new("E051", "cumulative chainwork overflows u128")
    })?;
    if cur.chainwork != expected_chainwork {
        return Err(ValidationError::new(
            "E051",
            format!(
                "chainwork of block {} is invalid: got {}, expected {}",
                cur.index, cur.chainwork, expected_chainwork
            ),
        ));
    }
    Ok(())
}

pub fn validate_block(
    chain: &mut Blockchain,
    prev: &Block,
    block: &Block,
) -> Result<(), ValidationError> {
    rule_block_version(block)?;
    rule_block_index_sequential(prev, block)?;
    rule_block_hash_consistent(block)?;
    rule_block_previous_hash(prev, block)?;
    rule_block_state_root_format(block)?;
    rule_block_merkle_root(block)?;
    rule_block_subsidy(block)?;
    rule_block_total_fees(block)?;
    rule_block_reward(block)?;
    rule_block_coinbase_consistent(block)?;
    rule_mined_for_valid(block, chain)?;
    rule_block_pow(block)?;
    rule_block_tx_count(block)?;
    rule_block_timestamp_monotonic(prev, block)?;
    rule_block_checkpoint(block)?;
    rule_block_nbits(chain, block)?;
    rule_block_chainwork(prev, block)?;
    validate_block_transactions(chain, &block.transactions, block.index)?;

    // Verify total supply does not exceed MAX_MONEY after this block
    let new_supply = chain.circulating_supply().checked_add(block.reward)
        .ok_or_else(|| ValidationError::new("E041", "supply overflow"))?;
    if new_supply > spec::MAX_SUPPLY {
        return Err(ValidationError::new(
            "E041",
            format!("new supply {} exceeds MAX_MONEY {}", new_supply, spec::MAX_SUPPLY)
        ));
    }

    Ok(())
}

/// Validate the structural integrity of the stored chain.
///
/// This check verifies everything that can be verified from the block
/// data alone: the genesis block, the block hash, the merkle root, the
/// proof of work, the reward schedule, the chainwork, and the block
/// headers. It deliberately does NOT replay transactions, because the
/// live state reflects the tip of the chain and cannot be used to
/// validate historical nonce and balance checks. Replaying the
/// transactions is the job of the reindex path, which rebuilds the
/// state from genesis and fails on the first invalid transaction.
///
/// This mirrors the reference node's behaviour: `verifychain` checks
/// the chain structure, while a reindex performs the full state
/// transition.
pub fn validate_chain(chain: &mut Blockchain) -> Result<(), ValidationError> {
    if chain.chain.is_empty() {
        return Err(ValidationError::new("E040", "chain is empty"));
    }

    {
        let genesis = &chain.chain[0];
        rule_genesis(genesis)?;
        rule_genesis_fingerprint(genesis)?;
        rule_genesis_output_script(genesis)?;
        rule_genesis_pow(genesis)?;
        rule_block_hash_consistent(genesis)?;
        rule_block_merkle_root(genesis)?;
        rule_block_version(genesis)?;
    }
    rule_total_supply(chain)?;

    for i in 1..chain.chain.len() {
        let (prev_hash, prev_index, prev_timestamp, prev_chainwork) = {
            let prev = &chain.chain[i - 1];
            (prev.hash.clone(), prev.index, prev.timestamp, prev.chainwork)
        };
        let (
            cur_index,
            cur_nversion,
            cur_previous_hash,
            cur_subsidy,
            cur_total_fees,
            cur_reward,
            cur_coinbase_txid,
            cur_mined_for,
            cur_nbits,
            cur_timestamp,
            cur_tx_count,
            cur_chainwork,
        ) = {
            let cur = &chain.chain[i];
            (
                cur.index,
                cur.nversion,
                cur.previous_hash.clone(),
                cur.subsidy,
                cur.total_fees,
                cur.reward,
                cur.coinbase_txid.clone(),
                cur.mined_for.clone(),
                cur.nbits,
                cur.timestamp,
                cur.transactions.len(),
                cur.chainwork,
            )
        };

        let expected_version = rules::block_version_at(cur_index);
        if cur_nversion != expected_version {
            return Err(ValidationError::new("E028",
                format!("unsupported block version {} at index {}: expected {}", cur_nversion, cur_index, expected_version)));
        }
        if cur_index != prev_index + 1 {
            return Err(ValidationError::new("E036",
                format!("index of block {} is not sequential after block {}", cur_index, prev_index)));
        }
        if cur_previous_hash != prev_hash {
            return Err(ValidationError::new("E035",
                format!("previous_hash of block {} does not match the hash of block {}", cur_index, prev_index)));
        }
        {
            let cur = &chain.chain[i];
            if cur.hash != cur.calculate_hash() {
                return Err(ValidationError::new("E034",
                    format!("hash of block {} is not consistent with its contents", cur_index)));
            }
            let expected_merkle = Block::compute_merkle_root(&cur.transactions);
            if cur.merkle_root != expected_merkle {
                return Err(ValidationError::new("E043",
                    format!("merkle root of block {} does not match: got {}, expected {}", cur_index, cur.merkle_root, expected_merkle)));
            }
            if !pow::block_meets_pow(cur) {
                return Err(ValidationError::new("E037",
                    format!("hash of block {} does not meet the target nbits {:#010x}", cur_index, cur.nbits)));
            }
            if !crate::blockchain::checkpoint::verify(cur.index, &cur.hash) {
                return Err(ValidationError::new("E038",
                    format!("block {} violates a checkpoint", cur_index)));
            }
        }
        let expected_subsidy = Blockchain::calculate_reward(cur_index);
        if cur_subsidy != expected_subsidy {
            return Err(ValidationError::new("E031",
                format!("subsidy for block {} does not match the era: got {}, expected {}", cur_index, cur_subsidy, expected_subsidy)));
        }
        let expected_reward = cur_subsidy.checked_add(cur_total_fees).ok_or_else(|| {
            ValidationError::new("E046", "block reward overflow")
        })?;
        if cur_reward != expected_reward {
            return Err(ValidationError::new("E046",
                format!("reward for block {} is invalid: got {}, expected {} (subsidy {} + fees {})", cur_index, cur_reward, expected_reward, cur_subsidy, cur_total_fees)));
        }
        if cur_index != 0 {
            let expected_txid = xepay_crypto::sha3_256_hex(
                format!("{}|{}|{}", cur_index, cur_mined_for, cur_timestamp).as_bytes(),
            );
            if cur_coinbase_txid != expected_txid {
                return Err(ValidationError::new("E048",
                    format!("coinbase_txid for block {} is inconsistent with index, mined_for, and timestamp", cur_index)));
            }
            if cur_mined_for.is_empty() {
                return Err(ValidationError::new("E049",
                    format!("block {} has an empty mined_for address", cur_index)));
            }
            rule_address_format(&cur_mined_for, chain).map_err(|_| {
                ValidationError::new("E049",
                    format!("mined_for address of block {} is invalid: {}", cur_index, cur_mined_for))
            })?;
        }
        let tx_limit = rules::max_tx_per_block_at(cur_index);
        if cur_tx_count > tx_limit {
            return Err(ValidationError::new("E030",
                format!("block contains {} transactions, exceeding the limit of {}", cur_tx_count, tx_limit)));
        }
        if cur_timestamp < prev_timestamp {
            return Err(ValidationError::new("E032",
                format!("timestamp of block {} is earlier than block {}", cur_index, prev_index)));
        }

        let now = crate::utils::now_millis();
        let max_future_time = now.saturating_add(2 * 60 * 60 * 1000);
        if cur_timestamp > max_future_time {
             return Err(ValidationError::new("E050",
                format!("timestamp of block {} is too far in the future", cur_index)));
        }

        if cur_nbits != chain.nbits {
            return Err(ValidationError::new("E033",
                format!("nbits of block {:#010x} does not match chain nbits {:#010x}", cur_nbits, chain.nbits)));
        }

        let expected_block_work = Block::compute_work(cur_nbits);
        let expected_chainwork = prev_chainwork.checked_add(expected_block_work).ok_or_else(|| {
            ValidationError::new("E051", "cumulative chainwork overflows u128")
        })?;
        if cur_chainwork != expected_chainwork {
            return Err(ValidationError::new("E051",
                format!("chainwork of block {} is invalid: got {}, expected {}", cur_index, cur_chainwork, expected_chainwork)));
        }
    }

    Ok(())
}

pub fn validate_mempool(chain: &Blockchain) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    for tx in &chain.mempool {
        if let Err(e) = validate_transaction(chain, tx) {
            errors.push(e);
        }
    }
    errors
}
