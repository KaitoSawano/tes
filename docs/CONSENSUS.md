# XEPAY Consensus Rules

All nodes must apply exactly these rules. The numbers are listed in
`SPECIFICATION.md`; the algorithms are in `XEPHASH.md` and `CHECKPOINTS.md`.
A change of any rule needs a hard fork (a new activation height).

## Block validity

A block is valid only if all of the following hold:

1. The version is 1 and the index is the parent index plus one; `previous_hash` is the parent hash.
2. The header hash is recomputed and equal to `hash`. From the state root activation the hash covers the header only (merkle root and state root), so headers can be verified without their transactions.
3. The proof of work is valid: header hash at most the target before the Xephash activation, Xephash at most the target from it.
4. `nbits` equals the difficulty required at this height (see below), and `chainwork` is the parent chainwork plus the work of this block.
5. The timestamp is not earlier than the parent's and at most 2 hours in the future.
6. The block has at most 1,000 transactions; the merkle root matches the transaction ids; every transaction id matches its content.
7. Every transaction has a valid ML-DSA-65 signature from the key that hashes to its sender address, the exact next nonce of the sender, an amount above zero, and a mature balance of at least amount plus fee. Money fields are checked against overflow.
8. The subsidy equals the schedule for the height, `reward = subsidy + total fees`, and the supply never exceeds 780,000,000 XEPC.
9. Applying the block changes the total money of the touched accounts by exactly the subsidy (a block cannot create coins by any other path).
10. From the state root activation the declared `state_root` equals the root computed after applying the block (see below). Before it the field must be empty.
11. The block does not violate a checkpoint (see `CHECKPOINTS.md`).

## Difficulty

* Before the Xephash activation: legacy schedule, interval 69,120 blocks.
* From the activation: the difficulty restarts at a fixed value, then every 3,600 blocks (15 hours at 15 s) it is retargeted from the measured time of the window (median time past at both ends). The change is limited to 0.25x .. 4x per window and the target never exceeds the proof-of-work limit.
* `nbits` is recomputed from the chain, so it is correct after a restart or a reorg.

## Fees

Fees are paid to the miner. The relay minimum is 1 ALD per byte (higher when the mempool is full); the wallet default is 0.01 XEPC and rises when the mempool holds more than one block. These are relay and wallet policies, not consensus rules.

## State root

From `STATE_ROOT_ACTIVATION_*` every header carries `state_root`: the root of a hexary Merkle Patricia Trie over all accounts and registered public keys (key = SHA3-256 of the address, leaf value = SHA3-256 of the RLP encoded account, nodes RLP-encoded and referenced by SHA3-256, no inlining of small nodes). A block is accepted only if the root computed after applying it equals the declared one. The block is applied to an in-memory batch first; accounts, undo data and the tip marker are then committed in one synced LevelDB write, so a crash leaves either the old or the new state. On start the node replays, rolls back or rebuilds the state as needed.

## Public key registry

A ML-DSA-65 public key is 1952 bytes. From the activation the first transaction of an address carries its public key; the node stores it (it is part of the state root and is undone with the block on a reorg). Later transactions of that address may leave the key out and are verified with the registered key. The signing hash does not cover the key.

## Proof of work

See `XEPHASH.md`. The block id (`hash`) is the SHA3-256 hash of the full header; Xephash is computed from the header hash without the nonce (`seal_hash`) and the nonce.

## Activation (hard fork)

State root, key registry, Xephash and the 15 hour retarget activate at heights set in `src/consensus/rules.rs` (see `SPECIFICATION.md`, section 8). Blocks below the activation keep the old rules, so the existing chain stays valid. Every node must upgrade before the activation height.

## Genesis

Each network has its own genesis block, mined and verified at start. The genesis block is never changed.
