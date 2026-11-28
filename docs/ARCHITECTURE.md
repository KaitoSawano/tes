# XEPAY Architecture

XEPAY is a Layer-1 payment network written in Rust: an account-based ledger,
SHA3-256 hashing, ML-DSA-65 (post-quantum) signatures and Xephash proof of work.

## Components

1. **Consensus (`src/consensus/`, `src/validation.rs`, `src/blockchain.rs`)**
   Parameters (`spec.rs`), rules and activation heights (`rules.rs`), genesis, proof of work
   and every validation rule (`validation.rs`, error codes `E0xx`). `blockchain.rs` holds the
   chain, the mempool, the fee market, difficulty, block connection and the checkpoints.

2. **Cryptography (`crypto/`, `src/dilithium/`)**
   - `crypto/src/sha3.rs`: SHA3-256 (streaming and one-shot).
   - `crypto/src/xephash.rs`: the Xephash proof of work (cache, dataset, light and full mode).
   - `crypto/src/encryption.rs`: AES-256-GCM and PBKDF2 for the wallet.
   - `src/dilithium/`: ML-DSA-65 keys, signing, verification and address derivation (Base58Check and Bech32).

3. **Storage (`src/storage.rs`, `src/storage/`)**
   - `state.rs`: the account state in LevelDB with an in-memory block batch, one atomic synced commit per block, undo data for reorgs, the public key registry and the state root.
   - `trie.rs`: the Merkle Patricia Trie with cached subtree hashes.
   - `block_store.rs`, `block_index.rs`: block files (Bincode, 128 MiB each) and the block index.
   - `storage.rs`: loading the chain, crash recovery (`recover_state`), reindex, checkpoint verification.

4. **P2P (`src/p2p/`)**
   TCP, custom framing, handshake, headers-first sync, side-chain pool and reorganization (`sync.rs`), peer management, anchors, ban manager.

5. **RPC and CLI (`src/rpc.rs`, `src/xepay.rs`)**
   JSON-RPC over HTTP with cookie authentication, and the `xepay` command line client.

6. **Binaries**: `xepayd` (node), `xepay` (client), `xepay-miner`, `xepay-genesis`, `xephash`.

## Data flow

1. A wallet signs a transaction with ML-DSA-65 (the public key is included only for the first spend of an address).
2. The transaction enters the mempool after validation (signature, nonce, balance, fee rate).
3. A miner asks for a template (`getblocktemplate`): the node picks transactions by fee rate, simulates the block on a throw-away state batch and returns the resulting `state_root`.
4. The miner solves Xephash and submits the block (`submitblock`).
5. The node validates the block, applies it atomically (state root and money conservation are checked before anything is written) and relays it to its peers.
