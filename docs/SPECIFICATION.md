# XEPAY Specification

This document is the authoritative description of the protocol as implemented in
this repository. Every number below is taken from the source code
(`src/consensus/spec.rs`, `src/consensus/rules.rs`, `src/blockchain.rs`,
`src/p2p/`, `crypto/src/`). If the code and this document disagree, the code
is right and this document has a bug.

## 1. Identity

| Item | Value |
|---|---|
| Name / symbol | XEPAY / XEPC |
| Smallest unit | Aldian (ALD) |
| Decimals | 8 (1 XEPC = 100,000,000 ALD) |
| Software version | 0.3.0 (Rust 1.75+, edition 2021) |
| Consensus | Proof of Work, account-based ledger |
| Hash function | SHA3-256 |
| Signatures | ML-DSA-65 (FIPS 204): public key 1952 bytes, signature 3309 bytes, secret key = 32-byte seed |
| Wallet encryption | AES-256-GCM, key derived with PBKDF2-HMAC-SHA256 |

## 2. Supply and emission

| Item | Value |
|---|---|
| Maximum supply (protocol limit) | 780,000,000 XEPC |
| Initial block reward | 15 XEPC |
| Reward schedule | multiplied by 9/10 every era (a 10% reduction, not a halving) |
| Era length | 5,200,000 blocks (about 2.47 years at 15 s per block) |
| Rounding | integer arithmetic; the reward is rounded down at every era step |
| Eras with a non-zero reward | 185 (the last era pays 1 ALD per block); hard cap of 200 eras |
| Total emission (exact, computed from the reward function) | 779,999,957.88 XEPC |
| Genesis block reward | 15 XEPC (the genesis block is block 0 of era 0) |
| Fees | go to the miner of the block; they do not create coins |

`reward(era) = floor(...floor(floor(15 XEPC * 9 / 10) * 9 / 10)...)`, applied `era` times.
The node refuses any block that would push the supply above the maximum.

Emission milestones (computed from the exact reward function; 15 s blocks):

| Era | Reward per block | Cumulative | Approx. year |
|---|---|---|---|
| 0 | 15 XEPC | 10.00% | 2.5 |
| 1 | 13.5 XEPC | 19.00% | 4.9 |
| 2 | 12.15 XEPC | 27.10% | 7.4 |
| 5 | 8.85735 XEPC | 46.86% | 14.8 |
| 6 | 7.971615 XEPC | 50% reached | 17.3 |
| 10 | 5.23017659 XEPC | 68.62% | 27.2 |
| 21 | 1.6412848 XEPC | 90% reached | 54.4 |
| 43 | 0.16162892 XEPC | 99% reached | 108.8 |
| 65 | 0.0159167 XEPC | 99.9% reached | 163.1 |
| 184 | 0.00000001 XEPC (1 ALD) | last non-zero era | ~457 |

Daily emission in era 0: 5,760 blocks x 15 XEPC = 86,400 XEPC per day.
`xepay getsupplyinfo` reports the live values (max, circulating, remaining,
percent mined, current era, remaining blocks).

## 3. Blocks and time

| Item | Value |
|---|---|
| Target block time | 15 seconds |
| Block version | 1 |
| Maximum transactions per block | 1,000 (about 5.4 MB with first-spend transactions, about 3.5 MB once keys are registered) |
| Coinbase maturity | 100 blocks (about 25 minutes) |
| Future time limit | a block more than 2 hours in the future is rejected |
| Block files | Bincode, rolled over at 128 MiB |
| Undo data kept | last 1,000 blocks |

## 4. Transactions and fees

| Item | Value |
|---|---|
| Model | account based; every transaction carries a per-account nonce |
| Maximum note length | 4,096 bytes |
| On-chain message | prefix `[MSG]`, at most 512 bytes, sent as a self-transfer of exactly 1 ALD |
| Self-transfer | rejected, except the on-chain message above |
| Typical transaction size | about 5.4 KB for the first spend of an address (carries the public key); about 3.4 KB afterwards |
| Default wallet fee | **0.01 XEPC** (1,000,000 ALD) |
| Minimum relay fee | 1 ALD per byte, raised to 2 / 5 / 10 ALD per byte when the mempool is 50% / 75% / 90% full |
| Mempool | at most 300 MiB and 20,000 transactions (20 blocks of backlog), entries expire after 14 days |
| Fee market | blocks take the highest fee rate first; when the mempool holds more than one block, `estimatefee` and the wallet raise the suggested fee above 0.01 XEPC; a full mempool evicts the cheapest transaction only for a clearly higher-paying one |
| Replace-by-fee | allowed with at least a 10% higher fee rate |

## 5. Addresses

| Network | Legacy (Base58Check) prefix byte | Bech32 prefix |
|---|---|---|
| Mainnet | 0x4b (addresses start with `X`) | `xepay` |
| Testnet | 0x6f | `xtes` |
| Regtest | 0x6f | `xreg` |

An address is derived from the SHA3-256 hash of the ML-DSA-65 public key.

## 6. Proof of work and difficulty

* **Before the Xephash activation height:** the block hash (SHA3-256 of the header) must be at most the target.
* **From `XEPHASH_ACTIVATION_*`:** Xephash v1 (memory-hard, see `XEPHASH.md`). Mainnet cache 4 MiB, dataset 128 MiB, epoch 30,000 blocks.
* **Difficulty before the activation:** the legacy schedule (interval 69,120 blocks).
* **Difficulty from the activation:** it restarts at a fixed value and is retargeted every **15 hours = 3,600 blocks**; the change is clamped to 0.25x .. 4x per window and never easier than the proof-of-work limit.
* Compact `nbits` format; genesis `nbits` 0x1e0ffff0 (mainnet and testnet), 0x207fffff (regtest).

## 7. State root and public key registry

From `STATE_ROOT_ACTIVATION_*` every header carries `state_root`, the root of a
hexary Merkle Patricia Trie over all accounts and registered public keys
(SHA3-256, RLP-encoded nodes). A block whose declared root differs from the
computed one is rejected. State changes are written atomically (accounts, undo
data and tip marker in one synced write). From the same height a transaction may
omit its public key when the sender's key is already registered.

## 8. Activation heights (hard fork)

| Feature | Mainnet | Testnet | Regtest |
|---|---|---|---|
| State root + key registry | 50,000 | 1 | 1 |
| Xephash + 15 hour retarget | 60,000 | 100 | 100 |

The mainnet values are placeholders: set them above the current tip plus a safety
margin before the release, and make every node upgrade before that height.

## 8b. Rule schedule

Rule parameters (`MAX_TX_PER_BLOCK`, `COINBASE_MATURITY`, `MAX_NOTE_LEN`, `BLOCK_VERSION`) are the base
rules from block 1. They change only through `RuleEra` entries (activation height) in
`src/consensus/rules.rs`; the schedules are empty today. They never influence the genesis block.

## 9. Checkpoints

Hard-coded lists per network in `blockchain::checkpoint` (see `CHECKPOINTS.md`).
Currently the lists are empty and only the genesis block is enforced; they are
filled from a synced node with `xepay generatecheckpoints`.

## 10. Networks

| Network | Flag | P2P port | RPC port | Magic | Data directory |
|---|---|---|---|---|---|
| Mainnet | (none) | 7555 | 7554 | `XEPC` (58455043) | `~/.xepay` |
| Testnet | `-testnet` | 12255 | 12254 | `ZTES` | `~/.xepay-testnet` |
| Regtest | `-regtest` | 18444 | 18443 | `ZREG` | `~/.xepay-regtest` |

Genesis (message `XEPAY Genesis - 2026`):

| Network | Timestamp (UTC) | Hash |
|---|---|---|
| Mainnet | 2026-11-15 09:09:40 | `00000828c058152573d532f6cfbacd535fec17f084a0aadfcc9dfaca6de69a5f` |
| Testnet | 2026-11-15 09:12:12 | `000009e097b67cc9806255f29717695be465077fb2b6693d8bb2cf3720c2a5ef` |
| Regtest | 2026-11-15 09:13:24 | `7376a1f85b4b34bdb47ba581cbce501a96284560425614764da3082a3e14fa8e` |

The genesis block is immutable and depends on genesis parameters only (see
`GENESIS_AND_RULES.md`). The node mines it at start and refuses to run if it does not
reproduce these hashes. `xepay getgenesishash` prints the active one.

## 11. Peer-to-peer protocol

| Item | Value |
|---|---|
| Frame header | magic (4) + command (12) + payload length (4) + checksum (4) |
| Maximum payload | 32 MiB |
| Protocol version | 1 |
| Maximum peers / outbound | 32 / 8 |
| Headers per `headers` message | 2,000 |
| Blocks in flight per peer | 16 |
| Maximum `inv` items / `addr` items | 50,000 / 1,000 |
| Block sync | headers first: `getheaders` / `headers` / `getdata` / `block` |
| New block announcement | `sendheaders` peers get a `headers` message (from the state root activation height), others get `inv` |
| Protection | anchors, ban manager, ASN map, per-peer rate limits, every header validated (hash, work, difficulty path, checkpoints) |

## 12. Binaries

| Binary | Purpose |
|---|---|
| `xepayd` | the node |
| `xepay` | command line client (RPC) |
| `xepay-miner` | stand-alone multi-threaded miner (restarts when the tip changes) |
| `xepay-genesis` | regenerates the genesis constants |
| `xephash` (crate `xepay-crypto`) | reference vectors, hash and benchmark tool |
