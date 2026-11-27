> A fast-block, post-quantum Layer-1 payment network written in Rust.
> **ML-DSA-65** signatures, **SHA3-256** hashing, **Xephash** memory-hard proof of work.
> **15-second target block time**, difficulty retargeted every 15 hours.

![language](https://img.shields.io/badge/language-Rust-orange)
![hash](https://img.shields.io/badge/hash-SHA3--256-green)
![signatures](https://img.shields.io/badge/signatures-ML--DSA--65-blue)
![consensus](https://img.shields.io/badge/consensus-Proof%20of%20Work%20(Xephash)-purple)

---

## Overview

**XEPAY** (**XEPC**) is an independent Layer-1 proof-of-work payment network written in Rust.
It uses an account-based ledger, a Merkle Patricia Trie state root, LevelDB storage and a
headers-first peer-to-peer protocol. It focuses on one job: fast, verifiable value transfer.

* **Post-quantum signatures:** every transaction is signed with ML-DSA-65 (FIPS 204).
* **Memory-hard proof of work:** Xephash (SHA3-256 based) keeps verification light (a few milliseconds) while mining depends on memory bandwidth. See `docs/XEPHASH.md`.
* **Verifiable by construction:** every block commits to its parent, to its transactions and to the full state (state root); nodes verify everything from genesis.
* **Safe by design:** atomic state commits, crash recovery, overflow-checked arithmetic, a per-block money-conservation check and hard-coded checkpoints.
* **Fee market:** the default fee is 0.01 XEPC and rises when the mempool has a backlog.

## Key numbers

| | |
|---|---|
| Maximum supply | 780,000,000 XEPC (8 decimals) |
| Initial block reward | 15 XEPC, reduced by 10% every 5,200,000 blocks (about 2.47 years) |
| Block time | 15 seconds |
| Difficulty retarget | every 15 hours (3,600 blocks), limited to 0.25x .. 4x per window |
| Block limit | 1,000 transactions |
| Coinbase maturity | 100 blocks |
| Default fee | 0.01 XEPC |

The complete, code-derived specification is in `docs/SPECIFICATION.md`.

## Install

```bash
git clone https://github.com/xepay-project/xepay.git
cd xepay
cargo build --release
./build.sh          # copies the binaries to the project root
./xepay help
```

## Networks

| Network | Flag | P2P Port | RPC Port |
|---|---|---|---|
| Mainnet | (none) | 7555 | 7554 |
| Testnet | -testnet | 12255 | 12254 |
| Regtest | -regtest | 18444 | 18443 |

Regtest is a private network for local development with trivial difficulty.

## Running

```bash
./xepayd                # mainnet node
./xepayd -testnet       # testnet node
./xepayd -regtest       # local development
XEPC_MINE_FOR="<address>" ./xepay-miner   # stand-alone miner (all CPU cores)
```

## Documentation

| Document | Content |
|---|---|
| `docs/SPECIFICATION.md` | all parameters: supply, emission, fees, networks, P2P |
| `docs/CONSENSUS.md` | block validity rules, difficulty, state root |
| `docs/XEPHASH.md` | the proof-of-work algorithm and the `xephash` tool |
| `docs/CHECKPOINTS.md` | how checkpoints work and how to add them |
| `docs/GENESIS_AND_RULES.md` | immutable genesis, rule schedule and upgrade process |
| `docs/ARCHITECTURE.md`, `docs/P2P_NETWORK.md`, `docs/SECURITY.md` | design and threat model |
| `docs/RPC_API.md`, `docs/WALLET.md`, `docs/GETTING_STARTED.md` | usage |

## License

Copyright (c) 2026 **Aldianokto**.
Licensed under the **Apache License, Version 2.0**. See the LICENSE file.
