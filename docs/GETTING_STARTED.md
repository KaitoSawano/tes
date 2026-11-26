# Getting Started with XEPAY

This guide will help you build, configure, and run an XEPAY node from source.

## 1. Prerequisites

- Rust (1.75 or later)
- Git
- Cargo

## 2. Build from Source

    git clone https://github.com/xepay-project/xepay.git
    cd xepay
    cargo build --release

## 3. Network Selection

| Network | Flag | P2P Port | RPC Port | Datadir |
|---|---|---|---|---|
| Mainnet | (none) | 7555 | 7554 | ~/.xepay |
| Testnet | -testnet | 12255 | 12254 | ~/.xepay-testnet |
| Regtest | -regtest | 18444 | 18443 | ~/.xepay-regtest |

## 4. Running a Node

    ./xepayd -regtest

## 5. Interacting with the Node

    ./xepay -regtest getinfo
    ./xepay -regtest getsupplyinfo

## 6. Create a Wallet

    ./xepay -regtest getcreatewallet
    ./xepay -regtest getcreatewalletbech32

## 7. Mining

    ./xepay -regtest generatetoaddress 10 "<your_address>"

## 8. Send Funds

    ./xepay -regtest sendtoaddress 5 "<to_address>"
    ./xepay -regtest estimatefee

## 9. Configuration File

    network=regtest
    port=18444
    rpcport=18443
    rpcuser=your_rpc_user
    rpcpassword=your_secure_password

## 10. Manual Reindex

    ./xepayd -regtest -reindex

A reindex replays every block and checks every declared state root.

## 11. Tools

    cargo run -p xepay-crypto --release --bin xephash -- bench regtest 5
    ./xepay generatecheckpoints

## 12. Troubleshooting

If RPC connection is refused, ensure the node is running and check the cookie file at ~/.xepay-regtest/.cookie.
