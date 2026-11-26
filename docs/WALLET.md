# XEPAY Wallet Guide

The wallet file is `wallet.dat` in the data directory of the network. It holds
ML-DSA-65 keys (32-byte seeds). There is no HD wallet: no standard for
hierarchical post-quantum key derivation exists yet, so it was removed.

## Addresses

- Legacy (Base58Check): `./xepay getcreatewallet` (mainnet addresses start with `X`).
- Bech32: `./xepay getcreatewalletbech32` (prefix `xepay`, testnet `xtes`, regtest `xreg`).
- List: `./xepay getlistwallet`, details: `./xepay getaddressinfo "<address>"`.

## Keys and backup

- Dump a key: `./xepay dumpprivkey "<address>"`; import: `./xepay importprivkey "<secret>"`.
- Dump everything: `./xepay dumpwallet`.
- Backup: `./xepay backupwallet "<destination>"`.

## Sending

- `./xepay sendtoaddress 5 "<to_address>"` selects the source address and the fee.
  The fee is 0.01 XEPC by default and is raised automatically while the mempool is congested
  (`./xepay estimatefee`).
- The first transaction of an address includes its public key (about 5.4 KB); later
  transactions are about 3.4 KB because the key is already registered on chain.

## Encryption

- Encrypt: `./xepay encryptwallet "<password>"` (AES-256-GCM, key from PBKDF2-HMAC-SHA256).
- Unlock: `./xepay walletpassphrase "<password>"`.

**Important:** back up `wallet.dat`. If you lose it, your funds are lost forever.
