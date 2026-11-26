# XEPAY Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in XEPAY, please do not open a public issue. Contact the maintainers directly.

## Best Practices

1. Never share your private keys.
2. Always verify the checksum of downloaded binaries.
3. Keep your node software up to date; upgrade before every announced activation height.
4. Run your node behind a firewall if possible.
5. Back up `wallet.dat` regularly and encrypt it (`encryptwallet`).

## Threat model and defenses

| Threat | Defense |
|---|---|
| Fake or very old history | checkpoints (blocks, headers, reorg limit, stored chain) and cumulative chainwork |
| Cheap fake headers | every header is validated: recomputed hash, difficulty path, Xephash, timestamp, chainwork, checkpoints |
| Double spend | proof of work, per-account nonces, mature-balance checks |
| Coins from nothing (overflow) | `checked_*` arithmetic everywhere, per-block money-conservation check, supply cap |
| State corruption or crash | in-memory block batch, state root check, single synced write, crash recovery on start, `-reindex` |
| Eclipse / Sybil | anchors, ban manager, ASN map, peer limits |
| Spam | fee market, relay fee floor, mempool caps, per-peer message rate limits |
| Quantum computers | ML-DSA-65 signatures and SHA3-256 |

## Cryptography

- SHA3-256 for hashing.
- ML-DSA-65 (FIPS 204) for signatures.
- Xephash (SHA3-256 based, memory hard) for proof of work.
- AES-256-GCM and PBKDF2-HMAC-SHA256 for wallet encryption.
