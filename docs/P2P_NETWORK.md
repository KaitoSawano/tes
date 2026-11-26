# XEPAY P2P Network

The XEPAY peer-to-peer network uses raw TCP with a custom framing protocol.

## Message Framing

Each message has a header containing:
- Network Magic (4 bytes)
- Command (12 bytes)
- Payload Length (4 bytes)
- Checksum (4 bytes)

## Handshake

When two nodes connect, they exchange `version` and `verack` messages to establish compatibility and share their current chain height.

## Anti-Eclipse Mechanisms

1. **Anchors:** Persists up to 2 block-relay-only connections across restarts.
2. **Banman:** Manual ban list for malicious peers.
3. **ASMap:** Maps IP addresses to Autonomous System Numbers to prevent Sybil attacks.

## Synchronization

Nodes sync headers first: `getheaders` / `headers` / `getdata` / `block`. Every received header is
validated (linkage, recomputed hash, difficulty path, proof of work, timestamp, chainwork, checkpoints)
before it is accepted, so a peer cannot inflate the known chain with fake headers. At most 2,000
headers are sent per message and 16 blocks are in flight per peer.

A peer that sent `sendheaders` receives new blocks as a `headers` message (from the state root activation
height, when a header alone proves the block); other peers receive `inv`. A header that does not connect
makes the node ask for the missing headers with `getheaders`.

Reorganizations never go below the highest checkpoint that is already in the chain.

## Limits

Maximum payload 32 MiB, 32 peers (8 outbound), 50,000 `inv` items and 1,000 `addr` items per message, with
per-peer rate limits.
