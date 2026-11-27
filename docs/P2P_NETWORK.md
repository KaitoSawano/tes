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

### Stall handling during sync

- A `headers` response is also limited to about 6 MiB; the requester continues from the last header it
  received, so a response can contain fewer than 2,000 headers.
- `getheaders` is not repeated automatically while an answer is still outstanding (minimum 15 seconds
  between automatic retries to the same peer). A repeated answer that adds no new header does not trigger
  another request.
- A peer is "stalling" only when no bytes at all were read from it for the stalling timeout (20 seconds at
  the start, doubled on each stall up to 120 seconds), or when it delivered no block for 60 seconds. The
  timer starts when the request is made.
- A stalling peer is not disconnected. Its in-flight requests are dropped and the same blocks are asked for
  again after a short cooldown (5 seconds). A block that arrives late is still accepted when its hash matches
  a validated header inside the download window.
- These rules only change local behaviour. The wire protocol and the consensus rules are unchanged, so no
  fork is needed and updated nodes stay compatible with nodes that are not yet updated.

## Limits

Maximum payload 32 MiB, 32 peers (8 outbound), 50,000 `inv` items and 1,000 `addr` items per message, with
per-peer rate limits.
