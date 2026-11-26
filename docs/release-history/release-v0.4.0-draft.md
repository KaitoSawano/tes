# XEPAY Release History - next release (draft)

Hard fork. Activation heights are set in `src/consensus/rules.rs`; every node must upgrade before them.

### New
- **Xephash proof of work** (memory-hard, SHA3-256 based) with a light verification mode, a multi-threaded miner and the stand-alone `xephash` tool.
- **Difficulty retarget every 15 hours** (3,600 blocks), limited to 0.25x .. 4x per window.
- **State root** in every block header (Merkle Patricia Trie) with atomic commits and crash recovery.
- **Public key registry:** transactions after the first spend are about 37% smaller.
- **Fee market:** the default fee stays 0.01 XEPC and rises when the mempool has a backlog; `estimatefee`.
- **Working checkpoints:** blocks, headers, reorganizations and the stored chain are checked; `getcheckpoints`, `getcheckpoint`, `generatecheckpoints`.
- **Headers announcements** (`sendheaders`) with full header validation.

### Fixed
- The retarget formula was off by a factor of 256 and could only make mining easier.
- The difficulty was not restored after a restart.
- Remote crash on a crafted `nbits` header; overflow in the block fee sum; several unchecked additions.
- `submitblock` and `generatetoaddress` could leave a half-applied state after a failure or interrupt.
- Pending transactions of one sender were not included in mined blocks.
- Reorg undo data did not delete accounts created by the undone block.
