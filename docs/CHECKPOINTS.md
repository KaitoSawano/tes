# Checkpoints

A checkpoint is a trusted pair (height, block hash) written into the source code.
It protects nodes against a long, fake history and against reorganizations of
very old blocks.

## What the node enforces

1. **Blocks and headers:** a block or header at a checkpoint height whose hash is
   different is rejected (`rule_block_checkpoint`, also during header sync).
2. **Reorganizations:** a fork whose common ancestor is below the highest
   checkpoint that is already in the chain is rejected (`reorg_allowed`). Blocks up
   to that checkpoint are final.
3. **Stored chain:** at start the node verifies the loaded chain against the
   genesis hash and every checkpoint. A mismatch is fatal: the data directory is
   corrupt, tampered with or on another fork.
4. **Table sanity:** at start every table is validated (heights above 0 and strictly
   increasing, hashes 64 lowercase hex characters). A typo stops the node instead of
   silently locking it out of the real chain.

The genesis block is checkpoint 0 and is always enforced (`xepay getcheckpoints`
shows it first).

## Adding checkpoints

On a fully synced node:

```text
xepay generatecheckpoints            # every 1000 blocks, only blocks with 100+ confirmations
xepay generatecheckpoints 10000 500  # every 10000 blocks, 500+ confirmations
xepay getcheckpoint 123456           # one line for one height
```

Each line looks like `Checkpoint { height: 123456, hash: "..." },`. Paste the lines
into `MAIN_CHECKPOINTS` (or `TEST_CHECKPOINTS`) in `src/blockchain.rs`, in ascending
order, then build and release. Rules for maintainers:

* use only blocks that are buried deep (hundreds of confirmations) and that you
  have verified on at least two independent nodes;
* add checkpoints with every release, never remove one;
* a checkpoint is a consensus rule: all nodes must run the same table.

Currently the tables are empty (no checkpoint beyond genesis).
