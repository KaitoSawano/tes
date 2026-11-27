# Genesis, Rules and Upgrades

The chain is a sequence of blocks, each pointing to the previous one, and the foundation is
block 0. The foundation must never move. XEPAY therefore separates two kinds of parameters.

## 1. Genesis parameters (immutable)

They define block 0 and are the ONLY inputs of the genesis hash (`src/consensus/genesis.rs`,
`GenesisParams`):

* genesis timestamp, genesis `nbits`, genesis message, genesis secret, genesis output script
* network name, hash algorithm, signature algorithm
* supply economics: `MAX_SUPPLY(_XEPC)`, `INITIAL_REWARD(_XEPC)`, `SUBSIDY_HALVING_INTERVAL`,
  `REWARD_REDUCTION_NUMERATOR/DENOMINATOR`, `MAX_ERAS`, `DECIMALS`, `ALD_PER_XEPC`

All of them are committed in `GenesisParams::commitment()`, which is stored in the genesis header.
Changing any of them changes the genesis hash. Such a build is a different network: every other node
rejects its blocks (block 1 points to another parent) and it can never join the main network.

## 2. Rule parameters (upgradable)

`MAX_TX_PER_BLOCK`, `COINBASE_MATURITY`, `MAX_NOTE_LEN`, `BLOCK_VERSION`, the difficulty schedule, the
proof-of-work algorithm, the zero hash and every other validation rule. They do NOT enter the genesis
hash. Block version, previous hash, chainwork and the date string of block 0 are frozen genesis
constants, so even a change of the rule `BLOCK_VERSION` cannot touch block 0.

They change only through an **activation height**:

* `rules::RuleEra { activation_height, rules }` in the schedule of the network
  (`MAIN_RULE_SCHEDULE`, ...). The era is valid from that height; older blocks keep their rules.
  An era can never activate at height 0.
* feature switches use an activation constant (`STATE_ROOT_ACTIVATION_*`, `XEPHASH_ACTIVATION_*`),
  never below height 1.

A node that edits a rule without an activation height keeps the same genesis hash but validates
differently: it rejects blocks that the network accepts (or the other way round) and forks itself off
until it installs the release that everybody else runs.

## 3. How a rule change is rolled out

1. **Proposal:** describe the change, the reason and the exact new value publicly.
2. **Implementation:** add a `RuleEra` (or an activation constant) with an activation height far
   in the future (weeks). Never edit the base constants.
3. **Release:** publish the release with notes and checksums. Ask exchanges, pools and node operators to upgrade.
4. **Monitoring:** watch the share of upgraded nodes (`getpeerinfo` user agent) and miners.
5. **Activation:** at the activation height the new rules apply. Not upgraded nodes reject the first block
   that follows the new rules and stay behind. Their operators install the new release and resync;
   they never need a new genesis.
6. **Soft fork rule of thumb:** make the rule stricter (smaller block, longer maturity): blocks of
   upgraded miners are still valid for old nodes. **Hard fork:** looser rules need every node to upgrade.
7. **Checkpoints:** after the activation, add a checkpoint at a deep block so nobody can rewrite it.

## 4. Checkpoints and genesis

Checkpoints are hard-coded block hashes (`blockchain::checkpoint`). Block hashes depend on the genesis,
so a checkpoint table is only valid for the genesis it was created with. If someone changes a genesis
parameter, every block hash changes, and the old checkpoints point to hashes that do not exist:

* a block at a checkpoint height is rejected (an ordinary validation error, never a panic);
* a stored chain that contradicts a checkpoint stops the node with a clear message at start;
* a node with a stale table and a new genesis simply never accepts the checkpointed block:
  it is isolated, not crashed.

Lookups for heights without a checkpoint, empty tables and chains shorter than a checkpoint height are
normal answers (`true`/`Ok`). Malformed tables are refused at start (`checkpoint::self_check`).

## 5. Tests that guard this

`src/tests/genesis_immutability_test.rs`:

* the genesis constants reproduce without mining and meet the genesis difficulty;
* changing each genesis parameter changes the commitment and the genesis hash;
* `GenesisParams` has no rule field (compile-time destructuring), and neither `genesis.rs` nor the
  genesis builders of `block.rs` read `rules::` (source lint);
* a made-up rule schedule changes the rules and leaves every genesis commitment untouched;
* a modified genesis gives a different chain: block 1 of the real chain is rejected by it;
* checkpoints with missing heights, wrong hashes, wrong indexes and short chains never panic.
