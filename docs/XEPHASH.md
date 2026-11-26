# Xephash v1

Memory-hard proof of work of XEPAY. It keeps SHA3-256 as the only hash and
adds an epoch cache and a dataset (cache -> dataset -> 64 random page reads).

## Function

* `H` = SHA3-256, words are little-endian `u32`, the nonce is a little-endian `u64`.
* `fnv(a,b) = (a*0x01000193 mod 2^32) xor b`, `reduce(x,n) = (x*n) >> 32`.
* `seed(e)` = `H` applied `e` times to 32 zero bytes, `e = block / epoch_length`.
* Cache: `c[0]=H(seed)`, `c[i]=H(c[i-1])`; then 3 rounds of
  `c[i] = H(c[i-1] xor c[reduce(first_word(c[i]), n)])`.
* Dataset item `i`: start from `c[i % n]`, `w[0] ^= i`, hash, fold 128 parents
  `c[reduce(fnv(i^j, w[j%8]), n)]` with `fnv`, hash again.
* Hash: `seed = H("XEPHASH1" || header_hash || nonce)`, a 128-byte mix starts as
  the seed x4, 64 reads of 4 consecutive items are folded in with `fnv`, the mix
  is compressed to 32 bytes, `result = H("XEPHASH1" || seed || mix_digest)`.
* The block is valid when `result <= target` (big-endian compare).

Verification uses only the cache (light mode, about 1-3 ms). Miners build the
full dataset (Main: 128 MiB) once per epoch.

## Integration

* **Header:** `Block::seal_hash()` = hash of the header without the nonce
  (from the activation height the header hash does not depend on the
  transactions). `Block::hash` stays the block id (hash of the full header).
* **Mining:** `pow::mine*` switches to `pow::mine_xephash` from
  `rules::xephash_activation_height()`; the dataset is built on first use.
* **Validation:** `validation::rule_block_pow` (and the header-only and chain
  checks) call `pow::block_meets_pow`, which verifies Xephash from the activation.
* **Difficulty:** the first Xephash block uses `rules::xephash_start_nbits()`,
  later blocks retarget as before. `adjust_difficulty` recomputes `nbits`
  from the chain, so it is also correct after a restart or a reorg.
* **Hard fork:** set `XEPHASH_ACTIVATION_MAIN` above the current tip and make
  every node upgrade before that height. Tune `xephash_start_nbits()` first.

Parameters live in `crypto/src/xephash.rs` (`Params::MAIN`, `TEST`, `REGTEST`).

## Difficulty (15 hour retarget)

From the Xephash activation the difficulty restarts at `rules::xephash_start_nbits()`
and is retargeted every 3600 blocks (15 hours at 15 s blocks), counted from the
activation block. The measured time of a window uses the median-time-past of its
first and last block. The change per window is clamped to 0.25x .. 4x and the
target never exceeds the proof-of-work limit. `Blockchain::adjust_difficulty`
recomputes the value from the chain, so it survives restarts and reorgs.

## Checkpoints

`blockchain::checkpoint` holds one list per network (empty by default). A
checkpoint rejects any block or header with a different hash at that height and
forbids reorganizations below the highest checkpoint already in the chain.
Add entries with `xepay getcheckpoint [height]` (prints the Rust line to paste).

## Tools for the community

```text
cargo run -p xepay-crypto --release --bin xephash -- vectors
cargo run -p xepay-crypto --release --bin xephash -- bench main 10
cargo run -p xepay-crypto --release --bin xephash -- hash main 60000 <header_hex> <nonce>
```

`vectors` prints the reference values that every independent implementation must
reproduce, `bench` measures cache/dataset build time and the light/full hash rate.
