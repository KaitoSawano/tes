# Audit Keamanan Xepay (block palsu & node crash)

Audit manual (tanpa kompilasi). Jalankan `cargo test` sebelum rilis.

## Sudah diperbaiki di kode

| # | Berkas | Masalah | Dampak | Perbaikan |
|---|--------|---------|--------|-----------|
| 1 | `src/p2p/sync.rs` `handle_reorg` | Block pada jalur reorg RPC `submitblock` tidak diperiksa PoW, hash, merkle, reward, nbits, chainwork | Block palsu dengan `chainwork` besar bisa memutar balik rantai | Panggil `validate_block_structural` sebelum rollback |
| 2 | `src/blockchain.rs` `add_transaction` | RBF menghapus tx lama SEBELUM tx pengganti divalidasi | Siapa pun bisa menghapus tx pending orang lain dengan tx palsu (tanpa tanda tangan) berfee lebih tinggi | Tx lama dikembalikan bila validasi gagal |
| 3 | `src/blockchain.rs` `add_transaction` | Tx COINBASE/GENESIS lolos `validate_transaction` | Mempool tercemar | Tolak tx spesial; tolak nonce lama lebih awal (hemat CPU) |
| 4 | `src/validation.rs` overlay | Saldo penerima memakai `balance_of` (termasuk coinbase belum matang) | Block lolos validasi lalu gagal saat apply | Pakai `mature_balance_at` |
| 5 | `src/validation.rs` | `output_script` ada di txid tetapi tidak ditandatangani | Malleability txid, bloat data | Aturan baru E013: harus kosong |
| 6 | `src/validation.rs` header | nbits header tidak dibatasi `pow_limit` | Header murah palsu | Tambah cek batas |
| 7 | `src/p2p/message.rs` | String dari jaringan tanpa batas (hingga 32 MB); header boleh membawa transaksi | Boros memori/CPU | Batas 1024 byte; tolak header berisi tx |
| 8 | `src/p2p/network.rs` | Locator `getheaders` hingga 5000 x scan seluruh rantai | CPU DoS | Maksimal 101 locator |
| 9 | `src/p2p/sync.rs` | Block sisi cabang tidak cek format `state_root` | Konsistensi | Tambah `rule_block_state_root_format` |

## Diperbaiki juga (blockchain belum diluncurkan, jadi aman diubah)

- `Block::compute_work` sekarang menghitung work 256-bit: `2^256 / (target + 1)` (sebelumnya selalu 1). Fork-choice kini memakai work terbanyak. Genesis tetap `chainwork = 1` (nilai beku), hash genesis tidak berubah. Test `security_hardening_test.rs` disesuaikan.
- `submitblock` tidak lagi menghapus seluruh mempool; hanya tx yang basi.
- `is_txid_in_chain` (scan seluruh rantai per tx) dihapus dari `add_transaction`; nonce yang sudah terpakai sudah menolak tx tersebut.
- Alamat bech32 harus 20 byte.

## Koreksi temuan

Aturan Median-Time-Past TIDAK perlu ditambahkan: aturan `timestamp >= prev` sudah lebih ketat, dan retarget memakai MTP.

## Audit double spending, koin dari udara kosong, saldo tidak berkurang

Audit manual (tanpa kompilasi), hanya jalur uang: `validation.rs`, `storage/state.rs`, `blockchain.rs` (`stage_block`, `connect_block`, mempool), `p2p/sync.rs` (reorg), `pow.rs`, `block.rs`, `dilithium/*`.

### Yang diperiksa dan terbukti aman

| Risiko | Mengapa aman |
|--------|--------------|
| Double spend (tx yang sama dua kali / replay) | Nonce harus sama persis dengan nonce akun (`apply_tx_to_account`), txid ganda dalam satu block ditolak (E025), tanda tangan memuat chain id |
| Saldo tidak berkurang setelah transaksi | `apply_tx_to_account` selalu mengurangi `amount + fee` dengan `checked_sub`; self-send hanya mengembalikan `amount`, fee tetap berkurang |
| Koin dari udara kosong | `connect_block` memeriksa `pending_supply_delta == subsidy` sebelum commit; reward, subsidy, total_fees, merkle, dan txid dicek ulang di validasi |
| Overflow / underflow | Semua penjumlahan saldo, fee, nonce, dan reward memakai `checked_*` |
| Spend coinbase belum matang | Validasi dan apply memakai aturan maturity yang sama (`block.index`) |
| Tx tanpa tanda tangan lolos | `COINBASE` / `GENESIS` tidak lagi dianggap spesial di luar genesis; alamat `from` harus sama persis dengan hash public key |

### Sudah diperbaiki di kode

| # | Berkas | Masalah | Dampak | Perbaikan |
|---|--------|---------|--------|-----------|
| 10 | `src/blockchain.rs` `circulating_supply`, `mine_pending`; `src/validation.rs` `validate_block` | Suplai dihitung dari `reward` (subsidy + fee), padahal fee hanya berpindah dari pengirim ke miner | Suplai yang dilaporkan RPC membengkak; di dekat batas 780 juta block valid bisa ditolak (E041) | Hitung dari `subsidy` saja |
| 11 | `src/validation.rs` `validate_block_transactions` | Tx spesial (`COINBASE`/`GENESIS`) dilewati (`continue`) padahal `stage_block` menolaknya | Block lolos validasi lalu gagal saat apply; di jalur reorg memicu rebuild state penuh | Tolak langsung dengan E026, sama seperti `validate_tx_for_block` |

Catatan: kedua perbaikan tidak mengubah hasil validasi untuk rantai yang ada sekarang (suplai jauh di bawah batas, dan block normal tidak memuat tx spesial), jadi tidak memecah konsensus.
