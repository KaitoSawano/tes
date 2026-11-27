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
