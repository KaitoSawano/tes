// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

use xepay::base58::{decode, encode};

#[test]
fn base58_roundtrip() {
    let payload = [vec![0x4bu8], vec![9u8; 20]].concat();
    let addr = encode(&payload);
    assert_eq!(decode(&addr), Some(payload));
}

#[test]
fn base58_keeps_leading_zero_bytes() {
    let payload = vec![0u8, 0, 1, 2, 3];
    assert_eq!(decode(&encode(&payload)), Some(payload));
}

#[test]
fn base58_rejects_corrupted_checksum() {
    let addr = encode(&[0x4bu8; 21]);
    let mut chars: Vec<char> = addr.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == '2' { '3' } else { '2' };
    let bad: String = chars.into_iter().collect();
    assert!(decode(&bad).is_none());
}

#[test]
fn base58_rejects_invalid_input() {
    assert!(decode("").is_none());
    assert!(decode("0OIl").is_none());
}
