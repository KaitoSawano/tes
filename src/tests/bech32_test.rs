// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

use xepay::bech32::{decode, encode};

#[test]
fn bech32_roundtrip() {
    let prog = [7u8; 20];
    let addr = encode("xepay", &prog).unwrap();
    assert!(addr.starts_with("xepay1q"));
    let (hrp, data) = decode(&addr).unwrap();
    assert_eq!(hrp, "xepay");
    assert_eq!(data, prog.to_vec());
}

#[test]
fn bech32_rejects_wrong_length() {
    assert!(encode("xepay", &[0u8; 19]).is_err());
    assert!(encode("xepay", &[0u8; 32]).is_err());
}

#[test]
fn bech32_rejects_uppercase_and_bad_checksum() {
    let addr = encode("xepay", &[1u8; 20]).unwrap();
    assert!(decode(&addr.to_uppercase()).is_none());

    let mut bad = addr.clone();
    let last = bad.pop().unwrap();
    bad.push(if last == 'q' { 'p' } else { 'q' });
    assert!(decode(&bad).is_none());
}

#[test]
fn bech32_bip173_vector() {
    let (hrp, data) = decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    assert_eq!(hrp, "bc");
    assert_eq!(hex::encode(data), "751e76e8199196d454941c45d1b3a323f1433bd6");
}
