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

#[test]
fn bech32_bip173_32_byte_program() {
    let (hrp, data) =
        decode("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7").unwrap();
    assert_eq!(hrp, "tb");
    assert_eq!(
        hex::encode(data),
        "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
    );
}

#[test]
fn bech32_bip173_invalid_vectors() {
    // Bad checksum.
    assert!(decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5").is_none());
    // Witness version above 0 is not used by XEPAY.
    assert!(decode("bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du").is_none());
    // Invalid zero padding.
    assert!(decode("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv").is_none());
    // Empty data part and empty HRP.
    assert!(decode("bc1gmk9yu").is_none());
    assert!(decode("1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_none());
}
