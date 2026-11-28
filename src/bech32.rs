// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Bech32 encoding/decoding for XEPAY Native SegWit addresses.

use bech32::{segwit, Fe32, Hrp}; // Import Hrp for parsing.

/// Encode a 20-byte witness program into a Native SegWit Bech32 address.
pub fn encode(hrp: &str, witness_program: &[u8]) -> Result<String, String> {
    if witness_program.len() != 20 {
        // Native SegWit (P2WPKH) requires a 20-byte witness program.
        return Err(format!(
            "witness program must be 20 bytes, got {}",
            witness_program.len()
        ));
    }

    // Parse the HRP string into an Hrp type.
    let hrp_parsed = Hrp::parse(hrp).map_err(|e| format!("invalid HRP: {}", e))?;

    // Encode using SegWit v0 (Fe32::Q = 0).
    segwit::encode(hrp_parsed, Fe32::Q, witness_program)
        .map_err(|e| format!("bech32 encoding failed: {}", e))
}

/// Decode a Native SegWit Bech32 address into its HRP and witness program.
pub fn decode(address: &str) -> Option<(String, Vec<u8>)> {
    // Only the canonical lowercase form is accepted. BIP-173 also allows an
    // all-uppercase address, but accepting it would give the same account two
    // different string keys (and the prefix checks in validation.rs are
    // case-sensitive).
    if address.chars().any(|c| c.is_ascii_uppercase()) {
        return None;
    }

    // Decode the SegWit address.
    let (hrp, variant, data) = segwit::decode(address).ok()?;

    // Ensure it is SegWit v0 (witness version 0).
    if variant != Fe32::Q {
        return None;
    }

    // Return the HRP as a string and the witness program.
    Some((hrp.to_string(), data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let prog = [7u8; 20];
        let addr = encode("xepay", &prog).unwrap();
        assert!(addr.starts_with("xepay1q"));
        let (hrp, data) = decode(&addr).unwrap();
        assert_eq!(hrp, "xepay");
        assert_eq!(data, prog.to_vec());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(encode("xepay", &[0u8; 19]).is_err());
        assert!(encode("xepay", &[0u8; 32]).is_err());
    }

    #[test]
    fn rejects_uppercase_and_bad_checksum() {
        let addr = encode("xepay", &[1u8; 20]).unwrap();
        assert!(decode(&addr.to_uppercase()).is_none());

        let mut bad = addr.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'q' { 'p' } else { 'q' });
        assert!(decode(&bad).is_none());
    }

    #[test]
    fn bip173_vector() {
        let (hrp, data) = decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        assert_eq!(hrp, "bc");
        assert_eq!(hex::encode(data), "751e76e8199196d454941c45d1b3a323f1433bd6");
    }
}
