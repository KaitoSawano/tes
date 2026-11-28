// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Bech32 encoding/decoding for XEPAY Native SegWit addresses.
//!
//! Implemented from scratch following BIP-173 (no external Bech32 crate).
//! Only witness version 0 with the original Bech32 checksum is used.

/// The 32-character Bech32 alphabet.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Generator coefficients of the BCH code used by the checksum.
const GENERATOR: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];

/// Maximum length of a complete Bech32 string (BIP-173).
const MAX_ADDRESS_LEN: usize = 90;

/// Length of the checksum in 5-bit symbols.
const CHECKSUM_LEN: usize = 6;

/// BCH checksum over a sequence of 5-bit values.
fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Expand the HRP into the values that are mixed into the checksum.
fn hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 2 + 1);
    for &c in bytes {
        out.push(c >> 5);
    }
    out.push(0);
    for &c in bytes {
        out.push(c & 31);
    }
    out
}

/// Compute the 6-symbol checksum for `hrp` and `data` (5-bit values).
fn create_checksum(hrp: &str, data: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; CHECKSUM_LEN]);
    let m = polymod(&values) ^ 1;
    let mut out = [0u8; CHECKSUM_LEN];
    for (i, o) in out.iter_mut().enumerate() {
        *o = ((m >> (5 * (CHECKSUM_LEN - 1 - i))) & 31) as u8;
    }
    out
}

/// Check the checksum of `data` (which includes the 6 checksum symbols).
fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == 1
}

/// Regroup a sequence of `from`-bit values into `to`-bit values.
///
/// With `pad == true` the last group is zero padded; with `pad == false`
/// leftover bits must be fewer than `from` and all zero, otherwise the input
/// is rejected (this is the strict rule BIP-173 requires when decoding).
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
    let max_value: u32 = (1 << to) - 1;
    let max_acc: u32 = (1 << (from + to - 1)) - 1;

    for &v in data {
        if (v as u32) >> from != 0 {
            return None;
        }
        acc = ((acc << from) | v as u32) & max_acc;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max_value) as u8);
        }
    }

    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & max_value) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & max_value) != 0 {
        return None;
    }
    Some(out)
}

/// Encode a 20-byte witness program into a Native SegWit Bech32 address.
pub fn encode(hrp: &str, witness_program: &[u8]) -> Result<String, String> {
    if witness_program.len() != 20 {
        // Native SegWit (P2WPKH) requires a 20-byte witness program.
        return Err(format!(
            "witness program must be 20 bytes, got {}",
            witness_program.len()
        ));
    }

    // The HRP must be 1..=83 printable ASCII characters, lowercase only.
    if hrp.is_empty()
        || hrp.len() > 83
        || hrp
            .bytes()
            .any(|c| !(33..=126).contains(&c) || c.is_ascii_uppercase())
    {
        return Err(format!("invalid HRP: {}", hrp));
    }

    // SegWit v0 (witness version 0) followed by the program as 5-bit groups.
    let mut data: Vec<u8> = vec![0];
    data.extend(
        convert_bits(witness_program, 8, 5, true)
            .ok_or_else(|| "bech32 encoding failed: bit conversion".to_string())?,
    );
    let checksum = create_checksum(hrp, &data);

    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + CHECKSUM_LEN);
    out.push_str(hrp);
    out.push('1');
    for &d in data.iter().chain(checksum.iter()) {
        out.push(CHARSET[d as usize] as char);
    }

    if out.len() > MAX_ADDRESS_LEN {
        return Err("bech32 encoding failed: address too long".to_string());
    }
    Ok(out)
}

/// Decode a Native SegWit Bech32 address into its HRP and witness program.
pub fn decode(address: &str) -> Option<(String, Vec<u8>)> {
    if address.len() < 8 || address.len() > MAX_ADDRESS_LEN {
        return None;
    }
    let bytes = address.as_bytes();

    // Only the canonical lowercase form is accepted. BIP-173 also allows an
    // all-uppercase address, but accepting it would give the same account two
    // different string keys (and the prefix checks in validation.rs are
    // case-sensitive). Non-printable and non-ASCII bytes are rejected too.
    if bytes
        .iter()
        .any(|&c| !(33..=126).contains(&c) || c.is_ascii_uppercase())
    {
        return None;
    }

    // The separator is the LAST '1'. The HRP must be non-empty and the data
    // part must hold the witness version plus the 6 checksum symbols.
    let sep = address.rfind('1')?;
    if sep < 1 || sep + 1 + CHECKSUM_LEN + 1 > address.len() {
        return None;
    }
    let hrp = &address[..sep];

    // Map the data part back to 5-bit values.
    let mut data: Vec<u8> = Vec::with_capacity(address.len() - sep - 1);
    for &c in &bytes[sep + 1..] {
        let idx = CHARSET.iter().position(|&x| x == c)?;
        data.push(idx as u8);
    }

    if !verify_checksum(hrp, &data) {
        return None;
    }

    let payload = &data[..data.len() - CHECKSUM_LEN];

    // Ensure it is SegWit v0 (witness version 0).
    if payload[0] != 0 {
        return None;
    }

    // The program must regroup to whole bytes with zero padding only, and a
    // v0 program is either 20 bytes (P2WPKH) or 32 bytes (P2WSH).
    let program = convert_bits(&payload[1..], 5, 8, false)?;
    if program.len() != 20 && program.len() != 32 {
        return None;
    }

    Some((hrp.to_string(), program))
}
