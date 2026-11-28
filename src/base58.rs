// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Base58Check encoding/decoding for XEPAY Legacy addresses.
//!
//! Implemented from scratch (no external Base58 crate). The raw Base58
//! alphabet is the same one Bitcoin uses; the 4-byte checksum is the first
//! four bytes of a double SHA3-256 of the payload.

use xepay_crypto::sha3_256_hex;

/// The Base58 alphabet (no `0`, `O`, `I` and `l`).
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Upper bound for the length of a string accepted by `decode`. A legacy
/// address is at most ~35 characters; the cap keeps the quadratic base
/// conversion cheap for hostile input.
const MAX_DECODE_LEN: usize = 128;

/// Encode raw bytes as Base58 (no checksum).
pub fn encode_raw(input: &[u8]) -> String {
    // Every leading zero byte is written as a leading '1'.
    let zeros = input.iter().take_while(|&&b| b == 0).count();

    // Base-58 digits, least significant digit first.
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 138 / 100 + 1);
    for &byte in &input[zeros..] {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

/// Decode a Base58 string into raw bytes (no checksum). Returns `None` if the
/// string contains a character outside the alphabet.
pub fn decode_raw(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();

    // Every leading '1' stands for one leading zero byte.
    let zeros = bytes.iter().take_while(|&&c| c == b'1').count();

    // Base-256 bytes, least significant byte first.
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() * 733 / 1000 + 1);
    for &c in &bytes[zeros..] {
        let mut carry = ALPHABET.iter().position(|&a| a == c)? as u32;
        for b in out.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut result = vec![0u8; zeros];
    result.extend(out.iter().rev());
    Some(result)
}

pub fn encode(payload: &[u8]) -> String {
    let mut body = payload.to_vec();
    let checksum = compute_checksum(payload);
    body.extend_from_slice(&checksum);
    encode_raw(&body)
}

pub fn decode(address: &str) -> Option<Vec<u8>> {
    if address.len() > MAX_DECODE_LEN {
        return None;
    }
    let decoded = decode_raw(address)?;
    if decoded.len() < 4 {
        return None;
    }
    let (payload, checksum) = decoded.split_at(decoded.len() - 4);
    let expected = compute_checksum(payload);
    if checksum != expected {
        return None;
    }
    Some(payload.to_vec())
}

fn compute_checksum(payload: &[u8]) -> [u8; 4] {
    let first_hash = sha3_256_hex(payload);
    let first_bytes = hex::decode(&first_hash).expect("sha3 hex is always valid");
    let second_hash = sha3_256_hex(&first_bytes);
    let second_bytes = hex::decode(&second_hash).expect("sha3 hex is always valid");
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&second_bytes[..4]);
    checksum
}
