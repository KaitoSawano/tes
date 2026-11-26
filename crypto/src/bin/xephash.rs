// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! `xephash`: stand-alone tool to verify, benchmark and cross-check Xephash.
//!
//! ```text
//! xephash vectors                              print the reference test vectors
//! xephash hash <net> <block> <header_hex> <nonce>   evaluate one hash (light mode)
//! xephash bench <net> [seconds]                benchmark light and full mode
//! ```
//! `<net>` is `main`, `test` or `regtest`.

use std::time::{Duration, Instant}; // timing for the benchmark

use xepay_crypto::sha3::sha3_256; // used to build the fixed test header
use xepay_crypto::xephash::{
    epoch_seed, hashimoto_full, hashimoto_light, Cache, Dataset, Engine, Item, Params,
}; // the Xephash API

/// Print usage and return a failing exit code.
fn usage() -> i32 {
    eprintln!("usage:");
    eprintln!("  xephash vectors");
    eprintln!("  xephash hash <main|test|regtest> <block_number> <header_hash_hex> <nonce>");
    eprintln!("  xephash bench <main|test|regtest> [seconds]");
    2 // conventional "bad usage" exit code
}

/// Map a network name to its parameters.
fn params_for(name: &str) -> Option<Params> {
    match name {
        "main" => Some(Params::MAIN),
        "test" => Some(Params::TEST),
        "regtest" => Some(Params::REGTEST),
        _ => None,
    }
}

/// `xephash vectors`: reproduce the published reference vectors.
fn cmd_vectors() -> i32 {
    let (cache_items, dataset_items) = (64u32, 256u32); // small parameters used by the vectors
    let header: Item = sha3_256(b"xephash test header"); // fixed 32-byte header hash
    let nonce: u64 = 0x0123_4567_89ab_cdef; // fixed nonce
    println!("# Xephash v1 reference vectors (cache_items=64, dataset_items=256)");
    println!("# header_hash = SHA3-256(\"xephash test header\") = {}", hex::encode(header));
    println!("# nonce = 0x{:016x}", nonce);
    for epoch in 0..2u64 {
        let seed = match epoch_seed(epoch) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: {}", e);
                return 1;
            }
        };
        let cache = match Cache::generate(&seed, cache_items) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: {}", e);
                return 1;
            }
        };
        let dataset = match Dataset::generate(&cache, dataset_items, 1) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("error: {}", e);
                return 1;
            }
        };
        let full = hashimoto_full(&dataset, &header, nonce);
        let light = hashimoto_light(&cache, dataset_items, &header, nonce);
        match (full, light) {
            (Ok(f), Ok(l)) => {
                println!("epoch {}", epoch);
                println!("  seed        {}", hex::encode(seed));
                println!("  dataset_item(0)   {}", hex::encode(cache.dataset_item(0)));
                println!("  dataset_item(255) {}", hex::encode(cache.dataset_item(255)));
                println!("  mix_digest  {}", hex::encode(f.mix_digest));
                println!("  result      {}", hex::encode(f.result));
                println!("  light==full {}", f == l);
            }
            _ => {
                eprintln!("error: evaluation failed");
                return 1;
            }
        }
    }
    0
}

/// `xephash hash ...`: evaluate one hash in light mode.
fn cmd_hash(args: &[String]) -> i32 {
    if args.len() != 4 {
        return usage();
    }
    let params = match params_for(&args[0]) {
        Some(p) => p,
        None => return usage(),
    };
    let block: u64 = match args[1].parse() {
        Ok(v) => v,
        Err(_) => return usage(),
    };
    let header_bytes = match hex::decode(&args[2]) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            eprintln!("header_hash must be 64 hex characters");
            return 2;
        }
    };
    let mut header: Item = [0u8; 32];
    header.copy_from_slice(&header_bytes); // exactly 32 bytes (checked above)
    let nonce: u64 = match args[3].parse() {
        Ok(v) => v,
        Err(_) => return usage(),
    };
    let engine = match Engine::new(params) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {}", e);
            return 1;
        }
    };
    match engine.verify(block, &header, nonce) {
        Ok(out) => {
            println!("mix_digest {}", hex::encode(out.mix_digest));
            println!("result     {}", hex::encode(out.result));
            0
        }
        Err(e) => {
            eprintln!("error: {}", e);
            1
        }
    }
}

/// `xephash bench ...`: measure setup time and hash rate.
fn cmd_bench(args: &[String]) -> i32 {
    let params = match args.first().and_then(|n| params_for(n)) {
        Some(p) => p,
        None => return usage(),
    };
    let seconds: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5).clamp(1, 600);
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    println!(
        "network params: cache {} KiB, dataset {} MiB, epoch {} blocks, {} threads",
        params.cache_items as u64 * 32 / 1024,
        params.dataset_items as u64 * 32 / (1024 * 1024),
        params.epoch_length,
        threads
    );

    let seed = match epoch_seed(0) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {}", e);
            return 1;
        }
    };
    let t = Instant::now();
    let cache = match Cache::generate(&seed, params.cache_items) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {}", e);
            return 1;
        }
    };
    println!("cache built in      {:.2?}", t.elapsed());

    let header: Item = sha3_256(b"xephash bench header");

    // Light mode: what every node does to verify a block.
    let t = Instant::now();
    let mut n_light = 0u64;
    while t.elapsed() < Duration::from_secs(1) {
        if hashimoto_light(&cache, params.dataset_items, &header, n_light).is_err() {
            return 1;
        }
        n_light += 1;
    }
    println!("light verification  {:.1} hashes/s (one thread)", n_light as f64 / t.elapsed().as_secs_f64());

    // Full mode: what a miner does.
    let t = Instant::now();
    let dataset = match Dataset::generate(&cache, params.dataset_items, threads) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {}", e);
            return 1;
        }
    };
    println!("dataset built in    {:.2?}", t.elapsed());

    let t = Instant::now();
    let mut n_full = 0u64;
    while t.elapsed() < Duration::from_secs(seconds) {
        if hashimoto_full(&dataset, &header, n_full).is_err() {
            return 1;
        }
        n_full += 1;
    }
    println!("full mining         {:.1} hashes/s (one thread)", n_full as f64 / t.elapsed().as_secs_f64());
    0
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect(); // skip the program name
    let code = match args.first().map(|s| s.as_str()) {
        Some("vectors") => cmd_vectors(),
        Some("hash") => cmd_hash(&args[1..]),
        Some("bench") => cmd_bench(&args[1..]),
        _ => usage(),
    };
    std::process::exit(code);
}
