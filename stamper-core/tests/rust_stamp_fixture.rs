//! The Rust-built stamp in `verifier/test/fixtures/rust-stamp.json`, which the TypeScript verifier must
//! accept (verifier/test/rust-stamp.test.ts). Every value comes from a label (tests/common); the build is
//! deterministic (RFC 6979 signatures), so the file is exactly what this test builds.
//!
//! Regenerate with: `cargo test --test rust_stamp_fixture -- --ignored --nocapture`

mod common;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use stamper_core::address::{p2pkh_address, p2pkh_script, Network};
use stamper_core::build::{build, BuildRequest, Output, Utxo};

const BURNED: u64 = 2_000_000_000_000;
const HARVESTED: u64 = 42_000_000;
const TICKER: &str = "OWL";

/// The 52-byte version 1 record (SPEC.md §3): SPLG, 01, sha256(signature)[0..20], burned, harvested, ticker.
fn record_v1(sig: &[u8; 64]) -> Vec<u8> {
    let mut r = b"SPLG\x01".to_vec();
    r.extend_from_slice(&Sha256::digest(sig)[..20]);
    r.extend_from_slice(&BURNED.to_le_bytes());
    r.extend_from_slice(&HARVESTED.to_le_bytes());
    r.push(TICKER.len() as u8);
    let mut t = TICKER.as_bytes().to_vec();
    t.resize(10, 0);
    r.extend_from_slice(&t);
    r
}

fn fixture() -> Value {
    let key = common::issuer("fixtures/rust-stamp/issuer");
    let sig: [u8; 64] = common::label("fixtures/rust-stamp/request-signature");
    let harvester = common::label::<20>("fixtures/rust-stamp/harvester");
    let mut record_script = vec![0x6a, 0x34];
    record_script.extend_from_slice(&record_v1(&sig));
    let req = BuildRequest {
        consensus_branch_id: 0x37a5_165b,
        expiry_height: 4_388_200,
        marginal_fee: 5_000,
        inputs: vec![Utxo { txid: common::label_hex("fixtures/rust-stamp/coin"), vout: 0, value: 1_000_000 }],
        outputs: vec![Output { value: 0, script: hex::encode(&record_script) }, Output { value: 546, script: hex::encode(p2pkh_script(&harvester)) }],
    };
    let built = build(&key, &req).expect("the stamp builds");
    assert_eq!(key.address(Network::Testnet), p2pkh_address(Network::Testnet, &key.pubkey_hash()));
    json!({
        "_comment": "A stamp built and signed by stamper-core (Rust) with public test keys derived from labels under \"sapling.cash/stamps/fixtures/rust-stamp/\" (never real keys; tests/rust_stamp_fixture.rs), for the record and address below. The TypeScript verifier must accept it.",
        "issuerAddress": key.address(Network::Testnet),
        "request": { "signature": bs58::encode(sig).into_string(), "address": p2pkh_address(Network::Testnet, &harvester), "burned": BURNED.to_string(), "harvested": HARVESTED.to_string(), "ticker": TICKER },
        "txid": built.txid,
        "txHex": built.hex,
        "fee": built.fee,
        "change": built.change,
    })
}

const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../verifier/test/fixtures/rust-stamp.json");

#[test]
fn the_fixture_file_matches() {
    let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(FILE).expect("verifier/test/fixtures/rust-stamp.json")).unwrap();
    assert_eq!(on_disk, fixture());
}

#[test]
#[ignore]
fn generate() {
    std::fs::write(FILE, serde_json::to_string_pretty(&fixture()).unwrap() + "\n").unwrap();
}
