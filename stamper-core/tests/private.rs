//! Private stamps, end to end without a network: seal a receiver, build and prove the stamp with
//! librustzcash, read it back, make a stamp proof with the receiver's viewing key and check it.
#![cfg(feature = "private")]

use std::time::Instant;

use base64::Engine;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use stamper_core::key::IssuerKey;
use stamper_core::private::build::{build_private, PrivateRequest, Sealed};
use stamper_core::private::memo::Receipt;
use stamper_core::private::proof::{check, make, Proof, POOL_IRONWOOD};
use stamper_core::private::seal::{seal, RequestKey};
use stamper_core::private::UNDELIVERABLE;
use stamper_core::build::Utxo;
use stamper_core::address::Network;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BranchId, NetworkType};

const HOLDER: [u8; 32] = [0x42; 32];

fn wallet(n: u8) -> (FullViewingKey, [u8; 43]) {
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([n; 32])).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let addr = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
    (fvk, addr)
}

fn receipt() -> Receipt {
    Receipt { ticker: "ROOT".into(), mint: bs58::encode([5u8; 32]).into_string(), burned: 1_250_000_000_000, harvested: 1_234_567, fee: 40_000, signature: bs58::encode([9u8; 64]).into_string(), block_time: 1_790_424_000 }
}

fn request(rk: &RequestKey, receiver: &[u8; 43], kid: u8) -> PrivateRequest {
    let sealed = seal(&rk.public(), kid, &HOLDER, receiver, [7; 32]).unwrap();
    PrivateRequest {
        network: Network::Testnet,
        consensus_branch_id: u32::from(BranchId::Nu6_3),
        target_height: 4_400_000,
        expiry_height: 4_400_040,
        marginal_fee: 5_000,
        input: Utxo { txid: "ab".repeat(32), vout: 0, value: 205_460 },
        receipt: receipt(),
        sealed: Sealed { kid, sealed: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sealed), holder: bs58::encode(HOLDER).into_string() },
        anchor: None,
    }
}

#[test]
fn a_private_stamp_is_built_proved_and_its_proof_checks() {
    let issuer = IssuerKey::from_bytes(&[3; 32]).unwrap();
    let rk = RequestKey::from_bytes([1; 32]);
    let (fvk, receiver) = wallet(11);
    let t0 = Instant::now();
    let built = build_private(&issuer, &rk, &request(&rk, &receiver, 1)).unwrap();
    eprintln!("first build (proving key + proof): {:?}", t0.elapsed());
    let t1 = Instant::now();
    let again = build_private(&issuer, &rk, &request(&rk, &receiver, 1)).unwrap();
    eprintln!("second build (proof only): {:?}", t1.elapsed());
    assert_ne!(built.txid, again.txid, "fresh randomness each build");

    // 4 logical actions: 1 input / 2 outputs (68 bytes) = 2, plus 2 Ironwood actions
    assert_eq!(built.logical_actions, 4);
    assert_eq!(built.fee, 20_000);
    assert_eq!(built.change, 205_460 - 546 - 20_000);
    let bytes = hex::decode(&built.hex).unwrap();
    eprintln!("private stamp size: {} bytes", bytes.len());

    let tx = Transaction::read(&bytes[..], BranchId::Nu6_3).unwrap();
    let t = tx.transparent_bundle().unwrap();
    assert_eq!(t.vin.len(), 1);
    assert_eq!(t.vout.len(), 2);
    let op = &t.vout[0].script_pubkey().0 .0;
    assert_eq!(&op[..7], &[0x6a, 0x17, b'S', b'P', b'L', b'G', 2]);
    assert!(tx.sapling_bundle().is_none() && tx.orchard_bundle().is_none());
    let iw = tx.ironwood_bundle().unwrap();
    assert_eq!(iw.actions().len(), 2);
    assert_eq!(i64::from(*iw.value_balance()), -546);

    // the holder makes a proof with their viewing key; anyone checks it without one
    let proof = make(&bytes, &[fvk.to_ivk(Scope::External)]).unwrap();
    assert_eq!(proof.pool, POOL_IRONWOOD);
    assert_eq!(proof.receiver, receiver);
    let s = proof.encode();
    assert_eq!(s.len(), "splg-proof:1:".len() + 156);
    let issuers = [issuer.pubkey_hash()];
    // with the spent coin's value: the issuer's signature is verified
    let shown = check(&bytes, &Proof::decode(&s).unwrap(), NetworkType::Test, &issuers, Some(&[205_460])).unwrap();
    assert!(shown.issuer_verified);
    assert_eq!(shown.not_checked.len(), 3);
    assert!(shown.checked.iter().any(|c| c.contains("signature verifies with the published issuer key")));
    assert_eq!(shown.wtxid.len(), 128);
    // a wrong value makes the genuine stamp fail, never pass
    assert!(check(&bytes, &proof, NetworkType::Test, &issuers, Some(&[205_461])).unwrap_err().contains("does not verify"));
    // without it: accepted as far as the bytes go, and the result says plainly the issuer was not verified
    let unverified = check(&bytes, &proof, NetworkType::Test, &issuers, None).unwrap();
    assert!(!unverified.issuer_verified);
    assert!(unverified.not_checked[0].contains("NOT verified"));
    // not the issuer: refused
    assert!(check(&bytes, &proof, NetworkType::Test, &[[0x11; 20]], None).unwrap_err().contains("issuer"));
    assert!(check(&bytes, &proof, NetworkType::Test, &[], None).is_err());
    assert_eq!(shown.receipt, receipt());
    assert_eq!(shown.value, 546);
    assert!(shown.address.starts_with("utest1"));
    assert_eq!(shown.input_key_hashes, vec![hex::encode(issuer.pubkey_hash())]);

    // another wallet cannot make one
    let (other, _) = wallet(12);
    assert!(make(&bytes, &[other.to_ivk(Scope::External)]).is_err());

    // every tampering fails
    let tampered = [
        Proof { action: 1 - proof.action, ..proof.clone() },
        Proof { value: 547, ..proof.clone() },
        Proof { receiver: wallet(12).1, ..proof.clone() },
        Proof { rseed: [0x33; 32], ..proof.clone() },
        Proof { txid: [0; 32], ..proof.clone() },
        Proof { pool: 1, ..proof.clone() },
    ];
    for p in tampered {
        assert!(check(&bytes, &p, NetworkType::Test, &issuers, None).is_err(), "{p:?}");
    }
    // the same proof against the other build of the same request fails (other txid)
    assert!(check(&hex::decode(&again.hex).unwrap(), &proof, NetworkType::Test, &issuers, None).is_err());
}

#[test]
fn undeliverable_requests_say_only_that() {
    let issuer = IssuerKey::from_bytes(&[3; 32]).unwrap();
    let rk = RequestKey::from_bytes([1; 32]);
    let (_, receiver) = wallet(11);
    // wrong key id, wrong request key, garbage, a receiver that is not a valid address
    let mut r = request(&rk, &receiver, 1);
    r.sealed.kid = 2;
    assert_eq!(build_private(&issuer, &rk, &r).unwrap_err(), UNDELIVERABLE);
    assert_eq!(build_private(&issuer, &RequestKey::from_bytes([2; 32]), &request(&rk, &receiver, 1)).unwrap_err(), UNDELIVERABLE);
    let mut r = request(&rk, &receiver, 1);
    r.sealed.sealed = "AAAA".into();
    assert_eq!(build_private(&issuer, &rk, &r).unwrap_err(), UNDELIVERABLE);
    let mut bad = receiver;
    bad[11..].copy_from_slice(&[0xff; 32]); // pk_d not a valid point encoding
    assert_eq!(build_private(&issuer, &rk, &request(&rk, &bad, 1)).unwrap_err(), UNDELIVERABLE);
}

#[test]
fn the_branch_must_match_librustzcash() {
    let issuer = IssuerKey::from_bytes(&[3; 32]).unwrap();
    let rk = RequestKey::from_bytes([1; 32]);
    let (_, receiver) = wallet(11);
    let mut r = request(&rk, &receiver, 1);
    r.consensus_branch_id = u32::from(BranchId::Nu6_2);
    assert!(build_private(&issuer, &rk, &r).unwrap_err().contains("branch"));
    // before NU6.3 there is no Ironwood pool
    let mut r = request(&rk, &receiver, 1);
    r.target_height = 4_100_000;
    r.expiry_height = 4_100_040;
    r.consensus_branch_id = u32::from(BranchId::Nu6_2);
    assert!(build_private(&issuer, &rk, &r).unwrap_err().contains("Ironwood"));
}

#[test]
fn a_coin_too_small_is_refused() {
    let issuer = IssuerKey::from_bytes(&[3; 32]).unwrap();
    let rk = RequestKey::from_bytes([1; 32]);
    let (_, receiver) = wallet(11);
    let mut r = request(&rk, &receiver, 1);
    r.input.value = 20_546 + 53;
    assert!(build_private(&issuer, &rk, &r).unwrap_err().contains("does not cover"));
}
