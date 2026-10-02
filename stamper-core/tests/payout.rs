//! Payout stamps (SPEC.md §10) end to end without a network: order addresses from a published exit key
//! (checked against librustzcash's own BIP44 derivation), a forward built with librustzcash's builder the
//! way Sapling's exiter builds one (coins in from order addresses, the version 3 record, one Ironwood note
//! per exit with its SPLG/3 receipt), a payout stamp proof made with the receiver's viewing key and checked
//! without one; then the test vectors in `test-vectors/payout.json`.
//!
//! Regenerate the vectors with: `cargo test --features private --test payout -- --ignored --nocapture`
#![cfg(feature = "private")]

mod common;

use orchard::keys::{FullViewingKey, Scope};
use rand_core::OsRng;
use serde_json::{json, Value};
use stamper_core::address::{hash160, p2pkh_address, Network};
use stamper_core::build::{GRACE_ACTIONS, P2PKH_STANDARD_INPUT_SIZE, P2PKH_STANDARD_OUTPUT_SIZE};
use stamper_core::payout::exit_key::{order_hash, order_pubkey};
use stamper_core::payout::proof::{check, exit_keys_from_params, make, shape, verify_inputs, ExitKey, PayoutProof};
use stamper_core::payout::receipt::PayoutReceipt;
use stamper_core::private::build::NoSapling;
use stamper_core::record::{exit_hash, record_v3, record_v3_script};
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_protocol::consensus::{BlockHeight, NetworkType, TestNetwork};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::builder::TransparentSigningSet;
use zcash_transparent::bundle::{OutPoint, TxOut};
use zcash_transparent::keys::{AccountPrivKey, AccountPubKey, NonHardenedChildIndex, TransparentKeyScope};
use zip32::AccountId;

use common::label;

const MARGINAL: u64 = 5_000;

fn account_priv(seed: &str, account: u32) -> AccountPrivKey {
    AccountPrivKey::from_seed(&TestNetwork, &label::<32>(seed), AccountId::try_from(account).unwrap()).unwrap()
}

fn exit_key(seed: &str, account: u32) -> [u8; 65] {
    account_priv(seed, account).to_account_pubkey().serialize().try_into().unwrap()
}

fn wallet(n: u8) -> (FullViewingKey, [u8; 43]) {
    let sk = common::spending_key(&format!("tests/payout/wallet/{n}"));
    let fvk = FullViewingKey::from(&sk);
    let addr = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
    (fvk, addr)
}

struct TestExit {
    index: u32,
    coins: Vec<u64>,
    receiver: [u8; 43],
    kind: &'static str,
    sent: u64,
    signature: [u8; 64],
}

/// A forward of `exits` from exit account 0 of `seed`, built as Sapling's exiter builds one. Returns the
/// transaction's bytes, the spent coins' values in input order, and each exit's receipt.
fn build_forward(seed: &str, exits: &[TestExit]) -> (Vec<u8>, Vec<u64>, Vec<PayoutReceipt>) {
    let key = account_priv(seed, 0);
    let single = exits.len() == 1;
    let mut signing = TransparentSigningSet::new();
    let config = BuildConfig::Standard { sapling_anchor: None, orchard_anchor: None, ironwood_anchor: Some(orchard::Anchor::empty_tree()), orchard_padding: BundlePadding::DEFAULT, ironwood_padding: BundlePadding::DEFAULT };
    let mut b = Builder::new(TestNetwork, BlockHeight::from_u32(4_400_000), config).with_expiry_height(BlockHeight::from_u32(4_400_040));
    let mut values = Vec::new();
    let mut receipts = Vec::new();
    for e in exits {
        let pk = signing.add_key(key.derive_external_secret_key(NonHardenedChildIndex::from_index(e.index).unwrap()).unwrap());
        let script = TransparentAddress::PublicKeyHash(hash160(&pk.serialize())).script();
        for (n, v) in e.coins.iter().enumerate() {
            let prev = label::<32>(&format!("tests/payout/coin/{}/{n}", e.index));
            b.add_transparent_p2pkh_input(pk, OutPoint::new(prev, n as u32), TxOut::new(Zatoshis::from_u64(*v).unwrap(), script.clone().into())).unwrap();
            values.push(*v);
        }
        let bridged: u64 = e.coins.iter().sum();
        let fee = MARGINAL * (e.coins.len() as u64 + 1 + u64::from(single));
        let coin = e.kind != "send";
        receipts.push(PayoutReceipt {
            kind: e.kind.into(),
            ticker: coin.then(|| "ROOT".into()),
            mint: coin.then(|| bs58::encode(label::<32>("tests/payout/mint")).into_string()),
            sent: e.sent,
            bridged,
            fee,
            received: bridged - fee,
            signature: bs58::encode(e.signature).into_string(),
            block_time: 1_790_640_000,
        });
    }
    b.add_transparent_null_data_output::<std::convert::Infallible>(&record_v3(&exits.iter().map(|e| e.signature).collect::<Vec<_>>()).unwrap()).unwrap();
    for (e, r) in exits.iter().zip(&receipts) {
        let to = Option::from(orchard::Address::from_raw_address_bytes(&e.receiver)).unwrap();
        b.add_ironwood_output::<std::convert::Infallible>(None, to, Zatoshis::from_u64(r.received).unwrap(), MemoBytes::from_bytes(&r.memo().unwrap()).unwrap()).unwrap();
    }
    let rule = FeeRule::non_standard(Zatoshis::from_u64(MARGINAL).unwrap(), GRACE_ACTIONS as usize, P2PKH_STANDARD_INPUT_SIZE, P2PKH_STANDARD_OUTPUT_SIZE).unwrap();
    let built = b.build(&signing, &[], &[], OsRng, &NoSapling, &NoSapling, &rule).unwrap();
    let mut bytes = Vec::new();
    built.transaction().write(&mut bytes).unwrap();
    (bytes, values, receipts)
}

fn keys(pubkey: [u8; 65]) -> Vec<ExitKey> {
    vec![ExitKey { account: 0, pubkey, from_height: 1, to_height: None }]
}

#[test]
fn order_addresses_are_librustzcash_s_bip44_children() {
    for (seed, account) in [("tests/payout/exit-seed", 0u32), ("tests/payout/exit-seed", 1), ("tests/payout/other-seed", 0)] {
        let pubkey = exit_key(seed, account);
        let apk = AccountPubKey::deserialize(&pubkey).unwrap();
        let sk = account_priv(seed, account);
        for index in [0u32, 1, 2, 77, 1_000, (1 << 31) - 1] {
            let want = apk.derive_address_pubkey(TransparentKeyScope::EXTERNAL, NonHardenedChildIndex::from_index(index).unwrap()).unwrap().serialize();
            assert_eq!(order_pubkey(&pubkey, index).unwrap(), want);
            let from_secret = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk.derive_external_secret_key(NonHardenedChildIndex::from_index(index).unwrap()).unwrap()).serialize();
            assert_eq!(want, from_secret);
        }
    }
}

#[test]
fn a_forward_of_two_exits_proves_each_note() {
    let seed = "tests/payout/exit-seed";
    let pubkey = exit_key(seed, 0);
    let (fvk_a, to_a) = wallet(1);
    let (fvk_b, to_b) = wallet(2);
    let exits = [
        TestExit { index: 7, coins: vec![300_000], receiver: to_a, kind: "sell", sent: 330_000, signature: label("tests/payout/exit/7") },
        TestExit { index: 9, coins: vec![120_000, 80_000], receiver: to_b, kind: "send", sent: 220_000, signature: label("tests/payout/exit/9") },
    ];
    let (tx, values, receipts) = build_forward(seed, &exits);
    let s = shape(&tx).unwrap();
    assert_eq!(s.hashes, vec![exit_hash(&exits[0].signature), exit_hash(&exits[1].signature)]);
    assert_eq!(s.into_pool, receipts[0].received + receipts[1].received);
    assert_eq!(s.actions, 2);
    verify_inputs(&tx, &values).unwrap();

    for (n, (fvk, e)) in [(fvk_a, &exits[0]), (fvk_b, &exits[1])].into_iter().enumerate() {
        let proof = make(&tx, &[fvk.to_ivk(Scope::External)], 0, e.index).unwrap();
        assert_eq!(proof.receiver, e.receiver);
        let text = proof.encode();
        assert_eq!(text.len(), "splg-proof:2:".len() + 164);
        let shown = check(&tx, &PayoutProof::decode(&text).unwrap(), NetworkType::Test, &keys(pubkey), Some(&values)).unwrap();
        assert!(shown.inputs_verified);
        assert_eq!(shown.receipt, receipts[n]);
        assert_eq!((shown.exits, shown.position, shown.order_inputs, shown.value), (2, n, e.coins.len(), receipts[n].received));
        assert_eq!(shown.order_key_hash, hex::encode(order_hash(&pubkey, e.index).unwrap()));
        assert!(shown.address.starts_with("utest1"));
        // offline without values: accepted as far as the bytes go, and said plainly
        let unverified = check(&tx, &proof, NetworkType::Test, &keys(pubkey), None).unwrap();
        assert!(!unverified.inputs_verified && unverified.not_checked[0].contains("NOT verified"));
        // every tampering fails
        let other = if n == 0 { exits[1].index } else { exits[0].index };
        let tampered = [
            PayoutProof { action: 1 - proof.action, ..proof.clone() },
            PayoutProof { value: proof.value + 1, ..proof.clone() },
            PayoutProof { receiver: wallet(3).1, ..proof.clone() },
            PayoutProof { rseed: label("tests/payout/wrong-rseed"), ..proof.clone() },
            PayoutProof { txid: label("tests/payout/wrong-txid"), ..proof.clone() },
            PayoutProof { pool: 1, ..proof.clone() },
            PayoutProof { index: 8, ..proof.clone() },
            PayoutProof { account: 1, ..proof.clone() },
        ];
        for p in tampered {
            assert!(check(&tx, &p, NetworkType::Test, &keys(pubkey), None).is_err(), "{p:?}");
        }
        // the other exit's order index is an order address of this transaction, but not the one that paid this note
        let wrong = check(&tx, &PayoutProof { index: other, ..proof.clone() }, NetworkType::Test, &keys(pubkey), None);
        assert!(wrong.unwrap_err().contains("not spent by order"));
        // another exit key, or a wrong spent value, fails
        assert!(check(&tx, &proof, NetworkType::Test, &keys(exit_key("tests/payout/other-seed", 0)), None).is_err());
        let mut bad = values.clone();
        bad[0] += 1;
        assert!(check(&tx, &proof, NetworkType::Test, &keys(pubkey), Some(&bad)).is_err());
    }
    // a key that receives nothing here cannot make one
    assert!(make(&tx, &[wallet(3).0.to_ivk(Scope::External)], 0, 7).is_err());
}

// ---- the vectors

const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/payout.json");

/// The parts of the vectors that are computed from labels alone.
fn computed() -> Value {
    let mut keys = Vec::new();
    for (seed, account, net, name) in [("vectors/payout/exit-seed/0", 0u32, Network::Mainnet, "mainnet"), ("vectors/payout/exit-seed/0", 1, Network::Mainnet, "mainnet"), ("vectors/payout/exit-seed/1", 0, Network::Testnet, "testnet")] {
        let pubkey = exit_key(seed, account);
        let addresses: Vec<Value> = [0u32, 1, 2, 1_000, (1 << 31) - 1]
            .iter()
            .map(|i| json!({ "index": i, "pubkey": hex::encode(order_pubkey(&pubkey, *i).unwrap()), "address": p2pkh_address(net, &order_hash(&pubkey, *i).unwrap()) }))
            .collect();
        keys.push(json!({ "seedLabel": seed, "account": account, "network": name, "accountPubkey": hex::encode(pubkey), "addresses": addresses }));
    }
    let records: Vec<Value> = [1usize, 2, 3, 4]
        .iter()
        .map(|k| {
            let sigs: Vec<[u8; 64]> = (0..*k).map(|i| label(&format!("vectors/payout/record/{k}/{i}"))).collect();
            let r = record_v3(&sigs).unwrap();
            json!({ "signatures": sigs.iter().map(|s| bs58::encode(s).into_string()).collect::<Vec<_>>(), "record": hex::encode(&r), "script": hex::encode(record_v3_script(&r)) })
        })
        .collect();
    let receipts: Vec<Value> = [
        PayoutReceipt { kind: "sell".into(), ticker: Some("ROOT".into()), mint: Some(bs58::encode(label::<32>("vectors/payout/receipt/0/mint")).into_string()), sent: 1_000_000, bridged: 968_000, fee: 15_000, received: 953_000, signature: bs58::encode(label::<64>("vectors/payout/receipt/0/signature")).into_string(), block_time: 1_790_640_000 },
        PayoutReceipt { kind: "harvest".into(), ticker: Some("ABCDEFGHIJ".into()), mint: Some(bs58::encode([0xffu8; 32]).into_string()), sent: u64::MAX, bridged: u64::MAX, fee: u64::MAX, received: 0, signature: bs58::encode([0xffu8; 64]).into_string(), block_time: 253_402_300_799 },
        PayoutReceipt { kind: "send".into(), ticker: None, mint: None, sent: 400_000, bridged: 367_000, fee: 10_000, received: 357_000, signature: bs58::encode(label::<64>("vectors/payout/receipt/2/signature")).into_string(), block_time: 0 },
    ]
    .into_iter()
    .map(|r| json!({ "receipt": r, "text": r.text().unwrap() }))
    .collect();
    json!({ "exitKeys": keys, "records": records, "receipts": receipts })
}

fn on_disk() -> Value {
    serde_json::from_str(&std::fs::read_to_string(FILE).expect("test-vectors/payout.json")).unwrap()
}

#[test]
fn the_computed_vectors_match() {
    let disk = on_disk();
    let want = computed();
    for k in ["exitKeys", "records", "receipts"] {
        assert_eq!(disk[k], want[k], "{k}");
    }
}

/// The synthetic forward in the vectors (built once by `regenerate`, never broadcast): each of its proofs
/// checks, with and without the spent values.
#[test]
fn the_synthetic_forward_checks() {
    let s = &on_disk()["synthetic"];
    let tx = hex::decode(s["hex"].as_str().unwrap()).unwrap();
    let pubkey: [u8; 65] = hex::decode(s["accountPubkey"].as_str().unwrap()).unwrap().try_into().unwrap();
    let values: Vec<u64> = s["spentValues"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().parse().unwrap()).collect();
    for e in s["exits"].as_array().unwrap() {
        let p = PayoutProof::decode(e["proof"].as_str().unwrap()).unwrap();
        let shown = check(&tx, &p, NetworkType::Test, &keys(pubkey), Some(&values)).unwrap();
        assert_eq!(serde_json::to_value(&shown.receipt).unwrap(), e["receipt"]);
        assert_eq!(shown.address, e["address"].as_str().unwrap());
        assert_eq!(shown.txid, s["txid"].as_str().unwrap());
        assert_eq!(p.index, e["index"].as_u64().unwrap() as u32);
    }
}

/// Sapling's first payout transactions on Zcash mainnet, read from the chain: each has a payout stamp's
/// shape, its inputs are spent by the order address the published exit key derives (signatures verified
/// with the spent coins' values), and its record has one exit. Their notes can be proved only with the
/// receiver's viewing key, so there is no proof here.
#[test]
fn the_mainnet_forwards_have_a_payout_stamps_shape() {
    let params = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../params/mainnet.json")).unwrap();
    let (_, published) = exit_keys_from_params(&params).unwrap();
    let list = on_disk()["mainnet"].as_array().unwrap().clone();
    assert!(!list.is_empty());
    for f in list {
        let tx = hex::decode(f["hex"].as_str().unwrap()).unwrap();
        let s = shape(&tx).unwrap();
        let account = f["account"].as_u64().unwrap() as u8;
        let key = published.iter().find(|k| k.account == account).expect("the account's key is published");
        assert_eq!(hex::encode(key.pubkey), f["accountPubkey"].as_str().unwrap());
        assert!(f["height"].as_u64().unwrap() as u32 >= key.from_height);
        let order = order_pubkey(&key.pubkey, f["index"].as_u64().unwrap() as u32).unwrap();
        assert!(s.input_keys.iter().all(|k| *k == order));
        assert_eq!(p2pkh_address(Network::Mainnet, &hash160(&order)), f["orderAddress"].as_str().unwrap());
        let values: Vec<u64> = f["spentValues"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().parse().unwrap()).collect();
        verify_inputs(&tx, &values).unwrap();
        assert_eq!(s.hashes.len(), 1);
        assert_eq!(s.into_pool.to_string(), f["intoPool"].as_str().unwrap());
        assert_eq!(hex::encode(record_v3_script(&[b"SPLG\x03".as_slice(), &s.hashes[0]].concat())), f["record"].as_str().unwrap());
        let mut bad = values.clone();
        bad[0] -= 1;
        assert!(verify_inputs(&tx, &bad).is_err());
    }
}

#[test]
#[ignore]
fn regenerate() {
    let mut v = computed();
    let seed = "vectors/payout/synthetic/exit-seed";
    let pubkey = exit_key(seed, 0);
    let exits = [
        TestExit { index: 12, coins: vec![468_000], receiver: wallet(21).1, kind: "sell", sent: 500_000, signature: label("vectors/payout/synthetic/exit/12") },
        TestExit { index: 13, coins: vec![200_000, 167_000], receiver: wallet(22).1, kind: "send", sent: 400_000, signature: label("vectors/payout/synthetic/exit/13") },
    ];
    let (tx, values, receipts) = build_forward(seed, &exits);
    let mut out = Vec::new();
    for ((n, e), r) in [21u8, 22].iter().zip(&exits).zip(&receipts) {
        let p = make(&tx, &[wallet(*n).0.to_ivk(Scope::External)], 0, e.index).unwrap();
        let shown = check(&tx, &p, NetworkType::Test, &keys(pubkey), Some(&values)).unwrap();
        out.push(json!({ "index": e.index, "walletLabel": format!("tests/payout/wallet/{n}"), "signature": r.signature, "proof": p.encode(), "receipt": r, "address": shown.address, "text": r.text().unwrap() }));
    }
    let mut shown = stamper_core::private::proof::inspect(&tx).unwrap().txid;
    shown.make_ascii_lowercase();
    v["synthetic"] = json!({
        "_comment": "Synthetic, not on any chain: a forward of two exits built by tests/payout.rs with test keys from labels, on testnet parameters. The receivers' viewing keys come from the wallet labels (tests/common spending_key).",
        "network": "testnet",
        "account": 0,
        "exitSeedLabel": seed,
        "accountPubkey": hex::encode(pubkey),
        "txid": shown,
        "hex": hex::encode(&tx),
        "spentValues": values.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
        "exits": out,
    });
    let old = std::fs::read_to_string(FILE).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok());
    v["mainnet"] = old.as_ref().map(|o| o["mainnet"].clone()).unwrap_or(json!([]));
    v["_comment"] = json!("Payout stamps (SPEC.md §10): order addresses of exit keys, version 3 records, SPLG/3 receipts, a synthetic forward with payout stamp proofs (splg-proof:2), and Sapling's first payout transactions on Zcash mainnet (read from the chain; no proof: their notes need the receiver's viewing key). Generated by stamper-core's tests/payout.rs, except `mainnet`.");
    std::fs::write(FILE, format!("{}\n", serde_json::to_string_pretty(&v).unwrap())).unwrap();
}
