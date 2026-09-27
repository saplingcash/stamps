//! Forged and malformed private stamps: each case must be refused.
#![cfg(feature = "private")]

use base64::Engine;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use stamper_core::address::Network;
use stamper_core::build::Utxo;
use stamper_core::key::IssuerKey;
use stamper_core::private::build::{build_private, NoSapling, PrivateRequest, Sealed};
use stamper_core::private::UNDELIVERABLE;
use stamper_core::private::memo::Receipt;
use stamper_core::private::proof::{check, make, Proof};
use stamper_core::private::seal::{seal, RequestKey};
use stamper_core::record::{record_v2, solana_signature};
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkType, TestNetwork};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::builder::TransparentSigningSet;
use zcash_transparent::bundle::{OutPoint, TxOut};

const HOLDER: [u8; 32] = [0x42; 32];

fn wallet(n: u8) -> (FullViewingKey, [u8; 43]) {
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([n; 32])).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let addr = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
    (fvk, addr)
}

fn victim_receipt() -> Receipt {
    Receipt { ticker: "ROOT".into(), mint: bs58::encode([5u8; 32]).into_string(), burned: 1_250_000_000_000, harvested: 1_234_567, fee: 40_000, signature: bs58::encode([9u8; 64]).into_string(), block_time: 1_790_424_000 }
}

fn request(rk: &RequestKey, receiver: &[u8; 43], receipt: Receipt) -> PrivateRequest {
    let sealed = seal(&rk.public(), 1, &HOLDER, receiver, [7; 32]).unwrap();
    PrivateRequest {
        network: Network::Testnet,
        consensus_branch_id: u32::from(BranchId::Nu6_3),
        target_height: 4_400_000,
        expiry_height: 4_400_040,
        marginal_fee: 5_000,
        input: Utxo { txid: "cd".repeat(32), vout: 0, value: 205_460 },
        receipt,
        sealed: Sealed { kid: 1, sealed: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sealed), holder: bs58::encode(HOLDER).into_string() },
        anchor: None,
    }
}

/// a transaction built by someone who is not the issuer, for somebody else's harvest, with a
/// made-up receipt: the check refuses it (not spent by a published issuer key).
#[test]
fn a_non_issuer_transaction_fails_check() {
    let attacker_key = IssuerKey::from_bytes(&[0x77; 32]).unwrap();
    let attacker_rk = RequestKey::from_bytes([0x66; 32]);
    let (fvk, attacker_receiver) = wallet(21);
    // the victim's harvest signature, with invented amounts
    let forged = Receipt { burned: 1, harvested: 999_999_999, fee: 1, ..victim_receipt() };
    let built = build_private(&attacker_key, &attacker_rk, &request(&attacker_rk, &attacker_receiver, forged.clone())).unwrap();
    let bytes = hex::decode(&built.hex).unwrap();
    let proof = make(&bytes, &[fvk.to_ivk(Scope::External)]).unwrap();
    let real_issuer = IssuerKey::from_bytes(&[3; 32]).unwrap();
    let err = check(&bytes, &Proof::decode(&proof.encode()).unwrap(), NetworkType::Test, &[real_issuer.pubkey_hash()], None).unwrap_err();
    assert!(err.contains("not spent by a published issuer key"), "{err}");
    assert_eq!(forged.signature, victim_receipt().signature);
}

/// a note of any value but the 546-zatoshi postage fails, even from an issuer key.
#[test]
fn a_note_other_than_the_postage_fails_check() {
    let (fvk, receiver) = wallet(22);
    let key = IssuerKey::from_bytes(&[0x78; 32]).unwrap();
    let height = BlockHeight::from_u32(4_400_000);
    let config = BuildConfig::Standard { sapling_anchor: None, orchard_anchor: None, ironwood_anchor: Some(orchard::Anchor::empty_tree()), orchard_padding: BundlePadding::DEFAULT, ironwood_padding: BundlePadding::DEFAULT };
    let mut b = Builder::new(TestNetwork, height, config).with_expiry_height(BlockHeight::from_u32(4_400_040));
    let mut signing = TransparentSigningSet::new();
    let pubkey = signing.add_key(secp256k1::SecretKey::from_slice(key.secret_bytes().as_ref()).unwrap());
    let addr = TransparentAddress::PublicKeyHash(key.pubkey_hash());
    let coin = TxOut::new(Zatoshis::from_u64(205_460).unwrap(), addr.script().into());
    b.add_transparent_p2pkh_input(pubkey, OutPoint::new([0xcd; 32], 0), coin).unwrap();
    let sig = solana_signature(&victim_receipt().signature).unwrap();
    b.add_transparent_null_data_output::<std::convert::Infallible>(&record_v2(&sig)).unwrap();
    b.add_transparent_output(&addr, Zatoshis::from_u64(205_460 - 20_000 - 1).unwrap()).unwrap();
    let memo = MemoBytes::from_bytes(&victim_receipt().memo().unwrap()).unwrap();
    b.add_ironwood_output::<std::convert::Infallible>(None, orchard::Address::from_raw_address_bytes(&receiver).unwrap(), Zatoshis::from_u64(1).unwrap(), memo).unwrap();
    let rule = FeeRule::non_standard(Zatoshis::from_u64(5_000).unwrap(), 2, 150, 34).unwrap();
    let res = b.build(&signing, &[], &[], rand_core::OsRng, &NoSapling, &NoSapling, &rule).unwrap();
    let mut bytes = Vec::new();
    res.transaction().write(&mut bytes).unwrap();
    // make() skips it (value != 546) but a hand-made proof string checks
    assert!(make(&bytes, &[fvk.to_ivk(Scope::External)]).is_err());
    let ivk = orchard::keys::PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
    let t = zcash_primitives::transaction::Transaction::read(&bytes[..], BranchId::Nu6_3).unwrap();
    let (i, note) = t.ironwood_bundle().unwrap().actions().iter().enumerate().find_map(|(i, a)| {
        let d = orchard::note_encryption::IronwoodDomain::for_action(a);
        zcash_note_encryption::try_note_decryption(&d, &ivk, a).map(|(n, _, _)| (i, n))
    }).unwrap();
    let p = Proof { txid: *t.txid().as_ref(), pool: 2, action: i as u8, receiver, value: 1, rseed: *note.rseed().as_bytes() };
    let err = check(&bytes, &p, NetworkType::Test, &[key.pubkey_hash()], Some(&[205_460])).unwrap_err();
    assert!(err.contains("546"), "{err}");
}

/// a request whose fee exceeds its harvested amount is undeliverable (refunded), never a hard
/// error that could stop the pass.
#[test]
fn a_fee_above_the_harvest_is_undeliverable() {
    let issuer = IssuerKey::from_bytes(&[3; 32]).unwrap();
    let rk = RequestKey::from_bytes([1; 32]);
    let (_, receiver) = wallet(11);
    let r = Receipt { harvested: 100, fee: 40_000, ..victim_receipt() };
    let err = build_private(&issuer, &rk, &request(&rk, &receiver, r)).unwrap_err();
    assert_eq!(err, UNDELIVERABLE);
}

/// a ticker with a Unicode format character (a right-to-left override) is refused.
#[test]
fn a_ticker_with_format_characters_is_refused() {
    let r = Receipt { ticker: "AB\u{202e}CD".into(), ..victim_receipt() };
    assert!(r.text().is_err());
}
