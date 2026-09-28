//! A transaction whose scriptSig names the issuer's key while its (mineable) txid is someone else's: the
//! offline checker must refuse it once the spent coin's value is given, and never claim the issuer without it.
#![cfg(feature = "private")]

mod common;

use orchard::keys::{FullViewingKey, Scope};
use stamper_core::private::build::NoSapling;
use stamper_core::private::memo::Receipt;
use stamper_core::private::proof::{check, make, Proof};
use stamper_core::record::{record_v2, solana_signature};
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkType, TestNetwork};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::builder::TransparentSigningSet;
use zcash_transparent::bundle::{OutPoint, TxOut};

fn victim_receipt() -> Receipt {
    Receipt { ticker: "ROOT".into(), mint: bs58::encode(crate::common::label::<32>("tests/mint")).into_string(), burned: 1_250_000_000_000, harvested: 1_234_567, fee: 40_000, signature: bs58::encode(crate::common::label::<64>("tests/harvest-signature")).into_string(), block_time: 1_790_424_000 }
}

/// The forger builds and signs their own transaction (their key spends their coin; the change pays
/// the issuer's address, which anyone may pay; 546 zat and the victim's receipt to the forger's receiver).
/// That transaction is valid and can be mined. Then, in the bytes they hand to a checker, they replace their
/// public key in the scriptSig by the issuer's (public, in every stamp). The txid does not change (v5/v6
/// txids leave out scriptSigs), so "this txid is mined" still holds on any explorer, and the offline
/// checker must not take it for the issuer's.
#[test]
fn a_swapped_scriptsig_with_the_same_txid_is_refused_or_flagged() {
    let issuer = crate::common::issuer("tests/issuer");
    let forger = crate::common::issuer("tests/forger");
    let sk = crate::common::spending_key("tests/wallet/31");
    let fvk = FullViewingKey::from(&sk);
    let receiver = fvk.address_at(0u32, Scope::External);

    let config = BuildConfig::Standard { sapling_anchor: None, orchard_anchor: None, ironwood_anchor: Some(orchard::Anchor::empty_tree()), orchard_padding: BundlePadding::DEFAULT, ironwood_padding: BundlePadding::DEFAULT };
    let mut b = Builder::new(TestNetwork, BlockHeight::from_u32(4_400_000), config).with_expiry_height(BlockHeight::from_u32(4_400_040));
    let mut signing = TransparentSigningSet::new();
    let pk = signing.add_key(secp256k1::SecretKey::from_slice(forger.secret_bytes().as_ref()).unwrap());
    let forger_addr = TransparentAddress::PublicKeyHash(forger.pubkey_hash());
    let issuer_addr = TransparentAddress::PublicKeyHash(issuer.pubkey_hash());
    b.add_transparent_p2pkh_input(pk, OutPoint::new(crate::common::label("tests/coin"), 0), TxOut::new(Zatoshis::from_u64(21_100).unwrap(), forger_addr.script().into())).unwrap();
    b.add_transparent_null_data_output::<std::convert::Infallible>(&record_v2(&solana_signature(&victim_receipt().signature).unwrap())).unwrap();
    b.add_transparent_output(&issuer_addr, Zatoshis::from_u64(21_100 - 20_000 - 546).unwrap()).unwrap();
    b.add_ironwood_output::<std::convert::Infallible>(None, receiver, Zatoshis::from_u64(546).unwrap(), MemoBytes::from_bytes(&victim_receipt().memo().unwrap()).unwrap()).unwrap();
    let rule = FeeRule::non_standard(Zatoshis::from_u64(5_000).unwrap(), 2, 150, 34).unwrap();
    let res = b.build(&signing, &[], &[], rand_core::OsRng, &NoSapling, &NoSapling, &rule).unwrap();
    let mut real = Vec::new();
    res.transaction().write(&mut real).unwrap();
    let real_txid = *res.transaction().txid().as_ref();

    // the honest bytes fail: not spent by the issuer
    let proof = make(&real, &[fvk.to_ivk(Scope::External)]).unwrap();
    assert!(check(&real, &proof, NetworkType::Test, &[issuer.pubkey_hash()], None).unwrap_err().contains("not spent by a published issuer"));

    // the same bytes with the issuer's public key in place of the forger's
    let (from, to) = (hex::encode(forger.public_key()), hex::encode(issuer.public_key()));
    let hexed = hex::encode(&real);
    assert_eq!(hexed.matches(&from).count(), 1);
    let forged = hex::decode(hexed.replace(&from, &to)).unwrap();
    let t = Transaction::read(&forged[..], BranchId::Nu6_3).unwrap();
    assert_eq!(t.txid().as_ref(), &real_txid, "the txid does not cover the scriptSig");
    let p = Proof::decode(&proof.encode()).unwrap();
    // with the spent coin's value, the signature is verified: it was made by the forger's key, not the issuer's
    let err = check(&forged, &p, NetworkType::Test, &[issuer.pubkey_hash()], Some(&[21_100])).unwrap_err();
    assert!(err.contains("does not verify with the key it names"), "{err}");
    // without it, the checker does not claim the issuer: it says so first, and the wtxid differs from the real one
    let shown = check(&forged, &p, NetworkType::Test, &[issuer.pubkey_hash()], None).unwrap();
    assert!(!shown.issuer_verified);
    assert!(shown.not_checked[0].contains("NOT verified"));
    assert!(shown.checked.iter().all(|c| !c.contains("signature verifies")));
    let real_t = Transaction::read(&real[..], BranchId::Nu6_3).unwrap();
    let real_wtxid = hex::encode([real_t.txid().as_ref().as_slice(), real_t.auth_commitment().as_bytes()].concat());
    assert_ne!(shown.wtxid, real_wtxid, "the wtxid covers the scriptSig");
}
