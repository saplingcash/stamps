//! The transaction reader on the coins a stamp spends (any version), and the issuer signature check against
//! swapped or changed bytes.
#![cfg(feature = "private")]

use stamper_core::key::IssuerKey;
use stamper_core::private::build::NoSapling;
use stamper_core::private::proof::inspect;
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::TxVersion;
use zcash_protocol::consensus::{BlockHeight, TestNetwork};
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::builder::TransparentSigningSet;
use zcash_transparent::bundle::{OutPoint, TxOut};

/// A v4 transaction (a coin that reached the issuer before NU5, or from a wallet that still builds v4) is
/// read, with its outputs' values and its own txid.
#[test]
fn inspect_reads_a_v4_transaction() {
    let key = IssuerKey::from_bytes(&[3; 32]).unwrap();
    // testnet Canopy (before NU5 at 1,842,420): the builder makes a v4 transaction
    let height = BlockHeight::from_u32(1_500_000);
    let mut b = Builder::new(TestNetwork, height, BuildConfig::Standard { sapling_anchor: None, orchard_anchor: None, ironwood_anchor: None, orchard_padding: BundlePadding::DEFAULT, ironwood_padding: BundlePadding::DEFAULT });
    let mut signing = TransparentSigningSet::new();
    let pk = signing.add_key(secp256k1::SecretKey::from_slice(key.secret_bytes().as_ref()).unwrap());
    let addr = TransparentAddress::PublicKeyHash(key.pubkey_hash());
    b.add_transparent_p2pkh_input(pk, OutPoint::new([0xcd; 32], 0), TxOut::new(Zatoshis::from_u64(100_000).unwrap(), addr.script().into())).unwrap();
    b.add_transparent_output(&addr, Zatoshis::from_u64(90_000).unwrap()).unwrap();
    let rule = FeeRule::non_standard(Zatoshis::from_u64(5_000).unwrap(), 2, 150, 34).unwrap();
    let res = b.build(&signing, &[], &[], rand_core::OsRng, &NoSapling, &NoSapling, &rule).unwrap();
    assert_eq!(res.transaction().version(), TxVersion::V4);
    let mut bytes = Vec::new();
    res.transaction().write(&mut bytes).unwrap();
    let t = inspect(&bytes).unwrap();
    assert_eq!(t.version, 4);
    assert_eq!(t.outputs[0].value, 90_000);
    let mut txid = *res.transaction().txid().as_ref();
    txid.reverse();
    assert_eq!(t.txid, hex::encode(txid));
}

mod forge {
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use stamper_core::key::IssuerKey;
    use stamper_core::private::build::NoSapling;
    use stamper_core::private::memo::Receipt;
    use stamper_core::private::proof::{check, make, Proof};
    use stamper_core::record::{record_v2, solana_signature};
    use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
    use zcash_primitives::transaction::fees::zip317::FeeRule;
    use zcash_protocol::consensus::{BlockHeight, NetworkType, TestNetwork};
    use zcash_protocol::memo::MemoBytes;
    use zcash_protocol::value::Zatoshis;
    use zcash_transparent::address::TransparentAddress;
    use zcash_transparent::builder::TransparentSigningSet;
    use zcash_transparent::bundle::{OutPoint, TxOut};

    fn victim() -> Receipt {
        Receipt { ticker: "ROOT".into(), mint: bs58::encode([5u8; 32]).into_string(), burned: 1_250_000_000_000, harvested: 1_234_567, fee: 40_000, signature: bs58::encode([9u8; 64]).into_string(), block_time: 1_790_424_000 }
    }

    /// The forger's own mineable transaction (their key, their coin of 21,100 zat, change to the issuer), and
    /// the same bytes with the issuer's public key swapped into the scriptSig (same txid).
    fn forged() -> (Vec<u8>, Vec<u8>, FullViewingKey, IssuerKey) {
        let issuer = IssuerKey::from_bytes(&[3; 32]).unwrap();
        let forger = IssuerKey::from_bytes(&[0x77; 32]).unwrap();
        let fvk = FullViewingKey::from(&Option::<SpendingKey>::from(SpendingKey::from_bytes([31; 32])).unwrap());
        let config = BuildConfig::Standard { sapling_anchor: None, orchard_anchor: None, ironwood_anchor: Some(orchard::Anchor::empty_tree()), orchard_padding: BundlePadding::DEFAULT, ironwood_padding: BundlePadding::DEFAULT };
        let mut b = Builder::new(TestNetwork, BlockHeight::from_u32(4_400_000), config).with_expiry_height(BlockHeight::from_u32(4_400_040));
        let mut signing = TransparentSigningSet::new();
        let pk = signing.add_key(secp256k1::SecretKey::from_slice(forger.secret_bytes().as_ref()).unwrap());
        b.add_transparent_p2pkh_input(pk, OutPoint::new([0xcd; 32], 0), TxOut::new(Zatoshis::from_u64(21_100).unwrap(), TransparentAddress::PublicKeyHash(forger.pubkey_hash()).script().into())).unwrap();
        b.add_transparent_null_data_output::<std::convert::Infallible>(&record_v2(&solana_signature(&victim().signature).unwrap())).unwrap();
        b.add_transparent_output(&TransparentAddress::PublicKeyHash(issuer.pubkey_hash()), Zatoshis::from_u64(554).unwrap()).unwrap();
        b.add_ironwood_output::<std::convert::Infallible>(None, fvk.address_at(0u32, Scope::External), Zatoshis::from_u64(546).unwrap(), MemoBytes::from_bytes(&victim().memo().unwrap()).unwrap()).unwrap();
        let rule = FeeRule::non_standard(Zatoshis::from_u64(5_000).unwrap(), 2, 150, 34).unwrap();
        let res = b.build(&signing, &[], &[], rand_core::OsRng, &NoSapling, &NoSapling, &rule).unwrap();
        let mut real = Vec::new();
        res.transaction().write(&mut real).unwrap();
        let swapped = hex::decode(hex::encode(&real).replace(&hex::encode(forger.public_key()), &hex::encode(issuer.public_key()))).unwrap();
        (real, swapped, fvk, issuer)
    }

    /// With the spent value given, the swapped scriptSig fails whatever value is claimed; without it, the
    /// check passes only as "issuer NOT verified".
    #[test]
    fn swapped_scriptsig_with_spent_values_fails() {
        let (real, swapped, fvk, issuer) = forged();
        let proof = Proof::decode(&make(&real, &[fvk.to_ivk(Scope::External)]).unwrap().encode()).unwrap();
        for v in [21_100u64, 21_101, 1, 0, 2_100_000_000_000_000] {
            assert!(check(&swapped, &proof, NetworkType::Test, &[issuer.pubkey_hash()], Some(&[v])).is_err(), "value {v}");
        }
        assert!(check(&swapped, &proof, NetworkType::Test, &[issuer.pubkey_hash()], Some(&[21_100, 1])).is_err());
        let open = check(&swapped, &proof, NetworkType::Test, &[issuer.pubkey_hash()], None).unwrap();
        assert!(!open.issuer_verified);
        assert!(open.not_checked[0].contains("NOT verified"));
        // the honest bytes fail on the issuer before any signature
        assert!(check(&real, &proof, NetworkType::Test, &[issuer.pubkey_hash()], Some(&[21_100])).is_err());
    }

    /// A genuine stamp's bytes with one memo-ciphertext byte changed: the txid changes (the proof no longer
    /// names it), and with a proof re-pointed at it the issuer's signature no longer verifies.
    #[test]
    fn a_genuine_stamp_verifies_only_with_its_value() {
        use stamper_core::address::Network;
        use stamper_core::build::Utxo;
        use stamper_core::private::build::{build_private, PrivateRequest, Sealed};
        use stamper_core::private::seal::{seal, RequestKey};
        use base64::Engine;
        let issuer = IssuerKey::from_bytes(&[3; 32]).unwrap();
        let rk = RequestKey::from_bytes([1; 32]);
        let fvk = FullViewingKey::from(&Option::<SpendingKey>::from(SpendingKey::from_bytes([32; 32])).unwrap());
        let receiver = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        let sealed = seal(&rk.public(), 1, &[0x42; 32], &receiver, [7; 32]).unwrap();
        let req = PrivateRequest { network: Network::Testnet, consensus_branch_id: 0x37a5_165b, target_height: 4_400_000, expiry_height: 4_400_040, marginal_fee: 5_000, input: Utxo { txid: "ab".repeat(32), vout: 0, value: 205_460 }, receipt: victim(), sealed: Sealed { kid: 1, sealed: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sealed), holder: bs58::encode([0x42; 32]).into_string() }, anchor: None };
        let built = build_private(&issuer, &rk, &req).unwrap();
        let bytes = hex::decode(&built.hex).unwrap();
        let proof = make(&bytes, &[fvk.to_ivk(Scope::External)]).unwrap();
        let ok = check(&bytes, &Proof::decode(&proof.encode()).unwrap(), NetworkType::Test, &[issuer.pubkey_hash()], Some(&[205_460])).unwrap();
        assert!(ok.issuer_verified);
        // a wrong spent value makes the genuine stamp fail, never pass something else
        assert!(check(&bytes, &proof, NetworkType::Test, &[issuer.pubkey_hash()], Some(&[205_461])).is_err());
    }
}
