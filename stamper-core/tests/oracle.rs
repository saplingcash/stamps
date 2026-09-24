//! The stamper's transactions checked against librustzcash, the reference implementation: it must
//! parse them, compute the same transaction id, and the same SIGHASH_ALL digest for every input,
//! under each consensus branch it knows. (NU7 is only in librustzcash behind an unstable flag; the
//! branch is a plain number for our builder, tested in `branches.rs`.)

use std::ops::Deref;

use stamper_core::address::{hash160, p2pkh_script};
use stamper_core::build::{build, BuildRequest, Output, Utxo};
use stamper_core::key::IssuerKey;
use stamper_core::tx::{OutPoint, SpentCoin, Tx, TxIn, TxOut};

use transparent_oracle::*;

mod transparent_oracle {
    pub use zcash_primitives::transaction::sighash::{signature_hash, SignableInput};
    pub use zcash_primitives::transaction::txid::TxIdDigester;
    pub use zcash_primitives::transaction::{Authorization, Transaction, TransactionData};
    pub use zcash_protocol::consensus::BranchId;
    pub use zcash_protocol::value::Zatoshis;
    pub use zcash_script::script;
    pub use zcash_transparent::address::Script;
    pub use zcash_transparent::bundle::{Bundle, TxIn as ZTxIn};
    pub use zcash_transparent::sighash::{SighashType, TransparentAuthorizingContext};
}

#[derive(Debug)]
struct Ctx {
    amounts: Vec<Zatoshis>,
    scripts: Vec<Script>,
}
impl zcash_transparent::bundle::Authorization for Ctx {
    type ScriptSig = Script;
}
impl TransparentAuthorizingContext for Ctx {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.amounts.clone()
    }
    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.scripts.clone()
    }
}
struct Auth;
impl Authorization for Auth {
    type TransparentAuth = Ctx;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

fn key(n: u8) -> IssuerKey {
    IssuerKey::from_bytes(&[n; 32]).unwrap()
}

/// librustzcash's (txid, sighash of every input) for our bytes.
fn oracle(bytes: &[u8], branch: BranchId, spent: &[SpentCoin]) -> ([u8; 32], Vec<[u8; 32]>) {
    let tx = Transaction::read(bytes, branch).expect("librustzcash parses the transaction");
    let txid = *tx.txid().as_ref();
    let data = tx.deref();
    let b = data.transparent_bundle().expect("a transparent bundle");
    let ctx = Ctx {
        amounts: spent.iter().map(|c| Zatoshis::from_u64(c.value).unwrap()).collect(),
        scripts: spent.iter().map(|c| Script(script::Code(c.script.clone()))).collect(),
    };
    let bundle = Bundle { vin: b.vin.iter().map(|i| ZTxIn::from_parts(i.prevout().clone(), i.script_sig().clone(), i.sequence())).collect(), vout: b.vout.clone(), authorization: ctx };
    let tdata: TransactionData<Auth> = TransactionData::from_parts(data.version(), data.consensus_branch_id(), data.lock_time(), data.expiry_height(), Some(bundle), None, None, None);
    let parts = tdata.digest(TxIdDigester);
    let tb = tdata.transparent_bundle().unwrap();
    let mut sighashes = Vec::new();
    for i in 0..spent.len() {
        let spk = &tb.authorization.scripts[i];
        let input = SignableInput::Transparent(zcash_transparent::sighash::SignableInput::from_parts(tb, SighashType::ALL, i, spk, spk, tb.authorization.amounts[i]).unwrap());
        sighashes.push(*signature_hash(&tdata, &input, &parts).as_ref());
    }
    (txid, sighashes)
}

fn branch_id(b: BranchId) -> u32 {
    u32::from(b)
}

#[test]
fn txid_and_sighash_match_librustzcash_on_every_known_branch() {
    for branch in [BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_1, BranchId::Nu6_2, BranchId::Nu6_3] {
        for n_inputs in 1..=3u8 {
            let k = key(7);
            let issuer_script = p2pkh_script(&k.pubkey_hash());
            let mut tx = Tx {
                consensus_branch_id: branch_id(branch),
                lock_time: 0,
                expiry_height: 4_388_206,
                inputs: (0..n_inputs).map(|i| TxIn { prevout: OutPoint { txid: [i + 1; 32], index: i as u32 }, script_sig: vec![0x51], sequence: 0xffff_fffe - i as u32 }).collect(),
                outputs: vec![
                    TxOut { value: 0, script: [vec![0x6a, 0x34], vec![0xab; 52]].concat() },
                    TxOut { value: 546, script: p2pkh_script(&hash160(b"someone")) },
                    TxOut { value: 123_456, script: issuer_script.clone() },
                ],
            };
            let spent: Vec<SpentCoin> = (0..n_inputs).map(|i| SpentCoin { value: 200_000 + i as u64, script: issuer_script.clone() }).collect();
            // sign every input so the bytes are a real transaction
            let sighashes: Vec<[u8; 32]> = (0..tx.inputs.len()).map(|i| tx.sighash_all(i, &spent)).collect();
            for (i, d) in sighashes.iter().enumerate() {
                let sig = k.sign_digest(d, 1);
                tx.inputs[i].script_sig = [vec![sig.len() as u8], sig, vec![33], k.public_key().to_vec()].concat();
            }
            let (txid, oracle_sighashes) = oracle(&tx.serialize(), branch, &spent);
            assert_eq!(txid, tx.txid(), "txid, branch {branch:?}, {n_inputs} inputs");
            assert_eq!(oracle_sighashes, sighashes, "sighash, branch {branch:?}, {n_inputs} inputs");
        }
    }
}

#[test]
fn a_built_stamp_parses_in_librustzcash_and_its_signature_verifies() {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let k = key(9);
    let req = BuildRequest {
        consensus_branch_id: branch_id(BranchId::Nu6_3),
        expiry_height: 4_388_206,
        marginal_fee: 5_000,
        inputs: vec![Utxo { txid: "11".repeat(32), vout: 1, value: 1_000_000 }],
        outputs: vec![Output { value: 0, script: format!("6a34{}", "cd".repeat(52)) }, Output { value: 546, script: hex::encode(p2pkh_script(&hash160(b"holder"))) }],
    };
    let built = build(&k, &req).unwrap();
    let bytes = hex::decode(&built.hex).unwrap();
    let spent = vec![SpentCoin { value: 1_000_000, script: p2pkh_script(&k.pubkey_hash()) }];
    let (txid, sighashes) = oracle(&bytes, BranchId::Nu6_3, &spent);
    let mut shown = txid;
    shown.reverse();
    assert_eq!(hex::encode(shown), built.txid);
    // the scriptSig's signature verifies against librustzcash's own digest, with the issuer key
    let tx = Transaction::read(&bytes[..], BranchId::Nu6_3).unwrap();
    let sig_script = tx.transparent_bundle().unwrap().vin[0].script_sig().0 .0.clone();
    let sig_len = sig_script[0] as usize;
    let der = &sig_script[1..sig_len]; // without the hash type byte
    let sig = k256::ecdsa::Signature::from_der(der).unwrap();
    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&k.public_key()).unwrap();
    vk.verify_prehash(&sighashes[0], &sig).expect("the signature verifies");
    assert_eq!(sig_script[sig_len], 0x01, "SIGHASH_ALL");
    assert!(sig.normalize_s().is_none(), "low S");
}
