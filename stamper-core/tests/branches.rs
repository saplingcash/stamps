//! The consensus branch is whatever the node says: the same stamp built for the current branch
//! (NU6.3, 0x37A5165B) and for NU7 (0x77190AD9, the value in ZIP 259 at the time of writing) differs
//! only where ZIP 244 says it must, and a signature for one branch is invalid under the other.

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use stamper_core::address::{hash160, p2pkh_script};
use stamper_core::build::{build, BuildRequest, Output, Utxo};
use stamper_core::key::IssuerKey;
use stamper_core::tx::{OutPoint, SpentCoin, Tx, TxIn, TxOut};

const NU6_3: u32 = 0x37A5_165B;
const NU7: u32 = 0x7719_0AD9;

fn request(branch: u32) -> BuildRequest {
    BuildRequest {
        consensus_branch_id: branch,
        expiry_height: 3_600_040,
        marginal_fee: 5_000,
        inputs: vec![Utxo { txid: "aa".repeat(32), vout: 0, value: 500_000 }],
        outputs: vec![Output { value: 0, script: format!("6a34{}", "01".repeat(52)) }, Output { value: 546, script: hex::encode(p2pkh_script(&hash160(b"x"))) }],
    }
}

/// Our own reading of a built transaction: (branch id from the header, the tx, the signature, the key).
fn reparse(hex_tx: &str) -> (u32, Vec<u8>) {
    let b = hex::decode(hex_tx).unwrap();
    (u32::from_le_bytes(b[8..12].try_into().unwrap()), b)
}

fn sighash_for(branch: u32, key: &IssuerKey) -> [u8; 32] {
    // rebuild the unsigned transaction exactly as `build` lays it out (one input, record, postage, change)
    let script = p2pkh_script(&key.pubkey_hash());
    let tx = Tx {
        consensus_branch_id: branch,
        lock_time: 0,
        expiry_height: 3_600_040,
        inputs: vec![TxIn { prevout: OutPoint { txid: [0xaa; 32], index: 0 }, script_sig: vec![], sequence: 0xffff_ffff }],
        outputs: vec![
            TxOut { value: 0, script: hex::decode(format!("6a34{}", "01".repeat(52))).unwrap() },
            TxOut { value: 546, script: p2pkh_script(&hash160(b"x")) },
            TxOut { value: 500_000 - 546 - 20_000, script: script.clone() },
        ],
    };
    tx.sighash_all(0, &[SpentCoin { value: 500_000, script }])
}

fn signature(b: &[u8]) -> k256::ecdsa::Signature {
    // header 20 bytes, 1 input count, 36 prevout, script length, then <len><der+type>
    let script_start = 20 + 1 + 36 + 1;
    let sig_len = b[script_start] as usize;
    k256::ecdsa::Signature::from_der(&b[script_start + 1..script_start + sig_len]).unwrap()
}

#[test]
fn the_branch_from_the_node_is_written_and_signed_over() {
    let k = IssuerKey::from_bytes(&[5; 32]).unwrap();
    let a = build(&k, &request(NU6_3)).unwrap();
    let b = build(&k, &request(NU7)).unwrap();
    let (branch_a, bytes_a) = reparse(&a.hex);
    let (branch_b, bytes_b) = reparse(&b.hex);
    assert_eq!((branch_a, branch_b), (NU6_3, NU7));
    assert_ne!(a.txid, b.txid, "the txid commits to the branch (replay protection)");
    // same fee and change on both sides of the switch (lengths may differ by the DER signature's 70–72 bytes)
    assert_eq!((a.fee, a.change), (b.fee, b.change));

    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&k.public_key()).unwrap();
    let (sig_a, sig_b) = (signature(&bytes_a), signature(&bytes_b));
    vk.verify_prehash(&sighash_for(NU6_3, &k), &sig_a).expect("NU6.3 signature valid under NU6.3");
    vk.verify_prehash(&sighash_for(NU7, &k), &sig_b).expect("NU7 signature valid under NU7");
    assert!(vk.verify_prehash(&sighash_for(NU7, &k), &sig_a).is_err(), "an NU6.3 signature is invalid after the switch");
    assert!(vk.verify_prehash(&sighash_for(NU6_3, &k), &sig_b).is_err(), "an NU7 signature is invalid before it");
}

#[test]
fn any_branch_value_works_without_a_code_change() {
    let k = IssuerKey::from_bytes(&[6; 32]).unwrap();
    for branch in [0xC2D6_D0B4u32, 0xC8E7_1055, 0x4DEC_4DF0, NU6_3, NU7, 0xDEAD_BEEF] {
        let built = build(&k, &request(branch)).unwrap();
        assert_eq!(reparse(&built.hex).0, branch);
    }
}
