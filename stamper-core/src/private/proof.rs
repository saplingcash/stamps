//! The stamp proof (SPEC.md §9.6): one string that shows a private stamp's note went to a receiver,
//! with its receipt, and nothing else about the holder's wallet.
//!
//! ```text
//! splg-proof:1:<base64url( txid 32 (internal order) || pool u8 (2 = Ironwood) || action u8
//!                          || receiver 43 || value u64 LE || rseed 32 )>
//! ```
//!
//! Checking needs no key: the note is rebuilt from the receiver, value, `rho` (the action's
//! nullifier) and `rseed`; its `esk` is derived from them (ZIP 212); the action must decrypt with that
//! `esk` and the receiver's `pk_d` to exactly this note (which also checks `epk` and `cmx`), and the
//! memo it yields is the receipt.
//!
//! That note check, and finding the note with a viewing key, are the zcash-delivery-proof library's
//! (`zdp:1:`, the same fields with a two-byte action index). This module adds what makes the note a
//! stamp: the transaction's shape, its issuer, and the receipt in the memo.

use base64::Engine;
use orchard::keys::IncomingViewingKey;
use serde::Serialize;
use sha2::{Digest, Sha256};
use zcash_delivery_proof::{DeliveryProof, Pool, ViewingKeys};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BranchId, NetworkType};

use super::memo::Receipt;
use super::POSTAGE;
use crate::record::{RECORD_V2_LEN, TAG};

pub const PREFIX: &str = "splg-proof:1:";
pub const PROOF_LEN: usize = 32 + 1 + 1 + 43 + 8 + 32;
pub const POOL_IRONWOOD: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub txid: [u8; 32],
    pub pool: u8,
    pub action: u8,
    pub receiver: [u8; 43],
    pub value: u64,
    pub rseed: [u8; 32],
}

impl Proof {
    pub fn encode(&self) -> String {
        let mut b = Vec::with_capacity(PROOF_LEN);
        b.extend_from_slice(&self.txid);
        b.push(self.pool);
        b.push(self.action);
        b.extend_from_slice(&self.receiver);
        b.extend_from_slice(&self.value.to_le_bytes());
        b.extend_from_slice(&self.rseed);
        format!("{PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))
    }

    pub fn decode(s: &str) -> Result<Proof, String> {
        let body = s.trim().strip_prefix(PREFIX).ok_or("not a stamp proof (splg-proof:1:…)")?;
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body).map_err(|_| "the proof is not base64url")?;
        if b.len() != PROOF_LEN {
            return Err("the proof has the wrong length".into());
        }
        Ok(Proof {
            txid: b[0..32].try_into().unwrap(),
            pool: b[32],
            action: b[33],
            receiver: b[34..77].try_into().unwrap(),
            value: u64::from_le_bytes(b[77..85].try_into().unwrap()),
            rseed: b[85..117].try_into().unwrap(),
        })
    }

    /// The same note as a zcash-delivery-proof proof; None unless the pool is Ironwood.
    pub fn delivery_proof(&self) -> Option<DeliveryProof> {
        (self.pool == POOL_IRONWOOD).then_some(DeliveryProof { txid: self.txid, pool: Pool::Ironwood, action: u16::from(self.action), receiver: self.receiver, value: self.value, rseed: self.rseed })
    }
}

/// What a checked proof shows.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Shown {
    /// the stamp's txid, displayed (byte-reversed) hex
    pub txid: String,
    /// the receiver as an Ironwood/Orchard-only unified address
    pub address: String,
    pub value: u64,
    pub receipt: Receipt,
    /// the transparent inputs' public key hashes (each one of the given issuers)
    pub input_key_hashes: Vec<String>,
    /// the transaction's wtxid (ZIP 239: txid then authorizing-data digest, internal byte order): the exact bytes
    /// checked, signatures included; a block explorer that shows it shows these bytes are the mined ones
    pub wtxid: String,
    /// whether each input's signature was verified against the issuer key it names (needs the spent coins'
    /// values); when false, the issuer is only what the bytes CLAIM
    pub issuer_verified: bool,
    /// what this check established
    pub checked: Vec<String>,
    /// what it did not establish, and needs a node and a Solana RPC (the verifier's check-proof does both)
    pub not_checked: Vec<String>,
}

/// What an offline check cannot establish, said with every result.
pub const NOT_CHECKED_OFFLINE: [&str; 3] = [
    "that these bytes are the mined transaction: a txid does not cover signatures, so a mined txid does not vouch for these inputs; compare the wtxid with a node you trust, or use the verifier's check-proof",
    "that the issuer key was valid at the transaction's height (the height is not known offline)",
    "that the receipt's amounts equal the Solana harvest's Redeemed event and fee (Solana is not read offline)",
];

/// Said when the inputs' signatures were not verified (no values for the spent coins were given).
pub const ISSUER_NOT_VERIFIED: &str = "THE ISSUER: the inputs name a published issuer key, but their signatures were NOT verified, so the issuer is only what these bytes claim (anyone can put the issuer's public key in a scriptSig without changing the txid). Give the spent coins' values to verify them, or use the verifier's check-proof or the stamp's page on the site";

/// The P2PKH key hashes of every issuer in a parameter file (`zcash.issuers[].address`), on its network.
pub fn issuers_from_params(json: &str) -> Result<(NetworkType, Vec<[u8; 20]>), String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|_| "the parameter file is not JSON")?;
    let (net, network) = match v["zcash"]["network"].as_str() {
        Some("mainnet") => (NetworkType::Main, crate::address::Network::Mainnet),
        Some("testnet") => (NetworkType::Test, crate::address::Network::Testnet),
        _ => return Err("the parameter file has no zcash.network".into()),
    };
    let list = v["zcash"]["issuers"].as_array().ok_or("the parameter file has no zcash.issuers")?;
    let hashes = list.iter().map(|i| i["address"].as_str().and_then(|a| crate::address::p2pkh_hash(network, a)).ok_or_else(|| "an issuer is not a P2PKH address on this network".to_string())).collect::<Result<Vec<_>, _>>()?;
    if hashes.is_empty() {
        return Err("the parameter file names no issuer".into());
    }
    Ok((net, hashes))
}

pub(crate) mod sig {
    use zcash_primitives::transaction::sighash::{signature_hash, SignableInput};
    use zcash_primitives::transaction::txid::TxIdDigester;
    use zcash_primitives::transaction::{Authorization, Transaction, TransactionData};
    use zcash_protocol::value::Zatoshis;
    use zcash_transparent::address::Script;
    use zcash_transparent::bundle::{Bundle, TxIn};
    use zcash_transparent::sighash::{SighashType, TransparentAuthorizingContext};

    #[derive(Debug)]
    struct Spent {
        amounts: Vec<Zatoshis>,
        scripts: Vec<Script>,
    }
    impl zcash_transparent::bundle::Authorization for Spent {
        type ScriptSig = Script;
    }
    impl TransparentAuthorizingContext for Spent {
        fn input_amounts(&self) -> Vec<Zatoshis> {
            self.amounts.clone()
        }
        fn input_scriptpubkeys(&self) -> Vec<Script> {
            self.scripts.clone()
        }
    }
    struct WithSpent;
    impl Authorization for WithSpent {
        type TransparentAuth = Spent;
        type SaplingAuth = sapling::bundle::Authorized;
        type OrchardAuth = orchard::bundle::Authorized;
    }

    /// The two pushes of a P2PKH scriptSig: the DER signature with its hash type, and the public key.
    pub fn pushes(ss: &[u8]) -> Option<(&[u8], &[u8])> {
        let n = *ss.first()? as usize;
        let sig = ss.get(1..1 + n)?;
        let k = *ss.get(1 + n)? as usize;
        let key = ss.get(2 + n..2 + n + k)?;
        (2 + n + k == ss.len() && k == 33).then_some((sig, key))
    }

    /// Verifies every input's SIGHASH_ALL signature (ZIP 244) with the public key it carries, given the
    /// values of the coins it spends (their scripts are the P2PKH of those keys).
    pub fn verify(t: &Transaction, values: &[u64]) -> Result<(), String> {
        let tb = t.transparent_bundle().ok_or("no transparent part")?;
        if values.len() != tb.vin.len() {
            return Err(format!("{} spent-coin values given for {} inputs", values.len(), tb.vin.len()));
        }
        let mut keys = Vec::new();
        let mut scripts = Vec::new();
        for i in &tb.vin {
            let (sig, key) = pushes(&i.script_sig().0 .0).ok_or("an input is not a P2PKH spend")?;
            keys.push((sig.to_vec(), key.to_vec()));
            scripts.push(Script(zcash_script::script::Code(crate::address::p2pkh_script(&crate::address::hash160(key)))));
        }
        let amounts = values.iter().map(|v| Zatoshis::from_u64(*v).map_err(|_| "a spent-coin value is out of range".to_string())).collect::<Result<Vec<_>, _>>()?;
        let spent = Spent { amounts: amounts.clone(), scripts: scripts.clone() };
        let bundle = Bundle { vin: tb.vin.iter().map(|i| TxIn::from_parts(i.prevout().clone(), i.script_sig().clone(), i.sequence())).collect(), vout: tb.vout.clone(), authorization: spent };
        let data: TransactionData<WithSpent> = t.clone().into_data().map_bundles(|_| Some(bundle), |s| s, |o| o);
        let parts = data.digest(TxIdDigester);
        let tbw = data.transparent_bundle().expect("set above");
        for (i, (sig, key)) in keys.iter().enumerate() {
            let (der, ht) = sig.split_at(sig.len().checked_sub(1).ok_or("an empty signature")?);
            if ht != [0x01] {
                return Err("an input's signature is not SIGHASH_ALL".into());
            }
            let input = zcash_transparent::sighash::SignableInput::from_parts(tbw, SighashType::ALL, i, &scripts[i], &scripts[i], amounts[i]).map_err(|_| "cannot form the signature hash")?;
            let digest = signature_hash(&data, &SignableInput::Transparent(input), &parts);
            use k256::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_| "an input's public key is not valid")?;
            let s = k256::ecdsa::Signature::from_der(der).map_err(|_| "an input's signature is not DER")?;
            vk.verify_prehash(digest.as_ref(), &s).map_err(|_| format!("input {i}'s signature does not verify with the key it names"))?;
        }
        Ok(())
    }
}

/// The shape of a private stamp (SPEC.md §9.4), as far as the bytes show it: spent only by the given
/// issuers; one version 2 record; no Sapling, Sprout or Orchard part; exactly 546 zatoshi into the
/// Ironwood pool; every other transparent output pays an issuer (its change).
fn stamp_shape(t: &Transaction, issuers: &[[u8; 20]]) -> Result<(), String> {
    if t.sapling_bundle().is_some() || t.sprout_bundle().is_some() || t.orchard_bundle().is_some() {
        return Err("the transaction has a Sapling, Sprout or Orchard part: not a private stamp".into());
    }
    let iw = t.ironwood_bundle().ok_or("the transaction has no Ironwood part")?;
    if i64::from(*iw.value_balance()) != -(POSTAGE as i64) {
        return Err("the transaction does not put exactly 546 zatoshi into the Ironwood pool".into());
    }
    let tb = t.transparent_bundle().ok_or("no transparent part")?;
    let known = |h: &[u8]| issuers.iter().any(|k| k.as_slice() == h);
    let hashes = input_key_hashes(t);
    if hashes.is_empty() || !hashes.iter().all(|h| hex::decode(h).map(|b| known(&b)).unwrap_or(false)) {
        return Err("the transaction is not spent by a published issuer key".into());
    }
    for o in &tb.vout {
        let s = &o.script_pubkey().0 .0;
        if s.first() == Some(&0x6a) {
            continue;
        }
        let issuer_change = s.len() == 25 && s[..3] == [0x76, 0xa9, 0x14] && s[23..] == [0x88, 0xac] && known(&s[3..23]);
        if !issuer_change {
            return Err("a transparent output pays someone who is not an issuer: a stamp only returns change to its issuer".into());
        }
    }
    record_hash(t).map(|_| ())
}

/// The consensus branch a v5/v6 transaction names in its header (a v4 transaction, which names none, is
/// read under Canopy).
pub fn header_branch(tx: &[u8]) -> Result<BranchId, String> {
    zcash_delivery_proof::header_branch(tx).map_err(|e| e.to_string())
}

pub(crate) fn read_tx(tx: &[u8]) -> Result<Transaction, String> {
    let t = Transaction::read(tx, header_branch(tx)?).map_err(|e| format!("not a transaction: {e}"))?;
    let mut back = Vec::new();
    t.write(&mut back).map_err(|e| e.to_string())?;
    if back != tx {
        return Err("the transaction's bytes do not survive a round trip through librustzcash".into());
    }
    Ok(t)
}

/// The receiver as a unified address holding only it.
pub fn receiver_address(receiver: &[u8; 43], network: NetworkType) -> String {
    zcash_delivery_proof::receiver_address(receiver, network)
}

/// The version 2 record's hash part, if the transaction carries exactly one OP_RETURN that is one.
fn record_hash(t: &Transaction) -> Result<[u8; 18], String> {
    let tb = t.transparent_bundle().ok_or("no transparent part")?;
    let rets: Vec<Vec<u8>> = tb.vout.iter().map(|o| o.script_pubkey().0 .0.clone()).filter(|s| s.first() == Some(&0x6a)).collect();
    if rets.len() != 1 {
        return Err("not exactly one OP_RETURN".into());
    }
    let s = &rets[0];
    if s.len() != 2 + RECORD_V2_LEN || s[1] as usize != RECORD_V2_LEN || &s[2..6] != TAG || s[6] != 2 {
        return Err("the OP_RETURN is not a version 2 record".into());
    }
    Ok(s[7..25].try_into().unwrap())
}

fn input_key_hashes(t: &Transaction) -> Vec<String> {
    t.transparent_bundle()
        .map(|tb| {
            tb.vin
                .iter()
                .map(|i| {
                    let ss = &i.script_sig().0 .0;
                    // two pushes: a signature, then a 33-byte compressed key
                    let n = *ss.first().unwrap_or(&0) as usize;
                    match ss.get(1 + n..) {
                        Some([33, key @ ..]) if key.len() == 33 => hex::encode(crate::address::hash160(key)),
                        _ => String::new(),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Checks a proof against the stamp transaction's bytes. `network` only chooses the address encoding.
///
/// `issuers`: the published issuers' key hashes (the parameter file's `zcash.issuers`). The check
/// fails unless the transaction has a private stamp's shape and is spent by one of them, and the note is
/// the 546-zatoshi postage. What bytes alone cannot show is listed in `not_checked`.
///
/// `spent_values`: the values (zatoshi) of the coins the inputs spend, in order. With them, every input's
/// signature is verified against the issuer key it names (ZIP 244); a wrong value can only make a genuine
/// stamp fail, never a forged one pass. Without them, the result says the issuer was NOT verified.
pub fn check(tx: &[u8], proof: &Proof, network: NetworkType, issuers: &[[u8; 20]], spent_values: Option<&[u64]>) -> Result<Shown, String> {
    if issuers.is_empty() {
        return Err("no published issuer key was given: nothing would show who sent this transaction".into());
    }
    let t = read_tx(tx)?;
    if t.txid().as_ref() != &proof.txid {
        return Err("the transaction is not the one the proof names".into());
    }
    if proof.pool != POOL_IRONWOOD {
        return Err("the proof names a pool other than Ironwood".into());
    }
    if proof.value != POSTAGE {
        return Err("the note is not the 546-zatoshi postage of a stamp".into());
    }
    stamp_shape(&t, issuers)?;
    if let Some(values) = spent_values {
        sig::verify(&t, values)?;
    }
    let delivery = zcash_delivery_proof::check(tx, &proof.delivery_proof().expect("an Ironwood proof")).map_err(|e| e.to_string())?;
    let receipt = Receipt::parse(&delivery.memo)?;
    let sig = crate::record::solana_signature(&receipt.signature)?;
    if Sha256::digest(sig)[..18] != record_hash(&t)? {
        return Err("the receipt's harvest is not the one the record names".into());
    }
    let mut shown = proof.txid;
    shown.reverse();
    let mut checked = vec![
        "the transaction's own txid is the proof's",
        if spent_values.is_some() { "every input's signature verifies with the published issuer key it names (ZIP 244, with the spent coins' values given)" } else { "every input names a published issuer key (signatures NOT verified: see notChecked)" },
        "its other outputs are the issuer's change",
        "it has a private stamp's shape: one version 2 record, no Sapling, Sprout or Orchard part, exactly 546 zatoshi into the Ironwood pool",
        "the named action delivers exactly this 546-zatoshi note to this receiver (its esk, epk and note commitment)",
        "the note's memo is a receipt, and its harvest signature hashes to the record",
    ];
    checked.retain(|c| !c.is_empty());
    let mut not_checked: Vec<String> = NOT_CHECKED_OFFLINE.iter().map(|s| s.to_string()).collect();
    if spent_values.is_none() {
        not_checked.insert(0, ISSUER_NOT_VERIFIED.to_string());
    }
    Ok(Shown {
        txid: hex::encode(shown),
        address: receiver_address(&proof.receiver, network),
        value: proof.value,
        receipt,
        input_key_hashes: input_key_hashes(&t),
        wtxid: hex::encode(delivery.wtxid),
        issuer_verified: spent_values.is_some(),
        checked: checked.iter().map(|s| s.to_string()).collect(),
        not_checked,
    })
}

/// The incoming viewing key in a UFVK or UIVK (its Orchard item, external scope).
pub fn viewing_keys(s: &str) -> Result<(NetworkType, Vec<IncomingViewingKey>), String> {
    let keys = ViewingKeys::parse(s).map_err(|e| e.to_string())?;
    Ok((keys.network, keys.incoming.into_iter().take(1).collect()))
}

/// Makes a proof for the stamp note in `tx` that one of `keys` can decrypt.
pub fn make(tx: &[u8], keys: &[IncomingViewingKey]) -> Result<Proof, String> {
    let t = read_tx(tx)?;
    t.ironwood_bundle().ok_or("the transaction has no Ironwood part")?;
    // the network only matters for encoding addresses, which make() does not do
    let keys = ViewingKeys { network: NetworkType::Main, incoming: keys.to_vec(), outgoing: vec![] };
    let found = zcash_delivery_proof::make(tx, &keys).map_err(|e| e.to_string())?;
    let p = found
        .into_iter()
        .map(|f| f.proof)
        .find(|p| p.pool == Pool::Ironwood && p.value == POSTAGE)
        .ok_or("none of these keys receives a note in this transaction")?;
    let action = u8::try_from(p.action).map_err(|_| "the stamp note's action index does not fit a stamp proof")?;
    Ok(Proof { txid: p.txid, pool: POOL_IRONWOOD, action, receiver: p.receiver, value: p.value, rseed: p.rseed })
}

/// A transaction as the stamp rules read it (SPEC.md §3, §9.4): what the verifier needs from a v5 or
/// v6 transaction, with its txid computed here (librustzcash) rather than taken from a node.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inspected {
    /// displayed (byte-reversed) hex
    pub txid: String,
    pub version: u32,
    pub consensus_branch_id: u32,
    pub expiry_height: u32,
    pub inputs: Vec<InspectedInput>,
    pub outputs: Vec<InspectedOutput>,
    pub sapling: bool,
    pub sprout: bool,
    pub orchard: bool,
    /// the Ironwood bundle, if any
    pub ironwood: Option<InspectedShielded>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectedInput {
    /// the coin it spends: txid (displayed hex) and output index
    pub prev_txid: String,
    pub prev_index: u32,
    pub script_sig: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectedOutput {
    pub value: u64,
    pub script: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectedShielded {
    pub actions: usize,
    /// the bundle's value balance in zatoshi (negative: value entering the pool)
    pub value_balance: i64,
}

pub fn inspect(tx: &[u8]) -> Result<Inspected, String> {
    let t = read_tx(tx)?;
    let mut shown = *t.txid().as_ref();
    shown.reverse();
    let (inputs, outputs) = match t.transparent_bundle() {
        Some(tb) => (
            tb.vin
                .iter()
                .map(|i| {
                    let mut prev = *i.prevout().hash();
                    prev.reverse();
                    InspectedInput { prev_txid: hex::encode(prev), prev_index: i.prevout().n(), script_sig: hex::encode(&i.script_sig().0 .0) }
                })
                .collect(),
            tb.vout.iter().map(|o| InspectedOutput { value: u64::from(o.value()), script: hex::encode(&o.script_pubkey().0 .0) }).collect(),
        ),
        None => (Vec::new(), Vec::new()),
    };
    let version = u32::from_le_bytes(tx[0..4].try_into().unwrap()) & 0x7fff_ffff;
    Ok(Inspected {
        txid: hex::encode(shown),
        version,
        consensus_branch_id: u32::from(header_branch(tx)?),
        expiry_height: u32::from(t.expiry_height()),
        inputs,
        outputs,
        sapling: t.sapling_bundle().is_some(),
        sprout: t.sprout_bundle().is_some(),
        orchard: t.orchard_bundle().is_some(),
        ironwood: t.ironwood_bundle().map(|b| InspectedShielded { actions: b.actions().len(), value_balance: i64::from(*b.value_balance()) }),
    })
}
