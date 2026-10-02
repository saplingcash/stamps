//! The stamp proof of a payout stamp (SPEC.md §10.5): one string that shows an exit's note went to a
//! receiver, with its receipt, and nothing else about the receiver's wallet.
//!
//! ```text
//! splg-proof:2:<base64url( txid 32 (internal order) || pool u8 (2 = Ironwood) || action u16 LE
//!                          || receiver 43 || value u64 LE || rseed 32 || account u8 || index u32 LE )>
//! ```
//!
//! The note check is the zcash-delivery-proof library's (its `zdp:1:` proof is the first 118 bytes). This
//! module adds what makes the note a payout stamp: the transaction's shape (spent from order addresses, one
//! version 3 record, nothing but Ironwood notes out), the order address of the published exit key, and the
//! receipt in the memo. `splg-proof:1` (private stamps, `crate::private::proof`) is unchanged.

use base64::Engine;
use orchard::keys::IncomingViewingKey;
use serde::Serialize;
use zcash_delivery_proof::{DeliveryProof, Pool, ViewingKeys};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::NetworkType;

use super::exit_key::{order_pubkey, parse_account_pubkey, ACCOUNT_PUBKEY_LEN, MAX_INDEX};
use super::receipt::PayoutReceipt;
use crate::private::proof::{read_tx, receiver_address, sig};
use crate::record::{exit_hash, parse_v3_script, solana_signature, RECORD_V3_HASH_LEN};

pub const PREFIX: &str = "splg-proof:2:";
pub const PROOF_LEN: usize = 32 + 1 + 2 + 43 + 8 + 32 + 1 + 4;
pub const POOL_IRONWOOD: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutProof {
    pub txid: [u8; 32],
    pub pool: u8,
    pub action: u16,
    pub receiver: [u8; 43],
    pub value: u64,
    pub rseed: [u8; 32],
    /// the exit key's account whose order address paid the note (0: exits from Sapling's site)
    pub account: u8,
    /// the exit's order index (its Solana memo names it)
    pub index: u32,
}

impl PayoutProof {
    pub fn to_bytes(&self) -> [u8; PROOF_LEN] {
        let mut b = [0u8; PROOF_LEN];
        b[0..32].copy_from_slice(&self.txid);
        b[32] = self.pool;
        b[33..35].copy_from_slice(&self.action.to_le_bytes());
        b[35..78].copy_from_slice(&self.receiver);
        b[78..86].copy_from_slice(&self.value.to_le_bytes());
        b[86..118].copy_from_slice(&self.rseed);
        b[118] = self.account;
        b[119..123].copy_from_slice(&self.index.to_le_bytes());
        b
    }

    pub fn encode(&self) -> String {
        format!("{PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn decode(s: &str) -> Result<PayoutProof, String> {
        let body = s.trim().strip_prefix(PREFIX).ok_or("not a payout stamp proof (splg-proof:2:…)")?;
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body).map_err(|_| "the proof is not base64url")?;
        if b.len() != PROOF_LEN {
            return Err("the proof has the wrong length".into());
        }
        let p = PayoutProof {
            txid: b[0..32].try_into().unwrap(),
            pool: b[32],
            action: u16::from_le_bytes(b[33..35].try_into().unwrap()),
            receiver: b[35..78].try_into().unwrap(),
            value: u64::from_le_bytes(b[78..86].try_into().unwrap()),
            rseed: b[86..118].try_into().unwrap(),
            account: b[118],
            index: u32::from_le_bytes(b[119..123].try_into().unwrap()),
        };
        if p.index > MAX_INDEX {
            return Err("the proof's order index is not below 2^31".into());
        }
        Ok(p)
    }

    /// The same note as a zcash-delivery-proof proof; None unless the pool is Ironwood.
    pub fn delivery_proof(&self) -> Option<DeliveryProof> {
        (self.pool == POOL_IRONWOOD).then_some(DeliveryProof { txid: self.txid, pool: Pool::Ironwood, action: self.action, receiver: self.receiver, value: self.value, rseed: self.rseed })
    }
}

/// One published exit key (the parameter file's `zcash.exitKeys`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitKey {
    pub account: u8,
    pub pubkey: [u8; ACCOUNT_PUBKEY_LEN],
    pub from_height: u32,
    pub to_height: Option<u32>,
}

/// The network and the published exit keys of a parameter file.
pub fn exit_keys_from_params(json: &str) -> Result<(NetworkType, Vec<ExitKey>), String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|_| "the parameter file is not JSON")?;
    let net = match v["zcash"]["network"].as_str() {
        Some("mainnet") => NetworkType::Main,
        Some("testnet") => NetworkType::Test,
        _ => return Err("the parameter file has no zcash.network".into()),
    };
    let list = v["zcash"]["exitKeys"].as_array().ok_or("the parameter file has no zcash.exitKeys")?;
    let height = |x: &serde_json::Value| x.as_u64().and_then(|h| u32::try_from(h).ok());
    let keys = list
        .iter()
        .map(|k| {
            Ok(ExitKey {
                account: k["account"].as_u64().and_then(|a| u8::try_from(a).ok()).ok_or("an exit key's account is not 0 to 255")?,
                pubkey: parse_account_pubkey(k["pubkey"].as_str().ok_or("an exit key has no pubkey")?)?,
                from_height: height(&k["fromHeight"]).ok_or("an exit key has no fromHeight")?,
                to_height: if k["toHeight"].is_null() { None } else { Some(height(&k["toHeight"]).ok_or("an exit key's toHeight is not a height")?) },
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    if keys.is_empty() {
        return Err("the parameter file names no exit key".into());
    }
    Ok((net, keys))
}

/// What a checked proof shows.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayoutShown {
    /// the payout stamp's txid, displayed (byte-reversed) hex
    pub txid: String,
    /// the receiver as an Ironwood/Orchard-only unified address
    pub address: String,
    pub value: u64,
    pub receipt: PayoutReceipt,
    pub account: u8,
    pub index: u32,
    /// the order address's public key hash (P2PKH)
    pub order_key_hash: String,
    /// the published exit key (130 hex) whose order address paid the note
    pub exit_key: String,
    /// how many exits the record names, and which one is this receipt's (0-based)
    pub exits: usize,
    pub position: usize,
    /// how many inputs the order address spends
    pub order_inputs: usize,
    /// the transaction's wtxid (ZIP 239: txid then authorizing-data digest, internal byte order): the exact
    /// bytes checked, signatures included
    pub wtxid: String,
    /// whether every input's signature was verified (needs the spent coins' values), and the receipt's
    /// `bridged` checked against the order address's coins
    pub inputs_verified: bool,
    pub checked: Vec<String>,
    pub not_checked: Vec<String>,
}

/// What an offline check cannot establish, said with every result.
pub const NOT_CHECKED_OFFLINE: [&str; 3] = [
    "that these bytes are the mined transaction: a txid does not cover signatures, so a mined txid does not vouch for these inputs; compare the wtxid with a node you trust, or use the verifier's check-proof",
    "that the exit key was valid at the transaction's height (the height is not known offline)",
    "that the receipt's exit is the Solana transaction it names, with this order index, this amount sent and this time (Solana is not read offline)",
];

/// Said when the inputs' signatures were not verified.
pub const INPUTS_NOT_VERIFIED: &str = "THE ORDER ADDRESS: the inputs name the order address's key, but their signatures were NOT verified, so the payer is only what these bytes claim (anyone can put a public key in a scriptSig without changing the txid), and the receipt's bridged amount was not checked against the coins spent. Give the spent coins' values to verify both, or use the verifier's check-proof or the payout's page on the site";

fn input_keys(t: &Transaction) -> Result<Vec<[u8; 33]>, String> {
    let tb = t.transparent_bundle().ok_or("the transaction has no transparent part")?;
    tb.vin
        .iter()
        .map(|i| {
            let (_, key) = sig::pushes(&i.script_sig().0 .0).ok_or("an input is not a P2PKH spend (a signature and a compressed key)")?;
            Ok(key.try_into().expect("33 bytes"))
        })
        .collect()
}

/// A payout stamp's shape (SPEC.md §10.2), read from the transaction's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutShape {
    /// the version 3 record's exit hashes, in order
    pub hashes: Vec<[u8; RECORD_V3_HASH_LEN]>,
    /// each input's public key, in order
    pub input_keys: Vec<[u8; 33]>,
    /// the inputs in runs of one key: run `j` is exit `j`'s order address (its key, and its inputs' positions)
    pub runs: Vec<([u8; 33], Vec<usize>)>,
    /// zatoshi into the Ironwood pool (the sum of the notes)
    pub into_pool: u64,
    pub actions: usize,
}

/// Reads a transaction as a payout stamp (its shape only: no key, no note).
pub fn shape(tx: &[u8]) -> Result<PayoutShape, String> {
    shape_of(&read_tx(tx)?)
}

/// Verifies every input's SIGHASH_ALL signature (ZIP 244) with the key it names, given the values of the
/// coins the inputs spend, in order.
pub fn verify_inputs(tx: &[u8], spent_values: &[u64]) -> Result<(), String> {
    sig::verify(&read_tx(tx)?, spent_values)
}

/// The shape of a payout stamp (SPEC.md §10.2), as far as the bytes show it: no Sapling, Sprout or Orchard
/// part; value into the Ironwood pool, in at least as many actions as exits; one transparent output, the
/// version 3 record (each exit once); every input a P2PKH spend, the inputs in one run per exit, in the
/// record's order, each run a different key.
fn shape_of(t: &Transaction) -> Result<PayoutShape, String> {
    if t.sapling_bundle().is_some() || t.sprout_bundle().is_some() || t.orchard_bundle().is_some() {
        return Err("the transaction has a Sapling, Sprout or Orchard part: not a payout stamp".into());
    }
    let iw = t.ironwood_bundle().ok_or("the transaction has no Ironwood part: not a payout stamp")?;
    if i64::from(*iw.value_balance()) >= 0 {
        return Err("the transaction puts nothing into the Ironwood pool".into());
    }
    let tb = t.transparent_bundle().ok_or("the transaction has no transparent part")?;
    if tb.vout.len() != 1 {
        return Err(format!("a payout stamp has one transparent output, the record; this transaction has {}", tb.vout.len()));
    }
    let hashes = parse_v3_script(&tb.vout[0].script_pubkey().0 .0).ok_or("the transparent output is not a version 3 record")?;
    if (1..hashes.len()).any(|i| hashes[..i].contains(&hashes[i])) {
        return Err("the record names one exit twice".into());
    }
    if hashes.len() > iw.actions().len() {
        return Err("the record names more exits than the Ironwood part has actions".into());
    }
    let keys = input_keys(t)?;
    let mut runs: Vec<([u8; 33], Vec<usize>)> = Vec::new();
    for (i, k) in keys.iter().enumerate() {
        match runs.last_mut() {
            Some((last, at)) if last == k => at.push(i),
            _ => {
                if runs.iter().any(|(r, _)| r == k) {
                    return Err("one key's inputs are not in one run: not a payout stamp's inputs".into());
                }
                runs.push((*k, vec![i]));
            }
        }
    }
    if runs.len() != hashes.len() {
        return Err(format!("the inputs come from {} keys, but the record names {} exits", runs.len(), hashes.len()));
    }
    Ok(PayoutShape { hashes, input_keys: keys, runs, into_pool: i64::from(*iw.value_balance()).unsigned_abs(), actions: iw.actions().len() })
}

/// Checks a payout stamp proof against the transaction's bytes. `network` only chooses the address encoding.
///
/// `keys`: the published exit keys (the parameter file's `zcash.exitKeys`); the proof's account selects
/// among them. The check fails unless the transaction has a payout stamp's shape, the note's memo is a
/// receipt naming exit `j` of the record, for this note's value, and the inputs of run `j` are spent by the
/// proof's order address under one of the account's keys.
///
/// `spent_values`: the values (zatoshi) of the coins the inputs spend, in order. With them, every input's
/// signature is verified against the key it names (ZIP 244), and the receipt's `bridged` must equal the
/// order address's coins; a wrong value can only make a genuine stamp fail. Without them, the result says
/// both were NOT verified.
pub fn check(tx: &[u8], proof: &PayoutProof, network: NetworkType, keys: &[ExitKey], spent_values: Option<&[u64]>) -> Result<PayoutShown, String> {
    let ours: Vec<&ExitKey> = keys.iter().filter(|k| k.account == proof.account).collect();
    if ours.is_empty() {
        return Err(format!("no published exit key for account {}: nothing would show who paid this note", proof.account));
    }
    let t = read_tx(tx)?;
    if t.txid().as_ref() != &proof.txid {
        return Err("the transaction is not the one the proof names".into());
    }
    if proof.pool != POOL_IRONWOOD {
        return Err("the proof names a pool other than Ironwood".into());
    }
    let s = shape_of(&t)?;
    if let Some(values) = spent_values {
        sig::verify(&t, values)?;
    }
    let delivery = zcash_delivery_proof::check(tx, &proof.delivery_proof().expect("an Ironwood proof")).map_err(|e| e.to_string())?;
    let receipt = PayoutReceipt::parse(&delivery.memo)?;
    if receipt.received != proof.value {
        return Err("the receipt's received amount is not this note's value".into());
    }
    let mine = exit_hash(&solana_signature(&receipt.signature)?);
    let position = s.hashes.iter().position(|h| *h == mine).ok_or("the receipt's exit is not one the record names")?;
    // the run of inputs for this exit: its key must be the proof's order address under a published key
    let (run_key, order_inputs) = &s.runs[position];
    let mut key = None;
    for k in &ours {
        if order_pubkey(&k.pubkey, proof.index)? == *run_key {
            key = Some(*k);
            break;
        }
    }
    let key = key.ok_or_else(|| format!("the inputs for this exit are not spent by order {}'s address of the published exit key for account {}", proof.index, proof.account))?;
    if let Some(values) = spent_values {
        let bridged: u64 = order_inputs.iter().map(|i| values[*i]).sum();
        if bridged != receipt.bridged {
            return Err(format!("the receipt says {} zatoshi were bridged, but the order address's coins hold {bridged}", receipt.bridged));
        }
    }
    let order_pk = *run_key;
    let hashes = s.hashes;
    let mut shown = proof.txid;
    shown.reverse();
    let mut checked = vec![
        "the transaction's own txid is the proof's".to_string(),
        "it has a payout stamp's shape: one transparent output, the version 3 record; no Sapling, Sprout or Orchard part; value into the Ironwood pool".to_string(),
        format!("{} of its inputs spend order {}'s address of the published exit key for account {}", order_inputs.len(), proof.index, proof.account),
    ];
    if spent_values.is_some() {
        checked.push("every input's signature verifies with the key it names (ZIP 244, with the spent coins' values given)".into());
        checked.push("the receipt's bridged amount is what the order address's coins hold".into());
    }
    checked.push(format!("the named action delivers exactly this {}-zatoshi note to this receiver (its esk, epk and note commitment)", proof.value));
    checked.push("the note's memo is a version 3 receipt, for this note's value, and its exit is one the record names".into());
    let mut not_checked: Vec<String> = NOT_CHECKED_OFFLINE.iter().map(|s| s.to_string()).collect();
    if spent_values.is_none() {
        not_checked.insert(0, INPUTS_NOT_VERIFIED.to_string());
    }
    Ok(PayoutShown {
        txid: hex::encode(shown),
        address: receiver_address(&proof.receiver, network),
        value: proof.value,
        receipt,
        account: proof.account,
        index: proof.index,
        order_key_hash: hex::encode(crate::address::hash160(&order_pk)),
        exit_key: hex::encode(key.pubkey),
        exits: hashes.len(),
        position,
        order_inputs: order_inputs.len(),
        wtxid: hex::encode(delivery.wtxid),
        inputs_verified: spent_values.is_some(),
        checked,
        not_checked,
    })
}

/// Makes a payout stamp proof for the note in `tx` that one of `keys` can decrypt and whose memo is a
/// version 3 receipt. `account` and `index` are the exit's (its Solana memo names the index).
pub fn make(tx: &[u8], keys: &[IncomingViewingKey], account: u8, index: u32) -> Result<PayoutProof, String> {
    if index > MAX_INDEX {
        return Err("the order index is not below 2^31".into());
    }
    let t = read_tx(tx)?;
    t.ironwood_bundle().ok_or("the transaction has no Ironwood part")?;
    let keys = ViewingKeys { network: NetworkType::Main, incoming: keys.to_vec(), outgoing: vec![] };
    let found = zcash_delivery_proof::make(tx, &keys).map_err(|e| e.to_string())?;
    let f = found
        .into_iter()
        .find(|f| f.proof.pool == Pool::Ironwood && PayoutReceipt::parse(&f.memo).is_ok())
        .ok_or("none of these keys receives a payout note (a note with a version 3 receipt) in this transaction")?;
    let p = f.proof;
    Ok(PayoutProof { txid: p.txid, pool: POOL_IRONWOOD, action: p.action, receiver: p.receiver, value: p.value, rseed: p.rseed, account, index })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes() {
        let p = PayoutProof { txid: [1; 32], pool: 2, action: 3, receiver: [4; 43], value: 5, rseed: [6; 32], account: 1, index: MAX_INDEX };
        let s = p.encode();
        assert_eq!(s.len(), PREFIX.len() + 164);
        assert_eq!(PayoutProof::decode(&s).unwrap(), p);
        assert!(PayoutProof::decode(&s.replace("splg-proof:2:", "splg-proof:1:")).is_err());
        let mut b = p.to_bytes();
        b[122] = 0x80; // index 2^31 or more
        assert!(PayoutProof::decode(&format!("{PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))).is_err());
        assert!(PayoutProof::decode(&format!("{PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&b[..122]))).is_err());
    }

    #[test]
    fn reads_exit_keys_from_params() {
        let k = format!("{}02{}", "11".repeat(32), "22".repeat(32));
        let json = format!(r#"{{"zcash":{{"network":"testnet","exitKeys":[{{"account":0,"pubkey":"{k}","fromHeight":5}},{{"account":1,"pubkey":"{k}","fromHeight":6,"toHeight":9}}]}}}}"#);
        let (net, keys) = exit_keys_from_params(&json).unwrap();
        assert_eq!(net, NetworkType::Test);
        assert_eq!((keys[0].account, keys[0].from_height, keys[0].to_height), (0, 5, None));
        assert_eq!((keys[1].account, keys[1].to_height), (1, Some(9)));
        assert!(exit_keys_from_params(r#"{"zcash":{"network":"mainnet","exitKeys":[]}}"#).is_err());
        assert!(exit_keys_from_params(r#"{"zcash":{"network":"mainnet"}}"#).is_err());
    }
}
