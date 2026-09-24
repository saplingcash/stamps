//! Building a stamp (or a UTXO split) from explicit inputs and outputs: strict checks, the ZIP 317
//! fee, change, and SIGHASH_ALL signatures from the issuer key.

use serde::{Deserialize, Serialize};

use crate::address::{p2pkh_script, script_kind, ScriptKind};
use crate::key::IssuerKey;
use crate::tx::{OutPoint, SpentCoin, Tx, TxIn, TxOut, SIGHASH_ALL};

/// ZIP 317 constants.
pub const GRACE_ACTIONS: u64 = 2;
pub const P2PKH_STANDARD_INPUT_SIZE: usize = 150;
pub const P2PKH_STANDARD_OUTPUT_SIZE: usize = 34;
/// Outputs below this are dust for Zebra's relay rules (P2PKH: 54 zat); change below it is dropped.
pub const DUST: u64 = 54;
/// The largest OP_RETURN script Zebra relays by default.
pub const MAX_OP_RETURN_SCRIPT: usize = 83;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Utxo {
    /// displayed (byte-reversed) hex, as nodes report it
    pub txid: String,
    pub vout: u32,
    pub value: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Output {
    pub value: u64,
    pub script: String,
}

/// What to build. The consensus branch comes from the node at build time.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildRequest {
    pub consensus_branch_id: u32,
    pub expiry_height: u32,
    /// zatoshi per logical action (ZIP 317 marginal fee)
    pub marginal_fee: u64,
    pub inputs: Vec<Utxo>,
    pub outputs: Vec<Output>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Built {
    pub txid: String,
    pub hex: String,
    pub fee: u64,
    pub change: u64,
    pub logical_actions: u64,
}

fn output_size(script_len: usize) -> usize {
    let cs = if script_len < 0xfd { 1 } else { 3 };
    8 + cs + script_len
}

/// ZIP 317: marginal_fee × max(grace_actions, max(⌈in/150⌉, ⌈out/34⌉)) for a transparent-only tx.
pub fn zip317_fee(n_inputs: usize, output_scripts: &[usize], marginal_fee: u64) -> (u64, u64) {
    let in_size = n_inputs * P2PKH_STANDARD_INPUT_SIZE;
    let out_size: usize = output_scripts.iter().map(|l| output_size(*l)).sum();
    let actions = (in_size.div_ceil(P2PKH_STANDARD_INPUT_SIZE)).max(out_size.div_ceil(P2PKH_STANDARD_OUTPUT_SIZE)) as u64;
    let logical = actions.max(GRACE_ACTIONS);
    (marginal_fee * logical, logical)
}

fn txid_bytes(display_hex: &str) -> Result<[u8; 32], String> {
    let mut b: [u8; 32] = hex::decode(display_hex).map_err(|_| "input txid is not hex")?.try_into().map_err(|_| "input txid must be 32 bytes")?;
    b.reverse();
    Ok(b)
}

/// Builds and signs. Every input is a P2PKH coin of the issuer key; change returns to that key.
pub fn build(key: &IssuerKey, req: &BuildRequest) -> Result<Built, String> {
    if req.inputs.is_empty() {
        return Err("no inputs".into());
    }
    if req.marginal_fee == 0 {
        return Err("marginal fee must be positive".into());
    }
    let mut outputs = Vec::new();
    let mut op_returns = 0;
    for o in &req.outputs {
        let script = hex::decode(&o.script).map_err(|_| "output script is not hex")?;
        match script_kind(&script) {
            ScriptKind::P2pkh | ScriptKind::P2sh => {
                if o.value < DUST {
                    return Err(format!("output of {} zat is dust", o.value));
                }
            }
            ScriptKind::OpReturn => {
                op_returns += 1;
                if o.value != 0 || script.len() > MAX_OP_RETURN_SCRIPT {
                    return Err("an OP_RETURN must carry 0 zat and at most 83 script bytes".into());
                }
            }
            ScriptKind::Other => return Err("only P2PKH, P2SH and OP_RETURN outputs are built".into()),
        }
        outputs.push(TxOut { value: o.value, script });
    }
    if op_returns > 1 {
        return Err("at most one OP_RETURN per transaction (Zebra relay rule)".into());
    }
    let total_in: u64 = req.inputs.iter().map(|u| u.value).sum();
    let total_out: u64 = outputs.iter().map(|o| o.value).sum();
    let change_script = p2pkh_script(&key.pubkey_hash());
    let mut scripts: Vec<usize> = outputs.iter().map(|o| o.script.len()).collect();

    // with a change output first; without it if the change would be dust
    scripts.push(change_script.len());
    let (fee_with, actions_with) = zip317_fee(req.inputs.len(), &scripts, req.marginal_fee);
    scripts.pop();
    let (fee_without, actions_without) = zip317_fee(req.inputs.len(), &scripts, req.marginal_fee);
    let (fee, logical, change) = match total_in.checked_sub(total_out + fee_with) {
        Some(c) if c >= DUST => (fee_with, actions_with, c),
        _ => {
            let spare = total_in.checked_sub(total_out + fee_without).ok_or_else(|| format!("inputs of {total_in} zat do not cover outputs of {total_out} and the fee of {fee_without}"))?;
            (fee_without + spare, actions_without, 0)
        }
    };
    if change > 0 {
        outputs.push(TxOut { value: change, script: change_script.clone() });
    }

    let mut tx = Tx { consensus_branch_id: req.consensus_branch_id, lock_time: 0, expiry_height: req.expiry_height, inputs: Vec::new(), outputs };
    for u in &req.inputs {
        tx.inputs.push(TxIn { prevout: OutPoint { txid: txid_bytes(&u.txid)?, index: u.vout }, script_sig: Vec::new(), sequence: 0xffff_ffff });
    }
    let spent: Vec<SpentCoin> = req.inputs.iter().map(|u| SpentCoin { value: u.value, script: change_script.clone() }).collect();
    let pubkey = key.public_key();
    for i in 0..tx.inputs.len() {
        let digest = tx.sighash_all(i, &spent);
        let sig = key.sign_digest(&digest, SIGHASH_ALL);
        let mut ss = Vec::with_capacity(sig.len() + 35);
        ss.push(sig.len() as u8);
        ss.extend_from_slice(&sig);
        ss.push(pubkey.len() as u8);
        ss.extend_from_slice(&pubkey);
        tx.inputs[i].script_sig = ss;
    }
    Ok(Built { txid: tx.txid_hex(), hex: hex::encode(tx.serialize()), fee, change, logical_actions: logical })
}
