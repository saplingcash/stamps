//! Stamp proofs (SPEC.md §9.6, §10.5) and transaction inspection as WebAssembly, for the verifier (Node) and
//! for checking or making a proof in a browser. A viewing key given to `make` stays in the page's
//! memory: nothing here does any I/O.

use stamper_core::payout::proof as payout;
use stamper_core::private::proof::{check as check_proof, inspect as inspect_tx, issuers_from_params, make as make_proof, viewing_keys, Proof};
use wasm_bindgen::prelude::*;

/// Where this module comes from, in a custom section of the WebAssembly binary named "sapling.cash"
/// (`wasm-objdump -j sapling.cash -s` shows it). Plain text; nothing reads it at run time.
#[used]
#[link_section = "sapling.cash"]
static ORIGIN: [u8; 94] = *b"Sapling stamp proofs, from https://sapling.cash; source: https://github.com/saplingcash/stamps";

fn bytes(tx_hex: &str) -> Result<Vec<u8>, JsError> {
    hex::decode(tx_hex.trim()).map_err(|_| JsError::new("the transaction must be hex"))
}

/// The transaction as the stamp rules read it, as JSON (txid computed here).
#[wasm_bindgen]
pub fn inspect(tx_hex: &str) -> Result<String, JsError> {
    let t = inspect_tx(&bytes(tx_hex)?).map_err(|e| JsError::new(&e))?;
    serde_json::to_string(&t).map_err(|e| JsError::new(&e.to_string()))
}

/// Checks a stamp proof against the stamp transaction and the parameter file (JSON text, which names the
/// published issuers); returns what it shows, what was checked and what was not, as JSON.
/// `spent_values`: the values of the coins the inputs spend, comma-separated zatoshi ("" = not given: the
/// issuer's signatures are then NOT verified, and the result says so).
#[wasm_bindgen]
pub fn check(tx_hex: &str, proof: &str, params_json: &str, spent_values: &str) -> Result<String, JsError> {
    let p = Proof::decode(proof).map_err(|e| JsError::new(&e))?;
    let (net, issuers) = issuers_from_params(params_json).map_err(|e| JsError::new(&e))?;
    let values = if spent_values.trim().is_empty() { None } else { Some(spent_values.split(',').map(|v| v.trim().parse::<u64>().map_err(|_| JsError::new("spent values are zatoshi amounts, comma-separated"))).collect::<Result<Vec<_>, _>>()?) };
    let shown = check_proof(&bytes(tx_hex)?, &p, net, &issuers, values.as_deref()).map_err(|e| JsError::new(&e))?;
    serde_json::to_string(&shown).map_err(|e| JsError::new(&e.to_string()))
}

/// Makes a stamp proof from a UFVK or UIVK and the stamp transaction.
#[wasm_bindgen]
pub fn make(tx_hex: &str, viewing_key: &str) -> Result<String, JsError> {
    let (_, keys) = viewing_keys(viewing_key).map_err(|e| JsError::new(&e))?;
    Ok(make_proof(&bytes(tx_hex)?, &keys).map_err(|e| JsError::new(&e))?.encode())
}

fn values(spent_values: &str) -> Result<Option<Vec<u64>>, JsError> {
    if spent_values.trim().is_empty() {
        return Ok(None);
    }
    spent_values.split(',').map(|v| v.trim().parse::<u64>().map_err(|_| JsError::new("spent values are zatoshi amounts, comma-separated"))).collect::<Result<Vec<_>, _>>().map(Some)
}

/// Checks a payout stamp proof (`splg-proof:2`, SPEC.md §10.5) against the transaction and the parameter file
/// (JSON text, which names the published exit keys); returns what it shows, what was checked and what was
/// not, as JSON. `spent_values` as for `check`: without them the order address's signatures and the
/// receipt's bridged amount are NOT verified, and the result says so.
#[wasm_bindgen]
pub fn check_payout(tx_hex: &str, proof: &str, params_json: &str, spent_values: &str) -> Result<String, JsError> {
    let p = payout::PayoutProof::decode(proof).map_err(|e| JsError::new(&e))?;
    let (net, keys) = payout::exit_keys_from_params(params_json).map_err(|e| JsError::new(&e))?;
    let shown = payout::check(&bytes(tx_hex)?, &p, net, &keys, values(spent_values)?.as_deref()).map_err(|e| JsError::new(&e))?;
    serde_json::to_string(&shown).map_err(|e| JsError::new(&e.to_string()))
}

/// Makes a payout stamp proof from a UFVK or UIVK, the transaction, and the exit's account and order index.
#[wasm_bindgen]
pub fn make_payout(tx_hex: &str, viewing_key: &str, account: u8, index: u32) -> Result<String, JsError> {
    let (_, keys) = viewing_keys(viewing_key).map_err(|e| JsError::new(&e))?;
    Ok(payout::make(&bytes(tx_hex)?, &keys, account, index).map_err(|e| JsError::new(&e))?.encode())
}
