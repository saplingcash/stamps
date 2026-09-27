//! Stamp proofs (SPEC.md §9.6) and transaction inspection as WebAssembly, for the verifier (Node) and
//! for checking or making a proof in a browser. A viewing key given to `make` stays in the page's
//! memory: nothing here does any I/O.

use stamper_core::private::proof::{check as check_proof, inspect as inspect_tx, issuers_from_params, make as make_proof, viewing_keys, Proof};
use wasm_bindgen::prelude::*;

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
