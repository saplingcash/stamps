//! Building a private stamp (SPEC.md §9.4) with librustzcash's own transaction builder:
//!
//! - one issuer coin in (P2PKH, signed with the issuer key);
//! - the version 2 record (OP_RETURN, 23 bytes) and change back to the issuer;
//! - one Ironwood output of 546 zatoshi to the receiver opened from the seal, with the receipt as
//!   its memo and no outgoing viewing key, padded to two actions.
//!
//! Since NU6.3 the Orchard pool refuses outputs to anyone but the spender's own address (the
//! cross-address restriction), so a payment to someone else's Orchard receiver goes to the Ironwood
//! pool, in a v6 transaction. The receiver never leaves this module: the result holds only the
//! transaction, in which it is encrypted.

use base64::Engine;
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::TxVersion;
use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork, NetworkType, Parameters, TestNetwork};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::builder::TransparentSigningSet;
use zcash_transparent::bundle::{OutPoint, TxOut};

use super::memo::Receipt;
use super::seal::RequestKey;
use super::{POSTAGE, UNDELIVERABLE};
use crate::address::Network;
use crate::build::{Built, Utxo, DUST, GRACE_ACTIONS, P2PKH_STANDARD_INPUT_SIZE, P2PKH_STANDARD_OUTPUT_SIZE};
use crate::key::IssuerKey;
use crate::record::{record_v2, solana_signature};

/// The sealed receiver, as the harvest's memo carries it.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Sealed {
    /// the request key's id
    pub kid: u8,
    /// 92 bytes, base64url without padding
    pub sealed: String,
    /// the harvesting wallet (the redeem's account #0), base58
    pub holder: String,
}

/// What to build. The branch comes from the node; it must match librustzcash's for `target_height`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateRequest {
    pub network: Network,
    pub consensus_branch_id: u32,
    /// the height the transaction is built for (the tip + 1)
    pub target_height: u32,
    pub expiry_height: u32,
    pub marginal_fee: u64,
    pub input: Utxo,
    pub receipt: Receipt,
    pub sealed: Sealed,
    /// the Ironwood anchor, hex (32 bytes); absent = the empty tree's root
    #[serde(default)]
    pub anchor: Option<String>,
}

/// The ZIP 317 fee rule for a marginal fee (the standard rule at 5,000 zat an action).
fn fee_rule(marginal_fee: u64) -> Result<FeeRule, String> {
    let fee = Zatoshis::from_u64(marginal_fee).map_err(|_| "bad marginal fee")?;
    FeeRule::non_standard(fee, GRACE_ACTIONS as usize, P2PKH_STANDARD_INPUT_SIZE, P2PKH_STANDARD_OUTPUT_SIZE).ok_or_else(|| "bad fee rule".into())
}

fn decode_sealed(s: &Sealed) -> Result<(u8, [u8; 32], Vec<u8>), String> {
    let holder: [u8; 32] = bs58::decode(&s.holder).into_vec().ok().and_then(|v| v.try_into().ok()).ok_or("the holder is not a base58 public key")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&s.sealed).map_err(|_| UNDELIVERABLE.to_string())?;
    Ok((s.kid, holder, bytes))
}

/// Opens the seal and checks the receiver is a valid shielded (Orchard-family) address.
pub fn open_receiver(request_key: &RequestKey, sealed: &Sealed) -> Result<orchard::Address, String> {
    let (kid, holder, bytes) = decode_sealed(sealed)?;
    let raw = request_key.open(kid, &holder, &bytes)?;
    Option::from(orchard::Address::from_raw_address_bytes(&raw)).ok_or_else(|| UNDELIVERABLE.to_string())
}

fn txid_bytes(display_hex: &str) -> Result<[u8; 32], String> {
    let mut b: [u8; 32] = hex::decode(display_hex).map_err(|_| "input txid is not hex")?.try_into().map_err(|_| "input txid must be 32 bytes")?;
    b.reverse();
    Ok(b)
}

fn builder_for<P: Parameters>(params: P, req: &PrivateRequest, anchor: orchard::Anchor) -> Result<Builder<P, ()>, String> {
    let height = BlockHeight::from_u32(req.target_height);
    let branch = BranchId::for_height(&params, height);
    if u32::from(branch) != req.consensus_branch_id {
        return Err(format!("the node's branch {:#010x} is not librustzcash's {:#010x} at height {}", req.consensus_branch_id, u32::from(branch), req.target_height));
    }
    if TxVersion::suggested_for_branch(branch) != TxVersion::V6 {
        return Err("private stamps need the Ironwood pool (NU6.3 or later)".into());
    }
    let config = BuildConfig::Standard { sapling_anchor: None, orchard_anchor: None, ironwood_anchor: Some(anchor), orchard_padding: BundlePadding::DEFAULT, ironwood_padding: BundlePadding::DEFAULT };
    Ok(Builder::new(params, height, config).with_expiry_height(BlockHeight::from_u32(req.expiry_height)))
}

/// Builds, proves and signs a private stamp.
pub fn build_private(issuer: &IssuerKey, request_key: &RequestKey, req: &PrivateRequest) -> Result<Built, String> {
    build_private_with_rng(issuer, request_key, req, OsRng)
}

pub fn build_private_with_rng<R: RngCore + CryptoRng>(issuer: &IssuerKey, request_key: &RequestKey, req: &PrivateRequest, rng: R) -> Result<Built, String> {
    match req.network {
        Network::Mainnet => build_on(MainNetwork, issuer, request_key, req, rng),
        Network::Testnet => build_on(TestNetwork, issuer, request_key, req, rng),
    }
}

fn build_on<P: Parameters + Clone, R: RngCore + CryptoRng>(params: P, issuer: &IssuerKey, request_key: &RequestKey, req: &PrivateRequest, rng: R) -> Result<Built, String> {
    debug_assert!(matches!((req.network, params.network_type()), (Network::Mainnet, NetworkType::Main) | (Network::Testnet, NetworkType::Test)));
    if req.marginal_fee == 0 {
        return Err("marginal fee must be positive".into());
    }
    if req.expiry_height <= req.target_height {
        return Err("the expiry height must be above the target height".into());
    }
    // a fee above the harvested amount leaves nothing to receive: the public rules call such a request
    // undeliverable (SPEC.md §9.1), and it is refunded, never stamped
    if req.receipt.fee > req.receipt.harvested {
        return Err(UNDELIVERABLE.into());
    }
    let memo = req.receipt.memo()?;
    let sig = solana_signature(&req.receipt.signature)?;
    let record = record_v2(&sig);
    let anchor = match &req.anchor {
        None => orchard::Anchor::empty_tree(),
        Some(h) => {
            let b: [u8; 32] = hex::decode(h).ok().and_then(|v| v.try_into().ok()).ok_or("the anchor must be 32 bytes of hex")?;
            Option::from(orchard::Anchor::from_bytes(b)).ok_or("the anchor is not a valid tree root")?
        }
    };
    // the receiver is opened last, after every other check, and only ever held here
    let receiver = open_receiver(request_key, &req.sealed)?;

    let mut signing = TransparentSigningSet::new();
    let sk = secp256k1::SecretKey::from_slice(issuer.secret_bytes().as_ref()).map_err(|_| "the issuer key is not a valid secp256k1 key")?;
    let pubkey = signing.add_key(sk);
    let issuer_addr = TransparentAddress::PublicKeyHash(issuer.pubkey_hash());
    let coin_value = Zatoshis::from_u64(req.input.value).map_err(|_| "bad input value")?;
    let outpoint = OutPoint::new(txid_bytes(&req.input.txid)?, req.input.vout);
    let coin = TxOut::new(coin_value, issuer_addr.script().into());
    let postage = Zatoshis::from_u64(POSTAGE).expect("546 zat");
    let memo_bytes = MemoBytes::from_bytes(&memo).map_err(|_| "bad memo")?;
    let rule = fee_rule(req.marginal_fee)?;

    // the same builder twice: first to learn the fee with a change output, then for real
    let assemble = |change: Zatoshis| -> Result<Builder<P, ()>, String> {
        let mut b = builder_for(params.clone(), req, anchor)?;
        b.add_transparent_p2pkh_input(pubkey, outpoint.clone(), coin.clone()).map_err(|e| format!("input: {e:?}"))?;
        b.add_transparent_null_data_output::<std::convert::Infallible>(&record).map_err(|e| format!("record: {e:?}"))?;
        b.add_transparent_output(&issuer_addr, change).map_err(|e| format!("change: {e:?}"))?;
        b.add_ironwood_output::<std::convert::Infallible>(None, receiver, postage, memo_bytes.clone()).map_err(|_| UNDELIVERABLE.to_string())?;
        Ok(b)
    };
    let fee = assemble(Zatoshis::from_u64(DUST).expect("dust"))?.get_fee(&rule).map_err(|e| format!("fee: {e:?}"))?;
    let fee_u64 = u64::from(fee);
    let change = req.input.value.checked_sub(POSTAGE + fee_u64).filter(|c| *c >= DUST).ok_or_else(|| format!("a coin of {} zat does not cover the postage, the fee of {fee_u64} and change", req.input.value))?;
    let builder = assemble(Zatoshis::from_u64(change).expect("change"))?;
    let result = builder.build(&signing, &[], &[], rng, &NoSapling, &NoSapling, &rule).map_err(|e| format!("build: {e:?}"))?;
    let tx = result.transaction();
    if tx.version() != TxVersion::V6 {
        return Err("librustzcash did not build a v6 transaction".into());
    }
    let mut bytes = Vec::new();
    tx.write(&mut bytes).map_err(|e| e.to_string())?;
    let mut shown = *tx.txid().as_ref();
    shown.reverse();
    // every private stamp has the same shape (SPEC.md §9.4): 2 Ironwood actions, 4 logical actions; a
    // change in librustzcash's padding or fee counting must stop here, not quietly change the cost
    let actions = tx.ironwood_bundle().map(|b| b.actions().len()).unwrap_or(0);
    if actions != 2 || fee_u64 != 4 * req.marginal_fee {
        return Err(format!("unexpected shape: {actions} Ironwood actions, fee {fee_u64} (expected 2 and {})", 4 * req.marginal_fee));
    }
    Ok(Built { txid: hex::encode(shown), hex: hex::encode(bytes), fee: fee_u64, change, logical_actions: 4 })
}

/// The builder's signature asks for Sapling provers; a private stamp has no Sapling part, so these
/// are never called.
pub struct NoSapling;

impl sapling::prover::SpendProver for NoSapling {
    type Proof = sapling::bundle::GrothProofBytes;
    #[allow(clippy::too_many_arguments)]
    fn prepare_circuit(
        _: sapling::ProofGenerationKey,
        _: sapling::Diversifier,
        _: sapling::Rseed,
        _: sapling::value::NoteValue,
        _: jubjub::Fr,
        _: sapling::value::ValueCommitTrapdoor,
        _: bls12_381::Scalar,
        _: sapling::MerklePath,
    ) -> Option<sapling::circuit::Spend> {
        None
    }
    fn create_proof<R: RngCore>(&self, _: sapling::circuit::Spend, _: &mut R) -> Self::Proof {
        unreachable!("a private stamp has no Sapling spends")
    }
    fn encode_proof(p: Self::Proof) -> sapling::bundle::GrothProofBytes {
        p
    }
}

impl sapling::prover::OutputProver for NoSapling {
    type Proof = sapling::bundle::GrothProofBytes;
    fn prepare_circuit(
        _: &sapling::keys::EphemeralSecretKey,
        _: sapling::PaymentAddress,
        _: jubjub::Fr,
        _: sapling::value::NoteValue,
        _: sapling::value::ValueCommitTrapdoor,
    ) -> sapling::circuit::Output {
        unreachable!("a private stamp has no Sapling outputs")
    }
    fn create_proof<R: RngCore>(&self, _: sapling::circuit::Output, _: &mut R) -> Self::Proof {
        unreachable!("a private stamp has no Sapling outputs")
    }
    fn encode_proof(p: Self::Proof) -> sapling::bundle::GrothProofBytes {
        p
    }
}

#[derive(Serialize)]
pub struct KeyInfo {
    pub kid: u8,
    pub x25519: String,
}
