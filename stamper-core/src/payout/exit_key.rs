//! Order addresses (SPEC.md §10.1): an exit's ZEC is paid to, and its payout stamp spent from, a
//! transparent address of its own, the external child `0/<order index>` of a published exit account public
//! key (65 bytes: the chain code, then the compressed secp256k1 key). That is BIP32 public derivation, as
//! ZIP 32 uses it for transparent addresses (BIP44 `m/44'/133'/<account>'/0/<index>`), so anyone can derive
//! every order address from the published key alone.

use hmac::{Hmac, Mac};
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};
use sha2::Sha512;

use crate::address::hash160;

pub const ACCOUNT_PUBKEY_LEN: usize = 65;
/// order indexes are non-hardened: below 2^31
pub const MAX_INDEX: u32 = (1 << 31) - 1;

/// BIP32 public child derivation (non-hardened): the child's compressed key and chain code.
fn child(key: &[u8; 33], chain_code: &[u8; 32], index: u32) -> Result<([u8; 33], [u8; 32]), String> {
    if index > MAX_INDEX {
        return Err(format!("the index {index} is not below 2^31"));
    }
    let mut mac = Hmac::<Sha512>::new_from_slice(chain_code).expect("any key length");
    mac.update(key);
    mac.update(&index.to_be_bytes());
    let i = mac.finalize().into_bytes();
    let il = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::clone_from_slice(&i[..32]))).filter(|s| !bool::from(s.is_zero())).ok_or("an invalid child key (BIP32: the next index is used)")?;
    let parent = EncodedPoint::from_bytes(key).ok().and_then(|p| Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&p))).ok_or("the account public key is not a valid secp256k1 key")?;
    let point = ProjectivePoint::GENERATOR * il + ProjectivePoint::from(parent);
    if bool::from(point.is_identity()) {
        return Err("an invalid child key (BIP32: the next index is used)".into());
    }
    let out: [u8; 33] = point.to_affine().to_encoded_point(true).as_bytes().try_into().expect("33 bytes compressed");
    Ok((out, i[32..].try_into().expect("32 bytes")))
}

/// The compressed public key of order `index` under a published account public key.
pub fn order_pubkey(account_pubkey: &[u8; ACCOUNT_PUBKEY_LEN], index: u32) -> Result<[u8; 33], String> {
    let chain: [u8; 32] = account_pubkey[..32].try_into().expect("32 bytes");
    let key: [u8; 33] = account_pubkey[32..].try_into().expect("33 bytes");
    let (ext_key, ext_chain) = child(&key, &chain, 0)?;
    Ok(child(&ext_key, &ext_chain, index)?.0)
}

/// The P2PKH key hash of order `index`'s address.
pub fn order_hash(account_pubkey: &[u8; ACCOUNT_PUBKEY_LEN], index: u32) -> Result<[u8; 20], String> {
    Ok(hash160(&order_pubkey(account_pubkey, index)?))
}

/// An account public key from its 130 hex characters.
pub fn parse_account_pubkey(hex_text: &str) -> Result<[u8; ACCOUNT_PUBKEY_LEN], String> {
    let b = hex::decode(hex_text).map_err(|_| "an exit key is not hex".to_string())?;
    let k: [u8; ACCOUNT_PUBKEY_LEN] = b.try_into().map_err(|_| "an exit key is 65 bytes: the chain code, then the compressed key".to_string())?;
    if !matches!(k[32], 2 | 3) {
        return Err("an exit key's public key is not a compressed secp256k1 key".into());
    }
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_keys_and_indexes() {
        let mut k = [0u8; 65];
        k[32] = 2;
        k[64] = 7; // x = 7 is not on secp256k1
        assert!(order_pubkey(&k, 0).is_err());
        assert!(parse_account_pubkey(&"00".repeat(65)).is_err());
        assert!(parse_account_pubkey("zz").is_err());
        let g = ProjectivePoint::GENERATOR.to_affine().to_encoded_point(true);
        k[32..].copy_from_slice(g.as_bytes());
        assert!(order_pubkey(&k, 0).is_ok());
        assert!(order_pubkey(&k, MAX_INDEX).is_ok());
        assert!(order_pubkey(&k, MAX_INDEX + 1).is_err());
    }
}
