//! Test keys and example values. Each one is derived from a label under "sapling.cash/stamps/": the
//! first bytes of SHA-512("sapling.cash/stamps/" + name), so any value in the tests and the test vectors
//! can be recomputed from its name alone. The TypeScript tests use the same derivation
//! (verifier/test/helpers/labels.ts).
#![allow(dead_code)]
use sha2::{Digest, Sha512};

pub const PREFIX: &str = "sapling.cash/stamps/";

/// The first `N` bytes (at most 64) of SHA-512(PREFIX + name).
pub fn label<const N: usize>(name: &str) -> [u8; N] {
    Sha512::digest(format!("{PREFIX}{name}").as_bytes())[..N].try_into().expect("at most 64 bytes")
}

/// A 32-byte value as the hex a node shows for a txid.
pub fn label_hex(name: &str) -> String {
    hex::encode(label::<32>(name))
}

/// A secp256k1 issuer key.
pub fn issuer(name: &str) -> stamper_core::key::IssuerKey {
    stamper_core::key::IssuerKey::from_bytes(&label::<32>(name)).expect("a valid secp256k1 key")
}

/// An X25519 request key.
#[cfg(feature = "private")]
pub fn request_key(name: &str) -> stamper_core::private::seal::RequestKey {
    stamper_core::private::seal::RequestKey::from_bytes(label::<32>(name))
}

/// An Orchard spending key: the label's bytes, or those of "name#1", "name#2", … for the rare value that
/// is not a valid key.
#[cfg(feature = "proof")]
pub fn spending_key(name: &str) -> orchard::keys::SpendingKey {
    (0u32..)
        .find_map(|i| Option::from(orchard::keys::SpendingKey::from_bytes(label::<32>(&if i == 0 { name.to_string() } else { format!("{name}#{i}") }))))
        .expect("a valid spending key")
}
