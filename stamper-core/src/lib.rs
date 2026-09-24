//! Sapling stamper core: builds and signs the Zcash transactions that carry stamps (SPEC.md).
//!
//! It has no network code. The caller (the stamper service) reads the consensus branch, the tip and
//! the issuer's coins from a node, and passes them in; this library turns them into a signed v5
//! transaction. The key never leaves it.

pub mod address;
pub mod build;
pub mod key;
pub mod tx;
