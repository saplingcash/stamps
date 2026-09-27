//! Private stamps (SPEC.md §9): the receiver sealed on Solana, the receipt memo, and the transaction
//! that delivers 546 zatoshi and the receipt to a shielded address.

#[cfg(feature = "private")]
pub mod build;
pub mod memo;
pub mod proof;
#[cfg(feature = "private")]
pub mod seal;

/// The postage a private stamp sends into the shielded pool, in zatoshi.
pub const POSTAGE: u64 = 546;

/// The one error a private build reports for a request that cannot be delivered (a seal that does
/// not open, a receiver that is not a valid shielded address). It says nothing about why.
pub const UNDELIVERABLE: &str = "undeliverable";
