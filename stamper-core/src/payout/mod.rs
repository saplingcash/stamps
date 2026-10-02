//! Payout stamps (SPEC.md §10): a shielded exit's own note is the stamp. Sapling pays an exit's ZEC from the
//! exit's order address, a child of a published exit key, as one Ironwood note whose memo is a version 3
//! receipt (`SPLG/3`); the transaction's OP_RETURN is the version 3 record naming the exit.
//!
//! - [`exit_key`]: the order addresses, derived from the published account public key;
//! - [`receipt`]: the `SPLG/3` receipt in the note's memo;
//! - [`proof`]: the stamp proof of a payout stamp, `splg-proof:2`.
//!
//! Nothing here builds or signs: Sapling's exiter does that with its own keys.

pub mod exit_key;
pub mod proof;
pub mod receipt;
