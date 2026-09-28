//! The public records a stamp carries in its OP_RETURN (SPEC.md §3).

use sha2::{Digest, Sha256};

pub const TAG: &[u8; 4] = b"SPLG";

/// The version 2 record, for a stamp delivered to a shielded address: the tag, `02` and the first 18
/// bytes of `sha256(sig)`. 23 bytes, so the whole output serializes to 34 bytes (one ZIP 317 unit). It
/// carries no amount and no address: enough to find its harvest on Solana, nothing more to learn.
pub const RECORD_V2_LEN: usize = 23;

pub fn record_v2(sig: &[u8; 64]) -> [u8; RECORD_V2_LEN] {
    let h = Sha256::digest(sig);
    let mut r = [0u8; RECORD_V2_LEN];
    r[..4].copy_from_slice(TAG);
    r[4] = 2;
    r[5..].copy_from_slice(&h[..18]);
    r
}

/// The OP_RETURN script of a version 2 record: `6a 17 <23 bytes>`.
pub fn record_v2_script(sig: &[u8; 64]) -> Vec<u8> {
    let mut s = vec![0x6a, RECORD_V2_LEN as u8];
    s.extend_from_slice(&record_v2(sig));
    s
}

/// Decodes a base58 Solana signature into its 64 bytes.
pub fn solana_signature(b58: &str) -> Result<[u8; 64], String> {
    let v = bs58::decode(b58).into_vec().map_err(|_| "the harvest signature is not base58".to_string())?;
    v.as_slice().try_into().map_err(|_| "the harvest signature must be 64 bytes".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_record_layout() {
        let sig = [7u8; 64];
        let r = record_v2(&sig);
        assert_eq!(&r[..5], b"SPLG\x02");
        assert_eq!(&r[5..], &Sha256::digest(sig)[..18]);
        let s = record_v2_script(&sig);
        assert_eq!(s.len(), 25);
        // value (8) + compactSize (1) + script (25) = 34 bytes: one ZIP 317 output unit
        assert_eq!(8 + 1 + s.len(), 34);
    }
}
