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

/// The version 3 record, carried by a payout stamp (SPEC.md §10): the tag, `03`, then the first 18 bytes of
/// `sha256(sig)` of each exit the transaction delivers, in order. One exit is 23 bytes, four are 77.
pub const RECORD_V3_VERSION: u8 = 3;
pub const RECORD_V3_HASH_LEN: usize = 18;
/// the most exits one payout transaction delivers (the 80-byte OP_RETURN limit)
pub const RECORD_V3_MAX_EXITS: usize = 4;

pub fn exit_hash(sig: &[u8; 64]) -> [u8; RECORD_V3_HASH_LEN] {
    let h = Sha256::digest(sig);
    let mut r = [0u8; RECORD_V3_HASH_LEN];
    r.copy_from_slice(&h[..RECORD_V3_HASH_LEN]);
    r
}

pub fn record_v3(sigs: &[[u8; 64]]) -> Result<Vec<u8>, String> {
    if sigs.is_empty() || sigs.len() > RECORD_V3_MAX_EXITS {
        return Err(format!("a version 3 record names 1 to {RECORD_V3_MAX_EXITS} exits, not {}", sigs.len()));
    }
    let mut r = TAG.to_vec();
    r.push(RECORD_V3_VERSION);
    for s in sigs {
        r.extend_from_slice(&exit_hash(s));
    }
    Ok(r)
}

/// The exit hashes a version 3 record names, or `None` if `data` is not one.
pub fn parse_v3(data: &[u8]) -> Option<Vec<[u8; RECORD_V3_HASH_LEN]>> {
    let body = data.strip_prefix(TAG.as_slice())?.strip_prefix(&[RECORD_V3_VERSION])?;
    if body.is_empty() || body.len() % RECORD_V3_HASH_LEN != 0 || body.len() / RECORD_V3_HASH_LEN > RECORD_V3_MAX_EXITS {
        return None;
    }
    Some(body.chunks(RECORD_V3_HASH_LEN).map(|c| c.try_into().expect("18 bytes")).collect())
}

/// The OP_RETURN script of a version 3 record: `6a`, then the record as one minimal push (`<len>` for 23,
/// 41 or 59 bytes; `4c 4d` for 77).
pub fn record_v3_script(record: &[u8]) -> Vec<u8> {
    let mut s = vec![0x6a];
    if record.len() > 75 {
        s.push(0x4c);
    }
    s.push(record.len() as u8);
    s.extend_from_slice(record);
    s
}

/// The exit hashes of an OP_RETURN script that is exactly a version 3 record in its minimal push.
pub fn parse_v3_script(script: &[u8]) -> Option<Vec<[u8; RECORD_V3_HASH_LEN]>> {
    let data = match script {
        [0x6a, 0x4c, n, rest @ ..] if *n as usize > 75 && rest.len() == *n as usize => rest,
        [0x6a, n, rest @ ..] if (1..=75).contains(n) && rest.len() == *n as usize => rest,
        _ => return None,
    };
    parse_v3(data)
}

/// Decodes a base58 Solana signature into its 64 bytes.
pub fn solana_signature(b58: &str) -> Result<[u8; 64], String> {
    let v = bs58::decode(b58).into_vec().map_err(|_| "the harvest signature is not base58".to_string())?;
    v.as_slice().try_into().map_err(|_| "the harvest signature must be 64 bytes".to_string())
}

/// A Robinhood Chain exit's name (SPEC.md §10.2): `hood:0x<transaction hash, 64 lowercase hex>:<log index>`.
pub const HOOD_PREFIX: &str = "hood:";

/// The transaction hash and log index of a Robinhood Chain exit's name (the index in decimal with no leading
/// zeros), or `None` if `name` is not exactly one.
pub fn hood_exit(name: &str) -> Option<([u8; 32], u32)> {
    let (h, n) = name.strip_prefix(HOOD_PREFIX)?.strip_prefix("0x")?.split_once(':')?;
    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    if n.is_empty() || n.len() > 10 || !n.bytes().all(|b| b.is_ascii_digit()) || (n.len() > 1 && n.starts_with('0')) {
        return None;
    }
    let hash: [u8; 32] = hex::decode(h).ok()?.try_into().ok()?;
    Some((hash, n.parse::<u32>().ok()?))
}

/// The 64 bytes a version 3 record names an exit by (SPEC.md §10.4): a Solana exit's signature; a Robinhood
/// Chain exit's transaction hash, then its log index as 32 big-endian bytes.
pub fn exit_id(name: &str) -> Result<[u8; 64], String> {
    if name.starts_with(HOOD_PREFIX) {
        let (hash, log) = hood_exit(name).ok_or("the exit's name is not hood:0x<64 hex>:<log index>")?;
        let mut id = [0u8; 64];
        id[..32].copy_from_slice(&hash);
        id[60..].copy_from_slice(&log.to_be_bytes());
        return Ok(id);
    }
    solana_signature(name)
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

    #[test]
    fn v3_record_layout() {
        let one = record_v3(&[[7u8; 64]]).unwrap();
        assert_eq!(one.len(), 23);
        assert_eq!(&one[..5], b"SPLG\x03");
        assert_eq!(record_v3_script(&one)[..2], [0x6a, 23]);
        let four = record_v3(&[[1; 64], [2; 64], [3; 64], [4; 64]]).unwrap();
        assert_eq!(four.len(), 77);
        let s = record_v3_script(&four);
        assert_eq!(s[..3], [0x6a, 0x4c, 77]);
        assert_eq!(parse_v3_script(&s).unwrap(), vec![exit_hash(&[1; 64]), exit_hash(&[2; 64]), exit_hash(&[3; 64]), exit_hash(&[4; 64])]);
        // a non-minimal push, a wrong length, a version 2 record, five exits: none is a version 3 record
        let mut long = vec![0x6a, 0x4c, 23];
        long.extend_from_slice(&one);
        assert!(parse_v3_script(&long).is_none());
        assert!(parse_v3_script(&record_v3_script(&four)[..79]).is_none());
        assert!(parse_v3_script(&record_v2_script(&[7u8; 64])).is_none());
        assert!(record_v3(&[]).is_err() && record_v3(&[[0; 64]; 5]).is_err());
        let mut five = four.clone();
        five.extend_from_slice(&[0; 18]);
        assert!(parse_v3(&five).is_none());
    }

    #[test]
    fn exit_names_and_their_ids() {
        let h = "cd".repeat(32);
        let hood = exit_id(&format!("hood:0x{h}:12")).unwrap();
        assert_eq!(&hood[..32], &[0xcd; 32]);
        assert_eq!(&hood[32..60], &[0; 28]);
        assert_eq!(&hood[60..], &12u32.to_be_bytes());
        assert_eq!(hood_exit(&format!("hood:0x{h}:0")), Some(([0xcd; 32], 0)));
        assert_eq!(hood_exit(&format!("hood:0x{h}:4294967295")), Some(([0xcd; 32], u32::MAX)));
        let sig = bs58::encode([9u8; 64]).into_string();
        assert_eq!(exit_id(&sig).unwrap(), [9u8; 64]);
        assert_ne!(exit_hash(&hood), exit_hash(&[9u8; 64]));
        // anything else is no exit: upper case hex, a short hash, a leading zero, no index, an index past u32, no 0x
        for bad in [format!("hood:0x{}:12", "CD".repeat(32)), format!("hood:0x{}:1", "cd".repeat(31)), format!("hood:0x{h}:01"), format!("hood:0x{h}:"), format!("hood:0x{h}:4294967296"), format!("hood:{h}:1"), bs58::encode([9u8; 32]).into_string()] {
            assert!(exit_id(&bad).is_err(), "{bad}");
        }
    }
}
