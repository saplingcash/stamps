//! The sealed receiver (SPEC.md §9.2): the shielded receiver a harvest names, encrypted to the
//! stamper's request key, so that only the stamper can read it. Think of a letter posted to the stamper:
//! anyone can see that it was posted and for which harvest, only the stamper's signer can read the
//! address written inside.
//!
//! ```text
//! plaintext  = 0x03 || receiver (43 bytes)
//! epk        = X25519(esk, basepoint)
//! ss         = X25519(esk, request_pk)                (an all-zero ss is refused)
//! key||nonce = HKDF-SHA256(ikm = ss, salt = epk || request_pk, info = "sapling-stamp:2 sealed-receiver", 44)
//! aad        = "sapling-stamp:2" || u8 kid || holder (32 bytes)
//! sealed     = epk || ChaCha20-Poly1305(key, nonce, plaintext, aad)       (92 bytes)
//! ```

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::UNDELIVERABLE;

pub const SEALED_LEN: usize = 92;
pub const RECEIVER_LEN: usize = 43;
const INFO: &[u8] = b"sapling-stamp:2 sealed-receiver";
const AAD_TAG: &[u8] = b"sapling-stamp:2";
const TYPECODE_ORCHARD: u8 = 0x03;

fn derive(ss: &[u8; 32], epk: &[u8; 32], request_pk: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(epk);
    salt[32..].copy_from_slice(request_pk);
    let mut okm = Zeroizing::new([0u8; 44]);
    Hkdf::<Sha256>::new(Some(&salt), ss).expand(INFO, okm.as_mut()).expect("44 bytes is a valid HKDF length");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    (key, nonce)
}

fn aad(kid: u8, holder: &[u8; 32]) -> Vec<u8> {
    let mut a = AAD_TAG.to_vec();
    a.push(kid);
    a.extend_from_slice(holder);
    a
}

/// Seals `receiver` to `request_pk` with the ephemeral secret `esk` (the site does this in the
/// browser; here for tests and vectors).
pub fn seal(request_pk: &[u8; 32], kid: u8, holder: &[u8; 32], receiver: &[u8; RECEIVER_LEN], esk: [u8; 32]) -> Result<[u8; SEALED_LEN], String> {
    let esk = StaticSecret::from(esk);
    let epk = PublicKey::from(&esk).to_bytes();
    let ss = Zeroizing::new(esk.diffie_hellman(&PublicKey::from(*request_pk)).to_bytes());
    if ss.iter().all(|b| *b == 0) {
        return Err("the request key is a low-order point".into());
    }
    let (key, nonce) = derive(&ss, &epk, request_pk);
    let mut pt = [0u8; 1 + RECEIVER_LEN];
    pt[0] = TYPECODE_ORCHARD;
    pt[1..].copy_from_slice(receiver);
    let ct = ChaCha20Poly1305::new(&key.into()).encrypt(&nonce.into(), Payload { msg: &pt, aad: &aad(kid, holder) }).map_err(|_| "sealing failed".to_string())?;
    let mut out = [0u8; SEALED_LEN];
    out[..32].copy_from_slice(&epk);
    out[32..].copy_from_slice(&ct);
    Ok(out)
}

/// The stamper's request key: an X25519 secret, stored as a 0600 file of 64 hex characters, never
/// printed. Only its public half is ever shown.
pub struct RequestKey {
    secret: StaticSecret,
}

impl RequestKey {
    pub fn generate() -> Self {
        RequestKey { secret: StaticSecret::random_from_rng(rand_core::OsRng) }
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        RequestKey { secret: StaticSecret::from(b) }
    }

    pub fn public(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }

    /// Writes the key to `path` with mode 0600; refuses to overwrite an existing file.
    pub fn write_new(&self, path: &Path) -> Result<(), String> {
        if path.exists() {
            return Err(format!("{} already exists: refusing to overwrite a key", path.display()));
        }
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(path).map_err(|e| e.to_string())?;
        let hexed = Zeroizing::new(hex::encode(self.secret.to_bytes()));
        f.write_all(hexed.as_bytes()).map_err(|e| e.to_string())?;
        f.write_all(b"\n").map_err(|e| e.to_string())
    }

    /// Reads the key file (fixed messages: never its content).
    pub fn read(path: &Path) -> Result<Self, String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path).map_err(|_| "cannot read the request key file".to_string())?.permissions().mode();
            if mode & 0o077 != 0 {
                return Err("the request key file must be mode 0600".into());
            }
        }
        let text = Zeroizing::new(fs::read_to_string(path).map_err(|_| "cannot read the request key file".to_string())?);
        let bytes = Zeroizing::new(hex::decode(text.trim()).map_err(|_| "the request key file is not hex".to_string())?);
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "the request key file must hold 32 bytes".to_string())?;
        Ok(Self::from_bytes(arr))
    }

    /// Opens a seal. Any failure is `undeliverable`, with no detail.
    pub fn open(&self, kid: u8, holder: &[u8; 32], sealed: &[u8]) -> Result<[u8; RECEIVER_LEN], String> {
        let sealed: &[u8; SEALED_LEN] = sealed.try_into().map_err(|_| UNDELIVERABLE.to_string())?;
        let mut epk = [0u8; 32];
        epk.copy_from_slice(&sealed[..32]);
        let ss = Zeroizing::new(self.secret.diffie_hellman(&PublicKey::from(epk)).to_bytes());
        if ss.iter().all(|b| *b == 0) {
            return Err(UNDELIVERABLE.into());
        }
        let (key, nonce) = derive(&ss, &epk, &self.public());
        let pt = Zeroizing::new(ChaCha20Poly1305::new(&key.into()).decrypt(&nonce.into(), Payload { msg: &sealed[32..], aad: &aad(kid, holder) }).map_err(|_| UNDELIVERABLE.to_string())?);
        if pt.len() != 1 + RECEIVER_LEN || pt[0] != TYPECODE_ORCHARD {
            return Err(UNDELIVERABLE.into());
        }
        let mut r = [0u8; RECEIVER_LEN];
        r.copy_from_slice(&pt[1..]);
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_and_opens() {
        let k = RequestKey::from_bytes([1; 32]);
        let holder = [2u8; 32];
        let receiver = [3u8; RECEIVER_LEN];
        let s = seal(&k.public(), 1, &holder, &receiver, [4; 32]).unwrap();
        assert_eq!(s.len(), SEALED_LEN);
        assert_eq!(k.open(1, &holder, &s).unwrap(), receiver);
    }

    #[test]
    fn a_seal_is_bound_to_its_key_id_holder_and_bytes() {
        let k = RequestKey::from_bytes([1; 32]);
        let holder = [2u8; 32];
        let s = seal(&k.public(), 1, &holder, &[3; RECEIVER_LEN], [4; 32]).unwrap();
        assert_eq!(k.open(2, &holder, &s).unwrap_err(), UNDELIVERABLE);
        assert_eq!(k.open(1, &[9; 32], &s).unwrap_err(), UNDELIVERABLE);
        assert_eq!(RequestKey::from_bytes([5; 32]).open(1, &holder, &s).unwrap_err(), UNDELIVERABLE);
        for i in 0..SEALED_LEN {
            let mut t = s;
            t[i] ^= 1;
            assert_eq!(k.open(1, &holder, &t).unwrap_err(), UNDELIVERABLE, "byte {i}");
        }
        assert_eq!(k.open(1, &holder, &s[..91]).unwrap_err(), UNDELIVERABLE);
    }

    #[test]
    fn fresh_esk_means_unlinkable_seals() {
        let k = RequestKey::from_bytes([1; 32]);
        let a = seal(&k.public(), 1, &[2; 32], &[3; RECEIVER_LEN], [4; 32]).unwrap();
        let b = seal(&k.public(), 1, &[2; 32], &[3; RECEIVER_LEN], [5; 32]).unwrap();
        assert!(a.iter().zip(b.iter()).filter(|(x, y)| x == y).count() < 10);
    }
}
