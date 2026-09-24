//! The issuer key: generated on the stamper's host, stored as a 0600 file of 64 hex characters, never
//! printed. Only its address is ever shown.

use k256::ecdsa::{SigningKey, VerifyingKey};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

use crate::address::{hash160, p2pkh_address, Network};

pub struct IssuerKey {
    key: SigningKey,
}

impl IssuerKey {
    pub fn generate() -> Self {
        IssuerKey { key: SigningKey::random(&mut rand_core::OsRng) }
    }

    pub fn from_bytes(b: &[u8; 32]) -> Result<Self, String> {
        SigningKey::from_bytes(b.into()).map(|key| IssuerKey { key }).map_err(|_| "not a valid secp256k1 key".into())
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
        let hexed = Zeroizing::new(hex::encode(self.key.to_bytes()));
        f.write_all(hexed.as_bytes()).map_err(|e| e.to_string())?;
        f.write_all(b"\n").map_err(|e| e.to_string())
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        let text = Zeroizing::new(fs::read_to_string(path).map_err(|e| format!("cannot read the key file: {e}"))?);
        let bytes = Zeroizing::new(hex::decode(text.trim()).map_err(|_| "the key file is not hex".to_string())?);
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "the key file must hold 32 bytes".to_string())?;
        Self::from_bytes(&arr)
    }

    pub fn public_key(&self) -> [u8; 33] {
        let vk = VerifyingKey::from(&self.key);
        let enc = vk.to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(enc.as_bytes());
        out
    }

    pub fn pubkey_hash(&self) -> [u8; 20] {
        hash160(&self.public_key())
    }

    pub fn address(&self, network: Network) -> String {
        p2pkh_address(network, &self.pubkey_hash())
    }

    /// A DER ECDSA signature (low S) over a 32-byte digest, followed by the hash type byte.
    pub fn sign_digest(&self, digest: &[u8; 32], hash_type: u8) -> Vec<u8> {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: k256::ecdsa::Signature = self.key.sign_prehash(digest).expect("a 32-byte digest always signs");
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut out = sig.to_der().as_bytes().to_vec();
        out.push(hash_type);
        out
    }
}
