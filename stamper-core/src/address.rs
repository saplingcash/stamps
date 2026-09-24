//! The issuer's own address (transparent P2PKH) and the standard output scripts.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    fn p2pkh_prefix(self) -> [u8; 2] {
        match self {
            Network::Mainnet => [0x1c, 0xb8],
            Network::Testnet => [0x1d, 0x25],
        }
    }
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let rip = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

pub fn p2pkh_script(hash: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// The Base58Check t-address of a P2PKH key hash.
pub fn p2pkh_address(network: Network, hash: &[u8; 20]) -> String {
    let mut body = network.p2pkh_prefix().to_vec();
    body.extend_from_slice(hash);
    let check = Sha256::digest(Sha256::digest(&body));
    body.extend_from_slice(&check[..4]);
    bs58::encode(body).into_string()
}

/// What kind of output script this is; the stamper builds nothing else.
#[derive(Debug, PartialEq, Eq)]
pub enum ScriptKind {
    P2pkh,
    P2sh,
    OpReturn,
    Other,
}

pub fn script_kind(s: &[u8]) -> ScriptKind {
    if s.len() == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac {
        ScriptKind::P2pkh
    } else if s.len() == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87 {
        ScriptKind::P2sh
    } else if !s.is_empty() && s[0] == 0x6a {
        ScriptKind::OpReturn
    } else {
        ScriptKind::Other
    }
}
