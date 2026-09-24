//! Transparent-only Zcash v5 transactions (ZIP 225): serialization, the transaction id (ZIP 244 §T)
//! and the SIGHASH_ALL signature digest for transparent inputs (ZIP 244 §S). Written from the ZIP
//! text; checked in tests against librustzcash.

use blake2b_simd::Params;

pub const V5_HEADER: u32 = 5 | (1 << 31);
pub const V5_VERSION_GROUP_ID: u32 = 0x26A7_270A;
pub const SIGHASH_ALL: u8 = 0x01;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutPoint {
    /// the previous transaction's id, in internal byte order (the reverse of how it is displayed)
    pub txid: [u8; 32],
    pub index: u32,
}

#[derive(Clone, Debug)]
pub struct TxIn {
    pub prevout: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script: Vec<u8>,
}

/// A transparent-only v5 transaction. `consensus_branch_id` is whatever the node reports; it is
/// never assumed here.
#[derive(Clone, Debug)]
pub struct Tx {
    pub consensus_branch_id: u32,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
}

/// The coin an input spends: needed by the signature digest (ZIP 244 S.2c, S.2d, S.2g).
#[derive(Clone, Debug)]
pub struct SpentCoin {
    pub value: u64,
    pub script: Vec<u8>,
}

pub fn compact_size(n: usize, out: &mut Vec<u8>) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
}

fn with_len(bytes: &[u8], out: &mut Vec<u8>) {
    compact_size(bytes.len(), out);
    out.extend_from_slice(bytes);
}

fn blake2b(personal: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let h = Params::new().hash_length(32).personal(personal).hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

impl OutPoint {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.txid);
        out.extend_from_slice(&self.index.to_le_bytes());
    }
}

impl TxOut {
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.value.to_le_bytes());
        with_len(&self.script, out);
    }
}

impl TxIn {
    pub fn write(&self, out: &mut Vec<u8>) {
        self.prevout.write(out);
        with_len(&self.script_sig, out);
        out.extend_from_slice(&self.sequence.to_le_bytes());
    }
}

impl Tx {
    /// The full serialization (ZIP 225), with empty Sapling and Orchard bundles.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&V5_HEADER.to_le_bytes());
        out.extend_from_slice(&V5_VERSION_GROUP_ID.to_le_bytes());
        out.extend_from_slice(&self.consensus_branch_id.to_le_bytes());
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out.extend_from_slice(&self.expiry_height.to_le_bytes());
        compact_size(self.inputs.len(), &mut out);
        for i in &self.inputs {
            i.write(&mut out);
        }
        compact_size(self.outputs.len(), &mut out);
        for o in &self.outputs {
            o.write(&mut out);
        }
        out.extend_from_slice(&[0, 0, 0]); // no Sapling spends, no Sapling outputs, no Orchard actions
        out
    }

    fn header_digest(&self) -> [u8; 32] {
        let mut d = Vec::with_capacity(20);
        d.extend_from_slice(&V5_HEADER.to_le_bytes());
        d.extend_from_slice(&V5_VERSION_GROUP_ID.to_le_bytes());
        d.extend_from_slice(&self.consensus_branch_id.to_le_bytes());
        d.extend_from_slice(&self.lock_time.to_le_bytes());
        d.extend_from_slice(&self.expiry_height.to_le_bytes());
        blake2b(b"ZTxIdHeadersHash", &d)
    }

    fn prevouts_digest(&self) -> [u8; 32] {
        let mut d = Vec::new();
        for i in &self.inputs {
            i.prevout.write(&mut d);
        }
        blake2b(b"ZTxIdPrevoutHash", &d)
    }

    fn sequence_digest(&self) -> [u8; 32] {
        let mut d = Vec::new();
        for i in &self.inputs {
            d.extend_from_slice(&i.sequence.to_le_bytes());
        }
        blake2b(b"ZTxIdSequencHash", &d)
    }

    fn outputs_digest(&self) -> [u8; 32] {
        let mut d = Vec::new();
        for o in &self.outputs {
            o.write(&mut d);
        }
        blake2b(b"ZTxIdOutputsHash", &d)
    }

    fn transparent_digest(&self) -> [u8; 32] {
        if self.inputs.is_empty() && self.outputs.is_empty() {
            return blake2b(b"ZTxIdTranspaHash", &[]);
        }
        let mut d = Vec::with_capacity(96);
        d.extend_from_slice(&self.prevouts_digest());
        d.extend_from_slice(&self.sequence_digest());
        d.extend_from_slice(&self.outputs_digest());
        blake2b(b"ZTxIdTranspaHash", &d)
    }

    fn top(&self, transparent: [u8; 32]) -> [u8; 32] {
        let mut personal = [0u8; 16];
        personal[..12].copy_from_slice(b"ZcashTxHash_");
        personal[12..].copy_from_slice(&self.consensus_branch_id.to_le_bytes());
        let mut d = Vec::with_capacity(128);
        d.extend_from_slice(&self.header_digest());
        d.extend_from_slice(&transparent);
        d.extend_from_slice(&blake2b(b"ZTxIdSaplingHash", &[]));
        d.extend_from_slice(&blake2b(b"ZTxIdOrchardHash", &[]));
        blake2b(&personal, &d)
    }

    /// The transaction id digest (ZIP 244 §T), in internal byte order.
    pub fn txid(&self) -> [u8; 32] {
        self.top(self.transparent_digest())
    }

    /// The txid as nodes and explorers display it (byte-reversed hex).
    pub fn txid_hex(&self) -> String {
        let mut t = self.txid();
        t.reverse();
        hex::encode(t)
    }

    /// The SIGHASH_ALL signature digest for transparent input `index` (ZIP 244 §S).
    pub fn sighash_all(&self, index: usize, spent: &[SpentCoin]) -> [u8; 32] {
        assert_eq!(spent.len(), self.inputs.len(), "one spent coin per input");
        let mut amounts = Vec::new();
        let mut scripts = Vec::new();
        for c in spent {
            amounts.extend_from_slice(&c.value.to_le_bytes());
            with_len(&c.script, &mut scripts);
        }
        let input = &self.inputs[index];
        let mut txin = Vec::new();
        input.prevout.write(&mut txin);
        txin.extend_from_slice(&spent[index].value.to_le_bytes());
        with_len(&spent[index].script, &mut txin);
        txin.extend_from_slice(&input.sequence.to_le_bytes());

        let mut d = Vec::with_capacity(1 + 6 * 32);
        d.push(SIGHASH_ALL);
        d.extend_from_slice(&self.prevouts_digest());
        d.extend_from_slice(&blake2b(b"ZTxTrAmountsHash", &amounts));
        d.extend_from_slice(&blake2b(b"ZTxTrScriptsHash", &scripts));
        d.extend_from_slice(&self.sequence_digest());
        d.extend_from_slice(&self.outputs_digest());
        d.extend_from_slice(&blake2b(b"Zcash___TxInHash", &txin));
        self.top(blake2b(b"ZTxIdTranspaHash", &d))
    }
}
