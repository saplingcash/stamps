/**
 * Reads the transparent part of a Zcash v5 transaction (ZIP 225), which is all the stamp rules need:
 * inputs (to check they spend from an issuer) and outputs (the record and the postage).
 */
import { sha256 } from "@noble/hashes/sha2";
import { ripemd160 } from "@noble/hashes/legacy";
import { blake2b } from "@noble/hashes/blake2b";

export const V5_VERSION_GROUP_ID = 0x26a7270a;

export interface TxIn {
  prevTxid: Uint8Array;
  prevIndex: number;
  scriptSig: Uint8Array;
  sequence: number;
}
export interface TxOut {
  value: bigint;
  script: Uint8Array;
}
export interface TransparentTx {
  version: number;
  versionGroupId: number;
  consensusBranchId: number;
  lockTime: number;
  expiryHeight: number;
  inputs: TxIn[];
  outputs: TxOut[];
}

class Reader {
  off = 0;
  private dv: DataView;
  constructor(private b: Uint8Array) {
    this.dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  }
  need(n: number) {
    if (this.off + n > this.b.length) throw new Error("transaction is truncated");
  }
  u32() {
    this.need(4);
    const v = this.dv.getUint32(this.off, true);
    this.off += 4;
    return v;
  }
  i64() {
    this.need(8);
    const v = this.dv.getBigInt64(this.off, true);
    this.off += 8;
    return v;
  }
  bytes(n: number) {
    this.need(n);
    const v = this.b.slice(this.off, this.off + n);
    this.off += n;
    return v;
  }
  compactSize(): number {
    this.need(1);
    const f = this.b[this.off++]!;
    if (f < 0xfd) return f;
    if (f === 0xfd) {
      this.need(2);
      const v = this.dv.getUint16(this.off, true);
      this.off += 2;
      return v;
    }
    if (f === 0xfe) return this.u32();
    throw new Error("compactSize too large");
  }
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 || /[^0-9a-f]/i.test(hex)) throw new Error("not hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}
export function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/** Parses a v5 transaction's header and transparent bundle; throws for other versions. */
export function parseTransparent(raw: Uint8Array): TransparentTx {
  const r = new Reader(raw);
  const header = r.u32();
  const overwintered = (header & 0x80000000) !== 0;
  const version = header & 0x7fffffff;
  if (!overwintered || version !== 5) throw new Error(`not a v5 transaction (version ${version})`);
  const versionGroupId = r.u32();
  if (versionGroupId !== V5_VERSION_GROUP_ID) throw new Error("wrong v5 version group id");
  const consensusBranchId = r.u32();
  const lockTime = r.u32();
  const expiryHeight = r.u32();
  const inputs: TxIn[] = [];
  for (let n = r.compactSize(), i = 0; i < n; i++) {
    const prevTxid = r.bytes(32);
    const prevIndex = r.u32();
    const scriptSig = r.bytes(r.compactSize());
    const sequence = r.u32();
    inputs.push({ prevTxid, prevIndex, scriptSig, sequence });
  }
  const outputs: TxOut[] = [];
  for (let n = r.compactSize(), i = 0; i < n; i++) {
    const value = r.i64();
    if (value < 0n) throw new Error("negative output value");
    outputs.push({ value, script: r.bytes(r.compactSize()) });
  }
  return { version, versionGroupId, consensusBranchId, lockTime, expiryHeight, inputs, outputs };
}

/** The pushes of a push-only script, or null if it contains anything but pushes. */
export function scriptPushes(script: Uint8Array): Uint8Array[] | null {
  const out: Uint8Array[] = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i++]!;
    let len: number;
    if (op >= 0x01 && op <= 0x4b) len = op;
    else if (op === 0x4c) {
      if (i + 1 > script.length) return null;
      len = script[i]!;
      i += 1;
    } else if (op === 0x4d) {
      if (i + 2 > script.length) return null;
      len = script[i]! | (script[i + 1]! << 8);
      i += 2;
    } else return null;
    if (i + len > script.length) return null;
    out.push(script.slice(i, i + len));
    i += len;
  }
  return out;
}

export function hash160(b: Uint8Array): Uint8Array {
  return ripemd160(sha256(b));
}

/** For a P2PKH spend (a signature push and a 33-byte compressed key push): HASH160 of the key; else null. */
export function p2pkhSpenderHash(scriptSig: Uint8Array): Uint8Array | null {
  const pushes = scriptPushes(scriptSig);
  if (!pushes || pushes.length !== 2) return null;
  const [sig, key] = pushes as [Uint8Array, Uint8Array];
  if (sig.length < 9 || sig.length > 73) return null;
  if (key.length !== 33 || (key[0] !== 0x02 && key[0] !== 0x03)) return null;
  return hash160(key);
}

/** The data of an OP_RETURN output of the form `6a 34 <52 bytes>`, or null. */
export function recordPayload(script: Uint8Array): Uint8Array | null {
  if (script.length !== 54 || script[0] !== 0x6a || script[1] !== 0x34) return null;
  return script.slice(2);
}

export function isOpReturn(script: Uint8Array): boolean {
  return script[0] === 0x6a;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * The txid (ZIP 244) of a transparent-only v5 transaction, as nodes display it (byte-reversed hex), or
 * null if the transaction has Sapling or Orchard parts (those are never stamps).
 */
export function txidTransparentOnly(raw: Uint8Array): string | null {
  const tx = parseTransparent(raw);
  // the three empty-bundle counts after the transparent part
  if (raw.length < 3 || raw[raw.length - 1] !== 0 || raw[raw.length - 2] !== 0 || raw[raw.length - 3] !== 0) return null;
  const le32 = (n: number) => Uint8Array.from([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
  const cat = (...parts: Uint8Array[]) => {
    const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
    let o = 0;
    for (const p of parts) {
      out.set(p, o);
      o += p.length;
    }
    return out;
  };
  const h = (personal: string | Uint8Array, data: Uint8Array) => blake2b(data, { dkLen: 32, personalization: typeof personal === "string" ? new TextEncoder().encode(personal) : personal });
  const cs = (n: number) => (n < 0xfd ? Uint8Array.from([n]) : Uint8Array.from([0xfd, n & 0xff, n >> 8]));
  const header = h("ZTxIdHeadersHash", cat(le32(((tx.version | 0x80000000) >>> 0)), le32(tx.versionGroupId), le32(tx.consensusBranchId), le32(tx.lockTime), le32(tx.expiryHeight)));
  let transparent: Uint8Array;
  if (!tx.inputs.length && !tx.outputs.length) transparent = h("ZTxIdTranspaHash", new Uint8Array());
  else {
    const prevouts = h("ZTxIdPrevoutHash", cat(...tx.inputs.map((i) => cat(i.prevTxid, le32(i.prevIndex)))));
    const sequences = h("ZTxIdSequencHash", cat(...tx.inputs.map((i) => le32(i.sequence))));
    const outputs = h("ZTxIdOutputsHash", cat(...tx.outputs.map((o) => {
      const v = new Uint8Array(8);
      new DataView(v.buffer).setBigInt64(0, o.value, true);
      return cat(v, cs(o.script.length), o.script);
    })));
    transparent = h("ZTxIdTranspaHash", cat(prevouts, sequences, outputs));
  }
  const personal = cat(new TextEncoder().encode("ZcashTxHash_"), le32(tx.consensusBranchId));
  const id = h(personal, cat(header, transparent, h("ZTxIdSaplingHash", new Uint8Array()), h("ZTxIdOrchardHash", new Uint8Array())));
  return bytesToHex(id.slice().reverse());
}
