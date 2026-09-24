/** The 52-byte stamp record (SPEC.md §3). */
import { sha256 } from "@noble/hashes/sha2";

export const RECORD_TAG = new Uint8Array([0x53, 0x50, 0x4c, 0x47]); // "SPLG"
export const RECORD_VERSION = 1;
export const RECORD_SIZE = 52;
export const TICKER_MAX = 10;

export interface StampRecord {
  /** sha256(64-byte Solana signature)[0..20] */
  sigHash: Uint8Array;
  /** coin base units burned */
  burned: bigint;
  /** ZEC base units harvested (the redeem payout, before the fee) */
  harvested: bigint;
  /** informational; no rule depends on it */
  ticker: string;
}

export function signatureHash(sig: Uint8Array): Uint8Array {
  if (sig.length !== 64) throw new Error("a Solana signature is 64 bytes");
  return sha256(sig).slice(0, 20);
}

const U64_MAX = (1n << 64n) - 1n;

/** The ticker's bytes: UTF-8, cut at a character boundary to at most 10 bytes. */
export function tickerBytes(ticker: string): Uint8Array {
  const out: number[] = [];
  for (const ch of ticker) {
    const b = new TextEncoder().encode(ch);
    if (out.length + b.length > TICKER_MAX) break;
    out.push(...b);
  }
  return Uint8Array.from(out);
}

export function encodeRecord(r: StampRecord): Uint8Array {
  if (r.sigHash.length !== 20) throw new Error("sigHash must be 20 bytes");
  if (r.burned < 0n || r.burned > U64_MAX || r.harvested < 0n || r.harvested > U64_MAX) throw new Error("amounts must fit in u64");
  const t = tickerBytes(r.ticker);
  const out = new Uint8Array(RECORD_SIZE);
  const dv = new DataView(out.buffer);
  out.set(RECORD_TAG, 0);
  out[4] = RECORD_VERSION;
  out.set(r.sigHash, 5);
  dv.setBigUint64(25, r.burned, true);
  dv.setBigUint64(33, r.harvested, true);
  out[41] = t.length;
  out.set(t, 42);
  return out;
}

/** Parses a record, or returns the reason it does not parse. */
export function decodeRecord(b: Uint8Array): StampRecord | { error: string } {
  if (b.length !== RECORD_SIZE) return { error: `record is ${b.length} bytes, not ${RECORD_SIZE}` };
  for (let i = 0; i < 4; i++) if (b[i] !== RECORD_TAG[i]) return { error: "tag is not SPLG" };
  if (b[4] !== RECORD_VERSION) return { error: `version ${b[4]} is not supported` };
  const n = b[41]!;
  if (n > TICKER_MAX) return { error: `ticker length ${n} exceeds ${TICKER_MAX}` };
  for (let i = 42 + n; i < RECORD_SIZE; i++) if (b[i] !== 0) return { error: "bytes after the ticker are not zero" };
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let ticker: string;
  try {
    ticker = new TextDecoder("utf-8", { fatal: true }).decode(b.slice(42, 42 + n));
  } catch {
    return { error: "ticker is not UTF-8" };
  }
  return { sigHash: b.slice(5, 25), burned: dv.getBigUint64(25, true), harvested: dv.getBigUint64(33, true), ticker };
}
