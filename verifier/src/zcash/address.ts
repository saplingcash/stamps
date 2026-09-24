/**
 * Zcash addresses a stamp can go to (SPEC.md §4): transparent P2PKH/P2SH (Base58Check), TEX (ZIP 320)
 * and Unified Addresses with a transparent receiver (ZIP 316). Everything else is undeliverable.
 */
import { sha256 } from "@noble/hashes/sha2";
import { base58, bech32m } from "@scure/base";
import { f4jumbleInv } from "./f4jumble.ts";

export type ZcashNetwork = "mainnet" | "testnet";
export type Destination = { kind: "p2pkh" | "p2sh"; hash: Uint8Array };
export type Decoded = { ok: true; destination: Destination; form: "transparent" | "tex" | "unified" } | { ok: false; reason: string };

const PREFIX = {
  mainnet: { p2pkh: [0x1c, 0xb8], p2sh: [0x1c, 0xbd], tex: "tex", ua: ["u", "tu"], uaShieldedOnly: "zu" },
  testnet: { p2pkh: [0x1d, 0x25], p2sh: [0x1c, 0xba], tex: "textest", ua: ["utest", "tutest"], uaShieldedOnly: "zutest" },
} as const;

function base58check(s: string): Uint8Array | null {
  let raw: Uint8Array;
  try {
    raw = base58.decode(s);
  } catch {
    return null;
  }
  if (raw.length < 5) return null;
  const body = raw.slice(0, -4);
  const sum = sha256(sha256(body)).slice(0, 4);
  for (let i = 0; i < 4; i++) if (sum[i] !== raw[raw.length - 4 + i]) return null;
  return body;
}

export function encodeTransparent(network: ZcashNetwork, d: Destination): string {
  const body = new Uint8Array(22);
  body.set(PREFIX[network][d.kind], 0);
  body.set(d.hash, 2);
  const sum = sha256(sha256(body)).slice(0, 4);
  const all = new Uint8Array(26);
  all.set(body, 0);
  all.set(sum, 22);
  return base58.encode(all);
}

function readCompactSize(b: Uint8Array, off: number): [number, number] | null {
  const first = b[off];
  if (first === undefined) return null;
  if (first < 0xfd) return [first, off + 1];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (first === 0xfd && off + 3 <= b.length) {
    const v = dv.getUint16(off + 1, true);
    return v < 0xfd ? null : [v, off + 3];
  }
  if (first === 0xfe && off + 5 <= b.length) {
    const v = dv.getUint32(off + 1, true);
    return v <= 0xffff ? null : [v, off + 5];
  }
  return null; // 0xff (8-byte) sizes exceed the 0x2000000 limit anyway
}

function decodeUnified(s: string, hrp: string): Decoded {
  let words: number[];
  try {
    const d = bech32m.decode(s as `${string}1${string}`, false);
    if (d.prefix !== hrp) return { ok: false, reason: "wrong network" };
    words = d.words;
  } catch {
    return { ok: false, reason: "not a valid unified address (checksum)" };
  }
  let jumbled: Uint8Array;
  try {
    jumbled = bech32m.fromWords(words);
  } catch {
    return { ok: false, reason: "not a valid unified address (padding)" };
  }
  let raw: Uint8Array;
  try {
    raw = f4jumbleInv(jumbled);
  } catch {
    return { ok: false, reason: "not a valid unified address (length)" };
  }
  const pad = new Uint8Array(16);
  pad.set(new TextEncoder().encode(hrp), 0);
  const tail = raw.slice(raw.length - 16);
  for (let i = 0; i < 16; i++) if (tail[i] !== pad[i]) return { ok: false, reason: "not a valid unified address (padding)" };
  const items = raw.slice(0, raw.length - 16);
  let off = 0;
  let last = -1;
  let transparent: Destination | null = null;
  while (off < items.length) {
    const tc = readCompactSize(items, off);
    if (!tc) return { ok: false, reason: "not a valid unified address (item)" };
    const len = readCompactSize(items, tc[1]);
    if (!len) return { ok: false, reason: "not a valid unified address (item)" };
    const [typecode] = tc;
    const [length, start] = len;
    if (typecode > 0x2000000 || length > 0x2000000 || start + length > items.length) return { ok: false, reason: "not a valid unified address (item)" };
    if (typecode <= last) return { ok: false, reason: "not a valid unified address (item order)" };
    last = typecode;
    const value = items.slice(start, start + length);
    if (typecode >= 0xe0 && typecode <= 0xfc) return { ok: false, reason: "this unified address carries data this wallet cannot read" };
    if (typecode === 0x00 || typecode === 0x01) {
      if (length !== 20) return { ok: false, reason: "not a valid unified address (transparent receiver)" };
      if (transparent) return { ok: false, reason: "not a valid unified address (two transparent receivers)" };
      transparent = { kind: typecode === 0x00 ? "p2pkh" : "p2sh", hash: value };
    }
    off = start + length;
  }
  if (!transparent) return { ok: false, reason: "this unified address has no transparent receiver: use a t1 or t3 address" };
  return { ok: true, destination: transparent, form: "unified" };
}

/** Decodes a stamp address for `network`, or says why it cannot receive a stamp. */
export function decodeAddress(input: string, network: ZcashNetwork): Decoded {
  const s = input;
  if (!s || /\s/.test(s)) return { ok: false, reason: "empty or contains whitespace" };
  const p = PREFIX[network];
  const lower = s.toLowerCase();
  const hrpOf = (x: string) => x.slice(0, x.lastIndexOf("1"));
  if (lower.includes("1") && s === lower) {
    const hrp = hrpOf(lower);
    if (hrp === p.tex) {
      try {
        const d = bech32m.decode(s as `${string}1${string}`);
        const hash = bech32m.fromWords(d.words);
        if (hash.length !== 20) return { ok: false, reason: "not a valid TEX address" };
        return { ok: true, destination: { kind: "p2pkh", hash }, form: "tex" };
      } catch {
        return { ok: false, reason: "not a valid TEX address (checksum)" };
      }
    }
    if ((p.ua as readonly string[]).includes(hrp)) return decodeUnified(s, hrp);
    if (hrp === p.uaShieldedOnly) return { ok: false, reason: "this unified address has no transparent receiver: use a t1 or t3 address" };
    if (hrp.startsWith("zs") || hrp.startsWith("ztestsapling")) return { ok: false, reason: "shielded addresses cannot receive a stamp: use a t1 or t3 address" };
  }
  const body = base58check(s);
  if (!body) return { ok: false, reason: "not a Zcash address this network accepts" };
  if (body.length === 22) {
    const pre = [body[0], body[1]];
    if (pre[0] === p.p2pkh[0] && pre[1] === p.p2pkh[1]) return { ok: true, destination: { kind: "p2pkh", hash: body.slice(2) }, form: "transparent" };
    if (pre[0] === p.p2sh[0] && pre[1] === p.p2sh[1]) return { ok: true, destination: { kind: "p2sh", hash: body.slice(2) }, form: "transparent" };
  }
  return { ok: false, reason: "not a Zcash address this network accepts" };
}

/** The scriptPubKey that pays a destination. */
export function destinationScript(d: Destination): Uint8Array {
  if (d.kind === "p2pkh") return Uint8Array.from([0x76, 0xa9, 0x14, ...d.hash, 0x88, 0xac]);
  return Uint8Array.from([0xa9, 0x14, ...d.hash, 0x87]);
}
