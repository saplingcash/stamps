/**
 * F4Jumble and its inverse (ZIP 316, "Jumbling"): an unkeyed 4-round Feistel construction over BLAKE2b.
 * Written from the specification text.
 */
import { blake2b } from "@noble/hashes/blake2b";

const L_H = 64;
const MIN = 38;
const MAX = (2 ** 16 + 1) * L_H;
const enc = new TextEncoder();

function personal(prefix: string, tail: number[]): Uint8Array {
  const p = new Uint8Array(16);
  p.set(enc.encode(prefix), 0);
  p.set(tail, 13);
  return p;
}

/** H_i(u) = BLAKE2b-(8·lenL)("UA_F4Jumble_H" || [i, 0, 0], u) */
function H(i: number, u: Uint8Array, lenL: number): Uint8Array {
  return blake2b(u, { dkLen: lenL, personalization: personal("UA_F4Jumble_H", [i, 0, 0]) });
}

/** G_i(u): the first lenR bytes of BLAKE2b-512("UA_F4Jumble_G" || [i] || I2LEOSP16(j), u) for j = 0, 1, … */
function G(i: number, u: Uint8Array, lenR: number): Uint8Array {
  const out = new Uint8Array(lenR);
  for (let j = 0, off = 0; off < lenR; j++, off += L_H) {
    const block = blake2b(u, { dkLen: 64, personalization: personal("UA_F4Jumble_G", [i, j & 0xff, (j >> 8) & 0xff]) });
    out.set(block.subarray(0, Math.min(L_H, lenR - off)), off);
  }
  return out;
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const o = new Uint8Array(a.length);
  for (let k = 0; k < a.length; k++) o[k] = a[k]! ^ b[k]!;
  return o;
}

function split(m: Uint8Array): [Uint8Array, Uint8Array, number, number] {
  if (m.length < MIN || m.length > MAX) throw new Error(`F4Jumble input must be ${MIN}..${MAX} bytes`);
  const lenL = Math.min(L_H, Math.floor(m.length / 2));
  const lenR = m.length - lenL;
  return [m.slice(0, lenL), m.slice(lenL), lenL, lenR];
}

export function f4jumble(m: Uint8Array): Uint8Array {
  const [a, b, lenL, lenR] = split(m);
  const x = xor(b, G(0, a, lenR));
  const y = xor(a, H(0, x, lenL));
  const d = xor(x, G(1, y, lenR));
  const c = xor(y, H(1, d, lenL));
  const out = new Uint8Array(m.length);
  out.set(c, 0);
  out.set(d, lenL);
  return out;
}

export function f4jumbleInv(m: Uint8Array): Uint8Array {
  const [c, d, lenL, lenR] = split(m);
  const y = xor(c, H(1, d, lenL));
  const x = xor(d, G(1, y, lenR));
  const a = xor(y, H(0, x, lenL));
  const b = xor(x, G(0, a, lenR));
  const out = new Uint8Array(m.length);
  out.set(a, 0);
  out.set(b, lenL);
  return out;
}
