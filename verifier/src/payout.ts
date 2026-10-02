/**
 * Payout stamps (SPEC.md §10): the exit memo on Solana, the order addresses derived from a published exit key,
 * and the version 3 record. The note and its receipt are shielded: only a payout stamp proof shows them (§10.5).
 */
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToNumberBE } from "@noble/curves/abstract/utils";
import { hmac } from "@noble/hashes/hmac";
import { sha256, sha512 } from "@noble/hashes/sha2";
import { base64urlnopad } from "@scure/base";
import type { ExitKey, Params } from "./params.ts";
import { RECORD_TAG } from "./record.ts";
import { hash160 } from "./zcash/tx.ts";

export const EXIT_MEMO_PREFIX = "sapling-exit:1:";
export const EXIT_SEALED_SIZE = 92;
export const RECORD_V3_VERSION = 3;
export const RECORD_V3_HASH_SIZE = 18;
export const RECORD_V3_MAX_EXITS = 4;
export const MAX_ORDER_INDEX = 2 ** 31 - 1;

/**
 * `sapling-exit:1:<kid>:<index>:<sealed>`: kid 1–255 and index 0 to 2^31 − 1 in decimal with no leading zeros,
 * sealed 92 bytes in canonical base64url without padding (SPEC.md §10.2, E2).
 */
export function parseExitMemo(memo: string): { kid: number; index: number; sealed: string } | { error: string } {
  const m = /^sapling-exit:1:([1-9][0-9]{0,2}):(0|[1-9][0-9]{0,9}):([A-Za-z0-9_-]{123})$/.exec(memo);
  if (!m) return { error: "E2: the memo is not sapling-exit:1:<kid>:<index>:<123 base64url characters>" };
  const kid = Number(m[1]);
  const index = Number(m[2]);
  if (kid > 255 || index > MAX_ORDER_INDEX) return { error: "E2: the key id or the order index is out of range" };
  let sealed: Uint8Array;
  try {
    sealed = base64urlnopad.decode(m[3]!);
  } catch {
    return { error: "E2: the seal is not base64url" };
  }
  if (sealed.length !== EXIT_SEALED_SIZE || base64urlnopad.encode(sealed) !== m[3]) return { error: "E2: the seal is not 92 bytes in canonical base64url" };
  return { kid, index, sealed: m[3]! };
}

const cat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) (out.set(p, at), (at += p.length));
  return out;
};
const u32be = (n: number) => Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);

/** BIP32 public child derivation (non-hardened). */
function child(key: Uint8Array, chainCode: Uint8Array, index: number): { key: Uint8Array; chainCode: Uint8Array } {
  const I = hmac(sha512, chainCode, cat(key, u32be(index)));
  const il = bytesToNumberBE(I.slice(0, 32));
  if (il === 0n || il >= secp256k1.CURVE.n) throw new Error("an invalid child key (BIP32: the next index is used)");
  const point = secp256k1.ProjectivePoint.BASE.multiply(il).add(secp256k1.ProjectivePoint.fromHex(key));
  if (point.equals(secp256k1.ProjectivePoint.ZERO)) throw new Error("an invalid child key (BIP32: the next index is used)");
  return { key: point.toRawBytes(true), chainCode: I.slice(32) };
}

/** Order `index`'s compressed public key under a 65-byte account public key (chain code, then key). */
export function orderPubkey(accountPubkey: Uint8Array, index: number): Uint8Array {
  if (accountPubkey.length !== 65) throw new Error("an exit key is 65 bytes");
  if (!Number.isInteger(index) || index < 0 || index > MAX_ORDER_INDEX) throw new Error("an order index is below 2^31");
  const external = child(accountPubkey.slice(32), accountPubkey.slice(0, 32), 0);
  return child(external.key, external.chainCode, index).key;
}

/** Order `index`'s P2PKH key hash. */
export function orderHash(accountPubkey: Uint8Array, index: number): Uint8Array {
  return hash160(orderPubkey(accountPubkey, index));
}

/** The exit keys of `account` valid at `height` (SPEC.md §10.1). */
export function exitKeysAt(p: Params, account: number, height: number): ExitKey[] {
  return (p.zcash.exitKeys ?? []).filter((k) => k.account === account && height >= k.fromHeight && (k.toHeight === undefined || height <= k.toHeight));
}

export function exitHash(sig: Uint8Array): Uint8Array {
  if (sig.length !== 64) throw new Error("a Solana signature is 64 bytes");
  return sha256(sig).slice(0, RECORD_V3_HASH_SIZE);
}

export function encodeRecordV3(sigs: Uint8Array[]): Uint8Array {
  if (sigs.length < 1 || sigs.length > RECORD_V3_MAX_EXITS) throw new Error(`a version 3 record names 1 to ${RECORD_V3_MAX_EXITS} exits`);
  return cat(RECORD_TAG, Uint8Array.of(RECORD_V3_VERSION), ...sigs.map(exitHash));
}

/** The OP_RETURN script of a version 3 record: `6a`, then one minimal push (`4c <len>` above 75 bytes). */
export function recordV3Script(record: Uint8Array): Uint8Array {
  return cat(Uint8Array.of(0x6a), record.length > 75 ? Uint8Array.of(0x4c, record.length) : Uint8Array.of(record.length), record);
}

/** The exit hashes of an OP_RETURN script that is exactly a version 3 record in its minimal push, or null. */
export function recordV3Hashes(script: Uint8Array): Uint8Array[] | null {
  let data: Uint8Array;
  if (script.length >= 3 && script[0] === 0x6a && script[1] === 0x4c && script[2]! > 75 && script.length === 3 + script[2]!) data = script.slice(3);
  else if (script.length >= 2 && script[0] === 0x6a && script[1]! >= 1 && script[1]! <= 75 && script.length === 2 + script[1]!) data = script.slice(2);
  else return null;
  for (let i = 0; i < 4; i++) if (data[i] !== RECORD_TAG[i]) return null;
  if (data[4] !== RECORD_V3_VERSION) return null;
  const body = data.slice(5);
  if (!body.length || body.length % RECORD_V3_HASH_SIZE !== 0 || body.length / RECORD_V3_HASH_SIZE > RECORD_V3_MAX_EXITS) return null;
  const out: Uint8Array[] = [];
  for (let i = 0; i < body.length; i += RECORD_V3_HASH_SIZE) out.push(body.slice(i, i + RECORD_V3_HASH_SIZE));
  return out;
}
