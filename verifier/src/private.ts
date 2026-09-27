/**
 * Private stamps (SPEC.md §9): the request memo that carries a sealed receiver, and the version 2
 * record. The seal itself is opaque here: only the stamper can open it.
 */
import { base64urlnopad } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2";
import { RECORD_TAG } from "./record.ts";

export const PRIVATE_MEMO_PREFIX = "sapling-stamp:2:";
export const SEALED_SIZE = 92;
export const RECORD_V2_VERSION = 2;
export const RECORD_V2_SIZE = 23;
export const RECORD_V2_HASH_SIZE = 18;

export interface RequestKey {
  id: number;
  /** X25519 public key, hex */
  x25519: string;
  /** unix seconds */
  from: number;
  /** unix seconds, exclusive; absent while the key is current */
  to?: number;
}

/**
 * `sapling-stamp:2:<kid>:<sealed>`: kid is 1–255 in decimal (no leading zeros), sealed is 92 bytes in
 * base64url without padding (123 characters).
 */
export function parsePrivateMemo(memo: string): { kid: number; sealed: Uint8Array } | { error: string } {
  if (!memo.startsWith(PRIVATE_MEMO_PREFIX)) return { error: "not a private request" };
  const m = /^([1-9][0-9]{0,2}):([A-Za-z0-9_-]{123})$/.exec(memo.slice(PRIVATE_MEMO_PREFIX.length));
  if (!m) return { error: "R4: the private request is not <kid>:<123 base64url characters>" };
  const kid = Number(m[1]);
  if (kid > 255) return { error: "R4: the key id exceeds 255" };
  let sealed: Uint8Array;
  try {
    sealed = base64urlnopad.decode(m[2]!);
  } catch {
    return { error: "R4: the seal is not base64url" };
  }
  if (sealed.length !== SEALED_SIZE || base64urlnopad.encode(sealed) !== m[2]) return { error: "R4: the seal is not 92 bytes in canonical base64url" };
  return { kid, sealed };
}

export function privateMemo(kid: number, sealed: Uint8Array): string {
  if (!Number.isInteger(kid) || kid < 1 || kid > 255) throw new Error("the key id must be 1 to 255");
  if (sealed.length !== SEALED_SIZE) throw new Error("a seal is 92 bytes");
  return `${PRIVATE_MEMO_PREFIX}${kid}:${base64urlnopad.encode(sealed)}`;
}

/** The request key with this id in force at `t`, if any. */
export function requestKeyInForce(keys: RequestKey[] | undefined, kid: number, t: number): RequestKey | null {
  return (keys ?? []).find((k) => k.id === kid && k.from <= t && (k.to === undefined || t < k.to)) ?? null;
}

export function signatureHashV2(sig: Uint8Array): Uint8Array {
  if (sig.length !== 64) throw new Error("a Solana signature is 64 bytes");
  return sha256(sig).slice(0, RECORD_V2_HASH_SIZE);
}

export function encodeRecordV2(sig: Uint8Array): Uint8Array {
  const out = new Uint8Array(RECORD_V2_SIZE);
  out.set(RECORD_TAG, 0);
  out[4] = RECORD_V2_VERSION;
  out.set(signatureHashV2(sig), 5);
  return out;
}

/** The data of an OP_RETURN output of the form `6a 17 <23 bytes>` that is a version 2 record, or null. */
export function recordV2Hash(script: Uint8Array): Uint8Array | null {
  if (script.length !== 2 + RECORD_V2_SIZE || script[0] !== 0x6a || script[1] !== RECORD_V2_SIZE) return null;
  for (let i = 0; i < 4; i++) if (script[2 + i] !== RECORD_TAG[i]) return null;
  if (script[6] !== RECORD_V2_VERSION) return null;
  return script.slice(7);
}
