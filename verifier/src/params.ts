/** Deployment parameters (SPEC.md §1). */
import type { ZcashNetwork } from "./zcash/address.ts";
import type { RequestKey } from "./private.ts";

export interface Issuer {
  /** a transparent P2PKH address on `zcash.network` */
  address: string;
  fromHeight: number;
  /** inclusive; absent while the issuer is current */
  toHeight?: number;
}
export interface FeeEntry {
  /** unix seconds */
  from: number;
  /** ZEC base units (8 decimals), as a decimal string */
  amount: string;
}
/** A published exit key (SPEC.md §10.1): order addresses are its external children `0/<index>`. */
export interface ExitKey {
  /** the exit key's account: 0 pays exits made on Sapling's site */
  account: number;
  /** 65 bytes, hex: the chain code, then the compressed secp256k1 public key */
  pubkey: string;
  fromHeight: number;
  /** inclusive; absent while the key is current */
  toHeight?: number;
}
export interface Params {
  solana: { programId: string; zecMint: string; tokenProgram: string; feeAccount: string; feeOwner: string };
  /** `requestKeys`: the keys private requests are sealed to (SPEC.md §9.2), append-only */
  /** `exitKeys`: the exit keys whose order addresses pay payout stamps (SPEC.md §10.1), append-only */
  zcash: { network: ZcashNetwork; issuers: Issuer[]; confirmations: number; requestKeys?: RequestKey[]; exitKeys?: ExitKey[] };
  fees: FeeEntry[];
  refundAfterDays: number;
}

export const MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
export const REDEEM_DISCRIMINATOR = Uint8Array.from([0xb8, 0x0c, 0x56, 0x95, 0x46, 0xc4, 0x61, 0xe1]);
export const REDEEMED_EVENT_DISCRIMINATOR = Uint8Array.from([0x0e, 0x1d, 0xb7, 0x47, 0x1f, 0xa5, 0x6b, 0x26]);
export const REQUEST_MEMO_PREFIX = "sapling-stamp:1:";
export const REFUND_MEMO_PREFIX = "sapling-stamp-refund:1:";
export const POSTAGE_ZAT = 546n;

/** Refuses parameter files that are incomplete (for example mainnet before its addresses exist). */
export function checkParams(p: Params): string[] {
  if (typeof p !== "object" || p === null || Array.isArray(p)) return ["the file is not a JSON object"];
  const isObject = (v: unknown) => typeof v === "object" && v !== null && !Array.isArray(v);
  const absent: string[] = [];
  if (!isObject(p.solana)) absent.push("solana is missing");
  if (!isObject(p.zcash)) absent.push("zcash is missing");
  else if (!Array.isArray(p.zcash.issuers)) absent.push("zcash.issuers is missing");
  if (!Array.isArray(p.fees)) absent.push("fees is missing");
  if (absent.length) return absent;
  const problems: string[] = [];
  const b58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
  for (const k of ["programId", "zecMint", "tokenProgram", "feeAccount", "feeOwner"] as const) if (!b58.test(p.solana[k] ?? "")) problems.push(`solana.${k} is not set`);
  if (p.zcash.network !== "mainnet" && p.zcash.network !== "testnet") problems.push("zcash.network must be mainnet or testnet");
  if (!p.zcash.issuers.length) problems.push("zcash.issuers is empty");
  if (!(p.zcash.confirmations >= 1)) problems.push("zcash.confirmations must be at least 1");
  if (!p.fees.length) problems.push("fees is empty");
  for (let i = 1; i < p.fees.length; i++) if (p.fees[i]!.from <= p.fees[i - 1]!.from) problems.push("fees must be in ascending order of `from`");
  for (const k of p.zcash.requestKeys ?? []) {
    if (!Number.isInteger(k.id) || k.id < 1 || k.id > 255) problems.push(`zcash.requestKeys: id ${k.id} is not 1 to 255`);
    if (!/^[0-9a-f]{64}$/.test(k.x25519 ?? "")) problems.push(`zcash.requestKeys: key ${k.id} is not 32 bytes of lowercase hex`);
    if (k.to !== undefined && k.to <= k.from) problems.push(`zcash.requestKeys: key ${k.id} ends before it starts`);
  }
  for (const k of p.zcash.exitKeys ?? []) {
    if (!Number.isInteger(k.account) || k.account < 0 || k.account > 255) problems.push(`zcash.exitKeys: account ${k.account} is not 0 to 255`);
    if (!/^[0-9a-f]{64}0[23][0-9a-f]{64}$/.test(k.pubkey ?? "")) problems.push(`zcash.exitKeys: account ${k.account}'s key is not 65 bytes of lowercase hex (chain code, compressed key)`);
    if (!Number.isInteger(k.fromHeight) || k.fromHeight < 1) problems.push(`zcash.exitKeys: account ${k.account}'s fromHeight is not a height`);
    if (k.toHeight !== undefined && !(Number.isInteger(k.toHeight) && k.toHeight >= k.fromHeight)) problems.push(`zcash.exitKeys: account ${k.account}'s key ends before it starts`);
  }
  return problems;
}

/** The smallest fee in force at any moment of [t − 86400, t] (SPEC.md §2 R5). */
export function requiredFee(fees: FeeEntry[], t: number): bigint | null {
  let min: bigint | null = null;
  for (let i = 0; i < fees.length; i++) {
    const start = fees[i]!.from;
    const end = i + 1 < fees.length ? fees[i + 1]!.from : Number.POSITIVE_INFINITY;
    if (start <= t && end > t - 86_400) {
      const a = BigInt(fees[i]!.amount);
      if (min === null || a < min) min = a;
    }
  }
  return min;
}
