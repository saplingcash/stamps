/** Deployment parameters (SPEC.md §1). */
import type { ZcashNetwork } from "./zcash/address.ts";

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
export interface Params {
  solana: { programId: string; zecMint: string; tokenProgram: string; feeAccount: string; feeOwner: string };
  zcash: { network: ZcashNetwork; issuers: Issuer[]; confirmations: number };
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
  const problems: string[] = [];
  const b58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
  for (const k of ["programId", "zecMint", "tokenProgram", "feeAccount", "feeOwner"] as const) if (!b58.test(p.solana[k] ?? "")) problems.push(`solana.${k} is not set`);
  if (p.zcash.network !== "mainnet" && p.zcash.network !== "testnet") problems.push("zcash.network must be mainnet or testnet");
  if (!p.zcash.issuers.length) problems.push("zcash.issuers is empty");
  if (!(p.zcash.confirmations >= 1)) problems.push("zcash.confirmations must be at least 1");
  if (!p.fees.length) problems.push("fees is empty");
  for (let i = 1; i < p.fees.length; i++) if (p.fees[i]!.from <= p.fees[i - 1]!.from) problems.push("fees must be in ascending order of `from`");
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
