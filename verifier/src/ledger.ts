/**
 * The ledger (SPEC.md §3, §6, §7): given the requests and refunds read from Solana and the issuer's
 * transactions read from Zcash, decide which are valid stamps, the state of every request, and whether
 * the invariant holds. Pure: no network.
 */
import { base58 } from "@scure/base";
import { decodeRecord, signatureHash } from "./record.ts";
import { recordV2Hash, requestKeyInForce, signatureHashV2 } from "./private.ts";
import { inspectTx, type Inspected } from "./zcash/inspect.ts";
import { decodeAddress, destinationScript } from "./zcash/address.ts";
import { bytesToHex, equalBytes, hexToBytes, isOpReturn, p2pkhSpenderHash, parseTransparent, recordPayload } from "./zcash/tx.ts";
import { POSTAGE_ZAT, type Params } from "./params.ts";
import type { Refund, Request } from "./solana/tx.ts";

export interface ZcashTxInfo {
  txid: string;
  /** block height; null if not mined */
  height: number | null;
  /** position in its block (0 = coinbase) */
  index: number;
  confirmations: number;
  rawHex: string;
  /** its block's time (unix seconds), for V5; a reader that cannot give it leaves V5 unchecked */
  time?: number;
}

export interface Stamp {
  id: string;
  height: number;
  request: string;
  mint: string;
  ticker: string;
  burned: bigint;
  harvested: bigint;
  fee: bigint;
  received: bigint;
  /** empty for a private stamp: its receiver is shielded */
  address: string;
  mode: "public" | "private";
}
export type State = "stamped" | "refunded" | "pending" | "overdue" | "unresolved";
export interface Rejected {
  txid: string;
  reason: string;
}
export interface Ledger {
  stamps: Stamp[];
  states: { request: string; state: State; undeliverable?: string }[];
  rejected: Rejected[];
  totals: { requests: number; stamped: number; refunded: number; pending: number; overdue: number; unresolved: number; feesPaid: bigint; refundedAmount: bigint };
  invariant: { ok: boolean; problems: string[] };
}

function issuerHashes(p: Params, height: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (const i of p.zcash.issuers) {
    if (height < i.fromHeight || (i.toHeight !== undefined && height > i.toHeight)) continue;
    const d = decodeAddress(i.address, p.zcash.network);
    if (d.ok && d.destination.kind === "p2pkh") out.push(d.destination.hash);
  }
  return out;
}

/** Why a request cannot receive a stamp, or undefined if it can (SPEC.md §2, §9.2). */
export function undeliverableReason(p: Params, r: Request): string | undefined {
  if (r.mode === "private") {
    // a fee above the harvested amount leaves nothing to receive (SPEC.md §9.1)
    if (r.feePaid > r.harvested) return "the fee exceeds the harvested amount";
    return requestKeyInForce(p.zcash.requestKeys, r.kid ?? 0, r.blockTime) ? undefined : "no request key with this id was in force at the harvest's time";
  }
  const dest = decodeAddress(r.address, p.zcash.network);
  return dest.ok ? undefined : dest.reason;
}

function txVersion(rawHex: string): number {
  const b = hexToBytes(rawHex.slice(0, 8));
  return (b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) & 0x7fffffff;
}

export function buildLedger(p: Params, requests: Request[], refunds: Refund[], zcashTxs: ZcashTxInfo[], now: number, unresolvedRequests: string[] = []): Ledger {
  const rejected: Rejected[] = [];
  // requests by the hash the record carries; a hash shared by two requests matches neither (V1)
  const byHash = new Map<string, Request[]>();
  const byHashV2 = new Map<string, Request[]>();
  for (const r of requests) {
    const sig = base58.decode(r.signature);
    const h = bytesToHex(signatureHash(sig));
    byHash.set(h, [...(byHash.get(h) ?? []), r]);
    const h2 = bytesToHex(signatureHashV2(sig));
    byHashV2.set(h2, [...(byHashV2.get(h2) ?? []), r]);
  }

  // refunds that match their request exactly (SPEC.md §5), the earliest per request
  const reqBySig = new Map(requests.map((r) => [r.signature, r]));
  const refundedAt = new Map<string, number>();
  let refundedAmount = 0n;
  for (const f of [...refunds].sort((a, b) => a.blockTime - b.blockTime)) {
    const r = reqBySig.get(f.requestSignature);
    if (!r || f.to !== r.source || f.amount !== r.feePaid) continue;
    if (refundedAt.has(r.signature)) continue;
    refundedAt.set(r.signature, f.blockTime);
    refundedAmount += f.amount;
  }
  const refunded = new Set(refundedAt.keys());

  // candidates in chain order (V4)
  const ordered = [...zcashTxs].sort((a, b) => (a.height ?? Infinity) - (b.height ?? Infinity) || a.index - b.index);
  const stampOf = new Map<string, Stamp>();
  for (const z of ordered) {
    if (z.height === null || z.confirmations < p.zcash.confirmations) {
      rejected.push({ txid: z.txid, reason: "Z1: not final yet" });
      continue;
    }
    const version = z.rawHex.length >= 8 ? txVersion(z.rawHex) : 0;
    if (version === 6) {
      const r = privateCandidate(p, z, byHashV2, refundedAt, stampOf, rejected);
      if (r) stampOf.set(r.request, r);
      continue;
    }
    let tx;
    try {
      tx = parseTransparent(hexToBytes(z.rawHex));
    } catch (e) {
      rejected.push({ txid: z.txid, reason: `Z2: ${(e as Error).message}` });
      continue;
    }
    const issuers = issuerHashes(p, z.height);
    const fromIssuer = tx.inputs.length > 0 && tx.inputs.every((i) => {
      const h = p2pkhSpenderHash(i.scriptSig);
      return h !== null && issuers.some((k) => equalBytes(k, h));
    });
    if (!fromIssuer) {
      rejected.push({ txid: z.txid, reason: "Z2: not spent by an issuer valid at this height" });
      continue;
    }
    const opReturns = tx.outputs.filter((o) => isOpReturn(o.script));
    if (opReturns.length !== 1) {
      rejected.push({ txid: z.txid, reason: `Z3: ${opReturns.length} OP_RETURN outputs` });
      continue;
    }
    const payload = recordPayload(opReturns[0]!.script);
    if (!payload) {
      rejected.push({ txid: z.txid, reason: "Z3: the OP_RETURN is not 6a 34 <52 bytes>" });
      continue;
    }
    const rec = decodeRecord(payload);
    if ("error" in rec) {
      rejected.push({ txid: z.txid, reason: `Z3: ${rec.error}` });
      continue;
    }
    const matches = byHash.get(bytesToHex(rec.sigHash)) ?? [];
    if (matches.length !== 1) {
      rejected.push({ txid: z.txid, reason: matches.length ? "V1: the signature hash matches more than one request" : "V1: no request has this signature hash" });
      continue;
    }
    const r = matches[0]!;
    if (r.mode !== "public") {
      rejected.push({ txid: z.txid, reason: "V3: a version 1 record for a private request" });
      continue;
    }
    if (rec.burned !== r.burned || rec.harvested !== r.harvested) {
      rejected.push({ txid: z.txid, reason: "V2: burned or harvested differs from the Redeemed event" });
      continue;
    }
    const dest = decodeAddress(r.address, p.zcash.network);
    if (!dest.ok) {
      rejected.push({ txid: z.txid, reason: `V3: the request's address is undeliverable (${dest.reason})` });
      continue;
    }
    const script = destinationScript(dest.destination);
    if (!tx.outputs.some((o) => o.value >= POSTAGE_ZAT && equalBytes(o.script, script))) {
      rejected.push({ txid: z.txid, reason: "V3: no output of at least 546 zatoshi to the request's address" });
      continue;
    }
    const refundTime = refundedAt.get(r.signature);
    if (refundTime !== undefined && z.time !== undefined && z.time > refundTime) {
      rejected.push({ txid: z.txid, reason: "V5: mined after the request was refunded" });
      continue;
    }
    if (stampOf.has(r.signature)) {
      rejected.push({ txid: z.txid, reason: `V4: a duplicate; the stamp of this request is ${stampOf.get(r.signature)!.id}` });
      continue;
    }
    stampOf.set(r.signature, { id: z.txid, height: z.height, request: r.signature, mint: r.mint, ticker: rec.ticker, burned: r.burned, harvested: r.harvested, fee: r.feePaid, received: r.harvested - r.feePaid, address: r.address, mode: "public" });
  }


  const unresolved = new Set(unresolvedRequests);
  const problems: string[] = [];
  const states: Ledger["states"] = requests.map((r) => {
    const undeliverable = undeliverableReason(p, r);
    let state: State;
    if (unresolved.has(r.signature)) state = "unresolved";
    else if (stampOf.has(r.signature)) {
      state = "stamped";
      if (refunded.has(r.signature)) problems.push(`${r.signature} is both stamped and refunded`);
    } else if (refunded.has(r.signature)) state = "refunded";
    else state = now - r.blockTime >= p.refundAfterDays * 86_400 ? "overdue" : "pending";
    if (state === "overdue") problems.push(`${r.signature} is overdue (${undeliverable ? `undeliverable: ${undeliverable}` : "no stamp"}, no refund)`);
    return { request: r.signature, state, ...(undeliverable ? { undeliverable } : {}) };
  });
  // a transaction that could not be read may be a request: it is reported, never guessed
  for (const s of unresolved) if (!reqBySig.has(s)) states.push({ request: s, state: "unresolved" });
  const count = (s: State) => states.filter((x) => x.state === s).length;
  return {
    stamps: [...stampOf.values()],
    states,
    rejected,
    totals: {
      requests: requests.length,
      stamped: count("stamped"),
      refunded: count("refunded"),
      pending: count("pending"),
      overdue: count("overdue"),
      unresolved: count("unresolved"),
      feesPaid: requests.reduce((a, r) => a + r.feePaid, 0n),
      refundedAmount,
    },
    invariant: { ok: problems.length === 0, problems },
  };
}

/**
 * A v6 transaction as a private stamp (SPEC.md §9.4): spent by an issuer; exactly one OP_RETURN, a
 * version 2 record naming exactly one request, which is private and deliverable; exactly 546 zatoshi
 * into the Ironwood pool and no Sapling, Sprout or Orchard part; every other transparent output pays an
 * issuer (its change). Who receives the note is shielded: only its holder can show it (§9.6).
 */
function privateCandidate(p: Params, z: ZcashTxInfo, byHashV2: Map<string, Request[]>, refundedAt: Map<string, number>, stampOf: Map<string, Stamp>, rejected: Rejected[]): Stamp | null {
  const reject = (reason: string) => {
    rejected.push({ txid: z.txid, reason });
    return null;
  };
  let t: Inspected;
  try {
    t = inspectTx(z.rawHex);
  } catch (e) {
    if (/not loaded/.test((e as Error).message)) throw e;
    return reject(`Z2: ${(e as Error).message}`);
  }
  if (t.txid !== z.txid) return reject("Z2: the transaction's own txid is not the one listed");
  const issuers = issuerHashes(p, z.height!);
  const isIssuer = (h: Uint8Array | null) => h !== null && issuers.some((k) => equalBytes(k, h));
  if (!t.inputs.length || !t.inputs.every((i) => isIssuer(p2pkhSpenderHash(hexToBytes(i.scriptSig))))) return reject("Z2: not spent by an issuer valid at this height");
  const outs = t.outputs.map((o) => ({ value: BigInt(o.value), script: hexToBytes(o.script) }));
  const opReturns = outs.filter((o) => isOpReturn(o.script));
  if (opReturns.length !== 1) return reject(`Z3: ${opReturns.length} OP_RETURN outputs`);
  const hash = recordV2Hash(opReturns[0]!.script);
  if (!hash) return reject("Z3: the OP_RETURN of a v6 transaction is not a version 2 record (6a 17 <23 bytes>)");
  const matches = byHashV2.get(bytesToHex(hash)) ?? [];
  if (matches.length !== 1) return reject(matches.length ? "V1: the signature hash matches more than one request" : "V1: no request has this signature hash");
  const r = matches[0]!;
  if (r.mode !== "private") return reject("V3: a version 2 record for a public request");
  const undeliverable = undeliverableReason(p, r);
  if (undeliverable) return reject(`V3: the request is undeliverable (${undeliverable})`);
  if (t.sapling || t.sprout || t.orchard) return reject("V3: the transaction has a Sapling, Sprout or Orchard part");
  if (!t.ironwood || BigInt(t.ironwood.valueBalance) !== -POSTAGE_ZAT) return reject("V3: the transaction does not put exactly 546 zatoshi into the Ironwood pool");
  const change = outs.filter((o) => !isOpReturn(o.script));
  if (!change.every((o) => issuers.some((k) => equalBytes(o.script, destinationScript({ kind: "p2pkh", hash: k }))))) return reject("V3: a transparent output pays someone other than an issuer");
  const refundTime = refundedAt.get(r.signature);
  if (refundTime !== undefined && z.time !== undefined && z.time > refundTime) return reject("V5: mined after the request was refunded");
  if (stampOf.has(r.signature)) return reject(`V4: a duplicate; the stamp of this request is ${stampOf.get(r.signature)!.id}`);
  return { id: z.txid, height: z.height!, request: r.signature, mint: r.mint, ticker: "", burned: r.burned, harvested: r.harvested, fee: r.feePaid, received: r.harvested - r.feePaid, address: "", mode: "private" };
}
