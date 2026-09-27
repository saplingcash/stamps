/**
 * Checking a stamp proof against both chains (SPEC.md §9.6): the proof's note and receipt (the
 * WebAssembly checker: issuer inputs, the private stamp's shape, the 546-zatoshi note, the receipt and
 * its record), the transaction mined with enough confirmations and spent by an issuer valid at its
 * height (the ledger's V3 for private stamps), and the receipt's amounts equal to the Solana harvest.
 * Two rules need every stamp and refund, not one: V4 (the first valid stamp of a request) and V5 (no
 * refund before it). Those are reported as not checked; the full verifier checks them.
 */
import { base64urlnopad } from "@scure/base";
import { check } from "../wasm/sapling_stamp_proof_wasm.js";
import { buildLedger, undeliverableReason } from "./ledger.ts";
import type { Params } from "./params.ts";
import { rpc } from "./rpc/jsonrpc.ts";
import { classify, type RpcTransaction } from "./solana/tx.ts";
import { bytesToHex } from "./zcash/tx.ts";
import { inspectTx } from "./zcash/inspect.ts";

export interface ProofResult {
  ok: boolean;
  error?: string;
  txid?: string;
  address?: string;
  harvest?: string;
  checked: string[];
  notChecked: string[];
}

export const NOT_CHECKED_HERE = [
  "V4: that this is the first valid stamp of its harvest (the full verifier reads every stamp)",
  "V5: that the harvest's fee was not refunded before this stamp (the full verifier reads every refund)",
];

/**
 * A spent coin's value in zatoshi from the node's verbose getrawtransaction: `vout[n].valueZat` (zcashd and
 * Zebra), else `value` in ZEC converted exactly from its decimal text.
 */
export async function spentValue(zcashUrl: string, txid: string, n: number): Promise<bigint | null> {
  const prev = await rpc<{ txid?: string; vout?: { n?: number; value?: number | string; valueZat?: number | string }[] }>(zcashUrl, "getrawtransaction", [txid, 1]);
  if (prev.txid !== undefined && prev.txid !== txid) return null;
  const out = (prev.vout ?? []).find((o, i) => (o.n ?? i) === n);
  if (!out) return null;
  if (out.valueZat !== undefined && /^\d+$/.test(String(out.valueZat))) return BigInt(String(out.valueZat));
  const m = /^(\d+)(?:\.(\d{1,8}))?$/.exec(String(out.value ?? ""));
  return m ? BigInt(m[1]!) * 100_000_000n + BigInt((m[2] ?? "").padEnd(8, "0")) : null;
}

/** The txid a proof names (displayed order). */
export function proofTxid(proof: string): string {
  const body = proof.trim().replace(/^splg-proof:1:/, "");
  const b = base64urlnopad.decode(body);
  if (b.length !== 117) throw new Error("not a stamp proof");
  return bytesToHex(b.slice(0, 32).reverse());
}

export async function checkProof(p: Params, proof: string, solanaUrl: string, zcashUrl: string, now = Math.floor(Date.now() / 1000)): Promise<ProofResult> {
  const checked: string[] = [];
  const fail = (error: string): ProofResult => ({ ok: false, error, checked, notChecked: NOT_CHECKED_HERE });
  let txid: string;
  try {
    txid = proofTxid(proof);
  } catch (e) {
    return fail((e as Error).message);
  }
  const t = await rpc<{ hex: string; height?: number; confirmations?: number }>(zcashUrl, "getrawtransaction", [txid, 1]);
  const height = typeof t.height === "number" && t.height >= 0 ? t.height : null;
  if (height === null || (t.confirmations ?? 0) < p.zcash.confirmations) return fail(`the transaction is not mined with ${p.zcash.confirmations} confirmations yet`);
  checked.push(`the transaction is mined at ${height}, with ${t.confirmations} confirmations`);

  // the note and the receipt, against the issuers valid at that height
  const valid = { ...p, zcash: { ...p.zcash, issuers: p.zcash.issuers.filter((i) => height >= i.fromHeight && (i.toHeight === undefined || height <= i.toHeight)) } };
  if (!valid.zcash.issuers.length) return fail("no issuer was valid at the transaction's height");
  // the values of the coins it spends, from the node's own transaction details (any transaction version:
  // a coin may come from a v4 transaction), so the checker verifies the issuer's signatures (they are not in
  // the txid: the bytes' scriptSigs alone prove nothing). A wrong value can only fail a genuine stamp.
  const spent: string[] = [];
  for (const i of inspectTx(t.hex).inputs) {
    const value = await spentValue(zcashUrl, i.prevTxid, i.prevIndex);
    if (value === null) return fail(`the node gave no value for the spent coin ${i.prevTxid}:${i.prevIndex}`);
    spent.push(value.toString());
  }
  let shown: { txid: string; address: string; value: number; issuerVerified: boolean; receipt: { burned: string; harvested: string; fee: string; signature: string }; checked: string[] };
  try {
    shown = JSON.parse(check(t.hex, proof, JSON.stringify(valid), spent.join(",")));
  } catch (e) {
    return fail(String((e as Error).message ?? e));
  }
  if (!shown.issuerVerified) return fail("the issuer's signatures were not verified");
  if (shown.txid !== txid) return fail("the node returned another transaction");
  checked.push(...shown.checked, "the issuer key was valid at the transaction's height");

  // the harvest on Solana: a private request, deliverable, with exactly the receipt's amounts
  const sig = shown.receipt.signature;
  const tx = await rpc<RpcTransaction | null>(solanaUrl, "getTransaction", [sig, { encoding: "json", maxSupportedTransactionVersion: 0, commitment: "finalized" }]);
  if (!tx) return fail("the receipt's harvest is not a finalized Solana transaction");
  const c = classify(tx, p);
  if (c.kind !== "request") return fail(`the receipt's harvest is not a stamp request (${c.kind === "other" ? c.reason : c.kind})`);
  const r = c.request;
  if (r.mode !== "private") return fail("the receipt's harvest asked for a public stamp");
  const undeliverable = undeliverableReason(p, r);
  if (undeliverable) return fail(`the receipt's harvest is undeliverable: ${undeliverable}`);
  if (BigInt(shown.receipt.burned) !== r.burned || BigInt(shown.receipt.harvested) !== r.harvested || BigInt(shown.receipt.fee) !== r.feePaid) return fail("the receipt's amounts are not the harvest's (Redeemed event and fee)");
  checked.push("the receipt's harvest is a finalized, deliverable private request, and its burned, harvested and fee amounts are the Redeemed event's and the fee transfer's");

  // the ledger's own rule for private stamps, on this one transaction
  const l = buildLedger(p, [r], [], [{ txid, height, index: 0, confirmations: t.confirmations ?? 0, rawHex: t.hex }], now);
  if (l.stamps.length !== 1) return fail(`the ledger does not take it as a stamp: ${l.rejected[0]?.reason ?? "?"}`);
  checked.push("the ledger's rules V1-V3 for private stamps accept it");
  return { ok: true, txid, address: shown.address, harvest: sig, checked, notChecked: NOT_CHECKED_HERE };
}
