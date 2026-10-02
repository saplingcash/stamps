/** Reads the fee account's history from a Solana RPC and classifies each transaction (SPEC.md §2, §5). */
import { rpc } from "./jsonrpc.ts";
import { classify, classifyExit, type ExitRequest, type Refund, type Request, type RpcTransaction } from "../solana/tx.ts";
import type { Params } from "../params.ts";

export interface SolanaRead {
  requests: Request[];
  refunds: Refund[];
  /** signatures whose transaction could not be read: their requests (if any) are unresolved */
  unreadable: string[];
  ignored: { signature: string; reason: string }[];
}

export async function readSolana(url: string, p: Params, log: (s: string) => void = () => {}): Promise<SolanaRead> {
  const sigs: string[] = [];
  let before: string | undefined;
  for (;;) {
    const page = await rpc<{ signature: string; err: unknown }[]>(url, "getSignaturesForAddress", [p.solana.feeAccount, { limit: 1000, commitment: "finalized", ...(before ? { before } : {}) }]);
    if (!page.length) break;
    for (const s of page) if (s.err === null) sigs.push(s.signature);
    before = page[page.length - 1]!.signature;
    if (page.length < 1000) break;
  }
  log(`solana: ${sigs.length} successful transactions touch the fee account`);
  const out: SolanaRead = { requests: [], refunds: [], unreadable: [], ignored: [] };
  for (const sig of sigs) {
    let tx: RpcTransaction | null = null;
    try {
      tx = await rpc<RpcTransaction | null>(url, "getTransaction", [sig, { encoding: "json", maxSupportedTransactionVersion: 0, commitment: "finalized" }]);
    } catch {
      /* unreadable below */
    }
    if (!tx) {
      out.unreadable.push(sig);
      continue;
    }
    const c = classify(tx, p);
    if (c.kind === "request") out.requests.push(c.request);
    else if (c.kind === "refund") out.refunds.push(c.refund);
    else out.ignored.push({ signature: sig, reason: c.reason });
  }
  return out;
}

export interface ExitsRead {
  exits: ExitRequest[];
  unreadable: string[];
  ignored: { signature: string; reason: string }[];
}

/**
 * Reads the given exit transactions (SPEC.md §10.2). An exit names no account of Sapling's on Solana, so the
 * exits to check are given; the Zcash side is complete on its own: every payout transaction from an order
 * address must name given exits, or it is reported (`buildPayoutLedger`, V1).
 */
export async function readExitRequests(url: string, p: Params, signatures: string[]): Promise<ExitsRead> {
  const out: ExitsRead = { exits: [], unreadable: [], ignored: [] };
  for (const sig of [...new Set(signatures)]) {
    let tx: RpcTransaction | null = null;
    try {
      tx = await rpc<RpcTransaction | null>(url, "getTransaction", [sig, { encoding: "json", maxSupportedTransactionVersion: 0, commitment: "finalized" }]);
    } catch {
      /* unreadable below */
    }
    if (!tx) {
      out.unreadable.push(sig);
      continue;
    }
    const c = classifyExit(tx, p);
    if (c.kind === "exit") out.exits.push(c.exit);
    else out.ignored.push({ signature: sig, reason: c.reason });
  }
  return out;
}
