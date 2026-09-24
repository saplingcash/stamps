/**
 * The verifier on REAL transactions, not built ones (fixtures/live-localnet-testnet.json): a stamped
 * harvest sent through the site to a local validator running the vault program with the real SPL Token
 * and Memo programs, an undeliverable request and its refund by the fee wallet, and the Zcash testnet
 * stamp answering the harvest. Builders can only repeat what the tests assume (a wrong program id
 * included); these transactions come from the programs themselves.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildLedger } from "../src/ledger.ts";
import { MEMO_PROGRAM, type Params } from "../src/params.ts";
import { classify, type RpcTransaction } from "../src/solana/tx.ts";

const f = JSON.parse(readFileSync(join(import.meta.dirname, "fixtures", "live-localnet-testnet.json"), "utf8")) as {
  params: Params;
  solana: { harvest: RpcTransaction; undeliverable: RpcTransaction; refund: RpcTransaction };
  zcash: { txid: string; height: number; index: number; rawHex: string };
};

describe("real transactions", () => {
  it("the real harvest names the programs the rules name (SPL Memo v2, SPL Token)", () => {
    const keys = f.solana.harvest.transaction.message.accountKeys;
    const programs = f.solana.harvest.transaction.message.instructions.map((i) => keys[i.programIdIndex]);
    expect(programs).toContain(MEMO_PROGRAM);
    expect(programs).toContain(f.params.solana.tokenProgram);
    expect(programs).toContain(f.params.solana.programId);
  });

  it("classifies the stamped harvest as a request, with the amounts of its Redeemed event", () => {
    const c = classify(f.solana.harvest, f.params);
    expect(c.kind).toBe("request");
    if (c.kind !== "request") return;
    expect(c.request).toMatchObject({ feePaid: 40_000n, burned: 33_553_707_981_674n, harvested: 100_710_012n });
    expect(c.request.address.startsWith("utest1")).toBe(true);
  });

  it("classifies the refund, and the ledger over both chains is stamped + refunded with the invariant holding", () => {
    const requests = [f.solana.harvest, f.solana.undeliverable].map((t) => {
      const c = classify(t, f.params);
      if (c.kind !== "request") throw new Error(c.kind === "other" ? c.reason : "not a request");
      return c.request;
    });
    const r = classify(f.solana.refund, f.params);
    expect(r.kind).toBe("refund");
    if (r.kind !== "refund") return;
    expect(r.refund).toMatchObject({ requestSignature: requests[1]!.signature, amount: 40_000n, to: requests[1]!.source });
    const ledger = buildLedger(f.params, requests, [r.refund], [{ txid: f.zcash.txid, height: f.zcash.height, index: f.zcash.index, confirmations: 20, rawHex: f.zcash.rawHex }], 1_800_000_000);
    expect(ledger.stamps.map((s) => s.id)).toEqual([f.zcash.txid]);
    expect(ledger.stamps[0]).toMatchObject({ request: requests[0]!.signature, fee: 40_000n, received: 100_670_012n });
    expect(ledger.totals).toMatchObject({ requests: 2, stamped: 1, refunded: 1, pending: 0, overdue: 0 });
    expect(ledger.invariant.ok).toBe(true);
  });
});
