/**
 * check-proof (SPEC.md §9.6) against a local JSON-RPC server that answers from a real private stamp mined
 * on Zcash testnet and a Solana harvest built here; plus the fee-above-payout rule (§9.1).
 */
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checkProof, proofTxid } from "../src/checkproof.ts";
import { undeliverableReason } from "../src/ledger.ts";
import { classify, type RpcTransaction } from "../src/solana/tx.ts";
import { loadInspectorFromDisk } from "../src/zcash/inspect.ts";
import { check } from "../wasm/sapling_stamp_proof_wasm.js";
import { fakeKey, harvestTx, testParams } from "./helpers/builders.ts";
import type { Params } from "../src/params.ts";

const fx = JSON.parse(readFileSync(join(import.meta.dirname, "fixtures/private-testnet-stamp.json"), "utf8")) as { txid: string; height: number; issuerAddress: string; requestSignature: string; requestPublic: string; proof: string; txHex: string; spentTxid: string; spentTxHex: string };
const SEALED = "A".repeat(123);
// the receipt in the fixture's note
const RECEIPT = { burned: 1_250_000_000_000n, harvested: 1_234_567n, fee: 40_000n };

function params(issuer = fx.issuerAddress): Params {
  const p = testParams({}, [issuer]);
  return { ...p, zcash: { ...p.zcash, requestKeys: [{ id: 1, x25519: fx.requestPublic, from: 0 }] } };
}
const harvest = (p: Params, over: { harvested?: bigint; memo?: string } = {}) =>
  harvestTx(p, { signature: fx.requestSignature, burned: RECEIPT.burned, harvested: over.harvested ?? RECEIPT.harvested, fee: RECEIPT.fee, memo: over.memo ?? `sapling-stamp:2:1:${SEALED}` });

let server: Server;
let url = "";
let solana: RpcTransaction | null = null;
let confirmations = 20;
let spentVersion = 5;
let spentOut: Record<string, unknown> = { n: 0, value: 0.01, valueZat: 1_000_000 };
beforeAll(async () => {
  await loadInspectorFromDisk();
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      const { method, params: args } = JSON.parse(body) as { method: string; params: unknown[] };
      const reply = (result: unknown) => res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result }));
      if (method === "getrawtransaction" && args[0] === fx.txid) return reply({ hex: fx.txHex, height: fx.height, confirmations });
      // the spent coin as the node details it (the value only: its bytes are not parsed, whatever their version)
      if (method === "getrawtransaction" && args[0] === fx.spentTxid) return reply({ txid: fx.spentTxid, version: spentVersion, vout: [spentOut], confirmations: confirmations + 2 });
      if (method === "getTransaction" && args[0] === fx.requestSignature) return reply(solana);
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: -5, message: "not found" } }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
afterAll(() => server.close());

describe("check-proof (SPEC.md §9.6)", () => {
  it("names the proof's transaction", () => {
    expect(proofTxid(fx.proof)).toBe(fx.txid);
  });
  it("holds for the real stamp, its harvest and its amounts, and says what it did not check", async () => {
    const p = params();
    solana = harvest(p);
    confirmations = 20;
    const r = await checkProof(p, fx.proof, url, url);
    expect(r.error).toBeUndefined();
    expect(r.ok).toBe(true);
    expect(r.checked.join("\n")).toMatch(/signature verifies with the published issuer key/);
    expect(r.checked.join("\n")).toMatch(/amounts are the Redeemed event's/);
    expect(r.notChecked.join("\n")).toMatch(/V4/);
    expect(r.notChecked.join("\n")).toMatch(/V5/);
  });
  it("fails when the harvest's amounts differ from the receipt's", async () => {
    const p = params();
    solana = harvest(p, { harvested: RECEIPT.harvested + 1n });
    expect(await checkProof(p, fx.proof, url, url)).toMatchObject({ ok: false, error: expect.stringMatching(/amounts/) });
  });
  it("fails for a harvest that asked for a public stamp", async () => {
    const p = params();
    solana = harvest(p, { memo: `sapling-stamp:1:${fx.issuerAddress}` });
    expect(await checkProof(p, fx.proof, url, url)).toMatchObject({ ok: false, error: expect.stringMatching(/public stamp/) });
  });
  it("fails when the transaction is not the published issuer's", async () => {
    const p = params(fakeKey().address("testnet"));
    solana = harvest(p);
    expect(await checkProof(p, fx.proof, url, url)).toMatchObject({ ok: false, error: expect.stringMatching(/not spent by a published issuer key/) });
  });
  it("reads the spent coin's value from the node's details, whatever the funding transaction's version (v4 too)", async () => {
    const p = params();
    solana = harvest(p);
    spentVersion = 4;
    spentOut = { n: 0, value: 0.01, valueZat: 1_000_000 };
    expect((await checkProof(p, fx.proof, url, url)).ok).toBe(true);
    // a node that gives only the ZEC value
    spentOut = { n: 0, value: "0.01000000" };
    expect((await checkProof(p, fx.proof, url, url)).ok).toBe(true);
    // a wrong value makes the genuine stamp fail (never pass something else)
    spentOut = { n: 0, valueZat: 999_999 };
    expect(await checkProof(p, fx.proof, url, url)).toMatchObject({ ok: false, error: expect.stringMatching(/does not verify/) });
    spentVersion = 5;
    spentOut = { n: 0, value: 0.01, valueZat: 1_000_000 };
  });
  it("fails before enough confirmations", async () => {
    const p = params();
    solana = harvest(p);
    confirmations = 3;
    expect(await checkProof(p, fx.proof, url, url)).toMatchObject({ ok: false, error: expect.stringMatching(/confirmations/) });
    confirmations = 20;
  });
  it("the offline check lists what it cannot see, and says plainly when the issuer was not verified", () => {
    const shown = JSON.parse(check(fx.txHex, fx.proof, JSON.stringify(params()), "")) as { issuerVerified: boolean; notChecked: string[] };
    expect(shown.issuerVerified).toBe(false);
    expect(shown.notChecked[0]).toMatch(/NOT verified/);
    expect(shown.notChecked.join("\n")).toMatch(/a mined txid does not vouch/);
    expect(shown.notChecked.join("\n")).toMatch(/Solana/);
    // with the spent coin's value (1,000,000 zat), the issuer's signature is verified
    expect(JSON.parse(check(fx.txHex, fx.proof, JSON.stringify(params()), "1000000")).issuerVerified).toBe(true);
    expect(() => check(fx.txHex, fx.proof, JSON.stringify(params()), "999999")).toThrow(/does not verify/);
    expect(() => check(fx.txHex, fx.proof, JSON.stringify(params(fakeKey().address("testnet"))), "")).toThrow(/issuer/);
  });
});

describe("a private request whose fee exceeds its payout (SPEC.md §9.1)", () => {
  it("is undeliverable, so it is refunded, never stamped", () => {
    const p = params();
    const c = classify(harvestTx(p, { harvested: 100n, fee: 40_000n, memo: `sapling-stamp:2:1:${SEALED}` }), p);
    if (c.kind !== "request") throw new Error("not a request");
    expect(undeliverableReason(p, c.request)).toMatch(/fee exceeds the harvested amount/);
    const ok = classify(harvestTx(p, { harvested: 40_000n, fee: 40_000n, memo: `sapling-stamp:2:1:${SEALED}` }), p);
    if (ok.kind !== "request") throw new Error("not a request");
    expect(undeliverableReason(p, ok.request)).toBeUndefined();
  });
});
