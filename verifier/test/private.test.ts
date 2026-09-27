import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { buildLedger, type ZcashTxInfo } from "../src/ledger.ts";
import { classify, type Request } from "../src/solana/tx.ts";
import { loadInspectorFromDisk, inspectTx } from "../src/zcash/inspect.ts";
import { check } from "../wasm/sapling_stamp_proof_wasm.js";
import { fakeKey, harvestTx, testParams } from "./helpers/builders.ts";
import type { Params } from "../src/params.ts";

const fx = JSON.parse(readFileSync(join(import.meta.dirname, "fixtures/private-testnet-stamp.json"), "utf8")) as {
  txid: string;
  height: number;
  issuerAddress: string;
  requestSignature: string;
  requestPublic: string;
  receiver: string;
  proof: string;
  txHex: string;
};
const SEALED = "A".repeat(123);
const T = 1_800_000_000;

beforeAll(async () => {
  await loadInspectorFromDisk();
});

function params(over: Partial<Params["zcash"]> = {}): Params {
  const p = testParams({}, [fx.issuerAddress]);
  return { ...p, zcash: { ...p.zcash, requestKeys: [{ id: 1, x25519: fx.requestPublic, from: 0 }], ...over } };
}
const privateRequest = (over: Partial<Request> = {}): Request => ({ signature: fx.requestSignature, slot: 1, blockTime: T, mint: "M", holder: "H", source: "S", burned: 1_250_000_000_000n, harvested: 1_234_567n, feePaid: 40_000n, address: "", mode: "private", kid: 1, sealed: SEALED, ...over });
const z = (over: Partial<ZcashTxInfo> = {}): ZcashTxInfo => ({ txid: fx.txid, height: fx.height, index: 1, confirmations: 12, rawHex: fx.txHex, ...over });

describe("a private stamp (SPEC.md §9), on Zcash testnet", () => {
  it("is read by the v6 reader, with its own txid", () => {
    const t = inspectTx(fx.txHex);
    expect(t).toMatchObject({ txid: fx.txid, version: 6, sapling: false, orchard: false, ironwood: { actions: 2, valueBalance: -546 } });
    expect(t.outputs[0]!.script.startsWith("6a1753504c4702")).toBe(true);
  });
  it("is a valid stamp of its private request; its receiver is not shown", () => {
    const l = buildLedger(params(), [privateRequest()], [], [z()], T + 100);
    expect(l.rejected).toEqual([]);
    expect(l.stamps).toEqual([{ id: fx.txid, height: fx.height, request: fx.requestSignature, mint: "M", ticker: "", burned: 1_250_000_000_000n, harvested: 1_234_567n, fee: 40_000n, received: 1_194_567n, address: "", mode: "private" }]);
    expect(l.states).toEqual([{ request: fx.requestSignature, state: "stamped" }]);
    expect(l.invariant.ok).toBe(true);
  });
  it("V3: does not count for a public request with the same signature", () => {
    const l = buildLedger(params(), [privateRequest({ mode: "public", address: fx.issuerAddress, kid: undefined, sealed: undefined })], [], [z()], T + 100);
    expect(l.rejected[0]!.reason).toMatch(/^V3: a version 2 record for a public request/);
  });
  it("V3: a request whose key id was not in force is undeliverable, and overdue until refunded", () => {
    const l = buildLedger(params({ requestKeys: [{ id: 1, x25519: fx.requestPublic, from: T + 1 }] }), [privateRequest()], [], [z()], T + 8 * 86_400);
    expect(l.rejected[0]!.reason).toMatch(/^V3: the request is undeliverable/);
    expect(l.states[0]).toMatchObject({ state: "overdue", undeliverable: expect.stringMatching(/no request key/) });
    expect(l.invariant.ok).toBe(false);
  });
  it("Z2: another issuer, or a txid that is not the transaction's own, does not count", () => {
    const other = { ...params(), zcash: { ...params().zcash, issuers: [{ address: fakeKey().address("testnet"), fromHeight: 1 }] } };
    expect(buildLedger(other, [privateRequest()], [], [z()], T + 100).rejected[0]!.reason).toMatch(/^Z2: not spent by an issuer/);
    expect(buildLedger(params(), [privateRequest()], [], [z({ txid: "00".repeat(32) })], T + 100).rejected[0]!.reason).toMatch(/^Z2: the transaction's own txid/);
    const cut = fx.txHex.slice(0, -2);
    expect(buildLedger(params(), [privateRequest()], [], [z({ rawHex: cut })], T + 100).rejected[0]!.reason).toMatch(/^Z2/);
  });
  it("Z1, V4, V5 apply as to public stamps", () => {
    expect(buildLedger(params(), [privateRequest()], [], [z({ confirmations: 9 })], T + 100).rejected[0]!.reason).toMatch(/^Z1/);
    const dup = buildLedger(params(), [privateRequest()], [], [z(), z({ index: 2 })], T + 100);
    expect(dup.stamps.length).toBe(1);
    const late = buildLedger(params(), [privateRequest()], [{ signature: "R", slot: 2, blockTime: T + 10, requestSignature: fx.requestSignature, to: "S", amount: 40_000n }], [z({ time: T + 20 })], T + 100);
    expect(late.rejected[0]!.reason).toMatch(/^V5/);
    expect(late.states[0]!.state).toBe("refunded");
  });
  it("its proof checks without a key, and names the receiver in full", () => {
    const shown = JSON.parse(check(fx.txHex, fx.proof, JSON.stringify(params()), "")) as { txid: string; address: string; value: number; receipt: { signature: string; ticker: string } };
    expect(shown).toMatchObject({ txid: fx.txid, address: fx.receiver, value: 546, receipt: { signature: fx.requestSignature, ticker: "T2TEST" } });
    expect(() => check(fx.txHex, fx.proof.replace(/.$/, (c) => (c === "A" ? "B" : "A")), JSON.stringify(params()), "")).toThrow();
  });
});

describe("a private request (SPEC.md §9.1)", () => {
  it("is classified with its key id and seal, and no address", () => {
    const p = params();
    const c = classify(harvestTx(p, { memo: `sapling-stamp:2:1:${SEALED}` }), p);
    expect(c.kind === "request" && [c.request.mode, c.request.kid, c.request.sealed, c.request.address]).toEqual(["private", 1, SEALED, ""]);
  });
  it("a malformed private memo is not a request", () => {
    const p = params();
    for (const memo of [`sapling-stamp:2:0:${SEALED}`, `sapling-stamp:2:1:${SEALED}A`, `sapling-stamp:2:1:${SEALED.slice(1)}`, `sapling-stamp:2:${SEALED}`]) {
      const c = classify(harvestTx(p, { memo }), p);
      expect(c.kind, memo).toBe("other");
    }
  });
});
