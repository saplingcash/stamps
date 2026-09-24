import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { bech32m } from "@scure/base";
import { f4jumble } from "../src/zcash/f4jumble.ts";
import { buildLedger, type ZcashTxInfo } from "../src/ledger.ts";
import { classify, type Classified, type Refund, type Request } from "../src/solana/tx.ts";
import { decodeAddress, destinationScript, encodeTransparent, type Destination } from "../src/zcash/address.ts";
import { hash160, parseTransparent, hexToBytes, p2pkhSpenderHash } from "../src/zcash/tx.ts";
import { buildV5, fakeKey, harvestTx, key, p2pkhScriptSig, recordScript, refundTx, stampTx, testParams } from "./helpers/builders.ts";
import type { Params } from "../src/params.ts";

const issuer = fakeKey();
const NOW = 1_800_000_000 + 3600;

function setup(over: Partial<Params> = {}) {
  const p = testParams(over, [issuer.address("testnet")]);
  const dest: Destination = { kind: "p2pkh", hash: Uint8Array.from(randomBytes(20)) };
  const addr = encodeTransparent("testnet", dest);
  const c = classify(harvestTx(p, { memo: `sapling-stamp:1:${addr}`, burned: 7n, harvested: 500_000n }), p);
  if (c.kind !== "request") throw new Error(c.kind === "other" ? c.reason : "not a request");
  return { p, dest, addr, req: c.request };
}
const refundOf = (c: Classified): Refund => {
  if (c.kind !== "refund") throw new Error("not a refund");
  return c.refund;
};
const z = (txid: string, rawHex: string, height = 100, index = 1, confirmations = 20): ZcashTxInfo => ({ txid, height, index, confirmations, rawHex });

describe("a Zcash v5 transaction", () => {
  it("is read back as built: inputs, outputs, the issuer's key hash", () => {
    const raw = hexToBytes(buildV5({ inputs: [{ scriptSig: p2pkhScriptSig(issuer.pubkey) }], outputs: [{ value: 546n, script: destinationScript({ kind: "p2sh", hash: new Uint8Array(20) }) }] }));
    const t = parseTransparent(raw);
    expect([t.version, t.inputs.length, t.outputs[0]!.value]).toEqual([5, 1, 546n]);
    expect(p2pkhSpenderHash(t.inputs[0]!.scriptSig)).toEqual(hash160(issuer.pubkey));
  });
  it("any version but 5 is refused", () => {
    expect(() => parseTransparent(hexToBytes(buildV5({ version: 4, inputs: [], outputs: [] })))).toThrow(/v5/);
  });
});

describe("valid stamps (SPEC §3, §6)", () => {
  it("a well-formed stamp counts, with the receipt's numbers", () => {
    const { p, dest, addr, req } = setup();
    const l = buildLedger(p, [req], [], [z("aa", stampTx(issuer.pubkey, req.signature, 7n, 500_000n, dest))], NOW);
    expect(l.stamps).toEqual([{ id: "aa", height: 100, request: req.signature, mint: req.mint, ticker: "OWL", burned: 7n, harvested: 500_000n, fee: 40_000n, received: 460_000n, address: addr }]);
    expect(l.states).toEqual([{ request: req.signature, state: "stamped" }]);
    expect(l.invariant.ok).toBe(true);
  });
  it("Z1: not counted before 10 confirmations", () => {
    const { p, dest, req } = setup();
    const l = buildLedger(p, [req], [], [z("aa", stampTx(issuer.pubkey, req.signature, 7n, 500_000n, dest), 100, 1, 9)], NOW);
    expect(l.stamps).toEqual([]);
    expect(l.rejected[0]!.reason).toMatch(/^Z1/);
  });
  it("Z2: someone else inscribing a correct record does not make a stamp", () => {
    const { p, dest, req } = setup();
    const l = buildLedger(p, [req], [], [z("aa", stampTx(fakeKey().pubkey, req.signature, 7n, 500_000n, dest))], NOW);
    expect(l.rejected[0]!.reason).toMatch(/^Z2/);
  });
  it("Z2: an issuer counts only inside its height range (key rotation)", () => {
    const { p, dest, req } = setup();
    p.zcash.issuers = [{ address: issuer.address("testnet"), fromHeight: 1, toHeight: 99 }];
    expect(buildLedger(p, [req], [], [z("aa", stampTx(issuer.pubkey, req.signature, 7n, 500_000n, dest), 100)], NOW).stamps).toEqual([]);
    expect(buildLedger(p, [req], [], [z("aa", stampTx(issuer.pubkey, req.signature, 7n, 500_000n, dest), 99)], NOW).stamps.length).toBe(1);
  });
  it("Z3: exactly one OP_RETURN, in the 6a 34 form", () => {
    const { p, dest, req } = setup();
    const two = buildV5({ inputs: [{ scriptSig: p2pkhScriptSig(issuer.pubkey) }], outputs: [{ value: 0n, script: recordScript(req.signature, 7n, 500_000n) }, { value: 0n, script: recordScript(req.signature, 7n, 500_000n) }, { value: 546n, script: destinationScript(dest) }] });
    expect(buildLedger(p, [req], [], [z("aa", two)], NOW).rejected[0]!.reason).toMatch(/^Z3: 2 OP_RETURN/);
  });
  it("V1: a record citing no request is not a stamp", () => {
    const { p, dest, req } = setup();
    const unrelated = harvestTx(p).transaction.signatures[0]!; // a signature no request has
    const l = buildLedger(p, [req], [], [z("aa", stampTx(issuer.pubkey, unrelated, 7n, 500_000n, dest))], NOW);
    expect(l.rejected[0]!.reason).toMatch(/^V1/);
  });
  it("V2: the amounts must match the Redeemed event", () => {
    const { p, dest, req } = setup();
    expect(buildLedger(p, [req], [], [z("aa", stampTx(issuer.pubkey, req.signature, 8n, 500_000n, dest))], NOW).rejected[0]!.reason).toMatch(/^V2/);
    expect(buildLedger(p, [req], [], [z("aa", stampTx(issuer.pubkey, req.signature, 7n, 499_999n, dest))], NOW).rejected[0]!.reason).toMatch(/^V2/);
  });
  it("V3: the postage must reach the request's own address", () => {
    const { p, req } = setup();
    const elsewhere: Destination = { kind: "p2pkh", hash: Uint8Array.from(randomBytes(20)) };
    expect(buildLedger(p, [req], [], [z("aa", stampTx(issuer.pubkey, req.signature, 7n, 500_000n, elsewhere))], NOW).rejected[0]!.reason).toMatch(/^V3/);
  });
  it("V4: of two valid candidates, the first in chain order wins; the other is a duplicate", () => {
    const { p, dest, req } = setup();
    const a = z("late", stampTx(issuer.pubkey, req.signature, 7n, 500_000n, dest), 100, 5);
    const b = z("early", stampTx(issuer.pubkey, req.signature, 7n, 500_000n, dest), 100, 2);
    const l = buildLedger(p, [req], [], [a, b], NOW);
    expect(l.stamps.map((s) => s.id)).toEqual(["early"]);
    expect(l.rejected).toEqual([{ txid: "late", reason: expect.stringMatching(/^V4/) }]);
  });
  it("a stamp to a unified address's transparent receiver counts", () => {
    const p0 = testParams({}, [issuer.address("testnet")]);
    // the official vectors are mainnet: build a testnet UA with a P2SH and a Sapling receiver
    const hash = Uint8Array.from(randomBytes(20));
    const pad = new Uint8Array(16);
    pad.set(new TextEncoder().encode("utest"));
    const ua = bech32m.encode("utest", bech32m.toWords(f4jumble(Uint8Array.from([0x01, 20, ...hash, 0x02, 43, ...new Uint8Array(43).fill(1), ...pad]))), false);
    expect(decodeAddress(ua, "testnet")).toMatchObject({ ok: true, destination: { kind: "p2sh" } });
    const c = classify(harvestTx(p0, { memo: `sapling-stamp:1:${ua}`, burned: 7n, harvested: 500_000n }), p0);
    const r = (c as { request: Request }).request;
    const l = buildLedger(p0, [r], [], [z("aa", stampTx(issuer.pubkey, r.signature, 7n, 500_000n, { kind: "p2sh", hash }))], NOW);
    expect(l.stamps.length).toBe(1);
  });
});

describe("states and the invariant (SPEC §7)", () => {
  it("pending, then overdue after 7 days, which breaks the invariant", () => {
    const { p, req } = setup();
    expect(buildLedger(p, [req], [], [], req.blockTime + 3600).states[0]!.state).toBe("pending");
    const late = buildLedger(p, [req], [], [], req.blockTime + 7 * 86_400);
    expect(late.states[0]!.state).toBe("overdue");
    expect(late.invariant.ok).toBe(false);
  });
  it("an undeliverable request must be refunded; a matching refund settles it", () => {
    const p = testParams({}, [issuer.address("testnet")]);
    const c = classify(harvestTx(p, { memo: "sapling-stamp:1:zs1notatransparentaddress" }), p);
    const r = (c as { request: Request }).request;
    const f = classify(refundTx(p, r.signature, r.source, r.feePaid), p);
    const l = buildLedger(p, [r], [refundOf(f)], [], r.blockTime + 8 * 86_400);
    expect(l.states[0]).toMatchObject({ state: "refunded", undeliverable: expect.stringMatching(/shielded|accepts/) });
    expect(l.totals.refundedAmount).toBe(r.feePaid);
    expect(l.invariant.ok).toBe(true);
  });
  it("a refund of the wrong amount or to the wrong account does not count", () => {
    const { p, req } = setup();
    const wrong = [classify(refundTx(p, req.signature, req.source, req.feePaid - 1n), p), classify(refundTx(p, req.signature, key(), req.feePaid), p)];
    const l = buildLedger(p, [req], wrong.map(refundOf), [], req.blockTime + 3600);
    expect(l.states[0]!.state).toBe("pending");
  });
  it("stamped and refunded at once breaks the invariant", () => {
    const { p, dest, req } = setup();
    const f = classify(refundTx(p, req.signature, req.source, req.feePaid), p);
    const l = buildLedger(p, [req], [refundOf(f)], [z("aa", stampTx(issuer.pubkey, req.signature, 7n, 500_000n, dest))], NOW);
    expect(l.invariant).toMatchObject({ ok: false, problems: [expect.stringMatching(/both stamped and refunded/)] });
  });
  it("V5: a stamp mined after its request was refunded is not valid; the request stays refunded", () => {
    const { p, dest, req } = setup();
    const f = refundOf(classify(refundTx(p, req.signature, req.source, req.feePaid), p));
    const after = { ...z("aa", stampTx(issuer.pubkey, req.signature, 7n, 500_000n, dest)), time: f.blockTime + 60 };
    const l = buildLedger(p, [req], [f], [after], NOW);
    expect(l.stamps).toEqual([]);
    expect(l.rejected).toEqual([{ txid: "aa", reason: "V5: mined after the request was refunded" }]);
    expect(l.states[0]!.state).toBe("refunded");
    expect(l.invariant.ok).toBe(true);
    // mined before the refund, it is valid, and the request is both stamped and refunded
    const before = { ...after, time: f.blockTime - 60 };
    expect(buildLedger(p, [req], [f], [before], NOW).invariant).toMatchObject({ ok: false, problems: [expect.stringMatching(/both stamped and refunded/)] });
  });
  it("an unreadable Solana transaction is reported unresolved, never guessed", () => {
    const { p } = setup();
    const l = buildLedger(p, [], [], [], NOW, ["someSignature"]);
    expect(l.states).toEqual([{ request: "someSignature", state: "unresolved" }]);
    expect(l.totals.unresolved).toBe(1);
  });
});
