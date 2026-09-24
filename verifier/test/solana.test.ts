import { describe, expect, it } from "vitest";
import { classify } from "../src/solana/tx.ts";
import { harvestTx, key, refundTx, sig, testParams } from "./helpers/builders.ts";

describe("a stamp request (SPEC §2)", () => {
  const p = testParams();
  it("is read with every field from the transaction and its Redeemed event", () => {
    const holder = key();
    const holderZec = key();
    const mint = key();
    const s = sig();
    const c = classify(harvestTx(p, { signature: s, holder, holderZec, mint, burned: 5n, harvested: 900_000n, fee: 40_000n, memo: "sapling-stamp:1:tmXYZ" }), p);
    expect(c).toEqual({ kind: "request", request: { signature: s, slot: 1000, blockTime: 1_800_000_000, mint, holder, source: holderZec, burned: 5n, harvested: 900_000n, feePaid: 40_000n, address: "tmXYZ" } });
  });
  it("R1: a failed harvest is not a request", () => {
    expect(classify(harvestTx(p, { err: { InstructionError: [0, "Custom"] } }), p).kind).toBe("other");
  });
  it("R2: exactly one redeem", () => {
    expect(classify(harvestTx(p, { twoRedeems: true }), p)).toMatchObject({ kind: "other", reason: expect.stringMatching(/^R2/) });
  });
  it("R3: the Redeemed event must be there, from the program itself (an inner program's data does not count)", () => {
    expect(classify(harvestTx(p, { noEvent: true }), p)).toMatchObject({ kind: "other", reason: expect.stringMatching(/^R3/) });
  });
  it("R4: exactly one memo, with the prefix and an address", () => {
    expect(classify(harvestTx(p, { memo: null }), p)).toMatchObject({ reason: expect.stringMatching(/^R4/) });
    expect(classify(harvestTx(p, { extraMemo: true }), p)).toMatchObject({ reason: expect.stringMatching(/^R4/) });
    expect(classify(harvestTx(p, { memo: "sapling-stamp:2:t1abc" }), p)).toMatchObject({ reason: expect.stringMatching(/^R4/) });
    expect(classify(harvestTx(p, { memo: "sapling-stamp:1:" }), p)).toMatchObject({ reason: expect.stringMatching(/^R4/) });
    expect(classify(harvestTx(p, { memo: "sapling-stamp:1:t1 abc" }), p)).toMatchObject({ reason: expect.stringMatching(/^R4/) });
  });
  it("R5: the fee comes from the holder's ZEC account, signed by the holder, and is at least the fee in force", () => {
    expect(classify(harvestTx(p, { fee: 39_999n }), p)).toMatchObject({ reason: expect.stringMatching(/^R5.*below/) });
    expect(classify(harvestTx(p, { feeSource: key() }), p)).toMatchObject({ reason: expect.stringMatching(/^R5/) });
    expect(classify(harvestTx(p, { feeAuthority: key() }), p)).toMatchObject({ reason: expect.stringMatching(/^R5/) });
    expect(classify(harvestTx(p, { fee: 50_000n }), p).kind).toBe("request"); // paying more is fine
  });
  it("R5: after a fee change, the lower fee is honoured for 24 hours", () => {
    const q = testParams({ fees: [{ from: 0, amount: "10000" }, { from: 1_800_000_000 - 3600, amount: "40000" }] });
    expect(classify(harvestTx(q, { fee: 10_000n, blockTime: 1_800_000_000 }), q).kind).toBe("request");
    expect(classify(harvestTx(q, { fee: 10_000n, blockTime: 1_800_000_000 + 86_400 }), q).kind).toBe("other");
  });
});

describe("a refund (SPEC §5)", () => {
  const p = testParams();
  it("is read from the fee account's transfer and its memo", () => {
    const req = sig();
    const to = key();
    expect(classify(refundTx(p, req, to, 40_000n), p)).toMatchObject({ kind: "refund", refund: { requestSignature: req, to, amount: 40_000n } });
  });
  it("must be signed by the fee owner", () => {
    expect(classify(refundTx(p, sig(), key(), 40_000n, key()), p).kind).toBe("other");
  });
});
