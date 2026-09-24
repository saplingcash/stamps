/** A stamp built by the Rust stamper-core is a valid stamp for the TypeScript verifier (cross-implementation check). */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { buildLedger } from "../src/ledger.ts";
import { parseTransparent, hexToBytes, txidTransparentOnly } from "../src/zcash/tx.ts";
import { testParams } from "./helpers/builders.ts";
import type { Request } from "../src/solana/tx.ts";

const fx = JSON.parse(readFileSync(new URL("./fixtures/rust-stamp.json", import.meta.url), "utf8")) as {
  issuerAddress: string;
  request: { signature: string; address: string; burned: string; harvested: string; ticker: string };
  txid: string;
  txHex: string;
  fee: number;
};

describe("a stamp from the Rust stamper", () => {
  it("parses as v5 with the NU6.3 branch, one input, the record, the postage and change", () => {
    const t = parseTransparent(hexToBytes(fx.txHex));
    expect(t.consensusBranchId).toBe(0x37a5165b);
    expect(t.outputs.map((o) => o.value)).toEqual([0n, 546n, BigInt(1_000_000 - 546 - fx.fee)]);
    expect(fx.fee).toBe(20_000);
  });
  it("has the txid the Rust side computed (ZIP 244, checked there against librustzcash)", () => {
    expect(txidTransparentOnly(hexToBytes(fx.txHex))).toBe(fx.txid);
  });
  it("is a valid stamp of its request", () => {
    const p = testParams({}, [fx.issuerAddress]);
    const req: Request = { signature: fx.request.signature, slot: 1, blockTime: 1_800_000_000, mint: "M", holder: "H", source: "S", burned: BigInt(fx.request.burned), harvested: BigInt(fx.request.harvested), feePaid: 40_000n, address: fx.request.address };
    const l = buildLedger(p, [req], [], [{ txid: fx.txid, height: 4_388_170, index: 3, confirmations: 12, rawHex: fx.txHex }], 1_800_000_100);
    expect(l.rejected).toEqual([]);
    expect(l.stamps).toMatchObject([{ id: fx.txid, ticker: "OWL", burned: 2_000_000_000_000n, harvested: 42_000_000n, received: 41_960_000n }]);
  });
});
