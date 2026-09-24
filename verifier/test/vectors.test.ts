/** The published record test vectors (test-vectors/records.json) are what the encoder produces. */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { base58 } from "@scure/base";
import { decodeRecord, encodeRecord, signatureHash } from "../src/record.ts";
import { bytesToHex, hexToBytes } from "../src/zcash/tx.ts";

interface Vector {
  description: string;
  signature: string;
  burned: string;
  harvested: string;
  ticker: string;
  record: string;
  script: string;
}
const vectors = JSON.parse(readFileSync(new URL("../../test-vectors/records.json", import.meta.url), "utf8")) as { vectors: Vector[] };

describe("record test vectors", () => {
  it.each(vectors.vectors.map((v) => [v.description, v] as const))("%s", (_d, v) => {
    const rec = encodeRecord({ sigHash: signatureHash(base58.decode(v.signature)), burned: BigInt(v.burned), harvested: BigInt(v.harvested), ticker: v.ticker });
    expect(bytesToHex(rec)).toBe(v.record);
    expect(`6a34${v.record}`).toBe(v.script);
    const d = decodeRecord(hexToBytes(v.record));
    expect(d).toMatchObject({ burned: BigInt(v.burned), harvested: BigInt(v.harvested) });
  });
});
