/**
 * The record test vectors (test-vectors/records.json): the published cases, each with a signature derived
 * from its label (helpers/labels.ts), encoded by this verifier. vectors.test.ts checks the file is exactly
 * this.
 *
 *   npx tsx test/helpers/record-vectors.ts --write
 */
import { writeFileSync } from "node:fs";
import { base58 } from "@scure/base";
import { encodeRecord, signatureHash } from "../../src/record.ts";
import { bytesToHex } from "../../src/zcash/tx.ts";
import { label } from "./labels.ts";

const CASES = [
  { description: "a typical harvest", burned: "2000000000000", harvested: "42000000", ticker: "OWL" },
  { description: "the largest amounts", burned: "18446744073709551615", harvested: "18446744073709551615", ticker: "ABCDEFGHIJ" },
  { description: "an empty ticker", burned: "1", harvested: "1", ticker: "" },
  { description: "a ticker cut at 10 bytes on a character boundary", burned: "123456789", harvested: "987654321", ticker: "ÄÄÄÄÄÄ" },
];

export function recordVectors() {
  return {
    _comment: "SPLG v1 records (SPEC.md §3). `signature` is a Solana signature in base58; `script` is the full OP_RETURN scriptPubKey.",
    vectors: CASES.map((c, i) => {
      const sig = label(`vectors/record/${i}/signature`, 64);
      const record = bytesToHex(encodeRecord({ sigHash: signatureHash(sig), burned: BigInt(c.burned), harvested: BigInt(c.harvested), ticker: c.ticker }));
      return { description: c.description, signature: base58.encode(sig), burned: c.burned, harvested: c.harvested, ticker: c.ticker, record, script: `6a34${record}` };
    }),
  };
}

if (process.argv.includes("--write")) writeFileSync(new URL("../../../test-vectors/records.json", import.meta.url), JSON.stringify(recordVectors(), null, 2) + "\n");
