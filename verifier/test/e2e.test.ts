/**
 * End to end, with no chain: a local HTTP server answers the Solana and Zebra JSON-RPC methods the
 * verifier uses, from transactions built here; the readers, the ledger and the command-line tool run
 * against it unchanged.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { randomBytes } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { buildLedger } from "../src/ledger.ts";
import { readSolana } from "../src/rpc/solana.ts";
import { readZcash } from "../src/rpc/zebra.ts";
import { classify, type RpcTransaction } from "../src/solana/tx.ts";
import { encodeTransparent, type Destination } from "../src/zcash/address.ts";
import { fakeKey, harvestTx, refundTx, stampTx, testParams } from "./helpers/builders.ts";

const issuer = fakeKey();
const p = testParams({}, [issuer.address("testnet")]);
p.zcash.issuers[0]!.fromHeight = 50;
const dest: Destination = { kind: "p2pkh", hash: Uint8Array.from(randomBytes(20)) };
const addr = encodeTransparent("testnet", dest);
const now = Math.floor(Date.now() / 1000);

// three requests: one stamped, one refunded (undeliverable address), one pending; plus a stranger's
// transaction on the fee account that is neither
const stamped = harvestTx(p, { memo: `sapling-stamp:1:${addr}`, burned: 11n, harvested: 900_000n, blockTime: now - 3600 });
const undeliverable = harvestTx(p, { memo: "sapling-stamp:1:zs1nope", blockTime: now - 7200 });
const pending = harvestTx(p, { memo: `sapling-stamp:1:${addr}`, blockTime: now - 60 });
const u = classify(undeliverable, p);
if (u.kind !== "request") throw new Error("fixture");
const refund = refundTx(p, u.request.signature, u.request.source, u.request.feePaid);
const stranger = harvestTx(p, { memo: null });
const solanaTxs: RpcTransaction[] = [stamped, undeliverable, pending, refund, stranger];
const bySig = new Map(solanaTxs.map((t) => [t.transaction.signatures[0]!, t]));

const stampHex = stampTx(issuer.pubkey, stamped.transaction.signatures[0]!, 11n, 900_000n, dest);
const zcash = new Map([["ab".repeat(32), { hex: stampHex, height: 120 }]]);
const TIP = 200;

let server: Server;
let url = "";
beforeAll(async () => {
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      const { method, params } = JSON.parse(body) as { method: string; params: unknown[] };
      const reply = (result: unknown) => res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result }));
      if (method === "getSignaturesForAddress") {
        const before = (params[1] as { before?: string }).before;
        return reply(before ? [] : solanaTxs.map((t) => ({ signature: t.transaction.signatures[0], err: null })));
      }
      if (method === "getTransaction") return reply(bySig.get(params[0] as string) ?? null);
      if (method === "getblockcount") return reply(TIP);
      if (method === "getaddresstxids") return reply([...zcash.keys()]);
      if (method === "getrawtransaction") {
        const t = zcash.get(params[0] as string)!;
        return reply({ hex: t.hex, height: t.height, confirmations: TIP - t.height + 1 });
      }
      if (method === "getblock") return reply({ tx: ["cb".repeat(32), ...zcash.keys()] });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: -32601, message: "method not found" } }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const a = server.address() as { port: number };
  url = `http://127.0.0.1:${a.port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

describe("the verifier against both chains' RPCs", () => {
  it("rebuilds the stamp set and the states from the RPCs alone", async () => {
    const sol = await readSolana(url, p);
    expect([sol.requests.length, sol.refunds.length, sol.ignored.length]).toEqual([3, 1, 1]);
    const zec = await readZcash(url, p);
    expect(zec[0]).toMatchObject({ height: 120, index: 1, confirmations: 81 });
    const l = buildLedger(p, sol.requests, sol.refunds, zec, now);
    expect(l.stamps.map((s) => [s.burned, s.harvested, s.received, s.address])).toEqual([[11n, 900_000n, 860_000n, addr]]);
    expect(Object.fromEntries(l.states.map((s) => [s.request, s.state]))).toEqual({
      [stamped.transaction.signatures[0]!]: "stamped",
      [undeliverable.transaction.signatures[0]!]: "refunded",
      [pending.transaction.signatures[0]!]: "pending",
    });
    expect(l.totals).toMatchObject({ requests: 3, stamped: 1, refunded: 1, pending: 1, feesPaid: 120_000n, refundedAmount: 40_000n });
    expect(l.invariant.ok).toBe(true);
  });

  it("the command-line tool prints the same, and exits 0 while the invariant holds", async () => {
    const dir = mkdtempSync(join(tmpdir(), "stamps-"));
    const file = join(dir, "params.json");
    writeFileSync(file, JSON.stringify(p));
    const tsx = join(__dirname, "..", "node_modules", "tsx", "dist", "cli.mjs");
    const { stdout } = await promisify(execFile)(process.execPath, [tsx, join(__dirname, "..", "src", "cli.ts"), "--params", file, "--solana", url, "--zcash", url, "--json"]);
    const out = JSON.parse(stdout) as { totals: { stamped: number }; invariant: { ok: boolean }; stamps: { received: string }[] };
    expect(out.totals.stamped).toBe(1);
    expect(out.stamps[0]!.received).toBe("860000");
    expect(out.invariant.ok).toBe(true);
  }, 60_000);
});
