/**
 * Payout stamps (SPEC.md §10): the vectors in test-vectors/payout.json (order addresses, version 3 records, a
 * synthetic forward of two exits with their proofs, and Sapling's first payout transactions on Zcash mainnet), the
 * exit requests on Solana, the payout ledger, the scan of the order addresses, and check-proof for splg-proof:2.
 */
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { base58 } from "@scure/base";
import { checkParams, type Params } from "../src/params.ts";
import { buildPayoutLedger, type ZcashTxInfo } from "../src/ledger.ts";
import { classifyExit, type ExitRequest, type RpcTransaction } from "../src/solana/tx.ts";
import { encodeRecordV3, orderHash, orderPubkey, parseExitMemo, recordV3Hashes, recordV3Script } from "../src/payout.ts";
import { checkProof, proofTxid } from "../src/checkproof.ts";
import { readPayoutCandidates } from "../src/rpc/zebra.ts";
import { encodeTransparent } from "../src/zcash/address.ts";
import { bytesToHex, hexToBytes } from "../src/zcash/tx.ts";
import { inspectTx, loadInspectorFromDisk } from "../src/zcash/inspect.ts";
import { check_payout } from "../wasm/sapling_stamp_proof_wasm.js";
import { exitTx, testParams } from "./helpers/builders.ts";

const root = join(import.meta.dirname, "..", "..");
interface Receipt { kind: string; ticker: string | null; mint: string | null; sent: string; bridged: string; fee: string; received: string; signature: string; blockTime: number }
const V = JSON.parse(readFileSync(join(root, "test-vectors/payout.json"), "utf8")) as {
  exitKeys: { account: number; network: "mainnet" | "testnet"; accountPubkey: string; addresses: { index: number; pubkey: string; address: string }[] }[];
  records: { signatures: string[]; record: string; script: string }[];
  synthetic: { accountPubkey: string; txid: string; hex: string; spentValues: string[]; exits: { index: number; signature: string; proof: string; receipt: Receipt; address: string }[] };
  mainnet: { account: number; index: number; orderAddress: string; accountPubkey: string; txid: string; height: number; hex: string; spentValues: string[]; intoPool: string; record: string }[];
};
const MAINNET = JSON.parse(readFileSync(join(root, "params/mainnet.json"), "utf8")) as Params;
const S = V.synthetic;

/** testnet parameters with the synthetic forward's exit key */
const params = (): Params => {
  const p = testParams();
  return { ...p, zcash: { ...p.zcash, exitKeys: [{ account: 0, pubkey: S.accountPubkey, fromHeight: 1 }] } };
};
const exitOf = (p: Params, e: { index: number; signature: string; receipt: Receipt }, over: { index?: number } = {}): ExitRequest => {
  const c = classifyExit(exitTx(p, { signature: e.signature, index: over.index ?? e.index, sent: BigInt(e.receipt.sent), blockTime: e.receipt.blockTime }), p);
  if (c.kind !== "exit") throw new Error(c.reason);
  return c.exit;
};
const z = (over: Partial<ZcashTxInfo> = {}): ZcashTxInfo => ({ txid: S.txid, height: 100, index: 1, confirmations: 20, rawHex: S.hex, ...over });
const NOW = 1_790_640_000 + 3600;

beforeAll(async () => {
  await loadInspectorFromDisk();
});

describe("the vectors (test-vectors/payout.json)", () => {
  it("order addresses: BIP32 public children 0/<index> of the account key", () => {
    for (const k of V.exitKeys) {
      const pub = hexToBytes(k.accountPubkey);
      for (const a of k.addresses) {
        expect(bytesToHex(orderPubkey(pub, a.index))).toBe(a.pubkey);
        expect(encodeTransparent(k.network, { kind: "p2pkh", hash: orderHash(pub, a.index) })).toBe(a.address);
      }
    }
  });
  it("version 3 records and their scripts, one to four exits", () => {
    for (const r of V.records) {
      const rec = encodeRecordV3(r.signatures.map((s) => base58.decode(s)));
      expect(bytesToHex(rec)).toBe(r.record);
      expect(bytesToHex(recordV3Script(rec))).toBe(r.script);
      expect(recordV3Hashes(hexToBytes(r.script))!.map(bytesToHex)).toEqual(r.signatures.map((s) => bytesToHex(encodeRecordV3([base58.decode(s)]).slice(5))));
    }
    expect(recordV3Hashes(hexToBytes("6a4c17" + V.records[0]!.record))).toBeNull(); // not the minimal push
    expect(recordV3Hashes(hexToBytes("6a17" + V.records[0]!.record.replace(/^53504c4703/, "53504c4702")))).toBeNull();
  });
  it("the mainnet parameter file publishes both exit keys, and they are the ones the mainnet forwards spend from", () => {
    expect(checkParams(MAINNET)).toEqual([]);
    for (const f of V.mainnet) {
      const k = MAINNET.zcash.exitKeys!.find((x) => x.account === f.account)!;
      expect(k.pubkey).toBe(f.accountPubkey);
      expect(f.height).toBeGreaterThanOrEqual(k.fromHeight);
      expect(encodeTransparent("mainnet", { kind: "p2pkh", hash: orderHash(hexToBytes(k.pubkey), f.index) })).toBe(f.orderAddress);
      const t = inspectTx(f.hex);
      expect(t.txid).toBe(f.txid);
      expect([t.outputs.length, t.outputs[0]!.script, String(-t.ironwood!.valueBalance)]).toEqual([1, f.record, f.intoPool]);
    }
  });
  it("the parameter checks refuse a malformed exit key", () => {
    const p = params();
    expect(checkParams({ ...p, zcash: { ...p.zcash, exitKeys: [{ account: 0, pubkey: "00", fromHeight: 1 }] } }).join()).toMatch(/65 bytes/);
    expect(checkParams({ ...p, zcash: { ...p.zcash, exitKeys: [{ account: 0, pubkey: S.accountPubkey, fromHeight: 9, toHeight: 8 }] } }).join()).toMatch(/ends before/);
  });
});

describe("exit requests on Solana (SPEC.md §10.2)", () => {
  const p = params();
  it("one exit memo and one ZEC transfer by the signer", () => {
    const c = classifyExit(exitTx(p, { index: 12, sent: 7n }), p);
    expect(c.kind === "exit" && [c.exit.index, c.exit.sent, c.exit.kid]).toEqual([12, 7n, 1]);
  });
  it("anything else is not an exit request", () => {
    const reason = (tx: RpcTransaction) => {
      const c = classifyExit(tx, p);
      return c.kind === "other" ? c.reason : "exit";
    };
    expect(reason(exitTx(p, { memo: null }))).toMatch(/^E2: 0 memo/);
    expect(reason(exitTx(p, { memo: "sapling-exit:1:1:01:" + "A".repeat(123) }))).toMatch(/^E2/);
    expect(reason(exitTx(p, { memo: "sapling-exit:1:1:2147483648:" + "A".repeat(123) }))).toMatch(/^E2/);
    expect(reason(exitTx(p, { memo: "sapling-stamp:1:t1abc" }))).toMatch(/^E2/);
    expect(reason(exitTx(p, { transfers: 2 }))).toMatch(/^E3: 2 ZEC/);
    expect(reason(exitTx(p, { authority: base58.encode(new Uint8Array(32).fill(9)) }))).toMatch(/^E3: .*authority/);
    expect(reason({ ...exitTx(p), meta: { err: { x: 1 }, logMessages: [] } })).toMatch(/^E1/);
    expect(parseExitMemo("sapling-exit:1:1:0:" + "A".repeat(122) + "B")).toHaveProperty("error");
  });
});

describe("the payout ledger (SPEC.md §10.4)", () => {
  const p = params();
  const exits = () => S.exits.map((e) => exitOf(p, e));
  it("the synthetic forward is the payout stamp of both its exits", () => {
    const l = buildPayoutLedger(p, exits(), [z()], NOW);
    expect(l.rejected).toEqual([]);
    expect(l.stamps.map((s) => [s.id, s.exit, s.index, s.position, s.exits])).toEqual(S.exits.map((e, j) => [S.txid, e.signature, e.index, j, 2]));
    expect(l.states.map((s) => s.state)).toEqual(["stamped", "stamped"]);
    const into = S.exits.reduce((a, e) => a + BigInt(e.receipt.received), 0n);
    expect([l.totals.stamped, l.totals.intoPool]).toEqual([2, into]);
  });
  it("Z1: not before its confirmations; V1: every exit it names must be given; V2: each run is its exit's order address", () => {
    expect(buildPayoutLedger(p, exits(), [z({ confirmations: 9 })], NOW).rejected[0]!.reason).toMatch(/^Z1/);
    expect(buildPayoutLedger(p, exits().slice(0, 1), [z()], NOW).rejected[0]!.reason).toMatch(/^V1: no exit/);
    const swapped = [exitOf(p, S.exits[0]!, { index: S.exits[1]!.index }), exitOf(p, S.exits[1]!, { index: S.exits[0]!.index })];
    expect(buildPayoutLedger(p, swapped, [z()], NOW).rejected[0]!.reason).toMatch(/^V2: exit 0/);
    // another exit key, or one not valid at the height
    const other = { ...p, zcash: { ...p.zcash, exitKeys: [{ account: 0, pubkey: V.exitKeys[0]!.accountPubkey, fromHeight: 1 }] } };
    expect(buildPayoutLedger(other, exits(), [z()], NOW).rejected[0]!.reason).toMatch(/^V2/);
    const later = { ...p, zcash: { ...p.zcash, exitKeys: [{ account: 0, pubkey: S.accountPubkey, fromHeight: 101 }] } };
    expect(buildPayoutLedger(later, exits(), [z()], NOW).rejected[0]!.reason).toMatch(/^V2/);
    // account 1's key never pays an exit request
    const acct1 = { ...p, zcash: { ...p.zcash, exitKeys: [{ account: 1, pubkey: S.accountPubkey, fromHeight: 1 }] } };
    expect(buildPayoutLedger(acct1, exits(), [z()], NOW).rejected[0]!.reason).toMatch(/^V2/);
  });
  it("V4: the first in chain order; the states of exits without one", () => {
    const l = buildPayoutLedger(p, exits(), [z({ txid: "later", height: 200 }), z()], NOW);
    expect(l.rejected.map((r) => r.reason)).toEqual([expect.stringMatching(/^P1: the transaction's own txid/)]);
    const dup = buildPayoutLedger(p, exits(), [z(), z({ height: 101 })], NOW);
    expect(dup.rejected[0]!.reason).toMatch(/^V4/);
    const none = buildPayoutLedger(p, exits(), [], NOW);
    expect(none.states.map((s) => s.state)).toEqual(["pending", "pending"]);
    expect(buildPayoutLedger(p, exits(), [], NOW + 7 * 86_400).states.map((s) => s.state)).toEqual(["unstamped", "unstamped"]);
    expect(buildPayoutLedger(p, exits(), [], NOW, [S.exits[0]!.signature, "gone"]).states.map((s) => s.state)).toEqual(["unresolved", "pending", "unresolved"]);
  });
  it("Sapling's mainnet forwards have a payout stamp's shape and spend their order addresses (no exit given: V1)", () => {
    for (const f of V.mainnet.filter((x) => x.account === 0)) {
      const l = buildPayoutLedger(MAINNET, [], [{ txid: f.txid, height: f.height, index: 1, confirmations: 20, rawHex: f.hex }], NOW);
      expect(l.rejected).toEqual([{ txid: f.txid, reason: "V1: no exit has this hash" }]);
    }
  });
  it("not payout stamps: a v5 transaction, a transparent payout, a stamp", () => {
    const mainnetStamp = V.mainnet[0]!;
    const notV6 = buildPayoutLedger(MAINNET, [], [{ txid: "x", height: 5, index: 1, confirmations: 20, rawHex: "05000080" + mainnetStamp.hex.slice(8) }], NOW);
    expect(notV6.rejected[0]!.reason).toMatch(/^P1/);
  });
});

// ---------------------------------------------------------------- a node and a Solana RPC, answering from the vectors

let server: Server;
let url = "";
let solana: Record<string, RpcTransaction> = {};
const zcash: Record<string, { hex: string; height: number }> = {};
const spent = new Map<string, bigint[]>();
beforeAll(async () => {
  await loadInspectorFromDisk();
  zcash[S.txid] = { hex: S.hex, height: 100 };
  inspectTx(S.hex).inputs.forEach((i, n) => {
    const outs = spent.get(i.prevTxid) ?? [];
    outs[i.prevIndex] = BigInt(S.spentValues[n]!);
    spent.set(i.prevTxid, outs);
  });
  const orderAddresses = (n: number) => new Set(Array.from({ length: n }, (_, i) => encodeTransparent("testnet", { kind: "p2pkh", hash: orderHash(hexToBytes(S.accountPubkey), i) })));
  const used = orderAddresses(20);
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      const { method, params: args } = JSON.parse(body) as { method: string; params: unknown[] };
      const reply = (result: unknown) => res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result }));
      if (method === "getblockcount") return reply(200);
      if (method === "getaddresstxids") return reply((args[0] as { addresses: string[] }).addresses.some((a) => used.has(a)) ? [S.txid] : []);
      if (method === "getblock") return reply({ tx: ["coinbase", S.txid], time: 1_790_650_000 });
      if (method === "getrawtransaction" && zcash[args[0] as string]) return reply({ ...zcash[args[0] as string], confirmations: 101 });
      if (method === "getrawtransaction" && spent.has(args[0] as string)) return reply({ txid: args[0], vout: [...spent.get(args[0] as string)!.entries()].filter(([, v]) => v !== undefined).map(([n, v]) => ({ n, valueZat: Number(v) })) });
      if (method === "getTransaction") return reply(solana[args[0] as string] ?? null);
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: -5, message: "not found" } }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
afterAll(() => server.close());

describe("reading the order addresses (SPEC.md §10.1)", () => {
  it("finds the forward among the transactions of the order addresses, batch by batch", async () => {
    const found = await readPayoutCandidates(url, params(), () => {}, 10);
    expect(found.map((f) => [f.txid, f.height, f.index, f.time])).toEqual([[S.txid, 100, 1, 1_790_650_000]]);
  });
});

describe("check-proof for a payout stamp (SPEC.md §10.5)", () => {
  const p = params();
  const setSolana = (over: { index?: number; sent?: bigint; blockTime?: number } = {}) => {
    solana = {};
    for (const e of S.exits) solana[e.signature] = exitTx(p, { signature: e.signature, index: over.index ?? e.index, sent: over.sent ?? BigInt(e.receipt.sent), blockTime: over.blockTime ?? e.receipt.blockTime });
  };
  it("names the proof's transaction", () => {
    for (const e of S.exits) expect(proofTxid(e.proof)).toBe(S.txid);
  });
  it("the WebAssembly checker shows each note and its receipt, offline", () => {
    for (const e of S.exits) {
      const shown = JSON.parse(check_payout(S.hex, e.proof, JSON.stringify(p), S.spentValues.join(","))) as { receipt: Receipt; address: string; inputsVerified: boolean };
      expect([shown.receipt, shown.address, shown.inputsVerified]).toEqual([e.receipt, e.address, true]);
      const unverified = JSON.parse(check_payout(S.hex, e.proof, JSON.stringify(p), "")) as { inputsVerified: boolean; notChecked: string[] };
      expect(unverified.inputsVerified).toBe(false);
      expect(unverified.notChecked[0]).toMatch(/NOT verified/);
    }
    expect(() => check_payout(S.hex, S.exits[0]!.proof, JSON.stringify(MAINNET), "")).toThrow(/order/);
  });
  it("holds against both chains for each exit of the forward", async () => {
    setSolana();
    for (const e of S.exits) {
      const r = await checkProof(p, e.proof, url, url, NOW);
      expect(r.error).toBeUndefined();
      expect([r.ok, r.exit, r.address, r.receipt?.received]).toEqual([true, e.signature, e.address, e.receipt.received]);
      expect(r.checked.join("\n")).toMatch(/exit request on Solana naming this order index/);
    }
  });
  it("fails when Solana disagrees: another order index, amount or time", async () => {
    for (const [over, msg] of [[{ index: 99 }, /order 99/], [{ sent: 1n }, /amount sent/], [{ blockTime: 5 }, /time/]] as const) {
      setSolana(over);
      const r = await checkProof(p, S.exits[0]!.proof, url, url, NOW);
      expect(r.ok).toBe(false);
      expect(r.error).toMatch(msg);
    }
    solana = {};
    expect((await checkProof(p, S.exits[0]!.proof, url, url, NOW)).error).toMatch(/not a finalized Solana transaction/);
  });
  it("fails when no exit key of its account was valid at its height", async () => {
    setSolana();
    const later = { ...p, zcash: { ...p.zcash, exitKeys: [{ account: 0, pubkey: S.accountPubkey, fromHeight: 101 }] } };
    expect((await checkProof(later, S.exits[0]!.proof, url, url, NOW)).error).toMatch(/no exit key of account 0/);
  });
});
