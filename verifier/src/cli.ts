#!/usr/bin/env -S npx tsx
/**
 * Rebuilds the set of Sapling stamps from both chains (SPEC.md) and checks the invariant.
 *
 *   npx tsx src/cli.ts --params ../params/testnet.json --solana <Solana RPC URL> --zcash <Zebra JSON-RPC URL> [--json]
 *
 * Read-only: it sends nothing. Exit code 0 when the invariant holds, 1 when it does not, 2 on errors.
 */
import { readFileSync } from "node:fs";
import { buildLedger } from "./ledger.ts";
import { checkParams, type Params } from "./params.ts";
import { readSolana } from "./rpc/solana.ts";
import { readZcash } from "./rpc/zebra.ts";

const args = process.argv.slice(2);
const opt = (n: string) => {
  const i = args.indexOf(`--${n}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const paramsFile = opt("params");
const solanaUrl = opt("solana");
const zcashUrl = opt("zcash");
if (!paramsFile || !solanaUrl || !zcashUrl) {
  console.error("usage: stamps-verify --params <file> --solana <url> --zcash <url> [--json]");
  process.exit(2);
}
const p = JSON.parse(readFileSync(paramsFile, "utf8")) as Params;
const problems = checkParams(p);
if (problems.length) {
  console.error(`the parameter file is not usable:\n  ${problems.join("\n  ")}`);
  process.exit(2);
}
const json = args.includes("--json");
const log = (s: string) => (json ? undefined : console.error(s));
try {
  const sol = await readSolana(solanaUrl, p, log);
  const zec = await readZcash(zcashUrl, p, log);
  const ledger = buildLedger(p, sol.requests, sol.refunds, zec, Math.floor(Date.now() / 1000), sol.unreadable);
  const replacer = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v);
  if (json) console.log(JSON.stringify({ ...ledger, ignoredSolana: sol.ignored }, replacer, 2));
  else {
    const t = ledger.totals;
    console.log(`requests ${t.requests}: stamped ${t.stamped}, refunded ${t.refunded}, pending ${t.pending}, overdue ${t.overdue}, unresolved ${t.unresolved}`);
    console.log(`fees paid ${t.feesPaid} ZEC base units, refunded ${t.refundedAmount}`);
    for (const s of ledger.stamps) console.log(`stamp ${s.id}  $${s.ticker}  burned ${s.burned}  harvested ${s.harvested}  fee ${s.fee}  received ${s.received}  → ${s.address}  (Solana ${s.request})`);
    for (const r of ledger.rejected) console.log(`not a stamp ${r.txid}: ${r.reason}`);
    console.log(ledger.invariant.ok ? "invariant: OK" : `invariant: BROKEN\n  ${ledger.invariant.problems.join("\n  ")}`);
  }
  process.exit(ledger.invariant.ok ? 0 : 1);
} catch (e) {
  console.error(`could not read the chains: ${(e as Error).message}`);
  process.exit(2);
}
