#!/usr/bin/env -S npx tsx
/**
 * Rebuilds the set of Sapling stamps from both chains (SPEC.md) and checks the invariant.
 *
 *   npx tsx src/cli.ts --params ../params/mainnet.json --solana <Solana RPC URL> --zcash <Zebra JSON-RPC URL> [--json]
 *
 * Read-only: it sends nothing. Exit code 0 when the invariant holds, 1 when it does not, 2 on errors
 * (bad arguments, an unusable parameter file, a chain that could not be read). The exit code is set,
 * never forced with process.exit(), so piped output is always written in full.
 */
import { readFileSync } from "node:fs";
import { formatZec } from "./format.ts";
import { buildLedger } from "./ledger.ts";
import { checkParams, type Params } from "./params.ts";
import { readSolana } from "./rpc/solana.ts";
import { readZcash } from "./rpc/zebra.ts";

const USAGE = `usage: stamps-verify --params <file> --solana <url> --zcash <url> [--json]

  --params <file>  the deployment's parameter file (params/mainnet.json)
  --solana <url>   a Solana JSON-RPC endpoint
  --zcash <url>    a Zcash node's JSON-RPC (getblockcount, getaddresstxids, getrawtransaction, getblock)
  --json           print the full result as JSON

Read-only. Exit code 0 when the invariant holds, 1 when it does not, 2 on errors.`;

async function main(args: string[]): Promise<number> {
  if (args.includes("--help") || args.includes("-h")) {
    console.log(USAGE);
    return 0;
  }
  const opt = (n: string) => {
    const i = args.indexOf(`--${n}`);
    if (i < 0) return undefined;
    const v = args[i + 1];
    return v === undefined || v.startsWith("--") ? "" : v;
  };
  const paramsFile = opt("params");
  const solanaUrl = opt("solana");
  const zcashUrl = opt("zcash");
  const missing = (["params", "solana", "zcash"] as const).filter((n) => !opt(n));
  if (!paramsFile || !solanaUrl || !zcashUrl) {
    console.error(`missing ${missing.map((n) => `--${n}`).join(", ")}\n\n${USAGE}`);
    return 2;
  }
  let p: Params;
  try {
    p = JSON.parse(readFileSync(paramsFile, "utf8")) as Params;
  } catch (e) {
    console.error(`cannot read the parameter file ${paramsFile}: ${(e as Error).message}`);
    return 2;
  }
  const problems = checkParams(p);
  if (problems.length) {
    console.error(`the parameter file is not usable:\n  ${problems.join("\n  ")}`);
    return 2;
  }
  const json = args.includes("--json");
  const log = (s: string) => (json ? undefined : console.error(s));
  let sol, zec;
  try {
    sol = await readSolana(solanaUrl, p, log);
    zec = await readZcash(zcashUrl, p, log);
  } catch (e) {
    console.error(`could not read the chains: ${(e as Error).message}`);
    return 2;
  }
  const ledger = buildLedger(p, sol.requests, sol.refunds, zec, Math.floor(Date.now() / 1000), sol.unreadable);
  const replacer = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v);
  if (json) console.log(JSON.stringify({ ...ledger, ignoredSolana: sol.ignored }, replacer, 2));
  else {
    const t = ledger.totals;
    console.log(`requests ${t.requests}: stamped ${t.stamped}, refunded ${t.refunded}, pending ${t.pending}, overdue ${t.overdue}, unresolved ${t.unresolved}`);
    console.log(`fees paid ${formatZec(t.feesPaid)} ZEC, refunded ${formatZec(t.refundedAmount)} ZEC`);
    for (const s of ledger.stamps) console.log(`stamp ${s.id}  $${s.ticker}  burned ${s.burned} (coin base units)  harvested ${formatZec(s.harvested)} ZEC  fee ${formatZec(s.fee)} ZEC  received ${formatZec(s.received)} ZEC  → ${s.address}  (Solana ${s.request})`);
    for (const r of ledger.rejected) console.log(`not a stamp ${r.txid}: ${r.reason}`);
    console.log(ledger.invariant.ok ? "invariant: OK" : `invariant: BROKEN\n  ${ledger.invariant.problems.join("\n  ")}`);
  }
  return ledger.invariant.ok ? 0 : 1;
}

process.exitCode = await main(process.argv.slice(2));
