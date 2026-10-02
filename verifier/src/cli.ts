#!/usr/bin/env -S npx tsx
/**
 * Rebuilds the set of Sapling stamps from both chains (SPEC.md) and checks the invariant.
 *
 *   npx tsx src/cli.ts --params ../params/mainnet.json --solana <Solana RPC URL> --zcash <Zebra JSON-RPC URL> [--json]
 *
 * Read-only: it sends nothing. Exit code 0 when the invariant holds, 1 when it does not, 2 on errors
 * (bad arguments, an unusable parameter file, a chain that could not be read). The exit code is set,
 * never forced with process.exit(), so piped output is always written in full.
 *
 *   npx tsx src/cli.ts check-proof --params <file> --solana <url> --zcash <url> --proof splg-proof:1:…
 *
 * checks one private stamp's proof against both chains (SPEC.md §9.6), or a payout stamp's (splg-proof:2:…,
 * §10.5): exit 0 when it holds, 1 when it does not, 2 on errors. It prints what it checked and what it did not.
 *
 *   npx tsx src/cli.ts --params <file> --solana <url> --zcash <url> --exits <file>
 *
 * also rebuilds the payout stamps (§10): the order addresses of the published exit keys are read from Zcash, and
 * the exits in <file> (their Solana signatures, one per line) from Solana.
 */
import { readFileSync } from "node:fs";
import { formatZec } from "./format.ts";
import { buildLedger, buildPayoutLedger } from "./ledger.ts";
import { checkParams, type Params } from "./params.ts";
import { readExitRequests, readSolana } from "./rpc/solana.ts";
import { readPayoutCandidates, readZcash } from "./rpc/zebra.ts";
import { checkProof } from "./checkproof.ts";
import { loadInspectorFromDisk } from "./zcash/inspect.ts";

const USAGE = `usage: stamps-verify --params <file> --solana <url> --zcash <url> [--json]
       stamps-verify --params <file> --solana <url> --zcash <url> --exits <file> [--json]
       stamps-verify check-proof --params <file> --solana <url> --zcash <url> --proof splg-proof:1:…|splg-proof:2:…

  --params <file>  the deployment's parameter file (params/mainnet.json)
  --solana <url>   a Solana JSON-RPC endpoint
  --zcash <url>    a Zcash node's JSON-RPC (getblockcount, getaddresstxids, getrawtransaction, getblock)
  --json           print the full result as JSON
  --exits <file>   also rebuild the payout stamps (SPEC.md §10): the exits' Solana signatures, one per line
  --proof <proof>  check-proof: the stamp proof to check (a private stamp's or a payout stamp's)

Read-only. Exit code 0 when the invariant (or the proof) holds, 1 when it does not, 2 on errors.`;

async function main(args: string[]): Promise<number> {
  if (args.includes("--help") || args.includes("-h")) {
    console.log(USAGE);
    return 0;
  }
  const proofMode = args[0] === "check-proof";
  const opt = (n: string) => {
    const i = args.indexOf(`--${n}`);
    if (i < 0) return undefined;
    const v = args[i + 1];
    return v === undefined || v.startsWith("--") ? "" : v;
  };
  const paramsFile = opt("params");
  const solanaUrl = opt("solana");
  const zcashUrl = opt("zcash");
  const proof = opt("proof");
  const required = proofMode ? ["params", "solana", "zcash", "proof"] : ["params", "solana", "zcash"];
  const missing = required.filter((n) => !opt(n));
  if (!paramsFile || !solanaUrl || !zcashUrl || (proofMode && !proof)) {
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
  // private stamps are v6 transactions, read by librustzcash compiled to WebAssembly (wasm/)
  try {
    await loadInspectorFromDisk();
  } catch (e) {
    console.error(`cannot load the transaction reader (wasm/): ${(e as Error).message}`);
    return 2;
  }
  const json = args.includes("--json");
  const log = (s: string) => (json ? undefined : console.error(s));
  if (proofMode) {
    let r;
    try {
      r = await checkProof(p, proof!, solanaUrl, zcashUrl);
    } catch (e) {
      console.error(`could not read the chains: ${(e as Error).message}`);
      return 2;
    }
    console.log(JSON.stringify(r, null, 2));
    return r.ok ? 0 : 1;
  }
  const exitsFile = opt("exits");
  let exitSigs: string[] | null = null;
  if (exitsFile !== undefined) {
    if (!(p.zcash.exitKeys ?? []).length) {
      console.error("--exits: the parameter file names no exit key (zcash.exitKeys)");
      return 2;
    }
    try {
      exitSigs = readFileSync(exitsFile, "utf8").split(/\s+/).filter(Boolean);
    } catch (e) {
      console.error(`cannot read the exits file ${exitsFile}: ${(e as Error).message}`);
      return 2;
    }
  }
  let sol, zec, exits, forwards;
  try {
    sol = await readSolana(solanaUrl, p, log);
    zec = await readZcash(zcashUrl, p, log);
    if (exitSigs) {
      exits = await readExitRequests(solanaUrl, p, exitSigs);
      forwards = await readPayoutCandidates(zcashUrl, p, log);
    }
  } catch (e) {
    console.error(`could not read the chains: ${(e as Error).message}`);
    return 2;
  }
  const now = Math.floor(Date.now() / 1000);
  const ledger = buildLedger(p, sol.requests, sol.refunds, zec, now, sol.unreadable);
  // payout stamps break no invariant: an exit without one was refunded by the bridge or paid out another way (§10.6)
  const payouts = exits && forwards ? buildPayoutLedger(p, exits.exits, forwards, now, exits.unreadable) : null;
  const replacer = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v);
  if (json) console.log(JSON.stringify({ ...ledger, ignoredSolana: sol.ignored, ...(payouts ? { payouts: { ...payouts, ignoredExits: exits!.ignored } } : {}) }, replacer, 2));
  else {
    const t = ledger.totals;
    console.log(`requests ${t.requests}: stamped ${t.stamped}, refunded ${t.refunded}, pending ${t.pending}, overdue ${t.overdue}, unresolved ${t.unresolved}`);
    console.log(`fees paid ${formatZec(t.feesPaid)} ZEC, refunded ${formatZec(t.refundedAmount)} ZEC`);
    for (const s of ledger.stamps) console.log(`stamp ${s.id}  $${s.ticker}  burned ${s.burned} (coin base units)  harvested ${formatZec(s.harvested)} ZEC  fee ${formatZec(s.fee)} ZEC  received ${formatZec(s.received)} ZEC  → ${s.mode === "private" ? "a shielded address (private stamp)" : s.address}  (Solana ${s.request})`);
    for (const r of ledger.rejected) console.log(`not a stamp ${r.txid}: ${r.reason}`);
    if (payouts) {
      const t = payouts.totals;
      console.log(`exits ${t.exits}: payout stamps ${t.stamped}, pending ${t.pending}, without a payout stamp ${t.unstamped}, unresolved ${t.unresolved}; sent ${formatZec(t.sent)} ZEC, into the shielded pool ${formatZec(t.intoPool)} ZEC`);
      for (const s of payouts.stamps) console.log(`payout stamp ${s.id}  exit ${s.exit} (order ${s.index}, ${s.position + 1} of ${s.exits})  sent ${formatZec(s.sent)} ZEC  → a shielded address`);
      for (const r of payouts.rejected) console.log(`not a payout stamp ${r.txid}: ${r.reason}`);
      for (const i of exits!.ignored) console.log(`not an exit ${i.signature}: ${i.reason}`);
    }
    console.log(ledger.invariant.ok ? "invariant: OK" : `invariant: BROKEN\n  ${ledger.invariant.problems.join("\n  ")}`);
  }
  return ledger.invariant.ok ? 0 : 1;
}

process.exitCode = await main(process.argv.slice(2));
