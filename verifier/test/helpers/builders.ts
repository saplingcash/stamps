/** Test-only builders: Zcash v5 transparent transactions and Solana transactions in RPC JSON shape. */
import { randomBytes } from "node:crypto";
import { base58, base64 } from "@scure/base";
import { encodeRecord, signatureHash } from "../../src/record.ts";
import { destinationScript, encodeTransparent, type Destination } from "../../src/zcash/address.ts";
import { bytesToHex, hash160, V5_VERSION_GROUP_ID } from "../../src/zcash/tx.ts";
import { MEMO_PROGRAM, REDEEMED_EVENT_DISCRIMINATOR, REDEEM_DISCRIMINATOR, type Params } from "../../src/params.ts";
import type { RpcTransaction } from "../../src/solana/tx.ts";

// ---------------------------------------------------------------- Zcash

export const NU6_BRANCH = 0x4dec4df0;

function compactSize(n: number): number[] {
  if (n < 0xfd) return [n];
  return [0xfd, n & 0xff, n >> 8];
}
function u32(n: number): number[] {
  return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}
function i64(v: bigint): number[] {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigInt64(0, v, true);
  return [...b];
}

/** A fake issuer: a 33-byte compressed-looking key (the verifier never checks signatures; the node did). */
export function fakeKey(): { pubkey: Uint8Array; address(network: "mainnet" | "testnet"): string } {
  const pubkey = new Uint8Array(33);
  pubkey[0] = 0x02;
  pubkey.set(randomBytes(32), 1);
  return { pubkey, address: (network) => encodeTransparent(network, { kind: "p2pkh", hash: hash160(pubkey) }) };
}

export function p2pkhScriptSig(pubkey: Uint8Array): Uint8Array {
  const sig = new Uint8Array(71);
  sig[0] = 0x30;
  sig.set(randomBytes(69), 1);
  sig[70] = 0x01;
  return Uint8Array.from([sig.length, ...sig, pubkey.length, ...pubkey]);
}

export interface BuildTx {
  version?: number;
  branch?: number;
  inputs: { scriptSig: Uint8Array }[];
  outputs: { value: bigint; script: Uint8Array }[];
}
export function buildV5(t: BuildTx): string {
  const bytes: number[] = [];
  bytes.push(...u32(((t.version ?? 5) | 0x80000000) >>> 0), ...u32(V5_VERSION_GROUP_ID), ...u32(t.branch ?? NU6_BRANCH), ...u32(0), ...u32(0));
  bytes.push(...compactSize(t.inputs.length));
  for (const i of t.inputs) bytes.push(...randomBytes(32), ...u32(0), ...compactSize(i.scriptSig.length), ...i.scriptSig, ...u32(0xffffffff));
  bytes.push(...compactSize(t.outputs.length));
  for (const o of t.outputs) bytes.push(...i64(o.value), ...compactSize(o.script.length), ...o.script);
  bytes.push(0, 0, 0); // no Sapling spends, no Sapling outputs, no Orchard actions
  return bytesToHex(Uint8Array.from(bytes));
}

export function recordScript(sig: string, burned: bigint, harvested: bigint, ticker = "OWL"): Uint8Array {
  const rec = encodeRecord({ sigHash: signatureHash(base58.decode(sig)), burned, harvested, ticker });
  return Uint8Array.from([0x6a, 0x34, ...rec]);
}

/** A well-formed stamp for a request, spent by `issuer`, paying 546 zat to `to`. */
export function stampTx(issuer: Uint8Array, sig: string, burned: bigint, harvested: bigint, to: Destination, extra: Partial<BuildTx> = {}): string {
  return buildV5({
    inputs: [{ scriptSig: p2pkhScriptSig(issuer) }],
    outputs: [
      { value: 0n, script: recordScript(sig, burned, harvested) },
      { value: 546n, script: destinationScript(to) },
      { value: 100_000n, script: destinationScript({ kind: "p2pkh", hash: hash160(issuer) }) },
    ],
    ...extra,
  });
}

// ---------------------------------------------------------------- Solana

export const key = () => base58.encode(randomBytes(32));
export const sig = () => base58.encode(randomBytes(64));

export const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
export function testParams(over: Partial<Params> = {}, issuers: string[] = []): Params {
  return {
    solana: { programId: key(), zecMint: key(), tokenProgram: TOKEN_PROGRAM, feeAccount: key(), feeOwner: key() },
    zcash: { network: "testnet", issuers: issuers.map((address) => ({ address, fromHeight: 1 })), confirmations: 10 },
    fees: [{ from: 0, amount: "40000" }],
    refundAfterDays: 7,
    ...over,
  };
}

function u64le(v: bigint): number[] {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, v, true);
  return [...b];
}

export interface HarvestOpts {
  signature?: string;
  holder?: string;
  holderZec?: string;
  mint?: string;
  burned?: bigint;
  harvested?: bigint;
  fee?: bigint;
  memo?: string | null;
  blockTime?: number;
  err?: unknown;
  /** tweaks */
  extraMemo?: boolean;
  noEvent?: boolean;
  feeSource?: string;
  feeAuthority?: string;
  twoRedeems?: boolean;
}

/** A harvest with a stamp request, as the site builds it (budget omitted: it does not matter). */
export function harvestTx(p: Params, o: HarvestOpts = {}): RpcTransaction {
  const holder = o.holder ?? key();
  const holderZec = o.holderZec ?? key();
  const mint = o.mint ?? key();
  const burned = o.burned ?? 2_000_000_000_000n;
  const harvested = o.harvested ?? 42_000_000n;
  const keys = [holder, holderZec, p.solana.feeAccount, p.solana.programId, p.solana.tokenProgram, MEMO_PROGRAM, p.solana.zecMint, mint];
  const idx = (k: string) => {
    let i = keys.indexOf(k);
    if (i < 0) {
      keys.push(k);
      i = keys.length - 1;
    }
    return i;
  };
  // redeem accounts: holder, config, coin_vault, coin_mint, holder_coin, zec_mint, vault_zec, holder_zec, ...
  const redeemAccounts = [holder, key(), key(), mint, key(), p.solana.zecMint, key(), holderZec, key(), p.solana.tokenProgram, key(), key()].map(idx);
  const redeemData = base58.encode(Uint8Array.from([...REDEEM_DISCRIMINATOR, ...u64le(burned), ...u64le(harvested)]));
  const instructions = [{ programIdIndex: idx(p.solana.programId), accounts: redeemAccounts, data: redeemData }];
  if (o.twoRedeems) instructions.push({ programIdIndex: idx(p.solana.programId), accounts: redeemAccounts, data: redeemData });
  const fee = o.fee ?? 40_000n;
  instructions.push({
    programIdIndex: idx(p.solana.tokenProgram),
    accounts: [o.feeSource ?? holderZec, p.solana.zecMint, p.solana.feeAccount, o.feeAuthority ?? holder].map(idx),
    data: base58.encode(Uint8Array.from([12, ...u64le(fee), 8])),
  });
  const memos = o.memo === null ? [] : [o.memo ?? `sapling-stamp:1:${encodeTransparent("testnet", { kind: "p2pkh", hash: Uint8Array.from(randomBytes(20)) })}`];
  if (o.extraMemo) memos.push("hello");
  for (const m of memos) instructions.push({ programIdIndex: idx(MEMO_PROGRAM), accounts: [], data: base58.encode(new TextEncoder().encode(m)) });
  const ev = Uint8Array.from([...REDEEMED_EVENT_DISCRIMINATOR, ...base58.decode(mint), ...base58.decode(holder), ...u64le(burned), ...u64le(harvested), ...u64le(10n ** 15n), ...u64le(10n ** 9n)]);
  const logs = [
    `Program ${p.solana.programId} invoke [1]`,
    "Program log: Instruction: Redeem",
    `Program ${p.solana.tokenProgram} invoke [2]`,
    `Program data: ${base64.encode(Uint8Array.from([1, 2, 3]))}`,
    `Program ${p.solana.tokenProgram} success`,
    ...(o.noEvent ? [] : [`Program data: ${base64.encode(ev)}`]),
    `Program ${p.solana.programId} success`,
  ];
  return {
    slot: 1000,
    blockTime: o.blockTime ?? 1_800_000_000,
    meta: { err: o.err ?? null, logMessages: logs, loadedAddresses: { writable: [], readonly: [] } },
    transaction: { signatures: [o.signature ?? sig()], message: { accountKeys: keys, instructions } },
  };
}

export function refundTx(p: Params, requestSig: string, to: string, amount: bigint, authority = p.solana.feeOwner): RpcTransaction {
  const keys = [authority, p.solana.feeAccount, to, p.solana.zecMint, p.solana.tokenProgram, MEMO_PROGRAM];
  return {
    slot: 2000,
    blockTime: 1_800_000_500,
    meta: { err: null, logMessages: [], loadedAddresses: { writable: [], readonly: [] } },
    transaction: {
      signatures: [sig()],
      message: {
        accountKeys: keys,
        instructions: [
          { programIdIndex: 4, accounts: [1, 3, 2, 0], data: base58.encode(Uint8Array.from([12, ...u64le(amount), 8])) },
          { programIdIndex: 5, accounts: [], data: base58.encode(new TextEncoder().encode(`sapling-stamp-refund:1:${requestSig}`)) },
        ],
      },
    },
  };
}
