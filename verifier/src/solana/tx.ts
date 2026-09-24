/**
 * Reads Solana transactions in the JSON shape of `getTransaction` (encoding "json",
 * maxSupportedTransactionVersion 0), and classifies them as stamp requests (SPEC.md §2) or refunds (§5).
 */
import { base58, base64 } from "@scure/base";
import { MEMO_PROGRAM, REDEEMED_EVENT_DISCRIMINATOR, REDEEM_DISCRIMINATOR, REFUND_MEMO_PREFIX, REQUEST_MEMO_PREFIX, requiredFee, type Params } from "../params.ts";

export interface RpcInstruction {
  programIdIndex: number;
  accounts: number[];
  data: string;
}
export interface RpcTransaction {
  slot: number;
  blockTime: number | null;
  meta: { err: unknown; logMessages?: string[] | null; loadedAddresses?: { writable: string[]; readonly: string[] } | null } | null;
  transaction: { signatures: string[]; message: { accountKeys: string[]; instructions: RpcInstruction[] } };
}

export interface Request {
  signature: string;
  slot: number;
  blockTime: number;
  mint: string;
  holder: string;
  /** the holder's ZEC account (redeem account #7), where a refund goes */
  source: string;
  burned: bigint;
  harvested: bigint;
  feePaid: bigint;
  address: string;
}
export interface Refund {
  signature: string;
  slot: number;
  /** the request it refunds */
  requestSignature: string;
  to: string;
  amount: bigint;
}
export type Classified = { kind: "request"; request: Request } | { kind: "refund"; refund: Refund } | { kind: "other"; reason: string };

interface Ix {
  programId: string;
  accounts: string[];
  data: Uint8Array;
}

function keysOf(tx: RpcTransaction): string[] {
  const l = tx.meta?.loadedAddresses;
  return [...tx.transaction.message.accountKeys, ...(l?.writable ?? []), ...(l?.readonly ?? [])];
}

function topLevel(tx: RpcTransaction): Ix[] {
  const keys = keysOf(tx);
  return tx.transaction.message.instructions.map((ix) => ({
    programId: keys[ix.programIdIndex] ?? "",
    accounts: ix.accounts.map((a) => keys[a] ?? ""),
    data: base58.decode(ix.data),
  }));
}

const startsWith = (b: Uint8Array, p: Uint8Array) => b.length >= p.length && p.every((x, i) => b[i] === x);
const u64 = (b: Uint8Array, off: number) => new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(off, true);

/** `Program data:` payloads logged while `programId` was the executing program. */
export function programData(logs: string[], programId: string): Uint8Array[] {
  const stack: string[] = [];
  const out: Uint8Array[] = [];
  for (const line of logs) {
    const invoke = /^Program (\S+) invoke \[\d+\]$/.exec(line);
    if (invoke) {
      stack.push(invoke[1]!);
      continue;
    }
    if (/^Program \S+ (success|failed)/.test(line)) {
      stack.pop();
      continue;
    }
    if (line.startsWith("Program data: ") && stack[stack.length - 1] === programId) {
      for (const part of line.slice("Program data: ".length).split(" ")) {
        try {
          out.push(base64.decode(part));
        } catch {
          /* not base64: ignore */
        }
      }
    }
  }
  return out;
}

interface Transfer {
  source: string;
  mint: string;
  destination: string;
  authority: string;
  amount: bigint;
}
function transferChecked(ix: Ix, tokenProgram: string): Transfer | null {
  if (ix.programId !== tokenProgram || ix.data.length !== 10 || ix.data[0] !== 12 || ix.accounts.length < 4) return null;
  return { source: ix.accounts[0]!, mint: ix.accounts[1]!, destination: ix.accounts[2]!, authority: ix.accounts[3]!, amount: u64(ix.data, 1) };
}

function memoText(ix: Ix): string | null {
  if (ix.programId !== MEMO_PROGRAM) return null;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(ix.data);
  } catch {
    return null;
  }
}

export function classify(tx: RpcTransaction, p: Params): Classified {
  const signature = tx.transaction.signatures[0] ?? "";
  if (!tx.meta || tx.meta.err !== null) return { kind: "other", reason: "failed or has no status" };
  if (tx.blockTime === null) return { kind: "other", reason: "no block time" };
  const ixs = topLevel(tx);
  const memos = ixs.filter((i) => i.programId === MEMO_PROGRAM);
  const transfers = ixs.map((i) => transferChecked(i, p.solana.tokenProgram)).filter((t): t is Transfer => t !== null);

  // a refund (SPEC.md §5)
  const refundMemo = memos.length === 1 ? memoText(memos[0]!) : null;
  if (refundMemo?.startsWith(REFUND_MEMO_PREFIX)) {
    const out = transfers.filter((t) => t.source === p.solana.feeAccount);
    if (out.length !== 1) return { kind: "other", reason: "refund memo without exactly one transfer from the fee account" };
    const t = out[0]!;
    if (t.mint !== p.solana.zecMint || t.authority !== p.solana.feeOwner) return { kind: "other", reason: "refund transfer has the wrong mint or authority" };
    return { kind: "refund", refund: { signature, slot: tx.slot, requestSignature: refundMemo.slice(REFUND_MEMO_PREFIX.length), to: t.destination, amount: t.amount } };
  }

  // a request (SPEC.md §2)
  const redeems = ixs.filter((i) => i.programId === p.solana.programId && startsWith(i.data, REDEEM_DISCRIMINATOR));
  if (redeems.length !== 1) return { kind: "other", reason: `R2: ${redeems.length} redeem instructions` };
  const redeem = redeems[0]!;
  const holder = redeem.accounts[0];
  const source = redeem.accounts[7];
  if (!holder || !source) return { kind: "other", reason: "R2: redeem has too few accounts" };
  const events = programData(tx.meta.logMessages ?? [], p.solana.programId).filter((d) => startsWith(d, REDEEMED_EVENT_DISCRIMINATOR));
  if (events.length !== 1) return { kind: "other", reason: `R3: ${events.length} Redeemed events` };
  const ev = events[0]!;
  if (ev.length < 8 + 32 + 32 + 32) return { kind: "other", reason: "R3: Redeemed event is too short" };
  const mint = base58.encode(ev.slice(8, 40));
  const evHolder = base58.encode(ev.slice(40, 72));
  if (evHolder !== holder) return { kind: "other", reason: "R3: event holder differs from the redeem's holder" };
  const burned = u64(ev, 72);
  const harvested = u64(ev, 80);
  if (memos.length !== 1) return { kind: "other", reason: `R4: ${memos.length} memo instructions` };
  const memo = memoText(memos[0]!);
  if (!memo || !memo.startsWith(REQUEST_MEMO_PREFIX)) return { kind: "other", reason: "R4: the memo is not a stamp request" };
  const address = memo.slice(REQUEST_MEMO_PREFIX.length);
  if (!address || /\s/.test(address)) return { kind: "other", reason: "R4: the address is empty or contains whitespace" };
  const fees = transfers.filter((t) => t.destination === p.solana.feeAccount);
  if (fees.length !== 1) return { kind: "other", reason: `R5: ${fees.length} transfers to the fee account` };
  const f = fees[0]!;
  if (f.source !== source || f.mint !== p.solana.zecMint || f.authority !== holder) return { kind: "other", reason: "R5: the fee transfer's source, mint or authority is wrong" };
  const need = requiredFee(p.fees, tx.blockTime);
  if (need === null || f.amount < need) return { kind: "other", reason: `R5: fee ${f.amount} is below the required ${need}` };
  return { kind: "request", request: { signature, slot: tx.slot, blockTime: tx.blockTime, mint, holder, source, burned, harvested, feePaid: f.amount, address } };
}
