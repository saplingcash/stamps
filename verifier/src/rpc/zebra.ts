/**
 * Reads the issuers' transactions, and the transactions spent from order addresses (payout stamps), from a Zcash
 * node with the zcashd-compatible JSON-RPC that Zebra serves (getblockcount, getaddresstxids, getrawtransaction,
 * getblock).
 */
import { rpc } from "./jsonrpc.ts";
import type { ZcashTxInfo } from "../ledger.ts";
import type { Params } from "../params.ts";
import { orderHash } from "../payout.ts";
import { encodeTransparent } from "../zcash/address.ts";
import { inspectTx } from "../zcash/inspect.ts";
import { bytesToHex, hexToBytes, p2pkhSpenderHash } from "../zcash/tx.ts";

export async function readZcash(url: string, p: Params, log: (s: string) => void = () => {}): Promise<ZcashTxInfo[]> {
  const tip = await rpc<number>(url, "getblockcount", []);
  const start = Math.min(...p.zcash.issuers.map((i) => i.fromHeight));
  const txids = await rpc<string[]>(url, "getaddresstxids", [{ addresses: p.zcash.issuers.map((i) => i.address), start: Math.max(1, start), end: tip }]);
  const unique = [...new Set(txids)];
  log(`zcash: ${unique.length} transactions from the issuer addresses up to height ${tip}`);
  return readTxs(url, unique, tip);
}

/** Each transaction with its height, its position in its block and its block's time. */
async function readTxs(url: string, unique: string[], tip: number): Promise<ZcashTxInfo[]> {
  const blockTxs = new Map<number, { txs: string[]; time: number }>();
  const out: ZcashTxInfo[] = [];
  for (const txid of unique) {
    const t = await rpc<{ hex: string; height?: number; confirmations?: number }>(url, "getrawtransaction", [txid, 1]);
    const height = typeof t.height === "number" && t.height >= 0 ? t.height : null;
    let index = 0;
    let time: number | undefined;
    if (height !== null) {
      if (!blockTxs.has(height)) {
        const b = await rpc<{ tx: (string | { txid: string })[]; time: number }>(url, "getblock", [String(height), 1]);
        blockTxs.set(height, { txs: b.tx.map((x) => (typeof x === "string" ? x : x.txid)), time: b.time });
      }
      index = blockTxs.get(height)!.txs.indexOf(txid);
      time = blockTxs.get(height)!.time;
    }
    out.push({ txid, height, index, confirmations: t.confirmations ?? (height !== null ? tip - height + 1 : 0), rawHex: t.hex, ...(time !== undefined ? { time } : {}) });
  }
  return out;
}

/** order addresses per batch: the scan of an exit key stops at the first batch with no transaction */
export const ORDER_GAP = 200;

/**
 * The transactions spent from order addresses (SPEC.md §10.1): for each exit key of account 0, its order
 * addresses `0/0`, `0/1`, … are read in batches of ORDER_GAP until a batch has no transaction; of their
 * transactions, those that spend a coin of one of those addresses are the candidates (a transaction that does not
 * parse is kept, and the ledger says why it is not a payout stamp).
 */
export async function readPayoutCandidates(url: string, p: Params, log: (s: string) => void = () => {}, gap = ORDER_GAP): Promise<ZcashTxInfo[]> {
  const tip = await rpc<number>(url, "getblockcount", []);
  const ours = new Set<string>();
  const txids = new Set<string>();
  for (const k of (p.zcash.exitKeys ?? []).filter((x) => x.account === 0)) {
    const pub = hexToBytes(k.pubkey);
    for (let start = 0; ; start += gap) {
      const hashes = Array.from({ length: gap }, (_, i) => orderHash(pub, start + i));
      for (const h of hashes) ours.add(bytesToHex(h));
      const batch = hashes.map((hash) => encodeTransparent(p.zcash.network, { kind: "p2pkh", hash }));
      const found = await rpc<string[]>(url, "getaddresstxids", [{ addresses: batch, start: k.fromHeight, end: k.toHeight ?? tip }]);
      for (const t of found) txids.add(t);
      if (!found.length) break;
    }
  }
  log(`zcash: ${txids.size} transactions touch the order addresses up to height ${tip}`);
  const all = await readTxs(url, [...txids], tip);
  // a candidate spends a coin of an order address (deliveries to them are not)
  return all.filter((z) => {
    try {
      return inspectTx(z.rawHex).inputs.some((i) => {
        const h = p2pkhSpenderHash(hexToBytes(i.scriptSig));
        return h !== null && ours.has(bytesToHex(h));
      });
    } catch {
      return true;
    }
  });
}
