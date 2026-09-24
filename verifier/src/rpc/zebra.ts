/**
 * Reads the issuers' transactions from a Zcash node with the zcashd-compatible JSON-RPC that Zebra
 * serves (getblockcount, getaddresstxids, getrawtransaction, getblock).
 */
import { rpc } from "./jsonrpc.ts";
import type { ZcashTxInfo } from "../ledger.ts";
import type { Params } from "../params.ts";

export async function readZcash(url: string, p: Params, log: (s: string) => void = () => {}): Promise<ZcashTxInfo[]> {
  const tip = await rpc<number>(url, "getblockcount", []);
  const start = Math.min(...p.zcash.issuers.map((i) => i.fromHeight));
  const txids = await rpc<string[]>(url, "getaddresstxids", [{ addresses: p.zcash.issuers.map((i) => i.address), start: Math.max(1, start), end: tip }]);
  const unique = [...new Set(txids)];
  log(`zcash: ${unique.length} transactions from the issuer addresses up to height ${tip}`);
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
