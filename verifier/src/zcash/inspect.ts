/**
 * Reading v6 transactions (private stamps, SPEC.md §9.4) with librustzcash compiled to WebAssembly
 * (`stamp-proof-wasm`, built into ../../wasm). The txid is computed there, never taken from a node.
 * The module is loaded once, from bytes, so the same code runs in Node and in a browser.
 */
import { initSync, inspect } from "../../wasm/sapling_stamp_proof_wasm.js";

export interface Inspected {
  txid: string;
  version: number;
  consensusBranchId: number;
  expiryHeight: number;
  inputs: { prevTxid: string; prevIndex: number; scriptSig: string }[];
  outputs: { value: number; script: string }[];
  sapling: boolean;
  sprout: boolean;
  orchard: boolean;
  ironwood: { actions: number; valueBalance: number } | null;
}

let loaded = false;

/** Loads the WebAssembly module from its bytes (`wasm/sapling_stamp_proof_wasm_bg.wasm`). */
export function loadInspector(wasm: Uint8Array | ArrayBuffer): void {
  if (loaded) return;
  initSync({ module: wasm });
  loaded = true;
}

export function inspectorLoaded(): boolean {
  return loaded;
}

/** Reads a transaction; throws if it does not parse or the module is not loaded. */
export function inspectTx(rawHex: string): Inspected {
  if (!loaded) throw new Error("the v6 reader is not loaded (loadInspector)");
  return JSON.parse(inspect(rawHex)) as Inspected;
}

/** Node only: loads the module from this package's wasm/ directory. */
export async function loadInspectorFromDisk(): Promise<void> {
  const { readFileSync } = await import("node:fs");
  loadInspector(readFileSync(new URL("../../wasm/sapling_stamp_proof_wasm_bg.wasm", import.meta.url)));
}
