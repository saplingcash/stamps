import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { bech32m } from "@scure/base";
import { f4jumble, f4jumbleInv } from "../src/zcash/f4jumble.ts";
import { decodeAddress, destinationScript, encodeTransparent } from "../src/zcash/address.ts";
import { bytesToHex, hexToBytes } from "../src/zcash/tx.ts";

const load = (f: string) => JSON.parse(readFileSync(new URL(`./fixtures/${f}`, import.meta.url), "utf8")) as unknown[][];

describe("F4Jumble (ZIP 316), against the official test vectors", () => {
  const rows = load("zcash-f4jumble.json").slice(2) as [string, string][];
  it(`jumbles and unjumbles all ${rows.length} vectors`, () => {
    for (const [normal, jumbled] of rows) {
      expect(bytesToHex(f4jumble(hexToBytes(normal)))).toBe(jumbled);
      expect(bytesToHex(f4jumbleInv(hexToBytes(jumbled)))).toBe(normal);
    }
  });
  it("refuses inputs shorter than 38 bytes", () => {
    expect(() => f4jumble(new Uint8Array(37))).toThrow();
  });
});

describe("Unified Addresses (ZIP 316), against the official test vectors", () => {
  const rows = load("zcash-unified-address.json").slice(2) as (string | number | null)[][];
  it(`finds the transparent receiver of every vector that has one, and refuses the rest (${rows.length} vectors)`, () => {
    let withT = 0;
    for (const r of rows) {
      const [p2pkh, p2sh, , , , , ua] = r as [string | null, string | null, unknown, unknown, unknown, unknown, string];
      const d = decodeAddress(ua, "mainnet");
      if (p2pkh || p2sh) {
        withT++;
        expect(d).toMatchObject({ ok: true, form: "unified" });
        if (d.ok) {
          expect(d.destination.kind).toBe(p2pkh ? "p2pkh" : "p2sh");
          expect(bytesToHex(d.destination.hash)).toBe(p2pkh ?? p2sh);
        }
      } else {
        expect(d).toMatchObject({ ok: false });
        if (!d.ok) expect(d.reason).toMatch(/no transparent receiver/);
      }
    }
    expect(withT).toBeGreaterThan(0);
  });
  it("refuses a vector on the wrong network, and one with a broken checksum", () => {
    const ua = (rows.find((r) => r[0]) as string[])[6]!;
    expect(decodeAddress(ua, "testnet").ok).toBe(false);
    const broken = ua.slice(0, -1) + (ua.endsWith("q") ? "p" : "q");
    expect(decodeAddress(broken, "mainnet").ok).toBe(false);
  });
  it("refuses a UA with a MUST-understand metadata item (typecodes 0xE0–0xFC)", () => {
    // a revision-2 transparent-enabled UA: a P2PKH receiver, then metadata item 0xE0
    const hrp = "tu";
    const items = Uint8Array.from([0x00, 20, ...new Uint8Array(20).fill(9), 0xe0, 1, 0]);
    const pad = new Uint8Array(16);
    pad.set(new TextEncoder().encode(hrp));
    const s = bech32m.encode(hrp, bech32m.toWords(f4jumble(Uint8Array.from([...items, ...pad]))), false);
    const d = decodeAddress(s, "mainnet");
    expect(d.ok).toBe(false);
    // the same UA without the metadata item is accepted
    const ok = bech32m.encode(hrp, bech32m.toWords(f4jumble(Uint8Array.from([0x00, 20, ...new Uint8Array(20).fill(9), ...pad]))), false);
    expect(decodeAddress(ok, "mainnet")).toMatchObject({ ok: true, destination: { kind: "p2pkh" } });
  });
});

describe("transparent and TEX addresses", () => {
  it("decodes the ZIP 320 example pair to the same key hash", () => {
    const t = decodeAddress("t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC", "mainnet");
    const tex = decodeAddress("tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte", "mainnet");
    expect(t).toMatchObject({ ok: true, form: "transparent", destination: { kind: "p2pkh" } });
    expect(tex).toMatchObject({ ok: true, form: "tex", destination: { kind: "p2pkh" } });
    if (t.ok && tex.ok) expect(bytesToHex(t.destination.hash)).toBe(bytesToHex(tex.destination.hash));
  });
  it("round-trips P2PKH and P2SH on both networks, and keeps networks apart", () => {
    const hash = Uint8Array.from({ length: 20 }, (_, i) => i);
    for (const network of ["mainnet", "testnet"] as const)
      for (const kind of ["p2pkh", "p2sh"] as const) {
        const a = encodeTransparent(network, { kind, hash });
        expect(decodeAddress(a, network)).toMatchObject({ ok: true, destination: { kind, hash } });
        expect(decodeAddress(a, network === "mainnet" ? "testnet" : "mainnet").ok).toBe(false);
      }
    expect(encodeTransparent("mainnet", { kind: "p2pkh", hash }).startsWith("t1")).toBe(true);
    expect(encodeTransparent("mainnet", { kind: "p2sh", hash }).startsWith("t3")).toBe(true);
    expect(encodeTransparent("testnet", { kind: "p2pkh", hash }).startsWith("tm")).toBe(true);
    expect(encodeTransparent("testnet", { kind: "p2sh", hash }).startsWith("t2")).toBe(true);
  });
  it("refuses a bad checksum, shielded addresses, whitespace and junk, with a reason", () => {
    const good = "t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC";
    expect(decodeAddress(good.slice(0, -1) + "D", "mainnet").ok).toBe(false);
    expect(decodeAddress("zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly", "mainnet")).toMatchObject({ ok: false, reason: expect.stringMatching(/shielded/) });
    expect(decodeAddress(` ${good}`, "mainnet").ok).toBe(false);
    expect(decodeAddress("hello", "mainnet").ok).toBe(false);
  });
  it("builds the standard destination scripts", () => {
    const hash = new Uint8Array(20).fill(0xab);
    expect(bytesToHex(destinationScript({ kind: "p2pkh", hash }))).toBe(`76a914${"ab".repeat(20)}88ac`);
    expect(bytesToHex(destinationScript({ kind: "p2sh", hash }))).toBe(`a914${"ab".repeat(20)}87`);
  });
});
