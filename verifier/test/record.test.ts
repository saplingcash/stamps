import { describe, expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import { RECORD_SIZE, decodeRecord, encodeRecord, signatureHash, tickerBytes } from "../src/record.ts";
import { REDEEMED_EVENT_DISCRIMINATOR, REDEEM_DISCRIMINATOR, requiredFee } from "../src/params.ts";

const enc = new TextEncoder();

describe("the record (SPEC §3)", () => {
  const sigHash = signatureHash(new Uint8Array(64).fill(7));
  it("round-trips, is 52 bytes, and starts with SPLG v1", () => {
    const b = encodeRecord({ sigHash, burned: 2_000_000_000_000n, harvested: 42_000_000n, ticker: "OWL" });
    expect(b.length).toBe(RECORD_SIZE);
    expect(Array.from(b.slice(0, 5))).toEqual([0x53, 0x50, 0x4c, 0x47, 1]);
    const d = decodeRecord(b);
    expect(d).toEqual({ sigHash, burned: 2_000_000_000_000n, harvested: 42_000_000n, ticker: "OWL" });
  });
  it("keeps the largest u64 amounts", () => {
    const max = (1n << 64n) - 1n;
    expect(decodeRecord(encodeRecord({ sigHash, burned: max, harvested: max, ticker: "" }))).toMatchObject({ burned: max, harvested: max, ticker: "" });
    expect(() => encodeRecord({ sigHash, burned: max + 1n, harvested: 0n, ticker: "" })).toThrow();
  });
  it("cuts the ticker to 10 bytes at a character boundary", () => {
    expect(tickerBytes("ABCDEFGHIJKL").length).toBe(10);
    expect(new TextDecoder().decode(tickerBytes("ÄÄÄÄÄÄ"))).toBe("ÄÄÄÄÄ"); // 2 bytes each: 5 fit
    expect(new TextDecoder().decode(tickerBytes("🌱🌱🌱"))).toBe("🌱🌱"); // 4 bytes each: 2 fit
  });
  it("refuses a wrong tag, version, length, ticker length or non-zero padding", () => {
    const good = encodeRecord({ sigHash, burned: 1n, harvested: 1n, ticker: "A" });
    const bad = (f: (b: Uint8Array) => void) => {
      const b = good.slice();
      f(b);
      return decodeRecord(b);
    };
    expect(bad((b) => (b[0] = 0x58))).toHaveProperty("error");
    expect(bad((b) => (b[4] = 2))).toHaveProperty("error");
    expect(bad((b) => (b[41] = 11))).toHaveProperty("error");
    expect(bad((b) => (b[51] = 1))).toHaveProperty("error");
    expect(decodeRecord(good.slice(0, 51))).toHaveProperty("error");
  });
  it("hashes the 64-byte signature and keeps 20 bytes", () => {
    const s = new Uint8Array(64).fill(1);
    expect(signatureHash(s)).toEqual(sha256(s).slice(0, 20));
    expect(() => signatureHash(new Uint8Array(63))).toThrow();
  });
});

describe("the constants SPEC §2 names", () => {
  it("are Anchor's discriminators for redeem and Redeemed", () => {
    expect(REDEEM_DISCRIMINATOR).toEqual(sha256(enc.encode("global:redeem")).slice(0, 8));
    expect(REDEEMED_EVENT_DISCRIMINATOR).toEqual(sha256(enc.encode("event:Redeemed")).slice(0, 8));
  });
});

describe("the required fee (SPEC §2 R5): the smallest in force in the last 24 hours", () => {
  const fees = [
    { from: 0, amount: "40000" },
    { from: 1_000_000, amount: "10000" },
    { from: 2_000_000, amount: "20000" },
  ];
  it("uses the current fee, and honours a lower one within 24 hours of a change", () => {
    expect(requiredFee(fees, 500_000)).toBe(40000n);
    expect(requiredFee(fees, 1_000_010)).toBe(10000n);
    expect(requiredFee(fees, 2_000_010)).toBe(10000n); // the fee rose 10 s ago: the lower one still counts
    expect(requiredFee(fees, 2_100_000)).toBe(20000n);
  });
  it("is null before the first entry", () => {
    expect(requiredFee([{ from: 100, amount: "1" }], 50)).toBeNull();
  });
});
