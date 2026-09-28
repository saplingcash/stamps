/**
 * Test keys and example values. Each one is derived from a label under "sapling.cash/stamps/": the first
 * bytes of SHA-512("sapling.cash/stamps/" + name), so any value in the tests and the test vectors can be
 * recomputed from its name alone. stamper-core's tests use the same derivation (tests/common).
 */
import { sha512 } from "@noble/hashes/sha2";

export const LABEL_PREFIX = "sapling.cash/stamps/";

/** The first `length` bytes (at most 64) of SHA-512(LABEL_PREFIX + name). */
export function label(name: string, length = 32): Uint8Array {
  if (length > 64) throw new Error("a label gives at most 64 bytes");
  return sha512(new TextEncoder().encode(LABEL_PREFIX + name)).slice(0, length);
}
