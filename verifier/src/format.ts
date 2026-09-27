/** ZEC base units (8 decimals) as a decimal ZEC amount, exactly (no floating point). */
export function formatZec(units: bigint): string {
  const neg = units < 0n;
  const a = neg ? -units : units;
  return `${neg ? "-" : ""}${a / 100_000_000n}.${(a % 100_000_000n).toString().padStart(8, "0")}`;
}
