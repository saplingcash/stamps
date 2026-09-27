/** The command-line tool's arguments, errors and exit codes, with no chain. */
import { describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { formatZec } from "../src/format.ts";

const tsx = join(__dirname, "..", "node_modules", "tsx", "dist", "cli.mjs");
const cli = join(__dirname, "..", "src", "cli.ts");

function run(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(process.execPath, [tsx, cli, ...args], (err, stdout, stderr) => resolve({ code: err ? ((err as { code?: number }).code ?? -1) : 0, stdout, stderr }));
  });
}

function file(content: string): string {
  const f = join(mkdtempSync(join(tmpdir(), "stamps-cli-")), "params.json");
  writeFileSync(f, content);
  return f;
}

describe("the command-line tool", () => {
  it("--help prints the usage and exits 0", async () => {
    const r = await run(["--help"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/^usage: stamps-verify --params <file> --solana <url> --zcash <url> \[--json\]/);
  }, 30_000);

  it("names the missing arguments and exits 2", async () => {
    const r = await run([]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/^missing --params, --solana, --zcash/);
    // a flag followed by another flag has no value
    const s = await run(["--params", "--solana", "http://127.0.0.1:1", "--zcash", "http://127.0.0.1:1"]);
    expect(s.code).toBe(2);
    expect(s.stderr).toMatch(/^missing --params\n/);
  }, 30_000);

  it("a parameter file that is missing or not JSON is an error (exit 2), not a broken invariant (exit 1)", async () => {
    const urls = ["--solana", "http://127.0.0.1:1", "--zcash", "http://127.0.0.1:1"];
    const missing = await run(["--params", join(tmpdir(), "no-such-dir-stamps", "params.json"), ...urls]);
    expect(missing.code).toBe(2);
    expect(missing.stderr).toMatch(/^cannot read the parameter file .*params\.json: ENOENT/);
    const junk = await run(["--params", file("{ not json"), ...urls]);
    expect(junk.code).toBe(2);
    expect(junk.stderr).toMatch(/^cannot read the parameter file /);
  }, 30_000);

  it("a parameter file with sections missing is refused by name (exit 2)", async () => {
    const urls = ["--solana", "http://127.0.0.1:1", "--zcash", "http://127.0.0.1:1"];
    const empty = await run(["--params", file("{}"), ...urls]);
    expect(empty.code).toBe(2);
    expect(empty.stderr).toBe("the parameter file is not usable:\n  solana is missing\n  zcash is missing\n  fees is missing\n");
    const list = await run(["--params", file("[]"), ...urls]);
    expect(list.stderr).toMatch(/not usable:\n {2}the file is not a JSON object/);
  }, 30_000);
});

describe("amounts in the output", () => {
  it("are shown in ZEC exactly, from base units", () => {
    expect(formatZec(0n)).toBe("0.00000000");
    expect(formatZec(40_000n)).toBe("0.00040000");
    expect(formatZec(120_000_000n)).toBe("1.20000000");
    expect(formatZec(2_100_000_000_000_000n)).toBe("21000000.00000000");
    expect(formatZec(-1n)).toBe("-0.00000001");
  });
});
