# Sapling stamps

A **stamp** is a permanent record, on Zcash, of a harvest on [Sapling](https://sapling.cash): someone
burned a Sapling coin on Solana and received ZEC from that coin's roots. The stamp records the amount
burned and the ZEC harvested, cites the Solana transaction, and sends 546 zatoshi to the Zcash address
the harvester chose.

This repository holds what anyone needs to check the stamps without trusting Sapling:

- [`SPEC.md`](SPEC.md): how a harvest asks for a stamp, the 52-byte record a stamp carries, and the rules
  that decide which Zcash transactions are valid stamps;
- [`verifier/`](verifier): a command-line tool that rebuilds the full set of stamps from a Solana RPC and
  a Zcash node of your choice, and checks the invariant;
- [`stamper-core/`](stamper-core): the Rust library and `stamper` tool that build and sign the Zcash
  transactions carrying stamps (v5, transparent, ZIP 244 signatures, ZIP 317 fees). The consensus branch
  is passed in from a node at build time, never assumed. It has no network code, and the issuer key never
  leaves it: `stamper keygen` writes it (mode 0600) and prints only its address;
- [`test-vectors/`](test-vectors) and [`params/`](params): record vectors and the deployment parameters
  (`mainnet.json`; `local.json` is a template for tests against a local Solana validator and Zcash
  testnet, since the vault program is deployed on no public Solana test network).

A stamp is a record and 546 zatoshi. It is not a token, it confers no claim on any asset, and it carries
no promise of value or of any future conversion.

## Run the verifier

Node.js 20 or later.

```bash
cd verifier
npm ci
npx tsx src/cli.ts --params ../params/mainnet.json --solana <Solana RPC URL> --zcash <Zebra JSON-RPC URL>
```

The Zcash node must serve the zcashd-compatible methods `getblockcount`, `getaddresstxids`,
`getrawtransaction` and `getblock` (Zebra does). The tool only reads; it exits 0 when the invariant
holds, 1 when it does not, and 2 when a chain could not be read. `--json` prints the full result.

## Tests

```bash
cd verifier && npm ci && npm test
cd stamper-core && cargo test --locked
```

`npm ci` installs exactly the versions in `package-lock.json` (tsx, which runs the tool, among them);
`stamper-core/rust-toolchain.toml` pins the Rust compiler and `Cargo.lock` the crates. The same checks and
a secret scan of the full history run on every push (`.github/workflows/checks.yml`).

`stamper-core`'s tests check its transaction ids and signature hashes against librustzcash (the reference
implementation) on every consensus branch librustzcash knows, check the branch switch for NU7, and the
verifier checks a stamp that `stamper-core` built and signed.

## Status

Draft. The format and rules are being tested on Zcash testnet; the mainnet parameters are filled in
when the stamper's addresses exist.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
