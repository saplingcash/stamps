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
- [`stamp-proof-wasm/`](stamp-proof-wasm): the proof checker and transaction reader as WebAssembly (the
  verifier reads v6 transactions with it; a browser can check or make a stamp proof with it);
- [`test-vectors/`](test-vectors) and [`params/`](params): record vectors and the deployment parameters
  (`mainnet.json`; `local.json` is a template for tests against a local Solana validator and Zcash
  testnet, since the vault program is deployed on no public Solana test network).

**Private stamps** (SPEC.md §9) deliver the same record privately: the harvest names a shielded receiver
sealed to a published request key, and the stamp pays 546 zatoshi and a text receipt to it in the
shielded pool. Anyone can still count every private stamp by the rules; the rules don't show where it
went. The issuer reads the receiver to send the stamp. The holder can show where it went with a stamp
proof that reveals that one note and nothing else. `stamper-core`'s `private` feature builds private
stamps (on librustzcash's transaction builder).

Checking a proof against both chains (mined, issuer, shape, note, receipt, and the receipt's amounts
against the Solana harvest):

```bash
cd verifier
npx tsx src/cli.ts check-proof --params ../params/mainnet.json --solana <Solana RPC URL> --zcash <Zebra JSON-RPC URL> --proof splg-proof:1:…
```

Offline, with only the transaction's bytes and the parameter file. A txid does not cover signatures, so
**a mined txid does not vouch for the bytes you check**: anyone can put the issuer's public key into a
scriptSig without changing the txid. Give the values of the coins the transaction spends
(`--spent-values`, from any explorer) and the tool verifies the inputs' signatures against the issuer key
(ZIP 244); without them it says plainly that the issuer was NOT verified. It prints the wtxid (ZIP 239),
which does cover the signatures, to compare with a node you trust, and lists in `notChecked` what it
cannot see (the issuer key's validity period, the Solana harvest). For a verdict, use `check-proof` above.

```bash
cd stamper-core
cargo run --release --features proof --bin stamp-proof -- check --tx <file with the raw tx hex> --params ../params/mainnet.json --proof splg-proof:1:… --spent-values <zat,…>
cargo run --release --features proof --bin stamp-proof -- make --tx <file> --params ../params/mainnet.json --viewing-key-file <file with a uview… or uivk…>
```

A viewing key is read from a file, never from the command line, and the tool has no network code.

`verifier/wasm/` holds the same checker as WebAssembly, built by `stamp-proof-wasm/build.sh` from pinned
inputs only (the toolchain, `Cargo.lock`, wasm-bindgen at the lock's version, no wasm-opt), so it can be
rebuilt byte for byte; CI does that on every push and fails on any difference. Its sha256 is in
`stamp-proof-wasm/SHA256`.

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
holds, 1 when it does not, and 2 on an error (bad arguments, an unusable parameter file, or a chain that
could not be read). Amounts are printed in ZEC; `--json` prints the full result, amounts in base units.
`--help` lists the options.

## Tests

```bash
cd verifier && npm ci && npm test
cd stamper-core && cargo test --locked --features private
```

`npm ci` installs exactly the versions in `package-lock.json` (tsx, which runs the tool, among them);
`stamper-core/rust-toolchain.toml` pins the Rust compiler and `Cargo.lock` the crates. The same checks and
a secret scan of the full history run on every push (`.github/workflows/checks.yml`).

`stamper-core`'s tests check its transaction ids and signature hashes against librustzcash (the reference
implementation) on every consensus branch librustzcash knows, check the branch switch for NU7, and the
verifier checks a stamp that `stamper-core` built and signed.

## Status

Version 1. The rules were tested on Zcash testnet and a local Solana validator running the real programs,
and reviewed independently. `params/mainnet.json` names the mainnet fee account, its owner and the
issuer; stamps start with Sapling's launch.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
