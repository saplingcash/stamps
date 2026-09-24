# Sapling stamps: specification, version 1

A **stamp** is a permanent record, on Zcash, of one **harvest** on Sapling (sapling.cash): a holder
burned a Sapling coin on Solana and received ZEC from that coin's roots. This document defines:

- how a harvest asks for a stamp (on Solana);
- the record a stamp carries (on Zcash);
- the rules that decide which Zcash transactions are valid stamps.

Anyone can rebuild the full set of stamps from the two chains with these rules alone. The verifier in
this repository does exactly that.

The key words MUST, MUST NOT and MAY are used as in RFC 2119.

## 1. Parameters

A deployment is described by a parameter file (`params/<network>.json`):

| Field | Meaning |
|---|---|
| `solana.programId` | the `sapling_vault` program (base58) |
| `solana.zecMint` | the ZEC token mint on Solana (SPL Token, 8 decimals) |
| `solana.tokenProgram` | the SPL Token program that owns `zecMint` |
| `solana.feeAccount` | the stamps fee wallet's ZEC token account |
| `solana.feeOwner` | the owner of `feeAccount` (signs refunds) |
| `zcash.network` | `mainnet` or `testnet` (address encodings) |
| `zcash.issuers` | the stamper's P2PKH addresses, each with `fromHeight` and optional `toHeight` (inclusive) |
| `zcash.confirmations` | confirmations before a stamp is final (default 10) |
| `fees` | the fee schedule: `{ "from": <unix seconds>, "amount": "<ZEC base units>" }` entries, ascending |
| `refundAfterDays` | days after which an undelivered request is overdue (default 7) |

Changes to `issuers` and `fees` are append-only. A change is published in this repository before it
takes effect.

## 2. The request (Solana)

A **request** is a Solana transaction `T` with signature `s` (base58; its 64 raw bytes are `sig`) and
block time `t`, such that all of the following hold:

1. **R1.** `T` is finalized and succeeded (`meta.err` is null).
2. **R2.** Exactly one top-level instruction of `T` invokes `solana.programId` with instruction data
   starting with the `redeem` discriminator `b8 0c 56 95 46 c4 61 e1`
   (`sha256("global:redeem")[0..8]`). Call it the **redeem**. Its account `#0` is the **holder** and
   its account `#7` is the **holder's ZEC account**.
3. **R3.** The logs of `T` contain exactly one `Redeemed` event emitted by `solana.programId`:
   - a `Program data: <base64>` line printed while `solana.programId` is the executing program;
   - its data starts with `0e 1d b7 47 1f a5 6b 26` (`sha256("event:Redeemed")[0..8]`);
   - then, in Borsh order: `mint` (32 bytes), `holder` (32), `amount` (u64 LE), `payout` (u64 LE),
     `supply_before` (u64 LE), `vault_before` (u64 LE);
   - `holder` MUST equal the redeem's account `#0`.

   `amount` is the **burned** amount (coin base units) and `payout` is the **harvested** amount (ZEC base
   units).
4. **R4.** Exactly one top-level instruction of `T` invokes the SPL Memo program
   `MemoSq4gqABAXKb96qnH8TzSNvK6oKvXYRvpKnwLdpq`. Its data is the UTF-8 string
   `sapling-stamp:1:<address>`, where `<address>` is one or more characters with no whitespace.
5. **R5.** Exactly one top-level instruction of `T` is an SPL Token `TransferChecked` (data byte `0` =
   `12`, then u64 LE amount, then u8 decimals = 8) invoking `solana.tokenProgram`, with accounts:
   - `[0]` source: the holder's ZEC account (the redeem's `#7`);
   - `[1]` mint: `solana.zecMint`;
   - `[2]` destination: `solana.feeAccount`;
   - `[3]` authority: the holder.

   Its amount is the **fee paid**. It MUST be at least the **required fee** at `t`: the smallest
   `fees[].amount` in force at any moment of `[t − 86400, t]`. An entry is in force from its `from` until
   the next entry's `from`.

A request's **address** is `<address>` from R4.

- It is **deliverable** if it decodes (§4) to a transparent destination on `zcash.network`.
- Otherwise it is **undeliverable**, and the request must be refunded (§5).

A transaction that fails any of R1–R5 is not a request, whatever it contains.

## 3. The record (Zcash)

A **stamp candidate** is a Zcash transaction `Z` such that:

1. **Z1.** It is mined, with at least `zcash.confirmations` confirmations.
2. **Z2.** It is a v5 transaction (ZIP 225). Every transparent input's `scriptSig`:
   - is exactly two pushes, a signature and a 33-byte compressed public key;
   - `HASH160(pubkey)` equals the hash of an issuer address valid at `Z`'s height.
3. **Z3.** Exactly one transparent output has a `scriptPubKey` starting with `OP_RETURN` (`0x6a`). That
   script is exactly `6a 34 <52 bytes>`, and the 52 bytes parse as the record below.

The record, 52 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | tag `53 50 4c 47` (ASCII `SPLG`) |
| 4 | 1 | version `01` |
| 5 | 20 | `sha256(sig)[0..20]`, where `sig` is the request's 64-byte signature |
| 25 | 8 | burned, u64 little-endian |
| 33 | 8 | harvested, u64 little-endian |
| 41 | 1 | ticker length `n`, 0 ≤ n ≤ 10 |
| 42 | 10 | ticker: `n` bytes of UTF-8, then zero bytes |

A record whose tag or version differs, whose `n` exceeds 10, or whose bytes after the ticker are not
zero, does not parse. The ticker is informational; no rule depends on it.

## 4. Addresses

`<address>` decodes to a **destination script** as follows. Anything else is undeliverable.

| Form | Mainnet | Testnet | Destination |
|---|---|---|---|
| Transparent P2PKH (Base58Check, 2-byte prefix + 20-byte hash) | prefix `1c b8` (`t1…`) | `1d 25` (`tm…`) | P2PKH |
| Transparent P2SH | `1c bd` (`t3…`) | `1c ba` (`t2…`) | P2SH |
| TEX (ZIP 320, Bech32m of the 20-byte key hash) | HRP `tex` | `textest` | P2PKH |
| Unified Address (ZIP 316) | HRP `u` (revision 0) or `tu` (revision 2) | `utest`, `tutest` | its transparent receiver (typecode `0x00` P2PKH or `0x01` P2SH) |

Unified Address decoding:
1. Decode with Bech32m, with no length limit.
2. Apply F4Jumble⁻¹.
3. Require and strip the 16-byte padding (the HRP, zero-padded).
4. Parse the `(typecode, length, value)` items with compactSize fields, in strictly ascending typecode
   order.

The address is undeliverable if:
- the UA does not parse;
- it contains a MUST-understand metadata item (typecodes `0xE0`–`0xFC`);
- it has no transparent receiver (for example a `zu…` address, or a UA with shielded receivers only).

Unknown receiver typecodes are ignored.

Destination scripts:
- P2PKH is `76 a9 14 <20-byte hash> 88 ac`.
- P2SH is `a9 14 <20-byte hash> 87`.

## 5. Refunds

A **refund** of request `R` is a finalized, successful Solana transaction with:
- exactly one top-level `TransferChecked` from `solana.feeAccount`, authority `solana.feeOwner`, mint
  `solana.zecMint`, to `R`'s source account, of exactly `R`'s fee paid;
- exactly one top-level Memo `sapling-stamp-refund:1:<s>`, where `<s>` is `R`'s signature in base58.

## 6. Valid stamps

A stamp candidate `Z` is a **valid stamp** of request `R` if:
1. **V1.** The record's `sha256(sig)[0..20]` equals that of `R`'s signature, and of no other request.
2. **V2.** The record's burned equals `R`'s burned, and its harvested equals `R`'s harvested.
3. **V3.** `R` is deliverable, and `Z` has an output paying at least 546 zatoshi to `R`'s destination
   script.
4. **V4.** Among the candidates satisfying V1–V3 for `R`, `Z` comes first in chain order: lowest block
   height, then lowest position in its block.

A stamp's **id** is its Zcash txid. Its **received** amount is `R`'s harvested minus `R`'s fee paid.

## 7. States and the invariant

Each request is in exactly one state:

| State | Meaning |
|---|---|
| `stamped` | it has a valid stamp |
| `refunded` | it has a refund and no valid stamp |
| `pending` | neither, and less than `refundAfterDays` since `t` |
| `overdue` | neither, and at least `refundAfterDays` since `t` (undeliverable requests included) |
| `unresolved` | a chain read failed (never reported as invalid) |

The **invariant** holds when:
- no request is both stamped and refunded;
- no request is `overdue`.

A verifier also reports:
- the requests;
- the fees paid;
- the refunds;
- the candidates that are not valid stamps, each with its reason.

## 8. What a stamp is not

A stamp is a record and 546 zatoshi. It is not a token; it confers no claim on any asset, and it
carries no promise of value or of any future conversion.
