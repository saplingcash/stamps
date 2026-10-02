# Sapling stamps: specification, version 1

A **stamp** is a permanent record, on Zcash, of one **harvest** on Sapling (sapling.cash): a holder
burned a Sapling coin on Solana and received ZEC from that coin's roots. This document defines:

- how a harvest asks for a stamp (on Solana);
- the record a stamp carries (on Zcash);
- the rules that decide which Zcash transactions are valid stamps.

Anyone can rebuild the full set of stamps from the two chains with these rules alone. The verifier in
this repository does exactly that.

A **payout stamp** (§10) is the other kind: the shielded note that pays ZEC out of Sapling to Zcash (a sale,
a harvest or a send) is itself the stamp, with its receipt in the note's memo.

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
| `zcash.requestKeys` | the keys private requests are sealed to (§9.2): `{ "id": 1–255, "x25519": "<64 hex>", "from": <unix seconds>, "to": <unix seconds, exclusive, optional> }` |
| `zcash.exitKeys` | the exit keys whose order addresses pay payout stamps (§10.1): `{ "account": 0–255, "pubkey": "<130 hex>", "fromHeight": <height>, "toHeight": <height, inclusive, optional> }` |

Changes to `issuers`, `fees`, `requestKeys` and `exitKeys` are append-only. A change is published in this repository before it
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
   `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`. Its data is the UTF-8 string
   `sapling-stamp:1:<address>`, where `<address>` is one or more characters with no whitespace, or
   `sapling-stamp:2:<kid>:<sealed>` for a private request (§9.1).
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

A private request (§9) has no address; its deliverability is defined in §9.1.

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
3. **V3.** For a private request, V3 is replaced by §9.4. `R` is deliverable, and `Z` has an output paying at least 546 zatoshi to `R`'s destination
   script.
4. **V4.** Among the candidates satisfying V1–V3 and V5 for `R`, `Z` comes first in chain order: lowest
   block height, then lowest position in its block.
5. **V5.** `R` has no refund (§5) whose Solana block time is earlier than the time of `Z`'s block. Once
   a request is refunded, no later stamp can make it stamped, so its state cannot be changed by whoever
   holds an issuer key afterwards. (The two chains' clocks are compared as they are; a stamp mined before
   its request's refund is still valid, and the request is then both stamped and refunded, which breaks
   the invariant of §7.)

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

## 9. Private stamps

A **private stamp** delivers the same record privately: the request names a shielded receiver that only
the issuer can read, and the stamp pays 546 zatoshi and a text receipt to that receiver in Zcash's
shielded pool. The harvest itself stays public on Solana (R2, R3); what is private is the receiver.

### 9.1 The request

A **private request** is a request (§2) whose memo is `sapling-stamp:2:<kid>:<sealed>`:

- `<kid>` is a request key id, 1–255 in decimal, with no leading zeros;
- `<sealed>` is exactly 92 bytes (§9.2) in base64url without padding (123 characters, canonical).

A memo of the `sapling-stamp:2:` form that does not match this is not a request.

A private request is **deliverable** if its fee paid does not exceed its harvested amount (otherwise the
receipt would have nothing to receive), and a key with id `<kid>` is in `zcash.requestKeys` and in force
at the request's block time `t` (`from ≤ t`, and `t < to` when `to` is set); otherwise it is
undeliverable and must be refunded (§5). An entry's `to` is set once, and only to a time in the future. Whether the seal opens to a valid receiver is known only to the issuer: a seal
that does not open is refunded as undeliverable, and the rules only require every request to end
stamped or refunded (§7).

### 9.2 The seal

The receiver is the 43-byte Orchard receiver of a Unified Address (ZIP 316, typecode `0x03`: an 11-byte
diversifier and a 32-byte `pk_d`). With the request key's public key `request_pk`, a fresh random
X25519 secret `esk`, the key id `kid` (one byte) and the harvest's holder (redeem account `#0`, 32 bytes):

```
plaintext  = 0x03 || receiver                                     (44 bytes)
epk        = X25519(esk, basepoint)
ss         = X25519(esk, request_pk)                              (all-zero: refused)
key||nonce = HKDF-SHA256(ikm = ss, salt = epk || request_pk, info = "sapling-stamp:2 sealed-receiver", L = 44)
aad        = "sapling-stamp:2" || kid || holder
sealed     = epk || ChaCha20-Poly1305(key, nonce, plaintext, aad)  (32 + 44 + 16 = 92 bytes)
```

`test-vectors/private.json` has seals to reproduce byte for byte.

### 9.3 The receipt

The shielded note's memo (512 bytes, ZIP 302) is UTF-8 text, zero-padded, of exactly nine lines
separated by `\n`:

```
SPLG/2 private stamp
coin $<ticker> <mint, base58>
burned <amount burned, 6 decimals>
harvested <ZEC harvested, 8 decimals> ZEC
fee <fee paid, 8 decimals> ZEC
received <harvested − fee, 8 decimals> ZEC
harvest <the request's signature, base58>
at <the request's block time, ISO 8601 UTC, YYYY-MM-DDTHH:MM:SSZ>
sapling.cash/stamp/<the request's signature, base58>
```

Amounts are written in full, with no separators, so they parse back exactly; the ticker is at most 10
bytes with no whitespace. The longest receipt is 439 bytes. A memo that differs from this form in any
byte is not a receipt.

### 9.4 The record and the rules

A private stamp is a v6 transaction. Its OP_RETURN carries the **version 2 record**, 23 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | tag `53 50 4c 47` (`SPLG`) |
| 4 | 1 | version `02` |
| 5 | 18 | `sha256(sig)[0..18]` |

The script is exactly `6a 17 <23 bytes>`. Z1 and Z2 apply as in §3; Z3 is met by a version 2 record.
A stamp candidate `Z` with a version 2 record is a **valid stamp** of request `R` if:

1. V1 holds with the 18-byte hash;
2. `R` is a private request and is deliverable (§9.1);
3. `Z` has no Sapling, Sprout or Orchard part, and its Ironwood bundle's value balance is exactly −546
   zatoshi (546 zatoshi enter the pool);
4. every transparent output of `Z` other than the record pays an issuer address valid at `Z`'s height
   (the issuer's change);
5. V4 and V5 hold.

A version 1 record never answers a private request, and a version 2 record never answers a public one.
The receiver of a private stamp is not public: the rules check that the issuer paid 546 zatoshi into the
shielded pool for the request, not to whom.

Since NU6.3 an Orchard action may only pay the address of the note it spends, so payments to someone
else's Orchard receiver are made in the Ironwood pool, which uses the same receivers and keys.

### 9.5 States

Private and public requests share the states and the invariant of §7.

### 9.6 Stamp proofs

A holder shows where their private stamp went with a **stamp proof**:

```
splg-proof:1:<base64url( txid 32 (internal byte order) || pool 1 (2 = Ironwood) || action 1
                         || receiver 43 || value 8 (little-endian) || rseed 32 )>
```

It is checked without any key:

1. the transaction's own txid is the proof's, and the transaction is a valid private stamp (§9.4): mined
   with `zcash.confirmations`, spent by an issuer valid at its height, of the shape of §9.4, and its
   record names a deliverable private request;
2. in action `action` of its Ironwood bundle, `rho` is the action's nullifier; the note
   (`receiver`, `value`, `rho`, `rseed`, note plaintext version 3) is rebuilt, and its `esk` derived from
   `rseed` (ZIP 212);
3. the action's encrypted note decrypts with that `esk` and the receiver's `pk_d` to exactly this note:
   this checks `epk` and the note commitment `cmx`, and yields the memo;
4. the memo is a receipt (§9.3) whose harvest signature hashes to the record's 18 bytes, and whose burned,
   harvested and fee amounts equal the request's (the Redeemed event's `amount` and `payout`, and the fee
   paid);
5. `value` is 546.

A proof reveals one note: its receiver, its value and its receipt. It shows where the stamp went, not
who controls that receiver. The holder makes a proof from a unified full or incoming viewing key.

What each tool checks:

- the verifier's `check-proof` command reads both chains and checks steps 1 to 5, except V4 and V5 (the
  first valid stamp of the request, and no refund before it), which need every stamp and refund: the
  full verifier checks those;
- `stamp-proof check` and the WebAssembly `check` read only the transaction's bytes and the parameter
  file. They check steps 2 to 5 (without the amounts), the shape of §9.4, and that every input names, and
  every change output pays, a published issuer. A txid does not cover scriptSigs, so the inputs' keys are
  only what the bytes claim unless the values of the spent coins are given: then every input's signature
  is verified against the key it names (ZIP 244 sighash); a wrong value can only make a genuine stamp
  fail. They cannot see whether these bytes are the mined ones (they print the wtxid, ZIP 239, which covers
  the signatures), the issuer's validity period, or the Solana harvest, and say so in their output
  (`notChecked`, with the unverified issuer first when no values were given).

## 10. Payout stamps

A **shielded exit** pays ZEC out of Sapling into a shielded Zcash address: the holder's Solana transaction
(a sale, a harvest or a send) moves ZEC on Solana to a bridge, the bridge delivers native ZEC to a transparent
**order address** of Sapling's, one per exit, and Sapling pays it on, less the Zcash network fee, as one
Ironwood note to the receiver the holder sealed on Solana. That note's memo is a receipt, and the transaction
names the exit in its OP_RETURN.

The note is the **payout stamp**: there is no other note and no stamp fee. What is public: the exit on Solana,
the delivery to the order address, and the payout transaction with its record. What is private: the receiver
and the receipt, which only the receiver can show (§10.5).

### 10.1 Exit keys and order addresses

The parameter file lists the **exit keys** in `zcash.exitKeys`, append-only, like `issuers`:

| Field | Meaning |
|---|---|
| `account` | the exit key's account, 0–255; account 0 pays the exits of §10.2 |
| `pubkey` | the account public key, 65 bytes in lowercase hex: the 32-byte chain code, then the 33-byte compressed secp256k1 key |
| `fromHeight` | the first height at which the key pays; `toHeight` (inclusive, optional) the last |

Order `i` (0 ≤ i < 2^31) of a key has the public key `CKDpub(CKDpub(pubkey, 0), i)` (BIP32 public child
derivation, non-hardened), and its order address is the P2PKH address of that key. This is the external chain
of ZIP 32's transparent derivation (`m/44'/<coin type>'/<account>'/0/i`), so the account's private key derives
the same addresses. An index whose derivation is invalid under BIP32 is never used.

Sapling's site also serves the keys in its exits file, `https://sapling.cash/.well-known/sapling-exits.json`
(`accountPubkey` is account 0, `accountsPubkey` account 1).

### 10.2 The exit (Solana)

An **exit request** is a Solana transaction `T` with signature `s` (64 raw bytes `sig`) and block time `t`, such
that:

1. **E1.** `T` is finalized and succeeded.
2. **E2.** Exactly one top-level instruction of `T` invokes the SPL Memo program. Its data is the UTF-8 string
   `sapling-exit:1:<kid>:<index>:<sealed>`:
   - `<kid>` is the exit request key's id, 1–255 in decimal, with no leading zeros;
   - `<index>` is the order index, 0 to 2^31 − 1 in decimal, with no leading zeros;
   - `<sealed>` is exactly 92 bytes in base64url without padding (123 characters, canonical).
3. **E3.** Exactly one top-level instruction of `T` is an SPL Token `TransferChecked` of `solana.zecMint`, and its
   authority is `T`'s first account (the fee payer, the **holder**). Its amount, not zero, is the exit's **sent**
   amount; its destination is the bridge's deposit account.

The seal is the construction of §9.2 with its own key and domain: the exit request key (not in the parameter
file: it only opens seals), info `"sapling-exit:1 sealed-receiver"`, and
`aad = "sapling-exit:1" || kid || holder || index` (index as 4 bytes, big-endian), so a seal is bound to its
wallet and its order. Whether a seal opens is known only to Sapling; these rules do not depend on it.

A Zcash account's exit (exit key account 1) is requested through the account's own programs, not by an exit memo
in its transaction; only its payout stamp proof (§10.5) is defined here.

### 10.3 The receipt

The note's memo (512 bytes, ZIP 302) is UTF-8 text, zero-padded, of exactly nine lines separated by `\n`:

```
SPLG/3 shielded exit
from <sell | harvest | send>[ $<ticker> <mint, base58>]
sent <ZEC sent on Solana, 8 decimals> ZEC
bridged <ZEC delivered to the order address, 8 decimals> ZEC
fee <this exit's share of the Zcash network fee, 8 decimals> ZEC
received <this note's value: bridged − fee, 8 decimals> ZEC
solana <the exit's signature, base58>
at <the exit's block time, ISO 8601 UTC, YYYY-MM-DDTHH:MM:SSZ>
sapling.cash/zec/exit/<the exit's signature, base58>
```

A sale or a harvest names its coin (the ticker is 1 to 10 characters `A`–`Z` and `0`–`9`); a send names none.
Amounts are written in full, with no separators, so they parse back exactly. The longest receipt is 450 bytes.
A memo that differs from this form in any byte is not a receipt.

### 10.4 The payout transaction and the rules

The **version 3 record** names the exits a transaction pays, `k` of them (1 ≤ k ≤ 4):

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | tag `53 50 4c 47` (`SPLG`) |
| 4 | 1 | version `03` |
| 5 | 18 × k | `sha256(sig)[0..18]` of each exit, in order |

One exit is 23 bytes, four are 77. The script is `6a` and the record as one minimal push: `6a <len> <record>` for
23, 41 or 59 bytes, `6a 4c 4d <record>` for 77.

A **payout stamp candidate** is a Zcash transaction `Z` that meets Z1 (§3) and:

1. **P1.** `Z` is a v6 transaction; its txid is computed from its bytes.
2. **P2.** `Z` has no Sapling, Sprout or Orchard part. Its Ironwood bundle has a negative value balance (value
   enters the pool) and at least `k` actions. It has exactly one transparent output: a version 3 record, which
   names no exit twice.
3. **P3.** Every transparent input is a P2PKH spend (two pushes: a signature and a 33-byte compressed public
   key). The inputs are `k` runs of consecutive inputs; all the inputs of run `j` carry one key, the runs carry
   different keys, and run `j` belongs to exit `j` of the record.

`Z` is a **valid payout stamp** of each exit it names if:

1. **V1.** Each hash of the record is `sha256(sig)[0..18]` of exactly one exit request.
2. **V2.** The key of run `j` is the order key (§10.1) of exit `j`'s index under an exit key of account 0 valid at
   `Z`'s height.
3. **V4.** No exit it names has a valid payout stamp earlier in chain order (as V4 of §6).

If any exit fails V1 or V2, `Z` is a payout stamp of none of them. A payout stamp's **id** is its Zcash txid;
`Z`'s value balance is the sum of its notes. The rules check that the order addresses' ZEC went into the
shielded pool for the exits the record names, not to whom: the note, its value and its receipt are shown by a
proof (§10.5).

As Sapling builds them (informative): each exit's note is `bridged − fee`; its `fee` share is
`marginal × (coins + 1)`, plus one `marginal` for a transaction of a single exit (its padding action), at ZIP 317's
marginal fee; there is no change output, and no outgoing viewing key is set.

### 10.5 Payout stamp proofs

The receiver shows their payout stamp with a **payout stamp proof**:

```
splg-proof:2:<base64url( txid 32 (internal byte order) || pool 1 (2 = Ironwood) || action 2 (little-endian)
                         || receiver 43 || value 8 (little-endian) || rseed 32
                         || account 1 || index 4 (little-endian) )>
```

123 bytes, 164 characters. Its first 118 bytes are a delivery proof of the zcash-delivery-proof format (`zdp:1:`).
It is checked without any key:

1. the transaction's own txid is the proof's, and it has a payout stamp's shape (P1–P3);
2. in action `action` of its Ironwood bundle, the note (`receiver`, `value`, `rho` = the action's nullifier,
   `rseed`) is rebuilt; it has the action's note commitment, and the action's encrypted note decrypts, with the
   `esk` derived from `rseed` (ZIP 212) and the receiver's `pk_d`, to exactly this note: this yields the memo;
3. the memo is a receipt (§10.3), its `received` is `value`, and its exit's `sha256(sig)[0..18]` is hash `j` of the
   record;
4. the key of run `j` is order `index`'s key under a published exit key of `account`, valid at the transaction's
   height;
5. every input's signature verifies with the key it names (ZIP 244), and the receipt's `bridged` is the sum of the
   coins run `j` spends;
6. for account 0, the receipt's exit is an exit request (§10.2) whose memo names `index`, whose sent amount is the
   receipt's `sent` and whose block time is the receipt's `at`; and `Z` is a valid payout stamp of it (§10.4).

A proof reveals one note: its receiver, its value and its receipt. It shows where the payout went, not who
controls that receiver. The receiver makes a proof from a unified full or incoming viewing key, with the exit's
order index (its memo names it).

What each tool checks:

- the verifier's `check-proof` command reads both chains and checks steps 1 to 6, except V4 (the first payout
  stamp of the exit), which the full verifier checks;
- `stamp-proof check` and the WebAssembly `check_payout` read only the transaction's bytes and the parameter file.
  They check steps 1 to 4 (without the height), and step 5 when the values of the spent coins are given; without
  them, the result says that the inputs' signatures and the bridged amount were not verified. They cannot see
  whether the bytes are the mined ones (they print the wtxid), the key's validity period, or Solana, and say so in
  `notChecked`.

`splg-proof:1` (§9.6) is unchanged; a proof's prefix says which kind it is.

### 10.6 States

Each exit request is in exactly one state:

| State | Meaning |
|---|---|
| `stamped` | it has a valid payout stamp |
| `pending` | not yet, and less than `refundAfterDays` since `t` |
| `unstamped` | no payout stamp after `refundAfterDays` |
| `unresolved` | a chain read failed |

An exit without a payout stamp breaks no rule of these: the bridge can return the ZEC on Solana before it
reaches the order address, and an exit whose receiver cannot be paid is paid to a transparent address its wallet
names, or returned through the bridge. Such a payment carries the version 3 record but no note and no receipt, and
is not a payout stamp (P2). The invariant of §7 is about stamp requests (§2) only.

An exit names no account of Sapling's on Solana, so the verifier reads the exits it is given; the Zcash side is
complete on its own, since every transaction spent from an order address must name exits that are given (V1).

### 10.7 What a payout stamp is not

A payout stamp is a payment and its record. Like a stamp (§8), it is not a token, confers no claim on any
asset, and carries no promise of value or of any future conversion.
