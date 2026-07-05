# Fixture: ProofMode bundle with a *pending* OpenTimestamps proof

A real [ProofMode](https://proofmode.org) capture (iPhone, Kyiv, 2024-04-24),
trimmed to the two files that matter for OpenTimestamps interop. The original
bundle also carried the `.mp4`, GPG detached signatures, and `pubkey.asc` —
those are the ProofMode/PGP trust layer, not the OTS layer, so they're omitted.

The filename **is** the SHA-256 of the media file
(`1eb44d04…956f50ba`) — that's the ProofMode convention, and it's also the
`File Hash SHA256` field inside `proof.json`.

## Why this fixture exists

It is the receipt-loss / no-anchor-yet failure mode in the wild — the exact
gap zeitwerk is built to close. `ots info` on the `.ots` shows **three
`PendingAttestation`s and zero Bitcoin attestations**:

```
File sha256 hash: 1eb44d04ca313287f431eede667e3a0c59e1f66f3aa697d748c9278e956f50ba
append <nonce>; sha256
 ├─► … verify PendingAttestation('https://bob.btc.calendar.opentimestamps.org')
 ├─► … verify PendingAttestation('https://finney.calendar.eternitywall.com')
 └─► … verify PendingAttestation('https://alice.btc.calendar.opentimestamps.org')
```

This file does **not** prove "the hash existed at time T." It records that the
hash was *submitted* to three calendars that promise to anchor it to Bitcoin
later. The actual proof must be fetched ("upgraded") from a calendar afterward.
Consequences:

- Lose this `.ots` → you also lose the calendar URIs and the per-branch salt
  nonces → no path to the eventual Bitcoin root. Total proof loss.
- The three calendars die before upgrade → the pending promise never becomes an
  anchored proof.

## What it teaches (byte-verified against `ots info`)

- **`.ots` anatomy**: 31-byte magic `\x00OpenTimestamps\x00\x00Proof\x00…`,
  version `0x01`, file-hash op `sha256` (`0x08`) + 32-byte digest, then the
  timestamp tree.
- **Op vocabulary**: only `append` (`0xf0`), `prepend` (`0xf1`), `sha256`
  (`0x08`). A zeitwerk Merkle path must stay inside this set — unknown *ops*
  break stock parsers (unknown *attestations* degrade to `UnknownAttestation`).
- **Fan-out** = OTS's federation primitive: one root, three calendars, one an
  independent operator (`eternitywall.com`).
- **Per-calendar nonce salting** (`append <random>; sha256` before each
  calendar) blinds the operator to `H(file)` — the opposite of zeitwerk's
  published-`H(doc)` leaf sets. That tension is the privacy tradeoff to flag.

## Reproduce

```
ots info 1eb44d04…956f50ba.ots
```
