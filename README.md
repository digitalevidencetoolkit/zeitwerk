# Zeitwerk

> Prove a piece of data existed at a given time — backed by several independent
> European institutions who'd all have to collude to forge it. No cost to the
> user, no blockchain, and verifiable forever, even if Zeitwerk itself disappears.

## What it is

Timestamping in the spirit of OpenTimestamps, minus the Bitcoin anchor and minus
the lose-your-receipt-lose-your-proof problem.

## Design commitments

- Boring primitives only — SHA-256, Ed25519, JSON/CBOR.
- Written spec; any verifier can be re-implemented from it.
- Reads OpenTimestamps `.ots` proofs — a strict upgrade, not a fork.
- Exports RFC 3161 tokens for legal-adjacent consumers.
- Offline-verifiable, forever.

---

See also: https://digitalevidencetoolkit.org/tools/zeitwerk-timestamping/

[Zeitwerk](/tools/zeitwerk-timestamping/) is funded by the Federal Ministry of Education and Research under grant number 16IS26S28, administered through the Prototype Fund.

<img src="https://digitalevidencetoolkit.org/images/logo-bmbf.svg" alt="BMBF logo" width="200px"> <img src="https://digitalevidencetoolkit.org/images/logo-okfn.svg" alt="OKFN logo" width="200px">
