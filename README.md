# Zeitwerk

> Prove a piece of data existed at a given time — backed by several independent
> European institutions who'd all have to collude to forge it. No cost to the
> user, no blockchain, and verifiable forever, even if Zeitwerk itself disappears.

## What it is

Timestamping in the spirit of OpenTimestamps, minus the Bitcoin anchor and minus the lose-your-receipt-lose-your-proof problem.

## How it works, in plain words

Zeitwerk never sees your documents — only SHA-256 hashes thereof. During each hour-long epoch it collects fingerprints, and sorts them into one list to be hashed down to a single value, the *"epoch
root"*. 

That root gets co-signed by (several) independent institutions, and the full list is published to public mirrors. Your receipt is the short trail from your fingerprint to that root. It is readable by OpenTimestamps tools. You get the receipt the moment you submit, and it becomes a fully-qualified proof when the epoch ends, within the hour.

Lose the receipt and nothing is lost: the fingerprint plus the published list rebuilds it.

## Design commitments

- Boring primitives only — SHA-256, Ed25519, JSON/CBOR.
- Written spec; any verifier can be re-implemented from it.
- Reads OpenTimestamps `.ots` proofs.
- Offline-verifiable, forever.

## Quickstart

Everything runs on the standard library plus the vendored `python-opentimestamps`
submodule; each step is one `make` target:

```sh
make setup   # create the venv + install dependencies (idempotent)
make test    # run the full suite, incl. the CI python -O pass
make build   # build an sdist + wheel into dist/
```

---

See also: https://digitalevidencetoolkit.org/tools/zeitwerk-timestamping/

[Zeitwerk](https://digitalevidencetoolkit.org/tools/zeitwerk-timestamping/) is funded by the Federal Ministry of Education and Research under grant number 16IS26S28, administered through the Prototype Fund.

<img src="https://digitalevidencetoolkit.org/images/logo-bmbf.svg" alt="BMBF logo" width="200px"> <img src="https://digitalevidencetoolkit.org/images/logo-okfn.svg" alt="OKFN logo" width="200px">
