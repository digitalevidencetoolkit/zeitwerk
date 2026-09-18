# Zeitwerk

> Prove a piece of data existed at a given time — backed by several independent European institutions who'd all have to collude to forge it. No cost to the user, no blockchain, and verifiable forever, even if Zeitwerk itself disappears.

## What it is

Timestamping in the spirit of OpenTimestamps, minus the Bitcoin anchor bit and minus the lose-your-receipt-lose-your-proof problem.

### Why

Digital evidence is increasingly contested, and as AI-generated media spreads, being able to show that something existed _before_ the controversy matters more. Fortunately, options abound! There are notaries and commercial services, but these can get expensive and incentivised to lock you in. RFC 3161 timestamps (eIDAS-qualified ones included) are priced for enterprise, and can't be observed for backdating from the outside. OpenTimestamps is open and free, but ties its proofs to Bitcoin, and as many have found out the hard way, a lost receipt is a lost proof.

Zeitwerk is for anyone who needs to prove when something existed: researchers preserving datasets, archivists, software maintainers, journalists and human-rights documenters.

## How it works

Zeitwerk never sees your documents — only SHA-256 hashes thereof. During each hour-long epoch it collects fingerprints, and sorts them into one list to be hashed down to a single value, the _"epoch
root"_.

That root gets co-signed by (several) independent institutions, and the full list is published to public mirrors.

_Your_ receipt is the short trail from your fingerprint to that root. It is readable by OpenTimestamps tools, yay for interoperability! You get a receipt the moment you submit a file, and it's elevated to a fully-qualified proof when the epoch ends, within the hour.

Crucially, you can lose the receipt without great damage: all can be rebuilt and verified from the file's fingerprint and the published lists of fingerprints – see below.

## Lost your receipt?

Every hour's list is published to a public git repository, at a path named after the hour, e.g. `epochs/2026/10/01/14/`.

Searching is relatively cheap, works offline, and the lists can be observed and mirrored easily.

## Need an Affidavit?

For legal and compliance use cases, we offer paid affidavits (around €5) as a sustainability model. For a small 5€ fee we'll issue a signed and dated affidavit stating that the unique hash of _this document_ was committed under anchor X on date Y.

## Design commitments

- Boring primitives: SHA-256, Ed25519, OpenTimestamps format.
- Written spec which can be re-implemented.
- Interop with `.ots` files, and design of our receipts this way too.
- Offline-verifiable, forever.

## Status and roadmap

**First Stage — June to November 2026**
- [x] Receipt format: Zeitwerk attestations inside the OpenTimestamps format ([#9](https://github.com/digitalevidencetoolkit/zeitwerk/pull/9))
- [x] Epoch tree and aggregator; inclusion and non-inclusion; receipt recovery from a published list ([#15](https://github.com/digitalevidencetoolkit/zeitwerk/pull/15))
- [x] Trust anchor ([#1](https://github.com/digitalevidencetoolkit/zeitwerk/issues/1)), hourly epoch ([#2](https://github.com/digitalevidencetoolkit/zeitwerk/issues/2)), git as   publication target ([#3](https://github.com/digitalevidencetoolkit/zeitwerk/issues/3))
- [ ] WIP October: witness server with a single Ed25519 signer: `POST /digest`, `GET /timestamp/<hash>`
- [ ] WIP October:  — hourly publishing and `/recover`
- [ ] November: written proof format spec, CLI verifier, N-of-M growth, public testnet?

⚠️ Receipts are not stable yet: the attestation tags are placeholders for now, so don't rely on anything Zeitwerk issues today.

**Second Stage — December 2026 to March 2027** _(proposed; funding decision expected mid-October)_
- Bring co-signers and observers on board.
- Governance model: paperwork and agreements, key rotations, scenario of the departure of a signer.
- Providing of affidavits and matching more compliance targets.
- Integration proposals in other tools and systems: [Proofmode](https://proofmode.org/), [Archive Transparency](https://archivetransparency.eu/), [Authentic Memory](https://authenticmemory.org/).


## Run a signer

**We need you!**
The institutions that participate in the federation are the real strength of the system. The commitment to supporting are relatively low: a signer runs a small daemon that signs the epoch roots every hour. These are only 32-byte hashes, with no user data and don't require a full server to operate.

→ If you're at a university, library, archive or digital-rights organisation and that sounds doable, [open an issue](https://github.com/digitalevidencetoolkit/zeitwerk/issues/new) or get in touch through the [project page](https://digitalevidencetoolkit.org/tools/zeitwerk-timestamping/).

## Quickstart

Everything runs on the standard library plus the vendored `python-opentimestamps`
submodule; each step is one `make` target:

```sh
make setup   # create the venv + install dependencies (idempotent)
make test    # run the full suite, incl. the CI python -O pass
make build   # build an sdist + wheel into dist/
```

## License

Zeitwerk's own code is released under the [MIT License](LICENSE). It depends on[python-opentimestamps](https://github.com/opentimestamps/python-opentimestamps), in `submodules/`, which keeps its own LGPLv3+ licence.

---

See also: https://digitalevidencetoolkit.org/tools/zeitwerk-timestamping/

[Zeitwerk](https://digitalevidencetoolkit.org/tools/zeitwerk-timestamping/) is funded by the Federal Ministry of Education and Research under grant number 16IS26S28, administered through the Prototype Fund.

<img src="https://digitalevidencetoolkit.org/images/logo-bmbf.svg" alt="BMBF logo" width="200px"> <img src="https://digitalevidencetoolkit.org/images/logo-okfn.svg" alt="OKFN logo" width="200px">
