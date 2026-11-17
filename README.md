# Zeitwerk

> Prove a piece of data existed at a given time — backed by several independent European institutions who'd all have to collude to forge it. No cost to the user, no blockchain, and verifiable forever, even if Zeitwerk itself disappears.

## What it is

Timestamping in the spirit of OpenTimestamps, minus the Bitcoin anchor bit and minus the lose-your-receipt-lose-your-proof problem.

### Why

Digital evidence is increasingly contested, and as AI-generated media spreads, being able to show that something existed _before_ the controversy matters more. Fortunately, options abound! There are notaries and commercial services, but these can get expensive and incentivised to lock you in. RFC 3161 timestamps (eIDAS-qualified ones included) are priced for enterprise, and can't be observed for backdating from the outside. OpenTimestamps is open and free, but ties its proofs to Bitcoin, and as many have found out the hard way, a lost receipt is a lost proof.

Zeitwerk is for anyone who needs to prove when something existed: researchers preserving datasets, archivists, software maintainers, journalists and human-rights documenters.

## How it works

Zeitwerk never sees your documents — only SHA-256 hashes thereof. During each hour-long epoch it collects fingerprints, and sorts them into one list to be hashed down to a single value, the _"epoch root"_.

That root gets co-signed by (several) independent institutions, and the full list is published to public mirrors.

_Your_ receipt is the short trail from your fingerprint to that root. It is readable by OpenTimestamps tools, yay for interoperability! You get a receipt the moment you submit a file, and it's elevated to a fully-qualified proof when the epoch ends, within the hour.

Crucially, you can lose the receipt without great damage: all can be rebuilt and verified from the file's fingerprint and the published lists of fingerprints – see below.

## Lost your receipt?

Every hour's list is published to a public git repository, at a path named after the hour, e.g. `epochs/2026/10/01/14/`.

Searching is made to be (relatively) cheap and to work offline. The required lists can be mirrored by observers. See the `zeitwerk recover` CLI to rebuild a receipt from a list clone.

## Need an Affidavit?

For legal and compliance use cases, we offer paid affidavits as a sustainability model. For a small fee (around €5) we'll issue a signed and dated affidavit stating that the unique hash of _this document_ was committed under anchor X on date Y.

## Design commitments

- Boring primitives: SHA-256, Ed25519, OpenTimestamps format.
- Written spec which can be re-implemented.
- Interop with `.ots` files, and design of our receipts this way too.
- Offline-verifiable, forever.

## Status and roadmap

**First Stage — June to November 2026**
- [x] Receipt format: Zeitwerk attestations inside the OpenTimestamps format ([#9](https://github.com/digitalevidencetoolkit/zeitwerk/pull/9))
- [x] Epoch tree and aggregator; inclusion and non-inclusion; receipt recovery from a published list ([#15](https://github.com/digitalevidencetoolkit/zeitwerk/pull/15))
- [x] Trust anchor ([#1](https://github.com/digitalevidencetoolkit/zeitwerk/issues/1)), hourly epoch ([#2](https://github.com/digitalevidencetoolkit/zeitwerk/issues/2)), git as publication target ([#3](https://github.com/digitalevidencetoolkit/zeitwerk/issues/3))
- [x] Witness server with a single Ed25519 signer: `POST /digest`, `GET /timestamp/<hash>`, `GET /key` ([#17](https://github.com/digitalevidencetoolkit/zeitwerk/issues/17))
- [x] Hourly publishing to git, `GET /recover`, third-party verification from the published folder ([#22](https://github.com/digitalevidencetoolkit/zeitwerk/issues/22), [#24](https://github.com/digitalevidencetoolkit/zeitwerk/pull/24)). Hours are published to [GitHub](https://github.com/digitalevidencetoolkit/zeitwerk-epochs) and [Codeberg](https://codeberg.org/digitalevidencetoolkit/zeitwerk-epochs) ([#23](https://github.com/digitalevidencetoolkit/zeitwerk/issues/23))
- [ ] November: written proof format spec, CLI verifier (in review, see [VERIFICATION.md](VERIFICATION.md)), N-of-M growth, public testnet?

⚠️ Receipts are not stable yet: the attestation tags are placeholders for now, so don't rely on anything Zeitwerk issues today.

**Second Stage — December 2026 to March 2027** _(proposed; funding decision expected mid-October)_
- Bring co-signers and observers on board.
- Governance model: paperwork and agreements, key rotations, scenario of the departure of a signer.
- Providing of affidavits and matching more compliance targets.
- Integration proposals in other tools and systems: [Proofmode](https://proofmode.org/), [Archive Transparency](https://archivetransparency.eu/), [Authentic Memory](https://authenticmemory.org/).


## Run a signer

**We need you!**
The institutions that participate in the federation are the real strength of the system. The commitment is relatively low: a signer runs a small daemon that signs the epoch roots every hour. These are only 32-byte hashes, with no user data and don't require a full server to operate.

→ If you're at a university, library, archive or digital-rights organisation and that sounds doable, [open an issue](https://github.com/digitalevidencetoolkit/zeitwerk/issues/new) or get in touch through the [project page](https://digitalevidencetoolkit.org/tools/zeitwerk-timestamping/).

## Quickstart

Everything runs on the standard library, `cryptography` and the vendored `python-opentimestamps` submodule; each step is one `make` target:

```sh
make setup   # create the venv + install dependencies (idempotent)
make test    # run the full suite, incl. the CI python -O pass
make build   # build an sdist + wheel into dist/
```

To run a witness that publishes each hour to a git remote of your own (an empty repository; its `main` branch gets one commit per hour):

```sh
.venv/bin/python -m zeitwerk.server --remote github=git@github.com:you/zeitwerk-epochs.git
```

State lives in `~/.zeitwerk` (`--data-dir` to move it): the SQLite store, the signing key, and `repo/`, the local clone the hours are committed to. Remotes are kept in that clone, so `--remote` is only needed once; `--remote name=url` again moves it. `--help` has the rest. Then, with only a fingerprint:

```sh
curl -s http://127.0.0.1:14788/recover/<sha256 hex>            # the receipt, from the earliest hour holding it
curl -s "http://127.0.0.1:14788/recover/<sha256 hex>?epoch=N"  # from the published folder for hour N alone
```

## Verify a document

`make setup` installs the `zeitwerk` command into `.venv/bin/`. It works offline, from a clone of the [published hours](https://github.com/digitalevidencetoolkit/zeitwerk-epochs):

```sh
# I have the receipt: check it against the witness's public key
zeitwerk verify doc.pdf --receipt doc.ots --key witness.pub

# I lost the receipt: rebuild it from the public record
zeitwerk recover doc.pdf --epochs ../zeitwerk-epochs > doc.ots

# I have no receipt: check the public record itself
zeitwerk verify doc.pdf --epochs ../zeitwerk-epochs
```

The first argument is a file to hash or a 64-hex fingerprint. Exit code 0 means verified, 1 not verified (reason on stderr), 2 bad input.

[VERIFICATION.md](VERIFICATION.md) has a worked example, the output format and the known gaps. The main one: the two `--epochs` commands take the signing key from the clone itself, so check that the `signer` line reads `6ca8feb89f12145e`.

## License

Zeitwerk's own code is released under the [MIT License](LICENSE). It depends on [python-opentimestamps](https://github.com/opentimestamps/python-opentimestamps), in `submodules/`, which keeps its own LGPLv3+ licence.

---

See also: https://digitalevidencetoolkit.org/tools/zeitwerk-timestamping/

[Zeitwerk](https://digitalevidencetoolkit.org/tools/zeitwerk-timestamping/) is funded by the Federal Ministry of Education and Research under grant number 16IS26S28, administered through the Prototype Fund.

<img src="https://digitalevidencetoolkit.org/images/logo-bmbf.svg" alt="BMBF logo" width="200px"> <img src="https://digitalevidencetoolkit.org/images/logo-okfn.svg" alt="OKFN logo" width="200px">
