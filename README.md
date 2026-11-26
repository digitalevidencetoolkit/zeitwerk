# Zeitwerk

> Prove a piece of data existed at a given time, signed by independent European organisations rather than a blockchain. No cost to the user, and verifiable forever, even if Zeitwerk itself disappears.

## What it is

Timestamping in the spirit of OpenTimestamps, minus the Bitcoin anchor bit and minus the lose-your-receipt-lose-your-proof problem.

### Why

Digital evidence is increasingly contested, and as AI-generated media spreads, being able to show that something existed _before_ the controversy matters more. Fortunately, options abound! There are notaries and commercial services, but these can get expensive and incentivised to lock you in. RFC 3161 timestamps (eIDAS-qualified ones included) are priced for enterprise, and can't be observed for backdating from the outside. OpenTimestamps is open and free, but ties its proofs to Bitcoin, and as many have found out the hard way, a lost receipt is a lost proof.

Zeitwerk is for anyone who needs to prove when something existed: researchers preserving datasets, archivists, software maintainers, journalists and human-rights documenters.

## How it works

Zeitwerk never sees your documents — only SHA-256 hashes thereof. During each hour-long epoch it collects fingerprints, and sorts them into one list to be hashed down to a single value, the _"epoch root"_.

The witness signs that root and publishes the full list to public git mirrors. Independent organisations each run a witness: two do today, each signing its own hours. Checking that several agree on an hour is the next piece.

_Your_ receipt is the short trail from your fingerprint to that root. It is readable by OpenTimestamps tools, yay for interoperability! You get a receipt the moment you submit a file, and it's elevated to a fully-qualified proof when the epoch ends, within the hour.

Crucially, you can lose the receipt without great damage: all can be rebuilt and verified from the file's fingerprint and the published lists of fingerprints – see below.

## Lost your receipt?

Every hour's list is published to a public git repository, at a path named after the hour, e.g. `epochs/2026/10/01/14/`.

Searching is made to be (relatively) cheap and to work offline. The required lists can be mirrored by observers. See the `zeitwerk recover` CLI to rebuild a receipt from a list clone.

## Need an affidavit?

Not offered today. A paid, signed affidavit (around €5) stating that a fingerprint was in hour N is one way someone could fund running a witness: see [#4](https://github.com/digitalevidencetoolkit/zeitwerk/issues/4).

## Design commitments

- Boring primitives: SHA-256, Ed25519, OpenTimestamps format.
- Written spec which can be re-implemented.
- Interop with `.ots` files, and design of our receipts this way too.
- Offline-verifiable, forever.

## Status and roadmap

**Built, June to November 2026**
- [x] Receipt format: Zeitwerk attestations inside the OpenTimestamps format ([#9](https://github.com/digitalevidencetoolkit/zeitwerk/pull/9))
- [x] Epoch tree and aggregator; inclusion and non-inclusion; receipt recovery from a published list ([#15](https://github.com/digitalevidencetoolkit/zeitwerk/pull/15))
- [x] Trust anchor ([#1](https://github.com/digitalevidencetoolkit/zeitwerk/issues/1)), hourly epoch ([#2](https://github.com/digitalevidencetoolkit/zeitwerk/issues/2)), git as publication target ([#3](https://github.com/digitalevidencetoolkit/zeitwerk/issues/3))
- [x] Witness server with a single Ed25519 signer: `POST /digest`, `GET /timestamp/<hash>`, `GET /key` ([#17](https://github.com/digitalevidencetoolkit/zeitwerk/issues/17))
- [x] Hourly publishing to git, `GET /recover`, third-party verification from the published folder ([#22](https://github.com/digitalevidencetoolkit/zeitwerk/issues/22), [#24](https://github.com/digitalevidencetoolkit/zeitwerk/pull/24)). Hours are published to [GitHub](https://github.com/digitalevidencetoolkit/zeitwerk-epochs) and [Codeberg](https://codeberg.org/digitalevidencetoolkit/zeitwerk-epochs) ([#23](https://github.com/digitalevidencetoolkit/zeitwerk/issues/23))
- [x] Offline CLI verifier: `zeitwerk verify` and `zeitwerk recover` ([#25](https://github.com/digitalevidencetoolkit/zeitwerk/pull/25))
- [x] A witness running around the clock, publishing every hour to both forges; [docs/witness-onboarding.md](docs/witness-onboarding.md) is how to run your own
- [x] Signing keys in DNS: `zeitwerk dns-record` prints a witness's TXT record, `zeitwerk verify --dns` checks the signer against it ([#34](https://github.com/digitalevidencetoolkit/zeitwerk/pull/34), [#35](https://github.com/digitalevidencetoolkit/zeitwerk/pull/35))
- [x] A public witness at [witness.digitalevidencetoolkit.org](https://witness.digitalevidencetoolkit.org), capped per hour ([#37](https://github.com/digitalevidencetoolkit/zeitwerk/pull/37))
- [x] A second witness, run independently by Olaia.eu at [witness.olaia.eu](https://witness.olaia.eu) since 20 November; [federation.json](federation.json) lists the witnesses
- [x] Two mirrors of our record, kept by the [Guardian Project](https://guardianproject.dev/nathan/zeitwerk-epochs) and [Authentic Memory](https://zeitwerk.authenticmemory.org); [zeitwerk.digitalevidencetoolkit.org](https://zeitwerk.digitalevidencetoolkit.org) shows every witness and mirror. We keep an append-only copy of Olaia.eu's record at [digitalevidencetoolkit/olaia-zeitwerk-epochs](https://github.com/digitalevidencetoolkit/olaia-zeitwerk-epochs), pushed hourly by [deploy/mirror.sh](deploy/mirror.sh)

**Not built**
- Nothing yet checks that several witnesses agree on an hour: each proof is one witness's signature (v0)
- No written spec of the format
- No RFC 3161 or C2PA export ([#5](https://github.com/digitalevidencetoolkit/zeitwerk/issues/5), [#7](https://github.com/digitalevidencetoolkit/zeitwerk/issues/7))

⚠️ Receipts are not stable yet: the attestation tags are placeholders for now, so don't rely on anything Zeitwerk issues today.


## Try the public witness

Ours runs at https://witness.digitalevidencetoolkit.org, with its status page at the root. Send it a document's SHA-256, never the document itself:

```sh
openssl dgst -sha256 -binary doc.pdf | curl -s --data-binary @- https://witness.digitalevidencetoolkit.org/digest -o doc.ots
```

Anything sent there is published for good to public git, so send fingerprints only. Each hour takes up to 5,000; past that the witness answers 503 until the next hour. Its signing key is `6ca8feb89f12145e`, published in our DNS zone at `_zeitwerk.digitalevidencetoolkit.org`. To verify, see [Verify a document](#verify-a-document); the endpoints under Quickstart work against it too. Every witness, each read from its own public record, is listed at https://zeitwerk.digitalevidencetoolkit.org.

## Be a witness

**We need you!**
The institutions that participate in the federation are the real strength of the system. The commitment is relatively low: a witness is a small daemon that signs one epoch root every hour. These are only 32-byte hashes, with no user data and don't require a full server to operate.

[docs/witness-onboarding.md](docs/witness-onboarding.md) is the whole setup: one Python service, one signing key, one git repository, under an hour on a 512 MB VM. Once yours runs, adding it to [federation.json](federation.json) is one pull request.

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

State lives in `~/.zeitwerk` (`--data-dir` to move it): the SQLite store, the signing key, and `repo/`, the local clone the hours are committed to. Remotes are kept in that clone, so `--remote` is only needed once; `--remote name=url` again moves it. `--help` has the rest. For a witness that stays up (systemd unit, deploy keys, backups), follow [docs/witness-onboarding.md](docs/witness-onboarding.md) instead.

The witness's status page is at its root, http://127.0.0.1:14788/: the fingerprints per hour over the last week, what is still waiting to be sealed, published or pushed, and each mirror. `/status.json` holds the same numbers.

Submit a document's SHA-256, never the document itself; the reply is a pending receipt:

```sh
openssl dgst -sha256 -binary doc.pdf | curl -s --data-binary @- http://127.0.0.1:14788/digest -o doc.ots
```

Then, once its hour is over, with only a fingerprint:

```sh
curl -s http://127.0.0.1:14788/recover/<sha256 hex>            # the receipt, from the earliest hour holding it
curl -s "http://127.0.0.1:14788/recover/<sha256 hex>?epoch=N"  # from the published folder for hour N alone
```

## Verify a document

`make setup` installs the `zeitwerk` command into `.venv/bin/`. It works offline, from a clone of the [published hours](https://github.com/digitalevidencetoolkit/zeitwerk-epochs). From scratch:

```sh
git clone https://github.com/digitalevidencetoolkit/zeitwerk && cd zeitwerk
git clone https://github.com/digitalevidencetoolkit/zeitwerk-epochs ../zeitwerk-epochs
make setup && source .venv/bin/activate
printf hello > hello.txt
zeitwerk verify hello.txt --epochs ../zeitwerk-epochs   # VERIFIED, hour 498469
```

Then, for your own documents:

```sh
# I have the receipt: check it against the witness's public key
zeitwerk verify doc.pdf --receipt doc.ots --key witness.pub

# I lost the receipt: rebuild it from the public record
zeitwerk recover doc.pdf --epochs ../zeitwerk-epochs > doc.ots

# I have no receipt: check the public record itself
zeitwerk verify doc.pdf --epochs ../zeitwerk-epochs

# ...and check the signer's key is the one our domain publishes
zeitwerk verify doc.pdf --epochs ../zeitwerk-epochs --dns digitalevidencetoolkit.org
```

The first argument is a file to hash or a 64-hex fingerprint. Exit code 0 means verified, 1 not verified (reason on stderr), 2 bad input.

[VERIFICATION.md](VERIFICATION.md) has an example and the output format; [docs/verification.md](docs/verification.md) does the same checks by hand with the library, and lists how each one can fail. On their own, the two `--epochs` commands take the signing key from the clone itself. `--dns` closes that gap: the key must also be published at `_zeitwerk.<domain>`, and the `dns` line says whether a validating resolver confirmed it with DNSSEC.

## License

Zeitwerk's own code is released under the [MIT License](LICENSE). It depends on [python-opentimestamps](https://github.com/opentimestamps/python-opentimestamps), in `submodules/`, which keeps its own LGPLv3+ licence.

---

See also: https://digitalevidencetoolkit.org/tools/zeitwerk-timestamping/

[Zeitwerk](https://digitalevidencetoolkit.org/tools/zeitwerk-timestamping/) is funded by the Federal Ministry of Research, Technology and Space (BMFTR) under grant number 16IS26S28, administered through the Prototype Fund.

<img src="site/funding.png" alt="Gefördert vom Bundesministerium für Forschung, Technologie und Raumfahrt · Open Knowledge Foundation Deutschland" width="360">
