# Verification

Was _this_ document timestamped by Zeitwerk? Can I answer this question while being offline? Are the clues to answering this question public or gatekept by operators in some ways?

**Let's start from a working install of our tool**, as well as a clone of one of the available mirrors:

```sh
make setup
git clone https://github.com/digitalevidencetoolkit/zeitwerk-epochs ../zeitwerk-epochs
# or https://codeberg.org/digitalevidencetoolkit/zeitwerk-epochs
```

## Pathways to verification

Zeitwerk includes three scenarios representing additional difficulty of the verification process:

```sh
# I have the receipt: check it against the witness's public key
zeitwerk verify doc.pdf --receipt doc.ots --key witness.pub

# I lost the receipt: rebuild it from the public record
zeitwerk recover doc.pdf --epochs ../zeitwerk-epochs > doc.ots

# I have no receipt: check the public record itself
zeitwerk verify doc.pdf --epochs ../zeitwerk-epochs
```

- `doc.pdf`, in this instance, is _any_ file to hash, or a 64-character SHA-256.
- `--key` is the witness's raw 32-byte Ed25519 public key. The record publishes it as `signers/<key id>.pub`.

## Your turn to try

The hour of 12 November 2026, 13:00 UTC holds the SHA-256 of the five bytes `hello`:

```sh
printf hello > hello.txt
zeitwerk verify hello.txt --epochs ../zeitwerk-epochs
```

```
fingerprint  2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
hour         498469 = 2026-11-12 13:00 UTC
leaf set     3 fingerprints, root f57a204d8f94da72a8c49367385e679267d441d2c51d56b25aa9d98e925a6a19 matches
signer       6ca8feb89f12145e
VERIFIED     signature valid over (hour, root)
```

We know for sure that this document existed by the end of _that_ hour.
