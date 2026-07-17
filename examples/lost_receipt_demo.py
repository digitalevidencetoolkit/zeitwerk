"""A guided tour of zeitwerk's core promise: lose the receipt, keep the proof.

Run it:

    python3 examples/lost_receipt_demo.py

(Set up once with: pip install -e submodules/python-opentimestamps -e .)

No network, no keys, no blockchain — just the epoch machinery, end to end.
The anchor attestation is a stand-in until Stage 5 wires in the real
federation signatures.
"""

import hashlib

from zeitwerk import (
    Aggregator,
    AnchorType,
    ZeitwerkAttestation,
    recover_receipt,
    verify_inclusion,
    verify_non_inclusion,
    verify_receipt,
)

EPOCH = 7


def main():
    print(__doc__)

    # -- during the epoch: people submit fingerprints of their documents ----
    yours = b"Contract, signed draft, 2026-07-17. The one that matters."
    others = [b"someone's photo", b"someone's report", b"someone's dataset"]

    your_fingerprint = hashlib.sha256(yours).digest()
    print(f"Your document's fingerprint (SHA-256): {your_fingerprint.hex()}")
    print("The document itself never leaves your machine — only this.\n")

    agg = Aggregator(epoch=EPOCH)
    agg.submit(your_fingerprint)
    for doc in others:
        agg.submit(hashlib.sha256(doc).digest())

    # -- at the close: freeze, publish, anchor, issue receipts --------------
    closed = agg.close()
    published_list = closed.leaf_set  # -> public mirrors (Stage 4)
    anchor = ZeitwerkAttestation(EPOCH, AnchorType.FEDERATED_COSIGN, b"demo")
    closed.seal(anchor)  # -> the federation's signature (Stage 5)

    original_receipt = closed.receipt(your_fingerprint)
    print(f"Epoch {EPOCH} closed: {len(published_list) // 32} fingerprints, "
          f"root {closed.root.hex()[:16]}…")
    print(f"Your receipt: {len(original_receipt)} bytes, readable by ordinary "
          f"OpenTimestamps tools.")
    print(f"  genuine?  {verify_receipt(your_fingerprint, original_receipt, closed.root)}")
    print(f"  on the published list?  "
          f"{verify_inclusion(your_fingerprint, published_list, closed.root)}\n")

    # -- years later: the receipt is gone ------------------------------------
    print("Years pass. The receipt file is gone — laptop died, backup failed.")
    print("All that survives: your document, and the epoch's public data")
    print("(the published list, the anchor — mirrored, out of anyone's hands).\n")

    fingerprint_again = hashlib.sha256(yours).digest()
    recovered = recover_receipt(fingerprint_again, published_list, anchor)

    print(f"Recovered receipt: {len(recovered)} bytes.")
    print(f"  byte-for-byte identical to the lost one?  "
          f"{recovered == original_receipt}")
    print(f"  genuine?  {verify_receipt(fingerprint_again, recovered, closed.root)}\n")

    # -- and the flip side: proving something was NOT there -------------------
    absent = hashlib.sha256(b"a document nobody ever stamped").digest()
    print("The list also proves absence — useful in disputes:")
    print(f"  unstamped document on the list?  "
          f"{not verify_non_inclusion(absent, published_list, closed.root)}")

    print("\nThat's the feature: losing the receipt loses nothing.")


if __name__ == "__main__":
    main()
