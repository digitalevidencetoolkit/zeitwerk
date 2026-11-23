"""federation.json: the list of witnesses the dashboard at site/ reads.

Adding a witness is a pull request to that file; these keep it readable.
"""

import json
import re
import unittest
from pathlib import Path

FEDERATION = Path(__file__).resolve().parent.parent / "federation.json"


class FederationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.federation = json.loads(FEDERATION.read_text())

    def test_each_witness_has_a_key_id_an_operator_and_a_github_record(self):
        for witness in self.federation["witnesses"]:
            with self.subTest(witness.get("operator")):
                self.assertRegex(witness["key_id"], r"^[0-9a-f]{16}$")
                self.assertTrue(witness["operator"])
                # The dashboard reads each record through GitHub's API.
                self.assertTrue(any(re.match(r"^https://github\.com/[^/]+/[^/]+$", r) for r in witness["records"]))

    def test_key_ids_are_unique(self):
        key_ids = [witness["key_id"] for witness in self.federation["witnesses"]]
        self.assertEqual(len(key_ids), len(set(key_ids)))

    def test_each_mirror_is_of_a_listed_witness(self):
        key_ids = {witness["key_id"] for witness in self.federation["witnesses"]}
        for mirror in self.federation.get("mirrors", []):
            with self.subTest(mirror["operator"]):
                self.assertIn(mirror["of"], key_ids)

    def test_each_mirror_copies_one_of_its_witnesss_records(self):
        records = {witness["key_id"]: witness["records"] for witness in self.federation["witnesses"]}
        for mirror in self.federation.get("mirrors", []):
            with self.subTest(mirror["operator"]):
                self.assertIn(mirror["from"], records[mirror["of"]])


if __name__ == "__main__":
    unittest.main()
