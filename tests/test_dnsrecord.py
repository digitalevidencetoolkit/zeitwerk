"""Tests for the _zeitwerk TXT record format (#32)."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from zeitwerk.cli import main
from zeitwerk.dnsrecord import format_record, parse_record

# The record live at _zeitwerk.digitalevidencetoolkit.org, and the key in it.
LIVE_RECORD = "v=zw0; k=ed25519; p=2mEQqOkv4bAqVifS83aHDZ/tp1hRPZVtPo/NRBOrtig="
LIVE_KEY = bytes.fromhex("da6110a8e92fe1b02a5627d2f376870d9feda758513d956d3e8fcd4413abb628")


class FormatRecordTests(unittest.TestCase):
    def test_formats_the_live_record(self):
        self.assertEqual(format_record(LIVE_KEY), LIVE_RECORD)

    def test_rejects_a_key_that_is_not_32_bytes(self):
        with self.assertRaisesRegex(ValueError, "32 bytes"):
            format_record(LIVE_KEY[:31])


class ParseRecordTests(unittest.TestCase):
    def test_parses_the_live_record(self):
        self.assertEqual(parse_record(LIVE_RECORD), LIVE_KEY)

    def test_roundtrip(self):
        key = bytes(range(32))
        self.assertEqual(parse_record(format_record(key)), key)

    def test_tolerates_spacing(self):
        """Zone editors differ in what they keep around ';' and '='."""
        record = "v=zw0;k=ed25519 ;  p = 2mEQqOkv4bAqVifS83aHDZ/tp1hRPZVtPo/NRBOrtig=;"
        self.assertEqual(parse_record(record), LIVE_KEY)

    def test_ignores_unknown_tags(self):
        """Like DKIM: a later tag (e.g. until=) doesn't break older readers."""
        self.assertEqual(parse_record(LIVE_RECORD + "; until=498566"), LIVE_KEY)

    def test_rejects_another_version(self):
        with self.assertRaisesRegex(ValueError, "version"):
            parse_record(LIVE_RECORD.replace("v=zw0", "v=zw1"))

    def test_rejects_a_record_without_version(self):
        with self.assertRaisesRegex(ValueError, "version"):
            parse_record("k=ed25519; p=2mEQqOkv4bAqVifS83aHDZ/tp1hRPZVtPo/NRBOrtig=")

    def test_rejects_another_key_type(self):
        with self.assertRaisesRegex(ValueError, "key type"):
            parse_record(LIVE_RECORD.replace("k=ed25519", "k=rsa"))

    def test_rejects_a_record_without_key(self):
        with self.assertRaisesRegex(ValueError, "no key"):
            parse_record("v=zw0; k=ed25519")

    def test_rejects_bad_base64(self):
        with self.assertRaisesRegex(ValueError, "base64"):
            parse_record("v=zw0; k=ed25519; p=not*base64")

    def test_rejects_a_key_that_is_not_32_bytes(self):
        with self.assertRaisesRegex(ValueError, "32 bytes"):
            parse_record("v=zw0; k=ed25519; p=" + "AAAA")

    def test_rejects_a_part_that_is_not_a_tag(self):
        with self.assertRaisesRegex(ValueError, "tag=value"):
            parse_record(LIVE_RECORD + "; garbage")

    def test_rejects_a_repeated_tag(self):
        """Two p= in one record: refuse, rather than pick one."""
        with self.assertRaisesRegex(ValueError, "twice"):
            parse_record(LIVE_RECORD + "; p=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")


class DnsRecordCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_prints_the_record_for_a_pub_file(self):
        key_file = self.temp_dir / "6ca8feb89f12145e.pub"
        key_file.write_bytes(LIVE_KEY)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            result = main(["dns-record", str(key_file)])
        self.assertEqual(result, 0)
        self.assertEqual(out.getvalue(), LIVE_RECORD + "\n")

    def test_missing_file(self):
        with contextlib.redirect_stderr(io.StringIO()):
            result = main(["dns-record", str(self.temp_dir / "nope.pub")])
        self.assertEqual(result, 2)

    def test_file_that_is_not_a_raw_key(self):
        """e.g. someone passes the private .pem by mistake."""
        key_file = self.temp_dir / "witness.pem"
        key_file.write_bytes(b"-----BEGIN PRIVATE KEY-----\n...")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            result = main(["dns-record", str(key_file)])
        self.assertEqual(result, 2)
        self.assertIn("32 bytes", err.getvalue())


if __name__ == "__main__":
    unittest.main()
