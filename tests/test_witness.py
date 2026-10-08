"""Tests for the witness (draft stub).

Runs with the stdlib: `python3 -m unittest discover tests`.
"""

import unittest

import zeitwerk  # noqa: F401  (runs the python-opentimestamps path shim)
from zeitwerk.witness import Witness


class WitnessClockTests(unittest.TestCase):
    def test_epoch_is_the_hour_of_the_clock(self):
        self.assertEqual(Witness(now=lambda: 3600 * 5 + 1).epoch(), 5)

    def test_epoch_turns_on_the_hour(self):
        self.assertEqual(Witness(now=lambda: 3600 * 5 - 0.5).epoch(), 4)


if __name__ == "__main__":
    unittest.main()
