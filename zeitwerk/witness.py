"""The witness behind the HTTP routes — draft stub (issue #17).

The clock is injected so tests can cross an hour boundary without waiting one.
"""

from __future__ import annotations

import time
from typing import Callable

EPOCH_SECONDS = 3600


class Witness:
    def __init__(self, now: Callable[[], float] = time.time):
        self._now = now

    def epoch(self) -> int:
        """The epoch accepting submissions right now: floor(unix_time / 3600)."""
        return int(self._now()) // EPOCH_SECONDS
