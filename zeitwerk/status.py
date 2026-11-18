"""What the status page shows: GET / renders it, GET /status.json is the data.

Counts and states only. Nothing here is a fingerprint, and the leaf counts
are the ones each hour's epoch.json publishes anyway. A remote's URL is shown
as the web page of the repository, so credentials or a local path in it stay
on the witness.

`caught_up` is the one-line health check: every finished hour is sealed and
published, and every mirror has every commit. For up to a minute after the
top of the hour it is false, until the closer gets round to the hour.
"""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from zeitwerk.gitrepo import remote_status
from zeitwerk.publisher import EPOCH_SECONDS
from zeitwerk.signer import Signer
from zeitwerk.store import Store

HOURS_SHOWN = 7 * 24  # the chart's window, ending with the current hour
FORGES = {"github.com": "GitHub", "codeberg.org": "Codeberg", "gitlab.com": "GitLab"}
SCP_STYLE = re.compile(r"(?:[^@/]+@)?([\w.-]+):(?!//)(.+)")  # git@github.com:org/repo.git


def witness_status(store: Store, signer: Signer, repo: str | Path, now: float, started: float) -> dict:
    """Everything the status page shows, as JSON-ready values."""
    current = int(now) // EPOCH_SECONDS
    fingerprints, sealed, published = store.totals()
    to_seal = len(store.unsealed_epochs(before=current))
    to_publish = len(store.unpublished_epochs())
    mirrors = _mirrors(Path(repo))
    return {
        "now": int(now),
        "started": int(started),
        "epoch": current,
        "signers": [signer.key_id.hex()],
        "fingerprints": fingerprints,
        "hours_sealed": sealed,
        "hours_published": published,
        "to_seal": to_seal,
        "to_publish": to_publish,
        "caught_up": to_seal == 0
        and to_publish == 0
        and mirrors is not None
        and all(mirror["unpushed"] == 0 for mirror in mirrors),
        "hours": [
            {"epoch": epoch, "fingerprints": count, "state": _state(epoch, current, is_sealed, is_published)}
            for epoch, count, is_sealed, is_published in store.hour_counts(since=current - HOURS_SHOWN + 1)
        ],
        "mirrors": mirrors,
    }


def web_url(url: str) -> str | None:
    """The https page of a git remote, without credentials or port; None for a local one."""
    scp = SCP_STYLE.fullmatch(url)
    if scp:
        host, path = scp.groups()
    else:
        parts = urlsplit(url)
        if parts.scheme not in ("ssh", "git", "http", "https") or not parts.hostname:
            return None
        host, path = parts.hostname, parts.path
    return f"https://{host}/{path.strip('/').removesuffix('.git')}"


def _state(epoch: int, current: int, sealed: bool, published: bool) -> str:
    if epoch == current:
        return "open"  # still taking fingerprints
    if not sealed:
        return "sealing"  # over, waiting for the closer
    return "published" if published else "sealed"


def _mirrors(repo: Path) -> list[dict] | None:
    """Each remote, or None if the repo can't be read (the page says unknown)."""
    try:
        remotes = remote_status(repo)
    except (OSError, subprocess.SubprocessError, ValueError):
        logging.exception("status: could not read the remotes of %s", repo)
        return None
    mirrors = []
    for name, url, unpushed, last_pushed in remotes:
        page = web_url(url)
        host = urlsplit(page).hostname if page else None
        mirrors.append({
            "name": name,
            "kind": FORGES.get(host, host) if host else "local",
            "url": page,
            "unpushed": unpushed,
            "last_pushed": last_pushed,
        })
    return mirrors
