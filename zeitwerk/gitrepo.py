"""Thin subprocess wrapper around the git CLI for publishing epoch data."""

from __future__ import annotations

import subprocess
from pathlib import Path

GIT_USER_NAME = "zeitwerk"
GIT_USER_EMAIL = "zeitwerk@digitalevidencetoolkit.org"
def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run a git command in the given repository."""
    return subprocess.run(
        ["git", "-C", str(repo), "-c", f"user.name={GIT_USER_NAME}", "-c", f"user.email={GIT_USER_EMAIL}", *args],
        check=True,
        capture_output=True,
        text=True,
    )
def ensure_repo(repo: Path) -> None:
    """Initialize a git repository at `repo` with a main branch if it doesn't exist."""
    if not (repo / ".git").exists():
        _git(repo, "init", "-b", "main")
