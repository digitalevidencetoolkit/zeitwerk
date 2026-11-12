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

def commit(repo: Path, epoch: int) -> bool:
    """Commit the epoch folder and signers directory. Returns True if a commit was made."""
    from datetime import datetime, timedelta, timezone

    # Stage only the specific epoch folder and signers/ directory
    from zeitwerk.publisher import epoch_path
    
    files_to_add = []
    epoch_folder = epoch_path(epoch)
    if (repo / epoch_folder).exists():
        files_to_add.append(f"{epoch_folder}/")
    if (repo / "signers").exists():
        files_to_add.append("signers/")

    if files_to_add:
        _git(repo, "add", *files_to_add)

    # Check if there's anything to commit
    # git diff --cached --quiet returns 0 if no changes, 1 if there are changes
    result = subprocess.run(
        ["git", "-C", str(repo), "-c", f"user.name={GIT_USER_NAME}", "-c", f"user.email={GIT_USER_EMAIL}",
         "diff", "--cached", "--quiet"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return False  # nothing staged

    # Build commit message
    dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(hours=epoch)
    message = f"epoch {epoch} ({dt.strftime('%Y-%m-%d %H:00 UTC')})"

    _git(repo, "commit", "-m", message)
    return True
