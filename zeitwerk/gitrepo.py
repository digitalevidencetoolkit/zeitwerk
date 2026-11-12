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


def push(repo: Path, timeout: float = 30.0) -> dict[str, str | None]:
    """Push main to every remote that has new commits.
    For each git remote, check if there are new commits on main that the remote
    doesn't have using `rev-list --count <remote>/main..main`. If count is 0,
    skip that remote. Otherwise, push to it.
    Args:
        repo: Path to the git repository.
        timeout: Timeout in seconds for each git operation.

    Returns:
        A dict mapping remote names to their stderr output (if any error occurred),
        or None if the push succeeded. Remotes with no new commits are not included.
    """
    from subprocess import CalledProcessError, TimeoutExpired

    result: dict[str, str | None] = {}

    # Get list of remotes
    try:
        remote_list = subprocess.run(
            ["git", "-C", str(repo), "remote"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        remotes = remote_list.stdout.strip().split('\n')
    except (CalledProcessError, TimeoutExpired):
        # If we can't even list remotes, return empty dict
        return {}

    for remote in remotes:
        if not remote:
            continue

        # Check if there are new commits: rev-list --count remote/main..main
        # If count is 0, skip this remote?
        try:
            count_result = subprocess.run(
                ["git", "-C", str(repo), "rev-list", "--count", f"{remote}/main..main"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True,
            )
            count = int(count_result.stdout.strip())
            if count == 0:
                # No new commits, skip
                continue
        except (CalledProcessError, TimeoutExpired, ValueError):
            # If we can't check the count, try to push anyway
            pass

        try:
            subprocess.run(
                ["git", "-C", str(repo), "push", remote, "main"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True,
            )
            result[remote] = None  # Success
        except (CalledProcessError, TimeoutExpired) as e:
            result[remote] = e.stderr if isinstance(e, CalledProcessError) else str(e)

    return result
