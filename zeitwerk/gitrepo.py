"""Thin subprocess wrapper around the git CLI for publishing epoch data."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

GIT_USER_NAME = "zeitwerk"
GIT_USER_EMAIL = "zeitwerk@digitalevidencetoolkit.org"

def _git(
    repo: Path,
    *args: str,
    timeout: float | None = None,
    check: bool = True,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a git command in the given repository.
    
    Args:
        repo: Path to the git repository.
        *args: Git command arguments.
        timeout: Timeout in seconds for the subprocess.
        check: If True, raise CalledProcessError on non-zero exit.
        capture_output: If True, capture stdout and stderr.
    
    Returns:
        CompletedProcess with the command results.
    """
    # Build environment to prevent interactive prompts and isolate from user config
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_SSH_COMMAND"] = "ssh -o BatchMode=yes"
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    
    return subprocess.run(
        ["git", "-C", str(repo), "-c", f"user.name={GIT_USER_NAME}", "-c", f"user.email={GIT_USER_EMAIL}",
         "-c", "commit.gpgsign=false", *args],
        check=check,
        capture_output=capture_output,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
        env=env,
    )
def ensure_repo(repo: Path) -> None:
    """Initialize a git repository at `repo` with a main branch if it doesn't exist."""
    repo.mkdir(parents=True, exist_ok=True)
    if not (repo / ".git").exists():
        _git(repo, "init")
        _git(repo, "symbolic-ref", "HEAD", "refs/heads/main")

def set_remote(repo: Path, name: str, url: str) -> None:
    """Point remote `name` at `url`, adding it if new; push() covers it from then on."""
    existing = _git(repo, "remote").stdout.split()
    if name in existing:
        # Changing URL of existing remote: remove stale tracking refs first
        # This ensures push() will correctly detect new commits after the URL change
        _git(repo, "remote", "set-url", name, url)
        # Remove the tracking branch for this remote so it will be refreshed on next fetch/push
        tracking_ref = f"refs/remotes/{name}/main"
        _git(repo, "update-ref", "-d", tracking_ref, check=False)
    else:
        _git(repo, "remote", "add", name, url)


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
    result = _git(repo, "diff", "--cached", "--quiet", check=False)
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

    # Nothing committed yet (a fresh data dir, before its first published hour): nothing to push.
    try:
        rev_parse_result = _git(repo, "rev-parse", "--verify", "--quiet", "main", timeout=timeout, check=False)
        if rev_parse_result.returncode != 0:
            return {}
    except (CalledProcessError, TimeoutExpired):
        return {}

    # Get list of remotes
    try:
        remote_list = _git(repo, "remote", timeout=timeout)
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
            count_result = _git(repo, "rev-list", "--count", f"{remote}/main..main", timeout=timeout)
            count = int(count_result.stdout.strip())
            if count == 0:
                # No new commits, skip
                continue
        except (CalledProcessError, TimeoutExpired, ValueError):
            # If we can't check the count, try to push anyway
            pass

        try:
            _git(repo, "push", remote, "main", timeout=timeout)
            result[remote] = None  # Success
        except (CalledProcessError, TimeoutExpired) as e:
            result[remote] = e.stderr if isinstance(e, CalledProcessError) else str(e)

    return result
