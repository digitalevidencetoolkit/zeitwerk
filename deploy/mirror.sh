#!/bin/sh
# Keep a copy of another witness's record, one that is never rewritten.
#
#   sh deploy/mirror.sh SOURCE DEST...
#
# Meant for cron, on a witness or any machine with git, a few minutes after
# the hour, once the source has published:
#
#   10 * * * * sh $HOME/mirror.sh https://github.com/them/zeitwerk-epochs git@github.com:you/zeitwerk-epochs.git >>$HOME/mirror.log 2>&1
#
# It fetches main from SOURCE into a bare repository under MIRRORS (default
# ~/mirrors), named after SOURCE, and pushes it to every DEST.
#
# A record only grows: each published hour is one commit on top of the last.
# So the copy only moves forward. If SOURCE's main no longer contains the
# copy's, the record was rewritten: the copy keeps its main, pushes nothing,
# leaves what it fetched at refs/source/main to look at, and fails every run
# until someone does. Pushes are never forced, so a DEST that changed on its
# own fails too, and keeps what it has.
#
# Pushes over SSH use the key at MIRROR_KEY (default ~/.ssh/mirror_ed25519),
# if it exists, and the host keys in ~/.ssh/known_hosts.

set -eu

log() {
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"
}

fail() {
    log "$source: $*"
    exit 1
}

[ $# -ge 2 ] || { echo "usage: $0 SOURCE DEST..." >&2; exit 2; }
source=$1
shift
name=$(basename "$source" .git)
dir=${MIRRORS:-$HOME/mirrors}/$name.git
key=${MIRROR_KEY:-$HOME/.ssh/mirror_ed25519}
if [ -f "$key" ]; then
    GIT_SSH_COMMAND="ssh -i $key -o IdentitiesOnly=yes -o BatchMode=yes"
    export GIT_SSH_COMMAND
fi

[ -d "$dir" ] || git init --quiet --bare "$dir"
cd "$dir"

git fetch --quiet "$source" +main:refs/source/main || fail "fetch failed"
new=$(git rev-parse refs/source/main)
old=$(git rev-parse --verify --quiet refs/heads/main || true)
if [ -n "$old" ] && ! git merge-base --is-ancestor "$old" "$new"; then
    fail "REWRITTEN: main is now $new, which doesn't contain $old. Keeping $old, pushing nothing; what was fetched is at refs/source/main in $dir."
fi
git update-ref refs/heads/main "$new"
added=$([ -n "$old" ] && git rev-list --count "$old..$new" || git rev-list --count "$new")
log "$source: main at $(git rev-parse --short "$new") ($(git log -1 --format=%s "$new")), $added new"

status=0
for dest in "$@"; do
    if git push --quiet "$dest" main:main; then
        log "$dest: up to date"
    else
        log "$dest: PUSH FAILED (not forced: it may have changed on its own, or refused the key)"
        status=1
    fi
done
exit $status
