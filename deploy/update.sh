#!/bin/sh
# Update a zeitwerk witness to another version of the code, in place.
#
#   sudo sh /opt/zeitwerk/deploy/update.sh              # the latest main
#   sudo sh /opt/zeitwerk/deploy/update.sh v0.2.0       # a tag, or any commit
#   sudo sh /opt/zeitwerk/deploy/update.sh --dry-run    # only show what would change
#
# Run it on the witness. It fetches from origin, lists the commits it adds
# (+) and takes away (-), checks the version out, runs `make setup` and
# restarts the service. Then the witness must answer within 30 s with the
# public key it had before; with another one, it isn't using its signing key,
# and is stopped. Going back is the same command with the old commit.
# A restart is safe at any time: the witness catches up on missed hours.
#
# The defaults follow docs/witness-onboarding.md; ZEITWERK_DIR,
# ZEITWERK_SERVICE and ZEITWERK_URL override them.

set -eu

main() {
    # Everything is read by now: nothing below may eat a copy of this script
    # piped in over ssh, or trip over a newer one written by the checkout.
    exec </dev/null
    dry_run=
    if [ "${1:-}" = --dry-run ]; then
        dry_run=1
        shift
    fi
    ref=${1:-main}
    dir=${ZEITWERK_DIR:-/opt/zeitwerk}
    service=${ZEITWERK_SERVICE:-zeitwerk-witness}
    url=${ZEITWERK_URL:-http://127.0.0.1:14788}

    cd "$dir"
    [ -w .git ] || fail "can't write $dir: run this with sudo"
    [ -z "$(git status --porcelain --untracked-files=no)" ] || fail "$dir has local changes: commit or discard them first"
    git fetch --quiet --tags origin
    target=$(git rev-parse --verify --quiet "origin/$ref^{commit}" || git rev-parse --verify --quiet "$ref^{commit}") ||
        fail "no branch, tag or commit called $ref"
    old=$(git rev-parse HEAD)
    if [ "$target" = "$old" ]; then
        echo "Already at $ref ($(short "$old")): nothing to do."
        return
    fi

    echo "From $(short "$old") to $ref ($(short "$target")):"
    git log --format='  + %h %s' "$old..$target"
    git log --format='  - %h %s' "$target..$old"
    if [ -n "$dry_run" ]; then
        echo "Dry run: nothing changed."
        return
    fi

    key_before=$(public_key) || echo "$service isn't answering at $url: no key to compare with after the restart."
    git checkout --quiet --detach "$target"
    git submodule update --init --quiet
    make setup
    systemctl restart "$service"
    check_witness
    echo "To go back, run this again with $(short "$old")."
}

# The restarted witness answers, with the key it had, and says how it's doing.
check_witness() {
    tries=0
    until key=$(public_key); do
        tries=$((tries + 1))
        [ "$tries" -lt 30 ] || fail "$service didn't answer at $url within 30 s: see journalctl -u $service. To go back, run this again with $(short "$old")."
        sleep 1
    done
    if [ -n "$key_before" ] && [ "$key" != "$key_before" ]; then
        systemctl stop "$service"
        fail "the public key changed, from $(printf %.8s "$key_before") to $(printf %.8s "$key"): $service isn't using its signing key, so it is stopped. Check its --data-dir."
    fi
    case $(curl -fsS --max-time 5 "$url/status.json" 2>/dev/null | grep -o '"caught_up": [a-z]*') in
        *true) health="all caught up" ;;
        *false) health="catching up, see $url/" ;;
        *) health="no status page in this version" ;;
    esac
    echo "$service is answering at $(short HEAD), key $(printf %.8s "$key")…, $health."
}

# The witness's public key in hex, or a failure if it doesn't answer.
public_key() {
    hex=$(curl -fsS --max-time 5 "$url/key" 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [ -n "$hex" ] && echo "$hex"
}

short() {
    git rev-parse --short "$1"
}

fail() {
    echo "update.sh: $*" >&2
    exit 1
}

main "$@"
