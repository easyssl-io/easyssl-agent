#!/bin/sh
# Tests scripts/release.sh in a throwaway clone of this repository, so nothing
# here is ever tagged: a release keeps a loadable copy of every pinned example,
# and refuses a repeated tag, a dirty tree and a version without a
# CHANGELOG.md entry. The clone takes no tags,
# and the test uses versions 0.901.x, which no real release reaches, so it
# passes whatever this repository has released.
set -eu
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git clone -q --no-tags . "$work/agent"
mkdir -p "$work/agent/scripts" && cp scripts/release.sh "$work/agent/scripts/release.sh"
cd "$work/agent"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
# The script as it is in this checkout, committed only when it differs from
# the clone's, so the clone's tree is clean either way.
git add scripts/release.sh
git diff --cached --quiet || git commit -q -m "the script under test"

fail=0
expect() { # expect STATUS DESCRIPTION COMMAND...
  want=$1; what=$2; shift 2
  if "$@" >"$work/out" 2>&1; then got=0; else got=1; fi
  if [ "$got" != "$want" ]; then echo "FAIL: $what (exit $got)"; cat "$work/out"; fail=1; fi
}
entry() { # entry VERSION, committed
  printf '\n## %s\n\nA test release.\n' "$1" >> CHANGELOG.md
  git add CHANGELOG.md && git commit -q -m "entry $1"
}
expect 1 "a version CHANGELOG.md has no entry for" scripts/release.sh 0.901.0
grep -q 'CHANGELOG.md has no' "$work/out" || { echo "FAIL: the refusal does not name CHANGELOG.md"; fail=1; }
entry 0.901.0
expect 0 "a release" scripts/release.sh 0.901.0
[ "$(git tag --points-at HEAD)" = v0.901.0 ] || { echo "FAIL: v0.901.0 is not on the release commit"; fail=1; }
[ -f internal/identity/testdata/v0.901.0/config.json ] || { echo "FAIL: no copy of the config examples"; fail=1; }
expect 1 "a version already tagged" scripts/release.sh 0.901.0
entry 0.901.1
expect 0 "a second release, loading the first's copies" scripts/release.sh 0.901.1
entry 0.901.2
echo x >> README.md
expect 1 "a working tree with changes" scripts/release.sh 0.901.2
exit "$fail"
