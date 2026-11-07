#!/bin/sh
# Releases the Agent as version VERSION (MAJOR.MINOR.PATCH, no `v`):
#
#   scripts/release.sh 0.1.0
#
# The tag sets the version a release build reports. Before tagging, this keeps
# the current examples of every file the Agent writes and a later Agent reads
# back, those of each package that pins them with contracttest.Messages
# (config.json today), under `<package>/testdata/v<VERSION>/`. Those copies
# never change: every later Agent must still load them, since an upgrade finds
# the files the old one wrote. Refuses a dirty tree and an existing tag, runs
# the tests, commits and tags `v<VERSION>`. Pushing is left to the caller:
# `git push origin HEAD v<VERSION>`.
set -eu
cd "$(dirname "$0")/.."

[ $# -eq 1 ] || { echo "usage: $0 VERSION (e.g. 0.1.0)" >&2; exit 2; }
version=$1
echo "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ||
  { echo "$version is not MAJOR.MINOR.PATCH" >&2; exit 2; }
[ -z "$(git status --porcelain)" ] || { echo "the working tree has changes" >&2; exit 1; }
if git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
  echo "v$version is already tagged" >&2; exit 1
fi

for test in $(grep -l 'contracttest.Messages(t, "testdata"' $(git ls-files '*_test.go')); do
  dir=$(dirname "$test")/testdata
  mkdir -p "$dir/v$version"
  cp "$dir"/*.json "$dir/v$version/"
  git add "$dir/v$version"
done

GOWORK=off go test ./...
git commit -q -m "Release v$version" -m "Keeps this version's examples of the files a later Agent reads back under testdata/v$version/."
git tag "v$version"
echo "Tagged v$version. Push with: git push origin HEAD v$version"
