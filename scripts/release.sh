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
# the files the old one wrote. Refuses a dirty tree, an existing tag and a
# version CHANGELOG.md has no `## VERSION` entry for, and runs the tests.
#
# It then builds the release for every platform in PLATFORMS, as a Server
# builds it, and records it at the top of `releases.json`: version, date, the
# contract version it speaks and each build's SHA-256. A Server carries that
# file, so its Marketplace lists every release, and a host running one of
# those digests runs that release. The first release recorded this way also
# records the earlier tags, without digests, since their bytes were never
# published. Everything is committed and the commit tagged `v<VERSION>`.
#
# Pushing and publishing are left to the caller:
#
#   git push origin HEAD v<VERSION>
#   scripts/publish-release.sh <VERSION>
#
# Needs jq.
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
command -v jq >/dev/null || { echo "jq is needed to record the release" >&2; exit 2; }
grep -qx "## $version" CHANGELOG.md 2>/dev/null ||
  { echo "CHANGELOG.md has no \"## $version\" entry: write what this release changes first, in its own commit" >&2; exit 1; }

for test in $(grep -l 'contracttest.Messages(t, "testdata"' $(git ls-files '*_test.go')); do
  dir=$(dirname "$test")/testdata
  mkdir -p "$dir/v$version"
  cp "$dir"/*.json "$dir/v$version/"
  git add "$dir/v$version"
done

GOWORK=off go test ./...

. scripts/lib/build.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
builds=$(build_release . "$version" "$work")
[ -f releases.json ] || seed_records "v$version" >releases.json
release_record "$version" "$(date -u +%Y-%m-%d)" "$(contract_at .)" "$builds" >"$work/entry.json"
jq --slurpfile e "$work/entry.json" '$e + .' releases.json >"$work/records.json"
mv "$work/records.json" releases.json
git add releases.json

git commit -q -m "Release v$version" -m "Keeps this version's examples of the files a later Agent reads back under testdata/v$version/, and records the release in releases.json: its contract version and the SHA-256 of each platform's build."
git tag "v$version"
echo "Tagged v$version. Push, then publish its builds:"
echo "  git push origin HEAD v$version"
echo "  scripts/publish-release.sh $version"
