#!/bin/sh
# Publishes Agent release VERSION as a GitHub Release, after scripts/release.sh
# recorded and tagged it and the tag was pushed:
#
#   scripts/publish-release.sh 0.3.0
#
# Builds the tag again, in a worktree of its own, refuses unless every build's
# SHA-256 is the one releases.json records, and creates the GitHub Release
# `v<VERSION>` with the builds and a SHA256SUMS file, its notes the version's
# CHANGELOG.md entry. A Server pinned at the tag downloads these builds and
# checks them against the same record, so every installation hands out the
# bytes released. The record is read at the tag, or, for a release tagged
# before releases.json existed and recorded by the first release after it, at
# HEAD.
#
# Only finished releases are published; a development build is served by the
# Server that built it. Needs gh, signed in with permission to create releases,
# and jq.
set -eu
cd "$(dirname "$0")/.."
[ $# -eq 1 ] || { echo "usage: $0 VERSION (e.g. 0.3.0)" >&2; exit 2; }
version=$1
tag="v$version"
command -v jq >/dev/null && command -v gh >/dev/null || { echo "gh and jq are needed" >&2; exit 2; }
git rev-parse -q --verify "refs/tags/$tag" >/dev/null || { echo "$tag is not tagged here" >&2; exit 1; }
[ -n "$(git ls-remote --tags origin "refs/tags/$tag")" ] || { echo "$tag is not pushed: git push origin $tag" >&2; exit 1; }
. scripts/lib/build.sh
work=$(mktemp -d)
trap 'git worktree remove --force "$work/tree" 2>/dev/null; rm -rf "$work"' EXIT
git show "$tag:releases.json" >"$work/records.json" 2>/dev/null &&
  [ -n "$(jq -c --arg v "$version" '.[] | select(.version == $v)' "$work/records.json")" ] ||
  git show "HEAD:releases.json" >"$work/records.json" 2>/dev/null || true
want=$(jq -c --arg v "$version" '.[] | select(.version == $v) | .builds // empty' "$work/records.json" 2>/dev/null)
[ -n "$want" ] || { echo "releases.json records no builds for $version, at $tag or at HEAD" >&2; exit 1; }
git worktree add -q --detach "$work/tree" "$tag"
# A checkout whose go.mod still points the contract at a sibling directory
# finds it beside the worktree too.
[ ! -d ../contract ] || ln -s "$(cd ../contract && pwd)" "$work/contract"
mkdir "$work/out"
got=$(build_release "$work/tree" "$version" "$work/out")
if [ "$(printf '%s' "$got" | jq -S -c .)" != "$(printf '%s' "$want" | jq -S -c .)" ]; then
  echo "the builds of $tag do not match what it recorded" >&2
  echo "  recorded: $want" >&2
  echo "  built:    $got" >&2
  exit 1
fi
(cd "$work/out" && for f in easyssl-agent-*-*; do printf '%s  %s\n' "$(sha256 "$f")" "$f"; done) >"$work/out/SHA256SUMS"
awk -v v="## $version" '$0 == v { on = 1; next } on && /^## / { exit } on' "$work/tree/CHANGELOG.md" >"$work/notes.md"
gh release create "$tag" --verify-tag --title "easySSL Agent $version" --notes-file "$work/notes.md" "$work/out"/*
