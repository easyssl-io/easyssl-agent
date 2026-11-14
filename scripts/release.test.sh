#!/bin/sh
# Tests scripts/release.sh in a throwaway clone of this repository, so nothing
# here is ever tagged: a release keeps a loadable copy of every pinned example,
# records itself at the top of releases.json with a build per platform whose
# digest is its bytes', and refuses a repeated tag, a dirty tree and a version
# without a CHANGELOG.md entry; publishing rebuilds the pushed tag and hands
# its builds to gh. The clone takes no tags,
# and the test uses versions 0.901.x, which no real release reaches, so it
# passes whatever this repository has released.
set -eu
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git clone -q --no-tags . "$work/agent"
# A go.mod that points the contract at a sibling directory finds it beside the
# clone too.
[ ! -d ../contract ] || ln -s "$(cd ../contract && pwd)" "$work/contract"
mkdir -p "$work/agent/scripts/lib" && cp scripts/release.sh scripts/publish-release.sh "$work/agent/scripts/" && cp scripts/lib/build.sh "$work/agent/scripts/lib/"
cd "$work/agent"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
# The script as it is in this checkout, committed only when it differs from
# the clone's, so the clone's tree is clean either way.
git add scripts/release.sh scripts/publish-release.sh scripts/lib/build.sh
git diff --cached --quiet || git commit -q -m "the script under test"
# The clone starts without the release record this repository now keeps, as
# the first release recorded did, so the seeding of earlier tags is what runs.
if [ -f releases.json ]; then git rm -q releases.json && git commit -q -m "no release recorded yet"; fi

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
# A release tagged before releases.json existed, which the first recorded
# release records too, rebuilt for its digests.
git tag v0.900.0
entry 0.901.0
expect 0 "a release" scripts/release.sh 0.901.0
[ "$(git tag --points-at HEAD)" = v0.901.0 ] || { echo "FAIL: v0.901.0 is not on the release commit"; fail=1; }
[ -f internal/identity/testdata/v0.901.0/config.json ] || { echo "FAIL: no copy of the config examples"; fail=1; }
[ "$(jq -r '[.[].version] | join(" ")' releases.json)" = "0.901.0 0.900.0" ] || { echo "FAIL: releases recorded: $(jq -c '[.[].version]' releases.json)"; fail=1; }
[ "$(jq '.[0].builds | length' releases.json)" = 2 ] && [ "$(jq '.[1].builds | length' releases.json)" = 2 ] ||
  { echo "FAIL: not one build per platform for the release and for the earlier tag"; fail=1; }
[ "$(jq -r '.[0].contractVersion' releases.json)" = "$(GOWORK=off go run ./cmd/easyssl-agent version --contract)" ] ||
  { echo "FAIL: the contract version recorded is not the one the build speaks"; fail=1; }
expect 1 "a version already tagged" scripts/release.sh 0.901.0
entry 0.901.1
expect 0 "a second release, loading the first's copies" scripts/release.sh 0.901.1
entry 0.901.2
echo x >> README.md
expect 1 "a working tree with changes" scripts/release.sh 0.901.2

# Publishing, against a throwaway remote and a stand-in gh that records what it
# was asked: nothing is pushed or published for real.
git init -q --bare "$work/origin.git"
git remote set-url origin "$work/origin.git"
mkdir "$work/bin" "$work/published"
printf '#!/bin/sh\nprintf "%%s\\n" "$@" >"%s/gh-args"\nfor a; do [ -f "$a" ] && cp "$a" "%s/published/"; done\n' "$work" "$work" >"$work/bin/gh"
chmod +x "$work/bin/gh"
git checkout -q README.md
expect 1 "publishing a tag not pushed" env PATH="$work/bin:$PATH" scripts/publish-release.sh 0.901.1
git push -q origin v0.901.1
expect 0 "publishing a pushed release" env PATH="$work/bin:$PATH" scripts/publish-release.sh 0.901.1
grep -qx 'v0.901.1' "$work/gh-args" || { echo "FAIL: gh was not asked for the release's tag"; fail=1; }
for f in easyssl-agent-linux-amd64 easyssl-agent-linux-arm64 SHA256SUMS; do
  [ -f "$work/published/$f" ] || { echo "FAIL: $f was not published"; fail=1; }
done
[ "$(cut -d' ' -f1 "$work/published/SHA256SUMS" | sort | tr '\n' ' ')" = "$(jq -r '.[] | select(.version == "0.901.1") | .builds[].sha256' releases.json | sort | tr '\n' ' ')" ] ||
  { echo "FAIL: SHA256SUMS does not list the recorded digests"; fail=1; }
# The earlier tag has no releases.json of its own; the record at HEAD is used.
rm -f "$work/published"/*
git push -q origin v0.900.0
expect 0 "publishing a release tagged before releases.json" env PATH="$work/bin:$PATH" scripts/publish-release.sh 0.900.0
[ "$(cut -d' ' -f1 "$work/published/SHA256SUMS" | sort | tr '\n' ' ')" = "$(jq -r '.[] | select(.version == "0.900.0") | .builds[].sha256' releases.json | sort | tr '\n' ' ')" ] ||
  { echo "FAIL: the earlier release is not published with its recorded digests"; fail=1; }
exit "$fail"
