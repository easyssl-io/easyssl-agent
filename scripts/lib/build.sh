# Sourced by release.sh and publish-release.sh: how a release is built and
# recorded, so the build a release records and the one it publishes cannot
# differ. Every function runs from the repository root.

# The platforms a release is built for, and the flags: -trimpath drops
# absolute paths, -buildid= the build id and -buildvcs=false the VCS stamp, so
# a digest identifies the source and the version stamped into it, and a later
# build of the same tag with the same Go toolchain has the same bytes.
PLATFORMS="linux/amd64 linux/arm64"
VERSION_VAR=github.com/easyssl-io/easyssl-agent/internal/buildinfo.Version

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

# build_release DIR VERSION OUT builds the Agent checked out in DIR as VERSION
# for every platform into OUT/easyssl-agent-<os>-<arch>, and prints the
# builds as the JSON array a release records.
build_release() {
  dir=$1 version=$2 out=$3
  json='[]'
  for p in $PLATFORMS; do
    os=${p%/*} arch=${p#*/}
    (cd "$dir" && GOWORK=off CGO_ENABLED=0 GOOS=$os GOARCH=$arch \
      go build -trimpath -buildvcs=false -ldflags "-s -w -buildid= -X $VERSION_VAR=$version" -o "$out/easyssl-agent-$os-$arch" ./cmd/easyssl-agent)
    json=$(printf '%s' "$json" | jq -c --arg os "$os" --arg arch "$arch" --arg sha "$(sha256 "$out/easyssl-agent-$os-$arch")" \
      '. + [{os: $os, arch: $arch, sha256: $sha}]')
  done
  printf '%s\n' "$json"
}

# contract_at DIR prints the contract version the Agent checked out in DIR
# speaks: its own answer, or for a build older than `version --contract`, the
# contract release its go.mod requires.
contract_at() {
  (cd "$1" && GOWORK=off go run ./cmd/easyssl-agent version --contract 2>/dev/null) ||
    sed -n 's#^require github.com/easyssl-io/easyssl-contract v\(.*\)$#\1#p; s#^[[:space:]]*github.com/easyssl-io/easyssl-contract v\([^ ]*\).*$#\1#p' "$1/go.mod" | head -1
}

# release_record VERSION DATE CONTRACT BUILDS prints one release record; BUILDS
# is a JSON array, empty for a release whose bytes were never published.
release_record() {
  jq -n -c --arg v "$1" --arg d "$2" --arg c "$3" --argjson b "$4" \
    '{version: $v, date: $d, contractVersion: $c} + (if ($b | length) > 0 then {builds: $b} else {} end)'
}

# seed_records TAG prints the records of the release tags before TAG, newest
# first and without builds: what releases.json starts with.
seed_records() {
  skip=$1
  seed=$(mktemp -d)
  out='[]'
  for t in $(git tag --list 'v*' --sort=-version:refname); do
    v=${t#v}
    case $v in *-*) continue ;; esac
    [ "$t" != "$skip" ] || continue
    rm -rf "$seed/tree" && git worktree add -q --detach "$seed/tree" "$t"
    c=$(contract_at "$seed/tree")
    d=$(TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%d "$t")
    out=$(printf '%s' "$out" | jq -c --argjson e "$(release_record "$v" "$d" "$c" '[]')" '. + [$e]')
    git worktree remove --force "$seed/tree"
  done
  rm -rf "$seed"
  printf '%s\n' "$out" | jq .
}
