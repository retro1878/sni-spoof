#!/usr/bin/env bash
# Cut a release. CI is the only publisher; this prepares the tree so the
# installer, the committed binary and the release assets agree.
#
#   scripts/release.sh v0.6.0
#
# Order matters: the installer's DL_URL and EXPECTED_SHA256 are baked into
# the tag, so they are set from a local build *before* tagging. CI then
# rebuilds from that tag and must reproduce the same bytes, which the script
# verifies against the published asset.
#
# Requires: go, gh (authenticated), curl, tar, sha256sum.
set -euo pipefail

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: $0 <version e.g. v0.6.0>" >&2; exit 1; }
case "$VERSION" in v[0-9]*) ;; *) echo "version must look like v0.6.0: $VERSION" >&2; exit 1;; esac

REPO="${SNISP_REPO:-retro1878/sni-spoof}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

for t in go gh curl tar; do
  command -v "$t" >/dev/null || { echo "missing required tool: $t" >&2; exit 1; }
done
command -v sha256sum >/dev/null && SHA=sha256sum || SHA="shasum -a 256"

git rev-parse "$VERSION" >/dev/null 2>&1 && { echo "error: $VERSION exists locally" >&2; exit 1; }
if git ls-remote --exit-code --tags origin "refs/tags/$VERSION" >/dev/null 2>&1; then
  echo "error: $VERSION already released" >&2; exit 1
fi
[ -z "$(git status --porcelain)" ] || { echo "error: working tree is dirty" >&2; exit 1; }

# Build from a clean export of HEAD and not the working tree: the tree holds
# raw_linux_test.go, which changes the compiled package set and therefore the
# bytes, while CI builds from a checkout that excludes it.
echo "==> building from a clean export of HEAD ($(go version | awk '{print $3}'))"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
git archive HEAD | tar -x -C "$TMP"
( cd "$TMP" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -buildvcs=false -trimpath -ldflags="-s -w -B gobuildid" \
    -o sni-spoof-linux-amd64 . )

SHA_AMD64="$($SHA "$TMP/sni-spoof-linux-amd64" | awk '{print $1}')"
cp "$TMP/sni-spoof-linux-amd64" sni-spoof-linux-amd64

echo "==> pointing the installer at $VERSION and pinning $SHA_AMD64"
sed -i.bak -E "s#^(DL_URL=\"https://github.com/[^\"]*/releases/download/)[^/]+/#\1$VERSION/#" scripts/setup.sh
sed -i.bak "s/^EXPECTED_SHA256=.*/EXPECTED_SHA256=\"$SHA_AMD64\"/" scripts/setup.sh
rm -f scripts/setup.sh.bak

grep -q "releases/download/$VERSION/" scripts/setup.sh || { echo "error: DL_URL not updated" >&2; exit 1; }
grep -q "EXPECTED_SHA256=\"$SHA_AMD64\"" scripts/setup.sh || { echo "error: pin not updated" >&2; exit 1; }

git add -A
git commit -q -m "Release $VERSION

Installer DL_URL and EXPECTED_SHA256 now describe the assets this tag
publishes; the committed linux/amd64 binary is rebuilt from the same
clean export CI uses.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin main

git tag -a "$VERSION" -m "$VERSION"
git push origin "$VERSION"

echo "==> dispatching CI"
gh workflow run release.yml -R "$REPO" -f "tag=$VERSION"

echo "==> waiting for CI"
for _ in $(seq 1 60); do
  sleep 10
  status="$(gh run list -R "$REPO" --workflow=release.yml --limit 1 \
    --json status,conclusion --jq '.[0].status+"/"+(.[0].conclusion//"-")' 2>/dev/null || echo "unknown/-")"
  case "$status" in
    completed/success) echo "    CI: $status"; break;;
    completed/*) echo "error: CI $status" >&2; exit 1;;
  esac
done

echo "==> verifying the published asset against the pin"
URL="https://github.com/$REPO/releases/download/$VERSION/sni-spoof-linux-amd64"
GOT="$(curl -fsSL "$URL" | $SHA | awk '{print $1}')"
if [ "$GOT" != "$SHA_AMD64" ]; then
  echo "error: published asset $GOT != pin $SHA_AMD64" >&2
  exit 1
fi
echo "    OK $SHA_AMD64"
echo "==> $VERSION published: https://github.com/$REPO/releases/tag/$VERSION"
