#!/usr/bin/env bash
# Build the release binaries, publish a GitHub release, and keep the
# installer's pinned checksum in sync. Self-contained on purpose: the
# repo is a fork, where GitHub Actions stays disabled, so CI cannot be
# relied on to do this.
#
#   scripts/release.sh v0.6.0
#
# Requires: go, gh (authenticated), curl, sha256sum.
set -euo pipefail

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: $0 <version e.g. v0.6.0>" >&2; exit 1; }
case "$VERSION" in v*) ;; *) echo "version must start with v: $VERSION" >&2; exit 1;; esac

REPO="${SNISP_REPO:-retro1878/sni-spoof}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

command -v go >/dev/null || { echo "go not found" >&2; exit 1; }
command -v gh  >/dev/null || { echo "gh not found" >&2; exit 1; }

command -v sha256sum >/dev/null && SHA=sha256sum || SHA="shasum -a 256"

if git rev-parse "$VERSION" >/dev/null 2>&1; then
  echo "error: $VERSION already exists locally" >&2; exit 1
fi
if git ls-remote --exit-code --tags origin "refs/tags/$VERSION" >/dev/null 2>&1; then
  echo "error: $VERSION already exists on origin" >&2; exit 1
fi
[ -z "$(git status --porcelain)" ] || { echo "error: working tree is dirty" >&2; exit 1; }

echo "==> go $(go version | awk '{print $3}')"
echo "==> building release binaries"
mkdir -p dist
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  GOOS="${target%/*}" GOARCH="${target#*/}" CGO_ENABLED=0 \
    go build -buildvcs=false -trimpath -ldflags="-s -w" -o "dist/sni-spoof-$target" .
  echo "    $target"
done

# The pin must describe the artifact we are about to publish, or the
# installer will reject its own release.
AMD64_SHA="$($SHA dist/sni-spoof-linux-amd64 | awk '{print $1}')"
if grep -q '^EXPECTED_SHA256=' scripts/setup.sh; then
  sed -i.bak "s/^EXPECTED_SHA256=.*/EXPECTED_SHA256=\"$AMD64_SHA\"/" scripts/setup.sh && rm -f scripts/setup.sh.bak
  echo "==> pinned EXPECTED_SHA256=$AMD64_SHA"
else
  echo "warning: no EXPECTED_SHA256 line in scripts/setup.sh" >&2
fi

cp dist/sni-spoof-linux-amd64 sni-spoof-linux-amd64
git add -A
git commit -q -m "Release $VERSION: reproducible binaries and matching installer pin

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>" 2>/dev/null \
  || echo "    (nothing to commit)"

git tag -a "$VERSION" -m "$VERSION"
git push origin main
git push origin "$VERSION"

echo "==> publishing release"
gh release create "$VERSION" dist/sni-spoof-* -R "$REPO" \
  --title "$VERSION" --generate-notes

echo
echo "==> verifying published assets against the pin"
for f in dist/sni-spoof-*; do
  name="$(basename "$f")"
  url="https://github.com/$REPO/releases/download/$VERSION/$name"
  got="$(curl -fsSL "$url" | $SHA | awk '{print $1}')"
  want="$($SHA "$f" | awk '{print $1}')"
  if [ "$got" = "$want" ]; then
    echo "    OK   $name"
  else
    echo "    FAIL $name ($got != $want)" >&2
    exit 1
  fi
done

rm -rf dist
echo "==> $VERSION published: https://github.com/$REPO/releases/tag/$VERSION"
