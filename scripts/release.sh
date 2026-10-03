#!/usr/bin/env bash
# Tag a release and let CI publish it. CI is the only publisher: it builds
# all four platforms on one toolchain, so the checksums are consistent with
# what the installer pins. Do not upload assets from here.
#
#   scripts/release.sh v0.6.0
#
# Requires: gh (authenticated). Building is not done here.
set -euo pipefail

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: $0 <version e.g. v0.6.0>" >&2; exit 1; }
case "$VERSION" in v[0-9]*) ;; *) echo "version must look like v0.6.0: $VERSION" >&2; exit 1;; esac

REPO="${SNISP_REPO:-retro1878/sni-spoof}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

command -v gh >/dev/null || { echo "gh not found" >&2; exit 1; }

git rev-parse "$VERSION" >/dev/null 2>&1 && { echo "error: $VERSION exists locally" >&2; exit 1; }
if git ls-remote --exit-code --tags origin "refs/tags/$VERSION" >/dev/null 2>&1; then
  echo "error: $VERSION already released" >&2; exit 1
fi
[ -z "$(git status --porcelain)" ] || { echo "error: working tree is dirty" >&2; exit 1; }

git tag -a "$VERSION" -m "$VERSION"
git push origin "$VERSION"

echo "==> tag pushed, dispatching CI"
gh workflow run release.yml -R "$REPO" -f "tag=$VERSION"

echo "==> waiting for CI"
gh run watch -R "$REPO" --exit-status 2>/dev/null || true
echo "==> check: https://github.com/$REPO/actions"
echo "==> if the run produced different bytes than setup.sh pins, rebuild"
echo "    the pinned binary from the same tag on the CI toolchain:"
echo "    go-version used by CI is in .github/workflows/release.yml"
