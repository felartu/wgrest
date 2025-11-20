#!/usr/bin/env bash
set -euo pipefail

# Build and package wgrest .deb using nfpm.
# Requirements: go, nfpm (go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest), git.

VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}"
DIST_DIR="dist"
MODCACHE="${MODCACHE:-$(pwd)/.modcache}"
CACHE="${CACHE:-$(pwd)/.cache}"
NFPM_BIN="${NFPM_BIN:-$(go env GOPATH 2>/dev/null)/bin/nfpm}"

mkdir -p "${DIST_DIR}"

if [[ ! -x "${NFPM_BIN}" ]]; then
  echo "nfpm not found at ${NFPM_BIN}. Install with: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"
  exit 1
fi

build_bin() {
  local arch="$1"
  local out="$2"
  echo "Building wgrest for ${arch}..."
  CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
    GOMODCACHE="${MODCACHE}" GOCACHE="${CACHE}" \
    go build -ldflags "-s -w -X main.appVersion=${VERSION}" -trimpath \
    -o "${out}" cmd/wgrest-server/main.go
}

package_deb() {
  local nfpm_cfg="$1"
  local target="$2"
  echo "Packaging ${target}..."
  "${NFPM_BIN}" package -p deb -f "${nfpm_cfg}" -t "${target}"
}

build_bin amd64 "${DIST_DIR}/wgrest-linux-amd64"
build_bin arm64 "${DIST_DIR}/wgrest-linux-arm64"

package_deb packaging/nfpm-amd64.yaml "${DIST_DIR}/wgrest_${VERSION}_amd64.deb"
package_deb packaging/nfpm-arm64.yaml "${DIST_DIR}/wgrest_${VERSION}_arm64.deb"

echo "Done. Packages in ${DIST_DIR}"
