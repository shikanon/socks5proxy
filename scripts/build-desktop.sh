#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
mkdir -p dist
export CGO_ENABLED=0
for os in darwin linux windows; do
  for arch in amd64 arm64; do
    suffix=""
    if [[ "$os" == windows ]]; then suffix=.exe; fi
    GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w" \
      -o "dist/socks5proxy_client_${os}_${arch}${suffix}" ./cmd/client
    if [[ "$os" != darwin ]]; then
      GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w" \
        -o "dist/socks5proxy_server_${os}_${arch}${suffix}" ./cmd/server
    fi
  done
done
