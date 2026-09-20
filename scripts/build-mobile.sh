#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
target="${1:-}"
case "$target" in
  android|ios) ;;
  *) echo "Usage: $0 android|ios" >&2; exit 2 ;;
esac
mobile_version=v0.0.0-20260908204917-8b95e45f8d3e
tool_dir="${MOBILE_TOOLS_DIR:-$root/.mobile-tools}"
mkdir -p "$tool_dir" dist
export GOBIN="$tool_dir"
export PATH="$tool_dir:$PATH"
go install "golang.org/x/mobile/cmd/gomobile@$mobile_version"
go install "golang.org/x/mobile/cmd/gobind@$mobile_version"
gomobile init

# gomobile creates its own temporary module. GOFLAGS=-modfile would override
# that generated module on Android, losing the local-source replacement.
# Bind a source snapshot instead, keeping tooling out of production go.mod.
build_dir="$(mktemp -d "${TMPDIR:-/tmp}/socks5proxy-mobile.XXXXXX")"
trap 'rm -rf "$build_dir"' EXIT
cp go.mod go.sum ./*.go "$build_dir/"
cp -R mobile internal "$build_dir/"
cd "$build_dir"
export GOFLAGS="-mod=mod"
go mod edit "-require=golang.org/x/mobile@$mobile_version"
go mod download golang.org/x/mobile

case "$target" in
  android)
    : "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK directory}"
    mkdir -p "$root/apps/android/app/libs"
    gomobile bind -target=android/arm64,android/arm,android/amd64 -androidapi 26 \
      -javapkg=com.shikanon.socks5proxy.core \
      -o "$root/apps/android/app/libs/tunnelcore.aar" ./mobile
    cp "$root/apps/android/app/libs/tunnelcore.aar" "$root/dist/tunnelcore-android.aar"
    ;;
  ios)
    gomobile bind -target=ios,iossimulator -iosversion=15.0 \
      -o "$root/dist/TunnelCore.xcframework" ./mobile
    ;;
esac
