#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="0.68.2"
ARCHIVE="conftest_${VERSION}_Linux_x86_64.tar.gz"
EXPECTED_SHA256="e8144c6d6d2ae0260b869caa60c7c262a1f95ac63ec1e5d2fb19be452d606347"
URL="https://github.com/open-policy-agent/conftest/releases/download/v${VERSION}/${ARCHIVE}"
DESTINATION="${1:-/usr/local/bin}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl --fail --silent --show-error --location "$URL" --output "$TMP_DIR/$ARCHIVE"
printf '%s  %s\n' "$EXPECTED_SHA256" "$TMP_DIR/$ARCHIVE" | sha256sum --check --status
tar -xzf "$TMP_DIR/$ARCHIVE" -C "$TMP_DIR" conftest
install -m 0755 "$TMP_DIR/conftest" "$DESTINATION/conftest"
"$DESTINATION/conftest" --version
