#!/usr/bin/env bash
# Copyright 2026 Julien Bombled
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

TARGET_DIR="$ROOT_DIR/target/release"
OUT_DIR="$ROOT_DIR/dist"
VERSION=""
ARCH=""

while [ $# -gt 0 ]; do
    case "$1" in
        --target-dir)
            TARGET_DIR="$2"
            shift 2
            ;;
        --out-dir)
            OUT_DIR="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --arch)
            ARCH="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

if [ -z "$VERSION" ]; then
    VERSION="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)"/\1/p' "$ROOT_DIR/Cargo.toml" | head -n1)"
fi
if [ -z "$VERSION" ]; then
    echo "Failed to determine package version" >&2
    exit 1
fi

if [ -z "$ARCH" ]; then
    if command -v dpkg >/dev/null 2>&1; then
        ARCH="$(dpkg --print-architecture)"
    else
        case "$(uname -m)" in
            x86_64) ARCH="amd64" ;;
            aarch64) ARCH="arm64" ;;
            *) ARCH="$(uname -m)" ;;
        esac
    fi
fi

if [ ! -f "$TARGET_DIR/routeward" ]; then
    echo "Missing binary: $TARGET_DIR/routeward" >&2
    exit 1
fi

STAGE_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$STAGE_DIR"
}
trap cleanup EXIT
chmod 0755 "$STAGE_DIR"

mkdir -p \
    "$STAGE_DIR/DEBIAN" \
    "$STAGE_DIR/usr/bin" \
    "$STAGE_DIR/lib/systemd/system" \
    "$STAGE_DIR/usr/share/doc/routeward" \
    "$OUT_DIR"

sed -e "s|@VERSION@|$VERSION|g" -e "s|@ARCH@|$ARCH|g" \
    "$SCRIPT_DIR/control.template" > "$STAGE_DIR/DEBIAN/control"
chmod 0644 "$STAGE_DIR/DEBIAN/control"

install -m 0755 "$SCRIPT_DIR/postinst" "$STAGE_DIR/DEBIAN/postinst"
install -m 0755 "$SCRIPT_DIR/prerm" "$STAGE_DIR/DEBIAN/prerm"
install -m 0755 "$SCRIPT_DIR/postrm" "$STAGE_DIR/DEBIAN/postrm"

install -m 0755 "$TARGET_DIR/routeward" "$STAGE_DIR/usr/bin/routeward"
if [ -f "$TARGET_DIR/routeward-desktop" ]; then
    install -m 0755 "$TARGET_DIR/routeward-desktop" "$STAGE_DIR/usr/bin/routeward-desktop"

    # Launcher entry and icons: the desktop cache refresh is done by dpkg triggers.
    install -d -m 0755 "$STAGE_DIR/usr/share/applications"
    install -m 0644 "$SCRIPT_DIR/routeward-desktop.desktop" \
        "$STAGE_DIR/usr/share/applications/routeward-desktop.desktop"
    for icon_size in 16 24 32 48 64 128 256 512; do
        icon_dir="$STAGE_DIR/usr/share/icons/hicolor/${icon_size}x${icon_size}/apps"
        install -d -m 0755 "$icon_dir"
        install -m 0644 "$ROOT_DIR/assets/branding/routeward-${icon_size}.png" "$icon_dir/routeward.png"
    done
    install -d -m 0755 "$STAGE_DIR/usr/share/icons/hicolor/scalable/apps"
    install -m 0644 "$ROOT_DIR/assets/branding/routeward-icon.svg" \
        "$STAGE_DIR/usr/share/icons/hicolor/scalable/apps/routeward.svg"
fi

install -m 0644 "$SCRIPT_DIR/routeward.service" "$STAGE_DIR/lib/systemd/system/routeward.service"

if [ -f "$ROOT_DIR/LICENSE" ]; then
    install -m 0644 "$ROOT_DIR/LICENSE" "$STAGE_DIR/usr/share/doc/routeward/LICENSE"
fi
if [ -f "$ROOT_DIR/NOTICE" ]; then
    install -m 0644 "$ROOT_DIR/NOTICE" "$STAGE_DIR/usr/share/doc/routeward/NOTICE"
fi

DEB_FILENAME="routeward_${VERSION}_${ARCH}.deb"
DEB_PATH="$OUT_DIR/$DEB_FILENAME"

dpkg-deb --root-owner-group --build "$STAGE_DIR" "$DEB_PATH"

(
    cd "$OUT_DIR"
    sha256sum "$DEB_FILENAME" > "${DEB_FILENAME}.sha256"
)

echo "Built $DEB_PATH"
