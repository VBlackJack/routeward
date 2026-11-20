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

# Fails when a Linux binary references a glibc symbol version newer than the supported floor.
# Weak references count too: the dynamic loader prints "weak version ... not found" on every start
# on an older glibc, even when the program falls back at run time.
#
# Usage: check-glibc-floor.sh --max <glibc version> <binary>...

set -euo pipefail

MAX_VERSION=""
BINARIES=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --max)
            MAX_VERSION="${2:-}"
            shift 2
            ;;
        *)
            BINARIES+=("$1")
            shift
            ;;
    esac
done

if [ -z "$MAX_VERSION" ] || [ "${#BINARIES[@]}" -eq 0 ]; then
    echo "Usage: $0 --max <glibc version> <binary>..." >&2
    exit 2
fi

if ! command -v objdump >/dev/null 2>&1; then
    echo "objdump (binutils) is required" >&2
    exit 2
fi

status=0
for binary in "${BINARIES[@]}"; do
    if [ ! -f "$binary" ]; then
        echo "Missing binary: $binary" >&2
        exit 2
    fi
    highest="$({ objdump -T "$binary" | grep -o 'GLIBC_[0-9][0-9.]*' || true; } | sed 's/^GLIBC_//' | sort -uV | tail -n 1)"
    if [ -z "$highest" ]; then
        echo "$binary: no versioned glibc symbol found" >&2
        exit 2
    fi
    newest="$(printf '%s\n%s\n' "$highest" "$MAX_VERSION" | sort -V | tail -n 1)"
    if [ "$newest" != "$MAX_VERSION" ]; then
        echo "$binary: needs GLIBC_$highest, above the supported floor GLIBC_$MAX_VERSION:" >&2
        objdump -T "$binary" | grep -E "GLIBC_[0-9.]+" | awk -v max="$MAX_VERSION" '{
            for (i = 1; i <= NF; i++) if ($i ~ /GLIBC_/) { v = $i; gsub(/[()]|GLIBC_/, "", v) }
            print v "\t" $0
        }' | while IFS="$(printf '\t')" read -r version line; do
            top="$(printf '%s\n%s\n' "$version" "$MAX_VERSION" | sort -V | tail -n 1)"
            if [ "$top" != "$MAX_VERSION" ]; then
                echo "  $line" >&2
            fi
        done
        status=1
    else
        echo "$binary: highest glibc symbol version GLIBC_$highest (floor GLIBC_$MAX_VERSION)"
    fi
done

exit "$status"
