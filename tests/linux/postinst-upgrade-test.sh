#!/bin/sh
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

# Exercises packaging/linux/postinst upgrade handling with a stubbed CLI and a temp state dir.
# No root and no systemd needed.

set -u

root=$(cd "$(dirname "$0")/../.." && pwd)
postinst="$root/packaging/linux/postinst"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail=0

check() {
    if [ "$2" = "ok" ]; then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi
}

# make_cli <mode>: running | stopped | down
make_cli() {
    case "$1" in
        running) body='printf "{\n  \"running\": true\n}\n"' ;;
        stopped) body='printf "{\n  \"running\": false\n}\n"' ;;
        *) body='exit 1' ;;
    esac
    printf '#!/bin/sh\n%s\n' "$body" >"$work/routeward"
    chmod 755 "$work/routeward"
}

# run_case <mode> <old-version-arg>; sets $dir and $rc
run_case() {
    make_cli "$1"
    dir="$work/state"
    rm -rf "$dir"
    mkdir -p "$dir"
    ROUTEWARD_STATE_DIR="$dir" ROUTEWARD_CLI="$work/routeward" \
        sh "$postinst" configure "$2" >/dev/null 2>&1
    rc=$?
}

run_case running 2026.1121.01
if [ "$rc" = 0 ] && [ -f "$dir/protection_state.json" ] \
    && [ "$(cat "$dir/protection_state.json")" = '{"protectionEnabled":true}' ]; then r=ok; else r=bad; fi
check "running daemon on upgrade writes the state file" "$r"
mode=$(stat -c %a "$dir/protection_state.json" 2>/dev/null || echo unknown)
if [ "$(uname -s)" != Linux ]; then
    echo "SKIP: file mode check (needs a Linux filesystem, got $mode)"
else
    if [ "$mode" = 600 ]; then r=ok; else r=bad; fi
    check "state file mode is 600 (got $mode)" "$r"
fi
if ls -A "$dir" | grep -q '^\.protection_state'; then r=bad; else r=ok; fi
check "no temp file left behind" "$r"

run_case stopped 2026.1121.01
if [ "$rc" = 0 ] && [ ! -e "$dir/protection_state.json" ]; then r=ok; else r=bad; fi
check "stopped protection writes nothing" "$r"

run_case down 2026.1121.01
if [ "$rc" = 0 ] && [ ! -e "$dir/protection_state.json" ]; then r=ok; else r=bad; fi
check "unreachable daemon writes nothing" "$r"

run_case running ""
if [ "$rc" = 0 ] && [ ! -e "$dir/protection_state.json" ]; then r=ok; else r=bad; fi
check "fresh install writes nothing" "$r"

make_cli running
dir="$work/state"
rm -rf "$dir"
mkdir -p "$dir"
printf '{"protectionEnabled":false}\n' >"$dir/protection_state.json"
touch -t 202001010000 "$dir/protection_state.json"
before=$(ls -l "$dir/protection_state.json")
ROUTEWARD_STATE_DIR="$dir" ROUTEWARD_CLI="$work/routeward" sh "$postinst" configure 2026.1121.01 >/dev/null 2>&1
rc=$?
after=$(ls -l "$dir/protection_state.json")
if [ "$rc" = 0 ] && [ "$before" = "$after" ] \
    && [ "$(cat "$dir/protection_state.json")" = '{"protectionEnabled":false}' ]; then r=ok; else r=bad; fi
check "existing state file is untouched (content and mtime)" "$r"

make_cli running
ROUTEWARD_STATE_DIR="$work/missing" ROUTEWARD_CLI="$work/routeward" sh "$postinst" configure 2026.1121.01 >/dev/null 2>&1
rc=$?
if [ "$rc" = 0 ] && [ ! -e "$work/missing" ]; then r=ok; else r=bad; fi
check "missing state dir is not an error" "$r"

exit "$fail"
