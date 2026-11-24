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

# Exercises packaging/linux/postinst upgrade handling with a stubbed CLI, a stubbed systemctl
# and a temp state dir. No root and no systemd needed; the real systemctl is never reached.

set -u

if [ "$(id -u)" -eq 0 ]; then
    echo "Refusing to run postinst-upgrade-test.sh as root (postinst ignores test overrides under uid 0)." >&2
    exit 1
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
postinst="$root/packaging/linux/postinst"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail=0

check() {
    if [ "$2" = "ok" ]; then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi
}

# Stub systemctl first on PATH: records its arguments and whether the state file existed at
# call time, so the log proves the order (state written BEFORE try-restart).
mkdir -p "$work/bin" "$work/sysd"
cat >"$work/bin/systemctl" <<'STUB'
#!/bin/sh
if [ -e "$ROUTEWARD_STATE_DIR/protection_state.json" ]; then seen=file; else seen=nofile; fi
echo "$* state=$seen" >>"$STUB_LOG"
exit 0
STUB
chmod 755 "$work/bin/systemctl"
PATH="$work/bin:$PATH"
export PATH
STUB_LOG="$work/systemctl.log"
export STUB_LOG
ROUTEWARD_SYSTEMD_DIR="$work/sysd"
export ROUTEWARD_SYSTEMD_DIR
ROUTEWARD_STATUS_TIMEOUT=1
export ROUTEWARD_STATUS_TIMEOUT

# make_cli <mode>: running | stopped | notok | hang | down
make_cli() {
    case "$1" in
        notok) body='printf "{\n  \"ok\": false\n}\n"' ;;
        hang) body='sleep 30' ;;
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
    : >"$STUB_LOG"
    ROUTEWARD_STATE_DIR="$dir" ROUTEWARD_CLI="$work/routeward" \
        sh "$postinst" configure "$2" >/dev/null 2>&1
    rc=$?
}

run_case running 2026.1121.01
if [ "$rc" = 0 ] && [ -f "$dir/protection_state.json" ] \
    && [ "$(cat "$dir/protection_state.json")" = '{"protectionEnabled":true}' ]; then r=ok; else r=bad; fi
check "running daemon on upgrade writes the state file" "$r"
if grep -qx 'try-restart routeward.service state=file' "$STUB_LOG" \
    && grep -qx 'daemon-reload state=file' "$STUB_LOG"; then r=ok; else r=bad; fi
check "systemctl try-restart ran after the state file was written" "$r"
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

run_case notok 2026.1121.01
if [ "$rc" = 0 ] && [ ! -e "$dir/protection_state.json" ]; then r=ok; else r=bad; fi
check "status JSON with ok false and no running field writes nothing" "$r"

if command -v timeout >/dev/null 2>&1; then
    start=$(date +%s)
    run_case hang 2026.1121.01
    elapsed=$(( $(date +%s) - start ))
    if [ "$rc" = 0 ] && [ "$elapsed" -lt 10 ] && [ ! -e "$dir/protection_state.json" ]; then r=ok; else r=bad; fi
    check "hanging CLI is cut off, postinst exits 0 and writes nothing (took ${elapsed}s)" "$r"
else
    echo "SKIP: hanging CLI case (timeout command not available)"
fi

run_case running ""
if [ "$rc" = 0 ] && [ ! -e "$dir/protection_state.json" ]; then r=ok; else r=bad; fi
check "fresh install writes nothing" "$r"
if grep -q try-restart "$STUB_LOG"; then r=bad; else r=ok; fi
check "fresh install does not try-restart" "$r"

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
