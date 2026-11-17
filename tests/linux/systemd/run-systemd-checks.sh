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

# Runtime check of the hardened packaging/linux/routeward.service.
#
# Host mode (default): builds the image from the repository root, starts it with systemd as PID 1
# and re-executes this script inside the container with --inside.
#   tests/linux/systemd/run-systemd-checks.sh
#
# Inside mode (--inside): runs the checks against the systemd instance of the container.
# Prints PASS/FAIL per check and a summary; exit code 0 only when every check passed.

set -uo pipefail

IMAGE="routeward-systemd-test"
CONTAINER="routeward-systemd-test-run"
INSIDE_SCRIPT="/opt/routeward-test/run-systemd-checks.sh"

if [[ "${1:-}" != "--inside" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
    if command -v cygpath >/dev/null 2>&1; then
        # Git Bash on Windows: hand the docker client a native path.
        ROOT_DIR="$(cygpath -m "${ROOT_DIR}")"
    fi
    docker build -f "${ROOT_DIR}/tests/linux/systemd/Dockerfile" -t "${IMAGE}" "${ROOT_DIR}" || exit 2
    docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
    docker run -d --name "${CONTAINER}" --privileged --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
        "${IMAGE}" >/dev/null || exit 2
    for _ in $(seq 1 60); do
        state="$(docker exec "${CONTAINER}" systemctl is-system-running 2>/dev/null || true)"
        if [[ "${state}" == "running" || "${state}" == "degraded" ]]; then
            break
        fi
        sleep 1
    done
    docker exec "${CONTAINER}" "${INSIDE_SCRIPT}" --inside
    rc=$?
    docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
    exit "${rc}"
fi

# ---------------------------------------------------------------------------
# Inside the container
# ---------------------------------------------------------------------------
BIN="/usr/bin/routeward"
TARGET_IP="10.200.1.1"
TARGET_PORT="18080"
SOCKS_LOG="/tmp/socks5_hits.log"
PROBE_IP="10.201.1.2"
PROFILE_PATH="/etc/routeward/active_profile.json"
SOCKET_PATH="/run/routeward/routeward.sock"
LOG_GLOB="/var/log/routeward/RouteWard_*.log"
CURL_USER="rwtest"
CTL_USER="rwctl"
DROPIN_DIR="/etc/systemd/system/routeward.service.d"
JOURNAL_BAD_PATTERN="Operation not permitted|SIGSYS|status=31|Bad system call"

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "[PASS] $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "[FAIL] $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
info() { echo "[INFO] $1"; }

ctl_as() { runuser -u "${CTL_USER}" -- "${BIN}" ctl "$@"; }

curl_as_user() {
    # Unmodified curl, no proxy settings, run as the unprivileged user.
    runuser -u "${CURL_USER}" -- env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
        -u ALL_PROXY -u all_proxy curl --noproxy "" -sS --max-time 5 "$@"
}

wait_for() {
    # wait_for <seconds> <command...>
    local limit="$1"
    shift
    local end=$((SECONDS + limit))
    while ((SECONDS < end)); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

nft_table_ip() { nft list table ip routeward; }
nft_table_ks() { nft list table inet routeward_ks; }
socket_ready() { [[ -S "${SOCKET_PATH}" ]]; }

probe_blocked() {
    # UDP sendto into the dummy interface fails at once with EPERM when an nft output chain drops it.
    ! bash -c "echo probe > /dev/udp/${PROBE_IP}/9" >/dev/null 2>&1
}

write_profile() {
    local kill_switch="$1"
    # Same mode as the unit's ConfigurationDirectory=routeward / ConfigurationDirectoryMode=0700.
    mkdir -p /etc/routeward && chmod 0700 /etc/routeward
    cat > "${PROFILE_PATH}" <<EOF
{
  "profileId": "00000000-0000-4000-8000-000000000201",
  "name": "SystemdUnitTestProfile",
  "version": "2026.1022.00",
  "enableLogging": true,
  "interceptionMode": "hybrid",
  "themeConfig": { "theme": "Drakul", "accent": "Default" },
  "securityPolicy": {
    "killSwitchEnabled": ${kill_switch},
    "blockUdpOnTcpOnlyProxy": true,
    "strictDnsNoLocalFallback": true,
    "blockEncryptedDnsBypass": true,
    "unknownProcessAction": { "type": "block" }
  },
  "defaultAction": { "type": "direct" },
  "dnsConfig": {
    "enableFakeIp": true,
    "remoteDnsResolution": true,
    "fakeIpCidr": "198.18.0.0/15",
    "upstreamDns": "${TARGET_IP}:53",
    "bypassDomains": ["localhost", "*.local"]
  },
  "proxies": [
    {
      "id": "socks-local",
      "name": "Local SOCKS5 Gateway",
      "protocol": "socks5",
      "host": "127.0.0.1",
      "port": 1080,
      "auth": null,
      "udpEnabled": true,
      "tls": false,
      "sni": null,
      "enabled": true,
      "lastLatencyMs": null,
      "exitIp": null
    }
  ],
  "chains": [],
  "rules": [
    {
      "id": "rule-curl-test",
      "name": "Curl Test Rule",
      "enabled": true,
      "priority": 1,
      "processPatterns": ["curl"],
      "domainPatterns": [],
      "ipCidrs": [],
      "portRanges": [],
      "protocol": "tcp",
      "action": { "type": "proxy", "targetId": "socks-local" }
    }
  ]
}
EOF
    chmod 0600 "${PROFILE_PATH}"
}

start_service() {
    systemctl reset-failed routeward >/dev/null 2>&1 || true
    systemctl start routeward && wait_for 10 socket_ready
}

start_interception() {
    "${BIN}" ctl start >/dev/null 2>&1 && wait_for 5 nft_table_ip
}

reset_state() {
    systemctl stop routeward >/dev/null 2>&1 || true
    "${BIN}" cleanup --force >/dev/null 2>&1 || true
    rm -f "${SOCKS_LOG}" /tmp/dns_hits.log ${LOG_GLOB}
}

attribution_check() {
    # Runs curl as the unprivileged user through the interception and returns 0 when the connection
    # was proxied and attributed to curl. Leaves the evidence in ATTR_* variables.
    rm -f "${SOCKS_LOG}"
    ATTR_RESP="$(curl_as_user "http://${TARGET_IP}:${TARGET_PORT}/attribution" 2>&1)"
    sleep 0.3
    ATTR_LOG="$(cat ${LOG_GLOB} 2>/dev/null)"
    ATTR_SOCKS="$(cat "${SOCKS_LOG}" 2>/dev/null)"
    [[ "${ATTR_RESP}" == "ROUTEWARD_OK" ]] \
        && grep -q "CONNECT ${TARGET_IP}:${TARGET_PORT}" "${SOCKS_LOG}" 2>/dev/null \
        && grep -q 'process="curl"' <<<"${ATTR_LOG}" \
        && grep -q 'exe="/usr/bin/curl"' <<<"${ATTR_LOG}"
}

echo "=== RouteWard hardened systemd unit - runtime checks ==="
systemctl --version | head -n 1
uname -r

# Environment: target address on lo, dummy probe interface, mock HTTP/SOCKS5/DNS servers.
ip addr add "${TARGET_IP}/32" dev lo 2>/dev/null || true
ip link add rwprobe type dummy 2>/dev/null || true
ip link set rwprobe up
ip addr add "10.201.1.1/24" dev rwprobe 2>/dev/null || true
cp /etc/resolv.conf /tmp/resolv.conf.bak 2>/dev/null || true
echo "nameserver ${TARGET_IP}" > /etc/resolv.conf 2>/dev/null || true
systemd-run --unit=rwmock --collect python3 /opt/routeward-test/mock_servers.py >/dev/null
sleep 1

systemctl cat routeward.service | sed -n '/^\[Service\]/,/^\[Install\]/p' | grep -E '^(SystemCall|Capability|Restrict|Protect|ExecStopPost)' || true

reset_state
write_profile true

# ---------------------------------------------------------------------------
# Check 1: unit starts, no EPERM / SIGSYS in the journal, no audit SECCOMP records
# ---------------------------------------------------------------------------
if start_service && [[ "$(systemctl is-active routeward)" == "active" ]]; then
    sleep 1
    JOURNAL="$(journalctl -u routeward --no-pager -o cat 2>&1)"
    if grep -Eiq "${JOURNAL_BAD_PATTERN}" <<<"${JOURNAL}"; then
        fail "1: unit active but journal contains EPERM/SIGSYS"
        grep -Ei "${JOURNAL_BAD_PATTERN}" <<<"${JOURNAL}" | head -n 10
    else
        pass "1: systemctl start routeward -> active, no 'Operation not permitted' or SIGSYS in the journal"
    fi
    if DMESG="$(dmesg 2>/dev/null)" && [[ -n "${DMESG}" ]]; then
        if grep -Eiq "audit.*(SECCOMP|syscall=)|type=1326" <<<"${DMESG}"; then
            fail "1b: kernel log contains SECCOMP audit records"
            grep -Ei "SECCOMP|type=1326" <<<"${DMESG}" | tail -n 5
        else
            pass "1b: no SECCOMP audit records in the kernel log"
        fi
    else
        info "1b: kernel log not readable, SECCOMP audit check skipped"
    fi
else
    fail "1: routeward did not become active"
    systemctl status routeward --no-pager || true
    journalctl -u routeward --no-pager -o cat | tail -n 30
fi

# ---------------------------------------------------------------------------
# Check 2: CLI over the Unix socket as a member of group routeward
# ---------------------------------------------------------------------------
if STATE_OUT="$(ctl_as state 2>&1)" && [[ -n "${STATE_OUT}" ]]; then
    pass "2: 'routeward ctl state' works as ${CTL_USER} (group routeward)"
else
    fail "2: 'routeward ctl state' failed as ${CTL_USER}: ${STATE_OUT:-}"
    ls -la /run/routeward || true
fi
if runuser -u "${CURL_USER}" -- "${BIN}" ctl state >/dev/null 2>&1; then
    fail "2b: a user outside group routeward could use the IPC socket"
else
    pass "2b: a user outside group routeward is refused on the IPC socket"
fi

# ---------------------------------------------------------------------------
# Check 3: process attribution of a non-root curl under the filter
# ---------------------------------------------------------------------------
if start_interception && attribution_check; then
    pass "3: curl run as ${CURL_USER} was proxied via SOCKS5 and attributed (process=curl, exe=/usr/bin/curl)"
    grep -E "Routed PID=" <<<"${ATTR_LOG}" | tail -n 1
else
    fail "3: non-root curl was not proxied/attributed (resp='${ATTR_RESP:-}')"
    echo "--- daemon log"; echo "${ATTR_LOG:-}" | tail -n 20
    echo "--- socks log"; echo "${ATTR_SOCKS:-}"
fi

# ---------------------------------------------------------------------------
# Check 4: UDP DNS through the interception (Fake-IP answer, raw reply path)
# ---------------------------------------------------------------------------
DNS_A="$(python3 /opt/routeward-test/mock_servers.py --dns-query "${TARGET_IP}" "app.routeward.test" 1 2>&1)"
rm -f "${SOCKS_LOG}"
DNS_CURL="$(curl_as_user "http://app.routeward.test:${TARGET_PORT}/dns-check" 2>&1)"
if grep -Eq "RCODE=0 ANCOUNT=1 IP=198\.1[89]\.[0-9]+\.[0-9]+" <<<"${DNS_A}" \
    && [[ "${DNS_CURL}" == "ROUTEWARD_OK" ]] \
    && grep -q "CONNECT app.routeward.test:${TARGET_PORT}" "${SOCKS_LOG}" 2>/dev/null; then
    pass "4: UDP DNS intercepted (${DNS_A}); curl by domain proxied with ATYP=domain"
else
    fail "4: UDP DNS Fake-IP path (dns='${DNS_A}', curl='${DNS_CURL}')"
    cat "${SOCKS_LOG}" 2>/dev/null || true
    journalctl -u routeward --no-pager -o cat | tail -n 20
fi

# ---------------------------------------------------------------------------
# Check 5: kill switch on, SIGKILL -> ExecStopPost fails closed; cleanup --force restores
# Restart=no is applied through a drop-in so the 3 s restart does not race the observation.
# ---------------------------------------------------------------------------
mkdir -p "${DROPIN_DIR}"
printf '[Service]\nRestart=no\n' > "${DROPIN_DIR}/norestart.conf"
systemctl daemon-reload
reset_state
write_profile true
start_service && start_interception
systemctl kill -s KILL routeward
if wait_for 10 nft_table_ks; then
    STOPPOST_DONE=0
    for _ in $(seq 1 50); do
        if ! systemctl is-active --quiet routeward; then STOPPOST_DONE=1; break; fi
        sleep 0.1
    done
    sleep 1
    if nft_table_ks >/dev/null 2>&1 && ! nft_table_ip >/dev/null 2>&1 && probe_blocked; then
        pass "5: after SIGKILL + ExecStopPost, table inet routeward_ks exists and the egress probe is blocked"
    else
        fail "5: kill switch table/probe state wrong after SIGKILL (stopped=${STOPPOST_DONE})"
        nft list ruleset || true
    fi
    "${BIN}" cleanup --force >/dev/null 2>&1
    if ! nft_table_ks >/dev/null 2>&1 && ! probe_blocked; then
        pass "5b: 'routeward cleanup --force' removed routeward_ks and restored egress"
    else
        fail "5b: cleanup --force did not restore egress"
        nft list ruleset || true
    fi
else
    fail "5: table inet routeward_ks never appeared after SIGKILL"
    journalctl -u routeward --no-pager -o cat | tail -n 30
    nft list ruleset || true
fi
info "5 journal (ExecStopPost):"
journalctl -u routeward --no-pager -o cat | tail -n 6
rm -f "${DROPIN_DIR}/norestart.conf"
systemctl daemon-reload

# Informational: behaviour with the shipped Restart=on-failure after a SIGKILL.
reset_state
write_profile true
start_service && start_interception
systemctl kill -s KILL routeward
wait_for 10 nft_table_ks
info "5c (Restart=on-failure): routeward_ks present right after the kill: $(nft_table_ks >/dev/null 2>&1 && echo yes || echo no)"
sleep 6
info "5c: after RestartSec: service=$(systemctl is-active routeward), routeward_ks=$(nft_table_ks >/dev/null 2>&1 && echo present || echo absent), ip routeward=$(nft_table_ip >/dev/null 2>&1 && echo present || echo absent)"

# ---------------------------------------------------------------------------
# Check 6: clean stop with the kill switch on leaves no routeward_ks
# ---------------------------------------------------------------------------
reset_state
write_profile true
start_service && start_interception
systemctl stop routeward
sleep 0.5
if ! nft_table_ks >/dev/null 2>&1 && ! nft_table_ip >/dev/null 2>&1 && ! probe_blocked; then
    pass "6: clean systemctl stop with kill switch on left no routeward_ks / routeward table and egress is open"
else
    fail "6: clean stop left routeward tables or blocked egress"
    nft list ruleset || true
    journalctl -u routeward --no-pager -o cat | tail -n 20
fi

# ---------------------------------------------------------------------------
# Check 7: control, CAP_DAC_READ_SEARCH removed from the bounding set
# ---------------------------------------------------------------------------
reset_state
write_profile false
mkdir -p "${DROPIN_DIR}"
printf '[Service]\nCapabilityBoundingSet=\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE CAP_CHOWN\n' \
    > "${DROPIN_DIR}/nodacrs.conf"
systemctl daemon-reload
if start_service && start_interception; then
    if attribution_check; then
        info "7: WITHOUT CAP_DAC_READ_SEARCH attribution STILL WORKS (capability not needed for this scenario)"
        pass "7: control run completed (attribution works without CAP_DAC_READ_SEARCH)"
    else
        info "7: WITHOUT CAP_DAC_READ_SEARCH attribution BREAKS (capability is needed)"
        pass "7: control run completed (attribution breaks without CAP_DAC_READ_SEARCH)"
        echo "--- daemon log"; echo "${ATTR_LOG:-}" | tail -n 8
        echo "resp='${ATTR_RESP:-}'"
    fi
else
    fail "7: control run could not start the service or interception"
    journalctl -u routeward --no-pager -o cat | tail -n 20
fi
reset_state
rm -f "${DROPIN_DIR}/nodacrs.conf"
rmdir "${DROPIN_DIR}" 2>/dev/null || true
systemctl daemon-reload
systemctl is-active --quiet routeward && fail "7: cleanup left the service running" || true

systemctl stop rwmock >/dev/null 2>&1 || true
cp /tmp/resolv.conf.bak /etc/resolv.conf 2>/dev/null || true

echo "=== Summary: ${PASS_COUNT} passed, ${FAIL_COUNT} failed ==="
[[ "${FAIL_COUNT}" -eq 0 ]]
