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

BIN="/workspace/target/release/routeward"
TARGET_IP="10.200.1.1"
TARGET_PORT="18080"
SOCKS_LOG="/tmp/socks5_hits.log"

echo "=== RouteWard Milestone 2 - Linux Container Integration Suite ==="

# Attach non-127.0.0.0/8 IPv4 address to loopback so outbound packets traverse nftables output chain
ip addr add "${TARGET_IP}/32" dev lo 2>/dev/null || true

# Start local HTTP target server (0.0.0.0:18080) and SOCKS5 gateway (127.0.0.1:1080)
python3 /workspace/tests/linux/mock_servers.py &
MOCK_PID=$!
sleep 0.5

write_profile() {
    local out_path="$1"
    local rule_action_json="$2"
    cat > "${out_path}" <<EOF
{
  "profileId": "00000000-0000-4000-8000-000000000099",
  "name": "LinuxTestProfile",
  "version": "2026.1022.00",
  "enableLogging": true,
  "interceptionMode": "hybrid",
  "themeConfig": {
    "theme": "Drakul",
    "accent": "Default"
  },
  "securityPolicy": {
    "killSwitchEnabled": true,
    "blockUdpOnTcpOnlyProxy": true,
    "strictDnsNoLocalFallback": true,
    "unknownProcessAction": { "type": "direct" }
  },
  "defaultAction": { "type": "direct" },
  "dnsConfig": {
    "enableFakeIp": true,
    "remoteDnsResolution": true,
    "fakeIpCidr": "198.18.0.0/15",
    "upstreamDns": "1.1.1.1:53",
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
      "action": ${rule_action_json}
    }
  ]
}
EOF
}

write_profile "/tmp/profile_proxy.json" '{ "type": "proxy", "targetId": "socks-local" }'
write_profile "/tmp/profile_direct.json" '{ "type": "direct" }'
write_profile "/tmp/profile_block.json" '{ "type": "block" }'

wait_for_nft_table() {
    for _ in $(seq 1 30); do
        if nft list table ip routeward >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# ---------------------------------------------------------------------------
# Scenario (a): Unmodified curl (no proxy setting) routed via SOCKS5 by rule
# ---------------------------------------------------------------------------
rm -f "${SOCKS_LOG}" /var/log/routeward/RouteWard_*.log
"${BIN}" -p /tmp/profile_proxy.json run >/tmp/rw_a.out 2>&1 &
RW_PID=$!
wait_for_nft_table

RESP_A=$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy \
    curl --noproxy "" -sS --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/scenario-a")
kill -INT "${RW_PID}" || true
wait "${RW_PID}" || true

LOG_FILE=$(ls -1 /var/log/routeward/RouteWard_*.log | head -n 1)
if [[ "${RESP_A}" == "ROUTEWARD_OK" ]] \
    && grep -q "CONNECT ${TARGET_IP}:${TARGET_PORT}" "${SOCKS_LOG}" \
    && grep -q 'process="curl"' "${LOG_FILE}" \
    && grep -q 'exe="/usr/bin/curl"' "${LOG_FILE}" \
    && grep -q "via Local SOCKS5 Gateway" "${LOG_FILE}"; then
    echo "[PASS] Scenario (a): curl transparently routed via SOCKS5 with PID and exe logged"
    grep "Routed PID=" "${LOG_FILE}" | tail -n 1
else
    echo "[FAIL] Scenario (a)"
    cat "${LOG_FILE}" || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (b): Direct rule pass-through
# ---------------------------------------------------------------------------
rm -f "${SOCKS_LOG}" /var/log/routeward/RouteWard_*.log
"${BIN}" -p /tmp/profile_direct.json run >/tmp/rw_b.out 2>&1 &
RW_PID=$!
wait_for_nft_table

RESP_B=$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy \
    curl --noproxy "" -sS --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/scenario-b")
kill -INT "${RW_PID}" || true
wait "${RW_PID}" || true

LOG_FILE=$(ls -1 /var/log/routeward/RouteWard_*.log | head -n 1)
if [[ "${RESP_B}" == "ROUTEWARD_OK" ]] \
    && [[ ! -s "${SOCKS_LOG}" ]] \
    && grep -q 'process="curl"' "${LOG_FILE}" \
    && grep -q "via DIRECT" "${LOG_FILE}"; then
    echo "[PASS] Scenario (b): Direct rule bypassed SOCKS5 and reached target directly"
    grep "Routed PID=" "${LOG_FILE}" | tail -n 1
else
    echo "[FAIL] Scenario (b)"
    cat "${LOG_FILE}" || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (c): Block rule resets connection (TCP RST)
# ---------------------------------------------------------------------------
rm -f "${SOCKS_LOG}" /var/log/routeward/RouteWard_*.log
"${BIN}" -p /tmp/profile_block.json run >/tmp/rw_c.out 2>&1 &
RW_PID=$!
wait_for_nft_table

set +e
env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy \
    curl --noproxy "" -sS --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/scenario-c" >/tmp/curl_c.out 2>&1
CURL_EXIT_C=$?
set -e

kill -INT "${RW_PID}" || true
wait "${RW_PID}" || true

LOG_FILE=$(ls -1 /var/log/routeward/RouteWard_*.log | head -n 1)
if [[ "${CURL_EXIT_C}" -ne 0 ]] \
    && grep -q "Blocked connection PID=" "${LOG_FILE}" \
    && grep -q "(TCP RST)" "${LOG_FILE}"; then
    echo "[PASS] Scenario (c): Block rule reset curl connection (curl exit=${CURL_EXIT_C}) and logged TCP RST"
    grep "Blocked connection PID=" "${LOG_FILE}" | tail -n 1
else
    echo "[FAIL] Scenario (c): expected non-zero curl exit, got ${CURL_EXIT_C}"
    cat "${LOG_FILE}" || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (d): Clean shutdown (SIGINT / SIGTERM) removes nftables table
# ---------------------------------------------------------------------------
"${BIN}" -p /tmp/profile_proxy.json run >/tmp/rw_d.out 2>&1 &
RW_PID=$!
wait_for_nft_table

kill -TERM "${RW_PID}"
wait "${RW_PID}" || true

if ! nft list table ip routeward >/dev/null 2>&1; then
    echo "[PASS] Scenario (d): Clean shutdown (SIGTERM) removed table ip routeward"
else
    echo "[FAIL] Scenario (d): table ip routeward still present after SIGTERM"
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (e): kill -9 (SIGKILL) of routeward -> watchdog removes nft table
# ---------------------------------------------------------------------------
"${BIN}" -p /tmp/profile_proxy.json run >/tmp/rw_e.out 2>&1 &
RW_PID=$!
wait_for_nft_table

kill -9 "${RW_PID}"
wait "${RW_PID}" 2>/dev/null || true
sleep 0.5

if ! nft list table ip routeward >/dev/null 2>&1; then
    RESP_AFTER_KILL=$(curl -sS --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/after-kill9")
    if [[ "${RESP_AFTER_KILL}" == "ROUTEWARD_OK" ]]; then
        echo "[PASS] Scenario (e): SIGKILL (kill -9) triggered pipe-linked watchdog; table ip routeward deleted and fail-open verified"
    else
        echo "[FAIL] Scenario (e): fail-open HTTP request failed after kill -9"
        exit 1
    fi
else
    echo "[FAIL] Scenario (e): table ip routeward still present after kill -9"
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (f): routeward cleanup removes an orphaned nftables table
# ---------------------------------------------------------------------------
nft add table ip routeward
if ! nft list table ip routeward >/dev/null 2>&1; then
    echo "[FAIL] Scenario (f): could not create synthetic orphaned table ip routeward"
    exit 1
fi

"${BIN}" cleanup >/tmp/rw_f.out 2>&1

if ! nft list table ip routeward >/dev/null 2>&1; then
    echo "[PASS] Scenario (f): routeward cleanup removed orphaned table ip routeward"
else
    echo "[FAIL] Scenario (f): table ip routeward still present after routeward cleanup"
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (g): Daemon started as root; non-root user in 'routeward' group
#               queries status via 'routeward ctl', starts interception, and
#               curl connection is reported (PID, exe, rxBytes > 0)
# ---------------------------------------------------------------------------
groupadd -f routeward
id -u rwmember >/dev/null 2>&1 || useradd -M -s /bin/bash -G routeward rwmember
id -u rwoutsider >/dev/null 2>&1 || useradd -M -s /bin/bash rwoutsider

mkdir -p /etc/routeward
chmod 0700 /etc/routeward
cp /tmp/profile_proxy.json /etc/routeward/active_profile.json
rm -f "${SOCKS_LOG}" /var/log/routeward/RouteWard_*.log /run/routeward/routeward.sock

# Verify daemon refuses to start if /etc/routeward/active_profile.json is group-readable (0640) or world-readable (0644)
chmod 0640 /etc/routeward/active_profile.json
set +e
"${BIN}" daemon >/tmp/rw_daemon_insecure.out 2>&1
INSECURE_EXIT=$?
set -e
if [[ "${INSECURE_EXIT}" -eq 0 ]]; then
    echo "[FAIL] Scenario (g): daemon started despite group-readable (0640) /etc/routeward/active_profile.json"
    exit 1
fi
chmod 0600 /etc/routeward/active_profile.json

"${BIN}" daemon >/tmp/rw_daemon.out 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 30); do
    if [[ -S /run/routeward/routeward.sock ]]; then
        break
    fi
    sleep 0.1
done

if [[ ! -S /run/routeward/routeward.sock ]]; then
    echo "[FAIL] Scenario (g): /run/routeward/routeward.sock was not created by daemon"
    cat /tmp/rw_daemon.out || true
    exit 1
fi

# Verify single-instance guard rejects a second daemon
set +e
"${BIN}" daemon >/tmp/rw_daemon_dup.out 2>&1
DUP_EXIT=$?
set -e
if [[ "${DUP_EXIT}" -eq 0 ]]; then
    echo "[FAIL] Scenario (g): duplicate daemon instance was not rejected"
    exit 1
fi

STATUS_G=$(su -s /bin/bash rwmember -c "${BIN} ctl status")
START_G=$(su -s /bin/bash rwmember -c "${BIN} ctl start")
wait_for_nft_table

RESP_G=$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy \
    curl --noproxy "" -sS --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/scenario-g")
sleep 0.2
CONNS_G=$(su -s /bin/bash rwmember -c "${BIN} ctl connections")
LOGS_G=$(su -s /bin/bash rwmember -c "${BIN} ctl logs")

if [[ "${RESP_G}" == "ROUTEWARD_OK" ]] \
    && echo "${STATUS_G}" | grep -q '"daemonConnected": true' \
    && echo "${START_G}" | grep -q '"running": true' \
    && echo "${CONNS_G}" | grep -q '"processName": "curl"' \
    && echo "${CONNS_G}" | grep -q '"processPath": "/usr/bin/curl"' \
    && echo "${CONNS_G}" | grep -Eq '"pid": [1-9][0-9]*' \
    && echo "${CONNS_G}" | grep -Eq '"rxBytes": [1-9][0-9]*' \
    && echo "${LOGS_G}" | grep -q "Accepted IPC client via SO_PEERCRED"; then
    echo "[PASS] Scenario (g): non-root 'routeward' group member controlled daemon via ctl and curl connection reported PID, exe, rxBytes > 0"
else
    echo "[FAIL] Scenario (g)"
    echo "STATUS_G=${STATUS_G}"
    echo "START_G=${START_G}"
    echo "CONNS_G=${CONNS_G}"
    echo "LOGS_G=${LOGS_G}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (h): Non-root user NOT in 'routeward' group is rejected by ctl
# ---------------------------------------------------------------------------
set +e
su -s /bin/bash rwoutsider -c "${BIN} ctl status" >/tmp/ctl_h.out 2>&1
OUTSIDER_EXIT=$?
set -e

if [[ "${OUTSIDER_EXIT}" -ne 0 ]]; then
    echo "[PASS] Scenario (h): non-root user outside 'routeward' group rejected (exit=${OUTSIDER_EXIT})"
else
    echo "[FAIL] Scenario (h): user outside 'routeward' group was unexpectedly allowed"
    cat /tmp/ctl_h.out || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (i): kill -9 (SIGKILL) of daemon removes nftables table via watchdog
# ---------------------------------------------------------------------------
if ! nft list table ip routeward >/dev/null 2>&1; then
    echo "[FAIL] Scenario (i): table ip routeward was not active before kill -9 of daemon"
    exit 1
fi

kill -9 "${DAEMON_PID}"
wait "${DAEMON_PID}" 2>/dev/null || true
sleep 0.5

if ! nft list table ip routeward >/dev/null 2>&1; then
    RESP_AFTER_DAEMON_KILL=$(curl -sS --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/after-daemon-kill9")
    if [[ "${RESP_AFTER_DAEMON_KILL}" == "ROUTEWARD_OK" ]]; then
        echo "[PASS] Scenario (i): SIGKILL (kill -9) of daemon triggered watchdog; table ip routeward deleted and fail-open verified"
    else
        echo "[FAIL] Scenario (i): fail-open HTTP request failed after daemon kill -9"
        exit 1
    fi
else
    echo "[FAIL] Scenario (i): table ip routeward still present after daemon kill -9"
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (j): Orphaned 'table ip routeward' is automatically cleaned up
#               at 'routeward daemon' startup and logged at INFO
# ---------------------------------------------------------------------------
nft add table ip routeward
if ! nft list table ip routeward >/dev/null 2>&1; then
    echo "[FAIL] Scenario (j): could not create synthetic orphaned table ip routeward"
    exit 1
fi

rm -f /var/log/routeward/RouteWard_*.log /run/routeward/routeward.sock
"${BIN}" daemon --duration-secs 2 >/tmp/rw_daemon_j.out 2>&1

if ! nft list table ip routeward >/dev/null 2>&1; then
    LOG_FILE_J=$(ls -1 /var/log/routeward/RouteWard_*.log | head -n 1)
    if grep -q 'Removed nftables table "ip routeward"' "${LOG_FILE_J}"; then
        echo "[PASS] Scenario (j): orphaned table ip routeward automatically removed at daemon startup and logged at INFO"
        grep 'Removed nftables table "ip routeward"' "${LOG_FILE_J}" | tail -n 1
    else
        echo "[FAIL] Scenario (j): table removed at startup, but INFO log entry was not found"
        cat "${LOG_FILE_J}" || true
        exit 1
    fi
else
    echo "[FAIL] Scenario (j): orphaned table ip routeward was NOT removed at daemon startup"
    exit 1
fi

kill "${MOCK_PID}" 2>/dev/null || true
echo "=== ALL 10 LINUX CONTAINER SCENARIOS PASSED ==="
