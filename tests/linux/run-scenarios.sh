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
TARGET_IPV6="fd00:200:1::1"
TARGET_PORT="18080"
SOCKS_LOG="/tmp/socks5_hits.log"

echo "=== RouteWard Milestone 2 - Linux Container Integration Suite ==="

# Attach non-127.0.0.0/8 IPv4 and non-::1 IPv6 addresses to loopback so outbound packets traverse nftables output chain
ip addr add "${TARGET_IP}/32" dev lo 2>/dev/null || true
ip -6 addr add "${TARGET_IPV6}/128" dev lo nodad 2>/dev/null || true

# Start local HTTP target server (0.0.0.0:18080) and SOCKS5 gateway (127.0.0.1:1080)
python3 /workspace/tests/linux/mock_servers.py &
MOCK_PID=$!
sleep 0.5

write_profile() {
    local out_path="$1"
    local rule_action_json="$2"
    local kill_switch="${3:-true}"
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
    "killSwitchEnabled": ${kill_switch},
    "blockUdpOnTcpOnlyProxy": true,
    "strictDnsNoLocalFallback": true,
    "unknownProcessAction": { "type": "block" }
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
write_profile "/tmp/profile_proxy_ks_off.json" '{ "type": "proxy", "targetId": "socks-local" }' false

# Probe target on a dummy (NOARP) interface: the loopback test target is always allowed by the
# fail-closed table (oif lo), so a block is proven by a UDP probe to the dummy subnet failing.
PROBE_IP="10.201.1.2"
PROBE_BLOCKED_CODE=7
ip link add rwprobe type dummy 2>/dev/null || true
ip link set rwprobe up
ip addr add "10.201.1.1/24" dev rwprobe 2>/dev/null || true

probe_exit_code() {
    # A UDP sendto into the dummy interface fails at once with EPERM when an nft output chain drops it
    # (TCP would only retransmit silently). Prints PROBE_BLOCKED_CODE when blocked, 0 when open.
    if bash -c "echo probe > /dev/udp/${PROBE_IP}/9" >/dev/null 2>&1; then
        echo 0
    else
        echo "${PROBE_BLOCKED_CODE}"
    fi
}

wait_for_block_table() {
    for _ in $(seq 1 50); do
        if nft list table inet routeward_ks >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

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
# Scenario (d2): Clean shutdown with the kill switch ON never leaves the network blocked
# ---------------------------------------------------------------------------
"${BIN}" -p /tmp/profile_proxy.json run >/tmp/rw_d2.out 2>&1 &
RW_PID=$!
wait_for_nft_table

kill -TERM "${RW_PID}"
wait "${RW_PID}" || true
sleep 0.5

RESP_D2=$(curl -sS --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/after-clean-stop")
PROBE_D2=$(probe_exit_code)
if ! nft list table ip routeward >/dev/null 2>&1 \
    && ! nft list table inet routeward_ks >/dev/null 2>&1 \
    && [[ "${RESP_D2}" == "ROUTEWARD_OK" ]] \
    && [[ "${PROBE_D2}" -ne "${PROBE_BLOCKED_CODE}" ]]; then
    echo "[PASS] Scenario (d2): clean stop with kill switch on left no routeward or routeward_ks table and traffic flows"
else
    echo "[FAIL] Scenario (d2): clean stop with kill switch on left the host blocked (resp=${RESP_D2}, probe=${PROBE_D2})"
    nft list ruleset || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (e): kill switch OFF, kill -9 (SIGKILL) of routeward -> watchdog removes nft table (fail-open)
# ---------------------------------------------------------------------------
"${BIN}" -p /tmp/profile_proxy_ks_off.json run >/tmp/rw_e.out 2>&1 &
RW_PID=$!
wait_for_nft_table

kill -9 "${RW_PID}"
wait "${RW_PID}" 2>/dev/null || true
sleep 0.5

if ! nft list table ip routeward >/dev/null 2>&1 && ! nft list table inet routeward_ks >/dev/null 2>&1; then
    RESP_AFTER_KILL=$(curl -sS --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/after-kill9")
    PROBE_E=$(probe_exit_code)
    if [[ "${RESP_AFTER_KILL}" == "ROUTEWARD_OK" ]] && [[ "${PROBE_E}" -ne "${PROBE_BLOCKED_CODE}" ]]; then
        echo "[PASS] Scenario (e): kill switch off, SIGKILL triggered pipe-linked watchdog; table ip routeward deleted and fail-open verified"
    else
        echo "[FAIL] Scenario (e): fail-open check failed after kill -9 (resp=${RESP_AFTER_KILL}, probe=${PROBE_E})"
        exit 1
    fi
else
    echo "[FAIL] Scenario (e): routeward tables still present after kill -9 with kill switch off"
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (e2): kill switch ON, kill -9 -> watchdog fails CLOSED (inet routeward_ks),
#                `routeward cleanup` restores traffic
# ---------------------------------------------------------------------------
"${BIN}" -p /tmp/profile_proxy.json run >/tmp/rw_e2.out 2>&1 &
RW_PID=$!
wait_for_nft_table

kill -9 "${RW_PID}"
wait "${RW_PID}" 2>/dev/null || true

if ! wait_for_block_table; then
    echo "[FAIL] Scenario (e2): table inet routeward_ks was not installed after kill -9 with kill switch on"
    nft list ruleset || true
    exit 1
fi
PROBE_E2=$(probe_exit_code)
if nft list table ip routeward >/dev/null 2>&1 || [[ "${PROBE_E2}" -ne "${PROBE_BLOCKED_CODE}" ]]; then
    echo "[FAIL] Scenario (e2): host not blocked after kill -9 with kill switch on (probe=${PROBE_E2})"
    nft list ruleset || true
    exit 1
fi

"${BIN}" cleanup >/tmp/rw_e2_cleanup.out 2>&1
RESP_E2=$(curl -sS --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/after-cleanup-e2")
PROBE_E2_AFTER=$(probe_exit_code)
if ! nft list table inet routeward_ks >/dev/null 2>&1 \
    && [[ "${RESP_E2}" == "ROUTEWARD_OK" ]] \
    && [[ "${PROBE_E2_AFTER}" -ne "${PROBE_BLOCKED_CODE}" ]]; then
    echo "[PASS] Scenario (e2): kill switch on, SIGKILL failed closed (inet routeward_ks, probe blocked) and routeward cleanup restored traffic"
else
    echo "[FAIL] Scenario (e2): cleanup did not restore traffic (resp=${RESP_E2}, probe=${PROBE_E2_AFTER})"
    nft list ruleset || true
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
# Scenario (i): kill switch ON, kill -9 (SIGKILL) of daemon -> watchdog fails CLOSED
#               (inet routeward_ks); `routeward cleanup` restores traffic
# ---------------------------------------------------------------------------
if ! nft list table ip routeward >/dev/null 2>&1; then
    echo "[FAIL] Scenario (i): table ip routeward was not active before kill -9 of daemon"
    exit 1
fi

kill -9 "${DAEMON_PID}"
wait "${DAEMON_PID}" 2>/dev/null || true

if ! wait_for_block_table; then
    echo "[FAIL] Scenario (i): table inet routeward_ks was not installed after daemon kill -9 with kill switch on"
    nft list ruleset || true
    exit 1
fi
PROBE_I=$(probe_exit_code)
if nft list table ip routeward >/dev/null 2>&1 || [[ "${PROBE_I}" -ne "${PROBE_BLOCKED_CODE}" ]]; then
    echo "[FAIL] Scenario (i): host not blocked after daemon kill -9 with kill switch on (probe=${PROBE_I})"
    nft list ruleset || true
    exit 1
fi

"${BIN}" cleanup --force >/tmp/rw_i_cleanup.out 2>&1
RESP_AFTER_DAEMON_KILL=$(curl -sS --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/after-daemon-kill9")
PROBE_I_AFTER=$(probe_exit_code)
if ! nft list table inet routeward_ks >/dev/null 2>&1 \
    && [[ "${RESP_AFTER_DAEMON_KILL}" == "ROUTEWARD_OK" ]] \
    && [[ "${PROBE_I_AFTER}" -ne "${PROBE_BLOCKED_CODE}" ]]; then
    echo "[PASS] Scenario (i): kill switch on, SIGKILL of daemon failed closed (inet routeward_ks, probe blocked) and routeward cleanup restored traffic"
else
    echo "[FAIL] Scenario (i): cleanup did not restore traffic after daemon kill -9 (resp=${RESP_AFTER_DAEMON_KILL}, probe=${PROBE_I_AFTER})"
    nft list ruleset || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (i2): kill switch OFF, kill -9 of daemon -> watchdog removes tables (fail-open)
# ---------------------------------------------------------------------------
cp /tmp/profile_proxy_ks_off.json /etc/routeward/active_profile.json
chmod 0600 /etc/routeward/active_profile.json
rm -f /run/routeward/routeward.sock
"${BIN}" daemon >/tmp/rw_daemon_i2.out 2>&1 &
DAEMON_I2_PID=$!
for _ in $(seq 1 30); do
    if [[ -S /run/routeward/routeward.sock ]]; then
        break
    fi
    sleep 0.1
done
"${BIN}" ctl start >/tmp/rw_i2_start.out 2>&1
wait_for_nft_table

kill -9 "${DAEMON_I2_PID}"
wait "${DAEMON_I2_PID}" 2>/dev/null || true
sleep 0.5

RESP_I2=$(curl -sS --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/after-daemon-kill9-ks-off")
PROBE_I2=$(probe_exit_code)
if ! nft list table ip routeward >/dev/null 2>&1 \
    && ! nft list table inet routeward_ks >/dev/null 2>&1 \
    && [[ "${RESP_I2}" == "ROUTEWARD_OK" ]] \
    && [[ "${PROBE_I2}" -ne "${PROBE_BLOCKED_CODE}" ]]; then
    echo "[PASS] Scenario (i2): kill switch off, SIGKILL of daemon triggered watchdog; tables deleted and fail-open verified"
else
    echo "[FAIL] Scenario (i2): fail-open check failed after daemon kill -9 with kill switch off (resp=${RESP_I2}, probe=${PROBE_I2})"
    nft list ruleset || true
    exit 1
fi

cp /tmp/profile_proxy.json /etc/routeward/active_profile.json
chmod 0600 /etc/routeward/active_profile.json
rm -f /run/routeward/routeward.sock

# ---------------------------------------------------------------------------
# Scenario (i3): kill switch ON, daemon IDLE (interception never started), kill -9, then the
#                systemd ExecStopPost hook (`cleanup --force --fail-closed-on-crash` with
#                SERVICE_RESULT=signal) must NOT install the block table: traffic stays open
# ---------------------------------------------------------------------------
"${BIN}" daemon >/tmp/rw_daemon_i3.out 2>&1 &
DAEMON_I3_PID=$!
for _ in $(seq 1 30); do
    if [[ -S /run/routeward/routeward.sock ]]; then
        break
    fi
    sleep 0.1
done

kill -9 "${DAEMON_I3_PID}"
wait "${DAEMON_I3_PID}" 2>/dev/null || true
sleep 0.5

SERVICE_RESULT=signal "${BIN}" cleanup --force --fail-closed-on-crash >/tmp/rw_i3_cleanup.out 2>&1
RESP_I3=$(curl -sS --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/after-idle-daemon-kill9")
PROBE_I3=$(probe_exit_code)
if ! nft list table inet routeward_ks >/dev/null 2>&1 \
    && ! nft list table ip routeward >/dev/null 2>&1 \
    && [[ "${RESP_I3}" == "ROUTEWARD_OK" ]] \
    && [[ "${PROBE_I3}" -ne "${PROBE_BLOCKED_CODE}" ]]; then
    echo "[PASS] Scenario (i3): idle daemon killed with kill switch on, fail-closed-on-crash cleanup installed no block table and traffic stayed open"
else
    echo "[FAIL] Scenario (i3): idle daemon crash must not fail closed (resp=${RESP_I3}, probe=${PROBE_I3})"
    cat /tmp/rw_i3_cleanup.out || true
    nft list ruleset || true
    exit 1
fi

rm -f /run/routeward/routeward.sock

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

# ---------------------------------------------------------------------------
# Scenario (k): 'routeward cleanup' is refused while daemon is active,
#               leaving 'table ip routeward' intact
# ---------------------------------------------------------------------------
rm -f /run/routeward/routeward.sock
"${BIN}" daemon >/tmp/rw_daemon_k.out 2>&1 &
DAEMON_K_PID=$!

for _ in $(seq 1 30); do
    if [[ -S /run/routeward/routeward.sock ]]; then
        break
    fi
    sleep 0.1
done

"${BIN}" ctl start >/dev/null
wait_for_nft_table

set +e
"${BIN}" cleanup >/tmp/rw_cleanup_k.out 2>&1
CLEANUP_K_EXIT=$?
set -e

if [[ "${CLEANUP_K_EXIT}" -ne 0 ]] && nft list table ip routeward >/dev/null 2>&1; then
    echo "[PASS] Scenario (k): routeward cleanup refused while daemon is active (exit=${CLEANUP_K_EXIT}) and table ip routeward remained intact"
else
    echo "[FAIL] Scenario (k): expected cleanup refusal and intact nft table (exit=${CLEANUP_K_EXIT})"
    cat /tmp/rw_cleanup_k.out || true
    kill -TERM "${DAEMON_K_PID}" 2>/dev/null || true
    exit 1
fi

kill -TERM "${DAEMON_K_PID}" 2>/dev/null || true
wait "${DAEMON_K_PID}" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Scenario (l): Kill-Switch (killSwitchEnabled=true) - SOCKS5 server stopped,
#               curl matched by Proxy rule fails, target HTTP server receives
#               zero direct connections, and ctl connections reports Blocked
# ---------------------------------------------------------------------------
kill "${MOCK_PID}" 2>/dev/null || true
wait "${MOCK_PID}" 2>/dev/null || true
rm -f "${SOCKS_LOG}" /tmp/http_target_hits.log /run/routeward/routeward.sock

# Restart only the HTTP target server so the SOCKS5 proxy (127.0.0.1:1080) is stopped
python3 /workspace/tests/linux/mock_servers.py --http-only &
MOCK_HTTP_PID=$!
sleep 0.3

cp /tmp/profile_proxy.json /etc/routeward/active_profile.json
chmod 0600 /etc/routeward/active_profile.json

"${BIN}" daemon >/tmp/rw_daemon_l.out 2>&1 &
DAEMON_L_PID=$!

for _ in $(seq 1 30); do
    if [[ -S /run/routeward/routeward.sock ]]; then
        break
    fi
    sleep 0.1
done

"${BIN}" ctl start >/dev/null
wait_for_nft_table

set +e
env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy \
    curl --noproxy "" -sS --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/scenario-l" >/tmp/curl_l.out 2>&1
CURL_EXIT_L=$?
set -e

sleep 0.2
CONNS_L=$("${BIN}" ctl connections)
LOGS_L=$("${BIN}" ctl logs)

kill -TERM "${DAEMON_L_PID}" 2>/dev/null || true
wait "${DAEMON_L_PID}" 2>/dev/null || true
kill "${MOCK_HTTP_PID}" 2>/dev/null || true

if [[ "${CURL_EXIT_L}" -ne 0 ]] \
    && [[ ! -s /tmp/http_target_hits.log ]] \
    && echo "${CONNS_L}" | grep -q '"processName": "curl"' \
    && echo "${CONNS_L}" | grep -q '"status": "blocked"' \
    && echo "${CONNS_L}" | grep -q '"routeLabel": "BLOCKED"' \
    && echo "${LOGS_L}" | grep -q "Kill-Switch blocked connection"; then
    echo "[PASS] Scenario (l): Kill-Switch blocked curl when SOCKS5 proxy stopped (curl exit=${CURL_EXIT_L}, 0 target hits, status=blocked)"
else
    echo "[FAIL] Scenario (l): expected curl failure, 0 target hits, and status=blocked (curl exit=${CURL_EXIT_L})"
    echo "HTTP_TARGET_HITS:"
    cat /tmp/http_target_hits.log 2>/dev/null || true
    echo "CONNS_L=${CONNS_L}"
    echo "LOGS_L=${LOGS_L}"
    exit 1
fi

# Restart full mock servers (HTTP + SOCKS5 + DNS UDP/TCP on :53) for DNS scenarios (m)-(q)
rm -f "${SOCKS_LOG}" /tmp/http_target_hits.log /tmp/dns_hits.log /run/routeward/routeward.sock
python3 /workspace/tests/linux/mock_servers.py &
MOCK_PID=$!
sleep 0.4

cp /etc/resolv.conf /tmp/resolv.conf.bak
echo "nameserver ${TARGET_IP}" > /etc/resolv.conf

cat > /tmp/profile_dns_fakeip.json <<EOF
{
  "profileId": "00000000-0000-4000-8000-000000000101",
  "name": "LinuxDnsFakeIpProfile",
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
    "blockEncryptedDnsBypass": true,
    "unknownProcessAction": { "type": "block" }
  },
  "defaultAction": { "type": "direct" },
  "dnsConfig": {
    "enableFakeIp": true,
    "remoteDnsResolution": true,
    "fakeIpCidr": "198.18.0.0/15",
    "upstreamDns": "${TARGET_IP}:53",
    "bypassDomains": ["corp.contoso.com", "localhost", "*.local"]
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
      "id": "rule-domain-routeward",
      "name": "RouteWard Domain Rule",
      "enabled": true,
      "priority": 1,
      "processPatterns": [],
      "domainPatterns": ["*.routeward.test"],
      "ipCidrs": [],
      "portRanges": [],
      "protocol": "tcp",
      "action": { "type": "proxy", "targetId": "socks-local" }
    }
  ]
}
EOF

cat > /tmp/profile_dns_real.json <<EOF
{
  "profileId": "00000000-0000-4000-8000-000000000102",
  "name": "LinuxDnsRealProfile",
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
    "blockEncryptedDnsBypass": true,
    "unknownProcessAction": { "type": "block" }
  },
  "defaultAction": { "type": "proxy", "targetId": "socks-local" },
  "dnsConfig": {
    "enableFakeIp": false,
    "remoteDnsResolution": true,
    "fakeIpCidr": "198.18.0.0/15",
    "upstreamDns": "${TARGET_IP}:53",
    "bypassDomains": ["corp.contoso.com", "localhost", "*.local"]
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
  "rules": []
}
EOF

# ---------------------------------------------------------------------------
# Scenario (m): Fake-IP end-to-end - DNS query returns IP in 198.18.0.0/15
#               with 5s TTL (AAAA -> NODATA), curl to domain matches domain
#               rule and sends domain name to SOCKS5, 0 INFO DNS logs
# ---------------------------------------------------------------------------
rm -f "${SOCKS_LOG}" /tmp/dns_hits.log /run/routeward/routeward.sock
cp /tmp/profile_dns_fakeip.json /etc/routeward/active_profile.json
chmod 0600 /etc/routeward/active_profile.json

"${BIN}" daemon >/tmp/rw_daemon_m.out 2>&1 &
DAEMON_M_PID=$!
for _ in $(seq 1 30); do
    if [[ -S /run/routeward/routeward.sock ]]; then
        break
    fi
    sleep 0.1
done

"${BIN}" ctl start >/dev/null
wait_for_nft_table

DNS_M_A=$(python3 /workspace/tests/linux/mock_servers.py --dns-query "${TARGET_IP}" "app.routeward.test" 1)
DNS_M_AAAA=$(python3 /workspace/tests/linux/mock_servers.py --dns-query "${TARGET_IP}" "app.routeward.test" 28)

RESP_M=$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy \
    curl --noproxy "" -sS --max-time 5 "http://app.routeward.test:${TARGET_PORT}/scenario-m")
sleep 0.2
FAKE_IPS_M=$("${BIN}" ctl fake-ips)
LOGS_M=$("${BIN}" ctl logs)

if echo "${DNS_M_A}" | grep -Eq "RCODE=0 ANCOUNT=1 IP=198\.1[89]\.[0-9]+\.[0-9]+ TTL=5" \
    && echo "${DNS_M_AAAA}" | grep -q "RCODE=0 ANCOUNT=0" \
    && [[ "${RESP_M}" == "ROUTEWARD_OK" ]] \
    && grep -q "CONNECT app.routeward.test:${TARGET_PORT}" "${SOCKS_LOG}" \
    && echo "${FAKE_IPS_M}" | grep -q '"domain": "app.routeward.test"' \
    && ! echo "${LOGS_M}" | grep -q '"component": "FakeIpDNS"'; then
    echo "[PASS] Scenario (m): Fake-IP end-to-end (${DNS_M_A}; AAAA NODATA; curl routed via SOCKS5 with ATYP=domain; 0 INFO DNS logs)"
else
    echo "[FAIL] Scenario (m)"
    echo "DNS_M_A=${DNS_M_A}"
    echo "DNS_M_AAAA=${DNS_M_AAAA}"
    echo "RESP_M=${RESP_M}"
    cat "${SOCKS_LOG}" 2>/dev/null || true
    echo "FAKE_IPS_M=${FAKE_IPS_M}"
    echo "LOGS_M=${LOGS_M}"
    kill -TERM "${DAEMON_M_PID}" 2>/dev/null || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (o): Bypassed domain (corp.contoso.com) resolved directly against
#               target DNS server without Fake-IP and without hitting SOCKS5
# ---------------------------------------------------------------------------
rm -f "${SOCKS_LOG}" /tmp/dns_hits.log
DNS_O=$(python3 /workspace/tests/linux/mock_servers.py --dns-query "${TARGET_IP}" "dc01.corp.contoso.com" 1)

if echo "${DNS_O}" | grep -q "RCODE=0 ANCOUNT=1 IP=${TARGET_IP}" \
    && grep -q "dc01.corp.contoso.com 1" /tmp/dns_hits.log \
    && [[ ! -s "${SOCKS_LOG}" ]]; then
    echo "[PASS] Scenario (o): Bypassed AD domain dc01.corp.contoso.com resolved directly (${DNS_O}) without Fake-IP or SOCKS5"
else
    echo "[FAIL] Scenario (o)"
    echo "DNS_O=${DNS_O}"
    cat /tmp/dns_hits.log 2>/dev/null || true
    cat "${SOCKS_LOG}" 2>/dev/null || true
    kill -TERM "${DAEMON_M_PID}" 2>/dev/null || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (p): blockEncryptedDnsBypass=true - DoH canary returns NXDOMAIN,
#               outbound port 853 (TCP & UDP) blocked, and IPv6 DNS (53 UDP/TCP)
#               intercepted into RouteWard Fake-IP DNS engine
# ---------------------------------------------------------------------------
DNS_P_CANARY=$(python3 /workspace/tests/linux/mock_servers.py --dns-query "${TARGET_IP}" "use-application-dns.net" 1)
DNS_P_V6_UDP_A=$(python3 /workspace/tests/linux/mock_servers.py --dns-query "${TARGET_IPV6}" "v6udp.routeward.test" 1)
DNS_P_V6_UDP_AAAA=$(python3 /workspace/tests/linux/mock_servers.py --dns-query "${TARGET_IPV6}" "v6udp.routeward.test" 28)
DNS_P_V6_TCP_A=$(python3 /workspace/tests/linux/mock_servers.py --dns-tcp-query "${TARGET_IPV6}" "v6tcp.routeward.test" 1)
NFT_IP4_P=$(nft list table ip routeward)
NFT_IP6_P=$(nft list table ip6 routeward)

set +e
env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy \
    curl --noproxy "" -sS --max-time 3 "http://${TARGET_IP}:853/dot" >/tmp/curl_p.out 2>&1
DOT_TCP_EXIT=$?
set -e

sleep 0.2
LOGS_P=$("${BIN}" ctl logs)

if echo "${DNS_P_CANARY}" | grep -q "RCODE=3 ANCOUNT=0" \
    && echo "${DNS_P_V6_UDP_A}" | grep -q "RCODE=0 ANCOUNT=1 IP=198.18." \
    && echo "${DNS_P_V6_UDP_AAAA}" | grep -q "RCODE=0 ANCOUNT=0" \
    && echo "${DNS_P_V6_TCP_A}" | grep -q "RCODE=0 ANCOUNT=1 IP=198.18." \
    && [[ "${DOT_TCP_EXIT}" -ne 0 ]] \
    && echo "${NFT_IP4_P}" | grep -q "udp dport 853 reject" \
    && echo "${NFT_IP6_P}" | grep -q "udp dport 53 redirect to :10853" \
    && echo "${NFT_IP6_P}" | grep -q "tcp dport 53 redirect to :10853" \
    && ! echo "${NFT_IP6_P}" | grep -q "udp dport 53 reject" \
    && echo "${NFT_IP6_P}" | grep -q "tcp dport 853 reject with tcp reset" \
    && echo "${LOGS_P}" | grep -q "Blocked DoH canary DNS query" \
    && echo "${LOGS_P}" | grep -q "Blocked encrypted DNS bypass (DoT TCP port 853)"; then
    echo "[PASS] Scenario (p): DoH canary NXDOMAIN, IPv6 UDP/TCP 53 intercepted cleanly, DoT 853 blocked"
else
    echo "[FAIL] Scenario (p)"
    echo "DNS_P_CANARY=${DNS_P_CANARY}"
    echo "DNS_P_V6_UDP_A=${DNS_P_V6_UDP_A}"
    echo "DNS_P_V6_UDP_AAAA=${DNS_P_V6_UDP_AAAA}"
    echo "DNS_P_V6_TCP_A=${DNS_P_V6_TCP_A}"
    echo "DOT_TCP_EXIT=${DOT_TCP_EXIT}"
    echo "NFT_IP4_P=${NFT_IP4_P}"
    echo "NFT_IP6_P=${NFT_IP6_P}"
    echo "LOGS_P=${LOGS_P}"
    kill -TERM "${DAEMON_M_PID}" 2>/dev/null || true
    exit 1
fi

kill -TERM "${DAEMON_M_PID}" 2>/dev/null || true
wait "${DAEMON_M_PID}" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Scenario (n): enableFakeIp=false - DNS query resolved via DNS-over-TCP
#               through SOCKS5 proxy, 0 direct UDP DNS packets
# ---------------------------------------------------------------------------
rm -f "${SOCKS_LOG}" /tmp/dns_hits.log /run/routeward/routeward.sock
cp /tmp/profile_dns_real.json /etc/routeward/active_profile.json
chmod 0600 /etc/routeward/active_profile.json

"${BIN}" daemon >/tmp/rw_daemon_n.out 2>&1 &
DAEMON_N_PID=$!
for _ in $(seq 1 30); do
    if [[ -S /run/routeward/routeward.sock ]]; then
        break
    fi
    sleep 0.1
done

"${BIN}" ctl start >/dev/null
wait_for_nft_table

DNS_N=$(python3 /workspace/tests/linux/mock_servers.py --dns-query "${TARGET_IP}" "real.routeward.test" 1)

if echo "${DNS_N}" | grep -q "RCODE=0 ANCOUNT=1 IP=${TARGET_IP}" \
    && grep -q "CONNECT ${TARGET_IP}:53" "${SOCKS_LOG}" \
    && grep -q "^TCP .* real.routeward.test 1" /tmp/dns_hits.log \
    && ! grep -q "^UDP " /tmp/dns_hits.log; then
    echo "[PASS] Scenario (n): enableFakeIp=false resolved real.routeward.test (${DNS_N}) via DNS-over-TCP through SOCKS5 with 0 direct UDP hits"
else
    echo "[FAIL] Scenario (n)"
    echo "DNS_N=${DNS_N}"
    cat "${SOCKS_LOG}" 2>/dev/null || true
    cat /tmp/dns_hits.log 2>/dev/null || true
    kill -TERM "${DAEMON_N_PID}" 2>/dev/null || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (q): kill -9 of daemon removes both ip and ip6 routeward tables
#               and restores direct DNS resolution immediately
# ---------------------------------------------------------------------------
kill -9 "${DAEMON_N_PID}"
wait "${DAEMON_N_PID}" 2>/dev/null || true
sleep 0.5

rm -f /tmp/dns_hits.log
DNS_Q=$(python3 /workspace/tests/linux/mock_servers.py --dns-query "${TARGET_IP}" "after-kill9.routeward.test" 1)

if ! nft list table ip routeward >/dev/null 2>&1 \
    && ! nft list table ip6 routeward >/dev/null 2>&1 \
    && echo "${DNS_Q}" | grep -q "RCODE=0 ANCOUNT=1 IP=${TARGET_IP}" \
    && grep -q "^UDP " /tmp/dns_hits.log; then
    echo "[PASS] Scenario (q): SIGKILL (kill -9) removed ip and ip6 routeward tables and restored direct UDP DNS resolution (${DNS_Q})"
else
    echo "[FAIL] Scenario (q)"
    echo "DNS_Q=${DNS_Q}"
    cat /tmp/dns_hits.log 2>/dev/null || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (r): AD bypass domain with silent internal DNS (and systemd-resolved
#               127.0.0.53 stub fallback) returns SERVFAIL and sends 0 queries
#               to simulated public upstreamDns (${TARGET_IP}:53)
# ---------------------------------------------------------------------------
SILENT_INTERNAL_DNS="10.200.1.2"
ip addr add "${SILENT_INTERNAL_DNS}/32" dev lo 2>/dev/null || true
mkdir -p /run/systemd/resolve
echo "nameserver 127.0.0.53" > /etc/resolv.conf
echo "nameserver ${SILENT_INTERNAL_DNS}" > /run/systemd/resolve/resolv.conf

rm -f "${SOCKS_LOG}" /tmp/dns_hits.log /tmp/https_443_hits.log /run/routeward/routeward.sock
cp /tmp/profile_dns_fakeip.json /etc/routeward/active_profile.json
chmod 0600 /etc/routeward/active_profile.json

"${BIN}" daemon >/tmp/rw_daemon_r.out 2>&1 &
DAEMON_R_PID=$!
for _ in $(seq 1 30); do
    if [[ -S /run/routeward/routeward.sock ]]; then
        break
    fi
    sleep 0.1
done

"${BIN}" ctl start >/dev/null
wait_for_nft_table

rm -f /tmp/dns_hits.log "${SOCKS_LOG}"
DNS_R=$(python3 /workspace/tests/linux/mock_servers.py --dns-query "${SILENT_INTERNAL_DNS}" "dc01.corp.contoso.com" 1)

if echo "${DNS_R}" | grep -q "RCODE=2 ANCOUNT=0" \
    && [[ ! -s /tmp/dns_hits.log ]] \
    && [[ ! -s "${SOCKS_LOG}" ]]; then
    echo "[PASS] Scenario (r): AD bypass domain with silent internal DNS returned SERVFAIL (${DNS_R}) with 0 queries to public upstreamDns"
else
    echo "[FAIL] Scenario (r)"
    echo "DNS_R=${DNS_R}"
    cat /tmp/dns_hits.log 2>/dev/null || true
    cat "${SOCKS_LOG}" 2>/dev/null || true
    kill -TERM "${DAEMON_R_PID}" 2>/dev/null || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (s): HTTPS connection to literal IP (${TARGET_IP}:443) with TLS SNI
#               matching a Proxy domain rule (*.routeward.test) is routed via
#               SOCKS5 with ATYP=domain
# ---------------------------------------------------------------------------
echo "nameserver ${TARGET_IP}" > /etc/resolv.conf
rm -f /run/systemd/resolve/resolv.conf "${SOCKS_LOG}" /tmp/https_443_hits.log

RESP_S=$(python3 /workspace/tests/linux/mock_servers.py --tls-sni-probe "${TARGET_IP}" "sni.routeward.test")
sleep 0.2

if [[ "${RESP_S}" == "HTTPS_SNI_OK" ]] \
    && grep -q "CONNECT sni.routeward.test:443" "${SOCKS_LOG}" \
    && grep -q "^TLS_443 " /tmp/https_443_hits.log; then
    echo "[PASS] Scenario (s): HTTPS connection to literal IP ${TARGET_IP}:443 with SNI sni.routeward.test routed via SOCKS5 (${RESP_S})"
else
    echo "[FAIL] Scenario (s)"
    echo "RESP_S=${RESP_S}"
    cat "${SOCKS_LOG}" 2>/dev/null || true
    cat /tmp/https_443_hits.log 2>/dev/null || true
    kill -TERM "${DAEMON_R_PID}" 2>/dev/null || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (t): Live change of securityPolicy via ctl replace-profile applied
#               atomically without restarting the engine (IPv4 & IPv6 853
#               unblocked while IPv6 53 interception remains active)
# ---------------------------------------------------------------------------
sed -e 's/"killSwitchEnabled": true/"killSwitchEnabled": false/' \
    -e 's/"blockEncryptedDnsBypass": true/"blockEncryptedDnsBypass": false/' \
    /tmp/profile_dns_fakeip.json > /tmp/profile_hot_reload.json

"${BIN}" ctl replace-profile --json-file /tmp/profile_hot_reload.json >/dev/null
sleep 0.2

NFT_IP4_T=$(nft list table ip routeward)
NFT_IP6_T=$(nft list table ip6 routeward)
LOGS_T=$("${BIN}" ctl logs)

if kill -0 "${DAEMON_R_PID}" 2>/dev/null \
    && ! echo "${NFT_IP4_T}" | grep -q "udp dport 853 reject" \
    && echo "${NFT_IP6_T}" | grep -q "udp dport 53 redirect to :10853" \
    && ! echo "${NFT_IP6_T}" | grep -q "tcp dport 853 reject" \
    && ! echo "${NFT_IP6_T}" | grep -q "udp dport 853 reject" \
    && echo "${LOGS_T}" | grep -q "securityPolicyChanged=true"; then
    echo "[PASS] Scenario (t): Live securityPolicy change applied atomically without restarting daemon (IPv4/IPv6 853 unblocked, IPv6 53 intercepted)"
else
    echo "[FAIL] Scenario (t)"
    echo "NFT_IP4_T=${NFT_IP4_T}"
    echo "NFT_IP6_T=${NFT_IP6_T}"
    echo "LOGS_T=${LOGS_T}"
    kill -TERM "${DAEMON_R_PID}" 2>/dev/null || true
    exit 1
fi

kill -TERM "${DAEMON_R_PID}" 2>/dev/null || true
wait "${DAEMON_R_PID}" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Scenario (u): End-to-end UDP exchange between client and UDP echo server
#               THROUGH socks5_udp_test_server using the engine's SOCKS5 UDP
#               client (Fake-IP reverse resolution to ATYP=0x03 domain)
# ---------------------------------------------------------------------------
UDP_TEST_SRV="/workspace/target/release/examples/socks5_udp_test_server"
rm -f /tmp/udp_srv_u.json /run/routeward/routeward.sock

"${UDP_TEST_SRV}" \
    --bind 127.0.0.1:1082 \
    --udp-echo-bind "${TARGET_IP}:19999" \
    --echo-prefix "UDP_ECHO_OK:" \
    --map-domain "udp.routeward.test=${TARGET_IP}" \
    --stats-file /tmp/udp_srv_u.json >/tmp/udp_srv_u.out 2>&1 &
UDP_SRV_U_PID=$!
sleep 0.3

cat > /tmp/profile_udp_u.json <<EOF
{
  "profileId": "00000000-0000-4000-8000-000000000201",
  "name": "LinuxUdpAssociateProfile",
  "version": "2026.1022.00",
  "enableLogging": true,
  "interceptionMode": "hybrid",
  "themeConfig": { "theme": "Drakul", "accent": "Default" },
  "securityPolicy": {
    "killSwitchEnabled": true,
    "blockUdpOnTcpOnlyProxy": true,
    "strictDnsNoLocalFallback": true,
    "blockEncryptedDnsBypass": true,
    "blockQuicUdp443": true,
    "unknownProcessAction": { "type": "block" }
  },
  "defaultAction": { "type": "proxy", "targetId": "socks-udp-1082" },
  "dnsConfig": {
    "enableFakeIp": true,
    "remoteDnsResolution": true,
    "fakeIpCidr": "198.18.0.0/15",
    "upstreamDns": "${TARGET_IP}:53",
    "bypassDomains": ["corp.contoso.com", "localhost", "*.local"]
  },
  "proxies": [
    {
      "id": "socks-udp-1082",
      "name": "SOCKS5 UDP Relay 1082",
      "protocol": "socks5",
      "host": "127.0.0.1",
      "port": 1082,
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
  "rules": []
}
EOF

cp /tmp/profile_udp_u.json /etc/routeward/active_profile.json
chmod 0600 /etc/routeward/active_profile.json

"${BIN}" daemon >/tmp/rw_daemon_u.out 2>&1 &
DAEMON_U_PID=$!
for _ in $(seq 1 30); do
    if [[ -S /run/routeward/routeward.sock ]]; then
        break
    fi
    sleep 0.1
done

"${BIN}" ctl start >/dev/null
wait_for_nft_table

DNS_U_OUT=$(python3 /workspace/tests/linux/mock_servers.py --dns-query "${TARGET_IP}" "udp.routeward.test" 1)
FAKE_IP_U=$(echo "${DNS_U_OUT}" | sed -n 's/.*IP=\([0-9.]*\) .*/\1/p')

UDP_U_RESP=$(python3 /workspace/tests/linux/mock_servers.py --socks5-udp-exchange 10808 "${FAKE_IP_U}" 19999 "hello-udp-42a")
STATS_U=$(cat /tmp/udp_srv_u.json 2>/dev/null || echo "{}")

if [[ "${UDP_U_RESP}" == "UDP_OK BODY=UDP_ECHO_OK:hello-udp-42a" ]] \
    && echo "${STATS_U}" | grep -q '"udp_associate_requests":1' \
    && echo "${STATS_U}" | grep -q '"udp_datagrams_relayed":1' \
    && echo "${STATS_U}" | grep -q '"udp_echo_received":1' \
    && echo "${STATS_U}" | grep -q '"last_udp_target":"Domain(udp.routeward.test:19999)"'; then
    echo "[PASS] Scenario (u): End-to-end UDP exchange via SOCKS5 UDP ASSOCIATE succeeded (${UDP_U_RESP}; ATYP=Domain(udp.routeward.test:19999))"
else
    echo "[FAIL] Scenario (u)"
    echo "DNS_U_OUT=${DNS_U_OUT} FAKE_IP_U=${FAKE_IP_U}"
    echo "UDP_U_RESP=${UDP_U_RESP}"
    echo "STATS_U=${STATS_U}"
    kill -TERM "${DAEMON_U_PID}" "${UDP_SRV_U_PID}" 2>/dev/null || true
    exit 1
fi

kill -TERM "${UDP_SRV_U_PID}" 2>/dev/null || true
wait "${UDP_SRV_U_PID}" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Scenario (v): Proxy refusing UDP ASSOCIATE (REP=0x07) + Kill-Switch =
#               blocked, 0 datagrams received by target, single WARN per node
# ---------------------------------------------------------------------------
rm -f /tmp/udp_srv_v.json
"${UDP_TEST_SRV}" \
    --bind 127.0.0.1:1083 \
    --udp-echo-bind "${TARGET_IP}:19998" \
    --disable-udp-associate \
    --stats-file /tmp/udp_srv_v.json >/tmp/udp_srv_v.out 2>&1 &
UDP_SRV_V_PID=$!
sleep 0.3

sed -e 's/"socks-udp-1082"/"socks-no-udp-1083"/g' \
    -e 's/"port": 1082/"port": 1083/' \
    /tmp/profile_udp_u.json > /tmp/profile_udp_v.json

"${BIN}" ctl replace-profile --json-file /tmp/profile_udp_v.json >/dev/null
sleep 0.2

set +e
UDP_V_RESP1=$(python3 /workspace/tests/linux/mock_servers.py --socks5-udp-exchange 10808 "${TARGET_IP}" 19998 "blocked-datagram-1")
UDP_V_EXIT1=$?
UDP_V_RESP2=$(python3 /workspace/tests/linux/mock_servers.py --socks5-udp-exchange 10808 "${TARGET_IP}" 19998 "blocked-datagram-2")
UDP_V_EXIT2=$?
set -e

STATS_V=$(cat /tmp/udp_srv_v.json 2>/dev/null || echo "{}")
LOGS_V=$("${BIN}" ctl logs)
WARN_COUNT_V=$(echo "${LOGS_V}" | grep -c 'REP=0x07 (Command not supported)' || true)

if [[ "${UDP_V_EXIT1}" -ne 0 ]] \
    && [[ "${UDP_V_EXIT2}" -ne 0 ]] \
    && echo "${STATS_V}" | grep -q '"udp_associate_refused":1' \
    && echo "${STATS_V}" | grep -q '"udp_echo_received":0' \
    && [[ "${WARN_COUNT_V}" -eq 1 ]]; then
    echo "[PASS] Scenario (v): Refused UDP ASSOCIATE (REP=0x07) enforced Kill-Switch (0 target datagrams, cached after 1st probe, single WARN)"
else
    echo "[FAIL] Scenario (v)"
    echo "UDP_V_EXIT1=${UDP_V_EXIT1} UDP_V_RESP1=${UDP_V_RESP1}"
    echo "UDP_V_EXIT2=${UDP_V_EXIT2} UDP_V_RESP2=${UDP_V_RESP2}"
    echo "STATS_V=${STATS_V}"
    echo "WARN_COUNT_V=${WARN_COUNT_V}"
    echo "LOGS_V=${LOGS_V}"
    kill -TERM "${DAEMON_U_PID}" "${UDP_SRV_V_PID}" 2>/dev/null || true
    exit 1
fi

kill -TERM "${UDP_SRV_V_PID}" 2>/dev/null || true
wait "${UDP_SRV_V_PID}" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Scenario (w): QUIC (UDP 443) rejected with ICMP Port Unreachable (client
#               error delay measured and displayed, 0 target datagrams);
#               LLMNR (UDP 5355) public FQDN blocked, local short name allowed
# ---------------------------------------------------------------------------
rm -f /tmp/udp_443_hits.log /tmp/llmnr_5355_hits.log

QUIC_W_OUT=$(python3 /workspace/tests/linux/mock_servers.py --quic-udp-probe "${TARGET_IP}" 443)
python3 /workspace/tests/linux/mock_servers.py --llmnr-query "${TARGET_IP}" "public.leak.example.com" >/dev/null
python3 /workspace/tests/linux/mock_servers.py --llmnr-query "${TARGET_IP}" "fileserver" >/dev/null
sleep 0.3

LOGS_W=$("${BIN}" ctl logs)

if echo "${QUIC_W_OUT}" | grep -Eq "QUIC_(REJECTED|ERROR) ERR=(ConnectionRefusedError|PermissionError:1)" \
    && [[ ! -s /tmp/udp_443_hits.log ]] \
    && grep -q "LLMNR_5355 .* fileserver" /tmp/llmnr_5355_hits.log \
    && ! grep -q "public.leak.example.com" /tmp/llmnr_5355_hits.log \
    && echo "${LOGS_W}" | grep -q "Blocked public FQDN .*public.leak.example.com.* on local name resolution protocol"; then
    echo "[PASS] Scenario (w): QUIC UDP 443 rejected (${QUIC_W_OUT}, 0 target datagrams); LLMNR public FQDN blocked and local short name allowed"
else
    echo "[FAIL] Scenario (w)"
    echo "QUIC_W_OUT=${QUIC_W_OUT}"
    cat /tmp/udp_443_hits.log 2>/dev/null || true
    cat /tmp/llmnr_5355_hits.log 2>/dev/null || true
    echo "LOGS_W=${LOGS_W}"
    kill -TERM "${DAEMON_U_PID}" 2>/dev/null || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (x): kill -9 of daemon - watchdog removes nftables rules so
#               UDP 443 and UDP 5355 (LLMNR) are no longer blocked
# ---------------------------------------------------------------------------
kill -9 "${DAEMON_U_PID}"
wait "${DAEMON_U_PID}" 2>/dev/null || true
sleep 0.5

rm -f /tmp/udp_443_hits.log /tmp/llmnr_5355_hits.log
python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'QUIC_AFTER_KILL9', ('${TARGET_IP}', 443)); s.close()"
python3 /workspace/tests/linux/mock_servers.py --llmnr-query "${TARGET_IP}" "after-kill9.example.com" >/dev/null
sleep 0.2

if ! nft list table ip routeward >/dev/null 2>&1 \
    && ! nft list table ip6 routeward >/dev/null 2>&1 \
    && grep -q "UDP_443 " /tmp/udp_443_hits.log \
    && grep -q "after-kill9.example.com" /tmp/llmnr_5355_hits.log; then
    echo "[PASS] Scenario (x): SIGKILL (kill -9) watchdog restored direct UDP 443 and UDP 5355 traffic immediately"
else
    echo "[FAIL] Scenario (x)"
    cat /tmp/udp_443_hits.log 2>/dev/null || true
    cat /tmp/llmnr_5355_hits.log 2>/dev/null || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (y): Ordinary UDP application (without SOCKS config) transparently
#               routed via TPROXY through socks5_udp_test_server
# ---------------------------------------------------------------------------
rm -f /tmp/udp_srv_y.json /tmp/udp_direct_hits.log /run/routeward/routeward.sock

"${UDP_TEST_SRV}" \
    --bind 127.0.0.1:1084 \
    --udp-echo-bind "${TARGET_IP}:19999" \
    --echo-prefix "UDP_ECHO_OK:" \
    --map-domain "udp-tproxy.routeward.test=${TARGET_IP}" \
    --stats-file /tmp/udp_srv_y.json >/tmp/udp_srv_y.out 2>&1 &
UDP_SRV_Y_PID=$!
sleep 0.3

cat > /tmp/profile_udp_tproxy.json <<EOF
{
  "profileId": "00000000-0000-4000-8000-000000000202",
  "name": "LinuxTransparentUdpTproxyProfile",
  "version": "2026.1022.00",
  "enableLogging": true,
  "interceptionMode": "hybrid",
  "themeConfig": { "theme": "Drakul", "accent": "Default" },
  "securityPolicy": {
    "killSwitchEnabled": true,
    "blockUdpOnTcpOnlyProxy": true,
    "strictDnsNoLocalFallback": true,
    "blockEncryptedDnsBypass": true,
    "blockQuicUdp443": true,
    "unknownProcessAction": { "type": "block" }
  },
  "defaultAction": { "type": "proxy", "targetId": "socks-udp-1084" },
  "dnsConfig": {
    "enableFakeIp": true,
    "remoteDnsResolution": true,
    "fakeIpCidr": "198.18.0.0/15",
    "upstreamDns": "${TARGET_IP}:53",
    "bypassDomains": ["corp.contoso.com", "localhost", "*.local"]
  },
  "proxies": [
    {
      "id": "socks-udp-1084",
      "name": "SOCKS5 UDP Relay 1084",
      "protocol": "socks5",
      "host": "127.0.0.1",
      "port": 1084,
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
      "id": "rule-udp-direct-19990",
      "name": "Direct UDP Port 19990",
      "enabled": true,
      "priority": 1,
      "processPatterns": [],
      "domainPatterns": [],
      "ipCidrs": [],
      "portRanges": [{ "start": 19990, "end": 19990 }],
      "protocol": "udp",
      "action": { "type": "direct" }
    }
  ]
}
EOF

cp /tmp/profile_udp_tproxy.json /etc/routeward/active_profile.json
chmod 0600 /etc/routeward/active_profile.json

"${BIN}" daemon >/tmp/rw_daemon_y.out 2>&1 &
DAEMON_Y_PID=$!
for _ in $(seq 1 30); do
    if [[ -S /run/routeward/routeward.sock ]]; then
        break
    fi
    sleep 0.1
done

"${BIN}" ctl start >/dev/null
wait_for_nft_table

UDP_Y_OUT=$(python3 /workspace/tests/linux/mock_servers.py --transparent-udp-send "${TARGET_IP}" 19999 "transparent-y")
STATS_Y=$(cat /tmp/udp_srv_y.json 2>/dev/null || echo "{}")

if [[ "${UDP_Y_OUT}" == "TRANSPARENT_UDP_OK FROM=${TARGET_IP}:19999 BODY=UDP_ECHO_OK:transparent-y" ]] \
    && echo "${STATS_Y}" | grep -q '"udp_associate_requests":1' \
    && echo "${STATS_Y}" | grep -q '"udp_datagrams_relayed":1' \
    && echo "${STATS_Y}" | grep -q '"udp_echo_received":1'; then
    echo "[PASS] Scenario (y): Ordinary UDP application transparently routed via TPROXY through SOCKS5 UDP ASSOCIATE (${UDP_Y_OUT})"
else
    echo "[FAIL] Scenario (y)"
    echo "UDP_Y_OUT=${UDP_Y_OUT}"
    echo "STATS_Y=${STATS_Y}"
    "${BIN}" ctl logs || true
    kill -TERM "${DAEMON_Y_PID}" "${UDP_SRV_Y_PID}" 2>/dev/null || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (z): Transparent UDP toward a Fake-IP destination transmits the
#               domain name (ATYP=0x03) to the SOCKS5 proxy and replies from
#               the Fake-IP
# ---------------------------------------------------------------------------
DNS_Z_OUT=$(python3 /workspace/tests/linux/mock_servers.py --dns-query "${TARGET_IP}" "udp-tproxy.routeward.test" 1)
FAKE_IP_Z=$(echo "${DNS_Z_OUT}" | sed -n 's/.*IP=\([0-9.]*\) .*/\1/p')

UDP_Z_OUT=$(python3 /workspace/tests/linux/mock_servers.py --transparent-udp-send "${FAKE_IP_Z}" 19999 "fakeip-tproxy-z")
STATS_Z=$(cat /tmp/udp_srv_y.json 2>/dev/null || echo "{}")

if [[ "${UDP_Z_OUT}" == "TRANSPARENT_UDP_OK FROM=${FAKE_IP_Z}:19999 BODY=UDP_ECHO_OK:fakeip-tproxy-z" ]] \
    && echo "${STATS_Z}" | grep -q '"udp_datagrams_relayed":2' \
    && echo "${STATS_Z}" | grep -q '"last_udp_target":"Domain(udp-tproxy.routeward.test:19999)"'; then
    echo "[PASS] Scenario (z): Transparent UDP to Fake-IP ${FAKE_IP_Z}:19999 transmitted ATYP=0x03 Domain(udp-tproxy.routeward.test:19999) and replied from Fake-IP"
else
    echo "[FAIL] Scenario (z)"
    echo "DNS_Z_OUT=${DNS_Z_OUT} FAKE_IP_Z=${FAKE_IP_Z}"
    echo "UDP_Z_OUT=${UDP_Z_OUT}"
    echo "STATS_Z=${STATS_Z}"
    "${BIN}" ctl logs || true
    kill -TERM "${DAEMON_Y_PID}" "${UDP_SRV_Y_PID}" 2>/dev/null || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (aa): Single UDP socket sending to two destinations governed by
#                two different rules (Proxy port 19999 vs Direct port 19990)
# ---------------------------------------------------------------------------
rm -f /tmp/udp_direct_hits.log
DUAL_AA_OUT=$(python3 /workspace/tests/linux/mock_servers.py --transparent-udp-dual-send "${TARGET_IP}" 19999 "${TARGET_IP}" 19990 "dual-42b")
STATS_AA=$(cat /tmp/udp_srv_y.json 2>/dev/null || echo "{}")

if echo "${DUAL_AA_OUT}" | grep -q "R1=${TARGET_IP}:19999:UDP_ECHO_OK:dual-42b-via-proxy" \
    && echo "${DUAL_AA_OUT}" | grep -q "R2=${TARGET_IP}:19990:DIRECT_ECHO_OK:dual-42b-via-direct" \
    && echo "${STATS_AA}" | grep -q '"udp_datagrams_relayed":3' \
    && grep -q "dual-42b-via-direct" /tmp/udp_direct_hits.log; then
    echo "[PASS] Scenario (aa): Single UDP socket routed 1st datagram via Proxy and 2nd datagram via Direct (${DUAL_AA_OUT})"
else
    echo "[FAIL] Scenario (aa)"
    echo "DUAL_AA_OUT=${DUAL_AA_OUT}"
    echo "STATS_AA=${STATS_AA}"
    cat /tmp/udp_direct_hits.log 2>/dev/null || true
    "${BIN}" ctl logs || true
    kill -TERM "${DAEMON_Y_PID}" "${UDP_SRV_Y_PID}" 2>/dev/null || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (ab): Transparent Direct UDP with process attribution + LLMNR
#                forwarded via TPROXY preserving client source port
# ---------------------------------------------------------------------------
rm -f /tmp/llmnr_5355_hits.log
LLMNR_AB_OUT=$(python3 /workspace/tests/linux/mock_servers.py --llmnr-query "${TARGET_IP}" "fileserver")
LLMNR_AB_PORT=$(echo "${LLMNR_AB_OUT}" | sed -n 's/.*SRC_PORT=\([0-9]*\).*/\1/p')
sleep 0.2

STATE_AB=$("${BIN}" ctl state)
LOGS_AB=$("${BIN}" ctl logs)

if echo "${LOGS_AB}" | grep -Eq 'Routed UDP .*python3(\.[0-9]+)?.*-> 10\.200\.1\.1:19990 .*via DIRECT' \
    && echo "${STATE_AB}" | grep -q '"routeLabel": "DIRECT"' \
    && grep -q "LLMNR_5355 .*:.*${LLMNR_AB_PORT} fileserver" /tmp/llmnr_5355_hits.log; then
    echo "[PASS] Scenario (ab): Transparent Direct UDP attributed to python3 and TPROXY LLMNR preserved source port ${LLMNR_AB_PORT}"
else
    echo "[FAIL] Scenario (ab)"
    echo "LLMNR_AB_OUT=${LLMNR_AB_OUT} LLMNR_AB_PORT=${LLMNR_AB_PORT}"
    cat /tmp/llmnr_5355_hits.log 2>/dev/null || true
    echo "LOGS_AB=${LOGS_AB}"
    kill -TERM "${DAEMON_Y_PID}" "${UDP_SRV_Y_PID}" 2>/dev/null || true
    exit 1
fi

kill -TERM "${UDP_SRV_Y_PID}" 2>/dev/null || true
wait "${UDP_SRV_Y_PID}" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Scenario (ac): Transparent UDP with proxy refusing UDP ASSOCIATE (REP=0x07)
#                + Kill-Switch = blocked (0 target datagrams)
# ---------------------------------------------------------------------------
rm -f /tmp/udp_srv_ac.json
"${UDP_TEST_SRV}" \
    --bind 127.0.0.1:1085 \
    --udp-echo-bind "${TARGET_IP}:19997" \
    --disable-udp-associate \
    --stats-file /tmp/udp_srv_ac.json >/tmp/udp_srv_ac.out 2>&1 &
UDP_SRV_AC_PID=$!
sleep 0.3

sed -e 's/"socks-udp-1084"/"socks-no-udp-1085"/g' \
    -e 's/"port": 1084/"port": 1085/' \
    /tmp/profile_udp_tproxy.json > /tmp/profile_udp_ac.json

"${BIN}" ctl replace-profile --json-file /tmp/profile_udp_ac.json >/dev/null
sleep 0.2

set +e
UDP_AC_OUT=$(python3 /workspace/tests/linux/mock_servers.py --transparent-udp-send "${TARGET_IP}" 19997 "blocked-tproxy-ac")
UDP_AC_EXIT=$?
set -e

STATS_AC=$(cat /tmp/udp_srv_ac.json 2>/dev/null || echo "{}")
LOGS_AC=$("${BIN}" ctl logs)

if [[ "${UDP_AC_EXIT}" -ne 0 ]] \
    && [[ "${UDP_AC_OUT}" == "TRANSPARENT_UDP_TIMEOUT" ]] \
    && echo "${STATS_AC}" | grep -q '"udp_associate_refused":1' \
    && echo "${STATS_AC}" | grep -q '"udp_echo_received":0' \
    && echo "${LOGS_AC}" | grep -Eq "Kill-Switch blocked UDP|Blocked UDP"; then
    echo "[PASS] Scenario (ac): Transparent UDP with proxy refusing UDP ASSOCIATE (REP=0x07) + Kill-Switch blocked datagram (0 target datagrams)"
else
    echo "[FAIL] Scenario (ac)"
    echo "UDP_AC_EXIT=${UDP_AC_EXIT} UDP_AC_OUT=${UDP_AC_OUT}"
    echo "STATS_AC=${STATS_AC}"
    echo "LOGS_AC=${LOGS_AC}"
    kill -TERM "${DAEMON_Y_PID}" "${UDP_SRV_AC_PID}" 2>/dev/null || true
    exit 1
fi

kill -TERM "${UDP_SRV_AC_PID}" 2>/dev/null || true
wait "${UDP_SRV_AC_PID}" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Scenario (ad): kill -9 of daemon - watchdog removes nftables tables,
#                ip rule (priority 10810), and local route (table 100),
#                restoring direct UDP immediately
# ---------------------------------------------------------------------------
kill -9 "${DAEMON_Y_PID}"
wait "${DAEMON_Y_PID}" 2>/dev/null || true
sleep 0.5

RULE_AD=$(ip rule show | grep "10810:" || true)
ROUTE_AD=$(ip route show table 100 2>/dev/null || true)
UDP_AD_OUT=$(python3 /workspace/tests/linux/mock_servers.py --transparent-udp-send "${TARGET_IP}" 19990 "after-kill9-42b")

if ! nft list table ip routeward >/dev/null 2>&1 \
    && ! nft list table ip6 routeward >/dev/null 2>&1 \
    && [[ -z "${RULE_AD}" ]] \
    && [[ -z "${ROUTE_AD}" ]] \
    && [[ "${UDP_AD_OUT}" == "TRANSPARENT_UDP_OK FROM=${TARGET_IP}:19990 BODY=DIRECT_ECHO_OK:after-kill9-42b" ]]; then
    echo "[PASS] Scenario (ad): SIGKILL (kill -9) watchdog removed nft tables, ip rule 10810, and route table 100, restoring direct UDP (${UDP_AD_OUT})"
else
    echo "[FAIL] Scenario (ad)"
    echo "RULE_AD=${RULE_AD}"
    echo "ROUTE_AD=${ROUTE_AD}"
    echo "UDP_AD_OUT=${UDP_AD_OUT}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (ae): Orphaned ip rule and route table 100 removed by
#                routeward cleanup when no daemon is active
# ---------------------------------------------------------------------------
rm -f /run/routeward/routeward.sock
ip rule add fwmark 21080 lookup 100 priority 10810
ip route add local 0.0.0.0/0 dev lo table 100
nft add table ip routeward

CLEANUP_AE_OUT=$("${BIN}" cleanup)
RULE_AE=$(ip rule show | grep "10810:" || true)
ROUTE_AE=$(ip route show table 100 2>/dev/null || true)

if [[ -z "${RULE_AE}" ]] \
    && [[ -z "${ROUTE_AE}" ]] \
    && ! nft list table ip routeward >/dev/null 2>&1; then
    echo "[PASS] Scenario (ae): routeward cleanup removed orphaned ip rule 10810, route table 100, and nft table (${CLEANUP_AE_OUT})"
else
    echo "[FAIL] Scenario (ae)"
    echo "CLEANUP_AE_OUT=${CLEANUP_AE_OUT}"
    echo "RULE_AE=${RULE_AE}"
    echo "ROUTE_AE=${ROUTE_AE}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (af): Pre-existing routing table or ip rule conflict detected at
#                startup - refuses to start without overwriting third-party route
# ---------------------------------------------------------------------------
ip route add 198.51.100.0/24 dev lo table 100

"${BIN}" daemon >/tmp/rw_daemon_af.out 2>&1 &
DAEMON_AF_PID=$!
for _ in $(seq 1 30); do
    if [[ -S /run/routeward/routeward.sock ]]; then
        break
    fi
    sleep 0.1
done

set +e
START_AF_OUT=$("${BIN}" ctl start 2>&1)
START_AF_EXIT=$?
set -e

ROUTE_AF_PRESERVED=$(ip route show table 100 2>/dev/null || true)
ip route del 198.51.100.0/24 dev lo table 100 2>/dev/null || true
kill -TERM "${DAEMON_AF_PID}" 2>/dev/null || true
wait "${DAEMON_AF_PID}" 2>/dev/null || true

if [[ "${START_AF_EXIT}" -ne 0 ]] \
    && echo "${START_AF_OUT}" | grep -Eq "tproxy_conflict|TPROXY|table 100" \
    && echo "${ROUTE_AF_PRESERVED}" | grep -q "198.51.100.0/24"; then
    echo "[PASS] Scenario (af): Pre-existing route in table 100 detected at startup; engine refused to start and preserved third-party route"
else
    echo "[FAIL] Scenario (af)"
    echo "START_AF_EXIT=${START_AF_EXIT} START_AF_OUT=${START_AF_OUT}"
    echo "ROUTE_AF_PRESERVED=${ROUTE_AF_PRESERVED}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (ag): Transparent Direct UDP toward a Fake-IP destination resolves
#                the real IPv4 address (10.200.1.1), delivers the datagram to
#                the real server, and reinjects the reply from the Fake-IP
# ---------------------------------------------------------------------------
rm -f /run/routeward/routeward.sock /tmp/udp_direct_hits.log
cp /tmp/profile_udp_tproxy.json /etc/routeward/active_profile.json
chmod 0600 /etc/routeward/active_profile.json

"${BIN}" daemon >/tmp/rw_daemon_ag.out 2>&1 &
DAEMON_AG_PID=$!
for _ in $(seq 1 30); do
    if [[ -S /run/routeward/routeward.sock ]]; then
        break
    fi
    sleep 0.1
done

"${BIN}" ctl start >/dev/null
wait_for_nft_table

DNS_AG_OUT=$(python3 /workspace/tests/linux/mock_servers.py --dns-query "${TARGET_IP}" "direct-fakeip-udp.routeward.test" 1)
FAKE_IP_AG=$(echo "${DNS_AG_OUT}" | sed -n 's/.*IP=\([0-9.]*\) .*/\1/p')

UDP_AG_OUT=$(python3 /workspace/tests/linux/mock_servers.py --transparent-udp-send "${FAKE_IP_AG}" 19990 "direct-fakeip-42b1")
sleep 0.2
LOGS_AG=$("${BIN}" ctl logs)

kill -TERM "${DAEMON_AG_PID}" 2>/dev/null || true
wait "${DAEMON_AG_PID}" 2>/dev/null || true

if [[ "${FAKE_IP_AG}" == 198.18.* || "${FAKE_IP_AG}" == 198.19.* ]] \
    && [[ "${UDP_AG_OUT}" == "TRANSPARENT_UDP_OK FROM=${FAKE_IP_AG}:19990 BODY=DIRECT_ECHO_OK:direct-fakeip-42b1" ]] \
    && grep -q "direct-fakeip-42b1" /tmp/udp_direct_hits.log \
    && echo "${LOGS_AG}" | grep -Eq -- "-> ${FAKE_IP_AG}:19990 \(domain=Some\(.*direct-fakeip-udp\.routeward\.test.*\), realIp=${TARGET_IP}\) via DIRECT"; then
    echo "[PASS] Scenario (ag): Transparent Direct UDP to Fake-IP ${FAKE_IP_AG}:19990 delivered to real IP ${TARGET_IP}:19990 and replied from ${FAKE_IP_AG}:19990"
else
    echo "[FAIL] Scenario (ag)"
    echo "DNS_AG_OUT=${DNS_AG_OUT} FAKE_IP_AG=${FAKE_IP_AG}"
    echo "UDP_AG_OUT=${UDP_AG_OUT}"
    cat /tmp/udp_direct_hits.log 2>/dev/null || true
    echo "LOGS_AG=${LOGS_AG}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (ah): Transparent IPv6 TCP connection intercepted via table ip6
#                routeward and routed through SOCKS5 (ATYP=0x04 IPv6)
# ---------------------------------------------------------------------------
rm -f "${SOCKS_LOG}" /tmp/http_target_hits.log /run/routeward/routeward.sock
cp /tmp/profile_proxy.json /etc/routeward/active_profile.json
chmod 0600 /etc/routeward/active_profile.json

"${BIN}" daemon >/tmp/rw_daemon_ah.out 2>&1 &
DAEMON_AH_PID=$!
for _ in $(seq 1 30); do
    if [[ -S /run/routeward/routeward.sock ]]; then
        break
    fi
    sleep 0.1
done

"${BIN}" ctl start >/dev/null
wait_for_nft_table

CURL_AH_OUT=$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy \
    curl -6 --noproxy "" -sS --max-time 5 "http://[${TARGET_IPV6}]:${TARGET_PORT}/v6-proxy-test")
sleep 0.2
LOGS_AH=$("${BIN}" ctl logs)

kill -TERM "${DAEMON_AH_PID}" 2>/dev/null || true
wait "${DAEMON_AH_PID}" 2>/dev/null || true

if [[ "${CURL_AH_OUT}" == "ROUTEWARD_OK" ]] \
    && grep -q "CONNECT ${TARGET_IPV6}:${TARGET_PORT}" "${SOCKS_LOG}" \
    && grep -q "GET /v6-proxy-test" /tmp/http_target_hits.log \
    && echo "${LOGS_AH}" | grep -q "via Local SOCKS5 Gateway"; then
    echo "[PASS] Scenario (ah): Transparent IPv6 TCP connection intercepted via table ip6 and routed via SOCKS5 (${TARGET_IPV6}:${TARGET_PORT})"
else
    echo "[FAIL] Scenario (ah)"
    echo "CURL_AH_OUT=${CURL_AH_OUT}"
    cat "${SOCKS_LOG}" 2>/dev/null || true
    cat /tmp/http_target_hits.log 2>/dev/null || true
    echo "LOGS_AH=${LOGS_AH}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenarios (ai) & (aj): Transparent IPv6 Direct UDP (TPROXY ip6 -> port 19990)
#                        and Transparent IPv6 Proxy UDP (TPROXY ip6 -> SOCKS5 ATYP=0x04 -> port 19999)
# ---------------------------------------------------------------------------
rm -f /tmp/udp_srv_aj.json /tmp/udp_direct_hits.log /run/routeward/routeward.sock

"${UDP_TEST_SRV}" \
    --bind 127.0.0.1:1084 \
    --udp-echo-bind "[${TARGET_IPV6}]:19999" \
    --echo-prefix "UDP6_ECHO_OK:" \
    --stats-file /tmp/udp_srv_aj.json >/tmp/udp_srv_aj.out 2>&1 &
UDP_SRV_AJ_PID=$!
sleep 0.3

cp /tmp/profile_udp_tproxy.json /etc/routeward/active_profile.json
chmod 0600 /etc/routeward/active_profile.json

"${BIN}" daemon >/tmp/rw_daemon_aiaj.out 2>&1 &
DAEMON_AIAJ_PID=$!
for _ in $(seq 1 30); do
    if [[ -S /run/routeward/routeward.sock ]]; then
        break
    fi
    sleep 0.1
done

"${BIN}" ctl start >/dev/null
wait_for_nft_table

UDP_AI_OUT=$(python3 /workspace/tests/linux/mock_servers.py --transparent-udp6-send "${TARGET_IPV6}" 19990 "transparent-v6-direct")
UDP_AJ_OUT=$(python3 /workspace/tests/linux/mock_servers.py --transparent-udp6-send "${TARGET_IPV6}" 19999 "transparent-v6-proxy")
sleep 0.2
STATS_AJ=$(cat /tmp/udp_srv_aj.json 2>/dev/null || echo "{}")
LOGS_AIAJ=$("${BIN}" ctl logs)

kill -TERM "${DAEMON_AIAJ_PID}" "${UDP_SRV_AJ_PID}" 2>/dev/null || true
wait "${DAEMON_AIAJ_PID}" 2>/dev/null || true
wait "${UDP_SRV_AJ_PID}" 2>/dev/null || true

if [[ "${UDP_AI_OUT}" == "TRANSPARENT_UDP6_OK FROM=[${TARGET_IPV6}]:19990 BODY=DIRECT_ECHO_OK:transparent-v6-direct" ]] \
    && grep -q "UDP_DIRECT_V6" /tmp/udp_direct_hits.log \
    && grep -q "transparent-v6-direct" /tmp/udp_direct_hits.log \
    && echo "${LOGS_AIAJ}" | grep -Eq "${TARGET_IPV6}.*:19990.*via DIRECT"; then
    echo "[PASS] Scenario (ai): Transparent IPv6 Direct UDP routed via TPROXY ip6 and replied from [${TARGET_IPV6}]:19990"
else
    echo "[FAIL] Scenario (ai)"
    echo "UDP_AI_OUT=${UDP_AI_OUT}"
    cat /tmp/udp_direct_hits.log 2>/dev/null || true
    echo "LOGS_AIAJ=${LOGS_AIAJ}"
    exit 1
fi

if [[ "${UDP_AJ_OUT}" == "TRANSPARENT_UDP6_OK FROM=[${TARGET_IPV6}]:19999 BODY=UDP6_ECHO_OK:transparent-v6-proxy" ]] \
    && echo "${STATS_AJ}" | grep -q '"udp_associate_requests":1' \
    && echo "${STATS_AJ}" | grep -q '"udp_datagrams_relayed":1' \
    && echo "${STATS_AJ}" | grep -q '"udp_echo_received":1' \
    && echo "${STATS_AJ}" | grep -q "\"last_udp_target\":\"Ipv6(${TARGET_IPV6}:19999)\""; then
    echo "[PASS] Scenario (aj): Transparent IPv6 UDP routed via TPROXY ip6 through SOCKS5 UDP ASSOCIATE (ATYP=0x04)"
else
    echo "[FAIL] Scenario (aj)"
    echo "UDP_AJ_OUT=${UDP_AJ_OUT}"
    echo "STATS_AJ=${STATS_AJ}"
    echo "LOGS_AIAJ=${LOGS_AIAJ}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Scenario (ak): a DNS server process (dnsmasq, in the default list) running as a dedicated
#                unprivileged user in the same network namespace as the daemon gets real
#                DNS answers: its upstream query is not redirected to the Fake-IP resolver,
#                the mock upstream is hit and the domain never enters the Fake-IP table.
#                The same profile with "!dnsmasq" (live reload, no restart) is the control:
#                the very same query is then answered with a Fake-IP.
# ---------------------------------------------------------------------------
CAP_EFF_HEX=$(awk '/^CapEff:/ {print $2}' /proc/self/status)
if (( (0x${CAP_EFF_HEX} >> 19) & 1 )); then
DNSMASQ_UID=$(id -u rwdns)
rm -f /tmp/dns_hits.log /run/routeward/routeward.sock /tmp/dnsmasq_ak.pid

dnsmasq --conf-file=/dev/null --keep-in-foreground --no-resolv --no-hosts --cache-size=0 \
    --listen-address=127.0.0.1 --bind-interfaces --port=53 --server="${TARGET_IP}" \
    --user=rwdns --group=rwdns --pid-file=/tmp/dnsmasq_ak.pid >/tmp/rw_dnsmasq_ak.out 2>&1 &
DNSMASQ_AK_PID=$!
for _ in $(seq 1 30); do
    if python3 /workspace/tests/linux/mock_servers.py --dns-query 127.0.0.1 "warmup.routeward.test" 1 >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

sed -e 's|"bypassDomains": \[\(.*\)\]|"bypassDomains": [\1],\n    "dnsServerProcesses": ["!dnsmasq"]|' \
    /tmp/profile_dns_fakeip.json > /tmp/profile_dns_server_removed.json
grep -q '"dnsServerProcesses": \["!dnsmasq"\]' /tmp/profile_dns_server_removed.json

cp /tmp/profile_dns_fakeip.json /etc/routeward/active_profile.json
chmod 0600 /etc/routeward/active_profile.json

"${BIN}" daemon >/tmp/rw_daemon_ak.out 2>&1 &
DAEMON_AK_PID=$!
for _ in $(seq 1 30); do
    if [[ -S /run/routeward/routeward.sock ]]; then
        break
    fi
    sleep 0.1
done

"${BIN}" ctl start >/dev/null
wait_for_nft_table

rm -f /tmp/dns_hits.log
DNS_AK=$(python3 /workspace/tests/linux/mock_servers.py --dns-query 127.0.0.1 "exempt.routeward.test" 1)
FAKE_IPS_AK=$("${BIN}" ctl fake-ips)
NFT_SET_AK=$(nft list set ip routeward dns_server_uids 2>&1 || true)
NFT_BLOCK_SET_AK=$(nft list set ip routeward dns_server_block_uids 2>&1 || true)
LOGS_AK=$("${BIN}" ctl logs)

if echo "${DNS_AK}" | grep -q "RCODE=0 ANCOUNT=1 IP=${TARGET_IP}" \
    && ! echo "${DNS_AK}" | grep -q "IP=198\.1[89]\." \
    && grep -q "^UDP .* exempt.routeward.test 1" /tmp/dns_hits.log \
    && ! echo "${FAKE_IPS_AK}" | grep -q "exempt.routeward.test" \
    && echo "${NFT_SET_AK}" | grep -Eq "elements = \{ ${DNSMASQ_UID} \}" \
    && ! echo "${NFT_BLOCK_SET_AK}" | grep -q "elements" \
    && echo "${LOGS_AK}" | grep -q "Exempting DNS server process dnsmasq"; then
    echo "[PASS] Scenario (ak): dnsmasq as uid ${DNSMASQ_UID} exempt from Fake-IP (${DNS_AK}; mock upstream hit; no Fake-IP entry)"
else
    echo "[FAIL] Scenario (ak): exemption"
    echo "DNS_AK=${DNS_AK}"
    cat /tmp/dns_hits.log 2>/dev/null || true
    echo "FAKE_IPS_AK=${FAKE_IPS_AK}"
    echo "NFT_SET_AK=${NFT_SET_AK}"
    echo "NFT_BLOCK_SET_AK=${NFT_BLOCK_SET_AK}"
    echo "LOGS_AK=${LOGS_AK}"
    kill -TERM "${DAEMON_AK_PID}" "${DNSMASQ_AK_PID}" 2>/dev/null || true
    exit 1
fi

# Control: removing the default with "!dnsmasq" through a live profile reload must send the same
# upstream query to the Fake-IP resolver, which proves the test above is not passing by accident.
"${BIN}" ctl replace-profile --json-file /tmp/profile_dns_server_removed.json >/dev/null
sleep 0.3

rm -f /tmp/dns_hits.log
DNS_AK_CTRL=$(python3 /workspace/tests/linux/mock_servers.py --dns-query 127.0.0.1 "control.routeward.test" 1)
FAKE_IPS_AK_CTRL=$("${BIN}" ctl fake-ips)
NFT_SET_AK_CTRL=$(nft list set ip routeward dns_server_uids 2>&1 || true)

kill -TERM "${DAEMON_AK_PID}" "${DNSMASQ_AK_PID}" 2>/dev/null || true
wait "${DAEMON_AK_PID}" 2>/dev/null || true
wait "${DNSMASQ_AK_PID}" 2>/dev/null || true

if echo "${DNS_AK_CTRL}" | grep -Eq "RCODE=0 ANCOUNT=1 IP=198\.1[89]\.[0-9]+\.[0-9]+" \
    && echo "${FAKE_IPS_AK_CTRL}" | grep -q '"domain": "control.routeward.test"' \
    && ! echo "${NFT_SET_AK_CTRL}" | grep -q "elements"; then
    echo "[PASS] Scenario (ak): control with !dnsmasq after live reload got a Fake-IP (${DNS_AK_CTRL})"
else
    echo "[FAIL] Scenario (ak): control"
    echo "DNS_AK_CTRL=${DNS_AK_CTRL}"
    echo "FAKE_IPS_AK_CTRL=${FAKE_IPS_AK_CTRL}"
    echo "NFT_SET_AK_CTRL=${NFT_SET_AK_CTRL}"
    exit 1
fi
else
    # The daemon recognises a DNS server of another user through /proc/<pid>/exe, which the
    # kernel only exposes to root with CAP_SYS_PTRACE (the systemd unit keeps it). Plain
    # `docker run --cap-add NET_ADMIN` does not grant it; CI runs --privileged.
    echo "[SKIP] Scenario (ak): needs CAP_SYS_PTRACE (docker run --cap-add NET_ADMIN --cap-add SYS_PTRACE)"
fi

cp /tmp/resolv.conf.bak /etc/resolv.conf 2>/dev/null || true
kill "${MOCK_PID}" 2>/dev/null || true

echo "=== ALL 41 LINUX CONTAINER SCENARIOS PASSED ==="
