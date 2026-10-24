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
# Scenario (l): Kill-Switch (killSwitchEnabled=true) — SOCKS5 server stopped,
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
# Scenario (m): Fake-IP end-to-end — DNS query returns IP in 198.18.0.0/15
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
# Scenario (p): blockEncryptedDnsBypass=true — DoH canary returns NXDOMAIN,
#               outbound port 853 (TCP & UDP) and IPv6 53/853 are blocked
# ---------------------------------------------------------------------------
DNS_P_CANARY=$(python3 /workspace/tests/linux/mock_servers.py --dns-query "${TARGET_IP}" "use-application-dns.net" 1)
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
    && [[ "${DOT_TCP_EXIT}" -ne 0 ]] \
    && echo "${NFT_IP4_P}" | grep -q "udp dport 853 reject" \
    && echo "${NFT_IP6_P}" | grep -q "udp dport 53 reject" \
    && echo "${NFT_IP6_P}" | grep -q "tcp dport 853 reject with tcp reset" \
    && echo "${LOGS_P}" | grep -q "Blocked DoH canary DNS query" \
    && echo "${LOGS_P}" | grep -q "Blocked encrypted DNS bypass (DoT TCP port 853)"; then
    echo "[PASS] Scenario (p): DoH canary returned NXDOMAIN, DoT 853 TCP/UDP and IPv6 53/853 blocked"
else
    echo "[FAIL] Scenario (p)"
    echo "DNS_P_CANARY=${DNS_P_CANARY}"
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
# Scenario (n): enableFakeIp=false — DNS query resolved via DNS-over-TCP
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

cp /tmp/resolv.conf.bak /etc/resolv.conf 2>/dev/null || true
kill "${MOCK_PID}" 2>/dev/null || true

echo "=== ALL 17 LINUX CONTAINER SCENARIOS PASSED ==="
