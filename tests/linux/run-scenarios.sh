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
rm -f "${SOCKS_LOG}" /workspace/logs/RouteWard_*.log
"${BIN}" -p /tmp/profile_proxy.json run >/tmp/rw_a.out 2>&1 &
RW_PID=$!
wait_for_nft_table

RESP_A=$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy \
    curl --noproxy "" -sS --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/scenario-a")
kill -INT "${RW_PID}" || true
wait "${RW_PID}" || true

LOG_FILE=$(ls -1 /workspace/logs/RouteWard_*.log | head -n 1)
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
rm -f "${SOCKS_LOG}" /workspace/logs/RouteWard_*.log
"${BIN}" -p /tmp/profile_direct.json run >/tmp/rw_b.out 2>&1 &
RW_PID=$!
wait_for_nft_table

RESP_B=$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy \
    curl --noproxy "" -sS --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/scenario-b")
kill -INT "${RW_PID}" || true
wait "${RW_PID}" || true

LOG_FILE=$(ls -1 /workspace/logs/RouteWard_*.log | head -n 1)
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
rm -f "${SOCKS_LOG}" /workspace/logs/RouteWard_*.log
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

LOG_FILE=$(ls -1 /workspace/logs/RouteWard_*.log | head -n 1)
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

kill "${MOCK_PID}" 2>/dev/null || true
echo "=== ALL 6 LINUX CONTAINER SCENARIOS PASSED ==="
