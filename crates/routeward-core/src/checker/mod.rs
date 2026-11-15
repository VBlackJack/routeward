/*
 * Copyright 2026 Julien Bombled
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::config::{ProxyNode, ProxyProtocol, SystemConstants};
use crate::proxy::ProxyConnector;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const EXIT_IP_JSON_KEY: &str = "ip";
const EMPTY_IPV4_HOST: &str = "0.0.0.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyHealthReport {
    pub proxy_id: String,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub udp_supported: bool,
    pub exit_ip: Option<String>,
    pub error_detail: Option<String>,
}

pub struct ProxyChecker;

impl ProxyChecker {
    pub async fn test_proxy(node: &ProxyNode, constants: &SystemConstants) -> ProxyHealthReport {
        let probe_timeout = Duration::from_millis(constants.checker.probe_timeout_ms);
        let addr = format!("{}:{}", node.host, node.port);
        let start = Instant::now();

        let tcp_result = timeout(probe_timeout, TcpStream::connect(&addr)).await;
        let mut stream = match tcp_result {
            Ok(Ok(s)) => s,
            Ok(Err(io_err)) => {
                return ProxyHealthReport {
                    proxy_id: node.id.clone(),
                    reachable: false,
                    latency_ms: None,
                    udp_supported: false,
                    exit_ip: None,
                    error_detail: Some(io_err.to_string()),
                };
            }
            Err(_) => {
                return ProxyHealthReport {
                    proxy_id: node.id.clone(),
                    reachable: false,
                    latency_ms: None,
                    udp_supported: false,
                    exit_ip: None,
                    error_detail: None,
                };
            }
        };

        let tcp_latency = start.elapsed().as_millis().max(1) as u64;

        let exit_ip = Self::try_resolve_exit_ip(&mut stream, node, constants).await;
        let udp_supported = if node.udp_enabled && node.protocol == ProxyProtocol::Socks5 {
            Self::probe_socks5_udp(node, constants)
                .await
                .unwrap_or(false)
        } else {
            false
        };

        ProxyHealthReport {
            proxy_id: node.id.clone(),
            reachable: true,
            latency_ms: Some(tcp_latency),
            udp_supported,
            exit_ip,
            error_detail: None,
        }
    }

    async fn try_resolve_exit_ip(
        stream: &mut TcpStream,
        node: &ProxyNode,
        constants: &SystemConstants,
    ) -> Option<String> {
        let chk = &constants.checker;
        let probe_timeout = Duration::from_millis(chk.probe_timeout_ms);

        let handshake = timeout(
            probe_timeout,
            ProxyConnector::negotiate_hop(
                stream,
                node,
                &chk.http_ip_echo_host,
                chk.http_ip_echo_port,
                &constants.protocols,
            ),
        )
        .await
        .ok()?
        .ok();

        handshake?;

        let http_req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            chk.http_ip_echo_path, chk.http_ip_echo_host
        );
        timeout(probe_timeout, stream.write_all(http_req.as_bytes()))
            .await
            .ok()?
            .ok()?;

        let mut buf = vec![0u8; 1024];
        let n = timeout(probe_timeout, stream.read(&mut buf))
            .await
            .ok()?
            .ok()?;
        let raw = String::from_utf8_lossy(&buf[..n]);
        let body = raw.split("\r\n\r\n").nth(1)?;
        let parsed: Value = serde_json::from_str(body.trim()).ok()?;
        parsed
            .get(EXIT_IP_JSON_KEY)
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
    }

    async fn probe_socks5_udp(node: &ProxyNode, constants: &SystemConstants) -> Option<bool> {
        let probe_timeout = Duration::from_millis(constants.checker.probe_timeout_ms);
        let addr = format!("{}:{}", node.host, node.port);
        let mut stream = timeout(probe_timeout, TcpStream::connect(&addr))
            .await
            .ok()?
            .ok()?;

        let assoc = timeout(
            probe_timeout,
            ProxyConnector::negotiate_socks5(
                &mut stream,
                node,
                EMPTY_IPV4_HOST,
                0,
                constants.protocols.socks5_cmd_udp_associate,
                &constants.protocols,
            ),
        )
        .await
        .ok()?;

        Some(assoc.is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyNode, ProxyProtocol, SystemConstants};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn reports_udp_unsupported_when_probe_fails() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral listener");
        let port = listener.local_addr().unwrap().port();
        let server_task = tokio::spawn(async move {
            // Accept TCP health connection and close immediately, then reject/close UDP probe
            for _ in 0..2 {
                if let Ok((stream, _)) = listener.accept().await {
                    drop(stream);
                }
            }
        });

        let constants = SystemConstants::load_embedded().unwrap();
        let node = ProxyNode {
            id: "udp-probe-fail".to_string(),
            name: "UDP Probe Fail".to_string(),
            protocol: ProxyProtocol::Socks5,
            host: "127.0.0.1".to_string(),
            port,
            auth: None,
            tls: false,
            sni: None,
            udp_enabled: true,
            enabled: true,
            last_latency_ms: None,
            exit_ip: None,
        };

        let report = ProxyChecker::test_proxy(&node, &constants).await;
        assert!(report.reachable);
        assert!(
            !report.udp_supported,
            "udp_supported must be false when probe_socks5_udp fails"
        );
        server_task.abort();
    }
}
