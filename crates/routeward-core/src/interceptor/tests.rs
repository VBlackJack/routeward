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

use super::*;
use crate::config::{
    ChainStrategy, ProfileConfig, ProxyChain, ProxyCredentials, ProxyNode, ProxyProtocol,
    RoutingRule, RuleAction, SystemConstants, TransportProtocol,
};
use crate::error::{RouteWardError, RouteWardResult};
use crate::interceptor::nat::{
    NatSessionEntry, PendingSynOutcome, PendingSynQueue, PidResolutionSource,
};
use crate::interceptor::nftables::NftablesInterceptor;
use crate::process::ProcessAttribution;
use crate::proxy::udp::Socks5UdpTarget;
use crate::rules::ConnectionRequest;
use crate::telemetry::{ConnectionStatus, LogLevel};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use uuid::Uuid;

fn allocate_closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

fn make_proxy_node(
    id: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> ProxyNode {
    let auth = match (username, password) {
        (Some(u), Some(p)) => Some(ProxyCredentials::new(u, p)),
        _ => None,
    };
    ProxyNode {
        id: id.to_string(),
        name: id.to_string(),
        protocol: ProxyProtocol::Socks5,
        host: "127.0.0.1".to_string(),
        port,
        auth,
        udp_enabled: false,
        tls: false,
        tls_skip_verify: false,
        sni: None,
        enabled: true,
        last_latency_ms: Some(15),
        exit_ip: None,
    }
}

async fn run_transparent_session(
    controller: &Arc<RouteWardController>,
    target_port: u16,
    action: RuleAction,
    rule_name: &str,
) -> (RouteWardResult<()>, Vec<u8>) {
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay_addr");

    let client_stream = TcpStream::connect(relay_addr)
        .await
        .expect("client connect");
    let peer_addr = client_stream.local_addr().expect("client local_addr");
    let (server_stream, accepted_peer) = relay_listener.accept().await.expect("accept");
    assert_eq!(peer_addr, accepted_peer);

    controller.nat_table.insert_session(NatSessionEntry {
        client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        client_port: peer_addr.port(),
        orig_dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        orig_dst_port: target_port,
        pid: 4242,
        process_name: "curl.exe".to_string(),
        process_path: "C:\\Windows\\System32\\curl.exe".to_string(),
        resolution_source: PidResolutionSource::SocketLayer,
        action,
        matched_rule_name: rule_name.to_string(),
        created_at: Instant::now(),
    });

    let client_task = tokio::spawn(async move {
        let mut client = client_stream;
        let mut buf = Vec::new();
        let _ = client.read_to_end(&mut buf).await;
        buf
    });

    let res = controller
        .handle_transparent_tcp_client(server_stream, accepted_peer)
        .await;
    let received = client_task.await.expect("client_task join");
    (res, received)
}

#[tokio::test]
async fn transparent_relay_rejects_and_logs_unknown_peer_connection() {
    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    let controller = RouteWardController::new(constants, profile, "en");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.expect("connect");
        let mut buf = [0u8; 8];
        client.read(&mut buf).await.expect("read EOF")
    });

    let (server_stream, peer_addr) = listener.accept().await.expect("accept");
    controller
        .handle_transparent_tcp_client(server_stream, peer_addr)
        .await
        .expect("handled");

    let bytes_read = client_task.await.expect("join");
    assert_eq!(bytes_read, 0);

    let logs = controller.telemetry.list_logs();
    assert!(logs.iter().any(|l| l.level == LogLevel::Warn
        && l.component == COMPONENT_TRANSPARENT
        && l.message.contains("Rejected unauthorized connection")));
}

#[tokio::test]
async fn kill_switch_blocks_transparent_and_socks5_when_upstream_proxy_refused() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let target_port = target_listener.local_addr().expect("target_addr").port();
    let direct_hits = Arc::new(AtomicUsize::new(0));
    let direct_hits_bg = direct_hits.clone();
    let _target_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = target_listener.accept().await {
            direct_hits_bg.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(b"DIRECT_HIT").await;
            let _ = stream.shutdown().await;
        }
    });

    let dead_port = allocate_closed_port();
    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.security_policy.kill_switch_enabled = true;
    profile.proxies = vec![make_proxy_node("proxy-dead", dead_port, None, None)];
    profile.rules.clear();
    profile.default_action = RuleAction::Proxy {
        target_id: "proxy-dead".to_string(),
    };

    let controller = Arc::new(RouteWardController::new(constants, profile, "en"));

    // 1. Transparent TCP relay: connection refused must be blocked, never direct
    let (res, client_bytes) = run_transparent_session(
        &controller,
        target_port,
        RuleAction::Proxy {
            target_id: "proxy-dead".to_string(),
        },
        "Rule-Proxy-Dead",
    )
    .await;
    assert!(res.is_err());
    assert!(client_bytes.is_empty());
    assert_eq!(direct_hits.load(Ordering::SeqCst), 0);

    let conns = controller.telemetry.list_connections();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0].status, ConnectionStatus::Blocked);
    assert_eq!(conns[0].route_label, ROUTE_BLOCK_LABEL);
    assert_eq!(conns[0].matched_rule, "Rule-Proxy-Dead");

    let logs = controller.telemetry.list_logs();
    assert!(logs.iter().any(|l| l.level == LogLevel::Warn
        && l.component == COMPONENT_TRANSPARENT
        && l.message.contains("Kill-Switch blocked connection")));

    // 2. Local SOCKS5 relay: connection refused must receive SOCKS5 general failure reply and be blocked
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socks");
    let socks_addr = socks_listener.local_addr().expect("socks_addr");

    let client_task = tokio::spawn(async move {
        let mut s = TcpStream::connect(socks_addr).await.expect("connect socks");
        s.write_all(&[0x05, 0x01, 0x00]).await.expect("greeting");
        let mut method_reply = [0u8; 2];
        s.read_exact(&mut method_reply).await.expect("method reply");
        assert_eq!(method_reply, [0x05, 0x00]);

        let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        req.extend_from_slice(&target_port.to_be_bytes());
        s.write_all(&req).await.expect("connect req");

        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await.expect("failure reply");
        reply
    });

    let (socks_server_stream, socks_peer) = socks_listener.accept().await.expect("accept");
    let socks_res = controller
        .handle_local_socks5_client(socks_server_stream, socks_peer.port())
        .await;
    assert!(socks_res.is_err());

    let reply = client_task.await.expect("socks client join");
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x01); // general SOCKS server failure
    assert_eq!(direct_hits.load(Ordering::SeqCst), 0);

    let conns = controller.telemetry.list_connections();
    assert_eq!(conns.len(), 2);
    assert!(conns
        .iter()
        .all(|c| c.status == ConnectionStatus::Blocked && c.route_label == ROUTE_BLOCK_LABEL));
    let logs = controller.telemetry.list_logs();
    assert!(logs.iter().any(|l| l.level == LogLevel::Warn
        && l.component == COMPONENT_ENGINE
        && l.message
            .contains("Kill-Switch blocked local SOCKS5 connection")));
}

#[tokio::test]
async fn kill_switch_blocks_on_upstream_timeout_and_auth_failure() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let target_port = target_listener.local_addr().expect("target_addr").port();
    let direct_hits = Arc::new(AtomicUsize::new(0));
    let direct_hits_bg = direct_hits.clone();
    let _target_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = target_listener.accept().await {
            direct_hits_bg.fetch_add(1, Ordering::SeqCst);
            let _ = stream.shutdown().await;
        }
    });

    // Hanging proxy that accepts TCP but never responds to SOCKS5 greeting
    let hanging_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hanging");
    let hanging_port = hanging_listener.local_addr().expect("hanging_addr").port();
    let _hanging_task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = hanging_listener.accept().await {
            held.push(stream);
        }
    });

    // Auth-rejecting SOCKS5 proxy
    let auth_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind auth");
    let auth_port = auth_listener.local_addr().expect("auth_addr").port();
    let _auth_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = auth_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 16];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(&[0x05, 0x02]).await;
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(&[0x01, 0x01]).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
    constants.network.proxy_handshake_timeout_ms = 120;
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.security_policy.kill_switch_enabled = true;
    profile.proxies = vec![
        make_proxy_node("proxy-timeout", hanging_port, None, None),
        make_proxy_node("proxy-bad-auth", auth_port, Some("user"), Some("wrong")),
    ];

    let controller = Arc::new(RouteWardController::new(constants, profile, "en"));

    let (timeout_res, _) = run_transparent_session(
        &controller,
        target_port,
        RuleAction::Proxy {
            target_id: "proxy-timeout".to_string(),
        },
        "Rule-Proxy-Timeout",
    )
    .await;
    assert!(timeout_res.is_err());

    let (auth_res, _) = run_transparent_session(
        &controller,
        target_port,
        RuleAction::Proxy {
            target_id: "proxy-bad-auth".to_string(),
        },
        "Rule-Proxy-Auth",
    )
    .await;
    assert!(auth_res.is_err());

    assert_eq!(direct_hits.load(Ordering::SeqCst), 0);
    let conns = controller.telemetry.list_connections();
    assert_eq!(conns.len(), 2);
    assert!(conns
        .iter()
        .all(|c| c.status == ConnectionStatus::Blocked && c.route_label == ROUTE_BLOCK_LABEL));
}

#[tokio::test]
async fn kill_switch_blocks_broken_chain_and_all_down_groups_but_allows_healthy_group_failover() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let target_port = target_listener.local_addr().expect("target_addr").port();
    let direct_hits = Arc::new(AtomicUsize::new(0));
    let direct_hits_bg = direct_hits.clone();
    let _target_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = target_listener.accept().await {
            direct_hits_bg.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(b"DIRECT_LEAK").await;
            let _ = stream.shutdown().await;
        }
    });

    // Healthy SOCKS5 proxy that replies with "PROXIED_OK" when connecting to target_port,
    // or fails SOCKS5 CONNECT if asked to chain to a dead hop.
    let healthy_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind healthy");
    let healthy_port = healthy_listener.local_addr().expect("healthy_addr").port();
    let proxy_hits = Arc::new(AtomicUsize::new(0));
    let proxy_hits_bg = proxy_hits.clone();
    let _healthy_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = healthy_listener.accept().await {
            let proxy_hits_inner = proxy_hits_bg.clone();
            tokio::spawn(async move {
                let mut greet = [0u8; 3];
                if stream.read_exact(&mut greet).await.is_err() {
                    return;
                }
                let _ = stream.write_all(&[0x05, 0x00]).await;

                let mut hdr = [0u8; 4];
                if stream.read_exact(&mut hdr).await.is_err() {
                    return;
                }
                let dst_port = match hdr[3] {
                    0x01 => {
                        let mut addr_port = [0u8; 6];
                        let _ = stream.read_exact(&mut addr_port).await;
                        u16::from_be_bytes([addr_port[4], addr_port[5]])
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        let _ = stream.read_exact(&mut len).await;
                        let mut dom_port = vec![0u8; (len[0] as usize) + 2];
                        let _ = stream.read_exact(&mut dom_port).await;
                        u16::from_be_bytes([
                            dom_port[dom_port.len() - 2],
                            dom_port[dom_port.len() - 1],
                        ])
                    }
                    _ => return,
                };

                if dst_port == target_port {
                    proxy_hits_inner.fetch_add(1, Ordering::SeqCst);
                    let _ = stream
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                        .await;
                    let _ = stream.write_all(b"PROXIED_OK").await;
                    let _ = stream.shutdown().await;
                } else {
                    // Next hop in chain is unreachable
                    let _ = stream
                        .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    let _ = stream.shutdown().await;
                }
            });
        }
    });

    let dead_port_1 = allocate_closed_port();
    let dead_port_2 = allocate_closed_port();

    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.security_policy.kill_switch_enabled = true;
    profile.proxies = vec![
        make_proxy_node("proxy-dead-1", dead_port_1, None, None),
        make_proxy_node("proxy-dead-2", dead_port_2, None, None),
        make_proxy_node("proxy-healthy", healthy_port, None, None),
    ];
    profile.chains = vec![
        ProxyChain {
            id: "chain-seq-broken".to_string(),
            name: "Broken Sequence Chain".to_string(),
            strategy: ChainStrategy::Sequence,
            proxy_ids: vec!["proxy-healthy".to_string(), "proxy-dead-1".to_string()],
            enabled: true,
        },
        ProxyChain {
            id: "group-failover-recover".to_string(),
            name: "Failover Group With Healthy Secondary".to_string(),
            strategy: ChainStrategy::Failover,
            proxy_ids: vec!["proxy-dead-1".to_string(), "proxy-healthy".to_string()],
            enabled: true,
        },
        ProxyChain {
            id: "group-failover-all-down".to_string(),
            name: "Failover Group All Down".to_string(),
            strategy: ChainStrategy::Failover,
            proxy_ids: vec!["proxy-dead-1".to_string(), "proxy-dead-2".to_string()],
            enabled: true,
        },
        ProxyChain {
            id: "group-lowest-latency-all-down".to_string(),
            name: "LowestLatency Group All Down".to_string(),
            strategy: ChainStrategy::LowestLatency,
            proxy_ids: vec!["proxy-dead-1".to_string(), "proxy-dead-2".to_string()],
            enabled: true,
        },
    ];

    let controller = Arc::new(RouteWardController::new(constants, profile, "en"));

    // 1. Sequence chain where hop 2 is down -> Blocked, 0 direct hits
    let (seq_res, seq_bytes) = run_transparent_session(
        &controller,
        target_port,
        RuleAction::Chain {
            target_id: "chain-seq-broken".to_string(),
        },
        "Rule-Broken-Seq",
    )
    .await;
    assert!(seq_res.is_err());
    assert!(seq_bytes.is_empty());

    // 2. Failover group where node 1 is down and node 2 is healthy -> Succeeds via node 2, 0 direct hits
    let (fo_ok_res, fo_ok_bytes) = run_transparent_session(
        &controller,
        target_port,
        RuleAction::Chain {
            target_id: "group-failover-recover".to_string(),
        },
        "Rule-Failover-Recover",
    )
    .await;
    assert!(fo_ok_res.is_ok());
    assert_eq!(fo_ok_bytes, b"PROXIED_OK");
    assert_eq!(proxy_hits.load(Ordering::SeqCst), 1);

    // 3. Failover group where all nodes are down -> Blocked, 0 direct hits
    let (fo_down_res, fo_down_bytes) = run_transparent_session(
        &controller,
        target_port,
        RuleAction::Chain {
            target_id: "group-failover-all-down".to_string(),
        },
        "Rule-Failover-All-Down",
    )
    .await;
    assert!(fo_down_res.is_err());
    assert!(fo_down_bytes.is_empty());

    // 4. LowestLatency group where all nodes are down -> Blocked, 0 direct hits
    let (ll_down_res, ll_down_bytes) = run_transparent_session(
        &controller,
        target_port,
        RuleAction::Chain {
            target_id: "group-lowest-latency-all-down".to_string(),
        },
        "Rule-LowestLatency-All-Down",
    )
    .await;
    assert!(ll_down_res.is_err());
    assert!(ll_down_bytes.is_empty());

    assert_eq!(direct_hits.load(Ordering::SeqCst), 0);

    let conns = controller.telemetry.list_connections();
    let blocked: Vec<_> = conns
        .iter()
        .filter(|c| c.status == ConnectionStatus::Blocked)
        .collect();
    assert_eq!(blocked.len(), 3);
    assert!(blocked.iter().all(|c| c.route_label == ROUTE_BLOCK_LABEL));
}

#[tokio::test]
async fn kill_switch_disabled_explicitly_falls_back_to_direct_with_warning() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let target_port = target_listener.local_addr().expect("target_addr").port();
    let direct_hits = Arc::new(AtomicUsize::new(0));
    let direct_hits_bg = direct_hits.clone();
    let _target_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = target_listener.accept().await {
            direct_hits_bg.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(b"DIRECT_FALLBACK_OK").await;
            let _ = stream.shutdown().await;
        }
    });

    let dead_port = allocate_closed_port();
    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.security_policy.kill_switch_enabled = false;
    profile.proxies = vec![make_proxy_node("proxy-dead", dead_port, None, None)];

    let controller = Arc::new(RouteWardController::new(constants, profile, "en"));

    let (res, received) = run_transparent_session(
        &controller,
        target_port,
        RuleAction::Proxy {
            target_id: "proxy-dead".to_string(),
        },
        "Rule-Proxy-Fallback",
    )
    .await;
    assert!(res.is_ok());
    assert_eq!(received, b"DIRECT_FALLBACK_OK");
    assert_eq!(direct_hits.load(Ordering::SeqCst), 1);

    let conns = controller.telemetry.list_connections();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0].route_label, ROUTE_DIRECT_LABEL);

    let logs = controller.telemetry.list_logs();
    assert!(logs.iter().any(|l| l.level == LogLevel::Warn
        && l.message
            .contains("falling back to DIRECT because killSwitchEnabled=false")));
}

#[test]
fn controller_starts_with_empty_fake_ip_cache_and_saves_profile() {
    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    let controller = RouteWardController::new(constants, profile, "en");

    // No simulated Fake-IP entries or connections are seeded at startup
    assert!(controller.dns.list_entries().is_empty());
    assert!(controller.telemetry.list_connections().is_empty());

    let temp_path =
        std::env::temp_dir().join(format!("routeward_ctrl_prof_{}.json", Uuid::new_v4()));
    controller
        .save_profile_to_path(&temp_path)
        .expect("controller atomic profile save");
    assert!(temp_path.exists());
    #[cfg(windows)]
    let _ = crate::config::security::apply_windows_sddl_dacl(&temp_path, "D:(A;;FA;;;WD)");
    let _ = std::fs::remove_file(&temp_path);
}

#[test]
fn expired_pending_syn_dropped_with_info_counter_when_kill_switch_enabled_and_reinjected_with_warn_when_disabled(
) {
    use crate::interceptor::nat::Ipv4TcpPacketMeta;

    let syn_meta = Ipv4TcpPacketMeta {
        ip_header_len: 20,
        total_len: 40,
        src_ip: Ipv4Addr::new(10, 0, 0, 5),
        dst_ip: Ipv4Addr::new(93, 184, 216, 34),
        src_port: 51111,
        dst_port: 443,
        tcp_flags: 0x02,
    };

    // 1. Kill switch enabled -> timed-out SYN is dropped (never reinjected), counter incremented, INFO log emitted
    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile_ks_on = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile_ks_on.enable_logging = false;
    profile_ks_on.security_policy.kill_switch_enabled = true;
    let ctrl_ks_on = RouteWardController::new(constants.clone(), profile_ks_on, "en");

    let queue_on = PendingSynQueue::new();
    queue_on.enqueue(vec![0x45, 0x00, 0x00, 0x28], syn_meta);

    let outcomes_on = ctrl_ks_on.poll_pending_syns(&queue_on, Duration::ZERO, |_| None);
    assert_eq!(outcomes_on.len(), 1);
    assert!(matches!(
        outcomes_on[0],
        PendingSynOutcome::TimedOutDropped { drop_count: 1, .. }
    ));
    assert_eq!(ctrl_ks_on.nat_table.dropped_unattributed_syn_count(), 1);
    assert_eq!(ctrl_ks_on.nat_table.reinjected_unattributed_syn_count(), 0);

    let logs_on = ctrl_ks_on.telemetry.list_logs();
    assert!(logs_on.iter().any(|l| l.level == LogLevel::Info
        && l.component == COMPONENT_WINDIVERT
        && l.message.contains("Dropped unattributed Pending SYN #1")
        && l.message.contains("killSwitchEnabled=true")));

    // 2. Kill switch disabled -> timed-out SYN is reinjected, counter incremented, WARN log emitted
    let mut profile_ks_off = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile_ks_off.enable_logging = false;
    profile_ks_off.security_policy.kill_switch_enabled = false;
    let ctrl_ks_off = RouteWardController::new(constants, profile_ks_off, "en");

    let queue_off = PendingSynQueue::new();
    queue_off.enqueue(vec![0x45, 0x00, 0x00, 0x28], syn_meta);

    let outcomes_off = ctrl_ks_off.poll_pending_syns(&queue_off, Duration::ZERO, |_| None);
    assert_eq!(outcomes_off.len(), 1);
    assert!(matches!(
        outcomes_off[0],
        PendingSynOutcome::TimedOutReinject {
            reinject_count: 1,
            ..
        }
    ));
    assert_eq!(ctrl_ks_off.nat_table.dropped_unattributed_syn_count(), 0);
    assert_eq!(ctrl_ks_off.nat_table.reinjected_unattributed_syn_count(), 1);

    let logs_off = ctrl_ks_off.telemetry.list_logs();
    assert!(logs_off.iter().any(|l| l.level == LogLevel::Warn
        && l.component == COMPONENT_WINDIVERT
        && l.message.contains("Released unattributed Pending SYN #1")
        && l.message.contains("killSwitchEnabled=false")));
}

#[test]
fn unknown_process_attribution_enforces_block_and_warns_with_kill_switch_and_defaults_to_block() {
    use crate::config::SecurityPolicyConfig;
    use crate::process::ProcessIdentity;

    // 1. Verify default_profile.json and SecurityPolicyConfig::default() default to Block
    let embedded_profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    assert_eq!(
        embedded_profile.security_policy.unknown_process_action,
        RuleAction::Block
    );
    assert_eq!(
        SecurityPolicyConfig::default().unknown_process_action,
        RuleAction::Block
    );

    // 2. When killSwitchEnabled = true and unknownProcessAction = Direct, override to Block with WARN
    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = embedded_profile.clone();
    profile.enable_logging = false;
    profile.security_policy.kill_switch_enabled = true;
    profile.security_policy.unknown_process_action = RuleAction::Direct;
    let ctrl_ks_on = RouteWardController::new(constants.clone(), profile, "en");

    let (pid, proc_name, _, action, rule_name, _, source) = ctrl_ks_on
        .attribute_or_apply_unknown_policy(
            ProcessAttribution::Unknown {
                reason: "socket closed before procfs scan".to_string(),
            },
            54321,
            "93.184.216.34",
            443,
            Some(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        );
    assert_eq!(pid, 0);
    assert_eq!(proc_name, "unknown");
    assert_eq!(action, RuleAction::Block);
    assert_eq!(
        rule_name,
        "SecurityPolicy:unknownProcessAction(KillSwitchOverride)"
    );
    assert_eq!(source, "procfs_unknown");

    let logs = ctrl_ks_on.telemetry.list_logs();
    assert!(logs.iter().any(|l| l.level == LogLevel::Warn
        && l.component == COMPONENT_TRANSPARENT
        && l.message
            .contains("overriding unknownProcessAction=Direct to Block")));

    // 3. Synthetic "pid:<n>" fallback identity is also treated as unattributed and blocked
    let (pid2, _, _, action2, _, _, source2) = ctrl_ks_on.attribute_or_apply_unknown_policy(
        ProcessAttribution::Single(ProcessIdentity {
            pid: 9999,
            name: "pid:9999".to_string(),
            executable_path: "pid:9999".to_string(),
        }),
        54322,
        "93.184.216.34",
        443,
        None,
    );
    assert_eq!(pid2, 9999);
    assert_eq!(action2, RuleAction::Block);
    assert_eq!(source2, "procfs_unknown");

    // 4. When killSwitchEnabled = false and unknownProcessAction = Direct, honors Direct and logs WARN
    let mut profile_ks_off = embedded_profile;
    profile_ks_off.enable_logging = false;
    profile_ks_off.security_policy.kill_switch_enabled = false;
    profile_ks_off.security_policy.unknown_process_action = RuleAction::Direct;
    let ctrl_ks_off = RouteWardController::new(constants, profile_ks_off, "en");

    let (_, _, _, action_off, rule_off, _, _) = ctrl_ks_off.attribute_or_apply_unknown_policy(
        ProcessAttribution::Unknown {
            reason: "ephemeral socket closed".to_string(),
        },
        54323,
        "93.184.216.34",
        443,
        None,
    );
    assert_eq!(action_off, RuleAction::Direct);
    assert_eq!(rule_off, "SecurityPolicy:unknownProcessAction");
}

#[test]
fn unmapped_fake_ip_in_cidr_is_blocked_and_never_leaks_direct() {
    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.default_action = RuleAction::Direct;
    let controller = RouteWardController::new(constants, profile, "en");

    // Unallocated IP inside 198.18.0.0/15 Fake-IP pool must be blocked
    let eval = controller.evaluate_rule(&ConnectionRequest {
        process_name: "curl.exe".to_string(),
        process_path: Some("C:\\Windows\\System32\\curl.exe".to_string()),
        target_host: "198.18.9.99".to_string(),
        target_ip: Some("198.18.9.99".to_string()),
        target_port: 443,
        protocol: TransportProtocol::Tcp,
    });
    assert_eq!(eval.action, RuleAction::Block);
    assert_eq!(eval.matched_rule_name, "FakeIP:UnmappedOrExpired");

    let logs = controller.telemetry.list_logs();
    assert!(logs.iter().any(|l| l.level == LogLevel::Warn
        && l.message
            .contains("Blocked connection to unmapped or expired Fake-IP 198.18.9.99:443")));
}

#[test]
fn dns_fake_ip_a_5s_ttl_aaaa_nodata_canary_nxdomain_and_no_info_log() {
    use crate::dns::codec::{
        build_query, extract_ipv4_answers, parse_dns_message, QTYPE_A, QTYPE_AAAA, QTYPE_PTR,
        RCODE_NOERROR, RCODE_NXDOMAIN,
    };

    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.dns_config.enable_fake_ip = true;
    profile.security_policy.block_encrypted_dns_bypass = true;
    let controller = RouteWardController::new(constants, profile, "en");

    // 1. A query -> Fake-IP in 198.18.0.0/15 with 5s OS wire TTL, 300s internal TTL
    let raw_a = build_query(0x1111, "app.routeward.test", QTYPE_A).expect("build A query");
    let resp_a = controller
        .resolve_dns_query_fast(&raw_a)
        .expect("fast Fake-IP A response");
    let msg_a = parse_dns_message(&resp_a).expect("parse A response");
    assert_eq!(msg_a.rcode(), RCODE_NOERROR);
    assert_eq!(msg_a.answers.len(), 1);
    let ips = extract_ipv4_answers(&resp_a).expect("extract A IPv4");
    assert_eq!(ips.len(), 1);
    let fake_ip = ips[0];
    assert!(controller.dns.is_in_fake_subnet(&fake_ip));
    assert_eq!(msg_a.answers[0].ttl, 5, "OS wire TTL must be 5 seconds");
    let internal_entries = controller.dns.list_entries();
    assert_eq!(internal_entries.len(), 1);
    assert!(
        internal_entries[0].ttl_remaining_seconds > 290,
        "Internal Fake-IP table TTL must remain ~300s"
    );

    // 2. AAAA query -> NODATA (RCODE=0, ANCOUNT=0)
    let raw_aaaa = build_query(0x2222, "app.routeward.test", QTYPE_AAAA).expect("build AAAA query");
    let resp_aaaa = controller
        .resolve_dns_query_fast(&raw_aaaa)
        .expect("fast Fake-IP AAAA response");
    let msg_aaaa = parse_dns_message(&resp_aaaa).expect("parse AAAA response");
    assert_eq!(msg_aaaa.rcode(), RCODE_NOERROR);
    assert!(msg_aaaa.answers.is_empty());

    // 3. PTR query for the Fake-IP -> returns domain
    let octs = fake_ip.octets();
    let ptr_name = format!(
        "{}.{}.{}.{}.in-addr.arpa",
        octs[3], octs[2], octs[1], octs[0]
    );
    let raw_ptr = build_query(0x3333, &ptr_name, QTYPE_PTR).expect("build PTR query");
    let resp_ptr = controller
        .resolve_dns_query_fast(&raw_ptr)
        .expect("fast Fake-IP PTR response");
    let msg_ptr = parse_dns_message(&resp_ptr).expect("parse PTR response");
    assert_eq!(msg_ptr.rcode(), RCODE_NOERROR);
    assert_eq!(msg_ptr.answers.len(), 1);

    // Ordinary DNS queries must NEVER emit INFO/WARN/ERROR logs for DnsEngine
    let logs_after_ordinary = controller.telemetry.list_logs();
    assert!(
        !logs_after_ordinary
            .iter()
            .any(|l| l.component == COMPONENT_DNS),
        "Ordinary DNS queries must not emit INFO/WARN/ERROR telemetry logs, got: {:?}",
        logs_after_ordinary
    );

    // 4. DoH canary query (use-application-dns.net) -> NXDOMAIN + WARN log
    let raw_canary =
        build_query(0x4444, "use-application-dns.net", QTYPE_A).expect("build canary query");
    let resp_canary = controller
        .resolve_dns_query_fast(&raw_canary)
        .expect("fast canary response");
    let msg_canary = parse_dns_message(&resp_canary).expect("parse canary response");
    assert_eq!(msg_canary.rcode(), RCODE_NXDOMAIN);
    assert!(msg_canary.answers.is_empty());

    let logs_after_canary = controller.telemetry.list_logs();
    assert!(logs_after_canary.iter().any(|l| l.level == LogLevel::Warn
        && l.component == COMPONENT_DNS
        && l.message.contains("Blocked DoH canary DNS query")));
}

#[tokio::test]
async fn dns_real_resolution_over_tcp_via_socks5_and_strict_servfail_when_proxy_down() {
    use crate::dns::codec::{
        build_a_query, build_a_response, encode_tcp_dns_frame, extract_ipv4_answers,
        parse_dns_message, parse_dns_query, RCODE_NOERROR, RCODE_SERVFAIL,
    };

    // Direct DNS trap server to verify 0 direct cleartext hits when proxy is used or down
    let direct_trap_udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind trap udp");
    let direct_trap_addr = direct_trap_udp.local_addr().expect("trap addr");
    let direct_hits = Arc::new(AtomicUsize::new(0));
    let direct_hits_bg = direct_hits.clone();
    let _trap_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((_, _)) = direct_trap_udp.recv_from(&mut buf).await {
            direct_hits_bg.fetch_add(1, Ordering::SeqCst);
        }
    });

    // Mock SOCKS5 server that speaks DNS-over-TCP once connected to the upstream DNS target
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socks5");
    let socks_port = socks_listener.local_addr().expect("socks addr").port();
    let proxy_dns_hits = Arc::new(AtomicUsize::new(0));
    let proxy_dns_hits_bg = proxy_dns_hits.clone();
    let _socks_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = socks_listener.accept().await {
            let hits = proxy_dns_hits_bg.clone();
            tokio::spawn(async move {
                let mut greet = [0u8; 3];
                if stream.read_exact(&mut greet).await.is_err() {
                    return;
                }
                let _ = stream.write_all(&[0x05, 0x00]).await;

                let mut hdr = [0u8; 4];
                if stream.read_exact(&mut hdr).await.is_err() {
                    return;
                }
                match hdr[3] {
                    0x01 => {
                        let mut addr_port = [0u8; 6];
                        let _ = stream.read_exact(&mut addr_port).await;
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        let _ = stream.read_exact(&mut len).await;
                        let mut dom_port = vec![0u8; (len[0] as usize) + 2];
                        let _ = stream.read_exact(&mut dom_port).await;
                    }
                    _ => return,
                }
                let _ = stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 53])
                    .await;

                // Read DNS-over-TCP frame
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let qlen = u16::from_be_bytes(len_buf) as usize;
                let mut qbuf = vec![0u8; qlen];
                if stream.read_exact(&mut qbuf).await.is_err() {
                    return;
                }
                hits.fetch_add(1, Ordering::SeqCst);
                if let Ok(parsed_q) = parse_dns_query(&qbuf) {
                    let resp = build_a_response(&parsed_q, Ipv4Addr::new(203, 0, 113, 77), 60);
                    let framed = encode_tcp_dns_frame(&resp);
                    let _ = stream.write_all(&framed).await;
                    let _ = stream.flush().await;
                }
            });
        }
    });

    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.dns_config.enable_fake_ip = false;
    profile.dns_config.remote_dns_resolution = true;
    profile.dns_config.upstream_dns = direct_trap_addr.to_string();
    profile.security_policy.strict_dns_no_local_fallback = true;
    profile.security_policy.kill_switch_enabled = true;
    profile.proxies = vec![make_proxy_node("socks-dns", socks_port, None, None)];
    profile.default_action = RuleAction::Proxy {
        target_id: "socks-dns".to_string(),
    };

    let controller = RouteWardController::new(constants.clone(), profile.clone(), "en");
    let raw_query = build_a_query(0x7777, "real.routeward.test").expect("build query");
    let resp_wire = controller
        .resolve_dns_query_async(&raw_query, Some(direct_trap_addr), true)
        .await;
    let msg = parse_dns_message(&resp_wire).expect("parse DNS response");
    assert_eq!(msg.rcode(), RCODE_NOERROR);
    let answers = extract_ipv4_answers(&resp_wire).expect("extract A answers");
    assert_eq!(answers, vec![Ipv4Addr::new(203, 0, 113, 77)]);
    assert_eq!(proxy_dns_hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        direct_hits.load(Ordering::SeqCst),
        0,
        "Zero direct cleartext DNS queries allowed"
    );

    // Now test with an unreachable proxy: must return SERVFAIL and never touch direct_trap_udp
    let dead_port = allocate_closed_port();
    profile.proxies = vec![make_proxy_node("socks-dead", dead_port, None, None)];
    profile.default_action = RuleAction::Proxy {
        target_id: "socks-dead".to_string(),
    };
    let controller_dead = RouteWardController::new(constants, profile, "en");
    let resp_fail = controller_dead
        .resolve_dns_query_async(&raw_query, Some(direct_trap_addr), true)
        .await;
    let msg_fail = parse_dns_message(&resp_fail).expect("parse SERVFAIL response");
    assert_eq!(msg_fail.rcode(), RCODE_SERVFAIL);
    assert_eq!(
        direct_hits.load(Ordering::SeqCst),
        0,
        "Strict DNS no-fallback must never fall back to cleartext DNS when proxy fails"
    );
    let warn_logs = controller_dead.telemetry.list_logs();
    assert!(warn_logs.iter().any(|l| l.level == LogLevel::Warn
        && l.component == COMPONENT_DNS
        && l.message
            .contains("returning SERVFAIL without cleartext fallback")));
}

#[tokio::test]
async fn dns_bypass_domain_and_bootstrap_proxy_hostname_resolved_directly() {
    use crate::dns::codec::{
        build_a_query, build_a_response, extract_ipv4_answers, parse_dns_message, parse_dns_query,
        RCODE_NOERROR,
    };

    // Mock direct UDP DNS server responding for AD bypass domain and proxy bootstrap host
    let mock_dns_udp = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind mock dns udp");
    let mock_dns_addr = mock_dns_udp.local_addr().expect("mock dns addr");
    let _dns_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((len, peer)) = mock_dns_udp.recv_from(&mut buf).await {
            if let Ok(q) = parse_dns_query(&buf[..len]) {
                let ip = if q.question.qname == "dc01.corp.contoso.com" {
                    Ipv4Addr::new(10, 10, 1, 5)
                } else if q.question.qname == "proxy.internal.test" {
                    Ipv4Addr::new(10, 10, 99, 88)
                } else {
                    Ipv4Addr::new(192, 0, 2, 1)
                };
                let resp = build_a_response(&q, ip, 120);
                let _ = mock_dns_udp.send_to(&resp, peer).await;
            }
        }
    });

    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.dns_config.enable_fake_ip = true;
    profile.dns_config.upstream_dns = mock_dns_addr.to_string();
    profile.dns_config.bypass_domains = vec!["corp.contoso.com".to_string()];

    let mut domain_proxy = make_proxy_node("proxy-by-domain", 1080, None, None);
    domain_proxy.host = "proxy.internal.test".to_string();
    profile.proxies = vec![domain_proxy];

    let controller = RouteWardController::new(constants, profile, "en");

    // 1. Bypassed AD domain resolves directly to 10.10.1.5 (not a Fake-IP)
    let raw_bypass = build_a_query(0x8888, "dc01.corp.contoso.com").expect("build bypass query");
    assert!(
        controller.resolve_dns_query_fast(&raw_bypass).is_none(),
        "Bypassed domain must not be answered by Fake-IP fast path"
    );
    let resp_bypass = controller
        .resolve_dns_query_async(&raw_bypass, Some(mock_dns_addr), true)
        .await;
    let msg_bypass = parse_dns_message(&resp_bypass).expect("parse bypass response");
    assert_eq!(msg_bypass.rcode(), RCODE_NOERROR);
    let bypass_ips = extract_ipv4_answers(&resp_bypass).expect("extract bypass IP");
    assert_eq!(bypass_ips, vec![Ipv4Addr::new(10, 10, 1, 5)]);

    // 2. Bootstrap resolution of domain-named proxy populates anti-loop upstream_endpoints
    controller.bootstrap_resolve_proxy_hosts().await;
    let endpoints = controller.nat_table.upstream_endpoints();
    assert!(
            endpoints.contains(&(IpAddr::V4(Ipv4Addr::new(10, 10, 99, 88)), 1080)),
            "Bootstrap proxy resolution must register (10.10.99.88, 1080) in nat_table.upstream_endpoints, got {:?}",
            endpoints
        );
}

#[tokio::test]
async fn bypassed_domains_never_query_public_upstream_and_return_servfail_when_internal_dns_silent()
{
    use crate::dns::codec::{build_a_query, parse_dns_message, RCODE_SERVFAIL};

    // Simulated public upstream DNS trap server - must receive 0 queries for bypassed domains
    let public_trap_udp = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind public trap udp");
    let public_trap_addr = public_trap_udp.local_addr().expect("public trap addr");
    let public_hits = Arc::new(AtomicUsize::new(0));
    let public_hits_bg = public_hits.clone();
    let _trap_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((_, _)) = public_trap_udp.recv_from(&mut buf).await {
            public_hits_bg.fetch_add(1, Ordering::SeqCst);
        }
    });

    // Silent / unreachable internal resolver
    let silent_internal_port = allocate_closed_port();
    let silent_internal_addr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), silent_internal_port);

    let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
    constants.network.tcp_connect_timeout_ms = 500;
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.dns_config.enable_fake_ip = true;
    profile.dns_config.upstream_dns = public_trap_addr.to_string();
    profile.dns_config.bypass_domains = vec!["corp.contoso.com".to_string()];

    let controller = RouteWardController::new(constants, profile, "en");
    *controller.system_resolvers_override.write() = Some(vec![silent_internal_addr]);

    // Verify candidate_dns_resolvers_with_system for BypassOnlySystem never includes public upstreams
    let candidates = controller.candidate_dns_resolvers_with_system(
        Some(silent_internal_addr),
        DnsResolverMode::BypassOnlySystem,
        &[],
    );
    assert_eq!(candidates, vec![silent_internal_addr]);
    assert!(!candidates.contains(&public_trap_addr));

    for bypassed_name in [
        "dc01.corp.contoso.com",
        "printer.local",
        "dc01",
        "1.0.0.10.in-addr.arpa",
    ] {
        let raw_q = build_a_query(0x9001, bypassed_name).expect("build query");
        let resp = controller
            .resolve_dns_query_async(&raw_q, Some(silent_internal_addr), true)
            .await;
        let msg = parse_dns_message(&resp).expect("parse SERVFAIL response");
        assert_eq!(
            msg.rcode(),
            RCODE_SERVFAIL,
            "Bypassed domain {bypassed_name} must return SERVFAIL when internal DNS is silent"
        );
    }

    assert_eq!(
        public_hits.load(Ordering::SeqCst),
        0,
        "Bypassed domains must NEVER query public upstreamDns"
    );
}

#[test]
fn direct_flow_resolution_prefers_system_and_last_orig_resolver_before_upstream_dns() {
    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    let upstream_addr: SocketAddr = "198.51.100.53:53".parse().unwrap();
    profile.dns_config.upstream_dns = upstream_addr.to_string();

    let controller = RouteWardController::new(constants, profile, "en");
    let sys_ip = Ipv4Addr::new(10, 20, 30, 40);
    let sys_sock = SocketAddr::new(IpAddr::V4(sys_ip), 53);
    let orig_sock: SocketAddr = "10.20.30.1:53".parse().unwrap();

    controller.record_orig_dns_resolver(orig_sock);

    // When system resolvers or last_seen_orig_resolver exist, DirectPreferSystem uses them and NOT upstreamDns
    let direct_list = controller.candidate_dns_resolvers_with_system(
        None,
        DnsResolverMode::DirectPreferSystem,
        &[sys_sock],
    );
    assert_eq!(direct_list, vec![orig_sock, sys_sock]);
    assert!(!direct_list.contains(&upstream_addr));

    // When no orig_resolver, no last_seen_orig_resolver, and no system resolvers exist:
    // DirectPreferSystem falls back to upstreamDns, whereas BypassOnlySystem stays empty.
    *controller.last_seen_orig_resolver.write() = None;
    let direct_fallback = controller.candidate_dns_resolvers_with_system(
        None,
        DnsResolverMode::DirectPreferSystem,
        &[],
    );
    assert!(direct_fallback.contains(&upstream_addr));

    let bypass_empty = controller.candidate_dns_resolvers_with_system(
        None,
        DnsResolverMode::BypassOnlySystem,
        &[],
    );
    assert!(bypass_empty.is_empty());
}

fn build_sample_tls_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    // server_name extension payload: list_len(2) + name_type(1=0) + host_len(2) + host
    let mut sni_ext_data = Vec::new();
    let list_len = (1 + 2 + sni_bytes.len()) as u16;
    sni_ext_data.extend_from_slice(&list_len.to_be_bytes());
    sni_ext_data.push(0x00); // host_name type
    sni_ext_data.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext_data.extend_from_slice(sni_bytes);

    // Extension header: type(2=0x0000) + len(2) + data
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext_data);

    // ClientHello body: client_version(2) + random(32) + session_id_len(1=0)
    // + cipher_suites_len(2=2) + cipher_suite(2) + comp_methods_len(1=1) + comp_method(1=0)
    // + extensions_len(2) + extensions
    let mut ch_body = Vec::new();
    ch_body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    ch_body.extend_from_slice(&[0x11; 32]); // Random
    ch_body.push(0x00); // Session ID len = 0
    ch_body.extend_from_slice(&2u16.to_be_bytes()); // Cipher suites len = 2
    ch_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    ch_body.push(0x01); // Compression methods len = 1
    ch_body.push(0x00); // null compression
    ch_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    ch_body.extend_from_slice(&extensions);

    // Handshake message: msg_type(1=1 ClientHello) + len(3) + ch_body
    let ch_len = ch_body.len();
    let mut handshake = vec![
        0x01,
        ((ch_len >> 16) & 0xFF) as u8,
        ((ch_len >> 8) & 0xFF) as u8,
        (ch_len & 0xFF) as u8,
    ];
    handshake.extend_from_slice(&ch_body);

    // TLS record: content_type(1=22 Handshake) + version(2=0x0301) + len(2) + handshake
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[tokio::test]
async fn transparent_relay_extracts_tls_sni_on_port_443_and_routes_literal_ip_via_socks5() {
    use crate::config::RoutingRule;

    let client_hello = build_sample_tls_client_hello("sni.routeward.test");
    let expected_hello_len = client_hello.len();

    let socks_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socks5");
    let socks_port = socks_listener.local_addr().expect("socks addr").port();
    let observed_domain = Arc::new(RwLock::new(String::new()));
    let observed_domain_bg = observed_domain.clone();
    let observed_hello_len = Arc::new(AtomicUsize::new(0));
    let observed_hello_len_bg = observed_hello_len.clone();

    let _socks_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = socks_listener.accept().await {
            let mut greet = [0u8; 3];
            if stream.read_exact(&mut greet).await.is_err() {
                return;
            }
            let _ = stream.write_all(&[0x05, 0x00]).await;

            let mut hdr = [0u8; 4];
            if stream.read_exact(&mut hdr).await.is_err() {
                return;
            }
            if hdr[3] == 0x03 {
                let mut len = [0u8; 1];
                let _ = stream.read_exact(&mut len).await;
                let mut dom_port = vec![0u8; (len[0] as usize) + 2];
                let _ = stream.read_exact(&mut dom_port).await;
                let dom = String::from_utf8_lossy(&dom_port[..len[0] as usize]).to_string();
                *observed_domain_bg.write() = dom;
            }
            let _ = stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xBB])
                .await;

            let mut hello_buf = vec![0u8; expected_hello_len];
            if stream.read_exact(&mut hello_buf).await.is_ok() {
                observed_hello_len_bg.store(hello_buf.len(), Ordering::SeqCst);
                let _ = stream.write_all(b"SNI_PROXIED_OK").await;
            }
            let _ = stream.shutdown().await;
        }
    });

    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.proxies = vec![make_proxy_node("proxy-sni", socks_port, None, None)];
    profile.default_action = RuleAction::Direct;
    profile.rules = vec![RoutingRule {
        id: "rule-sni-domain".to_string(),
        name: "Route SNI Domain Via Proxy".to_string(),
        enabled: true,
        priority: 1,
        process_patterns: Vec::new(),
        domain_patterns: vec!["*.routeward.test".to_string()],
        ip_cidrs: Vec::new(),
        port_ranges: Vec::new(),
        protocol: TransportProtocol::Tcp,
        action: RuleAction::Proxy {
            target_id: "proxy-sni".to_string(),
        },
    }];

    let controller = Arc::new(RouteWardController::new(constants, profile, "en"));

    let relay_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay_addr");
    let mut client_stream = TcpStream::connect(relay_addr)
        .await
        .expect("client connect");
    let peer_addr = client_stream.local_addr().expect("client local_addr");
    let (server_stream, accepted_peer) = relay_listener.accept().await.expect("accept");

    // Insert a NAT session targeting a non-Fake-IP literal IPv4 address on port 443 initially marked Direct
    controller.nat_table.insert_session(NatSessionEntry {
        client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        client_port: peer_addr.port(),
        orig_dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        orig_dst_port: 443,
        pid: 4242,
        process_name: "curl.exe".to_string(),
        process_path: "C:\\Windows\\System32\\curl.exe".to_string(),
        resolution_source: PidResolutionSource::SocketLayer,
        action: RuleAction::Direct,
        matched_rule_name: "Default".to_string(),
        created_at: Instant::now(),
    });

    let client_task = tokio::spawn(async move {
        client_stream
            .write_all(&client_hello)
            .await
            .expect("write ClientHello");
        let mut resp = Vec::new();
        let _ = client_stream.read_to_end(&mut resp).await;
        resp
    });

    let res = controller
        .handle_transparent_tcp_client(server_stream, accepted_peer)
        .await;
    assert!(res.is_ok());

    let reply = client_task.await.expect("client_task join");
    assert_eq!(reply, b"SNI_PROXIED_OK");
    assert_eq!(*observed_domain.read(), "sni.routeward.test");
    assert_eq!(
        observed_hello_len.load(Ordering::SeqCst),
        expected_hello_len,
        "Peeked TLS ClientHello bytes must be forwarded intact to upstream proxy"
    );
}

#[tokio::test]
async fn full_fake_ip_pool_returns_servfail_without_real_dns_fallback() {
    use crate::dns::codec::{build_a_query, parse_dns_message, RCODE_SERVFAIL};

    let trap_udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind trap udp");
    let trap_addr = trap_udp.local_addr().expect("trap addr");
    let trap_hits = Arc::new(AtomicUsize::new(0));
    let trap_hits_bg = trap_hits.clone();
    let _trap_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((_, _)) = trap_udp.recv_from(&mut buf).await {
            trap_hits_bg.fetch_add(1, Ordering::SeqCst);
        }
    });

    let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
    constants.dns.max_cache_entries = 0; // Simulate an unallocatable full Fake-IP pool
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.dns_config.enable_fake_ip = true;
    profile.dns_config.upstream_dns = trap_addr.to_string();

    let controller = RouteWardController::new(constants, profile, "en");
    let raw_query = build_a_query(0x6161, "overflow.routeward.test").expect("build query");

    let resp = controller
        .resolve_dns_query_async(&raw_query, Some(trap_addr), true)
        .await;
    let msg = parse_dns_message(&resp).expect("parse SERVFAIL");
    assert_eq!(msg.rcode(), RCODE_SERVFAIL);
    assert_eq!(
        trap_hits.load(Ordering::SeqCst),
        0,
        "Full Fake-IP pool must return SERVFAIL and never fall back to real DNS"
    );
}

#[tokio::test]
async fn live_profile_replacement_reapplies_interception_and_flushes_dns_cache_on_start_and_stop() {
    let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
    constants.network.default_relay_tcp_port = 0;
    constants.network.default_transparent_tcp_port = 0;
    constants.network.default_dns_listen_port = 0;
    constants.network.default_local_name_inspect_port = 0;
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.security_policy.kill_switch_enabled = false;

    let controller = RouteWardController::new(constants, profile.clone(), "en");
    controller.start_engine();
    assert!(controller.is_running());

    let mut updated_profile = profile;
    updated_profile.security_policy.kill_switch_enabled = true;
    updated_profile.security_policy.block_encrypted_dns_bypass = false;
    controller.replace_profile(updated_profile);

    let logs = controller.telemetry.list_logs();
    assert!(
        logs.iter().any(|l| l.level == LogLevel::Info
            && l.component == COMPONENT_ENGINE
            && l.message
                .contains("Reapplied active interception rules and proxy bootstrap")),
        "Expected live interception reload INFO log, got: {:?}",
        logs
    );

    controller.stop_engine();
    assert!(!controller.is_running());
}

#[tokio::test]
async fn forward_udp_datagram_evaluates_rules_per_datagram_and_enforces_fragmentation_and_kill_switch(
) {
    use crate::config::{PortRange, ProxyProtocol, RoutingRule, RuleAction, TransportProtocol};
    use crate::proxy::udp::{decode_socks5_udp_datagram, encode_socks5_udp_datagram};

    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let proto_consts = constants.protocols.clone();

    // 1. Direct UDP echo server
    let direct_echo = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind direct echo");
    let direct_echo_addr = direct_echo.local_addr().expect("direct echo addr");
    let _direct_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = direct_echo.recv_from(&mut buf).await {
            let mut reply = b"DIRECT:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = direct_echo.send_to(&reply, peer).await;
        }
    });

    // 2. Mock SOCKS5 UDP relay + TCP control server that records ATYP and echoes "PROXIED:" + payload
    let socks_udp = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind socks udp"),
    );
    let socks_udp_addr = socks_udp.local_addr().expect("socks udp addr");
    let last_atyp = Arc::new(parking_lot::Mutex::new(String::new()));
    let last_atyp_bg = last_atyp.clone();
    let socks_udp_bg = socks_udp.clone();
    let proto_bg = proto_consts.clone();
    let _socks_udp_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = socks_udp_bg.recv_from(&mut buf).await {
            if let Ok((target, payload)) = decode_socks5_udp_datagram(&buf[..n], &proto_bg) {
                *last_atyp_bg.lock() = match &target {
                    Socks5UdpTarget::Domain(dom, port) => format!("Domain({dom}:{port})"),
                    Socks5UdpTarget::Ipv4(ip, port) => format!("Ipv4({ip}:{port})"),
                    Socks5UdpTarget::Ipv6(ip, port) => format!("Ipv6({ip}:{port})"),
                };
                let mut echoed = b"PROXIED:".to_vec();
                echoed.extend_from_slice(payload);
                if let Ok(enc) = encode_socks5_udp_datagram(&target, &echoed, &proto_bg) {
                    let _ = socks_udp_bg.send_to(&enc, peer).await;
                }
            }
        }
    });

    let socks_tcp = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind socks tcp");
    let socks_tcp_addr = socks_tcp.local_addr().expect("socks tcp addr");
    let _socks_tcp_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = socks_tcp.accept().await {
            let relay_port = socks_udp_addr.port();
            tokio::spawn(async move {
                let mut g = [0u8; 2];
                if stream.read_exact(&mut g).await.is_err() {
                    return;
                }
                let mut m = vec![0u8; g[1] as usize];
                let _ = stream.read_exact(&mut m).await;
                let _ = stream.write_all(&[0x05, 0x00]).await;

                let mut h = [0u8; 4];
                if stream.read_exact(&mut h).await.is_err() {
                    return;
                }
                let mut tail = [0u8; 6];
                let _ = stream.read_exact(&mut tail).await;
                let pb = relay_port.to_be_bytes();
                let _ = stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, pb[0], pb[1]])
                    .await;
                let mut eof = [0u8; 16];
                let _ = stream.read(&mut eof).await;
            });
        }
    });

    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.security_policy.kill_switch_enabled = true;
    profile.proxies = vec![ProxyNode {
        id: "socks-udp-1".to_string(),
        name: "SOCKS5 UDP Node".to_string(),
        protocol: ProxyProtocol::Socks5,
        host: "127.0.0.1".to_string(),
        port: socks_tcp_addr.port(),
        auth: None,
        tls: false,
        tls_skip_verify: false,
        sni: None,
        udp_enabled: true,
        enabled: true,
        last_latency_ms: None,
        exit_ip: None,
    }];
    profile.rules = vec![
        RoutingRule {
            id: "rule-udp-proxy-domain".to_string(),
            name: "Proxy UDP Domain".to_string(),
            enabled: true,
            priority: 1,
            process_patterns: vec![],
            domain_patterns: vec!["*.proxied.routeward.test".to_string()],
            ip_cidrs: vec![],
            port_ranges: vec![],
            protocol: TransportProtocol::Udp,
            action: RuleAction::Proxy {
                target_id: "socks-udp-1".to_string(),
            },
        },
        RoutingRule {
            id: "rule-udp-direct".to_string(),
            name: "Direct UDP Port".to_string(),
            enabled: true,
            priority: 2,
            process_patterns: vec![],
            domain_patterns: vec![],
            ip_cidrs: vec![],
            port_ranges: vec![PortRange {
                start: direct_echo_addr.port(),
                end: direct_echo_addr.port(),
            }],
            protocol: TransportProtocol::Udp,
            action: RuleAction::Direct,
        },
    ];
    profile.default_action = RuleAction::Block;

    let controller = RouteWardController::new(constants, profile, "en");
    let fake_ip = controller
        .dns
        .allocate_or_get("echo.proxied.routeward.test")
        .expect("allocate fake ip");

    let client_sock: SocketAddr = "127.0.0.1:54321".parse().expect("client_sock");
    let proxied_target = Socks5UdpTarget::Ipv4(fake_ip, 9999);
    let direct_target = match direct_echo_addr {
        SocketAddr::V4(v4) => Socks5UdpTarget::Ipv4(*v4.ip(), v4.port()),
        SocketAddr::V6(v6) => Socks5UdpTarget::Ipv6(*v6.ip(), v6.port()),
    };

    // Same client socket -> Destination 1 (Fake-IP for echo.proxied.routeward.test:9999) -> Proxied with ATYP=0x03 Domain
    let reply1 = controller
        .forward_udp_datagram(
            client_sock,
            "udp-client",
            Some("/bin/udp-client"),
            4242,
            &proxied_target,
            b"hello-proxy",
            false,
        )
        .await
        .expect("proxied datagram should succeed");
    assert_eq!(reply1, b"PROXIED:hello-proxy");
    assert_eq!(
        *last_atyp.lock(),
        "Domain(echo.proxied.routeward.test:9999)"
    );

    // Same client socket -> Destination 2 (direct_echo_addr) -> Direct
    let reply2 = controller
        .forward_udp_datagram(
            client_sock,
            "udp-client",
            Some("/bin/udp-client"),
            4242,
            &direct_target,
            b"hello-direct",
            false,
        )
        .await
        .expect("direct datagram should succeed");
    assert_eq!(reply2, b"DIRECT:hello-direct");

    // Fragmented datagram whose rule is Proxy -> Blocked when Kill-Switch is active, counter incremented
    let frag_proxy_res = controller
        .forward_udp_datagram(
            client_sock,
            "udp-client",
            Some("/bin/udp-client"),
            4242,
            &proxied_target,
            b"frag-proxy",
            true,
        )
        .await;
    assert!(frag_proxy_res.is_err());
    assert_eq!(controller.fragmented_udp_drop_count(), 1);

    // Fragmented datagram whose rule is Direct -> Passes
    let frag_direct_reply = controller
        .forward_udp_datagram(
            client_sock,
            "udp-client",
            Some("/bin/udp-client"),
            4242,
            &direct_target,
            b"frag-direct",
            true,
        )
        .await
        .expect("fragmented direct datagram should pass");
    assert_eq!(frag_direct_reply, b"DIRECT:frag-direct");
}

#[tokio::test]
async fn udp_direct_fake_ip_resolves_real_ip_and_reinjects_reply_from_fake_ip() {
    use crate::dns::codec::{build_a_response, parse_dns_query};
    use crate::interceptor::nat::{build_forged_ipv4_udp_reply, parse_ipv4_udp_meta};

    // 1. Poisoned DNS resolver returning a cached Fake-IP (simulating local Windows AD dns.exe cache)
    let poisoned_dns = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind poisoned dns");
    let poisoned_dns_addr = poisoned_dns.local_addr().expect("poisoned dns addr");
    let _poisoned_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = poisoned_dns.recv_from(&mut buf).await {
            if let Ok(q) = parse_dns_query(&buf[..n]) {
                let resp = build_a_response(&q, Ipv4Addr::new(198, 18, 99, 99), 60);
                let _ = poisoned_dns.send_to(&resp, peer).await;
            }
        }
    });

    // 2. Clean upstream DNS resolver returning the real IPv4 address (127.0.0.1)
    let real_dns = UdpSocket::bind("127.0.0.1:0").await.expect("bind real dns");
    let real_dns_addr = real_dns.local_addr().expect("real dns addr");
    let _real_dns_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = real_dns.recv_from(&mut buf).await {
            if let Ok(q) = parse_dns_query(&buf[..n]) {
                let resp = build_a_response(&q, Ipv4Addr::LOCALHOST, 60);
                let _ = real_dns.send_to(&resp, peer).await;
            }
        }
    });

    // 3. Real UDP target server on 127.0.0.1:<port>
    let real_udp_server = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind real udp server");
    let real_udp_addr = real_udp_server.local_addr().expect("real udp addr");
    let server_received = Arc::new(AtomicUsize::new(0));
    let server_received_bg = server_received.clone();
    let _udp_srv_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = real_udp_server.recv_from(&mut buf).await {
            server_received_bg.fetch_add(1, Ordering::SeqCst);
            let mut reply = b"NTP_REAL_OK:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = real_udp_server.send_to(&reply, peer).await;
        }
    });

    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.default_action = RuleAction::Direct;
    profile.rules.clear();

    let controller = RouteWardController::new(constants, profile, "en");
    *controller.system_resolvers_override.write() = Some(vec![poisoned_dns_addr, real_dns_addr]);

    let fake_ip = controller
        .dns
        .allocate_or_get("time.cloudflare.com")
        .expect("allocate fake_ip");
    assert!(controller.dns.is_in_fake_subnet(&fake_ip));

    let client_ip = Ipv4Addr::new(10, 0, 2, 15);
    let client_port = 55123u16;
    let client_sock = SocketAddr::new(IpAddr::V4(client_ip), client_port);
    let target = Socks5UdpTarget::Ipv4(fake_ip, real_udp_addr.port());

    let reply_payload = controller
        .forward_udp_datagram(
            client_sock,
            "powershell.exe",
            Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            4016,
            &target,
            b"ntp-probe",
            false,
        )
        .await
        .expect("Direct UDP toward Fake-IP must resolve real IP and return reply");

    assert_eq!(reply_payload, b"NTP_REAL_OK:ntp-probe");
    assert_eq!(
        server_received.load(Ordering::SeqCst),
        1,
        "Real UDP server must receive the datagram on its real IPv4 address"
    );

    // Verify reply reinjection packet preserves Fake-IP as source so the client recognizes it
    let forged_reply = build_forged_ipv4_udp_reply(
        fake_ip,
        real_udp_addr.port(),
        client_ip,
        client_port,
        &reply_payload,
    )
    .expect("build_forged_ipv4_udp_reply");
    let reply_meta = parse_ipv4_udp_meta(&forged_reply).expect("parse reply meta");
    assert_eq!(reply_meta.src_ip, fake_ip);
    assert_eq!(reply_meta.src_port, real_udp_addr.port());
    assert_eq!(reply_meta.dst_ip, client_ip);
    assert_eq!(reply_meta.dst_port, client_port);

    // Verify Direct UDP log contains domain and realIp
    let logs = controller.telemetry.list_logs();
    assert!(
        logs.iter().any(|l| l.level == LogLevel::Info
            && l.component == COMPONENT_TRANSPARENT
            && l.message.contains("Routed UDP PID=4016")
            && l.message
                .contains("domain=Some(\"time.cloudflare.com\"), realIp=127.0.0.1")
            && l.message.contains("via DIRECT")),
        "Expected Direct UDP log with domain and realIp, got: {:?}",
        logs
    );
}

#[tokio::test]
async fn udp_direct_fake_ip_resolution_failure_with_killswitch_blocks_and_never_sends_to_fake_ip() {
    use crate::dns::codec::{build_rcode_response, parse_dns_query, RCODE_SERVFAIL};

    // Mock DNS resolver that always returns SERVFAIL (impossible direct resolution)
    let servfail_dns = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind servfail dns");
    let servfail_dns_addr = servfail_dns.local_addr().expect("servfail dns addr");
    let _servfail_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = servfail_dns.recv_from(&mut buf).await {
            if let Ok(q) = parse_dns_query(&buf[..n]) {
                let resp = build_rcode_response(&q, RCODE_SERVFAIL);
                let _ = servfail_dns.send_to(&resp, peer).await;
            }
        }
    });

    let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
    constants.network.tcp_connect_timeout_ms = 200;
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.default_action = RuleAction::Direct;
    profile.security_policy.kill_switch_enabled = true;
    profile.rules.clear();

    let controller = RouteWardController::new(constants, profile, "en");
    *controller.system_resolvers_override.write() = Some(vec![servfail_dns_addr]);

    let fake_ip = controller
        .dns
        .allocate_or_get("unresolvable-direct.routeward.test")
        .expect("allocate fake_ip");

    let client_sock: SocketAddr = "10.0.2.15:55124".parse().expect("client_sock");
    let target = Socks5UdpTarget::Ipv4(fake_ip, 123);

    let res = controller
        .forward_udp_datagram(
            client_sock,
            "powershell.exe",
            Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            4016,
            &target,
            b"ntp-probe",
            false,
        )
        .await;

    assert!(
        res.is_err(),
        "Direct UDP toward Fake-IP with impossible resolution must fail and never send to Fake-IP"
    );

    let conns = controller.telemetry.list_connections();
    assert!(
        conns.iter().any(|c| {
            c.protocol == TransportProtocol::Udp
                && c.target_port == 123
                && c.status == ConnectionStatus::Blocked
                && c.route_label == ROUTE_BLOCK_LABEL
                && c.resolved_domain.as_deref() == Some("unresolvable-direct.routeward.test")
        }),
        "Blocked connection must be recorded when Direct Fake-IP resolution fails: {:?}",
        conns
    );

    let logs = controller.telemetry.list_logs();
    assert!(
        logs.iter().any(|l| l.level == LogLevel::Warn
            && l.message
                .contains("Kill-Switch blocked Direct UDP datagram")),
        "Expected Kill-Switch WARN log on Direct Fake-IP resolution failure, got: {:?}",
        logs
    );
}

#[tokio::test]
async fn final_anti_fake_ip_egress_guard_blocks_tcp_and_udp_on_both_backends() {
    use crate::interceptor::nat::build_forged_ipv4_udp_reply;

    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.default_action = RuleAction::Direct;
    profile.rules.clear();

    let controller = RouteWardController::new(constants, profile, "en");

    // 1. User-space TCP guard (open_outbound_stream & connect_direct_tcp_protected)
    let unmapped_fake_tcp = Ipv4Addr::new(198, 18, 200, 10);
    let tcp_res = controller
        .open_outbound_stream(&RuleAction::Direct, &unmapped_fake_tcp.to_string(), 443)
        .await;
    assert!(
        matches!(tcp_res, Err(RouteWardError::BlockedByPolicy { .. })),
        "TCP Direct to unmapped Fake-IP must be blocked by final egress guard"
    );
    let raw_tcp_res = controller
        .connect_direct_tcp_protected(SocketAddr::new(IpAddr::V4(unmapped_fake_tcp), 80))
        .await;
    assert_eq!(
        raw_tcp_res.expect_err("must reject").kind(),
        std::io::ErrorKind::PermissionDenied
    );

    // 2. User-space UDP guard (send_and_optional_recv_udp_direct_protected & forward_udp_datagram)
    let unmapped_fake_udp = Ipv4Addr::new(198, 18, 200, 11);
    let raw_udp_res = controller
        .send_and_optional_recv_udp_direct_protected(
            b"probe",
            SocketAddr::new(IpAddr::V4(unmapped_fake_udp), 123),
            Duration::from_millis(100),
        )
        .await;
    assert_eq!(
        raw_udp_res.expect_err("must reject").kind(),
        std::io::ErrorKind::PermissionDenied
    );
    let fwd_udp_res = controller
        .forward_udp_datagram(
            "10.0.2.15:54321".parse().unwrap(),
            "test-app",
            None,
            1234,
            &Socks5UdpTarget::Ipv4(unmapped_fake_udp, 123),
            b"probe",
            false,
        )
        .await;
    assert!(
        matches!(fwd_udp_res, Err(RouteWardError::BlockedByPolicy { .. })),
        "UDP Direct to unmapped Fake-IP must be blocked by final egress guard"
    );

    // 3. WinDivert raw packet guard (TCP and UDP outbound packets targeting 198.18.0.0/15)
    let outbound_fake_udp_pkt = build_forged_ipv4_udp_reply(
        Ipv4Addr::new(10, 0, 2, 15),
        54000,
        Ipv4Addr::new(198, 18, 0, 42),
        123,
        b"leak",
    )
    .expect("build udp pkt");
    assert!(
        controller.check_and_block_outbound_fake_ip_packet(
            &outbound_fake_udp_pkt,
            true,
            "WinDivert"
        ),
        "WinDivert outbound packet targeting 198.18.0.42 must be blocked"
    );
    // Inbound reply from Fake-IP to client (is_outbound = false, dst = 10.0.2.15) must NOT be blocked
    let inbound_fake_reply_pkt = build_forged_ipv4_udp_reply(
        Ipv4Addr::new(198, 18, 0, 42),
        123,
        Ipv4Addr::new(10, 0, 2, 15),
        54000,
        b"reply",
    )
    .expect("build reply pkt");
    assert!(
        !controller.check_and_block_outbound_fake_ip_packet(
            &inbound_fake_reply_pkt,
            false,
            "WinDivert"
        ),
        "Inbound reply from Fake-IP to client must be allowed"
    );

    // 4. Nftables raw UDP guard and nftables filter_output ruleset guard
    let nft_raw_err = NftablesInterceptor::send_raw_ipv4_udp_packet(
        std::net::SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 15), 54000),
        std::net::SocketAddrV4::new(Ipv4Addr::new(198, 19, 1, 2), 5355),
        b"probe",
        0x5257,
    )
    .expect_err("Nftables send_raw_ipv4_udp_packet must reject Fake-IP destination");
    assert_eq!(nft_raw_err.kind(), std::io::ErrorKind::PermissionDenied);

    let nft_ruleset =
        NftablesInterceptor::build_nft_table_ruleset("routeward", "output", 21079, 10810, &[]);
    assert!(nft_ruleset.contains("meta mark 21079 ip daddr 198.18.0.0/15 drop"));
    assert!(nft_ruleset.contains("meta mark != 21080 ip daddr 198.18.0.0/15 drop"));

    let logs = controller.telemetry.list_logs();
    assert!(
        logs.iter()
            .any(|l| l.level == LogLevel::Warn && l.message.contains("Fake-IP egress guard")),
        "Expected WARN log from final Fake-IP egress guard, got: {:?}",
        logs
    );
}

#[tokio::test]
async fn ipv6_dual_stack_transparent_tcp_and_udp_interception() {
    // 1. Separate IPv4 + IPV6_V6ONLY=1 listeners coexist on loopback port when IPv6 is available
    let has_ipv6_loopback = std::net::TcpListener::bind("[::1]:0").is_ok();
    let Ok(v4_tcp) = std::net::TcpListener::bind("127.0.0.1:0") else {
        return;
    };
    let shared_port = v4_tcp.local_addr().expect("v4_tcp local_addr").port();
    if has_ipv6_loopback {
        let v6_tcp = RouteWardController::bind_tcp_v6_only(Ipv6Addr::LOCALHOST, shared_port)
            .expect("bind_tcp_v6_only alongside IPv4 listener");
        assert_eq!(v6_tcp.local_addr().expect("v6 local").port(), shared_port);
        drop(v6_tcp);
    }
    drop(v4_tcp);

    let Ok(v4_udp) = std::net::UdpSocket::bind("127.0.0.1:0") else {
        return;
    };
    let shared_udp_port = v4_udp.local_addr().expect("v4_udp local_addr").port();
    if has_ipv6_loopback {
        let v6_udp = RouteWardController::bind_udp_v6_only(Ipv6Addr::LOCALHOST, shared_udp_port)
            .expect("bind_udp_v6_only alongside IPv4 listener");
        assert_eq!(
            v6_udp.local_addr().expect("v6 udp local").port(),
            shared_udp_port
        );
        drop(v6_udp);
    }
    drop(v4_udp);

    // 2. Skip network relay sub-tests gracefully if loopback ::1 is unavailable on host
    let Ok(socks_v6_listener) = TcpListener::bind("[::1]:0").await else {
        return;
    };
    let socks_v6_port = socks_v6_listener
        .local_addr()
        .expect("socks v6 local_addr")
        .port();

    let proxy_task = tokio::spawn(async move {
        let (mut sock, _) = socks_v6_listener.accept().await.expect("accept socks v6");
        let mut greeting = [0u8; 3];
        sock.read_exact(&mut greeting).await.expect("greeting");
        sock.write_all(&[0x05, 0x00]).await.expect("no-auth");
        let mut req_head = [0u8; 4];
        sock.read_exact(&mut req_head).await.expect("req_head");
        // Expect ATYP=0x04 (IPv6 ::1:8443) or ATYP=0x03 (domain)
        match req_head[3] {
            0x04 => {
                let mut addr = [0u8; 16];
                sock.read_exact(&mut addr).await.expect("v6 addr");
            }
            0x03 => {
                let mut dlen = [0u8; 1];
                sock.read_exact(&mut dlen).await.expect("dlen");
                let mut dbuf = vec![0u8; dlen[0] as usize];
                sock.read_exact(&mut dbuf).await.expect("dom");
            }
            other => panic!("Unexpected ATYP {other}"),
        }
        let mut port_buf = [0u8; 2];
        sock.read_exact(&mut port_buf).await.expect("port");
        assert_eq!(u16::from_be_bytes(port_buf), 8443);
        sock.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .expect("connect ok");
        sock.write_all(b"IPV6_TRANSPARENT_OK")
            .await
            .expect("payload");
        let _ = sock.shutdown().await;
    });

    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.proxies = vec![ProxyNode {
        id: "socks-v6".to_string(),
        name: "Local IPv6 SOCKS5".to_string(),
        protocol: ProxyProtocol::Socks5,
        host: "::1".to_string(),
        port: socks_v6_port,
        auth: None,
        udp_enabled: true,
        tls: false,
        tls_skip_verify: false,
        sni: None,
        enabled: true,
        last_latency_ms: None,
        exit_ip: None,
    }];
    profile.rules = vec![RoutingRule {
        id: "direct-v6-udp".to_string(),
        name: "Direct Loopback UDP".to_string(),
        enabled: true,
        priority: 1,
        process_patterns: vec!["udp-test".to_string()],
        domain_patterns: vec![],
        ip_cidrs: vec!["::1/128".to_string()],
        port_ranges: vec![],
        protocol: TransportProtocol::Udp,
        action: RuleAction::Direct,
    }];
    let controller = RouteWardController::new(constants, profile, "en");

    let relay_v6_listener = TcpListener::bind("[::1]:0")
        .await
        .expect("relay v6 listener");
    let relay_v6_port = relay_v6_listener
        .local_addr()
        .expect("relay v6 addr")
        .port();
    let mut client_v6 = TcpStream::connect(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::LOCALHOST,
        relay_v6_port,
        0,
        0,
    )))
    .await
    .expect("connect relay v6");
    let client_v6_peer = client_v6.local_addr().expect("client v6 peer");
    let (server_v6, accepted_v6_peer) = relay_v6_listener.accept().await.expect("accept v6");

    controller.nat_table.insert_session(NatSessionEntry {
        client_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        client_port: client_v6_peer.port(),
        orig_dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        orig_dst_port: 8443,
        pid: 9001,
        process_name: "curl".to_string(),
        process_path: "/usr/bin/curl".to_string(),
        resolution_source: PidResolutionSource::SocketLayer,
        action: RuleAction::Proxy {
            target_id: "socks-v6".to_string(),
        },
        matched_rule_name: "RouteViaV6Proxy".to_string(),
        created_at: Instant::now(),
    });

    let read_task = tokio::spawn(async move {
        let mut out = Vec::new();
        let _ = client_v6.read_to_end(&mut out).await;
        out
    });

    let res = controller
        .handle_transparent_tcp_client(server_v6, accepted_v6_peer)
        .await;
    assert!(res.is_ok(), "IPv6 transparent relay failed: {:?}", res);
    let received = read_task.await.expect("read_task join");
    assert_eq!(received, b"IPV6_TRANSPARENT_OK");
    proxy_task.await.expect("proxy_task join");

    // 3. Direct UDP IPv6 round-trip via acquire_direct_udp_socket(true)
    let udp_v6_echo = UdpSocket::bind("[::1]:0").await.expect("udp v6 echo");
    let echo_port = udp_v6_echo.local_addr().expect("udp v6 echo addr").port();
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 128];
        let (n, peer) = udp_v6_echo.recv_from(&mut buf).await.expect("recv v6 udp");
        assert_eq!(&buf[..n], b"PING_V6");
        udp_v6_echo
            .send_to(b"PONG_V6", peer)
            .await
            .expect("send v6 udp");
    });

    let udp_reply = controller
        .forward_udp_datagram(
            accepted_v6_peer,
            "udp-test",
            Some("/usr/bin/udp-test"),
            9002,
            &Socks5UdpTarget::Ipv6(Ipv6Addr::LOCALHOST, echo_port),
            b"PING_V6",
            false,
        )
        .await
        .expect("IPv6 Direct UDP forward must succeed");
    assert_eq!(udp_reply, b"PONG_V6");
    echo_task.await.expect("echo_task join");
}

#[test]
fn named_profiles_save_list_switch_and_delete() {
    let temp_root = std::env::temp_dir().join(format!(
        "routeward_profiles_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_root).expect("create temp root");
    let temp_profile_path = temp_root
        .join("profile.json")
        .to_string_lossy()
        .into_owned();
    let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
    constants.ipc.windows_profile_path = temp_profile_path.clone();
    constants.ipc.linux_profile_path = temp_profile_path;

    let mut profile_a = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile_a.name = "Work Office".to_string();
    profile_a.profile_id = "work-office".to_string();

    let controller =
        RouteWardController::new_with_log_dir(constants, profile_a, "en", temp_root.join("logs"));
    let summaries = controller
        .save_named_profile(Some("work-office"), Some("Work Office"))
        .expect("save work-office profile");
    assert_eq!(summaries.len(), 1);
    assert!(summaries[0].active);
    assert_eq!(summaries[0].profile_id, "work-office");

    let mut profile_b = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile_b.name = "Home Direct".to_string();
    profile_b.profile_id = "home-direct".to_string();
    profile_b.rules.clear();
    controller.replace_profile(profile_b);
    let summaries = controller
        .save_named_profile(Some("home-direct"), Some("Home Direct"))
        .expect("save home-direct profile");
    assert_eq!(summaries.len(), 2);

    let switched = controller
        .switch_named_profile("work-office")
        .expect("switch to work-office");
    assert_eq!(switched.profile_id, "work-office");
    assert_eq!(controller.profile.read().name, "Work Office");

    assert!(
        controller.delete_named_profile("work-office").is_err(),
        "deleting the currently active profile must fail"
    );

    let after_delete = controller
        .delete_named_profile("home-direct")
        .expect("delete inactive profile");
    assert_eq!(after_delete.len(), 1);
    assert_eq!(after_delete[0].profile_id, "work-office");

    let _ = std::fs::remove_dir_all(&temp_root);
}
