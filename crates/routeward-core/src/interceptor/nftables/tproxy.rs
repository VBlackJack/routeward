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

impl NftablesInterceptor {
    /// Parses a hexadecimal (`0x...`) or decimal `fwmark` token from `ip -4 rule show` output
    /// (stripping any optional `/mask` suffix).
    pub fn parse_fwmark_token(token: &str) -> Option<u32> {
        let head = token.split('/').next()?.trim();
        if let Some(hex) = head.strip_prefix("0x").or_else(|| head.strip_prefix("0X")) {
            u32::from_str_radix(hex, 16).ok()
        } else {
            head.parse::<u32>().ok()
        }
    }

    /// Inspects `ip -4 rule show` output and returns a descriptive conflict error if `spec.rule_priority`,
    /// `spec.fwmark`, or `spec.route_table` is already in use by any existing policy routing rule.
    pub fn detect_ip_rule_conflict(
        ip_rule_stdout: &str,
        spec: TproxyRoutingSpec,
    ) -> Option<String> {
        for raw_line in ip_rule_stdout.lines() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((prio_str, _rest)) = line.split_once(':') {
                if let Ok(prio) = prio_str.trim().parse::<u32>() {
                    if prio == spec.rule_priority {
                        return Some(format!(
                            "ip rule priority {} is already in use: \"{line}\"",
                            spec.rule_priority
                        ));
                    }
                }
            }

            let tokens: Vec<&str> = line.split_whitespace().collect();
            let mut idx = 0;
            while idx + 1 < tokens.len() {
                match tokens[idx] {
                    "fwmark" => {
                        if let Some(mark) = Self::parse_fwmark_token(tokens[idx + 1]) {
                            if mark == spec.fwmark {
                                return Some(format!(
                                    "ip rule fwmark {:#x} ({}) is already in use: \"{line}\"",
                                    spec.fwmark, spec.fwmark
                                ));
                            }
                        }
                        idx += 2;
                    }
                    "lookup" | "table" => {
                        if let Ok(tbl) = tokens[idx + 1].parse::<u32>() {
                            if tbl == spec.route_table {
                                return Some(format!(
                                    "ip rule routing table {} is already referenced: \"{line}\"",
                                    spec.route_table
                                ));
                            }
                        }
                        idx += 2;
                    }
                    _ => {
                        idx += 1;
                    }
                }
            }
        }
        None
    }

    /// Inspects `ip -4 route show table <route_table>` output and returns a descriptive conflict error
    /// if the table already contains any routes.
    pub fn detect_ip_route_table_conflict(
        ip_route_stdout: &str,
        route_table: u32,
    ) -> Option<String> {
        for raw_line in ip_route_stdout.lines() {
            let line = raw_line.trim();
            if !line.is_empty() {
                return Some(format!(
                    "routing table {route_table} is not empty: \"{line}\""
                ));
            }
        }
        None
    }

    /// Builds the exact `ip` CLI arguments to install the `TPROXY` `ip rule`.
    pub fn build_ip_rule_add_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-4".to_string(),
            "rule".to_string(),
            "add".to_string(),
            "fwmark".to_string(),
            spec.fwmark.to_string(),
            "lookup".to_string(),
            spec.route_table.to_string(),
            "priority".to_string(),
            spec.rule_priority.to_string(),
        ]
    }

    /// Builds the exact `ip` CLI arguments to remove the `TPROXY` `ip rule`.
    pub fn build_ip_rule_del_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-4".to_string(),
            "rule".to_string(),
            "del".to_string(),
            "fwmark".to_string(),
            spec.fwmark.to_string(),
            "lookup".to_string(),
            spec.route_table.to_string(),
            "priority".to_string(),
            spec.rule_priority.to_string(),
        ]
    }

    /// Builds the exact `ip` CLI arguments to install the local `0.0.0.0/0 dev lo` route in `spec.route_table`.
    pub fn build_ip_route_add_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-4".to_string(),
            "route".to_string(),
            "add".to_string(),
            "local".to_string(),
            "0.0.0.0/0".to_string(),
            "dev".to_string(),
            "lo".to_string(),
            "table".to_string(),
            spec.route_table.to_string(),
        ]
    }

    /// Builds the exact `ip` CLI arguments to remove the local `0.0.0.0/0 dev lo` route from `spec.route_table`.
    pub fn build_ip_route_del_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-4".to_string(),
            "route".to_string(),
            "del".to_string(),
            "local".to_string(),
            "0.0.0.0/0".to_string(),
            "dev".to_string(),
            "lo".to_string(),
            "table".to_string(),
            spec.route_table.to_string(),
        ]
    }

    /// Builds the exact `ip -6` CLI arguments to install the IPv6 `TPROXY` `ip rule`.
    pub fn build_ip6_rule_add_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-6".to_string(),
            "rule".to_string(),
            "add".to_string(),
            "fwmark".to_string(),
            spec.fwmark.to_string(),
            "lookup".to_string(),
            spec.route_table.to_string(),
            "priority".to_string(),
            spec.rule_priority.to_string(),
        ]
    }

    /// Builds the exact `ip -6` CLI arguments to remove the IPv6 `TPROXY` `ip rule`.
    pub fn build_ip6_rule_del_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-6".to_string(),
            "rule".to_string(),
            "del".to_string(),
            "fwmark".to_string(),
            spec.fwmark.to_string(),
            "lookup".to_string(),
            spec.route_table.to_string(),
            "priority".to_string(),
            spec.rule_priority.to_string(),
        ]
    }

    /// Builds the exact `ip -6` CLI arguments to install the local `::/0 dev lo` route in `spec.route_table`.
    pub fn build_ip6_route_add_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-6".to_string(),
            "route".to_string(),
            "add".to_string(),
            "local".to_string(),
            "::/0".to_string(),
            "dev".to_string(),
            "lo".to_string(),
            "table".to_string(),
            spec.route_table.to_string(),
        ]
    }

    /// Builds the exact `ip -6` CLI arguments to remove the local `::/0 dev lo` route from `spec.route_table`.
    pub fn build_ip6_route_del_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-6".to_string(),
            "route".to_string(),
            "del".to_string(),
            "local".to_string(),
            "::/0".to_string(),
            "dev".to_string(),
            "lo".to_string(),
            "table".to_string(),
            spec.route_table.to_string(),
        ]
    }

    /// Removes the exact `TPROXY` `ip rule` and local route on `lo` installed by RouteWard.
    pub fn delete_tproxy_routing(
        ip_binary: &str,
        spec: TproxyRoutingSpec,
        telemetry: &TelemetryHub,
    ) {
        let rule_del_args = Self::build_ip_rule_del_args(spec);
        if let Ok(out) = Command::new(ip_binary)
            .args(&rule_del_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            if out.status.success() {
                telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_NFTABLES,
                    format!(
                        "Removed TPROXY ip rule (fwmark={:#x}, table={}, priority={})",
                        spec.fwmark, spec.route_table, spec.rule_priority
                    ),
                );
            }
        }

        let route_del_args = Self::build_ip_route_del_args(spec);
        if let Ok(out) = Command::new(ip_binary)
            .args(&route_del_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            if out.status.success() {
                telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_NFTABLES,
                    format!(
                        "Removed TPROXY local route (local 0.0.0.0/0 dev lo table {})",
                        spec.route_table
                    ),
                );
            }
        }

        let _ = Command::new(ip_binary)
            .args(Self::build_ip6_rule_del_args(spec))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output();
        let _ = Command::new(ip_binary)
            .args(Self::build_ip6_route_del_args(spec))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output();
    }

    #[cfg(target_os = "linux")]
    pub(super) fn check_and_install_tproxy_routing(
        ip_binary: &str,
        spec: TproxyRoutingSpec,
        telemetry: &TelemetryHub,
        i18n: &crate::i18n::I18nRegistry,
    ) -> RouteWardResult<()> {
        let rule_show = Command::new(ip_binary)
            .args(["-4", "rule", "show"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("Failed to execute {ip_binary} -4 rule show: {err}"),
            })?;
        if !rule_show.status.success() {
            let stderr = String::from_utf8_lossy(&rule_show.stderr)
                .trim()
                .to_string();
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("{ip_binary} -4 rule show failed: {stderr}"),
            });
        }
        let rule_stdout = String::from_utf8_lossy(&rule_show.stdout);
        if let Some(conflict) = Self::detect_ip_rule_conflict(&rule_stdout, spec) {
            let detail = format!(
                "{}: {conflict}",
                i18n.t_english(ERR_KEY_INTERCEPTOR_TPROXY_CONFLICT)
            );
            telemetry.push_log(LogLevel::Error, COMPONENT_NFTABLES, detail.clone());
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_TPROXY_CONFLICT,
                detail,
            });
        }

        let route_show = Command::new(ip_binary)
            .args([
                "-4",
                "route",
                "show",
                "table",
                &spec.route_table.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!(
                    "Failed to execute {ip_binary} -4 route show table {}: {err}",
                    spec.route_table
                ),
            })?;
        if route_show.status.success() {
            let route_stdout = String::from_utf8_lossy(&route_show.stdout);
            if let Some(conflict) =
                Self::detect_ip_route_table_conflict(&route_stdout, spec.route_table)
            {
                let detail = format!(
                    "{}: {conflict}",
                    i18n.t_english(ERR_KEY_INTERCEPTOR_TPROXY_CONFLICT)
                );
                telemetry.push_log(LogLevel::Error, COMPONENT_NFTABLES, detail.clone());
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_TPROXY_CONFLICT,
                    detail,
                });
            }
        }

        let rule_add_args = Self::build_ip_rule_add_args(spec);
        let rule_add_out = Command::new(ip_binary)
            .args(&rule_add_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("Failed to execute {ip_binary} rule add: {err}"),
            })?;
        if !rule_add_out.status.success() {
            let stderr = String::from_utf8_lossy(&rule_add_out.stderr)
                .trim()
                .to_string();
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("{ip_binary} -4 rule add failed: {stderr}"),
            });
        }

        let route_add_args = Self::build_ip_route_add_args(spec);
        let route_add_out = Command::new(ip_binary)
            .args(&route_add_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        match route_add_out {
            Ok(out) if out.status.success() => {
                telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_NFTABLES,
                    format!(
                        "Installed TPROXY policy routing (fwmark={:#x}, table={}, priority={}, tproxy_port={})",
                        spec.fwmark, spec.route_table, spec.rule_priority, spec.tproxy_port
                    ),
                );
                // Best-effort IPv6 TPROXY routing: install ip -6 rule & local ::/0 route if IPv6 is enabled on kernel
                let ip6_rule_ok = Command::new(ip_binary)
                    .args(Self::build_ip6_rule_add_args(spec))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if ip6_rule_ok {
                    let ip6_route_ok = Command::new(ip_binary)
                        .args(Self::build_ip6_route_add_args(spec))
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                    if !ip6_route_ok {
                        let _ = Command::new(ip_binary)
                            .args(Self::build_ip6_rule_del_args(spec))
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .output();
                        telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_NFTABLES,
                            format!(
                                "IPv6 TPROXY route (local ::/0 table {}) unavailable on this kernel; continuing with IPv4 TPROXY",
                                spec.route_table
                            ),
                        );
                    }
                }
                Ok(())
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                let _ = Command::new(ip_binary)
                    .args(Self::build_ip_rule_del_args(spec))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .output();
                Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!(
                        "{ip_binary} -4 route add local 0.0.0.0/0 dev lo table {} failed: {stderr}",
                        spec.route_table
                    ),
                })
            }
            Err(err) => {
                let _ = Command::new(ip_binary)
                    .args(Self::build_ip_rule_del_args(spec))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .output();
                Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("Failed invoking {ip_binary} route add: {err}"),
                })
            }
        }
    }

    /// Pure parser converting raw `sockaddr_in` fields (network byte order) into `SocketAddrV4`.
    pub fn parse_sockaddr_in_fields(
        sin_family: u16,
        sin_port_be: u16,
        sin_addr_be: u32,
        relay_port: u16,
    ) -> Option<SocketAddrV4> {
        if sin_family != AF_INET_U16 {
            return None;
        }
        let port = u16::from_be(sin_port_be);
        let ip = Ipv4Addr::from(u32::from_be(sin_addr_be));
        if port == 0 {
            return None;
        }
        // Reject direct unredirected connections whose original destination is the local relay itself
        if ip.is_loopback() && port == relay_port {
            return None;
        }
        Some(SocketAddrV4::new(ip, port))
    }

    /// Queries `getsockopt(SOL_IP, SO_ORIGINAL_DST)` on an accepted Linux TCP stream.
    #[cfg(target_os = "linux")]
    pub fn query_original_dst(
        stream: &tokio::net::TcpStream,
        relay_port: u16,
    ) -> Option<SocketAddrV4> {
        use std::os::fd::AsRawFd;

        let fd = stream.as_raw_fd();
        let mut raw_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addr_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                &mut raw_addr as *mut libc::sockaddr_in as *mut libc::c_void,
                &mut addr_len,
            )
        };
        if ret != 0 {
            return None;
        }

        Self::parse_sockaddr_in_fields(
            raw_addr.sin_family,
            raw_addr.sin_port,
            raw_addr.sin_addr.s_addr,
            relay_port,
        )
    }

    #[cfg(not(target_os = "linux"))]
    pub fn query_original_dst(
        _stream: &tokio::net::TcpStream,
        _relay_port: u16,
    ) -> Option<SocketAddrV4> {
        None
    }

    /// Parses raw `sockaddr_in6` fields returned by `IP6T_SO_ORIGINAL_DST` and rejects
    /// loopback connections targeting `relay_port` directly without NAT redirection.
    pub fn parse_sockaddr_in6_fields(
        sin6_family: u16,
        sin6_port_be: u16,
        sin6_addr: [u8; 16],
        relay_port: u16,
    ) -> Option<SocketAddrV6> {
        if sin6_family != AF_INET6_U16 {
            return None;
        }
        let port = u16::from_be(sin6_port_be);
        if port == 0 {
            return None;
        }
        let ip = Ipv6Addr::from(sin6_addr);
        if ip.is_loopback() && port == relay_port {
            return None;
        }
        Some(SocketAddrV6::new(ip, port, 0, 0))
    }

    /// Queries `SO_ORIGINAL_DST` (IPv4) or `IP6T_SO_ORIGINAL_DST` (IPv6) on an accepted Linux TCP stream.
    #[cfg(target_os = "linux")]
    pub fn query_original_dst_any(
        stream: &tokio::net::TcpStream,
        relay_port: u16,
    ) -> Option<SocketAddr> {
        if let Some(v4) = Self::query_original_dst(stream, relay_port) {
            return Some(SocketAddr::V4(v4));
        }
        use std::os::fd::AsRawFd;

        let fd = stream.as_raw_fd();
        let mut raw_addr6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut addr_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                libc::IP6T_SO_ORIGINAL_DST,
                &mut raw_addr6 as *mut libc::sockaddr_in6 as *mut libc::c_void,
                &mut addr_len,
            )
        };
        if ret != 0 {
            return None;
        }

        Self::parse_sockaddr_in6_fields(
            raw_addr6.sin6_family,
            raw_addr6.sin6_port,
            raw_addr6.sin6_addr.s6_addr,
            relay_port,
        )
        .map(SocketAddr::V6)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn query_original_dst_any(
        _stream: &tokio::net::TcpStream,
        _relay_port: u16,
    ) -> Option<SocketAddr> {
        None
    }

    /// Immediately resets (`TCP RST`) an accepted connection via `SO_LINGER(1, 0)` and closes it.
    #[cfg(target_os = "linux")]
    pub fn reset_and_close_tcp_stream(stream: tokio::net::TcpStream) {
        use std::os::fd::AsRawFd;

        let fd = stream.as_raw_fd();
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const libc::linger as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            );
        }
        drop(stream);
    }

    #[cfg(not(target_os = "linux"))]
    pub fn reset_and_close_tcp_stream(stream: tokio::net::TcpStream) {
        drop(stream);
    }

    #[cfg(target_os = "linux")]
    pub fn enable_udp_pktinfo(sock: &tokio::net::UdpSocket) {
        use std::os::fd::AsRawFd;
        let fd = sock.as_raw_fd();
        let on: libc::c_int = 1;
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                &on as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn enable_udp_pktinfo(_sock: &tokio::net::UdpSocket) {}

    #[cfg(target_os = "linux")]
    pub async fn recv_udp_with_local_ip(
        sock: &tokio::net::UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, std::net::SocketAddr, Option<Ipv4Addr>)> {
        use std::os::fd::AsRawFd;
        sock.async_io(tokio::io::Interest::READABLE, || {
            let fd = sock.as_raw_fd();
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut src_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut cmsg_space = [0u8; 64];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut src_addr as *mut libc::sockaddr_in as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_space.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_space.len();

            let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }

            let peer_ip = Ipv4Addr::from(u32::from_be(src_addr.sin_addr.s_addr));
            let peer_port = u16::from_be(src_addr.sin_port);
            let peer = std::net::SocketAddr::V4(SocketAddrV4::new(peer_ip, peer_port));

            let mut local_dst_ip: Option<Ipv4Addr> = None;
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::IPPROTO_IP
                        && (*cmsg).cmsg_type == libc::IP_PKTINFO
                    {
                        let pktinfo_ptr = libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo;
                        let pktinfo = std::ptr::read_unaligned(pktinfo_ptr);
                        local_dst_ip = Some(Ipv4Addr::from(u32::from_be(pktinfo.ipi_addr.s_addr)));
                        break;
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }

            Ok((n as usize, peer, local_dst_ip))
        })
        .await
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn recv_udp_with_local_ip(
        sock: &tokio::net::UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, std::net::SocketAddr, Option<Ipv4Addr>)> {
        let (len, peer) = sock.recv_from(buf).await?;
        Ok((len, peer, None))
    }

    #[cfg(target_os = "linux")]
    pub async fn send_udp_from_local_ip(
        sock: &tokio::net::UdpSocket,
        payload: &[u8],
        peer: std::net::SocketAddr,
        local_src_ip: Option<Ipv4Addr>,
    ) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd;
        let std::net::SocketAddr::V4(peer_v4) = peer else {
            return sock.send_to(payload, peer).await;
        };
        let Some(src_ip) = local_src_ip else {
            return sock.send_to(payload, peer).await;
        };

        sock.async_io(tokio::io::Interest::WRITABLE, || {
            let fd = sock.as_raw_fd();
            let mut iov = libc::iovec {
                iov_base: payload.as_ptr() as *mut libc::c_void,
                iov_len: payload.len(),
            };
            let mut dst_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            dst_addr.sin_family = libc::AF_INET as libc::sa_family_t;
            dst_addr.sin_port = peer_v4.port().to_be();
            dst_addr.sin_addr = libc::in_addr {
                s_addr: u32::from(*peer_v4.ip()).to_be(),
            };

            let cmsg_len =
                unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) }
                    as usize;
            let mut cmsg_space = vec![0u8; cmsg_len];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut dst_addr as *mut libc::sockaddr_in as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_space.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_len;

            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                if !cmsg.is_null() {
                    (*cmsg).cmsg_level = libc::IPPROTO_IP;
                    (*cmsg).cmsg_type = libc::IP_PKTINFO;
                    (*cmsg).cmsg_len =
                        libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize;
                    let pktinfo = libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: libc::in_addr {
                            s_addr: u32::from(src_ip).to_be(),
                        },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    std::ptr::write_unaligned(
                        libc::CMSG_DATA(cmsg) as *mut libc::in_pktinfo,
                        pktinfo,
                    );
                }
            }

            let n = unsafe { libc::sendmsg(fd, &msg, 0) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(n as usize)
        })
        .await
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn send_udp_from_local_ip(
        sock: &tokio::net::UdpSocket,
        payload: &[u8],
        peer: std::net::SocketAddr,
        _local_src_ip: Option<Ipv4Addr>,
    ) -> std::io::Result<usize> {
        sock.send_to(payload, peer).await
    }

    #[cfg(target_os = "linux")]
    pub fn enable_ipv6_udp_pktinfo(sock: &tokio::net::UdpSocket) {
        use std::os::fd::AsRawFd;
        let fd = sock.as_raw_fd();
        let on: libc::c_int = 1;
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVPKTINFO,
                &on as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn enable_ipv6_udp_pktinfo(_sock: &tokio::net::UdpSocket) {}

    #[cfg(target_os = "linux")]
    pub async fn recv_udp_v6_with_local_ip(
        sock: &tokio::net::UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, std::net::SocketAddr, Option<Ipv6Addr>)> {
        use std::os::fd::AsRawFd;
        sock.async_io(tokio::io::Interest::READABLE, || {
            let fd = sock.as_raw_fd();
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut src_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            let mut cmsg_space = [0u8; 128];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut src_addr as *mut libc::sockaddr_in6 as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_space.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_space.len();

            let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }

            let peer_ip = Ipv6Addr::from(src_addr.sin6_addr.s6_addr);
            let peer_port = u16::from_be(src_addr.sin6_port);
            let peer = std::net::SocketAddr::V6(SocketAddrV6::new(
                peer_ip,
                peer_port,
                src_addr.sin6_flowinfo,
                src_addr.sin6_scope_id,
            ));

            let mut local_dst_ip: Option<Ipv6Addr> = None;
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::IPPROTO_IPV6
                        && (*cmsg).cmsg_type == libc::IPV6_PKTINFO
                    {
                        let pktinfo_ptr = libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo;
                        let pktinfo = std::ptr::read_unaligned(pktinfo_ptr);
                        local_dst_ip = Some(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr));
                        break;
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }

            Ok((n as usize, peer, local_dst_ip))
        })
        .await
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn recv_udp_v6_with_local_ip(
        sock: &tokio::net::UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, std::net::SocketAddr, Option<Ipv6Addr>)> {
        let (len, peer) = sock.recv_from(buf).await?;
        Ok((len, peer, None))
    }

    #[cfg(target_os = "linux")]
    pub async fn send_udp_v6_from_local_ip(
        sock: &tokio::net::UdpSocket,
        payload: &[u8],
        peer: std::net::SocketAddr,
        local_src_ip: Option<Ipv6Addr>,
    ) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd;
        let std::net::SocketAddr::V6(peer_v6) = peer else {
            return sock.send_to(payload, peer).await;
        };
        let Some(src_ip) = local_src_ip else {
            return sock.send_to(payload, peer).await;
        };

        sock.async_io(tokio::io::Interest::WRITABLE, || {
            let fd = sock.as_raw_fd();
            let mut iov = libc::iovec {
                iov_base: payload.as_ptr() as *mut libc::c_void,
                iov_len: payload.len(),
            };
            let mut dst_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            dst_addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            dst_addr.sin6_port = peer_v6.port().to_be();
            dst_addr.sin6_flowinfo = peer_v6.flowinfo();
            dst_addr.sin6_scope_id = peer_v6.scope_id();
            dst_addr.sin6_addr = libc::in6_addr {
                s6_addr: peer_v6.ip().octets(),
            };

            let cmsg_len =
                unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) }
                    as usize;
            let mut cmsg_space = vec![0u8; cmsg_len];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut dst_addr as *mut libc::sockaddr_in6 as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_space.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_len;

            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                if !cmsg.is_null() {
                    (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                    (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                    (*cmsg).cmsg_len =
                        libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize;
                    let pktinfo = libc::in6_pktinfo {
                        ipi6_addr: libc::in6_addr {
                            s6_addr: src_ip.octets(),
                        },
                        ipi6_ifindex: 0,
                    };
                    std::ptr::write_unaligned(
                        libc::CMSG_DATA(cmsg) as *mut libc::in6_pktinfo,
                        pktinfo,
                    );
                }
            }

            let n = unsafe { libc::sendmsg(fd, &msg, 0) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(n as usize)
        })
        .await
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn send_udp_v6_from_local_ip(
        sock: &tokio::net::UdpSocket,
        payload: &[u8],
        peer: std::net::SocketAddr,
        _local_src_ip: Option<Ipv6Addr>,
    ) -> std::io::Result<usize> {
        sock.send_to(payload, peer).await
    }

    /// Configures a Linux UDP listener socket with `IP_TRANSPARENT` and `IP_RECVORIGDSTADDR`
    /// so it can receive `TPROXY`-intercepted datagrams and recover their original destination IPv4/port.
    #[cfg(target_os = "linux")]
    pub fn enable_udp_tproxy_options(sock: &tokio::net::UdpSocket) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let fd = sock.as_raw_fd();
        let on: libc::c_int = 1;
        unsafe {
            if libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                &on as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_RECVORIGDSTADDR,
                &on as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn enable_udp_tproxy_options(_sock: &tokio::net::UdpSocket) -> std::io::Result<()> {
        Ok(())
    }

    /// Receives a UDP datagram on a `TPROXY` listener socket and extracts `(len, client_addr, orig_dst)`
    /// from the ancillary `IP_ORIGDSTADDR` control message.
    #[cfg(target_os = "linux")]
    pub async fn recv_udp_tproxy_orig_dst(
        sock: &tokio::net::UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddrV4, Option<SocketAddrV4>)> {
        use std::os::fd::AsRawFd;
        sock.async_io(tokio::io::Interest::READABLE, || {
            let fd = sock.as_raw_fd();
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut src_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut cmsg_space = [0u8; 128];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut src_addr as *mut libc::sockaddr_in as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_space.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_space.len();

            let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }

            let peer_ip = Ipv4Addr::from(u32::from_be(src_addr.sin_addr.s_addr));
            let peer_port = u16::from_be(src_addr.sin_port);
            let client_addr = SocketAddrV4::new(peer_ip, peer_port);

            let mut orig_dst: Option<SocketAddrV4> = None;
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::SOL_IP
                        && (*cmsg).cmsg_type == libc::IP_ORIGDSTADDR
                    {
                        let data_ptr = libc::CMSG_DATA(cmsg);
                        let data_slice = std::slice::from_raw_parts(
                            data_ptr,
                            std::mem::size_of::<libc::sockaddr_in>(),
                        );
                        orig_dst =
                            crate::interceptor::nat::parse_ipv4_origdstaddr_bytes(data_slice);
                        break;
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }

            Ok((n as usize, client_addr, orig_dst))
        })
        .await
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn recv_udp_tproxy_orig_dst(
        sock: &tokio::net::UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddrV4, Option<SocketAddrV4>)> {
        let (len, peer) = sock.recv_from(buf).await?;
        let client_v4 = match peer {
            std::net::SocketAddr::V4(v4) => v4,
            std::net::SocketAddr::V6(_) => SocketAddrV4::new(Ipv4Addr::LOCALHOST, peer.port()),
        };
        Ok((len, client_v4, None))
    }

    /// Enables `IPV6_TRANSPARENT` and `IPV6_RECVORIGDSTADDR` on a bound Linux IPv6 UDP TPROXY socket
    /// (`IPV6_V6ONLY` must already be configured prior to `bind()`).
    #[cfg(target_os = "linux")]
    pub fn enable_udp_tproxy_v6_options(sock: &tokio::net::UdpSocket) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let fd = sock.as_raw_fd();
        let on: libc::c_int = 1;
        unsafe {
            if libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                libc::IPV6_TRANSPARENT,
                &on as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                libc::IPV6_RECVORIGDSTADDR,
                &on as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn enable_udp_tproxy_v6_options(_sock: &tokio::net::UdpSocket) -> std::io::Result<()> {
        Ok(())
    }

    /// Receives an IPv6 UDP datagram on a `TPROXY` listener socket and extracts
    /// `(len, client_addr, orig_dst)` from the ancillary `IPV6_ORIGDSTADDR` control message.
    #[cfg(target_os = "linux")]
    pub async fn recv_udp_tproxy_v6_orig_dst(
        sock: &tokio::net::UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddrV6, Option<SocketAddrV6>)> {
        use std::os::fd::AsRawFd;
        sock.async_io(tokio::io::Interest::READABLE, || {
            let fd = sock.as_raw_fd();
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut src_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            let mut cmsg_space = [0u8; 256];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut src_addr as *mut libc::sockaddr_in6 as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_space.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_space.len();

            let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }

            let peer_ip = Ipv6Addr::from(src_addr.sin6_addr.s6_addr);
            let peer_port = u16::from_be(src_addr.sin6_port);
            let client_addr = SocketAddrV6::new(
                peer_ip,
                peer_port,
                src_addr.sin6_flowinfo,
                src_addr.sin6_scope_id,
            );

            let mut orig_dst: Option<SocketAddrV6> = None;
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::SOL_IPV6
                        && (*cmsg).cmsg_type == libc::IPV6_ORIGDSTADDR
                    {
                        let data_ptr = libc::CMSG_DATA(cmsg);
                        let data_slice = std::slice::from_raw_parts(
                            data_ptr,
                            std::mem::size_of::<libc::sockaddr_in6>(),
                        );
                        orig_dst =
                            crate::interceptor::nat::parse_ipv6_origdstaddr_bytes(data_slice);
                        break;
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }

            Ok((n as usize, client_addr, orig_dst))
        })
        .await
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn recv_udp_tproxy_v6_orig_dst(
        sock: &tokio::net::UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddrV6, Option<SocketAddrV6>)> {
        let (len, peer) = sock.recv_from(buf).await?;
        let client_v6 = match peer {
            SocketAddr::V6(v6) => v6,
            SocketAddr::V4(_) => SocketAddrV6::new(Ipv6Addr::LOCALHOST, peer.port(), 0, 0),
        };
        Ok((len, client_v6, None))
    }

    /// Resolves the effective Fake-IP network: the profile CIDR first, then the system constant,
    /// then the RFC 2544 default. Mirrors the resolution order of the DNS Fake-IP engine.
    pub fn resolve_fake_ip_net(profile_cidr: &str, constants_cidr: &str) -> Ipv4Net {
        profile_cidr
            .parse::<Ipv4Net>()
            .or_else(|_| constants_cidr.parse::<Ipv4Net>())
            .unwrap_or_else(|_| ruleset::default_fake_ip_net())
    }

    /// Sets the Fake-IP network enforced by the raw-socket egress guard.
    pub fn set_fake_ip_guard_net(net: Ipv4Net) {
        *FAKE_IP_GUARD_NET.write() = Some(net);
    }

    /// Returns the Fake-IP network enforced by the raw-socket egress guard
    /// (RFC 2544 `198.18.0.0/15` until a configured network is set).
    pub fn fake_ip_guard_net() -> Ipv4Net {
        FAKE_IP_GUARD_NET
            .read()
            .unwrap_or_else(ruleset::default_fake_ip_net)
    }

    /// Returns `true` if `ip` belongs to the given Fake-IP network.
    pub fn is_fake_ip_in(ip: Ipv4Addr, net: Ipv4Net) -> bool {
        net.contains(&ip)
    }

    /// Returns `true` if `ip` belongs to the currently configured Fake-IP network.
    pub fn is_rfc2544_fake_ip(ip: Ipv4Addr) -> bool {
        Self::is_fake_ip_in(ip, Self::fake_ip_guard_net())
    }

    /// Final egress guard: refuses raw packets addressed to an untranslated Fake-IP in `net`.
    pub(super) fn check_fake_ip_egress(dst: SocketAddrV4, net: Ipv4Net) -> std::io::Result<()> {
        if Self::is_fake_ip_in(*dst.ip(), net) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Final Fake-IP egress guard blocked raw UDP packet to untranslated Fake-IP destination {dst}"
                ),
            ));
        }
        Ok(())
    }

    /// Emits a raw IPv4 + UDP datagram (`src -> dst`) using `SOCK_RAW` + `IP_HDRINCL` + `SO_MARK`
    /// so replies to `TPROXY`-intercepted clients (and authorized local LLMNR/mDNS queries) preserve
    /// the exact source IPv4 address and source port without re-triggering `TPROXY`.
    #[cfg(target_os = "linux")]
    pub fn send_raw_ipv4_udp_packet(
        src: SocketAddrV4,
        dst: SocketAddrV4,
        payload: &[u8],
        fwmark: u32,
    ) -> std::io::Result<usize> {
        Self::check_fake_ip_egress(dst, Self::fake_ip_guard_net())?;

        let raw_pkt = crate::interceptor::nat::build_forged_ipv4_udp_reply(
            *src.ip(),
            src.port(),
            *dst.ip(),
            dst.port(),
            payload,
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP payload too large for IPv4 packet",
            )
        })?;

        let mut dst_sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        dst_sin.sin_family = libc::AF_INET as libc::sa_family_t;
        dst_sin.sin_port = dst.port().to_be();
        dst_sin.sin_addr = libc::in_addr {
            s_addr: u32::from(*dst.ip()).to_be(),
        };

        RAW_UDP_V4_SOCKETS.send_with_retry(
            fwmark,
            || create_raw_udp_socket(RawUdpFamily::V4, fwmark),
            |sock| {
                raw_sendto(
                    sock,
                    &raw_pkt,
                    &dst_sin as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            },
        )
    }

    #[cfg(not(target_os = "linux"))]
    pub fn send_raw_ipv4_udp_packet(
        _src: SocketAddrV4,
        dst: SocketAddrV4,
        _payload: &[u8],
        _fwmark: u32,
    ) -> std::io::Result<usize> {
        Self::check_fake_ip_egress(dst, Self::fake_ip_guard_net())?;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "send_raw_ipv4_udp_packet is only supported on Linux",
        ))
    }

    /// Sends an arbitrary forged IPv6 + UDP packet from `src` to `dst` via a marked raw socket.
    #[cfg(target_os = "linux")]
    pub fn send_raw_ipv6_udp_packet(
        src: SocketAddrV6,
        dst: SocketAddrV6,
        payload: &[u8],
        fwmark: u32,
    ) -> std::io::Result<usize> {
        let raw_pkt = crate::interceptor::nat::build_forged_ipv6_udp_reply(
            *src.ip(),
            src.port(),
            *dst.ip(),
            dst.port(),
            payload,
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP payload too large for IPv6 packet",
            )
        })?;

        let mut dst_sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        dst_sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        dst_sin6.sin6_port = 0;
        dst_sin6.sin6_scope_id = dst.scope_id();
        dst_sin6.sin6_addr = libc::in6_addr {
            s6_addr: dst.ip().octets(),
        };

        RAW_UDP_V6_SOCKETS.send_with_retry(
            fwmark,
            || create_raw_udp_socket(RawUdpFamily::V6, fwmark),
            |sock| {
                raw_sendto(
                    sock,
                    &raw_pkt,
                    &dst_sin6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            },
        )
    }

    #[cfg(not(target_os = "linux"))]
    pub fn send_raw_ipv6_udp_packet(
        _src: SocketAddrV6,
        _dst: SocketAddrV6,
        _payload: &[u8],
        _fwmark: u32,
    ) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "send_raw_ipv6_udp_packet is only supported on Linux",
        ))
    }
}

/// Linux `IPV6_HDRINCL` socket option value (not exported by the `libc` crate).
#[cfg(target_os = "linux")]
const LINUX_IPV6_HDRINCL: libc::c_int = 36;

/// Maximum number of send attempts for one raw datagram: the first attempt uses the cached socket,
/// the second runs on a freshly created socket after the cached one proved dead.
#[cfg(target_os = "linux")]
const RAW_SEND_MAX_ATTEMPTS: usize = 2;

/// Errno `EBADF` (Linux numbering): the cached descriptor is no longer valid.
#[cfg(target_os = "linux")]
const ERRNO_EBADF: i32 = 9;
/// Errno `ENOTSOCK` (Linux numbering): the cached descriptor is no longer a socket.
#[cfg(target_os = "linux")]
const ERRNO_ENOTSOCK: i32 = 88;
/// Errno `ENETDOWN` (Linux numbering): the socket's network stack went down underneath it.
#[cfg(target_os = "linux")]
const ERRNO_ENETDOWN: i32 = 100;

/// Address family of a cached raw UDP socket.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum RawUdpFamily {
    V4,
    V6,
}

/// Owned raw socket descriptor, closed when the last `Arc` holder drops it.
#[cfg(target_os = "linux")]
struct RawUdpSocket(std::os::fd::OwnedFd);

/// Lazily created raw sockets, one per `SO_MARK` value, shared by all sending tasks.
///
/// `sendto(2)` on a raw socket is safe to call concurrently. Creation happens under the lock so
/// two tasks never race to create duplicates. A socket is dropped from the cache when a send
/// reports that it is dead, and in-flight senders keep their `Arc` so the descriptor is never
/// closed (and reused by the kernel) under them.
#[cfg(target_os = "linux")]
struct RawSocketCache<S> {
    sockets: Mutex<Vec<(u32, Arc<S>)>>,
}

#[cfg(target_os = "linux")]
impl<S> RawSocketCache<S> {
    const fn new() -> Self {
        Self {
            sockets: Mutex::new(Vec::new()),
        }
    }

    /// Returns the cached socket for `fwmark`, creating it with `create` on first use.
    fn get_or_create<F>(&self, fwmark: u32, create: F) -> std::io::Result<Arc<S>>
    where
        F: FnOnce() -> std::io::Result<S>,
    {
        let mut guard = self.sockets.lock();
        if let Some((_, sock)) = guard.iter().find(|(mark, _)| *mark == fwmark) {
            return Ok(Arc::clone(sock));
        }
        let sock = Arc::new(create()?);
        guard.push((fwmark, Arc::clone(&sock)));
        Ok(sock)
    }

    /// Drops the cached entry for `fwmark` only if it is still `stale` (a concurrent task may
    /// already have replaced it).
    fn invalidate(&self, fwmark: u32, stale: &Arc<S>) {
        let mut guard = self.sockets.lock();
        guard.retain(|(mark, sock)| !(*mark == fwmark && Arc::ptr_eq(sock, stale)));
    }

    /// Number of cached sockets.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.sockets.lock().len()
    }

    /// Runs `send` on the cached socket. When it fails with an error that means the socket itself
    /// is dead, the entry is discarded and the send is retried once on a new socket.
    fn send_with_retry<T, C, F>(&self, fwmark: u32, create: C, send: F) -> std::io::Result<T>
    where
        C: Fn() -> std::io::Result<S>,
        F: Fn(&S) -> std::io::Result<T>,
    {
        let mut attempt = 1;
        loop {
            let sock = self.get_or_create(fwmark, &create)?;
            match send(&sock) {
                Err(err) if attempt < RAW_SEND_MAX_ATTEMPTS && is_dead_socket_error(&err) => {
                    self.invalidate(fwmark, &sock);
                    attempt += 1;
                }
                other => return other,
            }
        }
    }
}

/// Returns `true` when `err` shows the socket descriptor can no longer be used, as opposed to a
/// per-destination failure (unreachable network, bad address) that a new socket would not fix.
#[cfg(target_os = "linux")]
fn is_dead_socket_error(err: &std::io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code) if code == ERRNO_EBADF || code == ERRNO_ENOTSOCK || code == ERRNO_ENETDOWN
    )
}

#[cfg(target_os = "linux")]
static RAW_UDP_V4_SOCKETS: RawSocketCache<RawUdpSocket> = RawSocketCache::new();
#[cfg(target_os = "linux")]
static RAW_UDP_V6_SOCKETS: RawSocketCache<RawUdpSocket> = RawSocketCache::new();

/// Creates a raw socket with `IP_HDRINCL`/`IPV6_HDRINCL` and, when non-zero, `SO_MARK = fwmark`.
///
/// The IPv4 socket also enables `SO_BROADCAST` and disables `IP_MULTICAST_LOOP`; the latter only
/// affects multicast destinations, so applying it to every IPv4 send is behaviourally identical to
/// setting it per multicast datagram.
#[cfg(target_os = "linux")]
fn create_raw_udp_socket(family: RawUdpFamily, fwmark: u32) -> std::io::Result<RawUdpSocket> {
    use std::os::fd::FromRawFd;

    let domain = match family {
        RawUdpFamily::V4 => libc::AF_INET,
        RawUdpFamily::V6 => libc::AF_INET6,
    };
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_RAW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `socket(2)` and is owned by nothing else.
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

    let one: libc::c_int = 1;
    let int_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    unsafe {
        match family {
            RawUdpFamily::V4 => {
                let _ = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    &one as *const libc::c_int as *const libc::c_void,
                    int_len,
                );
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BROADCAST,
                    &one as *const libc::c_int as *const libc::c_void,
                    int_len,
                );
                let zero: libc::c_uchar = 0;
                let _ = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_MULTICAST_LOOP,
                    &zero as *const libc::c_uchar as *const libc::c_void,
                    std::mem::size_of::<libc::c_uchar>() as libc::socklen_t,
                );
            }
            RawUdpFamily::V6 => {
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_IPV6,
                    LINUX_IPV6_HDRINCL,
                    &one as *const libc::c_int as *const libc::c_void,
                    int_len,
                );
            }
        }
        if fwmark != 0 {
            let mark: libc::c_uint = fwmark;
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const libc::c_uint as *const libc::c_void,
                std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
            );
        }
    }
    Ok(RawUdpSocket(owned))
}

/// Sends one fully built IP packet to `addr` through `sock`.
#[cfg(target_os = "linux")]
fn raw_sendto(
    sock: &RawUdpSocket,
    packet: &[u8],
    addr: *const libc::sockaddr,
    addr_len: libc::socklen_t,
) -> std::io::Result<usize> {
    use std::os::fd::AsRawFd;

    let sent = unsafe {
        libc::sendto(
            sock.0.as_raw_fd(),
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            addr,
            addr_len,
        )
    };
    if sent < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(sent as usize)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod raw_socket_cache_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    fn dead_err() -> std::io::Error {
        std::io::Error::from_raw_os_error(ERRNO_EBADF)
    }

    #[test]
    fn creates_once_and_reuses_per_mark() {
        let cache: RawSocketCache<u32> = RawSocketCache::new();
        let created = AtomicUsize::new(0);
        let make = |mark: u32| {
            created.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(mark)
        };
        let a = cache.get_or_create(1, || make(1)).unwrap();
        let b = cache.get_or_create(1, || make(1)).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(created.load(AtomicOrdering::SeqCst), 1);
        let c = cache.get_or_create(2, || make(2)).unwrap();
        assert!(!Arc::ptr_eq(&a, &c));
        assert_eq!(created.load(AtomicOrdering::SeqCst), 2);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn creation_failure_is_not_cached() {
        let cache: RawSocketCache<u32> = RawSocketCache::new();
        let err = cache
            .get_or_create(0, || Err(std::io::Error::from_raw_os_error(1)))
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(1));
        assert_eq!(cache.len(), 0);
        assert!(cache.get_or_create(0, || Ok(7)).is_ok());
    }

    #[test]
    fn dead_socket_is_recreated_once_and_send_retried() {
        let cache: RawSocketCache<u32> = RawSocketCache::new();
        let created = AtomicUsize::new(0);
        let result = cache.send_with_retry(
            0,
            || Ok(created.fetch_add(1, AtomicOrdering::SeqCst) as u32),
            |sock| {
                if *sock == 0 {
                    Err(dead_err())
                } else {
                    Ok(*sock)
                }
            },
        );
        assert_eq!(result.unwrap(), 1);
        assert_eq!(created.load(AtomicOrdering::SeqCst), 2);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn persistent_dead_socket_stops_after_max_attempts() {
        let cache: RawSocketCache<u32> = RawSocketCache::new();
        let sends = AtomicUsize::new(0);
        let result: std::io::Result<u32> = cache.send_with_retry(
            0,
            || Ok(0),
            |_| {
                sends.fetch_add(1, AtomicOrdering::SeqCst);
                Err(dead_err())
            },
        );
        assert!(result.is_err());
        assert_eq!(sends.load(AtomicOrdering::SeqCst), RAW_SEND_MAX_ATTEMPTS);
    }

    #[test]
    fn destination_errors_keep_the_cached_socket() {
        let cache: RawSocketCache<u32> = RawSocketCache::new();
        let created = AtomicUsize::new(0);
        for _ in 0..3 {
            let result: std::io::Result<u32> = cache.send_with_retry(
                0,
                || Ok(created.fetch_add(1, AtomicOrdering::SeqCst) as u32),
                |_| Err(std::io::Error::from_raw_os_error(101)),
            );
            assert_eq!(result.unwrap_err().raw_os_error(), Some(101));
        }
        assert_eq!(created.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn invalidate_ignores_a_replaced_socket() {
        let cache: RawSocketCache<u32> = RawSocketCache::new();
        let old = cache.get_or_create(0, || Ok(1)).unwrap();
        cache.invalidate(0, &old);
        let fresh = cache.get_or_create(0, || Ok(2)).unwrap();
        cache.invalidate(0, &old);
        assert_eq!(cache.len(), 1);
        assert!(Arc::ptr_eq(
            &fresh,
            &cache.get_or_create(0, || Ok(3)).unwrap()
        ));
    }

    #[test]
    fn dead_socket_error_classification() {
        for code in [ERRNO_EBADF, ERRNO_ENOTSOCK, ERRNO_ENETDOWN] {
            assert!(is_dead_socket_error(&std::io::Error::from_raw_os_error(
                code
            )));
        }
        assert!(!is_dead_socket_error(&std::io::Error::from_raw_os_error(
            101
        )));
        assert!(!is_dead_socket_error(&std::io::Error::other("x")));
    }
}
