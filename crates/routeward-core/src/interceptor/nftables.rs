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

#[cfg(not(target_os = "linux"))]
use crate::error::ERR_KEY_INTERCEPTOR_DRIVER;
use crate::error::{RouteWardError, RouteWardResult};
#[cfg(target_os = "linux")]
use crate::error::{
    ERR_KEY_INTERCEPTOR_NFT_FAILED, ERR_KEY_INTERCEPTOR_NFT_MISSING, ERR_KEY_INTERCEPTOR_NOT_ROOT,
};
use crate::interceptor::backend::Interceptor;
use crate::interceptor::RouteWardController;
use crate::telemetry::{LogLevel, TelemetryHub};
use parking_lot::Mutex;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const BACKEND_NAME: &str = "nftables";
const COMPONENT_NFTABLES: &str = "NftablesInterceptor";
const AF_INET_U16: u16 = 2;

struct NftActiveState {
    nft_binary: String,
    table_name: String,
    watchdog_stdin: Option<ChildStdin>,
    watchdog_child: Option<Child>,
    telemetry: TelemetryHub,
}

/// Linux transparent IPv4 TCP interceptor backed by a dedicated `nftables` table
/// (`table ip <table_name>`) and a pipe-linked fail-open watchdog process.
pub struct NftablesInterceptor {
    active: Arc<AtomicBool>,
    state: Mutex<Option<NftActiveState>>,
}

impl Default for NftablesInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl NftablesInterceptor {
    pub fn new() -> Self {
        Self {
            active: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(None),
        }
    }

    /// Generates the dedicated IPv4 `nftables` ruleset for `nft -f -`.
    pub fn build_nft_table_ruleset(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        relay_port: u16,
        upstream_endpoints: &[(Ipv4Addr, u16)],
    ) -> String {
        Self::build_nft_table_ruleset_with_dns(
            table_name,
            chain_name,
            fwmark,
            relay_port,
            10853,
            53,
            853,
            true,
            upstream_endpoints,
        )
    }

    /// Generates the dedicated IPv4 `nftables` ruleset including DNS port 53 redirection
    /// to `dns_listen_port` and optional encrypted DNS bypass (port 853) blocking.
    #[allow(clippy::too_many_arguments)]
    pub fn build_nft_table_ruleset_with_dns(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        relay_port: u16,
        dns_listen_port: u16,
        dns_standard_port: u16,
        dot_port: u16,
        block_encrypted_dns: bool,
        upstream_endpoints: &[(Ipv4Addr, u16)],
    ) -> String {
        Self::build_nft_table_ruleset_full(
            table_name,
            chain_name,
            fwmark,
            relay_port,
            dns_listen_port,
            10854,
            dns_standard_port,
            dot_port,
            443,
            5353,
            5355,
            137,
            block_encrypted_dns,
            true,
            upstream_endpoints,
        )
    }

    /// Generates the dedicated IPv4 `nftables` ruleset including:
    /// - DNS port 53 (UDP and TCP) redirection to `dns_listen_port`
    /// - mDNS (`5353`) and LLMNR (`5355`) UDP redirection to `local_name_inspect_port` (`10854`)
    /// - optional DoT/DoQ (`UDP 853`) and QUIC (`UDP 443`) `reject` (ICMPv4 Port Unreachable)
    /// - NetBIOS-NS (`UDP 137`) drop toward non-local/public IPv4 addresses
    #[allow(clippy::too_many_arguments)]
    pub fn build_nft_table_ruleset_full(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        relay_port: u16,
        dns_listen_port: u16,
        local_name_inspect_port: u16,
        dns_standard_port: u16,
        dot_port: u16,
        quic_port: u16,
        mdns_port: u16,
        llmnr_port: u16,
        netbios_ns_port: u16,
        block_encrypted_dns: bool,
        block_quic_udp_443: bool,
        upstream_endpoints: &[(Ipv4Addr, u16)],
    ) -> String {
        let mut script = String::with_capacity(1024);
        script.push_str(&format!("table ip {table_name} {{\n"));
        script.push_str(&format!("    chain {chain_name} {{\n"));
        script.push_str("        type nat hook output priority -100; policy accept;\n");
        script.push_str(&format!("        meta mark {fwmark} return\n"));
        script.push_str("        ip daddr 127.0.0.0/8 return\n");
        script.push_str(&format!(
            "        udp dport {dns_standard_port} redirect to :{dns_listen_port}\n"
        ));
        script.push_str(&format!(
            "        tcp dport {dns_standard_port} redirect to :{dns_listen_port}\n"
        ));
        script.push_str(&format!(
            "        udp dport {{ {mdns_port}, {llmnr_port} }} redirect to :{local_name_inspect_port}\n"
        ));
        for (ip, port) in upstream_endpoints {
            if !ip.is_loopback() {
                script.push_str(&format!("        ip daddr {ip} tcp dport {port} return\n"));
            }
        }
        script.push_str(&format!(
            "        tcp dport 1-65535 redirect to :{relay_port}\n"
        ));
        script.push_str("    }\n");
        script.push_str("    chain filter_output {\n");
        script.push_str("        type filter hook output priority 0; policy accept;\n");
        script.push_str(&format!("        meta mark {fwmark} return\n"));
        script.push_str("        ip daddr 127.0.0.0/8 return\n");
        if block_encrypted_dns {
            script.push_str(&format!("        udp dport {dot_port} reject\n"));
        }
        if block_quic_udp_443 {
            script.push_str(&format!("        udp dport {quic_port} reject\n"));
        }
        script.push_str(&format!(
            "        udp dport {netbios_ns_port} ip daddr != {{ 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 }} drop\n"
        ));
        script.push_str("    }\n");
        script.push_str("}\n");
        script
    }

    /// Generates the dedicated IPv6 `nftables` ruleset (`table ip6 <table_name>`) to block
    /// outbound IPv6 DNS (port 53) and DoT (port 853) unconditionally while the engine runs
    /// (independently of `killSwitchEnabled`), forcing the OS to fall back to IPv4 DNS resolvers
    /// until full IPv6 interception in Batch 4.3.
    pub fn build_nft_ip6_table_ruleset(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        dns_standard_port: u16,
        dot_port: u16,
        _kill_switch_enabled: bool,
        _block_encrypted_dns: bool,
    ) -> Option<String> {
        let mut script = String::with_capacity(512);
        script.push_str(&format!("table ip6 {table_name} {{\n"));
        script.push_str(&format!("    chain {chain_name} {{\n"));
        script.push_str("        type filter hook output priority 0; policy accept;\n");
        script.push_str(&format!("        meta mark {fwmark} return\n"));
        script.push_str("        ip6 daddr ::1 return\n");
        script.push_str(&format!("        udp dport {dns_standard_port} reject\n"));
        script.push_str(&format!(
            "        tcp dport {dns_standard_port} reject with tcp reset\n"
        ));
        script.push_str(&format!("        udp dport {dot_port} reject\n"));
        script.push_str(&format!(
            "        tcp dport {dot_port} reject with tcp reset\n"
        ));
        script.push_str("    }\n");
        script.push_str("}\n");
        Some(script)
    }

    /// Builds a single atomic `nft -f -` transaction script that replaces both `table ip <table_name>`
    /// and `table ip6 <table_name>` in one kernel commit without any permissive window.
    #[allow(clippy::too_many_arguments)]
    pub fn build_atomic_replace_ruleset(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        relay_port: u16,
        dns_listen_port: u16,
        dns_standard_port: u16,
        dot_port: u16,
        kill_switch_enabled: bool,
        block_encrypted_dns: bool,
        upstream_endpoints: &[(Ipv4Addr, u16)],
    ) -> String {
        Self::build_atomic_replace_ruleset_full(
            table_name,
            chain_name,
            fwmark,
            relay_port,
            dns_listen_port,
            10854,
            dns_standard_port,
            dot_port,
            443,
            5353,
            5355,
            137,
            kill_switch_enabled,
            block_encrypted_dns,
            true,
            upstream_endpoints,
        )
    }

    /// Builds a single atomic `nft -f -` transaction script with all UDP/QUIC/local-name parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn build_atomic_replace_ruleset_full(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        relay_port: u16,
        dns_listen_port: u16,
        local_name_inspect_port: u16,
        dns_standard_port: u16,
        dot_port: u16,
        quic_port: u16,
        mdns_port: u16,
        llmnr_port: u16,
        netbios_ns_port: u16,
        kill_switch_enabled: bool,
        block_encrypted_dns: bool,
        block_quic_udp_443: bool,
        upstream_endpoints: &[(Ipv4Addr, u16)],
    ) -> String {
        let mut batch = String::with_capacity(1536);
        batch.push_str(&format!("table ip {table_name}\n"));
        batch.push_str(&format!("delete table ip {table_name}\n"));
        batch.push_str(&Self::build_nft_table_ruleset_full(
            table_name,
            chain_name,
            fwmark,
            relay_port,
            dns_listen_port,
            local_name_inspect_port,
            dns_standard_port,
            dot_port,
            quic_port,
            mdns_port,
            llmnr_port,
            netbios_ns_port,
            block_encrypted_dns,
            block_quic_udp_443,
            upstream_endpoints,
        ));
        if let Some(ip6_script) = Self::build_nft_ip6_table_ruleset(
            table_name,
            chain_name,
            fwmark,
            dns_standard_port,
            dot_port,
            kill_switch_enabled,
            block_encrypted_dns,
        ) {
            batch.push_str(&format!("table ip6 {table_name}\n"));
            batch.push_str(&format!("delete table ip6 {table_name}\n"));
            batch.push_str(&ip6_script);
        }
        batch
    }

    /// Deletes the dedicated `nftables` tables (`ip` and `ip6`) if they exist.
    pub fn delete_nft_table(
        nft_binary: &str,
        table_name: &str,
        telemetry: &TelemetryHub,
    ) -> RouteWardResult<()> {
        for family in ["ip", "ip6"] {
            match Command::new(nft_binary)
                .args(["delete", "table", family, table_name])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
            {
                Ok(out) if out.status.success() => {
                    telemetry.push_log(
                        LogLevel::Info,
                        COMPONENT_NFTABLES,
                        format!("Removed nftables table \"{family} {table_name}\""),
                    );
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let trimmed = stderr.trim();
                    if trimmed.contains("No such file or directory")
                        || trimmed.contains("does not exist")
                    {
                        telemetry.push_log(
                            LogLevel::Info,
                            COMPONENT_NFTABLES,
                            format!(
                                "nftables table \"{family} {table_name}\" was already absent during cleanup"
                            ),
                        );
                    } else {
                        telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_NFTABLES,
                            format!(
                                "Could not delete nftables table \"{family} {table_name}\" (exit={:?}): {trimmed}",
                                out.status.code()
                            ),
                        );
                    }
                }
                Err(err) => {
                    telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_NFTABLES,
                        format!(
                            "Failed invoking {nft_binary} to delete table \"{family} {table_name}\": {err}"
                        ),
                    );
                }
            }
        }
        Ok(())
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
}

impl Interceptor for NftablesInterceptor {
    fn name(&self) -> &'static str {
        BACKEND_NAME
    }

    #[cfg(target_os = "linux")]
    fn start(&self, controller: RouteWardController) -> RouteWardResult<()> {
        use std::io::Write;
        use std::os::unix::process::CommandExt;

        if self
            .active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }

        // 1. Mandatory root privilege check (Milestone 2 runs as root only)
        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root {
            self.active.store(false, Ordering::SeqCst);
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NOT_ROOT,
                detail: controller.i18n.t(ERR_KEY_INTERCEPTOR_NOT_ROOT),
            });
        }

        let net = &controller.constants.network;
        let nft_bin = net.linux_nft_binary.clone();
        let table_name = net.linux_nft_table_name.clone();
        let chain_name = net.linux_nft_chain_name.clone();
        let fwmark = net.linux_fwmark;
        let relay_port = net.default_transparent_tcp_port;

        // 2. Verify nft binary is installed and reachable
        match Command::new(&nft_bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                self.active.store(false, Ordering::SeqCst);
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("{nft_bin} --version failed: {stderr}"),
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                self.active.store(false, Ordering::SeqCst);
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_MISSING,
                    detail: format!(
                        "{}: {}",
                        controller.i18n.t(ERR_KEY_INTERCEPTOR_NFT_MISSING),
                        nft_bin
                    ),
                });
            }
            Err(err) => {
                self.active.store(false, Ordering::SeqCst);
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("Failed to execute {nft_bin}: {err}"),
                });
            }
        }

        // 3. Remove any stale tables (`ip` and `ip6`) with the same name before installing fresh rules
        for family in ["ip", "ip6"] {
            let _ = Command::new(&nft_bin)
                .args(["delete", "table", family, &table_name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .output();
        }

        // 4. Build and load the dedicated nftables tables via `nft -f -`
        let upstream_endpoints = controller.nat_table.upstream_endpoints();
        let dns_listen_port = net.default_dns_listen_port;
        let local_name_inspect_port = net.default_local_name_inspect_port;
        let quic_port = net.quic_default_port;
        let mdns_port = net.mdns_standard_port;
        let llmnr_port = net.llmnr_standard_port;
        let netbios_ns_port = net.netbios_ns_standard_port;
        let dns_standard_port = controller.constants.dns.dns_standard_port;
        let dot_port = controller.constants.dns.dns_over_tls_port;
        let (kill_switch_enabled, block_encrypted_dns, block_quic_udp_443) = {
            let prof = controller.profile.read();
            (
                prof.security_policy.kill_switch_enabled,
                prof.security_policy.block_encrypted_dns_bypass,
                prof.security_policy.block_quic_udp_443,
            )
        };

        if let Some(ip6_ruleset) = Self::build_nft_ip6_table_ruleset(
            &table_name,
            &chain_name,
            fwmark,
            dns_standard_port,
            dot_port,
            kill_switch_enabled,
            block_encrypted_dns,
        ) {
            if let Ok(mut ip6_child) = Command::new(&nft_bin)
                .args(["-f", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
            {
                if let Some(mut stdin) = ip6_child.stdin.take() {
                    let _ = stdin.write_all(ip6_ruleset.as_bytes());
                }
                if let Ok(out) = ip6_child.wait_with_output() {
                    if out.status.success() {
                        controller.telemetry.push_log(
                            LogLevel::Info,
                            COMPONENT_NFTABLES,
                            format!(
                                "Installed nftables IPv6 DNS/DoT guard table \"ip6 {table_name}\""
                            ),
                        );
                    } else {
                        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                        controller.telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_NFTABLES,
                            format!(
                                "Could not install nftables table \"ip6 {table_name}\": {stderr}"
                            ),
                        );
                    }
                }
            }
        }

        // 5. Spawn pipe-linked fail-open watchdog in its own process group before installing `ip routeward`.
        // If RouteWard dies with SIGKILL (kill -9), the kernel closes watchdog_stdin immediately,
        // `cat` exits on EOF, and `nft delete table ip/ip6 <table_name>` cleans up automatically.
        let watchdog_script = format!(
            "cat >/dev/null; {nft_bin} delete table ip {table_name} >/dev/null 2>&1; {nft_bin} delete table ip6 {table_name} >/dev/null 2>&1"
        );
        let mut watchdog_stdin = None;
        let mut watchdog_child = None;

        match Command::new("sh")
            .args(["-c", &watchdog_script])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
        {
            Ok(mut child) => {
                let wid = child.id();
                watchdog_stdin = child.stdin.take();
                watchdog_child = Some(child);
                controller.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_NFTABLES,
                    format!(
                        "Started pipe-linked nftables fail-open watchdog (PID={wid}, table=\"ip {table_name}\")"
                    ),
                );
            }
            Err(err) => {
                controller.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_NFTABLES,
                    format!("Could not spawn pipe-linked watchdog for nftables: {err}"),
                );
            }
        }

        *self.state.lock() = Some(NftActiveState {
            nft_binary: nft_bin.clone(),
            table_name: table_name.clone(),
            watchdog_stdin,
            watchdog_child,
            telemetry: controller.telemetry.clone(),
        });

        let ruleset = Self::build_nft_table_ruleset_full(
            &table_name,
            &chain_name,
            fwmark,
            relay_port,
            dns_listen_port,
            local_name_inspect_port,
            dns_standard_port,
            dot_port,
            quic_port,
            mdns_port,
            llmnr_port,
            netbios_ns_port,
            block_encrypted_dns,
            block_quic_udp_443,
            &upstream_endpoints,
        );

        let mut apply_child = match Command::new(&nft_bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(err) => {
                self.stop();
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("Could not spawn {nft_bin} -f -: {err}"),
                });
            }
        };

        if let Some(mut stdin) = apply_child.stdin.take() {
            let _ = stdin.write_all(ruleset.as_bytes());
        }

        let apply_out = match apply_child.wait_with_output() {
            Ok(out) => out,
            Err(err) => {
                self.stop();
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("Failed waiting for {nft_bin} -f -: {err}"),
                });
            }
        };

        if !apply_out.status.success() {
            self.stop();
            let stderr = String::from_utf8_lossy(&apply_out.stderr)
                .trim()
                .to_string();
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("nft -f - rejected table \"ip {table_name}\": {stderr}"),
            });
        }

        controller.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_NFTABLES,
            format!(
                "Installed nftables table \"ip {table_name}\" (chain=\"{chain_name}\", fwmark={fwmark:#x}, redirect_port={relay_port}, dns_port={dns_listen_port})"
            ),
        );

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn start(&self, _controller: RouteWardController) -> RouteWardResult<()> {
        Err(RouteWardError::InterceptorError {
            key: ERR_KEY_INTERCEPTOR_DRIVER,
            detail: "nftables backend is only supported on Linux".to_string(),
        })
    }

    #[cfg(target_os = "linux")]
    fn reload(&self, controller: RouteWardController) -> RouteWardResult<()> {
        use std::io::Write;

        if !self.is_active() {
            return Ok(());
        }

        let net = &controller.constants.network;
        let nft_bin = net.linux_nft_binary.clone();
        let table_name = net.linux_nft_table_name.clone();
        let chain_name = net.linux_nft_chain_name.clone();
        let fwmark = net.linux_fwmark;
        let relay_port = net.default_transparent_tcp_port;
        let dns_listen_port = net.default_dns_listen_port;
        let local_name_inspect_port = net.default_local_name_inspect_port;
        let quic_port = net.quic_default_port;
        let mdns_port = net.mdns_standard_port;
        let llmnr_port = net.llmnr_standard_port;
        let netbios_ns_port = net.netbios_ns_standard_port;
        let dns_standard_port = controller.constants.dns.dns_standard_port;
        let dot_port = controller.constants.dns.dns_over_tls_port;
        let upstream_endpoints = controller.nat_table.upstream_endpoints();
        let (kill_switch_enabled, block_encrypted_dns, block_quic_udp_443) = {
            let prof = controller.profile.read();
            (
                prof.security_policy.kill_switch_enabled,
                prof.security_policy.block_encrypted_dns_bypass,
                prof.security_policy.block_quic_udp_443,
            )
        };

        let atomic_batch = Self::build_atomic_replace_ruleset_full(
            &table_name,
            &chain_name,
            fwmark,
            relay_port,
            dns_listen_port,
            local_name_inspect_port,
            dns_standard_port,
            dot_port,
            quic_port,
            mdns_port,
            llmnr_port,
            netbios_ns_port,
            kill_switch_enabled,
            block_encrypted_dns,
            block_quic_udp_443,
            &upstream_endpoints,
        );

        let mut apply_child = Command::new(&nft_bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("Could not spawn {nft_bin} -f - for atomic reload: {err}"),
            })?;

        if let Some(mut stdin) = apply_child.stdin.take() {
            let _ = stdin.write_all(atomic_batch.as_bytes());
        }

        let apply_out =
            apply_child
                .wait_with_output()
                .map_err(|err| RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("Failed waiting for {nft_bin} -f - atomic reload: {err}"),
                })?;

        if !apply_out.status.success() {
            let stderr = String::from_utf8_lossy(&apply_out.stderr)
                .trim()
                .to_string();
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!(
                    "nft -f - rejected atomic table reload for \"{table_name}\": {stderr}"
                ),
            });
        }

        controller.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_NFTABLES,
            format!(
                "Atomically replaced nftables tables \"ip {table_name}\" and \"ip6 {table_name}\" (killSwitchEnabled={kill_switch_enabled}, blockEncryptedDnsBypass={block_encrypted_dns})"
            ),
        );

        Ok(())
    }

    fn stop(&self) {
        self.active.store(false, Ordering::SeqCst);
        if let Some(mut state) = self.state.lock().take() {
            // Closing the pipe write-end lets the watchdog exit cleanly
            drop(state.watchdog_stdin.take());
            let _ = Self::delete_nft_table(&state.nft_binary, &state.table_name, &state.telemetry);
            if let Some(mut child) = state.watchdog_child.take() {
                let _ = child.wait();
            }
        }
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
}

impl Drop for NftablesInterceptor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_expected_nft_ruleset_with_fwmark_loopback_and_upstream_exclusions() {
        let upstreams = vec![
            (Ipv4Addr::new(127, 0, 0, 1), 1080),
            (Ipv4Addr::new(192, 168, 31, 10), 1080),
        ];
        let ruleset = NftablesInterceptor::build_nft_table_ruleset(
            "routeward",
            "output",
            21079,
            10810,
            &upstreams,
        );

        assert!(ruleset.contains("table ip routeward {"));
        assert!(ruleset.contains("chain output {"));
        assert!(ruleset.contains("type nat hook output priority -100; policy accept;"));
        assert!(ruleset.contains("meta mark 21079 return"));
        assert!(ruleset.contains("ip daddr 127.0.0.0/8 return"));
        assert!(ruleset.contains("udp dport 53 redirect to :10853"));
        assert!(ruleset.contains("tcp dport 53 redirect to :10853"));
        assert!(ruleset.contains("udp dport { 5353, 5355 } redirect to :10854"));
        assert!(ruleset.contains("ip daddr 192.168.31.10 tcp dport 1080 return"));
        assert!(ruleset.contains("tcp dport 1-65535 redirect to :10810"));
        assert!(ruleset.contains("udp dport 853 reject"));
        assert!(ruleset.contains("udp dport 443 reject"));
        assert!(ruleset.contains("udp dport 137 ip daddr !="));

        let ip6_ruleset = NftablesInterceptor::build_nft_ip6_table_ruleset(
            "routeward",
            "output",
            21079,
            53,
            853,
            false,
            false,
        )
        .expect("ip6 ruleset generated even when killSwitchEnabled=false");
        assert!(ip6_ruleset.contains("table ip6 routeward {"));
        assert!(ip6_ruleset.contains("udp dport 53 reject"));
        assert!(ip6_ruleset.contains("tcp dport 53 reject with tcp reset"));
        assert!(ip6_ruleset.contains("udp dport 853 reject"));
        assert!(ip6_ruleset.contains("tcp dport 853 reject with tcp reset"));

        let atomic_batch = NftablesInterceptor::build_atomic_replace_ruleset(
            "routeward",
            "output",
            21079,
            10810,
            10853,
            53,
            853,
            false,
            false,
            &upstreams,
        );
        assert!(atomic_batch.contains("table ip routeward\ndelete table ip routeward\n"));
        assert!(atomic_batch.contains("table ip6 routeward\ndelete table ip6 routeward\n"));
        assert!(!atomic_batch.contains("udp dport 853 reject\n    }\n}\ntable ip6"));
    }

    #[test]
    fn parses_sockaddr_in_original_dst_and_rejects_unredirected_loopback_relay() {
        let ip_be = u32::from(Ipv4Addr::new(93, 184, 216, 34)).to_be();
        let port_be = 443u16.to_be();
        let parsed = NftablesInterceptor::parse_sockaddr_in_fields(2, port_be, ip_be, 10810)
            .expect("valid original dst");
        assert_eq!(parsed.ip(), &Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(parsed.port(), 443);

        // Direct connection to 127.0.0.1:10810 without DNAT must be rejected
        let loop_ip_be = u32::from(Ipv4Addr::new(127, 0, 0, 1)).to_be();
        let relay_port_be = 10810u16.to_be();
        assert!(
            NftablesInterceptor::parse_sockaddr_in_fields(2, relay_port_be, loop_ip_be, 10810)
                .is_none()
        );
    }
}
