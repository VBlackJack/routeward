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

use thiserror::Error;

pub const ERR_KEY_CONFIG_LOAD: &str = "errors.config.load_failed";
pub const ERR_KEY_CONFIG_SAVE: &str = "errors.config.save_failed";
pub const ERR_KEY_CONFIG_JSON: &str = "errors.config.invalid_json";
pub const ERR_KEY_PROXY_NOT_FOUND: &str = "errors.proxy.not_found";
pub const ERR_KEY_CHAIN_EMPTY: &str = "errors.proxy.chain_empty";
pub const ERR_KEY_HANDSHAKE_FAILED: &str = "errors.proxy.handshake_failed";
pub const ERR_KEY_CONNECTION_TIMEOUT: &str = "errors.proxy.connection_timeout";
pub const ERR_KEY_AUTH_REJECTED: &str = "errors.proxy.auth_rejected";
pub const ERR_KEY_UDP_NOT_SUPPORTED: &str = "errors.proxy.udp_not_supported";
pub const ERR_KEY_INVALID_URI: &str = "errors.proxy.invalid_uri";
pub const ERR_KEY_RULE_BLOCKED: &str = "errors.rule.blocked_by_policy";
pub const ERR_KEY_INTERCEPTOR_DRIVER: &str = "errors.interceptor.driver_missing";
pub const ERR_KEY_INTERCEPTOR_OPEN: &str = "errors.interceptor.open_failed";
pub const ERR_KEY_INTERCEPTOR_NOT_ROOT: &str = "errors.interceptor.not_root";
pub const ERR_KEY_INTERCEPTOR_NFT_MISSING: &str = "errors.interceptor.nft_missing";
pub const ERR_KEY_INTERCEPTOR_NFT_FAILED: &str = "errors.interceptor.nft_failed";
pub const ERR_KEY_INTERCEPTOR_TPROXY_CONFLICT: &str = "errors.interceptor.tproxy_conflict";
pub const ERR_KEY_DAEMON_ALREADY_RUNNING: &str = "errors.daemon.already_running";
pub const ERR_KEY_DAEMON_GROUP_MISSING: &str = "errors.daemon.group_missing";
pub const ERR_KEY_DAEMON_NOT_ELEVATED: &str = "errors.daemon.not_elevated";
pub const ERR_KEY_DAEMON_IPC_ERROR: &str = "errors.daemon.ipc_error";
pub const ERR_KEY_DAEMON_DISCONNECTED: &str = "errors.daemon.disconnected";
pub const ERR_KEY_DAEMON_INSECURE_PROFILE: &str = "errors.daemon.insecure_profile";
pub const ERR_KEY_CLEANUP_DAEMON_ACTIVE: &str = "errors.daemon.cleanup_refused_active";

pub const DAEMON_EXIT_GENERAL_ERROR: u8 = 1;
pub const DAEMON_EXIT_NOT_ELEVATED: u8 = 10;
pub const DAEMON_EXIT_INSECURE_PROFILE: u8 = 11;
pub const DAEMON_EXIT_IPC_ERROR: u8 = 12;
pub const DAEMON_EXIT_CONFIG_ERROR: u8 = 13;

#[derive(Debug, Error)]
pub enum RouteWardError {
    #[error("{key}: {detail}")]
    ConfigError { key: &'static str, detail: String },

    #[error("{key}: {detail}")]
    InterceptorError { key: &'static str, detail: String },

    #[error("{key}: {detail}")]
    DaemonError { key: &'static str, detail: String },

    #[error("{key}: {proxy_id}")]
    ProxyNotFound { key: &'static str, proxy_id: String },

    #[error("{key}")]
    EmptyProxyChain { key: &'static str },

    #[error("{key}: {detail}")]
    ProtocolHandshake { key: &'static str, detail: String },

    #[error("{key}")]
    ConnectionTimeout { key: &'static str },

    #[error("{key}")]
    AuthenticationRejected { key: &'static str },

    #[error("{key}: {proxy_id}")]
    UdpAssociateUnsupported { key: &'static str, proxy_id: String },

    #[error("{key}: {uri}")]
    InvalidProxyUri { key: &'static str, uri: String },

    #[error("{key}: {rule_name}")]
    BlockedByPolicy {
        key: &'static str,
        rule_name: String,
    },

    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
}

impl RouteWardError {
    pub fn i18n_key(&self) -> &'static str {
        match self {
            Self::ConfigError { key, .. }
            | Self::InterceptorError { key, .. }
            | Self::DaemonError { key, .. }
            | Self::ProxyNotFound { key, .. }
            | Self::EmptyProxyChain { key }
            | Self::ProtocolHandshake { key, .. }
            | Self::ConnectionTimeout { key }
            | Self::AuthenticationRejected { key }
            | Self::UdpAssociateUnsupported { key, .. }
            | Self::InvalidProxyUri { key, .. }
            | Self::BlockedByPolicy { key, .. } => key,
            Self::Io(_) => ERR_KEY_DAEMON_IPC_ERROR,
        }
    }

    pub fn daemon_exit_code(&self) -> u8 {
        match self.i18n_key() {
            ERR_KEY_DAEMON_NOT_ELEVATED | ERR_KEY_INTERCEPTOR_NOT_ROOT => DAEMON_EXIT_NOT_ELEVATED,
            ERR_KEY_DAEMON_INSECURE_PROFILE => DAEMON_EXIT_INSECURE_PROFILE,
            ERR_KEY_DAEMON_IPC_ERROR => DAEMON_EXIT_IPC_ERROR,
            ERR_KEY_CONFIG_LOAD | ERR_KEY_CONFIG_SAVE | ERR_KEY_CONFIG_JSON => {
                DAEMON_EXIT_CONFIG_ERROR
            }
            _ => DAEMON_EXIT_GENERAL_ERROR,
        }
    }
}

pub type RouteWardResult<T> = Result<T, RouteWardError>;
