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
pub const ERR_KEY_DAEMON_UNTRUSTED_PIPE_OWNER: &str = "errors.daemon.untrusted_pipe_owner";
pub const ERR_KEY_DAEMON_PIPE_SQUATTED: &str = "errors.daemon.pipe_squatted";
pub const ERR_KEY_DAEMON_GROUP_MISSING: &str = "errors.daemon.group_missing";
pub const ERR_KEY_DAEMON_NOT_ELEVATED: &str = "errors.daemon.not_elevated";
pub const ERR_KEY_DAEMON_IPC_ERROR: &str = "errors.daemon.ipc_error";
pub const ERR_KEY_DAEMON_INVALID_PAUSE: &str = "errors.daemon.invalid_pause";
pub const ERR_KEY_DAEMON_PAUSE_NOT_ACTIVE: &str = "errors.daemon.pause_not_active";
pub const ERR_KEY_DAEMON_DISCONNECTED: &str = "errors.daemon.disconnected";
pub const ERR_KEY_DAEMON_INSECURE_PROFILE: &str = "errors.daemon.insecure_profile";
pub const ERR_KEY_DAEMON_IO_TIMEOUT: &str = "errors.daemon.io_timeout";
pub const ERR_KEY_SERVICE_INSECURE_BINARY: &str = "errors.service.insecure_binary_location";
pub const ERR_KEY_CLEANUP_DAEMON_ACTIVE: &str = "errors.daemon.cleanup_refused_active";
pub const ERR_KEY_SYSTEM_REGISTRY_WRITE: &str = "errors.system.registry_write_failed";
pub const ERR_KEY_SYSTEM_PAC_URL_INVALID: &str = "errors.system.pac_url_invalid";
pub const ERR_KEY_SYSTEM_PATH_EMPTY: &str = "errors.system.executable_path_empty";
pub const ERR_KEY_SYSTEM_LAUNCH_FAILED: &str = "errors.system.launch_failed";
pub const ERR_KEY_SYSTEM_BACKUP_FAILED: &str = "errors.system.backup_failed";
pub const ERR_KEY_SYSTEM_PURGE_FAILED: &str = "errors.system.purge_failed";
pub const ERR_KEY_SYSTEM_PURGE_UNSUPPORTED: &str = "errors.system.purge_unsupported";

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

    #[error("{key}: {detail}")]
    SystemError { key: &'static str, detail: String },

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
            | Self::SystemError { key, .. }
            | Self::ProxyNotFound { key, .. }
            | Self::EmptyProxyChain { key }
            | Self::ProtocolHandshake { key, .. }
            | Self::ConnectionTimeout { key }
            | Self::AuthenticationRejected { key }
            | Self::UdpAssociateUnsupported { key, .. }
            | Self::InvalidProxyUri { key, .. }
            | Self::BlockedByPolicy { key, .. } => key,
            Self::Io(err) => Self::io_i18n_key(err),
        }
    }

    /// Maps an I/O error to the most specific existing key; unknown kinds stay generic IPC errors.
    fn io_i18n_key(err: &std::io::Error) -> &'static str {
        use std::io::ErrorKind;
        match err.kind() {
            ErrorKind::TimedOut | ErrorKind::WouldBlock => ERR_KEY_DAEMON_IO_TIMEOUT,
            ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::NotConnected
            | ErrorKind::BrokenPipe
            | ErrorKind::UnexpectedEof => ERR_KEY_DAEMON_DISCONNECTED,
            _ => ERR_KEY_DAEMON_IPC_ERROR,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn io_errors_map_to_specific_keys() {
        let key = |kind| RouteWardError::Io(Error::from(kind)).i18n_key();
        assert_eq!(key(ErrorKind::TimedOut), ERR_KEY_DAEMON_IO_TIMEOUT);
        assert_eq!(key(ErrorKind::BrokenPipe), ERR_KEY_DAEMON_DISCONNECTED);
        assert_eq!(
            key(ErrorKind::ConnectionRefused),
            ERR_KEY_DAEMON_DISCONNECTED
        );
        assert_eq!(key(ErrorKind::PermissionDenied), ERR_KEY_DAEMON_IPC_ERROR);
        assert_eq!(key(ErrorKind::Other), ERR_KEY_DAEMON_IPC_ERROR);
    }

    #[test]
    fn system_errors_carry_their_own_key_and_display_the_detail() {
        let err = RouteWardError::SystemError {
            key: ERR_KEY_SYSTEM_REGISTRY_WRITE,
            detail: "reg add failed".to_string(),
        };
        assert_eq!(err.i18n_key(), ERR_KEY_SYSTEM_REGISTRY_WRITE);
        assert_eq!(
            err.to_string(),
            "errors.system.registry_write_failed: reg add failed"
        );
        assert_eq!(err.daemon_exit_code(), DAEMON_EXIT_GENERAL_ERROR);
    }
}
