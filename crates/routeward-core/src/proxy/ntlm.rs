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

use crate::config::ProxyCredentials;
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_AUTH_REJECTED};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SspiScheme {
    Negotiate,
    Ntlm,
}

impl SspiScheme {
    pub fn as_header_scheme(self) -> &'static str {
        match self {
            Self::Negotiate => "Negotiate",
            Self::Ntlm => "NTLM",
        }
    }

    #[cfg(windows)]
    fn as_sspi_package_wide(self) -> Vec<u16> {
        let name = match self {
            Self::Negotiate => "Negotiate\0",
            Self::Ntlm => "NTLM\0",
        };
        name.encode_utf16().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedWinCredentials {
    pub domain: String,
    pub user: String,
    pub password: String,
}

/// Splits explicit Windows proxy credentials into domain, username, and password
/// (`DOMAIN\\user`, `user@domain` for UPN/Kerberos, or plain `user`).
pub fn parse_windows_credentials(creds: &ProxyCredentials) -> ParsedWinCredentials {
    let raw_user = creds.username.trim();
    let password = creds.password_str().to_string();
    if let Some((domain, user)) = raw_user.split_once('\\') {
        ParsedWinCredentials {
            domain: domain.trim().to_string(),
            user: user.trim().to_string(),
            password,
        }
    } else {
        ParsedWinCredentials {
            domain: String::new(),
            user: raw_user.to_string(),
            password,
        }
    }
}

pub fn select_sspi_scheme(challenges: &[String]) -> Option<SspiScheme> {
    let mut saw_ntlm = false;
    for header_val in challenges {
        for raw_token in header_val.split(',') {
            let scheme_token = raw_token.split_whitespace().next().unwrap_or("");
            if scheme_token.eq_ignore_ascii_case("Negotiate") {
                return Some(SspiScheme::Negotiate);
            }
            if scheme_token.eq_ignore_ascii_case("NTLM") {
                saw_ntlm = true;
            }
        }
    }
    if saw_ntlm {
        Some(SspiScheme::Ntlm)
    } else {
        None
    }
}

pub fn extract_challenge_token(challenges: &[String], scheme: SspiScheme) -> Option<Vec<u8>> {
    let expected = scheme.as_header_scheme();
    for header_val in challenges {
        let trimmed = header_val.trim();
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let hdr_scheme = parts.next().unwrap_or("");
        if hdr_scheme.eq_ignore_ascii_case(expected) {
            if let Some(b64) = parts.next() {
                let clean = b64.trim();
                if !clean.is_empty() {
                    if let Ok(decoded) = BASE64_STANDARD.decode(clean) {
                        return Some(decoded);
                    }
                }
            }
        }
    }
    None
}

#[cfg(windows)]
mod win_impl {
    use super::*;
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{SEC_E_OK, SEC_I_CONTINUE_NEEDED};
    use windows_sys::Win32::Security::Authentication::Identity::{
        AcquireCredentialsHandleW, DeleteSecurityContext, FreeCredentialsHandle,
        InitializeSecurityContextW, SecBuffer, SecBufferDesc, ISC_REQ_CONFIDENTIALITY,
        ISC_REQ_CONNECTION, ISC_REQ_REPLAY_DETECT, ISC_REQ_SEQUENCE_DETECT, SECBUFFER_TOKEN,
        SECBUFFER_VERSION, SECPKG_CRED_OUTBOUND,
    };
    use windows_sys::Win32::Security::Credentials::SecHandle;
    use windows_sys::Win32::System::Rpc::{
        SEC_WINNT_AUTH_IDENTITY_UNICODE, SEC_WINNT_AUTH_IDENTITY_W,
    };

    const MAX_SSPI_TOKEN_BYTES: usize = 16384;
    const SECURITY_NATIVE_DREP: u32 = 0x0000_0010;

    fn to_wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub struct SspiClientSession {
        scheme: SspiScheme,
        target_spn_wide: Vec<u16>,
        cred_handle: SecHandle,
        has_cred: bool,
        ctx_handle: SecHandle,
        has_ctx: bool,
    }

    unsafe impl Send for SspiClientSession {}

    impl Drop for SspiClientSession {
        fn drop(&mut self) {
            unsafe {
                if self.has_ctx {
                    let _ = DeleteSecurityContext(&self.ctx_handle);
                    self.has_ctx = false;
                }
                if self.has_cred {
                    let _ = FreeCredentialsHandle(&self.cred_handle);
                    self.has_cred = false;
                }
            }
        }
    }

    impl SspiClientSession {
        pub fn acquire(
            scheme: SspiScheme,
            proxy_host: &str,
            creds: Option<&ProxyCredentials>,
        ) -> RouteWardResult<Self> {
            let package_wide = scheme.as_sspi_package_wide();
            let spn_str = format!(
                "HTTP/{}",
                proxy_host
                    .trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
            );
            let target_spn_wide = to_wide_null(&spn_str);

            let mut cred_handle = SecHandle {
                dwLower: 0,
                dwUpper: 0,
            };
            let mut expiry: i64 = 0;

            let non_empty_creds =
                creds.filter(|c| !c.username.trim().is_empty() || !c.password_str().is_empty());
            let status = if let Some(c) = non_empty_creds {
                let parsed = parse_windows_credentials(c);
                let user_wide: Vec<u16> = parsed.user.encode_utf16().collect();
                let domain_wide: Vec<u16> = parsed.domain.encode_utf16().collect();
                let pass_wide: Vec<u16> = parsed.password.encode_utf16().collect();
                let mut auth_identity = SEC_WINNT_AUTH_IDENTITY_W {
                    User: if user_wide.is_empty() {
                        null_mut()
                    } else {
                        user_wide.as_ptr() as *mut u16
                    },
                    UserLength: user_wide.len() as u32,
                    Domain: if domain_wide.is_empty() {
                        null_mut()
                    } else {
                        domain_wide.as_ptr() as *mut u16
                    },
                    DomainLength: domain_wide.len() as u32,
                    Password: if pass_wide.is_empty() {
                        null_mut()
                    } else {
                        pass_wide.as_ptr() as *mut u16
                    },
                    PasswordLength: pass_wide.len() as u32,
                    Flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
                };
                unsafe {
                    AcquireCredentialsHandleW(
                        null(),
                        package_wide.as_ptr(),
                        SECPKG_CRED_OUTBOUND,
                        null(),
                        &mut auth_identity as *mut _ as *mut c_void,
                        None,
                        null(),
                        &mut cred_handle,
                        &mut expiry,
                    )
                }
            } else {
                unsafe {
                    AcquireCredentialsHandleW(
                        null(),
                        package_wide.as_ptr(),
                        SECPKG_CRED_OUTBOUND,
                        null(),
                        null_mut(),
                        None,
                        null(),
                        &mut cred_handle,
                        &mut expiry,
                    )
                }
            };

            if status != SEC_E_OK {
                tracing::warn!(
                    target: "routeward::proxy::sspi",
                    "AcquireCredentialsHandleW({}) failed with HRESULT 0x{:08X}",
                    scheme.as_header_scheme(),
                    status as u32
                );
                return Err(RouteWardError::AuthenticationRejected {
                    key: ERR_KEY_AUTH_REJECTED,
                });
            }

            Ok(Self {
                scheme,
                target_spn_wide,
                cred_handle,
                has_cred: true,
                ctx_handle: SecHandle {
                    dwLower: 0,
                    dwUpper: 0,
                },
                has_ctx: false,
            })
        }

        pub fn step(&mut self, challenge_token: Option<&[u8]>) -> RouteWardResult<(String, bool)> {
            let mut out_storage = vec![0u8; MAX_SSPI_TOKEN_BYTES];
            let mut out_buf = SecBuffer {
                cbBuffer: out_storage.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: out_storage.as_mut_ptr() as *mut c_void,
            };
            let mut out_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: &mut out_buf,
            };

            let mut in_storage = challenge_token.map(|b| b.to_vec()).unwrap_or_default();
            let mut in_buf = SecBuffer {
                cbBuffer: in_storage.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: in_storage.as_mut_ptr() as *mut c_void,
            };
            let mut in_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: &mut in_buf,
            };
            let p_in_desc = if challenge_token.is_some() {
                &mut in_desc as *mut SecBufferDesc
            } else {
                null_mut()
            };

            let req_flags = ISC_REQ_CONFIDENTIALITY
                | ISC_REQ_REPLAY_DETECT
                | ISC_REQ_SEQUENCE_DETECT
                | ISC_REQ_CONNECTION;
            let mut context_attr = 0u32;
            let mut expiry: i64 = 0;

            let p_old_ctx = if self.has_ctx {
                &self.ctx_handle as *const SecHandle
            } else {
                null()
            };
            let mut new_ctx = SecHandle {
                dwLower: 0,
                dwUpper: 0,
            };

            let status = unsafe {
                InitializeSecurityContextW(
                    &self.cred_handle,
                    p_old_ctx,
                    self.target_spn_wide.as_ptr(),
                    req_flags,
                    0,
                    SECURITY_NATIVE_DREP,
                    p_in_desc,
                    0,
                    &mut new_ctx,
                    &mut out_desc,
                    &mut context_attr,
                    &mut expiry,
                )
            };

            if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED {
                tracing::warn!(
                    target: "routeward::proxy::sspi",
                    "InitializeSecurityContextW({}) failed with HRESULT 0x{:08X}",
                    self.scheme.as_header_scheme(),
                    status as u32
                );
                return Err(RouteWardError::AuthenticationRejected {
                    key: ERR_KEY_AUTH_REJECTED,
                });
            }

            if !self.has_ctx {
                self.ctx_handle = new_ctx;
                self.has_ctx = true;
            } else if new_ctx.dwLower != 0 || new_ctx.dwUpper != 0 {
                self.ctx_handle = new_ctx;
            }

            let token_len = (out_buf.cbBuffer as usize).min(out_storage.len());
            let encoded = BASE64_STANDARD.encode(&out_storage[..token_len]);
            let complete = status == SEC_E_OK;
            Ok((encoded, complete))
        }
    }
}

#[cfg(not(windows))]
mod non_win_impl {
    use super::*;

    pub struct SspiClientSession;

    impl SspiClientSession {
        pub fn acquire(
            scheme: SspiScheme,
            _proxy_host: &str,
            _creds: Option<&ProxyCredentials>,
        ) -> RouteWardResult<Self> {
            Err(RouteWardError::ProtocolHandshake {
                key: crate::error::ERR_KEY_HANDSHAKE_FAILED,
                detail: format!(
                    "Windows SSPI {} authentication is only supported on Windows hosts",
                    scheme.as_header_scheme()
                ),
            })
        }

        pub fn step(&mut self, _challenge_token: Option<&[u8]>) -> RouteWardResult<(String, bool)> {
            Err(RouteWardError::ProtocolHandshake {
                key: crate::error::ERR_KEY_HANDSHAKE_FAILED,
                detail: "Windows SSPI authentication is only supported on Windows hosts"
                    .to_string(),
            })
        }
    }
}

#[cfg(not(windows))]
pub use non_win_impl::SspiClientSession;
#[cfg(windows)]
pub use win_impl::SspiClientSession;

/// Asynchronous wrapper executing blocking SSPI credential/token calls on Tokio's blocking pool.
pub async fn sspi_step_async(
    mut session: SspiClientSession,
    challenge: Option<Vec<u8>>,
) -> RouteWardResult<(SspiClientSession, String, bool)> {
    tokio::task::spawn_blocking(move || {
        let (token, complete) = session.step(challenge.as_deref())?;
        Ok((session, token, complete))
    })
    .await
    .map_err(|err| {
        tracing::warn!(target: "routeward::proxy::sspi", "SSPI task join error: {err}");
        RouteWardError::AuthenticationRejected {
            key: ERR_KEY_AUTH_REJECTED,
        }
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_domain_and_upn_windows_credentials() {
        let dom = parse_windows_credentials(&ProxyCredentials::new("CORP\\alice", "secret"));
        assert_eq!(dom.domain, "CORP");
        assert_eq!(dom.user, "alice");
        assert_eq!(dom.password, "secret");

        let upn = parse_windows_credentials(&ProxyCredentials::new("alice@corp.local", "pw"));
        assert_eq!(upn.domain, "");
        assert_eq!(upn.user, "alice@corp.local");
        assert_eq!(upn.password, "pw");
    }

    #[test]
    fn selects_negotiate_over_ntlm_and_decodes_challenge_token() {
        let headers = vec![
            "Basic realm=\"Corp\"".to_string(),
            "NTLM".to_string(),
            "Negotiate Y2hhbGxlbmdl".to_string(),
        ];
        let scheme = select_sspi_scheme(&headers);
        assert_eq!(scheme, Some(SspiScheme::Negotiate));
        let token = extract_challenge_token(&headers, SspiScheme::Negotiate);
        assert_eq!(token.as_deref(), Some(b"challenge".as_slice()));
    }

    #[cfg(windows)]
    #[test]
    fn acquires_windows_ntlm_type1_token_for_explicit_credentials() {
        let creds = ProxyCredentials::new("CORP\\testuser", "testpass");
        let mut sess =
            SspiClientSession::acquire(SspiScheme::Ntlm, "proxy.corp.local", Some(&creds))
                .expect("acquire NTLM SSPI session");
        let (b64, complete) = sess.step(None).expect("generate NTLM Type 1 token");
        assert!(!complete);
        let decoded = BASE64_STANDARD.decode(&b64).expect("valid base64");
        assert!(decoded.starts_with(b"NTLMSSP\0"));
    }
}
