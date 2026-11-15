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

use crate::config::{ProxyCredentials, ProxyNode, ProxyProtocol};
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_INVALID_URI};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use uuid::Uuid;

const SCHEME_SEPARATOR: &str = "://";
const SCHEME_SOCKS5: &str = "socks5";
const SCHEME_HTTP: &str = "http";
const SCHEME_HTTPS: &str = "https";
const QUERY_KEY_SNI: &str = "sni";

pub struct ProxyUriCodec;

impl ProxyUriCodec {
    pub fn parse_batch(text: &str) -> Vec<ProxyNode> {
        let trimmed = text.trim();
        let expanded = if !trimmed.contains(SCHEME_SEPARATOR) {
            Self::try_decode_base64(trimmed).unwrap_or_else(|| trimmed.to_string())
        } else {
            trimmed.to_string()
        };

        expanded
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| Self::parse_uri(line).ok())
            .collect()
    }

    pub fn parse_uri(raw_uri: &str) -> RouteWardResult<ProxyNode> {
        let trimmed = raw_uri.trim();
        let (scheme_raw, remainder) = trimmed.split_once(SCHEME_SEPARATOR).ok_or_else(|| {
            RouteWardError::InvalidProxyUri {
                key: ERR_KEY_INVALID_URI,
                uri: Self::redact_uri_userinfo(trimmed),
            }
        })?;

        let scheme = scheme_raw.to_lowercase();
        let (before_fragment, fragment_name) = match remainder.split_once('#') {
            Some((left, frag)) => (left, Some(Self::percent_decode(frag))),
            None => (remainder, None),
        };

        let (authority_part, query_part) = match before_fragment.split_once('?') {
            Some((auth, q)) => (auth, Some(q)),
            None => (before_fragment, None),
        };

        let protocol = match scheme.as_str() {
            SCHEME_SOCKS5 => ProxyProtocol::Socks5,
            SCHEME_HTTP => ProxyProtocol::Http,
            SCHEME_HTTPS => ProxyProtocol::Https,
            _ => {
                return Err(RouteWardError::InvalidProxyUri {
                    key: ERR_KEY_INVALID_URI,
                    uri: Self::redact_uri_userinfo(trimmed),
                })
            }
        };

        let (userinfo_opt, host_port_str) = match authority_part.rsplit_once('@') {
            Some((u, hp)) => (Some(u), hp),
            None => (None, authority_part),
        };

        let redacted_uri = Self::redact_uri_userinfo(trimmed);
        let (host, port) = Self::parse_host_port(host_port_str, &redacted_uri)?;

        let auth = userinfo_opt.map(|raw_user_info| {
            if let Some((u, p)) = raw_user_info.split_once(':') {
                ProxyCredentials::new(Self::percent_decode(u), Self::percent_decode(p))
            } else {
                ProxyCredentials::new(Self::percent_decode(raw_user_info), String::new())
            }
        });

        let mut sni: Option<String> = None;
        if let Some(q) = query_part {
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if k.eq_ignore_ascii_case(QUERY_KEY_SNI) {
                        sni = Some(Self::percent_decode(v));
                    }
                }
            }
        }

        let tls = matches!(protocol, ProxyProtocol::Https) || sni.is_some();
        let udp_enabled = matches!(protocol, ProxyProtocol::Socks5);

        let name = fragment_name
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| format!("{} {}:{}", scheme.to_uppercase(), host, port));

        Ok(ProxyNode {
            id: format!("proxy-{}", Uuid::new_v4()),
            name,
            protocol,
            host,
            port,
            auth,
            udp_enabled,
            tls,
            sni,
            enabled: true,
            last_latency_ms: None,
            exit_ip: None,
        })
    }

    pub fn to_uri(node: &ProxyNode) -> String {
        let scheme = match node.protocol {
            ProxyProtocol::Socks5 => SCHEME_SOCKS5,
            ProxyProtocol::Http => SCHEME_HTTP,
            ProxyProtocol::Https => SCHEME_HTTPS,
        };

        let auth_prefix = match &node.auth {
            Some(creds) if !creds.username.is_empty() || !creds.password_str().is_empty() => {
                format!(
                    "{}:{}@",
                    Self::percent_encode(&creds.username),
                    Self::percent_encode(creds.password_str())
                )
            }
            _ => String::new(),
        };

        let query = node
            .sni
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(|s| format!("?sni={}", Self::percent_encode(s)))
            .unwrap_or_default();

        let frag = Self::percent_encode(&node.name);
        format!(
            "{scheme}://{auth_prefix}{}:{}{query}#{frag}",
            node.host, node.port
        )
    }

    fn parse_host_port(host_port: &str, full_uri: &str) -> RouteWardResult<(String, u16)> {
        let clean = host_port.trim_end_matches('/');
        let (host_str, port_str) =
            clean
                .rsplit_once(':')
                .ok_or_else(|| RouteWardError::InvalidProxyUri {
                    key: ERR_KEY_INVALID_URI,
                    uri: full_uri.to_string(),
                })?;

        let port = port_str
            .parse::<u16>()
            .map_err(|_| RouteWardError::InvalidProxyUri {
                key: ERR_KEY_INVALID_URI,
                uri: full_uri.to_string(),
            })?;

        let host = host_str
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        if host.is_empty() || port == 0 {
            return Err(RouteWardError::InvalidProxyUri {
                key: ERR_KEY_INVALID_URI,
                uri: full_uri.to_string(),
            });
        }
        Ok((host, port))
    }

    fn try_decode_base64(input: &str) -> Option<String> {
        URL_SAFE_NO_PAD
            .decode(input)
            .or_else(|_| STANDARD.decode(input))
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }

    fn percent_encode(input: &str) -> String {
        let mut encoded = String::with_capacity(input.len());
        for &byte in input.as_bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                encoded.push(byte as char);
            } else {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
        encoded
    }

    fn percent_decode(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut decoded: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut idx = 0;
        while idx < bytes.len() {
            if bytes[idx] == b'%' && idx + 2 < bytes.len() {
                if let Ok(hex_str) = std::str::from_utf8(&bytes[idx + 1..idx + 3]) {
                    if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                        decoded.push(val);
                        idx += 3;
                        continue;
                    }
                }
            }
            if bytes[idx] == b'+' {
                decoded.push(b' ');
            } else {
                decoded.push(bytes[idx]);
            }
            idx += 1;
        }
        String::from_utf8_lossy(&decoded).into_owned()
    }

    fn redact_uri_userinfo(uri: &str) -> String {
        if let Some((scheme, rest)) = uri.split_once(SCHEME_SEPARATOR) {
            if let Some((_, after_at)) = rest.rsplit_once('@') {
                return format!("{scheme}{SCHEME_SEPARATOR}[REDACTED]@{after_at}");
            }
        }
        if let Some((_, after_at)) = uri.rsplit_once('@') {
            return format!("[REDACTED]@{after_at}");
        }
        uri.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_socks5_and_https_uris() {
        let socks_node =
            ProxyUriCodec::parse_uri("socks5://alice:secret123@10.20.30.40:1080#Corporate%20SOCKS")
                .expect("Valid SOCKS5 URI");
        assert_eq!(socks_node.protocol, ProxyProtocol::Socks5);
        assert_eq!(socks_node.host, "10.20.30.40");
        assert_eq!(socks_node.port, 1080);
        assert_eq!(socks_node.name, "Corporate SOCKS");
        assert_eq!(socks_node.auth.as_ref().unwrap().username, "alice");

        let https_node = ProxyUriCodec::parse_uri(
            "https://bob:pass@edge.example.net:443?sni=edge.example.net#EdgeNode",
        )
        .expect("Valid HTTPS URI");
        assert_eq!(https_node.protocol, ProxyProtocol::Https);
        assert!(https_node.tls);
        assert_eq!(https_node.sni.as_deref(), Some("edge.example.net"));

        let exported = ProxyUriCodec::to_uri(&https_node);
        assert!(exported.starts_with("https://bob:pass@edge.example.net:443"));
    }

    #[test]
    fn round_trips_special_characters_in_userinfo_sni_and_fragment() {
        let mut node = ProxyUriCodec::parse_uri(
            "socks5://alice%3Adev:p%40ss%3Aw%25ord@10.20.30.40:1080?sni=edge%20node#Corp%20%25Node",
        )
        .expect("Valid URI with percent-encoded special chars");
        assert_eq!(node.name, "Corp %Node");
        assert_eq!(node.sni.as_deref(), Some("edge node"));
        let creds = node.auth.as_ref().expect("auth preserved");
        assert_eq!(creds.username, "alice:dev");
        assert_eq!(creds.password_str(), "p@ss:w%ord");

        let re_encoded = ProxyUriCodec::to_uri(&node);
        node.id = String::new();
        let reparsed = ProxyUriCodec::parse_uri(&re_encoded).expect("Re-parsed URI");
        assert_eq!(reparsed.name, "Corp %Node");
        assert_eq!(reparsed.sni.as_deref(), Some("edge node"));
        let recreds = reparsed.auth.expect("re-parsed auth");
        assert_eq!(recreds.username, "alice:dev");
        assert_eq!(recreds.password_str(), "p@ss:w%ord");
    }
}
