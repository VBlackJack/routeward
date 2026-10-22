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
use crate::error::{ProxifierError, ProxifierResult, ERR_KEY_INVALID_URI};
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

    pub fn parse_uri(raw_uri: &str) -> ProxifierResult<ProxyNode> {
        let trimmed = raw_uri.trim();
        let (scheme_raw, remainder) = trimmed.split_once(SCHEME_SEPARATOR).ok_or_else(|| {
            ProxifierError::InvalidProxyUri {
                key: ERR_KEY_INVALID_URI,
                uri: trimmed.to_string(),
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
                return Err(ProxifierError::InvalidProxyUri {
                    key: ERR_KEY_INVALID_URI,
                    uri: trimmed.to_string(),
                })
            }
        };

        let (userinfo_opt, host_port_str) = match authority_part.rsplit_once('@') {
            Some((u, hp)) => (Some(u), hp),
            None => (None, authority_part),
        };

        let (host, port) = Self::parse_host_port(host_port_str, trimmed)?;

        let auth = userinfo_opt.map(|raw_user_info| {
            if let Some((u, p)) = raw_user_info.split_once(':') {
                ProxyCredentials {
                    username: Self::percent_decode(u),
                    password: Self::percent_decode(p),
                }
            } else {
                ProxyCredentials {
                    username: Self::percent_decode(raw_user_info),
                    password: String::new(),
                }
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
            Some(creds) if !creds.username.is_empty() || !creds.password.is_empty() => {
                format!("{}:{}@", creds.username, creds.password)
            }
            _ => String::new(),
        };

        let query = node
            .sni
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(|s| format!("?sni={s}"))
            .unwrap_or_default();

        let frag = node.name.replace(' ', "%20");
        format!(
            "{scheme}://{auth_prefix}{}:{}{query}#{frag}",
            node.host, node.port
        )
    }

    fn parse_host_port(host_port: &str, full_uri: &str) -> ProxifierResult<(String, u16)> {
        let clean = host_port.trim_end_matches('/');
        let (host_str, port_str) =
            clean
                .rsplit_once(':')
                .ok_or_else(|| ProxifierError::InvalidProxyUri {
                    key: ERR_KEY_INVALID_URI,
                    uri: full_uri.to_string(),
                })?;

        let port = port_str
            .parse::<u16>()
            .map_err(|_| ProxifierError::InvalidProxyUri {
                key: ERR_KEY_INVALID_URI,
                uri: full_uri.to_string(),
            })?;

        let host = host_str
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        if host.is_empty() || port == 0 {
            return Err(ProxifierError::InvalidProxyUri {
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

    fn percent_decode(input: &str) -> String {
        input.replace("%20", " ").replace('+', " ")
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
}
