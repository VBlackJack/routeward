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
const SCHEME_SOCKS4: &str = "socks4";
const SCHEME_SOCKS4A: &str = "socks4a";
const SCHEME_HTTP: &str = "http";
const SCHEME_HTTPS: &str = "https";
const QUERY_KEY_SNI: &str = "sni";
const QUERY_KEY_TLS_SKIP_VERIFY: &str = "tlsSkipVerify";
const QUERY_KEY_INSECURE: &str = "insecure";

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
            SCHEME_SOCKS4 | SCHEME_SOCKS4A => ProxyProtocol::Socks4,
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
                ProxyCredentials::new(
                    Self::percent_decode_userinfo(u),
                    Self::percent_decode_userinfo(p),
                )
            } else {
                ProxyCredentials::new(Self::percent_decode_userinfo(raw_user_info), String::new())
            }
        });

        let mut sni: Option<String> = None;
        let mut tls_skip_verify = false;
        if let Some(q) = query_part {
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if k.eq_ignore_ascii_case(QUERY_KEY_SNI) {
                        sni = Some(Self::percent_decode(v));
                    } else if k.eq_ignore_ascii_case(QUERY_KEY_TLS_SKIP_VERIFY)
                        || k.eq_ignore_ascii_case(QUERY_KEY_INSECURE)
                    {
                        tls_skip_verify =
                            matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes");
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
            tls_skip_verify,
            sni,
            enabled: true,
            last_latency_ms: None,
            exit_ip: None,
        })
    }

    pub fn to_uri(node: &ProxyNode) -> String {
        let scheme = match node.protocol {
            ProxyProtocol::Socks5 => SCHEME_SOCKS5,
            ProxyProtocol::Socks4 => SCHEME_SOCKS4,
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

        let mut params = Vec::new();
        if let Some(s) = node.sni.as_ref().filter(|s| !s.is_empty()) {
            params.push(format!("{}={}", QUERY_KEY_SNI, Self::percent_encode(s)));
        }
        if node.tls_skip_verify {
            params.push(format!("{QUERY_KEY_TLS_SKIP_VERIFY}=1"));
        }
        let query = if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        };

        let host_part = if node.host.contains(':') && !node.host.starts_with('[') {
            format!("[{}]", node.host)
        } else {
            node.host.clone()
        };

        let frag = Self::percent_encode(&node.name);
        format!(
            "{scheme}://{auth_prefix}{host_part}:{}{query}#{frag}",
            node.port
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

    /// Decodes `%XX` escapes only: in userinfo a literal `+` is a plus sign, never a space.
    fn percent_decode_userinfo(input: &str) -> String {
        Self::percent_decode_with(input, false)
    }

    fn percent_decode(input: &str) -> String {
        Self::percent_decode_with(input, true)
    }

    fn percent_decode_with(input: &str, plus_as_space: bool) -> String {
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
            if plus_as_space && bytes[idx] == b'+' {
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

    #[test]
    fn userinfo_keeps_literal_plus_and_decodes_percent_2b() {
        let node = ProxyUriCodec::parse_uri("http://us+er:pa+ss%2Bx@10.0.0.1:8080")
            .expect("URI with plus signs in userinfo");
        let creds = node.auth.as_ref().expect("auth present");
        assert_eq!(creds.username, "us+er");
        assert_eq!(creds.password_str(), "pa+ss+x");
    }

    #[test]
    fn scheme_table_maps_protocol_tls_and_udp() {
        let cases = [
            ("socks5://h:1", ProxyProtocol::Socks5, false, true),
            ("SOCKS5://h:1", ProxyProtocol::Socks5, false, true),
            ("socks4://h:1", ProxyProtocol::Socks4, false, false),
            ("socks4a://h:1", ProxyProtocol::Socks4, false, false),
            ("http://h:1", ProxyProtocol::Http, false, false),
            ("https://h:1", ProxyProtocol::Https, true, false),
        ];
        for (uri, protocol, tls, udp) in cases {
            let node = ProxyUriCodec::parse_uri(uri).unwrap_or_else(|e| panic!("{uri}: {e:?}"));
            assert_eq!(node.protocol, protocol, "{uri}");
            assert_eq!(node.tls, tls, "{uri}");
            assert_eq!(node.udp_enabled, udp, "{uri}");
            assert!(node.auth.is_none(), "{uri}");
        }
    }

    #[test]
    fn unsupported_schemes_are_rejected() {
        for uri in [
            "ftp://h:1",
            "ssh://h:1",
            "vmess://h:1",
            "socks://h:1",
            "://h:1",
            "h:1",
        ] {
            assert!(ProxyUriCodec::parse_uri(uri).is_err(), "{uri}");
        }
    }

    #[test]
    fn port_table_accepts_range_and_rejects_the_rest() {
        let cases: [(&str, Option<u16>); 10] = [
            ("socks5://h:0", None),
            ("socks5://h:1", Some(1)),
            ("socks5://h:80", Some(80)),
            ("socks5://h:65535", Some(65535)),
            ("socks5://h:65536", None),
            ("socks5://h:0x50", None),
            ("socks5://h:-1", None),
            ("socks5://h:8o", None),
            ("socks5://h:", None),
            ("socks5://h: 80", None),
        ];
        for (uri, expected) in cases {
            let parsed = ProxyUriCodec::parse_uri(uri);
            match expected {
                Some(port) => assert_eq!(parsed.expect(uri).port, port, "{uri}"),
                None => assert!(parsed.is_err(), "{uri}"),
            }
        }
    }

    #[test]
    fn host_table_handles_ipv6_literals_and_trailing_slash() {
        let cases = [
            ("socks5://[::1]:1080", "::1", 1080),
            ("socks5://[2001:db8::7]:9050", "2001:db8::7", 9050),
            ("http://u:p@[fe80::1]:8080", "fe80::1", 8080),
            ("http://example.com:3128/", "example.com", 3128),
            ("http://10.0.0.1:3128", "10.0.0.1", 3128),
        ];
        for (uri, host, port) in cases {
            let node = ProxyUriCodec::parse_uri(uri).expect(uri);
            assert_eq!(node.host, host, "{uri}");
            assert_eq!(node.port, port, "{uri}");
        }
    }

    #[test]
    fn ipv6_literal_without_port_is_rejected() {
        assert!(ProxyUriCodec::parse_uri("socks5://[::1]").is_err());
    }

    #[test]
    fn ipv6_host_round_trips_through_to_uri() {
        let node = ProxyUriCodec::parse_uri("socks5://[2001:db8::7]:9050#v6").expect("v6 uri");
        let exported = ProxyUriCodec::to_uri(&node);
        assert!(
            exported.starts_with("socks5://[2001:db8::7]:9050"),
            "{exported}"
        );
        let reparsed = ProxyUriCodec::parse_uri(&exported).expect("re-parse");
        assert_eq!(reparsed.host, "2001:db8::7");
        assert_eq!(reparsed.port, 9050);
    }

    #[test]
    fn missing_parts_are_rejected() {
        for uri in [
            "",
            "   ",
            "socks5://",
            "socks5://:1080",
            "socks5://host",
            "socks5://user:pass@",
            "socks5://user:pass@:1080",
            "http://#frag",
            "http://?sni=x",
        ] {
            assert!(ProxyUriCodec::parse_uri(uri).is_err(), "{uri:?}");
        }
    }

    #[test]
    fn userinfo_table_decodes_percent_escapes_and_keeps_plus() {
        let cases = [
            ("http://u:p@h:1", "u", "p"),
            ("http://u@h:1", "u", ""),
            ("http://u:@h:1", "u", ""),
            ("http://:p@h:1", "", "p"),
            ("http://a+b:c+d@h:1", "a+b", "c+d"),
            ("http://a%2Bb:c%2Bd@h:1", "a+b", "c+d"),
            ("http://a%20b:c%20d@h:1", "a b", "c d"),
            ("http://a%40b:c%3Ad@h:1", "a@b", "c:d"),
            ("http://a@b:c@h:1", "a@b", "c"),
            ("http://u:p%zz@h:1", "u", "p%zz"),
            ("http://u:p%4@h:1", "u", "p%4"),
        ];
        for (uri, user, pass) in cases {
            let node = ProxyUriCodec::parse_uri(uri).expect(uri);
            let creds = node.auth.as_ref().unwrap_or_else(|| panic!("{uri}: auth"));
            assert_eq!(creds.username, user, "{uri}");
            assert_eq!(creds.password_str(), pass, "{uri}");
        }
    }

    #[test]
    fn fragment_and_sni_decode_plus_as_space() {
        let node = ProxyUriCodec::parse_uri("https://h:443?sni=a+b#Node+One").expect("uri");
        assert_eq!(node.name, "Node One");
        assert_eq!(node.sni.as_deref(), Some("a b"));
    }

    #[test]
    fn default_name_is_built_when_fragment_is_missing_or_blank() {
        for uri in ["socks5://h:1", "socks5://h:1#", "socks5://h:1#%20%20"] {
            let node = ProxyUriCodec::parse_uri(uri).expect(uri);
            assert_eq!(node.name, "SOCKS5 h:1", "{uri}");
        }
    }

    #[test]
    fn tls_skip_verify_query_table() {
        let cases = [
            ("https://h:1?tlsSkipVerify=1", true),
            ("https://h:1?insecure=true", true),
            ("https://h:1?INSECURE=YES", true),
            ("https://h:1?insecure=0", false),
            ("https://h:1?insecure=false", false),
            ("https://h:1?insecure", false),
            ("https://h:1", false),
        ];
        for (uri, expected) in cases {
            let node = ProxyUriCodec::parse_uri(uri).expect(uri);
            assert_eq!(node.tls_skip_verify, expected, "{uri}");
        }
    }

    #[test]
    fn sni_on_plain_scheme_enables_tls() {
        let node = ProxyUriCodec::parse_uri("http://h:8080?sni=front.example").expect("uri");
        assert!(node.tls);
        assert_eq!(node.sni.as_deref(), Some("front.example"));
    }

    #[test]
    fn parse_uri_trims_surrounding_whitespace() {
        let node = ProxyUriCodec::parse_uri("  socks5://h:1080\n").expect("trimmed uri");
        assert_eq!(node.host, "h");
    }

    #[test]
    fn invalid_uri_errors_never_leak_credentials() {
        for uri in [
            "ftp://user:topsecret@h:1",
            "socks5://user:topsecret@h:99999",
            "socks5://user:topsecret@:1080",
        ] {
            let err = ProxyUriCodec::parse_uri(uri).expect_err(uri);
            let text = format!("{err:?}");
            assert!(!text.contains("topsecret"), "{uri}: {text}");
            assert!(text.contains("[REDACTED]"), "{uri}: {text}");
        }
    }

    #[test]
    fn garbage_input_is_rejected_without_panicking() {
        let long = "a".repeat(10_000);
        let garbage = [
            "garbage",
            "::::",
            "://",
            "@@@@",
            "socks5:///",
            "socks5://@:",
            "socks5://[:1",
            "socks5://]]]:1",
            "http://%:%",
            "\u{0}\u{1}",
            "socks5://\u{e9}\u{e9}:80\u{e9}",
            long.as_str(),
        ];
        for uri in garbage {
            let _ = ProxyUriCodec::parse_uri(uri);
        }
        assert!(ProxyUriCodec::parse_uri("garbage").is_err());
        assert!(ProxyUriCodec::parse_uri("socks5://[:1").is_err());
    }

    #[test]
    fn parse_batch_skips_comments_blanks_and_invalid_lines() {
        let text = "# comment\n\nsocks5://a:1\nnot a uri\nhttp://b:2\nftp://c:3\n";
        let nodes = ProxyUriCodec::parse_batch(text);
        let hosts: Vec<&str> = nodes.iter().map(|n| n.host.as_str()).collect();
        assert_eq!(hosts, ["a", "b"]);
    }

    #[test]
    fn parse_batch_decodes_base64_subscription_bodies() {
        let plain = "socks5://a:1\nhttp://b:2";
        let standard = STANDARD.encode(plain);
        let url_safe = URL_SAFE_NO_PAD.encode(plain);
        for body in [standard, url_safe] {
            let nodes = ProxyUriCodec::parse_batch(&body);
            assert_eq!(nodes.len(), 2, "{body}");
        }
        assert!(ProxyUriCodec::parse_batch("").is_empty());
    }
}
