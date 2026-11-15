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

const HTTP_METHODS: &[&str] = &[
    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE ",
];

pub struct HttpHostExtractor;

impl HttpHostExtractor {
    /// Checks whether a peeked buffer starts cleanly with a plaintext HTTP/1.x request method.
    pub fn looks_like_http_request(prefix: &[u8]) -> bool {
        if prefix.is_empty() {
            return false;
        }
        let upper_prefix: String = prefix
            .iter()
            .take(10)
            .map(|b| (*b as char).to_ascii_uppercase())
            .collect();
        HTTP_METHODS.iter().any(|m| {
            if upper_prefix.len() >= m.len() {
                upper_prefix.starts_with(m)
            } else {
                m.starts_with(&upper_prefix)
            }
        })
    }

    /// Extracts the normalized hostname from an HTTP/1.x `Host:` header (stripping optional port
    /// and IPv6 brackets). Returns `None` when headers are incomplete or invalid.
    pub fn extract_host(packet: &[u8]) -> Option<String> {
        let header_end = packet
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .or_else(|| packet.windows(2).position(|w| w == b"\n\n"))?;

        let raw_headers = std::str::from_utf8(&packet[..header_end]).ok()?;
        let mut lines = raw_headers.lines();
        let request_line = lines.next()?.trim();
        let req_upper = request_line.to_ascii_uppercase();
        if !HTTP_METHODS.iter().any(|m| req_upper.starts_with(m)) {
            return None;
        }

        for line in lines {
            if let Some((name, val)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("Host") {
                    return Self::normalize_host_header_value(val);
                }
            }
        }
        None
    }

    fn normalize_host_header_value(raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return None;
        }
        let host = if trimmed.starts_with('[') {
            let close_idx = trimmed.find(']')?;
            &trimmed[1..close_idx]
        } else if let Some((h, port_part)) = trimmed.rsplit_once(':') {
            if !port_part.is_empty() && port_part.chars().all(|c| c.is_ascii_digit()) {
                h
            } else {
                trimmed
            }
        } else {
            trimmed
        };

        let normalized = host.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_normalized_host_from_http_requests_with_or_without_port() {
        let req =
            b"GET /index.html HTTP/1.1\r\nHost: Edge.Example.COM:8080\r\nUser-Agent: curl\r\n\r\n";
        assert_eq!(
            HttpHostExtractor::extract_host(req).as_deref(),
            Some("edge.example.com")
        );

        let v6_req = b"POST /api HTTP/1.1\r\nhost: [2001:db8::1]:80\r\n\r\n";
        assert_eq!(
            HttpHostExtractor::extract_host(v6_req).as_deref(),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn rejects_non_http_and_incomplete_headers() {
        assert!(!HttpHostExtractor::looks_like_http_request(b"\x16\x03\x01"));
        assert!(HttpHostExtractor::extract_host(b"GET / HTTP/1.1\r\nHost: a.com\r\n").is_none());
    }
}
