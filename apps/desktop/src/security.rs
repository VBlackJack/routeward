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

pub const HEADER_ROUTEWARD_TOKEN: &str = "x-routeward-token";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpSecurityRejection {
    MalformedRequest,
    InvalidHost,
    InvalidOrigin,
    InvalidToken,
}

impl HttpSecurityRejection {
    pub fn status_line(&self) -> &'static str {
        match self {
            Self::MalformedRequest => "HTTP/1.1 400 Bad Request",
            Self::InvalidHost | Self::InvalidOrigin => "HTTP/1.1 403 Forbidden",
            Self::InvalidToken => "HTTP/1.1 401 Unauthorized",
        }
    }
}

/// Constant-time byte comparison to prevent timing side-channels when verifying the desktop loopback token.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut diff = a_bytes.len() ^ b_bytes.len();
    let max_len = a_bytes.len().max(b_bytes.len());
    for i in 0..max_len {
        let byte_a = a_bytes.get(i).copied().unwrap_or(0);
        let byte_b = b_bytes.get(i).copied().unwrap_or(0);
        diff |= (byte_a ^ byte_b) as usize;
    }
    diff == 0
}

/// Strictly validates the `Host`, `Origin`, and ephemeral token headers on incoming loopback HTTP requests.
/// Returns the request `(method, path)` tuple if valid.
pub fn validate_loopback_http_request_with_method(
    raw_request: &str,
    expected_port: u16,
    expected_token: &str,
) -> Result<(String, String), HttpSecurityRejection> {
    let header_section = raw_request
        .split("\r\n\r\n")
        .next()
        .or_else(|| raw_request.split("\n\n").next())
        .unwrap_or(raw_request);

    let mut lines = header_section.lines();
    let request_line = lines
        .next()
        .ok_or(HttpSecurityRejection::MalformedRequest)?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or(HttpSecurityRejection::MalformedRequest)?
        .to_ascii_uppercase();
    let path = parts
        .next()
        .ok_or(HttpSecurityRejection::MalformedRequest)?
        .to_string();

    let expected_host = format!("127.0.0.1:{expected_port}");
    let expected_origin = format!("http://127.0.0.1:{expected_port}");

    let mut host_header: Option<String> = None;
    let mut origin_header: Option<String> = None;
    let mut token_header: Option<String> = None;

    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            let key = name.trim().to_ascii_lowercase();
            let value = val.trim();
            match key.as_str() {
                "host" => host_header = Some(value.to_string()),
                "origin" => origin_header = Some(value.to_string()),
                HEADER_ROUTEWARD_TOKEN => token_header = Some(value.to_string()),
                "authorization" => {
                    if let Some(bearer) = value.strip_prefix("Bearer ") {
                        token_header = Some(bearer.trim().to_string());
                    }
                }
                _ => {}
            }
        }
    }

    if host_header.as_deref() != Some(expected_host.as_str()) {
        return Err(HttpSecurityRejection::InvalidHost);
    }

    if path.starts_with("/api/") {
        if method != "GET" {
            if origin_header.as_deref() != Some(expected_origin.as_str()) {
                return Err(HttpSecurityRejection::InvalidOrigin);
            }
        } else if let Some(ref origin) = origin_header {
            if origin != &expected_origin {
                return Err(HttpSecurityRejection::InvalidOrigin);
            }
        }

        match token_header {
            Some(ref provided) if constant_time_eq(provided, expected_token) => {}
            _ => return Err(HttpSecurityRejection::InvalidToken),
        }
    } else if let Some(ref origin) = origin_header {
        if origin != &expected_origin {
            return Err(HttpSecurityRejection::InvalidOrigin);
        }
    }

    Ok((method, path))
}

/// Strictly validates incoming loopback HTTP requests and returns only the request path.
pub fn validate_loopback_http_request(
    raw_request: &str,
    expected_port: u16,
    expected_token: &str,
) -> Result<String, HttpSecurityRejection> {
    validate_loopback_http_request_with_method(raw_request, expected_port, expected_token)
        .map(|(_, path)| path)
}

pub fn extract_json_body(raw_request: &str) -> &str {
    if let Some(idx) = raw_request.find("\r\n\r\n") {
        &raw_request[idx + 4..]
    } else if let Some(idx) = raw_request.find("\n\n") {
        &raw_request[idx + 2..]
    } else {
        ""
    }
}
