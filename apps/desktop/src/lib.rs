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

pub mod commands;

use commands::DesktopCommandBridge;
use routeward_core::config::{ProfileConfig, SystemConstants};

const DEFAULT_DESKTOP_LOCALE: &str = "fr";
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

pub fn create_desktop_bridge() -> Result<DesktopCommandBridge, String> {
    let constants = SystemConstants::load_embedded().map_err(|e| e.to_string())?;
    let profile = ProfileConfig::load_embedded_default().map_err(|e| e.to_string())?;
    let bridge = DesktopCommandBridge::new(constants, profile, DEFAULT_DESKTOP_LOCALE);
    bridge.spawn_background_sync();
    Ok(bridge)
}

/// Strictly validates the `Host`, `Origin`, and ephemeral token headers on incoming loopback HTTP requests.
/// Returns the request path if valid.
pub fn validate_loopback_http_request(
    raw_request: &str,
    expected_port: u16,
    expected_token: &str,
) -> Result<String, HttpSecurityRejection> {
    let header_section = raw_request
        .split("\r\n\r\n")
        .next()
        .or_else(|| raw_request.split("\n\n").next())
        .unwrap_or(raw_request);

    let mut lines = header_section.lines();
    let request_line = lines
        .next()
        .ok_or(HttpSecurityRejection::MalformedRequest)?;
    let path = request_line
        .split_whitespace()
        .nth(1)
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
        if origin_header.as_deref() != Some(expected_origin.as_str()) {
            return Err(HttpSecurityRejection::InvalidOrigin);
        }
        if token_header.as_deref() != Some(expected_token) {
            return Err(HttpSecurityRejection::InvalidToken);
        }
    } else if let Some(ref origin) = origin_header {
        if origin != &expected_origin {
            return Err(HttpSecurityRejection::InvalidOrigin);
        }
    }

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_host_origin_and_token_on_api_routes() {
        let port = 54321;
        let token = "secret-ephemeral-token-123";

        let valid_api_req = format!(
            "POST /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n{{}}"
        );
        let path = validate_loopback_http_request(&valid_api_req, port, token)
            .expect("Valid request should pass");
        assert_eq!(path, "/api/state");

        // Wrong Host header (DNS rebinding attempt)
        let bad_host_req = format!(
            "POST /api/state HTTP/1.1\r\nHost: attacker.example.com\r\nOrigin: http://127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
        );
        assert_eq!(
            validate_loopback_http_request(&bad_host_req, port, token),
            Err(HttpSecurityRejection::InvalidHost)
        );

        // Wrong Origin header (cross-origin browser request)
        let bad_origin_req = format!(
            "POST /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://evil.local\r\nX-RouteWard-Token: {token}\r\n\r\n"
        );
        assert_eq!(
            validate_loopback_http_request(&bad_origin_req, port, token),
            Err(HttpSecurityRejection::InvalidOrigin)
        );

        // Missing Origin header on /api/*
        let missing_origin_req = format!(
            "POST /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
        );
        assert_eq!(
            validate_loopback_http_request(&missing_origin_req, port, token),
            Err(HttpSecurityRejection::InvalidOrigin)
        );

        // Wrong or missing token on /api/*
        let bad_token_req = format!(
            "POST /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nX-RouteWard-Token: wrong-token\r\n\r\n"
        );
        assert_eq!(
            validate_loopback_http_request(&bad_token_req, port, token),
            Err(HttpSecurityRejection::InvalidToken)
        );
    }
}
