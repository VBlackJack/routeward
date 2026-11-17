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

//! Navigation policy for the embedded WebView.
//!
//! The initialization script injects the bridge token into every document the
//! WebView loads, so the WebView must never leave the loopback UI origin.

const SCHEME_SEPARATOR: &str = "://";
const ALLOWED_SCHEME: &str = "http";
const AUTHORITY_TERMINATORS: [char; 3] = ['/', '?', '#'];
const USERINFO_MARKER: char = '@';
const BACKSLASH: char = '\\';
const LOG_SCHEME_MAX_CHARS: usize = 16;
/// Prefix of object URLs created by `URL.createObjectURL` (used by exports).
const BLOB_PREFIX: &str = "blob:";

/// Returns the authority (`host[:port]`) of an `http://` URL, or `None` when
/// the URL is not a plain hierarchical http URL.
fn http_authority(url: &str) -> Option<&str> {
    let (scheme, rest) = url.split_once(SCHEME_SEPARATOR)?;
    if !scheme.eq_ignore_ascii_case(ALLOWED_SCHEME) {
        return None;
    }
    let end = rest.find(AUTHORITY_TERMINATORS).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Builds the allowed origin authority (`host:port`) from the UI URL.
pub fn ui_origin_authority(ui_url: &str) -> Option<String> {
    http_authority(ui_url).map(str::to_ascii_lowercase)
}

/// Decides whether the WebView may navigate to `target`.
///
/// Only `http` URLs whose authority is exactly the UI origin authority are
/// allowed (scheme, host and port); path, query and fragment are free.
/// Anything with userinfo, backslashes, whitespace or control characters is
/// denied, as are all non-http schemes (`javascript:`, `data:`, `file:`,
/// `about:blank`). The one exception is `blob:http://<allowed authority>/...`
/// (exact same origin only), which exports need for `<a download>` on
/// WebKitGTK; foreign blob origins and blob URLs with userinfo stay denied.
pub fn is_navigation_allowed(target: &str, allowed_authority: &str) -> bool {
    if target.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    let target = match target.get(..BLOB_PREFIX.len()) {
        Some(prefix) if prefix.eq_ignore_ascii_case(BLOB_PREFIX) => &target[BLOB_PREFIX.len()..],
        _ => target,
    };
    let Some(authority) = http_authority(target) else {
        return false;
    };
    if authority.contains(USERINFO_MARKER) || authority.contains(BACKSLASH) {
        return false;
    }
    authority.eq_ignore_ascii_case(allowed_authority)
}

/// Decides whether a WebView permission request is auto-allowed.
///
/// Only the "multiple automatic downloads" permission is ever granted (so a second export
/// is not held by the browser engine's download limiter), and only when the requesting
/// URI is the UI origin (same rule as navigation). Every other request is left to the
/// engine's default handling: this never denies anything.
#[cfg(any(windows, test))]
pub fn should_allow_multiple_downloads(
    is_multiple_downloads_kind: bool,
    requesting_uri: &str,
    allowed_authority: &str,
) -> bool {
    is_multiple_downloads_kind && is_navigation_allowed(requesting_uri, allowed_authority)
}

fn truncated_scheme(scheme: &str) -> String {
    scheme.chars().take(LOG_SCHEME_MAX_CHARS).collect()
}

/// Reduces a URL to a form safe for logs: scheme and host only, never
/// userinfo, path, query or fragment (which may carry the token).
pub fn redact_url_for_log(target: &str) -> String {
    match target.split_once(SCHEME_SEPARATOR) {
        Some((scheme, rest)) => {
            let end = rest.find(AUTHORITY_TERMINATORS).unwrap_or(rest.len());
            let host = rest[..end].rsplit(USERINFO_MARKER).next().unwrap_or("");
            format!("{}{SCHEME_SEPARATOR}{host}", truncated_scheme(scheme))
        }
        None => {
            let scheme = target.split(':').next().unwrap_or("");
            format!("{}:", truncated_scheme(scheme))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiple_downloads_allowed_only_for_ui_origin_and_kind() {
        let auth = "127.0.0.1:5000";
        assert!(should_allow_multiple_downloads(
            true,
            "http://127.0.0.1:5000/",
            auth
        ));
        assert!(should_allow_multiple_downloads(
            true,
            "blob:http://127.0.0.1:5000/abc",
            auth
        ));
        assert!(!should_allow_multiple_downloads(
            false,
            "http://127.0.0.1:5000/",
            auth
        ));
        assert!(!should_allow_multiple_downloads(
            true,
            "http://evil.example/",
            auth
        ));
        assert!(!should_allow_multiple_downloads(
            true,
            "http://127.0.0.1:5001/",
            auth
        ));
        assert!(!should_allow_multiple_downloads(true, "", auth));
    }

    const AUTH: &str = "127.0.0.1:49152";

    #[test]
    fn derives_authority_from_ui_url() {
        assert_eq!(
            ui_origin_authority("http://127.0.0.1:49152/").as_deref(),
            Some(AUTH)
        );
        assert_eq!(ui_origin_authority("file:///x"), None);
    }

    #[test]
    fn allows_same_origin_with_path_query_fragment() {
        assert!(is_navigation_allowed("http://127.0.0.1:49152/", AUTH));
        assert!(is_navigation_allowed("http://127.0.0.1:49152", AUTH));
        assert!(is_navigation_allowed(
            "http://127.0.0.1:49152/assets/app.js?x=1#top",
            AUTH
        ));
        assert!(is_navigation_allowed("HTTP://127.0.0.1:49152/a", AUTH));
        assert!(is_navigation_allowed("http://127.0.0.1:49152?q=1", AUTH));
    }

    #[test]
    fn denies_other_port_host_and_scheme() {
        assert!(!is_navigation_allowed("http://127.0.0.1:49153/", AUTH));
        assert!(!is_navigation_allowed("http://127.0.0.1/", AUTH));
        assert!(!is_navigation_allowed("http://localhost:49152/", AUTH));
        assert!(!is_navigation_allowed("https://127.0.0.1:49152/", AUTH));
        assert!(!is_navigation_allowed("http://example.com/", AUTH));
        assert!(!is_navigation_allowed(
            "http://127.0.0.1.evil.com:49152/",
            AUTH
        ));
        assert!(!is_navigation_allowed("http://127.0.0.1.evil.com/", AUTH));
    }

    #[test]
    fn denies_userinfo_and_backslash_tricks() {
        assert!(!is_navigation_allowed(
            "http://127.0.0.1:49152@evil.com/",
            AUTH
        ));
        assert!(!is_navigation_allowed(
            "http://evil.com@127.0.0.1:49152/",
            AUTH
        ));
        assert!(!is_navigation_allowed(
            "http://127.0.0.1:49152\\@evil.com/",
            AUTH
        ));
        assert!(!is_navigation_allowed(
            "http://evil.com\\.127.0.0.1:49152/",
            AUTH
        ));
        assert!(!is_navigation_allowed(
            "http://127.0.0.1:49152 .evil.com/",
            AUTH
        ));
        assert!(!is_navigation_allowed("http://127.0.0.1:49152\t/", AUTH));
    }

    #[test]
    fn denies_non_http_schemes() {
        assert!(!is_navigation_allowed("javascript:alert(1)", AUTH));
        assert!(!is_navigation_allowed("data:text/html,<b>x</b>", AUTH));
        assert!(!is_navigation_allowed("file:///C:/Windows/win.ini", AUTH));
        assert!(!is_navigation_allowed("about:blank", AUTH));
        assert!(!is_navigation_allowed("", AUTH));
    }

    #[test]
    fn allows_same_origin_blob_only() {
        // Intentional behaviour change: same-origin blob: used to be denied.
        assert!(is_navigation_allowed(
            "blob:http://127.0.0.1:49152/0b6e-uuid",
            AUTH
        ));
        assert!(!is_navigation_allowed("blob:http://evil.com/x", AUTH));
        assert!(!is_navigation_allowed(
            "blob:http://127.0.0.1:49153/x",
            AUTH
        ));
        assert!(!is_navigation_allowed(
            "blob:http://evil.com@127.0.0.1:49152/x",
            AUTH
        ));
        assert!(!is_navigation_allowed(
            "blob:http://127.0.0.1:49152@evil.com/x",
            AUTH
        ));
        assert!(!is_navigation_allowed(
            "blob:https://127.0.0.1:49152/x",
            AUTH
        ));
        assert!(!is_navigation_allowed(
            "blob:blob:http://127.0.0.1:49152/x",
            AUTH
        ));
        assert!(!is_navigation_allowed("blob:", AUTH));
    }

    #[test]
    fn log_redaction_drops_userinfo_path_and_query() {
        assert_eq!(
            redact_url_for_log("http://user:pw@evil.com:80/p?token=abc#f"),
            "http://evil.com:80"
        );
        assert_eq!(redact_url_for_log("javascript:alert(1)"), "javascript:");
        assert!(!redact_url_for_log("http://h/?token=abc").contains("token"));
    }
}
