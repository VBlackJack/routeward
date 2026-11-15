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

use crate::config::ProxyNode;
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_HANDSHAKE_FAILED};
use crate::proxy::AsyncTunnelStream;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::sync::{Arc, OnceLock};
use tokio_rustls::TlsConnector;

static CRYPTO_INIT: OnceLock<()> = OnceLock::new();
static STANDARD_TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
static INSECURE_TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();

#[derive(Debug)]
struct NoCertVerification;

impl ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn ensure_crypto_provider() {
    CRYPTO_INIT.get_or_init(|| {
        let _ = default_provider().install_default();
    });
}

fn build_root_store() -> RootCertStore {
    let mut store = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for err in &native.errors {
        tracing::warn!(
            target: "routeward::proxy::tls",
            "Partial error loading OS root certificates: {err}"
        );
    }
    for cert in native.certs {
        let _ = store.add(cert);
    }
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    store
}

pub fn build_client_config(skip_verify: bool) -> Arc<ClientConfig> {
    ensure_crypto_provider();
    if skip_verify {
        INSECURE_TLS_CONFIG
            .get_or_init(|| {
                let mut cfg = ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoCertVerification))
                    .with_no_client_auth();
                // Keep ALPN empty so CONNECT proxies always stay on HTTP/1.1.
                cfg.alpn_protocols.clear();
                Arc::new(cfg)
            })
            .clone()
    } else {
        STANDARD_TLS_CONFIG
            .get_or_init(|| {
                let roots = build_root_store();
                let mut cfg = ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                cfg.alpn_protocols.clear();
                Arc::new(cfg)
            })
            .clone()
    }
}

/// Resolves the effective TLS SNI/certificate verification host for an upstream proxy node.
pub fn resolve_tls_server_name(node: &ProxyNode, spn_host_override: Option<&str>) -> String {
    node.sni
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| spn_host_override.map(str::trim).filter(|s| !s.is_empty()))
        .unwrap_or(node.host.as_str())
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

/// Wraps an established byte stream in a rustls client TLS session.
pub async fn wrap_client_stream<S: AsyncTunnelStream + 'static>(
    stream: S,
    server_name: &str,
    skip_verify: bool,
) -> RouteWardResult<Box<dyn AsyncTunnelStream>> {
    let trimmed = server_name
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let parsed_name = ServerName::try_from(trimmed.to_string()).map_err(|err| {
        RouteWardError::ProtocolHandshake {
            key: ERR_KEY_HANDSHAKE_FAILED,
            detail: format!("Invalid TLS server name \"{trimmed}\": {err}"),
        }
    })?;

    if skip_verify {
        tracing::warn!(
            target: "routeward::proxy::tls",
            "TLS certificate verification disabled for proxy host \"{trimmed}\" (tlsSkipVerify=true)"
        );
    }

    let connector = TlsConnector::from(build_client_config(skip_verify));
    let tls_stream = connector
        .connect(parsed_name, stream)
        .await
        .map_err(|err| RouteWardError::ProtocolHandshake {
            key: ERR_KEY_HANDSHAKE_FAILED,
            detail: format!("TLS handshake failed for \"{trimmed}\": {err}"),
        })?;
    Ok(Box::new(tls_stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::sni::TlsSniExtractor;
    use tokio::io::{duplex, AsyncReadExt};

    #[test]
    fn builds_standard_and_insecure_tls_configs_without_h2_alpn() {
        let standard = build_client_config(false);
        assert!(standard.alpn_protocols.is_empty());
        let insecure = build_client_config(true);
        assert!(insecure.alpn_protocols.is_empty());
    }

    #[tokio::test]
    async fn wrap_client_stream_emits_client_hello_with_configured_sni() {
        let (client, mut server) = duplex(8192);
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = server.read(&mut buf).await.unwrap_or(0);
            TlsSniExtractor::extract_sni(&buf[..n])
        });

        let res = wrap_client_stream(client, "proxy.corp.example", false).await;
        assert!(res.is_err());
        let extracted = reader.await.expect("server task");
        assert_eq!(extracted.as_deref(), Some("proxy.corp.example"));
    }
}
