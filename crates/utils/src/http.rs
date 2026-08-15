/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose};
use reqwest::{
    Client, ClientBuilder,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, USER_AGENT},
};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, aws_lc_rs},
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::{
    str::FromStr,
    sync::{Arc, LazyLock},
    time::Duration,
};

struct SharedTlsConfigs {
    strict: ClientConfig,
    strict_http1: ClientConfig,
    insecure: ClientConfig,
    insecure_http1: ClientConfig,
}

#[derive(Debug)]
struct NoCertificateVerification(Arc<CryptoProvider>);

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

static SHARED_TLS_CONFIGS: LazyLock<SharedTlsConfigs> = LazyLock::new(|| {
    let provider = Arc::new(aws_lc_rs::default_provider());

    let verifier = rustls_platform_verifier::Verifier::new(provider.clone())
        .expect("Failed to load the platform certificate verifier");

    let mut strict = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("Failed to build the TLS client configuration")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    strict.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let mut insecure = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("Failed to build the TLS client configuration")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification(provider)))
        .with_no_client_auth();
    insecure.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let mut strict_http1 = strict.clone();
    strict_http1.alpn_protocols = vec![b"http/1.1".to_vec()];

    let mut insecure_http1 = insecure.clone();
    insecure_http1.alpn_protocols = vec![b"http/1.1".to_vec()];

    SharedTlsConfigs {
        strict,
        strict_http1,
        insecure,
        insecure_http1,
    }
});

pub fn init_shared_tls_configs() {
    LazyLock::force(&SHARED_TLS_CONFIGS);
}

pub fn shared_tls_config(allow_invalid_certs: bool) -> ClientConfig {
    if allow_invalid_certs {
        SHARED_TLS_CONFIGS.insecure.clone()
    } else {
        SHARED_TLS_CONFIGS.strict.clone()
    }
}

pub fn http_client_builder(allow_invalid_certs: bool) -> ClientBuilder {
    Client::builder().use_preconfigured_tls(shared_tls_config(allow_invalid_certs))
}

pub fn http1_client_builder(allow_invalid_certs: bool) -> ClientBuilder {
    let tls = if allow_invalid_certs {
        SHARED_TLS_CONFIGS.insecure_http1.clone()
    } else {
        SHARED_TLS_CONFIGS.strict_http1.clone()
    };

    Client::builder().http1_only().use_preconfigured_tls(tls)
}

pub fn unpooled_http_client(allow_invalid_certs: bool) -> Client {
    http_client_builder(allow_invalid_certs)
        .pool_max_idle_per_host(0)
        .build()
        .unwrap_or_default()
}

pub fn build_http_client(
    raw_headers: impl IntoIterator<Item = (String, String)>,
    username: Option<&str>,
    password: Option<&str>,
    token: Option<&str>,
    content_type: Option<&str>,
    timeout: Duration,
    allow_invalid_certs: bool,
) -> Result<Client, String> {
    let mut headers = build_http_headers(raw_headers, username, password, token, content_type)?;
    headers.insert(USER_AGENT, "Stalwart/1.0.0".parse().unwrap());

    match http_client_builder(allow_invalid_certs)
        .connect_timeout(timeout)
        .default_headers(headers)
        .build()
    {
        Ok(client) => Ok(client),
        Err(err) => Err(format!("Failed to build HTTP client: {}", err)),
    }
}

pub fn build_http_headers(
    raw_headers: impl IntoIterator<Item = (String, String)>,
    username: Option<&str>,
    password: Option<&str>,
    token: Option<&str>,
    content_type: Option<&str>,
) -> Result<HeaderMap, String> {
    let mut headers = HeaderMap::new();

    if let Some(content_type) = content_type {
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(content_type).unwrap());
    }

    for (header, value) in raw_headers
        .into_iter()
        .map(|(k, v)| {
            Ok((
                HeaderName::from_str(k.trim())
                    .map_err(|err| format!("Invalid header {k:?}: {err}",))?,
                HeaderValue::from_str(v.trim())
                    .map_err(|err| format!("Invalid value {v:?}: {err}",))?,
            ))
        })
        .collect::<Result<Vec<(HeaderName, HeaderValue)>, String>>()?
    {
        headers.insert(header, value);
    }

    if let (Some(name), Some(secret)) = (username, password) {
        headers.insert(
            AUTHORIZATION,
            format!(
                "Basic {}",
                general_purpose::STANDARD.encode(format!("{}:{}", name, secret))
            )
            .parse()
            .unwrap(),
        );
    } else if let Some(token) = token {
        headers.insert(AUTHORIZATION, format!("Bearer {}", token).parse().unwrap());
    }

    Ok(headers)
}
