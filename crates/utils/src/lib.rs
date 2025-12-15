/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod bimap;
pub mod cache;
pub mod chained_bytes;
pub mod cheeky_hash;
pub mod codec;
pub mod config;
pub mod glob;
pub mod map;
pub mod snowflake;
pub mod template;
pub mod topological;
pub mod url_params;

use compact_str::ToCompactString;
use futures::StreamExt;
use reqwest::Response;
use rustls::{
    ClientConfig, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};
use rustls_pki_types::TrustAnchor;
use std::sync::Arc;

pub trait HttpLimitResponse: Sync + Send {
    fn bytes_with_limit(
        self,
        limit: usize,
    ) -> impl std::future::Future<Output = reqwest::Result<Option<Vec<u8>>>> + Send;
}

impl HttpLimitResponse for Response {
    async fn bytes_with_limit(self, limit: usize) -> reqwest::Result<Option<Vec<u8>>> {
        if self
            .content_length()
            .is_some_and(|len| len as usize > limit)
        {
            return Ok(None);
        }

        let mut bytes = Vec::with_capacity(std::cmp::min(limit, 1024));
        let mut stream = self.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len() + chunk.len() > limit {
                return Ok(None);
            }
            bytes.extend_from_slice(&chunk);
        }

        Ok(Some(bytes))
    }
}

pub trait UnwrapFailure<T> {
    fn failed(self, action: &str) -> T;
}

impl<T> UnwrapFailure<T> for Option<T> {
    fn failed(self, message: &str) -> T {
        match self {
            Some(result) => result,
            None => {
                trc::event!(
                    Server(trc::ServerEvent::StartupError),
                    Details = message.to_compact_string()
                );
                eprintln!("{message}");
                std::process::exit(1);
            }
        }
    }
}

impl<T, E: std::fmt::Display> UnwrapFailure<T> for Result<T, E> {
    fn failed(self, message: &str) -> T {
        match self {
            Ok(result) => result,
            Err(err) => {
                trc::event!(
                    Server(trc::ServerEvent::StartupError),
                    Details = message.to_compact_string(),
                    Reason = err.to_compact_string()
                );

                #[cfg(feature = "test_mode")]
                panic!("{message}: {err}");

                #[cfg(not(feature = "test_mode"))]
                {
                    eprintln!("{message}: {err}");
                    std::process::exit(1);
                }
            }
        }
    }
}

pub fn failed(message: &str) -> ! {
    trc::event!(
        Server(trc::ServerEvent::StartupError),
        Details = message.to_compact_string(),
    );
    eprintln!("{message}");
    std::process::exit(1);
}

pub async fn wait_for_shutdown() {
    #[cfg(not(target_env = "msvc"))]
    let signal = {
        use tokio::signal::unix::{SignalKind, signal};

        let mut h_term = signal(SignalKind::terminate()).failed("start signal handler");
        let mut h_int = signal(SignalKind::interrupt()).failed("start signal handler");

        tokio::select! {
            _ = h_term.recv() => "SIGTERM",
            _ = h_int.recv() => "SIGINT",
        }
    };

    #[cfg(target_env = "msvc")]
    let signal = {
        match tokio::signal::ctrl_c().await {
            Ok(()) => "SIGINT",
            Err(err) => {
                trc::event!(
                    Server(trc::ServerEvent::ThreadError),
                    Details = "Unable to listen for shutdown signal",
                    Reason = err.to_string(),
                );
                "Error"
            }
        }
    };

    trc::event!(Server(trc::ServerEvent::Shutdown), CausedBy = signal);
}

pub fn rustls_client_config(allow_invalid_certs: bool) -> ClientConfig {
    let config = ClientConfig::builder();

    if !allow_invalid_certs {
        let mut root_cert_store = RootCertStore::empty();

        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| TrustAnchor {
            subject: ta.subject.clone(),
            subject_public_key_info: ta.subject_public_key_info.clone(),
            name_constraints: ta.name_constraints.clone(),
        }));

        config
            .with_root_certificates(root_cert_store)
            .with_no_client_auth()
    } else {
        config
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DummyVerifier {}))
            .with_no_client_auth()
    }
}

pub trait DomainPart {
    fn to_lowercase_domain(&self) -> String;
    fn domain_part(&self) -> &str;
    fn try_domain_part(&self) -> Option<&str>;
    fn try_local_part(&self) -> Option<&str>;
}

impl<T: AsRef<str>> DomainPart for T {
    fn to_lowercase_domain(&self) -> String {
        let address = self.as_ref();
        if let Some((local, domain)) = address.rsplit_once('@') {
            let mut address = String::with_capacity(address.len());
            address.push_str(local);
            address.push('@');
            for ch in domain.chars() {
                for ch in ch.to_lowercase() {
                    address.push(ch);
                }
            }
            address
        } else {
            address.to_string()
        }
    }

    #[inline(always)]
    fn try_domain_part(&self) -> Option<&str> {
        self.as_ref().rsplit_once('@').map(|(_, d)| d)
    }

    #[inline(always)]
    fn try_local_part(&self) -> Option<&str> {
        self.as_ref().rsplit_once('@').map(|(l, _)| l)
    }

    #[inline(always)]
    fn domain_part(&self) -> &str {
        self.as_ref()
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or_default()
    }
}

#[derive(Debug)]
struct DummyVerifier;

impl ServerCertVerifier for DummyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

// Basic email sanitizer
pub fn sanitize_email(email: &str) -> Option<String> {
    let mut result = String::with_capacity(email.len());
    let mut found_local = false;
    let mut found_domain = false;
    let mut last_ch = char::from(0);

    for ch in email.chars() {
        if !ch.is_whitespace() {
            if ch == '@' {
                if !result.is_empty() && !found_local {
                    found_local = true;
                } else {
                    return None;
                }
            } else if ch == '.' {
                if !(last_ch.is_alphanumeric() || last_ch == '-' || last_ch == '_') {
                    return None;
                } else if found_local {
                    found_domain = true;
                }
            }
            last_ch = ch;
            for ch in ch.to_lowercase() {
                result.push(ch);
            }
        }
    }

    if found_domain
        && last_ch != '.'
        && psl::domain(result.as_bytes()).is_some_and(|d| d.suffix().typ().is_some())
    {
        Some(result)
    } else {
        None
    }
}
