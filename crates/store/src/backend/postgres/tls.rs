/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// Credits: https://github.com/jbg/tokio-postgres-rustls

use std::{
    convert::TryFrom,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use aws_lc_rs::digest;
use futures::future::{FutureExt, TryFutureExt};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect};
use tokio_rustls::{TlsConnector, client::TlsStream};
use x509_parser::{
    asn1_rs::oid,
    oid_registry::{
        OID_HASH_SHA1, OID_MD5_WITH_RSA, OID_NIST_HASH_SHA256, OID_NIST_HASH_SHA384,
        OID_NIST_HASH_SHA512, OID_PKCS1_MD5WITHRSAENC, OID_PKCS1_RSASSAPSS, OID_PKCS1_SHA1WITHRSA,
        OID_PKCS1_SHA224WITHRSA, OID_PKCS1_SHA256WITHRSA, OID_PKCS1_SHA384WITHRSA,
        OID_PKCS1_SHA512WITHRSA, OID_SHA1_WITH_RSA, OID_SIG_DSA_WITH_SHA1,
        OID_SIG_ECDSA_WITH_SHA224, OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ECDSA_WITH_SHA384,
        OID_SIG_ECDSA_WITH_SHA512,
    },
    parse_x509_certificate,
    prelude::X509Certificate,
    signature_algorithm::RsaSsaPssParams,
};

#[derive(Clone)]
pub struct MakeRustlsConnect {
    config: Arc<ClientConfig>,
}

impl MakeRustlsConnect {
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> MakeTlsConnect<S> for MakeRustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = RustlsStream<S>;
    type TlsConnect = RustlsConnect;
    type Error = io::Error;

    fn make_tls_connect(&mut self, hostname: &str) -> io::Result<RustlsConnect> {
        ServerName::try_from(hostname.to_string())
            .map(|dns_name| {
                RustlsConnect(Some(RustlsConnectData {
                    hostname: dns_name,
                    connector: Arc::clone(&self.config).into(),
                }))
            })
            .or(Ok(RustlsConnect(None)))
    }
}

pub struct RustlsConnect(Option<RustlsConnectData>);

struct RustlsConnectData {
    hostname: ServerName<'static>,
    connector: TlsConnector,
}

impl<S> TlsConnect<S> for RustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = RustlsStream<S>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<RustlsStream<S>>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        match self.0 {
            None => Box::pin(core::future::ready(Err(io::ErrorKind::InvalidInput.into()))),
            Some(c) => c
                .connector
                .connect(c.hostname, stream)
                .map_ok(|s| RustlsStream(Box::pin(s)))
                .boxed(),
        }
    }
}

pub struct RustlsStream<S>(Pin<Box<TlsStream<S>>>);

fn cb_digest_for_cert(cert: &X509Certificate<'_>) -> Option<&'static digest::Algorithm> {
    let sig_alg = cert.signature_algorithm.oid();
    // Signature algorithms that use a digest should use the same digest for channel binding:
    if sig_alg == &OID_PKCS1_SHA512WITHRSA || sig_alg == &OID_SIG_ECDSA_WITH_SHA512 {
        Some(&digest::SHA512)
    } else if sig_alg == &OID_PKCS1_SHA384WITHRSA || sig_alg == &OID_SIG_ECDSA_WITH_SHA384 {
        Some(&digest::SHA384)
    } else if sig_alg == &OID_PKCS1_MD5WITHRSAENC
        || sig_alg == &OID_MD5_WITH_RSA
        || sig_alg == &OID_PKCS1_SHA1WITHRSA
        || sig_alg == &OID_SHA1_WITH_RSA
        || sig_alg == &OID_SIG_DSA_WITH_SHA1
        || sig_alg == &OID_PKCS1_SHA256WITHRSA
        || sig_alg == &OID_SIG_ECDSA_WITH_SHA256
    {
        // ...apart from MD5 or SHA1, which use SHA256 for channel binding, as per RFC 5929 section 4.1:
        Some(&digest::SHA256)
    } else if sig_alg == &OID_PKCS1_SHA224WITHRSA || sig_alg == &OID_SIG_ECDSA_WITH_SHA224 {
        Some(&digest::SHA224)
    } else if sig_alg == &OID_PKCS1_RSASSAPSS {
        // For RSASSA-PSS, the hash algorithm is specified in the parameters of the signature algorithm:
        let params_any = cert.signature_algorithm.parameters()?;
        let pss = RsaSsaPssParams::try_from(params_any).ok()?;
        let alg = pss.hash_algorithm_oid();
        if alg == &OID_NIST_HASH_SHA512 {
            Some(&digest::SHA512)
        } else if alg == &OID_NIST_HASH_SHA384 {
            Some(&digest::SHA384)
        } else if alg == &OID_NIST_HASH_SHA256 || alg == &OID_HASH_SHA1 {
            Some(&digest::SHA256)
        } else if alg == &oid!(2.16.840.1.101.3.4.2.4) {
            // id-sha224 from RFC 4055 ^
            Some(&digest::SHA224)
        } else {
            None
        }
    } else {
        None
    }
}

impl<S> tokio_postgres::tls::TlsStream for RustlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn channel_binding(&self) -> ChannelBinding {
        let (_, session) = self.0.get_ref();
        match session.peer_certificates() {
            Some(certs) if !certs.is_empty() => match parse_x509_certificate(certs[0].as_ref()) {
                Ok((_, cert)) => {
                    if let Some(digest_alg) = cb_digest_for_cert(&cert) {
                        let dgst = digest::digest(digest_alg, certs[0].as_ref());
                        ChannelBinding::tls_server_end_point(dgst.as_ref().into())
                    } else {
                        ChannelBinding::none()
                    }
                }
                Err(_) => ChannelBinding::none(),
            },
            _ => ChannelBinding::none(),
        }
    }
}

impl<S> AsyncRead for RustlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        self.0.as_mut().poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for RustlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<tokio::io::Result<usize>> {
        self.0.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<tokio::io::Result<()>> {
        self.0.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<tokio::io::Result<()>> {
        self.0.as_mut().poll_shutdown(cx)
    }
}
