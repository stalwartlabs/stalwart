/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{error::TlsError, rules::Policy};
use rustls::{
    CertificateError, DigitallySignedStruct, Error, OtherError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature},
};
use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use std::{borrow::Cow, sync::Arc};
use webpki::{EndEntityCert, KeyUsage, VerifiedPath, anchor_from_trusted_cert};
use x509_parser::{
    certificate::X509Certificate, prelude::FromDer, time::ASN1Time, x509::X509Version,
};

#[derive(Debug)]
pub(crate) struct PeerVerifier {
    anchors: Box<[TrustAnchor<'static>]>,
    roots: Box<[CertificateDer<'static>]>,
    pinned: Box<[CertificateDer<'static>]>,
    issuers: Box<[CertificateDer<'static>]>,
    policy: Policy,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PeerVerifier {
    pub(crate) fn new(
        roots: Vec<CertificateDer<'static>>,
        policy: Policy,
        algorithms: WebPkiSupportedAlgorithms,
    ) -> Result<Self, TlsError> {
        let mut anchors = Vec::with_capacity(roots.len());
        let mut self_issued = Vec::with_capacity(roots.len());
        let mut pinned = Vec::new();
        let mut issuers = Vec::new();
        for root in roots {
            let (_, cert) = X509Certificate::from_der(&root).map_err(|_| TlsError::InvalidCa)?;
            let is_self_issued = cert.subject().as_raw() == cert.issuer().as_raw();
            let signs = signs_certificates(&cert);
            match (is_self_issued, signs) {
                (true, true) => match anchor_from_trusted_cert(&root) {
                    Ok(anchor) => {
                        anchors.push(anchor.to_owned());
                        self_issued.push(root);
                    }
                    Err(_) => pinned.push(root),
                },
                (true, false) => pinned.push(root),
                (false, _) => issuers.push(root),
            }
        }
        Ok(Self {
            anchors: anchors.into_boxed_slice(),
            roots: self_issued.into_boxed_slice(),
            pinned: pinned.into_boxed_slice(),
            issuers: issuers.into_boxed_slice(),
            policy,
            algorithms,
        })
    }

    fn verify_chain(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<&CertificateDer<'static>, Error> {
        if let Some(root) = self
            .roots
            .iter()
            .chain(&self.pinned)
            .find(|root| *root == end_entity)
        {
            return trusted_end_entity(root, now).map(|()| root);
        }
        let cert = EndEntityCert::try_from(end_entity).map_err(certificate_error)?;
        let intermediates = if self.issuers.is_empty() {
            Cow::Borrowed(intermediates)
        } else {
            Cow::Owned(
                intermediates
                    .iter()
                    .chain(&self.issuers)
                    .map(|cert| CertificateDer::from(cert.as_ref()))
                    .collect(),
            )
        };
        let path = cert
            .verify_for_usage(
                self.algorithms.all,
                &self.anchors,
                &intermediates,
                now,
                KeyUsage::server_auth(),
                None,
                Some(&intermediates_sign_certificates),
            )
            .map_err(certificate_error)?;
        let anchor = path.anchor();
        self.anchors
            .iter()
            .position(|candidate| candidate == anchor)
            .and_then(|index| self.roots.get(index))
            .ok_or(Error::InvalidCertificate(CertificateError::UnknownIssuer))
    }
}

impl ServerCertVerifier for PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let root = self.verify_chain(end_entity, intermediates, now)?;
        let root = self.policy.needs_root().then_some(root.as_ref());
        if self.policy.accepts(end_entity, root) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn intermediates_sign_certificates(path: &VerifiedPath<'_>) -> Result<(), webpki::Error> {
    path.intermediate_certificates().try_for_each(|cert| {
        let der = cert.der();
        match X509Certificate::from_der(&der) {
            Ok((_, cert)) if signs_certificates(&cert) => Ok(()),
            _ => Err(webpki::Error::EndEntityUsedAsCa),
        }
    })
}

fn signs_certificates(cert: &X509Certificate<'_>) -> bool {
    let key_cert_sign = match cert.key_usage() {
        Ok(usage) => usage.map(|usage| usage.value.key_cert_sign()),
        Err(_) => return false,
    };
    if key_cert_sign == Some(false) {
        return false;
    }
    match cert.basic_constraints() {
        Ok(Some(constraints)) => constraints.value.ca,
        Ok(None) => cert.version() == X509Version::V1 || key_cert_sign == Some(true),
        Err(_) => false,
    }
}

fn trusted_end_entity(cert: &CertificateDer<'_>, now: UnixTime) -> Result<(), Error> {
    let invalid = Error::InvalidCertificate(CertificateError::BadEncoding);
    let (_, cert) = X509Certificate::from_der(cert).map_err(|_| invalid.clone())?;
    let now = i64::try_from(now.as_secs())
        .ok()
        .and_then(|secs| ASN1Time::from_timestamp(secs).ok())
        .ok_or(invalid)?;
    let validity = cert.validity();
    if now < validity.not_before {
        return Err(Error::InvalidCertificate(CertificateError::NotValidYet));
    }
    if now > validity.not_after {
        return Err(Error::InvalidCertificate(CertificateError::Expired));
    }
    let server_auth = match cert.extended_key_usage() {
        Ok(Some(usage)) => usage.value.server_auth,
        Ok(None) => true,
        Err(_) => false,
    };
    let signing = match cert.key_usage() {
        Ok(Some(usage)) => {
            usage.value.digital_signature()
                || usage.value.key_encipherment()
                || usage.value.key_agreement()
        }
        Ok(None) => true,
        Err(_) => false,
    };
    if server_auth && signing {
        Ok(())
    } else {
        Err(Error::InvalidCertificate(CertificateError::InvalidPurpose))
    }
}

fn certificate_error(err: webpki::Error) -> Error {
    Error::InvalidCertificate(match err {
        webpki::Error::CertExpired { .. } => CertificateError::Expired,
        webpki::Error::CertNotValidYet { .. } => CertificateError::NotValidYet,
        webpki::Error::UnknownIssuer => CertificateError::UnknownIssuer,
        webpki::Error::InvalidSignatureForPublicKey => CertificateError::BadSignature,
        webpki::Error::RequiredEkuNotFoundContext(_) => CertificateError::InvalidPurpose,
        err => CertificateError::Other(OtherError(Arc::new(err))),
    })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/tls/verifier/tests.rs"]
mod tests;
