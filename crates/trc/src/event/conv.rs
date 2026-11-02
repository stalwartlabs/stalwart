/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, fmt::Debug, str::FromStr, time::Duration};

use compact_str::{CompactString, ToCompactString, format_compact};

use crate::*;
use mail_auth::{arc::ArcError, dkim::DkimError, dkim2::Dkim2Error};

impl AsRef<EventType> for Error {
    fn as_ref(&self) -> &EventType {
        &self.0.inner
    }
}

impl From<&'static str> for Value {
    fn from(value: &'static str) -> Self {
        Self::String(CompactString::const_new(value))
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::String(CompactString::from_string_buffer(value))
    }
}

impl From<CompactString> for Value {
    fn from(value: CompactString) -> Self {
        Self::String(value)
    }
}

impl From<Box<str>> for Value {
    fn from(value: Box<str>) -> Self {
        Self::String(CompactString::from(value))
    }
}

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Self::UInt(value)
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl From<f32> for Value {
    fn from(value: f32) -> Self {
        Self::Float(value.into())
    }
}

impl From<u16> for Value {
    fn from(value: u16) -> Self {
        Self::UInt(value.into())
    }
}

impl From<i32> for Value {
    fn from(value: i32) -> Self {
        Self::Int(value.into())
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Self {
        Self::UInt(value.into())
    }
}

impl From<usize> for Value {
    fn from(value: usize) -> Self {
        Self::UInt(value as u64)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<IpAddr> for Value {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ip) => Value::Ipv4(ip),
            IpAddr::V6(ip) => Value::Ipv6(ip),
        }
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(value) => value.into(),
            None => Self::None,
        }
    }
}

impl From<Duration> for Value {
    fn from(value: Duration) -> Self {
        Self::Duration(value.as_millis() as u64)
    }
}

impl From<Error> for Value {
    fn from(value: Error) -> Self {
        Self::Event(value)
    }
}

impl From<EventType> for Error {
    fn from(value: EventType) -> Self {
        Error::new(value)
    }
}

impl From<StoreEvent> for Error {
    fn from(value: StoreEvent) -> Self {
        Error::new(EventType::Store(value))
    }
}

impl From<AuthEvent> for Error {
    fn from(value: AuthEvent) -> Self {
        Error::new(EventType::Auth(value))
    }
}

impl From<Vec<u8>> for Value {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(value)
    }
}

impl From<&[u8]> for Value {
    fn from(value: &[u8]) -> Self {
        Self::Bytes(value.to_vec())
    }
}

impl From<Cow<'static, str>> for Value {
    fn from(value: Cow<'static, str>) -> Self {
        match value {
            Cow::Borrowed(value) => Self::String(CompactString::const_new(value)),
            Cow::Owned(value) => Self::String(value.into()),
        }
    }
}

impl<T> From<&crate::Result<T>> for Value
where
    T: Debug,
{
    fn from(value: &crate::Result<T>) -> Self {
        match value {
            Ok(value) => format_compact!("{:?}", value).into(),
            Err(err) => Value::Event(err.clone()),
        }
    }
}

impl<T> From<Vec<T>> for Value
where
    T: Into<Value>,
{
    fn from(value: Vec<T>) -> Self {
        Self::Array(value.into_iter().map(Into::into).collect())
    }
}

impl<T> From<&[T]> for Value
where
    T: Into<Value> + Clone,
{
    fn from(value: &[T]) -> Self {
        Self::Array(value.iter().map(|v| v.clone().into()).collect())
    }
}

impl EventType {
    pub fn from_io_error(self, err: std::io::Error) -> Error {
        self.reason(err).details("I/O error")
    }

    pub fn from_json_error(self, err: serde_json::Error) -> Error {
        self.reason(err).details("JSON deserialization failed")
    }

    pub fn from_http_error(self, err: reqwest::Error) -> Error {
        self.into_err()
            .ctx_opt(
                Key::Url,
                err.url().map(|url| url.as_ref().to_compact_string()),
            )
            .ctx_opt(Key::Code, err.status().map(|status| status.as_u16()))
            .reason(err)
    }

    pub fn from_http_str_error(self, err: reqwest::header::ToStrError) -> Error {
        self.reason(err)
            .details("Failed to convert header to string")
    }
}

impl From<mail_auth::Error> for Error {
    fn from(err: mail_auth::Error) -> Self {
        match err {
            mail_auth::Error::Parse => EventType::MailAuth(MailAuthEvent::ParseError).into_err(),
            mail_auth::Error::MissingParameters => {
                EventType::MailAuth(MailAuthEvent::MissingParameters).into_err()
            }
            mail_auth::Error::NoHeadersFound => {
                EventType::MailAuth(MailAuthEvent::NoHeadersFound).into_err()
            }
            mail_auth::Error::Io(details) => EventType::MailAuth(MailAuthEvent::Io)
                .into_err()
                .details(CompactString::from(details)),
            mail_auth::Error::Base64 => EventType::MailAuth(MailAuthEvent::Base64).into_err(),
            mail_auth::Error::NotAligned => {
                EventType::MailAuth(MailAuthEvent::PolicyNotAligned).into_err()
            }
            mail_auth::Error::Crypto(err) => match err {
                mail_auth::crypto::CryptoError::Library(details) => {
                    EventType::MailAuth(MailAuthEvent::Crypto)
                        .into_err()
                        .details(CompactString::from(details))
                }
                mail_auth::crypto::CryptoError::FailedVerification => {
                    EventType::Dkim(DkimEvent::VerificationFailed)
                        .into_err()
                        .details(err.to_compact_string())
                }
                mail_auth::crypto::CryptoError::IncompatibleAlgorithms
                | mail_auth::crypto::CryptoError::MalformedPublicKey => {
                    EventType::Dkim(DkimEvent::PublicKeyError)
                        .into_err()
                        .details(err.to_compact_string())
                }
            },
            mail_auth::Error::Dns(err) => match err {
                mail_auth::DnsError::Resolver(details) => {
                    EventType::MailAuth(MailAuthEvent::DnsError)
                        .into_err()
                        .details(CompactString::from(details))
                }
                mail_auth::DnsError::RecordNotFound(code) => {
                    EventType::MailAuth(MailAuthEvent::DnsRecordNotFound)
                        .into_err()
                        .code(code.to_str())
                }
                mail_auth::DnsError::InvalidRecordType => {
                    EventType::MailAuth(MailAuthEvent::DnsInvalidRecordType).into_err()
                }
            },
            mail_auth::Error::Dkim(err) => EventType::Dkim(match err {
                DkimError::UnsupportedVersion
                | DkimError::UnsupportedAlgorithm
                | DkimError::UnsupportedCanonicalization
                | DkimError::AuidMismatch
                | DkimError::SignatureExpired
                | DkimError::BodyLengthTag => DkimEvent::SignatureInvalid,
                DkimError::UnsupportedKeyType | DkimError::PublicKeyRevoked => {
                    DkimEvent::PublicKeyError
                }
                DkimError::BodyHashMismatch => DkimEvent::HashMismatch,
            })
            .into_err()
            .details(err.to_compact_string()),
            mail_auth::Error::Arc(err) => EventType::Arc(match err {
                ArcError::ChainTooLong
                | ArcError::InvalidInstance(_)
                | ArcError::InvalidChainValidation
                | ArcError::BrokenChain => ArcEvent::ChainInvalid,
                ArcError::HasHeaderTag | ArcError::SignatureExpired | ArcError::BodyLengthTag => {
                    ArcEvent::SignatureInvalid
                }
                ArcError::BodyHashMismatch => ArcEvent::HashMismatch,
            })
            .into_err()
            .details(err.to_compact_string()),
            mail_auth::Error::Dkim2(err) => EventType::Dkim2(match &err {
                Dkim2Error::InstanceMissing(_)
                | Dkim2Error::InstanceSyntax(_)
                | Dkim2Error::InstanceTagMissing { .. }
                | Dkim2Error::InstanceNotSigned(_)
                | Dkim2Error::InstanceDuplicateHash(_)
                | Dkim2Error::UnknownHash { .. } => Dkim2Event::InstanceInvalid,
                Dkim2Error::SignatureMissing(_)
                | Dkim2Error::SignatureSyntax(_)
                | Dkim2Error::SignatureTagMissing { .. }
                | Dkim2Error::SignatureTagUnexpected { .. }
                | Dkim2Error::DuplicateSelector(_)
                | Dkim2Error::TooManySelectors(_)
                | Dkim2Error::UnknownAlgorithm { .. } => Dkim2Event::SignatureInvalid,
                Dkim2Error::SequenceGap(_)
                | Dkim2Error::SequenceOverflow
                | Dkim2Error::ChainTooLong
                | Dkim2Error::NotFullyVerified => Dkim2Event::ChainInvalid,
                Dkim2Error::SignatureExpired(_) | Dkim2Error::SignatureFromFuture(_) => {
                    Dkim2Event::TimestampInvalid
                }
                Dkim2Error::MailFromMismatch { .. } | Dkim2Error::RcptToMismatch { .. } => {
                    Dkim2Event::EnvelopeMismatch
                }
                Dkim2Error::MailFromDomainMismatch(_)
                | Dkim2Error::NextDomainMismatch(_)
                | Dkim2Error::CustodyMailFromMismatch { .. }
                | Dkim2Error::CustodyDomainMismatch { .. }
                | Dkim2Error::FromNotAuthentic(_) => Dkim2Event::CustodyBroken,
                Dkim2Error::PublicKeyFetch { .. }
                | Dkim2Error::PublicKeyMissing { .. }
                | Dkim2Error::PublicKeyMultiple { .. }
                | Dkim2Error::PublicKeySyntax { .. }
                | Dkim2Error::PublicKeyMalformed { .. }
                | Dkim2Error::PublicKeyAlgorithmMismatch { .. }
                | Dkim2Error::PublicKeyRevoked { .. } => Dkim2Event::PublicKeyError,
                Dkim2Error::IncorrectSignature { .. } | Dkim2Error::NoSignatureGroupPassed(_) => {
                    Dkim2Event::VerificationFailed
                }
                Dkim2Error::HeaderHashMismatch { .. }
                | Dkim2Error::BodyHashMismatch { .. }
                | Dkim2Error::NoHashGroupPassed(_) => Dkim2Event::HashMismatch,
                Dkim2Error::InvalidJson(_)
                | Dkim2Error::InvalidRecipe { .. }
                | Dkim2Error::NullBodyRecipe(_)
                | Dkim2Error::RecipeSyntax
                | Dkim2Error::HeaderNotRepresentable
                | Dkim2Error::BodyUnreconstructable => Dkim2Event::RecipeError,
            })
            .into_err()
            .details(err.to_compact_string()),
        }
    }
}

impl From<&mail_auth::DkimResult> for Error {
    fn from(value: &mail_auth::DkimResult) -> Self {
        match value.clone() {
            mail_auth::DkimResult::Pass => Error::new(EventType::Dkim(DkimEvent::Pass)),
            mail_auth::DkimResult::Neutral(err) => {
                Error::new(EventType::Dkim(DkimEvent::Neutral)).caused_by(Error::from(err))
            }
            mail_auth::DkimResult::Fail(err) => {
                Error::new(EventType::Dkim(DkimEvent::Fail)).caused_by(Error::from(err))
            }
            mail_auth::DkimResult::PermError(err) => {
                Error::new(EventType::Dkim(DkimEvent::PermError)).caused_by(Error::from(err))
            }
            mail_auth::DkimResult::TempError(err) => {
                Error::new(EventType::Dkim(DkimEvent::TempError)).caused_by(Error::from(err))
            }
            mail_auth::DkimResult::None => Error::new(EventType::Dkim(DkimEvent::None)),
        }
    }
}

impl From<&mail_auth::Dkim2Result> for Error {
    fn from(value: &mail_auth::Dkim2Result) -> Self {
        match value.clone() {
            mail_auth::Dkim2Result::Pass => Error::new(EventType::Dkim(DkimEvent::Pass)),
            mail_auth::Dkim2Result::Fail(err) => {
                Error::new(EventType::Dkim(DkimEvent::Fail)).caused_by(Error::from(err))
            }
            mail_auth::Dkim2Result::PermError(err) => {
                Error::new(EventType::Dkim(DkimEvent::PermError)).caused_by(Error::from(err))
            }
            mail_auth::Dkim2Result::TempError(err) => {
                Error::new(EventType::Dkim(DkimEvent::TempError)).caused_by(Error::from(err))
            }
            mail_auth::Dkim2Result::None => Error::new(EventType::Dkim(DkimEvent::None)),
        }
    }
}

impl From<&mail_auth::dkim2::Dkim2Output<'_>> for Error {
    fn from(value: &mail_auth::dkim2::Dkim2Output<'_>) -> Self {
        Error::from(value.result()).ctx_opt(
            Key::Domain,
            value
                .chain()
                .first()
                .map(|link| link.signature.d.to_compact_string()),
        )
    }
}

impl From<&mail_auth::DmarcResult> for Error {
    fn from(value: &mail_auth::DmarcResult) -> Self {
        match value.clone() {
            mail_auth::DmarcResult::Pass => Error::new(EventType::Dmarc(DmarcEvent::Pass)),
            mail_auth::DmarcResult::Fail(err) => {
                Error::new(EventType::Dmarc(DmarcEvent::Fail)).caused_by(Error::from(err))
            }
            mail_auth::DmarcResult::PermError(err) => {
                Error::new(EventType::Dmarc(DmarcEvent::PermError)).caused_by(Error::from(err))
            }
            mail_auth::DmarcResult::TempError(err) => {
                Error::new(EventType::Dmarc(DmarcEvent::TempError)).caused_by(Error::from(err))
            }
            mail_auth::DmarcResult::None => Error::new(EventType::Dmarc(DmarcEvent::None)),
        }
    }
}

impl From<&mail_auth::DkimOutput<'_>> for Error {
    fn from(value: &mail_auth::DkimOutput<'_>) -> Self {
        Error::from(value.result()).ctx_opt(
            Key::Domain,
            value.signature().map(|s| s.d.to_compact_string()),
        )
    }
}

impl From<&mail_auth::IprevOutput> for Error {
    fn from(value: &mail_auth::IprevOutput) -> Self {
        match value.result().clone() {
            mail_auth::IprevResult::Pass => Error::new(EventType::Iprev(IprevEvent::Pass)),
            mail_auth::IprevResult::Fail(err) => {
                Error::new(EventType::Iprev(IprevEvent::Fail)).caused_by(Error::from(err))
            }
            mail_auth::IprevResult::PermError(err) => {
                Error::new(EventType::Iprev(IprevEvent::PermError)).caused_by(Error::from(err))
            }
            mail_auth::IprevResult::TempError(err) => {
                Error::new(EventType::Iprev(IprevEvent::TempError)).caused_by(Error::from(err))
            }
            mail_auth::IprevResult::None => Error::new(EventType::Iprev(IprevEvent::None)),
        }
        .ctx_opt(
            Key::Details,
            value.ptr.as_ref().map(|s| {
                s.iter()
                    .map(|v| Value::String(v.as_ref().into()))
                    .collect::<Vec<_>>()
            }),
        )
    }
}

impl From<&mail_auth::SpfOutput> for Error {
    fn from(value: &mail_auth::SpfOutput) -> Self {
        Error::new(EventType::Spf(match value.result() {
            mail_auth::SpfResult::Pass => SpfEvent::Pass,
            mail_auth::SpfResult::Fail => SpfEvent::Fail,
            mail_auth::SpfResult::SoftFail => SpfEvent::SoftFail,
            mail_auth::SpfResult::Neutral => SpfEvent::Neutral,
            mail_auth::SpfResult::PermError => SpfEvent::PermError,
            mail_auth::SpfResult::TempError => SpfEvent::TempError,
            mail_auth::SpfResult::None => SpfEvent::None,
        }))
        .ctx_opt(
            Key::Details,
            value.explanation().map(|s| s.to_compact_string()),
        )
    }
}

impl From<rkyv::rancor::Error> for Error {
    fn from(value: rkyv::rancor::Error) -> Self {
        Error::new(EventType::Store(StoreEvent::DeserializeError))
            .reason(value)
            .details("Rkyv de/serialization failed")
    }
}

pub trait AssertSuccess
where
    Self: Sized,
{
    fn assert_success(
        self,
        cause: EventType,
    ) -> impl std::future::Future<Output = crate::Result<Self>> + Send;
}

impl AssertSuccess for reqwest::Response {
    async fn assert_success(self, cause: EventType) -> crate::Result<Self> {
        let status = self.status();
        if status.is_success() {
            Ok(self)
        } else {
            Err(cause
                .ctx(Key::Code, status.as_u16())
                .details("HTTP request failed")
                .ctx_opt(Key::Reason, self.text().await.map(CompactString::from).ok()))
        }
    }
}

impl FromStr for EventType {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        EventType::parse(s).ok_or(())
    }
}

impl FromStr for Key {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Key::parse(s).ok_or(())
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/trc/src/event/conv/tests.rs"]
mod tests;
