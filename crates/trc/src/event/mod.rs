/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod conv;
pub mod level;

pub mod enums;
#[allow(clippy::match_like_matches_macro)]
pub mod enums_impl;

use compact_str::ToCompactString;
use std::fmt::Display;

use crate::*;

impl<T> Event<T> {
    pub fn with_capacity(inner: T, capacity: usize) -> Self {
        Self {
            inner,
            keys: Vec::with_capacity(capacity),
        }
    }

    pub fn with_keys(inner: T, keys: Vec<(Key, Value)>) -> Self {
        Self { inner, keys }
    }

    pub fn new(inner: T) -> Self {
        Self {
            inner,
            keys: Vec::with_capacity(5),
        }
    }

    pub fn value(&self, key: Key) -> Option<&Value> {
        self.keys
            .iter()
            .find_map(|(k, v)| if *k == key { Some(v) } else { None })
    }

    pub fn value_as_str(&self, key: Key) -> Option<&str> {
        self.value(key).and_then(|v| v.as_str())
    }

    pub fn value_as_uint(&self, key: Key) -> Option<u64> {
        self.value(key).and_then(|v| v.to_uint())
    }

    pub fn take_value(&mut self, key: Key) -> Option<Value> {
        self.keys.iter_mut().find_map(|(k, v)| {
            if *k == key {
                Some(std::mem::take(v))
            } else {
                None
            }
        })
    }

    pub fn into_boxed(self) -> Box<Self> {
        Box::new(self)
    }
}

impl Error {
    #[inline(always)]
    pub fn new(inner: EventType) -> Self {
        Error(Box::new(Event::new(inner)))
    }

    #[inline(always)]
    pub fn set_ctx(&mut self, key: Key, value: impl Into<Value>) {
        self.0.keys.push((key, value.into()));
    }

    #[inline(always)]
    pub fn ctx(mut self, key: Key, value: impl Into<Value>) -> Self {
        self.0.keys.push((key, value.into()));
        self
    }

    #[inline(always)]
    pub fn ctx_unique(mut self, key: Key, value: impl Into<Value>) -> Self {
        if self.0.keys.iter().all(|(k, _)| *k != key) {
            self.0.keys.push((key, value.into()));
        }
        self
    }

    #[inline(always)]
    pub fn ctx_opt(self, key: Key, value: Option<impl Into<Value>>) -> Self {
        match value {
            Some(value) => self.ctx(key, value),
            None => self,
        }
    }

    #[inline(always)]
    pub fn matches(&self, inner: EventType) -> bool {
        self.0.inner == inner
    }

    #[inline(always)]
    pub fn event_type(&self) -> EventType {
        self.0.inner
    }

    #[inline(always)]
    pub fn span_id(self, session_id: u64) -> Self {
        self.ctx(Key::SpanId, session_id)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Self {
        self.ctx(Key::CausedBy, error)
    }

    #[inline(always)]
    pub fn details(self, error: impl Into<Value>) -> Self {
        self.ctx(Key::Details, error)
    }

    #[inline(always)]
    pub fn code(self, error: impl Into<Value>) -> Self {
        self.ctx(Key::Code, error)
    }

    #[inline(always)]
    pub fn id(self, error: impl Into<Value>) -> Self {
        self.ctx(Key::Id, error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Self {
        self.ctx(Key::Reason, error.to_compact_string())
    }

    #[inline(always)]
    pub fn document_id(self, id: u32) -> Self {
        self.ctx(Key::DocumentId, id)
    }

    #[inline(always)]
    pub fn account_id(self, id: u32) -> Self {
        self.ctx(Key::AccountId, id)
    }

    #[inline(always)]
    pub fn collection(self, id: impl Into<u8>) -> Self {
        self.ctx(Key::Collection, id.into() as u64)
    }

    #[inline(always)]
    pub fn wrap(self, cause: EventType) -> Self {
        Error::new(cause).caused_by(self)
    }

    #[inline(always)]
    pub fn keys(&self) -> &[(Key, Value)] {
        &self.0.keys
    }

    #[inline(always)]
    pub fn value(&self, key: Key) -> Option<&Value> {
        self.0.value(key)
    }

    #[inline(always)]
    pub fn value_as_str(&self, key: Key) -> Option<&str> {
        self.0.value_as_str(key)
    }

    #[inline(always)]
    pub fn value_as_uint(&self, key: Key) -> Option<u64> {
        self.0.value_as_uint(key)
    }

    #[inline(always)]
    pub fn take_value(&mut self, key: Key) -> Option<Value> {
        self.0.take_value(key)
    }

    #[inline(always)]
    pub fn is_assertion_failure(&self) -> bool {
        self.0.inner == EventType::Store(StoreEvent::AssertValueFailed)
    }

    pub fn key(&self, key: Key) -> Option<&Value> {
        self.0
            .keys
            .iter()
            .find_map(|(k, v)| if *k == key { Some(v) } else { None })
    }

    #[inline(always)]
    pub fn is_jmap_method_error(&self) -> bool {
        !matches!(
            self.0.inner,
            EventType::Jmap(
                JmapEvent::UnknownCapability | JmapEvent::NotJson | JmapEvent::NotRequest
            )
        )
    }

    #[inline(always)]
    pub fn must_disconnect(&self) -> bool {
        matches!(
            self.0.inner,
            EventType::Network(_)
                | EventType::Auth(AuthEvent::TooManyAttempts)
                | EventType::Limit(LimitEvent::ConcurrentRequest | LimitEvent::TooManyRequests)
                | EventType::Security(_)
        )
    }

    #[inline(always)]
    pub fn should_write_err(&self) -> bool {
        !matches!(self.0.inner, EventType::Network(_) | EventType::Security(_))
    }

    pub fn corrupted_key(key: &[u8], value: Option<&[u8]>, caused_by: &'static str) -> Error {
        EventType::Store(StoreEvent::DataCorruption)
            .ctx(Key::Key, key)
            .ctx_opt(Key::Value, value)
            .ctx(Key::CausedBy, caused_by)
    }
}

impl Event<EventDetails> {
    pub fn span_id(&self) -> Option<u64> {
        for (key, value) in &self.keys {
            match (key, value) {
                (Key::SpanId, Value::UInt(value)) => return Some(*value),
                (Key::SpanId, Value::Int(value)) => return Some(*value as u64),
                _ => {}
            }
        }

        None
    }
}

impl EventType {
    #[inline(always)]
    pub fn is_span_start(&self) -> bool {
        matches!(
            self,
            EventType::Smtp(SmtpEvent::ConnectionStart)
                | EventType::Imap(ImapEvent::ConnectionStart)
                | EventType::ManageSieve(ManageSieveEvent::ConnectionStart)
                | EventType::Pop3(Pop3Event::ConnectionStart)
                | EventType::Http(HttpEvent::ConnectionStart)
                | EventType::Delivery(DeliveryEvent::AttemptStart)
        )
    }

    #[inline(always)]
    pub fn is_span_end(&self) -> bool {
        matches!(
            self,
            EventType::Smtp(SmtpEvent::ConnectionEnd)
                | EventType::Imap(ImapEvent::ConnectionEnd)
                | EventType::ManageSieve(ManageSieveEvent::ConnectionEnd)
                | EventType::Pop3(Pop3Event::ConnectionEnd)
                | EventType::Http(HttpEvent::ConnectionEnd)
                | EventType::Delivery(DeliveryEvent::AttemptEnd)
        )
    }

    pub fn is_raw_io(&self) -> bool {
        matches!(
            self,
            EventType::Imap(ImapEvent::RawInput | ImapEvent::RawOutput)
                | EventType::Smtp(SmtpEvent::RawInput | SmtpEvent::RawOutput)
                | EventType::Pop3(Pop3Event::RawInput | Pop3Event::RawOutput)
                | EventType::ManageSieve(ManageSieveEvent::RawInput | ManageSieveEvent::RawOutput)
                | EventType::Delivery(DeliveryEvent::RawInput | DeliveryEvent::RawOutput)
                | EventType::Milter(MilterEvent::Read | MilterEvent::Write)
        )
    }

    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(self)
    }
}

impl StoreEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Store(self))
    }
}

impl DnsEvent {
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Dns(self))
    }
}

impl AcmeEvent {
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Acme(self))
    }
}

impl DkimEvent {
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Dkim(self))
    }
}

impl SecurityEvent {
    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Security(self))
    }
}

impl AuthEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Auth(self))
    }
}

impl ManageEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Manage(self))
    }
}

impl JmapEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Jmap(self))
    }
}

impl LimitEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Limit(self))
    }
}

impl ResourceEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Resource(self))
    }
}

impl SmtpEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Smtp(self))
    }
}

impl SieveEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Sieve(self))
    }
}

impl SpamEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Spam(self))
    }
}

impl ImapEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Imap(self))
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }
}

impl Pop3Event {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Pop3(self))
    }
}

impl ManageSieveEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::ManageSieve(self))
    }
}

impl NetworkEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Network(self))
    }
}

impl Value {
    pub fn from_maybe_string(value: &[u8]) -> Self {
        if let Ok(value) = std::str::from_utf8(value) {
            Self::String(value.into())
        } else {
            Self::Bytes(value.to_vec())
        }
    }

    pub fn to_uint(&self) -> Option<u64> {
        match self {
            Self::UInt(value) => Some(*value),
            Self::Int(value) => Some(*value as u64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value.as_str()),
            _ => None,
        }
    }

    pub fn into_string(self) -> Option<CompactString> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }
}

impl<T> AddContext<T> for Result<T> {
    #[inline(always)]
    fn caused_by(self, location: &'static str) -> Result<T> {
        match self {
            Ok(value) => Ok(value),
            Err(mut err) => {
                err.set_ctx(Key::CausedBy, location);
                Err(err)
            }
        }
    }

    #[inline(always)]
    fn add_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce(Error) -> Error,
    {
        match self {
            Ok(value) => Ok(value),
            Err(err) => Err(f(err)),
        }
    }
}

impl std::error::Error for Error {}
impl Eq for Error {}
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        if self.0.inner == other.0.inner && self.0.keys.len() == other.0.keys.len() {
            for kv in self.0.keys.iter() {
                if !other.0.keys.iter().any(|okv| kv == okv) {
                    return false;
                }
            }

            true
        } else {
            false
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::String(l0), Self::String(r0)) => l0 == r0,
            (Self::UInt(l0), Self::UInt(r0)) => l0 == r0,
            (Self::Int(l0), Self::Int(r0)) => l0 == r0,
            (Self::Float(l0), Self::Float(r0)) => l0 == r0,
            (Self::Bytes(l0), Self::Bytes(r0)) => l0 == r0,
            (Self::Bool(l0), Self::Bool(r0)) => l0 == r0,
            (Self::Ipv4(l0), Self::Ipv4(r0)) => l0 == r0,
            (Self::Ipv6(l0), Self::Ipv6(r0)) => l0 == r0,
            (Self::Event(l0), Self::Event(r0)) => l0 == r0,
            (Self::Array(l0), Self::Array(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl Eq for Value {}

impl From<EventType> for usize {
    fn from(value: EventType) -> Self {
        value.to_id() as usize
    }
}

impl AsRef<Event<EventDetails>> for Event<EventDetails> {
    fn as_ref(&self) -> &Event<EventDetails> {
        self
    }
}

impl Key {
    pub fn code(&self) -> u64 {
        match self {
            Key::AccountName => 0,
            Key::AccountId => 1,
            Key::BlobId => 2,
            Key::CausedBy => 3,
            Key::ChangeId => 4,
            Key::Code => 5,
            Key::Collection => 6,
            Key::Contents => 7,
            Key::Details => 8,
            Key::DkimFail => 9,
            Key::DkimNone => 10,
            Key::DkimPass => 11,
            Key::DmarcNone => 12,
            Key::DmarcPass => 13,
            Key::DmarcQuarantine => 14,
            Key::DmarcReject => 15,
            Key::DocumentId => 16,
            Key::Domain => 17,
            Key::Due => 18,
            Key::Elapsed => 19,
            Key::Expires => 20,
            Key::From => 21,
            Key::Hostname => 22,
            Key::Id => 23,
            Key::Key => 24,
            Key::Limit => 25,
            Key::ListenerId => 26,
            Key::LocalIp => 27,
            Key::LocalPort => 28,
            Key::MailboxName => 29,
            Key::MailboxId => 30,
            Key::MessageId => 31,
            Key::NextDsn => 32,
            Key::NextRetry => 33,
            Key::Path => 34,
            Key::Policy => 35,
            Key::QueueId => 36,
            Key::RangeFrom => 37,
            Key::RangeTo => 38,
            Key::Reason => 39,
            Key::RemoteIp => 40,
            Key::RemotePort => 41,
            Key::ReportId => 42,
            Key::Result => 43,
            Key::Size => 44,
            Key::Source => 45,
            Key::SpanId => 46,
            Key::SpfFail => 47,
            Key::SpfNone => 48,
            Key::SpfPass => 49,
            Key::Strict => 50,
            Key::Tls => 51,
            Key::To => 52,
            Key::Total => 53,
            Key::TotalFailures => 54,
            Key::TotalSuccesses => 55,
            Key::Type => 56,
            Key::Uid => 57,
            Key::UidNext => 58,
            Key::UidValidity => 59,
            Key::Url => 60,
            Key::ValidFrom => 61,
            Key::ValidTo => 62,
            Key::Value => 63,
            Key::Version => 64,
            Key::QueueName => 65,
        }
    }

    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Key::AccountName),
            1 => Some(Key::AccountId),
            2 => Some(Key::BlobId),
            3 => Some(Key::CausedBy),
            4 => Some(Key::ChangeId),
            5 => Some(Key::Code),
            6 => Some(Key::Collection),
            7 => Some(Key::Contents),
            8 => Some(Key::Details),
            9 => Some(Key::DkimFail),
            10 => Some(Key::DkimNone),
            11 => Some(Key::DkimPass),
            12 => Some(Key::DmarcNone),
            13 => Some(Key::DmarcPass),
            14 => Some(Key::DmarcQuarantine),
            15 => Some(Key::DmarcReject),
            16 => Some(Key::DocumentId),
            17 => Some(Key::Domain),
            18 => Some(Key::Due),
            19 => Some(Key::Elapsed),
            20 => Some(Key::Expires),
            21 => Some(Key::From),
            22 => Some(Key::Hostname),
            23 => Some(Key::Id),
            24 => Some(Key::Key),
            25 => Some(Key::Limit),
            26 => Some(Key::ListenerId),
            27 => Some(Key::LocalIp),
            28 => Some(Key::LocalPort),
            29 => Some(Key::MailboxName),
            30 => Some(Key::MailboxId),
            31 => Some(Key::MessageId),
            32 => Some(Key::NextDsn),
            33 => Some(Key::NextRetry),
            34 => Some(Key::Path),
            35 => Some(Key::Policy),
            36 => Some(Key::QueueId),
            37 => Some(Key::RangeFrom),
            38 => Some(Key::RangeTo),
            39 => Some(Key::Reason),
            40 => Some(Key::RemoteIp),
            41 => Some(Key::RemotePort),
            42 => Some(Key::ReportId),
            43 => Some(Key::Result),
            44 => Some(Key::Size),
            45 => Some(Key::Source),
            46 => Some(Key::SpanId),
            47 => Some(Key::SpfFail),
            48 => Some(Key::SpfNone),
            49 => Some(Key::SpfPass),
            50 => Some(Key::Strict),
            51 => Some(Key::Tls),
            52 => Some(Key::To),
            53 => Some(Key::Total),
            54 => Some(Key::TotalFailures),
            55 => Some(Key::TotalSuccesses),
            56 => Some(Key::Type),
            57 => Some(Key::Uid),
            58 => Some(Key::UidNext),
            59 => Some(Key::UidValidity),
            60 => Some(Key::Url),
            61 => Some(Key::ValidFrom),
            62 => Some(Key::ValidTo),
            63 => Some(Key::Value),
            64 => Some(Key::Version),
            65 => Some(Key::QueueName),
            _ => None,
        }
    }
}
