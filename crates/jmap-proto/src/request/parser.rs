/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Call, Request, RequestMethod,
    method::{MethodFunction, MethodName, MethodObject},
};
use crate::request::{
    CopyRequestMethod, GetRequestMethod, ParseRequestMethod, QueryChangesRequestMethod,
    QueryRequestMethod, SetRequestMethod, deserialize::DeserializeArguments,
};
use compact_str::{CompactString, ToCompactString};
use registry::schema::prelude::ObjectType;
use serde::{
    Deserialize, Deserializer,
    de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use serde_json::value::RawValue;
use simdutf8::basic::from_utf8;
use std::{
    borrow::Cow,
    fmt::{self, Display},
    marker::PhantomData,
};
use utils::text::utf8_lossy;

const MAX_ERROR_EXCERPT: usize = 1024;

impl<'x> Request<'x> {
    pub fn parse(json: &'x [u8], max_calls: usize, max_size: usize) -> trc::Result<Self> {
        if json.len() <= max_size {
            let request = match from_utf8(json) {
                Ok(text) => serde_json::from_str::<Request>(text)
                    .or_else(|err| Self::parse_lenient(text, err)),
                Err(err) => Err(err.to_compact_string()),
            };
            match request {
                Ok(request) => {
                    if request.method_calls.len() <= max_calls {
                        Ok(request)
                    } else {
                        Err(trc::LimitEvent::CallsIn.into_err())
                    }
                }
                Err(err) => Err(trc::JmapEvent::NotRequest.into_err().reason(err).details(
                    CompactString::from(utf8_lossy(json.get(..MAX_ERROR_EXCERPT).unwrap_or(json))),
                )),
            }
        } else {
            Err(trc::LimitEvent::SizeRequest.into_err())
        }
    }

    #[cold]
    #[inline(never)]
    fn parse_lenient(text: &'x str, err: serde_json::Error) -> Result<Self, CompactString> {
        serde_json::from_str::<LenientRequest>(text)
            .map(|request| request.0)
            .map_err(|_| err.to_compact_string())
    }

    pub(crate) fn deserialize_field<A, C>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'x>,
        C: CallList<'x>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"using" => {
                self.using = map.next_value()?;
            },
            b"methodCalls" => {
                self.method_calls = map.next_value::<C>()?.into_calls();
            },
            b"createdIds" => {
                self.created_ids = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

pub(crate) trait CallList<'de>: Deserialize<'de> {
    fn into_calls(self) -> Vec<Call<RequestMethod<'de>>>;
}

impl<'de> CallList<'de> for Vec<Call<RequestMethod<'de>>> {
    fn into_calls(self) -> Vec<Call<RequestMethod<'de>>> {
        self
    }
}

impl<'de> CallList<'de> for Vec<LenientCall<'de>> {
    fn into_calls(self) -> Vec<Call<RequestMethod<'de>>> {
        self.into_iter().map(|call| call.0).collect()
    }
}

impl<'de> DeserializeArguments<'de> for Request<'de> {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        self.deserialize_field::<A, Vec<Call<RequestMethod<'de>>>>(key, map)
    }
}

pub(crate) struct LenientRequest<'x>(pub Request<'x>);

#[repr(transparent)]
pub(crate) struct LenientCall<'x>(Call<RequestMethod<'x>>);

struct MethodArguments(MethodName);

impl<'de> DeserializeSeed<'de> for MethodArguments {
    type Value = RequestMethod<'de>;

    #[inline(always)]
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match (self.0.fnc, self.0.obj) {
            (MethodFunction::Get, MethodObject::Email) => RequestMethod::Get(
                GetRequestMethod::Email(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::Mailbox) => RequestMethod::Get(
                GetRequestMethod::Mailbox(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::Thread) => RequestMethod::Get(
                GetRequestMethod::Thread(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::Identity) => RequestMethod::Get(
                GetRequestMethod::Identity(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::EmailSubmission) => RequestMethod::Get(
                GetRequestMethod::EmailSubmission(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::PushSubscription) => RequestMethod::Get(
                GetRequestMethod::PushSubscription(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::VacationResponse) => RequestMethod::Get(
                GetRequestMethod::VacationResponse(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::SieveScript) => RequestMethod::Get(
                GetRequestMethod::Sieve(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::Principal) => RequestMethod::Get(
                GetRequestMethod::Principal(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::Quota) => RequestMethod::Get(
                GetRequestMethod::Quota(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::Blob) => RequestMethod::Get(
                GetRequestMethod::Blob(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::Calendar) => RequestMethod::Get(
                GetRequestMethod::Calendar(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::CalendarEvent) => RequestMethod::Get(
                GetRequestMethod::CalendarEvent(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::CalendarEventNotification) => {
                RequestMethod::Get(GetRequestMethod::CalendarEventNotification(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::Get, MethodObject::ParticipantIdentity) => RequestMethod::Get(
                GetRequestMethod::ParticipantIdentity(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::AddressBook) => RequestMethod::Get(
                GetRequestMethod::AddressBook(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::ContactCard) => RequestMethod::Get(
                GetRequestMethod::ContactCard(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::FileNode) => RequestMethod::Get(
                GetRequestMethod::FileNode(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::ShareNotification) => RequestMethod::Get(
                GetRequestMethod::ShareNotification(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Get, MethodObject::SearchSnippet) => {
                RequestMethod::SearchSnippet(Deserialize::deserialize(deserializer)?)
            }
            (MethodFunction::Get, MethodObject::Registry(_)) => RequestMethod::Get(
                GetRequestMethod::Registry(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::Email) => RequestMethod::Set(
                SetRequestMethod::Email(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::Mailbox) => RequestMethod::Set(
                SetRequestMethod::Mailbox(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::Identity) => RequestMethod::Set(
                SetRequestMethod::Identity(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::EmailSubmission) => RequestMethod::Set(
                SetRequestMethod::EmailSubmission(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::PushSubscription) => RequestMethod::Set(
                SetRequestMethod::PushSubscription(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::VacationResponse) => RequestMethod::Set(
                SetRequestMethod::VacationResponse(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::SieveScript) => RequestMethod::Set(
                SetRequestMethod::Sieve(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::Calendar) => RequestMethod::Set(
                SetRequestMethod::Calendar(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::CalendarEvent) => RequestMethod::Set(
                SetRequestMethod::CalendarEvent(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::CalendarEventNotification) => {
                RequestMethod::Set(SetRequestMethod::CalendarEventNotification(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::Set, MethodObject::ParticipantIdentity) => RequestMethod::Set(
                SetRequestMethod::ParticipantIdentity(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::AddressBook) => RequestMethod::Set(
                SetRequestMethod::AddressBook(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::ContactCard) => RequestMethod::Set(
                SetRequestMethod::ContactCard(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::FileNode) => RequestMethod::Set(
                SetRequestMethod::FileNode(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::ShareNotification) => RequestMethod::Set(
                SetRequestMethod::ShareNotification(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Set, MethodObject::Registry(_)) => RequestMethod::Set(
                SetRequestMethod::Registry(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::Email) => RequestMethod::Query(
                QueryRequestMethod::Email(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::Mailbox) => RequestMethod::Query(
                QueryRequestMethod::Mailbox(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::EmailSubmission) => RequestMethod::Query(
                QueryRequestMethod::EmailSubmission(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::SieveScript) => RequestMethod::Query(
                QueryRequestMethod::Sieve(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::Principal) => RequestMethod::Query(
                QueryRequestMethod::Principal(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::Quota) => RequestMethod::Query(
                QueryRequestMethod::Quota(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::Calendar) => RequestMethod::Query(
                QueryRequestMethod::Calendar(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::CalendarEvent) => RequestMethod::Query(
                QueryRequestMethod::CalendarEvent(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::CalendarEventNotification) => {
                RequestMethod::Query(QueryRequestMethod::CalendarEventNotification(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::Query, MethodObject::AddressBook) => RequestMethod::Query(
                QueryRequestMethod::AddressBook(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::ContactCard) => RequestMethod::Query(
                QueryRequestMethod::ContactCard(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::FileNode) => RequestMethod::Query(
                QueryRequestMethod::FileNode(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::ShareNotification) => RequestMethod::Query(
                QueryRequestMethod::ShareNotification(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Query, MethodObject::Registry(_)) => RequestMethod::Query(
                QueryRequestMethod::Registry(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::QueryChanges, MethodObject::Email) => RequestMethod::QueryChanges(
                QueryChangesRequestMethod::Email(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::QueryChanges, MethodObject::Mailbox) => RequestMethod::QueryChanges(
                QueryChangesRequestMethod::Mailbox(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::QueryChanges, MethodObject::EmailSubmission) => {
                RequestMethod::QueryChanges(QueryChangesRequestMethod::EmailSubmission(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::QueryChanges, MethodObject::Principal) => RequestMethod::QueryChanges(
                QueryChangesRequestMethod::Principal(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::QueryChanges, MethodObject::Quota) => RequestMethod::QueryChanges(
                QueryChangesRequestMethod::Quota(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::QueryChanges, MethodObject::CalendarEvent) => {
                RequestMethod::QueryChanges(QueryChangesRequestMethod::CalendarEvent(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::QueryChanges, MethodObject::CalendarEventNotification) => {
                RequestMethod::QueryChanges(QueryChangesRequestMethod::CalendarEventNotification(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::QueryChanges, MethodObject::ContactCard) => {
                RequestMethod::QueryChanges(QueryChangesRequestMethod::ContactCard(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::QueryChanges, MethodObject::FileNode) => RequestMethod::QueryChanges(
                QueryChangesRequestMethod::FileNode(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::QueryChanges, MethodObject::ShareNotification) => {
                RequestMethod::QueryChanges(QueryChangesRequestMethod::ShareNotification(
                    Deserialize::deserialize(deserializer)?,
                ))
            }
            (MethodFunction::Changes, _) => {
                RequestMethod::Changes(Deserialize::deserialize(deserializer)?)
            }
            (MethodFunction::Copy, MethodObject::Email) => RequestMethod::Copy(
                CopyRequestMethod::Email(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Copy, MethodObject::Blob) => RequestMethod::Copy(
                CopyRequestMethod::Blob(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Copy, MethodObject::CalendarEvent) => RequestMethod::Copy(
                CopyRequestMethod::CalendarEvent(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Copy, MethodObject::ContactCard) => RequestMethod::Copy(
                CopyRequestMethod::ContactCard(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Copy, MethodObject::FileNode) => RequestMethod::Copy(
                CopyRequestMethod::FileNode(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Lookup, MethodObject::Blob) => {
                RequestMethod::LookupBlob(Deserialize::deserialize(deserializer)?)
            }
            (MethodFunction::Upload, MethodObject::Blob) => {
                RequestMethod::UploadBlob(Deserialize::deserialize(deserializer)?)
            }
            (MethodFunction::Import, MethodObject::Email) => {
                RequestMethod::ImportEmail(Deserialize::deserialize(deserializer)?)
            }
            (MethodFunction::Parse, MethodObject::Email) => RequestMethod::Parse(
                ParseRequestMethod::Email(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Parse, MethodObject::CalendarEvent) => RequestMethod::Parse(
                ParseRequestMethod::CalendarEvent(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Parse, MethodObject::ContactCard) => RequestMethod::Parse(
                ParseRequestMethod::ContactCard(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::GetAvailability, MethodObject::Principal) => RequestMethod::Get(
                GetRequestMethod::PrincipalAvailability(Deserialize::deserialize(deserializer)?),
            ),
            (MethodFunction::Validate, MethodObject::SieveScript) => {
                RequestMethod::ValidateScript(Deserialize::deserialize(deserializer)?)
            }
            (MethodFunction::RegistrationOptions, MethodObject::Registry(ObjectType::Passkey)) => {
                RequestMethod::PasskeyRegistrationOptions(Deserialize::deserialize(deserializer)?)
            }
            (MethodFunction::Echo, MethodObject::Core) => {
                RequestMethod::Echo(Deserialize::deserialize(deserializer)?)
            }
            _ => {
                IgnoredAny::deserialize(deserializer)?;
                RequestMethod::Error(
                    trc::JmapEvent::UnknownMethod
                        .into_err()
                        .details(self.0.as_str()),
                )
            }
        })
    }
}

struct CallVisitor;

impl<'de> Visitor<'de> for CallVisitor {
    type Value = Call<RequestMethod<'de>>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array with 3 elements")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<Call<RequestMethod<'de>>, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let method_name = seq
            .next_element::<Cow<str>>()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let (name, method) = match MethodName::parse(method_name.as_ref()) {
            Some(name) => match seq.next_element_seed(MethodArguments(name)) {
                Ok(Some(method)) => (name, method),
                Err(err) => (name, RequestMethod::invalid(err)),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            None => {
                seq.next_element::<IgnoredAny>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                (MethodName::error(), RequestMethod::unknown(method_name))
            }
        };

        let id = seq
            .next_element::<String>()?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;

        Ok(Call { id, method, name })
    }
}

struct LenientCallVisitor;

impl<'de> Visitor<'de> for LenientCallVisitor {
    type Value = LenientCall<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array with 3 elements")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<LenientCall<'de>, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let method_name = seq
            .next_element::<Cow<str>>()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let arguments = seq
            .next_element::<&'de RawValue>()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        let id = seq
            .next_element::<String>()?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;
        let (name, method) = match MethodName::parse(method_name.as_ref()) {
            Some(name) => {
                let mut deserializer = serde_json::Deserializer::from_str(arguments.get());
                match MethodArguments(name).deserialize(&mut deserializer) {
                    Ok(method) => (name, method),
                    Err(err) => (name, RequestMethod::invalid(err)),
                }
            }
            None => (MethodName::error(), RequestMethod::unknown(method_name)),
        };

        Ok(LenientCall(Call { id, method, name }))
    }
}

impl<'de> Deserialize<'de> for LenientCall<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(LenientCallVisitor)
    }
}

impl RequestMethod<'_> {
    fn invalid(err: impl Display) -> Self {
        RequestMethod::Error(
            trc::JmapEvent::InvalidArguments
                .into_err()
                .details(err.to_compact_string()),
        )
    }

    fn unknown(method_name: Cow<'_, str>) -> Self {
        RequestMethod::Error(
            trc::JmapEvent::UnknownMethod
                .into_err()
                .details(method_name.into_owned()),
        )
    }
}

struct RequestVisitor<C> {
    _calls: PhantomData<C>,
}

impl<'de, C: CallList<'de>> Visitor<'de> for RequestVisitor<C> {
    type Value = Request<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JMAP request object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut target = Request::default();
        let mut has_using = false;
        let mut has_method_calls = false;

        while let Some(key) = map.next_key::<&str>()? {
            match key {
                "using" => has_using = true,
                "methodCalls" => has_method_calls = true,
                _ => {}
            }
            target.deserialize_field::<A, C>(key, &mut map)?;
        }

        if !has_using || !has_method_calls {
            return Err(de::Error::custom(
                "Request is missing the \"using\" or \"methodCalls\" property.",
            ));
        }

        Ok(target)
    }
}

impl<'de> Deserialize<'de> for Request<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RequestVisitor::<Vec<Call<RequestMethod<'de>>>> {
            _calls: PhantomData,
        })
    }
}

impl<'de> Deserialize<'de> for LenientRequest<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_map(RequestVisitor::<Vec<LenientCall<'de>>> {
                _calls: PhantomData,
            })
            .map(LenientRequest)
    }
}

impl<'de> Deserialize<'de> for Call<RequestMethod<'de>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(CallVisitor)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/jmap-proto/src/request/parser/tests.rs"]
mod tests;
