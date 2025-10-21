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
    QueryRequestMethod, SetRequestMethod,
    deserialize::{DeserializeArguments, deserialize_request},
};
use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use std::fmt::{self, Display};

impl<'x> Request<'x> {
    pub fn parse(json: &'x [u8], max_calls: usize, max_size: usize) -> trc::Result<Self> {
        if json.len() <= max_size {
            match serde_json::from_slice::<Request>(json) {
                Ok(request) => {
                    if request.method_calls.len() <= max_calls {
                        Ok(request)
                    } else {
                        Err(trc::LimitEvent::CallsIn.into_err())
                    }
                }
                Err(err) => Err(trc::JmapEvent::NotRequest
                    .into_err()
                    .details(err.to_string())),
            }
        } else {
            Err(trc::LimitEvent::SizeRequest.into_err())
        }
    }
}

impl<'de> DeserializeArguments<'de> for Request<'de> {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"using" => {
                self.using = map.next_value()?;
            },
            b"methodCalls" => {
                self.method_calls = map.next_value()?;
            },
            b"createdIds" => {
                self.created_ids = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
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
            .next_element::<&str>()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let name = match MethodName::parse(method_name) {
            Some(name) => name,
            None => {
                // Ignore the rest of the call
                let _ = seq
                    .next_element::<serde::de::IgnoredAny>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let id = seq
                    .next_element::<String>()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                return Ok(Call {
                    id,
                    method: RequestMethod::Error(
                        trc::JmapEvent::UnknownMethod
                            .into_err()
                            .details(method_name.to_string()),
                    ),
                    name: MethodName::error(),
                });
            }
        };

        let method = match (&name.fnc, &name.obj) {
            (MethodFunction::Get, MethodObject::Email) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::Email(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::Mailbox) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::Mailbox(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::Thread) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::Thread(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::Identity) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::Identity(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::EmailSubmission) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::EmailSubmission(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::PushSubscription) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::PushSubscription(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::VacationResponse) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::VacationResponse(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::SieveScript) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::Sieve(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::Principal) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::Principal(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::Quota) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::Quota(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::Blob) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::Blob(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::Calendar) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::Calendar(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::CalendarEvent) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::CalendarEvent(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::CalendarEventNotification) => {
                match seq.next_element() {
                    Ok(Some(value)) => {
                        RequestMethod::Get(GetRequestMethod::CalendarEventNotification(value))
                    }
                    Err(err) => RequestMethod::invalid(err),
                    Ok(None) => {
                        return Err(de::Error::invalid_length(1, &self));
                    }
                }
            }
            (MethodFunction::Get, MethodObject::ParticipantIdentity) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::ParticipantIdentity(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::AddressBook) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::AddressBook(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::ContactCard) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::ContactCard(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::FileNode) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::FileNode(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::ShareNotification) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Get(GetRequestMethod::ShareNotification(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Get, MethodObject::SearchSnippet) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::SearchSnippet(value),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Set, MethodObject::Email) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Set(SetRequestMethod::Email(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Set, MethodObject::Mailbox) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Set(SetRequestMethod::Mailbox(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Set, MethodObject::Identity) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Set(SetRequestMethod::Identity(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Set, MethodObject::EmailSubmission) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Set(SetRequestMethod::EmailSubmission(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Set, MethodObject::PushSubscription) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Set(SetRequestMethod::PushSubscription(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Set, MethodObject::VacationResponse) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Set(SetRequestMethod::VacationResponse(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Set, MethodObject::SieveScript) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Set(SetRequestMethod::Sieve(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Set, MethodObject::Calendar) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Set(SetRequestMethod::Calendar(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Set, MethodObject::CalendarEvent) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Set(SetRequestMethod::CalendarEvent(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Set, MethodObject::CalendarEventNotification) => {
                match seq.next_element() {
                    Ok(Some(value)) => {
                        RequestMethod::Set(SetRequestMethod::CalendarEventNotification(value))
                    }
                    Err(err) => RequestMethod::invalid(err),
                    Ok(None) => {
                        return Err(de::Error::invalid_length(1, &self));
                    }
                }
            }
            (MethodFunction::Set, MethodObject::ParticipantIdentity) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Set(SetRequestMethod::ParticipantIdentity(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Set, MethodObject::AddressBook) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Set(SetRequestMethod::AddressBook(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Set, MethodObject::ContactCard) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Set(SetRequestMethod::ContactCard(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Set, MethodObject::FileNode) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Set(SetRequestMethod::FileNode(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Set, MethodObject::ShareNotification) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Set(SetRequestMethod::ShareNotification(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Query, MethodObject::Email) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Query(QueryRequestMethod::Email(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Query, MethodObject::Mailbox) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Query(QueryRequestMethod::Mailbox(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Query, MethodObject::EmailSubmission) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Query(QueryRequestMethod::EmailSubmission(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Query, MethodObject::SieveScript) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Query(QueryRequestMethod::Sieve(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Query, MethodObject::Principal) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Query(QueryRequestMethod::Principal(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Query, MethodObject::Quota) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Query(QueryRequestMethod::Quota(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Query, MethodObject::CalendarEvent) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Query(QueryRequestMethod::CalendarEvent(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Query, MethodObject::CalendarEventNotification) => {
                match seq.next_element() {
                    Ok(Some(value)) => {
                        RequestMethod::Query(QueryRequestMethod::CalendarEventNotification(value))
                    }
                    Err(err) => RequestMethod::invalid(err),
                    Ok(None) => {
                        return Err(de::Error::invalid_length(1, &self));
                    }
                }
            }
            (MethodFunction::Query, MethodObject::ContactCard) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Query(QueryRequestMethod::ContactCard(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Query, MethodObject::FileNode) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Query(QueryRequestMethod::FileNode(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Query, MethodObject::ShareNotification) => match seq.next_element() {
                Ok(Some(value)) => {
                    RequestMethod::Query(QueryRequestMethod::ShareNotification(value))
                }
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::QueryChanges, MethodObject::Email) => match seq.next_element() {
                Ok(Some(value)) => {
                    RequestMethod::QueryChanges(QueryChangesRequestMethod::Email(value))
                }
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::QueryChanges, MethodObject::Mailbox) => match seq.next_element() {
                Ok(Some(value)) => {
                    RequestMethod::QueryChanges(QueryChangesRequestMethod::Mailbox(value))
                }
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::QueryChanges, MethodObject::EmailSubmission) => {
                match seq.next_element() {
                    Ok(Some(value)) => RequestMethod::QueryChanges(
                        QueryChangesRequestMethod::EmailSubmission(value),
                    ),
                    Err(err) => RequestMethod::invalid(err),
                    Ok(None) => {
                        return Err(de::Error::invalid_length(1, &self));
                    }
                }
            }
            (MethodFunction::QueryChanges, MethodObject::SieveScript) => match seq.next_element() {
                Ok(Some(value)) => {
                    RequestMethod::QueryChanges(QueryChangesRequestMethod::Sieve(value))
                }
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::QueryChanges, MethodObject::Principal) => match seq.next_element() {
                Ok(Some(value)) => {
                    RequestMethod::QueryChanges(QueryChangesRequestMethod::Principal(value))
                }
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::QueryChanges, MethodObject::Quota) => match seq.next_element() {
                Ok(Some(value)) => {
                    RequestMethod::QueryChanges(QueryChangesRequestMethod::Quota(value))
                }
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::QueryChanges, MethodObject::CalendarEvent) => match seq.next_element()
            {
                Ok(Some(value)) => {
                    RequestMethod::QueryChanges(QueryChangesRequestMethod::CalendarEvent(value))
                }
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::QueryChanges, MethodObject::CalendarEventNotification) => {
                match seq.next_element() {
                    Ok(Some(value)) => RequestMethod::QueryChanges(
                        QueryChangesRequestMethod::CalendarEventNotification(value),
                    ),
                    Err(err) => RequestMethod::invalid(err),
                    Ok(None) => {
                        return Err(de::Error::invalid_length(1, &self));
                    }
                }
            }
            (MethodFunction::QueryChanges, MethodObject::ContactCard) => match seq.next_element() {
                Ok(Some(value)) => {
                    RequestMethod::QueryChanges(QueryChangesRequestMethod::ContactCard(value))
                }
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::QueryChanges, MethodObject::FileNode) => match seq.next_element() {
                Ok(Some(value)) => {
                    RequestMethod::QueryChanges(QueryChangesRequestMethod::FileNode(value))
                }
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::QueryChanges, MethodObject::ShareNotification) => {
                match seq.next_element() {
                    Ok(Some(value)) => RequestMethod::QueryChanges(
                        QueryChangesRequestMethod::ShareNotification(value),
                    ),
                    Err(err) => RequestMethod::invalid(err),
                    Ok(None) => {
                        return Err(de::Error::invalid_length(1, &self));
                    }
                }
            }
            (MethodFunction::Changes, _) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Changes(value),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Copy, MethodObject::Email) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Copy(CopyRequestMethod::Email(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Copy, MethodObject::Blob) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Copy(CopyRequestMethod::Blob(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Copy, MethodObject::CalendarEvent) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Copy(CopyRequestMethod::CalendarEvent(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Copy, MethodObject::ContactCard) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Copy(CopyRequestMethod::ContactCard(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Lookup, MethodObject::Blob) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::LookupBlob(value),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Upload, MethodObject::Blob) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::UploadBlob(value),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Import, MethodObject::Email) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::ImportEmail(value),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Parse, MethodObject::Email) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Parse(ParseRequestMethod::Email(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Parse, MethodObject::CalendarEvent) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Parse(ParseRequestMethod::CalendarEvent(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Parse, MethodObject::ContactCard) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Parse(ParseRequestMethod::ContactCard(value)),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::GetAvailability, MethodObject::Principal) => {
                match seq.next_element() {
                    Ok(Some(value)) => {
                        RequestMethod::Get(GetRequestMethod::PrincipalAvailability(value))
                    }
                    Err(err) => RequestMethod::invalid(err),
                    Ok(None) => {
                        return Err(de::Error::invalid_length(1, &self));
                    }
                }
            }
            (MethodFunction::Validate, MethodObject::SieveScript) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::ValidateScript(value),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            (MethodFunction::Echo, MethodObject::Core) => match seq.next_element() {
                Ok(Some(value)) => RequestMethod::Echo(value),
                Err(err) => RequestMethod::invalid(err),
                Ok(None) => {
                    return Err(de::Error::invalid_length(1, &self));
                }
            },
            _ => {
                return Err(de::Error::custom(format!(
                    "Invalid method function/object combination: {}",
                    method_name
                )));
            }
        };

        let id = seq
            .next_element::<String>()?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;

        Ok(Call { id, method, name })
    }
}

impl RequestMethod<'_> {
    fn invalid(err: impl Display) -> Self {
        RequestMethod::Error(
            trc::JmapEvent::InvalidArguments
                .into_err()
                .details(err.to_string()),
        )
    }
}

impl<'de> Deserialize<'de> for Request<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
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

#[cfg(test)]
mod tests {
    use crate::request::Request;

    const TEST: &str = r#"
    {
        "using": [ "urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail" ],
        "methodCalls": [
          [ "method1", {
            "arg1": "arg1data",
            "arg2": "arg2data"
          }, "c1" ],
          [ "Core/echo", {
            "hello": true,
            "high": 5
          }, "c2" ],
          [ "method3", {"hello": [{"a": {"b": true}}]}, "c3" ]
        ],
        "createdIds": {
            "c1": "m1",
            "c2": "m2"
        }
      }
    "#;

    const TEST1: &str = r#"
    {
    "using": [
        "urn:ietf:params:jmap:core",
        "urn:ietf:params:jmap:mail"
    ],
    "methodCalls": [
        [
        "Email/query",
        {
            "accountId": "0",
            "filter": { "conditions": [ { "hasKeyword": "music", "maxSize": 455 }, { "hasKeyword": "video" }, { "operator": "AND", "conditions": [ { "subject": "test" }, { "minSize": 100 } ] } ], "operator": "OR" },
            "sort": [
            {
                "property": "subject",
                "isAscending": true
            },
            {
                "property": "allInThreadHaveKeyword",
                "isAscending": false,
                "keyword": "$seen"
            },
            {
                "keyword": "$junk",
                "property": "someInThreadHaveKeyword",
                "collation": "i;octet",
                "isAscending": false
            }
            ],
            "position": 0,
            "limit": 10
        },
        "c1"
        ]
    ],
    "createdIds": {}
    }
    "#;

    const TEST2: &str = r##"
    {
        "using": [
          "urn:ietf:params:jmap:submission",
          "urn:ietf:params:jmap:mail",
          "urn:ietf:params:jmap:core"
        ],
        "methodCalls": [
          [
            "Email/set",
            {
              "accountId": "c",
              "create": {
                "c37ee58b-e224-4799-88e6-1d7484e3b782": {
                  "mailboxIds": {
                    "9": true
                  },
                  "subject": "test",
                  "from": [
                    {
                      "name": "Foo",
                      "email": "foo@bar.com"
                    }
                  ],
                  "to": [
                    {
                      "name": null,
                      "email": "bar@foo.com"
                    }
                  ],
                  "cc": [],
                  "bcc": [],
                  "replyTo": [
                    {
                      "name": null,
                      "email": "foo@bar.com"
                    }
                  ],
                  "htmlBody": [
                    {
                      "partId": "c37ee58b-e224-4799-88e6-1d7484e3b782",
                      "type": "text/html"
                    }
                  ],
                  "bodyValues": {
                    "c37ee58b-e224-4799-88e6-1d7484e3b782": {
                      "value": "<p>test email<br></p>",
                      "isEncodingProblem": false,
                      "isTruncated": false
                    }
                  },
                  "header:User-Agent:asText": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0"
                }
              }
            },
            "c0"
          ],
          [
            "EmailSubmission/set",
            {
              "accountId": "c",
              "create": {
                "c37ee58b-e224-4799-88e6-1d7484e3b782": {
                  "identityId": "a",
                  "emailId": "#c37ee58b-e224-4799-88e6-1d7484e3b782",
                  "envelope": {
                    "mailFrom": {
                      "email": "foo@bar.com"
                    },
                    "rcptTo": [
                      {
                        "email": "bar@foo.com"
                      }
                    ]
                  }
                }
              },
              "onSuccessUpdateEmail": {
                "#c37ee58b-e224-4799-88e6-1d7484e3b782": {
                  "mailboxIds/d": true,
                  "mailboxIds/9": null,
                  "keywords/$seen": true,
                  "keywords/$draft": null
                }
              }
            },
            "c1"
          ]
        ]
      }
    "##;

    #[test]
    fn parse_request() {
        println!("{:#?}", Request::parse(TEST.as_bytes(), 10, 10240));
        println!("{:#?}", Request::parse(TEST1.as_bytes(), 10, 10240));
        println!("{:#?}", Request::parse(TEST2.as_bytes(), 10, 10240));
    }
}
