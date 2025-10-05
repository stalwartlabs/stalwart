/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{
        AnyId, JmapObject, JmapObjectId, MaybeReference,
        email::{EmailProperty, EmailValue},
        parse_ref,
    },
    request::{MaybeInvalid, deserialize::DeserializeArguments, reference::MaybeIdReference},
    types::date::UTCDate,
};
use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, Property, Value};
use std::{borrow::Cow, str::FromStr};
use types::{blob::BlobId, id::Id};
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone, Default)]
pub struct EmailSubmission;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EmailSubmissionProperty {
    Id,
    IdentityId,
    ThreadId,
    EmailId,
    Envelope,
    MailFrom,
    RcptTo,
    Email,
    Parameters,
    SendAt,
    UndoStatus,
    DeliveryStatus,
    SmtpReply,
    Delivered,
    Displayed,
    DsnBlobIds,
    MdnBlobIds,

    Pointer(JsonPointer<EmailSubmissionProperty>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EmailSubmissionValue {
    Id(Id),
    Date(UTCDate),
    BlobId(BlobId),
    UndoStatus(UndoStatus),
    Delivered(Delivered),
    Displayed(Displayed),
    IdReference(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UndoStatus {
    Pending,
    Final,
    Canceled,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Delivered {
    Queued,
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Displayed {
    Yes,
    Unknown,
}

impl Property for EmailSubmissionProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        EmailSubmissionProperty::parse(value, key.is_none())
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            EmailSubmissionProperty::DeliveryStatus => "deliveryStatus",
            EmailSubmissionProperty::DsnBlobIds => "dsnBlobIds",
            EmailSubmissionProperty::Email => "email",
            EmailSubmissionProperty::Envelope => "envelope",
            EmailSubmissionProperty::Id => "id",
            EmailSubmissionProperty::IdentityId => "identityId",
            EmailSubmissionProperty::MdnBlobIds => "mdnBlobIds",
            EmailSubmissionProperty::SendAt => "sendAt",
            EmailSubmissionProperty::ThreadId => "threadId",
            EmailSubmissionProperty::UndoStatus => "undoStatus",
            EmailSubmissionProperty::Parameters => "parameters",
            EmailSubmissionProperty::SmtpReply => "smtpReply",
            EmailSubmissionProperty::Delivered => "delivered",
            EmailSubmissionProperty::Displayed => "displayed",
            EmailSubmissionProperty::MailFrom => "mailFrom",
            EmailSubmissionProperty::RcptTo => "rcptTo",
            EmailSubmissionProperty::EmailId => "emailId",
            EmailSubmissionProperty::Pointer(json_pointer) => {
                return json_pointer.to_string().into();
            }
        }
        .into()
    }
}

impl Element for EmailSubmissionValue {
    type Property = EmailSubmissionProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                EmailSubmissionProperty::Id
                | EmailSubmissionProperty::ThreadId
                | EmailSubmissionProperty::IdentityId
                | EmailSubmissionProperty::EmailId => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(EmailSubmissionValue::Id(v)),
                    MaybeReference::Reference(v) => Some(EmailSubmissionValue::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                EmailSubmissionProperty::MdnBlobIds | EmailSubmissionProperty::DsnBlobIds => {
                    match parse_ref(value) {
                        MaybeReference::Value(v) => Some(EmailSubmissionValue::BlobId(v)),
                        MaybeReference::Reference(v) => Some(EmailSubmissionValue::IdReference(v)),
                        MaybeReference::ParseError => None,
                    }
                }
                EmailSubmissionProperty::SendAt => UTCDate::from_str(value)
                    .ok()
                    .map(EmailSubmissionValue::Date),
                EmailSubmissionProperty::UndoStatus => {
                    UndoStatus::parse(value).map(EmailSubmissionValue::UndoStatus)
                }
                EmailSubmissionProperty::Delivered => {
                    Delivered::parse(value).map(EmailSubmissionValue::Delivered)
                }
                EmailSubmissionProperty::Displayed => {
                    Displayed::parse(value).map(EmailSubmissionValue::Displayed)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            EmailSubmissionValue::Id(id) => id.to_string().into(),
            EmailSubmissionValue::Date(utcdate) => utcdate.to_string().into(),
            EmailSubmissionValue::BlobId(blob_id) => blob_id.to_string().into(),
            EmailSubmissionValue::IdReference(r) => format!("#{r}").into(),
            EmailSubmissionValue::UndoStatus(undo_status) => undo_status.as_str().into(),
            EmailSubmissionValue::Delivered(delivered) => delivered.as_str().into(),
            EmailSubmissionValue::Displayed(displayed) => displayed.as_str().into(),
        }
    }
}

impl EmailSubmissionProperty {
    fn parse(value: &str, allow_patch: bool) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            "id" => EmailSubmissionProperty::Id,
            "identityId" => EmailSubmissionProperty::IdentityId,
            "threadId" => EmailSubmissionProperty::ThreadId,
            "emailId" => EmailSubmissionProperty::EmailId,
            "envelope" => EmailSubmissionProperty::Envelope,
            "mailFrom" => EmailSubmissionProperty::MailFrom,
            "rcptTo" => EmailSubmissionProperty::RcptTo,
            "email" => EmailSubmissionProperty::Email,
            "parameters" => EmailSubmissionProperty::Parameters,
            "sendAt" => EmailSubmissionProperty::SendAt,
            "undoStatus" => EmailSubmissionProperty::UndoStatus,
            "deliveryStatus" => EmailSubmissionProperty::DeliveryStatus,
            "smtpReply" => EmailSubmissionProperty::SmtpReply,
            "delivered" => EmailSubmissionProperty::Delivered,
            "displayed" => EmailSubmissionProperty::Displayed,
            "dsnBlobIds" => EmailSubmissionProperty::DsnBlobIds,
            "mdnBlobIds" => EmailSubmissionProperty::MdnBlobIds,
        )
        .or_else(|| {
            if allow_patch && value.contains('/') {
                EmailSubmissionProperty::Pointer(JsonPointer::parse(value)).into()
            } else {
                None
            }
        })
    }

    fn patch_or_prop(&self) -> &EmailSubmissionProperty {
        if let EmailSubmissionProperty::Pointer(ptr) = self
            && let Some(JsonPointerItem::Key(Key::Property(prop))) = ptr.last()
        {
            prop
        } else {
            self
        }
    }
}

impl UndoStatus {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"pending" => UndoStatus::Pending,
            b"final" => UndoStatus::Final,
            b"canceled" => UndoStatus::Canceled,
        )
    }

    fn as_str(&self) -> &'static str {
        match self {
            UndoStatus::Pending => "pending",
            UndoStatus::Final => "final",
            UndoStatus::Canceled => "canceled",
        }
    }
}

impl Delivered {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"queued" => Delivered::Queued,
            b"yes" => Delivered::Yes,
            b"no" => Delivered::No,
            b"unknown" => Delivered::Unknown,
        )
    }

    fn as_str(&self) -> &'static str {
        match self {
            Delivered::Queued => "queued",
            Delivered::Yes => "yes",
            Delivered::No => "no",
            Delivered::Unknown => "unknown",
        }
    }
}

impl Displayed {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"yes" => Displayed::Yes,
            b"unknown" => Displayed::Unknown,
        )
    }

    fn as_str(&self) -> &'static str {
        match self {
            Displayed::Yes => "yes",
            Displayed::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct EmailSubmissionSetArguments<'x> {
    pub on_success_update_email:
        Option<VecMap<MaybeIdReference<Id>, Value<'x, EmailProperty, EmailValue>>>,
    pub on_success_destroy_email: Option<Vec<MaybeIdReference<Id>>>,
}

impl<'x> DeserializeArguments<'x> for EmailSubmissionSetArguments<'x> {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'x>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"onSuccessUpdateEmail" => {
                self.on_success_update_email = map.next_value()?;
            },
            b"onSuccessDestroyEmail" => {
                self.on_success_destroy_email = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl FromStr for EmailSubmissionProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        EmailSubmissionProperty::parse(s, false).ok_or(())
    }
}

impl<'de> serde::Deserialize<'de> for UndoStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        UndoStatus::parse(<&str>::deserialize(deserializer)?)
            .ok_or_else(|| serde::de::Error::custom("invalid JMAP UndoStatus"))
    }
}

impl JmapObject for EmailSubmission {
    type Property = EmailSubmissionProperty;

    type Element = EmailSubmissionValue;

    type Id = Id;

    type Filter = EmailSubmissionFilter;

    type Comparator = EmailSubmissionComparator;

    type GetArguments = ();

    type SetArguments<'de> = EmailSubmissionSetArguments<'de>;

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = EmailSubmissionProperty::Id;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailSubmissionFilter {
    IdentityIds(Vec<MaybeInvalid<Id>>),
    EmailIds(Vec<MaybeInvalid<Id>>),
    ThreadIds(Vec<MaybeInvalid<Id>>),
    Before(UTCDate),
    After(UTCDate),
    UndoStatus(UndoStatus),
    _T(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailSubmissionComparator {
    EmailId,
    ThreadId,
    SentAt,
    _T(String),
}

impl<'de> DeserializeArguments<'de> for EmailSubmissionFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"identityIds" => {
                *self = EmailSubmissionFilter::IdentityIds(map.next_value()?);
            },
            b"emailIds" => {
                *self = EmailSubmissionFilter::EmailIds(map.next_value()?);
            },
            b"threadIds" => {
                *self = EmailSubmissionFilter::ThreadIds(map.next_value()?);
            },
            b"before" => {
                *self = EmailSubmissionFilter::Before(map.next_value()?);
            },
            b"after" => {
                *self = EmailSubmissionFilter::After(map.next_value()?);
            },
            b"undoStatus" => {
                *self = EmailSubmissionFilter::UndoStatus(map.next_value()?);
            },
            _ => {
                *self = EmailSubmissionFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for EmailSubmissionComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<Cow<str>>()?;
            hashify::fnc_map!(value.as_bytes(),

                b"emailId" => {
                    *self = EmailSubmissionComparator::EmailId;
                },
                b"threadId" => {
                    *self = EmailSubmissionComparator::ThreadId;
                },
                b"sentAt" => {
                    *self = EmailSubmissionComparator::SentAt;
                },
                _ => {
                    *self = EmailSubmissionComparator::_T(key.to_string());
                }
            );
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
    }
}

impl Default for EmailSubmissionFilter {
    fn default() -> Self {
        EmailSubmissionFilter::_T("".to_string())
    }
}

impl Default for EmailSubmissionComparator {
    fn default() -> Self {
        EmailSubmissionComparator::_T("".to_string())
    }
}

impl From<Id> for EmailSubmissionValue {
    fn from(id: Id) -> Self {
        EmailSubmissionValue::Id(id)
    }
}

impl JmapObjectId for EmailSubmissionValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            EmailSubmissionValue::Id(id) => Some(*id),
            _ => None,
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            EmailSubmissionValue::Id(id) => Some(AnyId::Id(*id)),
            EmailSubmissionValue::BlobId(blob_id) => Some(AnyId::BlobId(blob_id.clone())),
            _ => None,
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        if let EmailSubmissionValue::IdReference(r) = self {
            Some(r)
        } else {
            None
        }
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        match new_id {
            AnyId::Id(id) => {
                *self = EmailSubmissionValue::Id(id);
            }
            AnyId::BlobId(blob_id) => {
                *self = EmailSubmissionValue::BlobId(blob_id);
            }
        }
        true
    }
}

impl JmapObjectId for EmailSubmissionProperty {
    fn as_id(&self) -> Option<Id> {
        None
    }

    fn as_any_id(&self) -> Option<AnyId> {
        None
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, _: AnyId) -> bool {
        false
    }
}
