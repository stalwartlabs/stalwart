/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::object::email::{EmailProperty, HeaderForm, HeaderProperty};
use crate::object::{AnyId, JmapObject, JmapObjectId};
use crate::types::date::UTCDate;
use jmap_tools::{Element, JsonPointer, JsonPointerItem};
use jmap_tools::{Key, Property};
use std::borrow::Cow;
use std::str::FromStr;
use types::{id::Id, type_state::DataType};

#[derive(Debug, Clone, Default)]
pub struct PushSubscription;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PushSubscriptionProperty {
    Id,
    DeviceClientId,
    Url,
    Keys,
    P256dh,
    Auth,
    VerificationCode,
    Expires,
    Types,
    EmailPush,

    // Other
    Pointer(JsonPointer<PushSubscriptionProperty>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PushSubscriptionValue {
    Id(Id),
    Date(UTCDate),
    Types(DataType),
}

impl Property for PushSubscriptionProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        PushSubscriptionProperty::parse(value, key.is_none())
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            PushSubscriptionProperty::DeviceClientId => "deviceClientId",
            PushSubscriptionProperty::Expires => "expires",
            PushSubscriptionProperty::Id => "id",
            PushSubscriptionProperty::Keys => "keys",
            PushSubscriptionProperty::Types => "types",
            PushSubscriptionProperty::Url => "url",
            PushSubscriptionProperty::EmailPush => "emailPush",
            PushSubscriptionProperty::VerificationCode => "verificationCode",
            PushSubscriptionProperty::P256dh => "p256dh",
            PushSubscriptionProperty::Auth => "auth",
            PushSubscriptionProperty::Pointer(json_pointer) => {
                return json_pointer.to_string().into();
            }
        }
        .into()
    }
}

impl PushSubscriptionProperty {
    fn parse(value: &str, allow_patch: bool) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => PushSubscriptionProperty::Id,
            b"deviceClientId" => PushSubscriptionProperty::DeviceClientId,
            b"url" => PushSubscriptionProperty::Url,
            b"keys" => PushSubscriptionProperty::Keys,
            b"p256dh" => PushSubscriptionProperty::P256dh,
            b"auth" => PushSubscriptionProperty::Auth,
            b"verificationCode" => PushSubscriptionProperty::VerificationCode,
            b"expires" => PushSubscriptionProperty::Expires,
            b"types" => PushSubscriptionProperty::Types,
            b"emailPush" => PushSubscriptionProperty::EmailPush,
        )
        .or_else(|| {
            if allow_patch && value.contains('/') {
                PushSubscriptionProperty::Pointer(JsonPointer::parse(value)).into()
            } else {
                None
            }
        })
    }

    fn patch_or_prop(&self) -> &PushSubscriptionProperty {
        if let PushSubscriptionProperty::Pointer(ptr) = self
            && let Some(JsonPointerItem::Key(Key::Property(prop))) = ptr.last()
        {
            prop
        } else {
            self
        }
    }
}

impl Element for PushSubscriptionValue {
    type Property = PushSubscriptionProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                PushSubscriptionProperty::Id => {
                    Id::from_str(value).ok().map(PushSubscriptionValue::Id)
                }
                PushSubscriptionProperty::Types => {
                    DataType::parse(value).map(PushSubscriptionValue::Types)
                }
                PushSubscriptionProperty::Expires => UTCDate::from_str(value)
                    .ok()
                    .map(PushSubscriptionValue::Date),
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            PushSubscriptionValue::Id(id) => id.to_string().into(),
            PushSubscriptionValue::Date(utcdate) => utcdate.to_string().into(),
            PushSubscriptionValue::Types(data_type) => data_type.as_str().into(),
        }
    }
}

impl FromStr for PushSubscriptionProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PushSubscriptionProperty::parse(s, false).ok_or(())
    }
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub enum EmailPushProperty {
    Id,
    BlobId,
    ThreadId,
    MailboxIds,
    Keywords,
    Size,
    ReceivedAt,
    MessageId,
    InReplyTo,
    References,
    Sender,
    From,
    To,
    Cc,
    Bcc,
    ReplyTo,
    Subject,
    SentAt,
    Preview,
    HasAttachment,
    BodyStructure,
    BodyValues,
    TextBody,
    HtmlBody,
    Attachments,
    Headers,
    Header(EmailPushHeaderProperty),
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct EmailPushHeaderProperty {
    pub form: EmailPushHeaderForm,
    pub header: String,
    pub all: bool,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq, Default,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
#[repr(u8)]
pub enum EmailPushHeaderForm {
    #[default]
    Raw = 0,
    Text = 1,
    Addresses = 2,
    GroupedAddresses = 3,
    MessageIds = 4,
    Date = 5,
    Urls = 6,
}

impl TryFrom<&EmailProperty> for EmailPushProperty {
    type Error = ();

    fn try_from(value: &EmailProperty) -> Result<Self, Self::Error> {
        Ok(match value {
            EmailProperty::Id => EmailPushProperty::Id,
            EmailProperty::BlobId => EmailPushProperty::BlobId,
            EmailProperty::ThreadId => EmailPushProperty::ThreadId,
            EmailProperty::MailboxIds => EmailPushProperty::MailboxIds,
            EmailProperty::Keywords => EmailPushProperty::Keywords,
            EmailProperty::Size => EmailPushProperty::Size,
            EmailProperty::ReceivedAt => EmailPushProperty::ReceivedAt,
            EmailProperty::MessageId => EmailPushProperty::MessageId,
            EmailProperty::InReplyTo => EmailPushProperty::InReplyTo,
            EmailProperty::References => EmailPushProperty::References,
            EmailProperty::Sender => EmailPushProperty::Sender,
            EmailProperty::From => EmailPushProperty::From,
            EmailProperty::To => EmailPushProperty::To,
            EmailProperty::Cc => EmailPushProperty::Cc,
            EmailProperty::Bcc => EmailPushProperty::Bcc,
            EmailProperty::ReplyTo => EmailPushProperty::ReplyTo,
            EmailProperty::Subject => EmailPushProperty::Subject,
            EmailProperty::SentAt => EmailPushProperty::SentAt,
            EmailProperty::Preview => EmailPushProperty::Preview,
            EmailProperty::HasAttachment => EmailPushProperty::HasAttachment,
            EmailProperty::BodyStructure => EmailPushProperty::BodyStructure,
            EmailProperty::BodyValues => EmailPushProperty::BodyValues,
            EmailProperty::TextBody => EmailPushProperty::TextBody,
            EmailProperty::HtmlBody => EmailPushProperty::HtmlBody,
            EmailProperty::Attachments => EmailPushProperty::Attachments,
            EmailProperty::Headers => EmailPushProperty::Headers,
            EmailProperty::Header(header) => EmailPushProperty::Header(EmailPushHeaderProperty {
                form: (&header.form).into(),
                header: header.header.clone(),
                all: header.all,
            }),
            _ => return Err(()),
        })
    }
}

impl From<&EmailPushProperty> for EmailProperty {
    fn from(value: &EmailPushProperty) -> Self {
        match value {
            EmailPushProperty::Id => EmailProperty::Id,
            EmailPushProperty::BlobId => EmailProperty::BlobId,
            EmailPushProperty::ThreadId => EmailProperty::ThreadId,
            EmailPushProperty::MailboxIds => EmailProperty::MailboxIds,
            EmailPushProperty::Keywords => EmailProperty::Keywords,
            EmailPushProperty::Size => EmailProperty::Size,
            EmailPushProperty::ReceivedAt => EmailProperty::ReceivedAt,
            EmailPushProperty::MessageId => EmailProperty::MessageId,
            EmailPushProperty::InReplyTo => EmailProperty::InReplyTo,
            EmailPushProperty::References => EmailProperty::References,
            EmailPushProperty::Sender => EmailProperty::Sender,
            EmailPushProperty::From => EmailProperty::From,
            EmailPushProperty::To => EmailProperty::To,
            EmailPushProperty::Cc => EmailProperty::Cc,
            EmailPushProperty::Bcc => EmailProperty::Bcc,
            EmailPushProperty::ReplyTo => EmailProperty::ReplyTo,
            EmailPushProperty::Subject => EmailProperty::Subject,
            EmailPushProperty::SentAt => EmailProperty::SentAt,
            EmailPushProperty::Preview => EmailProperty::Preview,
            EmailPushProperty::HasAttachment => EmailProperty::HasAttachment,
            EmailPushProperty::BodyStructure => EmailProperty::BodyStructure,
            EmailPushProperty::BodyValues => EmailProperty::BodyValues,
            EmailPushProperty::TextBody => EmailProperty::TextBody,
            EmailPushProperty::HtmlBody => EmailProperty::HtmlBody,
            EmailPushProperty::Attachments => EmailProperty::Attachments,
            EmailPushProperty::Headers => EmailProperty::Headers,
            EmailPushProperty::Header(header) => EmailProperty::Header(HeaderProperty {
                form: (&header.form).into(),
                header: header.header.clone(),
                all: header.all,
            }),
        }
    }
}

impl From<&ArchivedEmailPushProperty> for EmailProperty {
    fn from(value: &ArchivedEmailPushProperty) -> Self {
        match value {
            ArchivedEmailPushProperty::Id => EmailProperty::Id,
            ArchivedEmailPushProperty::BlobId => EmailProperty::BlobId,
            ArchivedEmailPushProperty::ThreadId => EmailProperty::ThreadId,
            ArchivedEmailPushProperty::MailboxIds => EmailProperty::MailboxIds,
            ArchivedEmailPushProperty::Keywords => EmailProperty::Keywords,
            ArchivedEmailPushProperty::Size => EmailProperty::Size,
            ArchivedEmailPushProperty::ReceivedAt => EmailProperty::ReceivedAt,
            ArchivedEmailPushProperty::MessageId => EmailProperty::MessageId,
            ArchivedEmailPushProperty::InReplyTo => EmailProperty::InReplyTo,
            ArchivedEmailPushProperty::References => EmailProperty::References,
            ArchivedEmailPushProperty::Sender => EmailProperty::Sender,
            ArchivedEmailPushProperty::From => EmailProperty::From,
            ArchivedEmailPushProperty::To => EmailProperty::To,
            ArchivedEmailPushProperty::Cc => EmailProperty::Cc,
            ArchivedEmailPushProperty::Bcc => EmailProperty::Bcc,
            ArchivedEmailPushProperty::ReplyTo => EmailProperty::ReplyTo,
            ArchivedEmailPushProperty::Subject => EmailProperty::Subject,
            ArchivedEmailPushProperty::SentAt => EmailProperty::SentAt,
            ArchivedEmailPushProperty::Preview => EmailProperty::Preview,
            ArchivedEmailPushProperty::HasAttachment => EmailProperty::HasAttachment,
            ArchivedEmailPushProperty::BodyStructure => EmailProperty::BodyStructure,
            ArchivedEmailPushProperty::BodyValues => EmailProperty::BodyValues,
            ArchivedEmailPushProperty::TextBody => EmailProperty::TextBody,
            ArchivedEmailPushProperty::HtmlBody => EmailProperty::HtmlBody,
            ArchivedEmailPushProperty::Attachments => EmailProperty::Attachments,
            ArchivedEmailPushProperty::Headers => EmailProperty::Headers,
            ArchivedEmailPushProperty::Header(header) => EmailProperty::Header(HeaderProperty {
                form: (&header.form).into(),
                header: header.header.as_str().to_string(),
                all: header.all,
            }),
        }
    }
}

impl From<&ArchivedEmailPushHeaderForm> for HeaderForm {
    fn from(value: &ArchivedEmailPushHeaderForm) -> Self {
        match value {
            ArchivedEmailPushHeaderForm::Raw => HeaderForm::Raw,
            ArchivedEmailPushHeaderForm::Text => HeaderForm::Text,
            ArchivedEmailPushHeaderForm::Addresses => HeaderForm::Addresses,
            ArchivedEmailPushHeaderForm::GroupedAddresses => HeaderForm::GroupedAddresses,
            ArchivedEmailPushHeaderForm::MessageIds => HeaderForm::MessageIds,
            ArchivedEmailPushHeaderForm::Date => HeaderForm::Date,
            ArchivedEmailPushHeaderForm::Urls => HeaderForm::URLs,
        }
    }
}

impl From<&HeaderForm> for EmailPushHeaderForm {
    fn from(value: &HeaderForm) -> Self {
        match value {
            HeaderForm::Raw => EmailPushHeaderForm::Raw,
            HeaderForm::Text => EmailPushHeaderForm::Text,
            HeaderForm::Addresses => EmailPushHeaderForm::Addresses,
            HeaderForm::GroupedAddresses => EmailPushHeaderForm::GroupedAddresses,
            HeaderForm::MessageIds => EmailPushHeaderForm::MessageIds,
            HeaderForm::Date => EmailPushHeaderForm::Date,
            HeaderForm::URLs => EmailPushHeaderForm::Urls,
        }
    }
}

impl From<&EmailPushHeaderForm> for HeaderForm {
    fn from(value: &EmailPushHeaderForm) -> Self {
        match value {
            EmailPushHeaderForm::Raw => HeaderForm::Raw,
            EmailPushHeaderForm::Text => HeaderForm::Text,
            EmailPushHeaderForm::Addresses => HeaderForm::Addresses,
            EmailPushHeaderForm::GroupedAddresses => HeaderForm::GroupedAddresses,
            EmailPushHeaderForm::MessageIds => HeaderForm::MessageIds,
            EmailPushHeaderForm::Date => HeaderForm::Date,
            EmailPushHeaderForm::Urls => HeaderForm::URLs,
        }
    }
}

impl JmapObject for PushSubscription {
    type Property = PushSubscriptionProperty;

    type Element = PushSubscriptionValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = PushSubscriptionProperty::Id;
}

impl From<Id> for PushSubscriptionValue {
    fn from(id: Id) -> Self {
        PushSubscriptionValue::Id(id)
    }
}

impl JmapObjectId for PushSubscriptionValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            PushSubscriptionValue::Id(id) => Some(*id),
            _ => None,
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            PushSubscriptionValue::Id(id) => Some(AnyId::Id(*id)),
            _ => None,
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = PushSubscriptionValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for PushSubscriptionProperty {
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
