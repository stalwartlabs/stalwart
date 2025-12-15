/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    method::query::{Comparator, Filter},
    object::{AnyId, JmapObject, JmapObjectId, MaybeReference, parse_ref},
    request::{MaybeInvalid, deserialize::DeserializeArguments},
    types::date::UTCDate,
};
use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, Property};
use mail_parser::HeaderName;
use serde::Serialize;
use std::{borrow::Cow, fmt::Display, str::FromStr};
use types::{blob::BlobId, id::Id, keyword::Keyword};

#[derive(Debug, Clone, Default)]
pub struct Email;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EmailProperty {
    // Metadata
    Id,
    BlobId,
    ThreadId,
    MailboxIds,
    Keywords,
    Size,
    ReceivedAt,

    // Address
    Name,
    Email,

    // GroupedAddresses
    Addresses,

    // Header Fields Properties
    Value,
    Header(HeaderProperty),

    // Convenience properties
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

    // Body Parts
    TextBody,
    HtmlBody,
    Attachments,
    PartId,
    Headers,
    Type,
    Charset,
    Disposition,
    Cid,
    Language,
    Location,
    SubParts,
    BodyStructure,
    BodyValues,
    IsEncodingProblem,
    IsTruncated,
    HasAttachment,
    Preview,

    // Other
    Keyword(Keyword),
    IdValue(Id),
    IdReference(String),
    Pointer(JsonPointer<EmailProperty>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HeaderProperty {
    pub form: HeaderForm,
    pub header: String,
    pub all: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HeaderForm {
    Raw,
    Text,
    Addresses,
    GroupedAddresses,
    MessageIds,
    Date,
    URLs,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EmailValue {
    Id(Id),
    Date(UTCDate),
    BlobId(BlobId),
    IdReference(String),
}

impl Property for EmailProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        let allow_patch = key.is_none();
        if let Some(Key::Property(key)) = key {
            match key.patch_or_prop() {
                EmailProperty::Keywords => EmailProperty::Keyword(Keyword::parse(value)).into(),
                EmailProperty::MailboxIds => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(EmailProperty::IdValue(v)),
                    MaybeReference::Reference(v) => Some(EmailProperty::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                _ => EmailProperty::parse(value, allow_patch),
            }
        } else {
            EmailProperty::parse(value, allow_patch)
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            EmailProperty::Attachments => "attachments",
            EmailProperty::Bcc => "bcc",
            EmailProperty::BlobId => "blobId",
            EmailProperty::BodyStructure => "bodyStructure",
            EmailProperty::BodyValues => "bodyValues",
            EmailProperty::Cc => "cc",
            EmailProperty::Charset => "charset",
            EmailProperty::Cid => "cid",
            EmailProperty::Disposition => "disposition",
            EmailProperty::Email => "email",
            EmailProperty::From => "from",
            EmailProperty::HasAttachment => "hasAttachment",
            EmailProperty::Headers => "headers",
            EmailProperty::HtmlBody => "htmlBody",
            EmailProperty::Id => "id",
            EmailProperty::InReplyTo => "inReplyTo",
            EmailProperty::Keywords => "keywords",
            EmailProperty::Language => "language",
            EmailProperty::Location => "location",
            EmailProperty::MailboxIds => "mailboxIds",
            EmailProperty::MessageId => "messageId",
            EmailProperty::Name => "name",
            EmailProperty::PartId => "partId",
            EmailProperty::Preview => "preview",
            EmailProperty::ReceivedAt => "receivedAt",
            EmailProperty::References => "references",
            EmailProperty::ReplyTo => "replyTo",
            EmailProperty::Sender => "sender",
            EmailProperty::SentAt => "sentAt",
            EmailProperty::Size => "size",
            EmailProperty::Subject => "subject",
            EmailProperty::SubParts => "subParts",
            EmailProperty::TextBody => "textBody",
            EmailProperty::ThreadId => "threadId",
            EmailProperty::To => "to",
            EmailProperty::Type => "type",
            EmailProperty::Addresses => "addresses",
            EmailProperty::Value => "value",
            EmailProperty::IsEncodingProblem => "isEncodingProblem",
            EmailProperty::IsTruncated => "isTruncated",
            EmailProperty::Header(header) => return header.to_string().into(),
            EmailProperty::Keyword(keyword) => return keyword.to_string().into(),
            EmailProperty::IdValue(id) => return id.to_string().into(),
            EmailProperty::Pointer(json_pointer) => return json_pointer.to_string().into(),
            EmailProperty::IdReference(r) => return format!("#{r}").into(),
        }
        .into()
    }
}

impl Element for EmailValue {
    type Property = EmailProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                EmailProperty::Id | EmailProperty::ThreadId | EmailProperty::MailboxIds => {
                    match parse_ref(value) {
                        MaybeReference::Value(v) => Some(EmailValue::Id(v)),
                        MaybeReference::Reference(v) => Some(EmailValue::IdReference(v)),
                        MaybeReference::ParseError => None,
                    }
                }
                EmailProperty::BlobId => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(EmailValue::BlobId(v)),
                    MaybeReference::Reference(v) => Some(EmailValue::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                EmailProperty::Header(HeaderProperty {
                    form: HeaderForm::Date,
                    ..
                })
                | EmailProperty::ReceivedAt
                | EmailProperty::SentAt => UTCDate::from_str(value).ok().map(EmailValue::Date),
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            EmailValue::Id(id) => id.to_string().into(),
            EmailValue::Date(utcdate) => utcdate.to_string().into(),
            EmailValue::BlobId(blob_id) => blob_id.to_string().into(),
            EmailValue::IdReference(r) => format!("#{r}").into(),
        }
    }
}

impl EmailProperty {
    fn parse(value: &str, allow_patch: bool) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
                "id" => EmailProperty::Id,
                "blobId" => EmailProperty::BlobId,
                "threadId" => EmailProperty::ThreadId,
                "mailboxIds" => EmailProperty::MailboxIds,
                "keywords" => EmailProperty::Keywords,
                "size" => EmailProperty::Size,
                "receivedAt" => EmailProperty::ReceivedAt,
                "name" => EmailProperty::Name,
                "email" => EmailProperty::Email,
                "addresses" => EmailProperty::Addresses,
                "value" => EmailProperty::Value,
                "messageId" => EmailProperty::MessageId,
                "inReplyTo" => EmailProperty::InReplyTo,
                "references" => EmailProperty::References,
                "sender" => EmailProperty::Sender,
                "from" => EmailProperty::From,
                "to" => EmailProperty::To,
                "cc" => EmailProperty::Cc,
                "bcc" => EmailProperty::Bcc,
                "replyTo" => EmailProperty::ReplyTo,
                "subject" => EmailProperty::Subject,
                "sentAt" => EmailProperty::SentAt,
                "textBody" => EmailProperty::TextBody,
                "htmlBody" => EmailProperty::HtmlBody,
                "attachments" => EmailProperty::Attachments,
                "partId" => EmailProperty::PartId,
                "headers" => EmailProperty::Headers,
                "type" => EmailProperty::Type,
                "charset" => EmailProperty::Charset,
                "disposition" => EmailProperty::Disposition,
                "cid" => EmailProperty::Cid,
                "language" => EmailProperty::Language,
                "location" => EmailProperty::Location,
                "subParts" => EmailProperty::SubParts,
                "bodyStructure" => EmailProperty::BodyStructure,
                "bodyValues" => EmailProperty::BodyValues,
                "isEncodingProblem" => EmailProperty::IsEncodingProblem,
                "isTruncated" => EmailProperty::IsTruncated,
                "hasAttachment" => EmailProperty::HasAttachment,
                "preview" => EmailProperty::Preview
        )
        .or_else(|| {
            if let Some(header) = value.strip_prefix("header:") {
                HeaderProperty::parse(header).map(EmailProperty::Header)
            } else if allow_patch && value.contains('/') {
                EmailProperty::Pointer(JsonPointer::parse(value)).into()
            } else {
                None
            }
        })
    }

    fn patch_or_prop(&self) -> &EmailProperty {
        if let EmailProperty::Pointer(ptr) = self
            && let Some(JsonPointerItem::Key(Key::Property(prop))) = ptr.last()
        {
            prop
        } else {
            self
        }
    }

    pub fn as_rfc_header(&self) -> HeaderName<'static> {
        match self {
            EmailProperty::MessageId => HeaderName::MessageId,
            EmailProperty::InReplyTo => HeaderName::InReplyTo,
            EmailProperty::References => HeaderName::References,
            EmailProperty::Sender => HeaderName::Sender,
            EmailProperty::From => HeaderName::From,
            EmailProperty::To => HeaderName::To,
            EmailProperty::Cc => HeaderName::Cc,
            EmailProperty::Bcc => HeaderName::Bcc,
            EmailProperty::ReplyTo => HeaderName::ReplyTo,
            EmailProperty::Subject => HeaderName::Subject,
            EmailProperty::SentAt => HeaderName::Date,
            _ => unreachable!(),
        }
    }

    pub fn try_into_id(self) -> Option<Id> {
        match self {
            EmailProperty::IdValue(id) => Some(id),
            _ => None,
        }
    }

    pub fn try_into_keyword(self) -> Option<Keyword> {
        match self {
            EmailProperty::Keyword(keyword) => Some(keyword),
            _ => None,
        }
    }
}

impl HeaderProperty {
    fn parse(value: &str) -> Option<Self> {
        let mut result = HeaderProperty {
            form: HeaderForm::Raw,
            header: String::new(),
            all: false,
        };

        for (pos, value) in value.split(':').enumerate() {
            match pos {
                0 => {
                    result.header = value.to_string();
                }
                1 => {
                    hashify::fnc_map!(value.as_bytes(),
                        b"asText" => { result.form = HeaderForm::Text;},
                        b"asAddresses" => { result.form = HeaderForm::Addresses;},
                        b"asGroupedAddresses" => { result.form = HeaderForm::GroupedAddresses;},
                        b"asMessageIds" => { result.form = HeaderForm::MessageIds;},
                        b"asDate" => { result.form = HeaderForm::Date;},
                        b"asURLs" => { result.form = HeaderForm::URLs;},
                        b"asRaw"  => { result.form = HeaderForm::Raw; },
                        b"all"  => { result.all = true; },
                        _ => {
                            return None;
                        }
                    );
                }
                2 if value == "all" && !result.all => {
                    result.all = true;
                }
                _ => return None,
            }
        }

        if !result.header.is_empty() {
            Some(result)
        } else {
            None
        }
    }
}

impl Display for HeaderProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "header:{}", self.header)?;
        self.form.fmt(f)?;
        if self.all { write!(f, ":all") } else { Ok(()) }
    }
}

impl Display for HeaderForm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HeaderForm::Raw => Ok(()),
            HeaderForm::Text => write!(f, ":asText"),
            HeaderForm::Addresses => write!(f, ":asAddresses"),
            HeaderForm::GroupedAddresses => write!(f, ":asGroupedAddresses"),
            HeaderForm::MessageIds => write!(f, ":asMessageIds"),
            HeaderForm::Date => write!(f, ":asDate"),
            HeaderForm::URLs => write!(f, ":asURLs"),
        }
    }
}

impl FromStr for EmailProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        EmailProperty::parse(s, false).ok_or(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct EmailGetArguments {
    pub body_properties: Option<Vec<MaybeInvalid<EmailProperty>>>,
    pub fetch_text_body_values: Option<bool>,
    pub fetch_html_body_values: Option<bool>,
    pub fetch_all_body_values: Option<bool>,
    pub max_body_value_bytes: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct EmailQueryArguments {
    pub collapse_threads: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct EmailParseArguments {
    pub body_properties: Option<Vec<MaybeInvalid<EmailProperty>>>,
    pub fetch_text_body_values: Option<bool>,
    pub fetch_html_body_values: Option<bool>,
    pub fetch_all_body_values: Option<bool>,
    pub max_body_value_bytes: Option<usize>,
}

impl<'de> DeserializeArguments<'de> for EmailGetArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"bodyProperties" => {
                self.body_properties = map.next_value()?;
            },
            b"fetchTextBodyValues" => {
                self.fetch_text_body_values = map.next_value()?;
            },
            b"fetchHTMLBodyValues" => {
                self.fetch_html_body_values = map.next_value()?;
            },
            b"fetchAllBodyValues" => {
                self.fetch_all_body_values = map.next_value()?;
            },
            b"maxBodyValueBytes" => {
                self.max_body_value_bytes = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for EmailQueryArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "collapseThreads" {
            self.collapse_threads = map.next_value()?;
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for EmailParseArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"bodyProperties" => {
                self.body_properties = map.next_value()?;
            },
            b"fetchTextBodyValues" => {
                self.fetch_text_body_values = map.next_value()?;
            },
            b"fetchHTMLBodyValues" => {
                self.fetch_html_body_values = map.next_value()?;
            },
            b"fetchAllBodyValues" => {
                self.fetch_all_body_values = map.next_value()?;
            },
            b"maxBodyValueBytes" => {
                self.max_body_value_bytes = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl JmapObject for Email {
    type Property = EmailProperty;

    type Element = EmailValue;

    type Id = Id;

    type Filter = EmailFilter;

    type Comparator = EmailComparator;

    type GetArguments = EmailGetArguments;

    type SetArguments<'de> = ();

    type QueryArguments = EmailQueryArguments;

    type CopyArguments = ();

    type ParseArguments = EmailParseArguments;

    const ID_PROPERTY: Self::Property = EmailProperty::Id;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailFilter {
    InMailbox(Id),
    InMailboxOtherThan(Vec<Id>),
    Before(UTCDate),
    After(UTCDate),
    MinSize(u32),
    MaxSize(u32),
    AllInThreadHaveKeyword(Keyword),
    SomeInThreadHaveKeyword(Keyword),
    NoneInThreadHaveKeyword(Keyword),
    HasKeyword(Keyword),
    NotKeyword(Keyword),
    HasAttachment(bool),
    From(String),
    To(String),
    Cc(String),
    Bcc(String),
    Subject(String),
    Body(String),
    Header(Vec<String>),
    Text(String),
    SentBefore(UTCDate),
    SentAfter(UTCDate),
    InThread(Id),
    Id(Vec<Id>),
    _T(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailComparator {
    ReceivedAt,
    Size,
    From,
    To,
    Subject,
    Cc,
    SentAt,
    ThreadId,
    HasKeyword(Keyword),
    AllInThreadHaveKeyword(Keyword),
    SomeInThreadHaveKeyword(Keyword),
    _T(String),
}

impl<'de> DeserializeArguments<'de> for EmailFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"inMailbox" => {
                *self = EmailFilter::InMailbox(map.next_value()?);
            },
            b"inMailboxOtherThan" => {
                *self = EmailFilter::InMailboxOtherThan(map.next_value()?);
            },
            b"before" => {
                *self = EmailFilter::Before(map.next_value()?);
            },
            b"after" => {
                *self = EmailFilter::After(map.next_value()?);
            },
            b"minSize" => {
                *self = EmailFilter::MinSize(map.next_value()?);
            },
            b"maxSize" => {
                *self = EmailFilter::MaxSize(map.next_value()?);
            },
            b"allInThreadHaveKeyword" => {
                *self = EmailFilter::AllInThreadHaveKeyword(map.next_value()?);
            },
            b"someInThreadHaveKeyword" => {
                *self = EmailFilter::SomeInThreadHaveKeyword(map.next_value()?);
            },
            b"noneInThreadHaveKeyword" => {
                *self = EmailFilter::NoneInThreadHaveKeyword(map.next_value()?);
            },
            b"hasKeyword" => {
                *self = EmailFilter::HasKeyword(map.next_value()?);
            },
            b"notKeyword" => {
                *self = EmailFilter::NotKeyword(map.next_value()?);
            },
            b"hasAttachment" => {
                *self = EmailFilter::HasAttachment(map.next_value()?);
            },
            b"from" => {
                *self = EmailFilter::From(map.next_value()?);
            },
            b"to" => {
                *self = EmailFilter::To(map.next_value()?);
            },
            b"cc" => {
                *self = EmailFilter::Cc(map.next_value()?);
            },
            b"bcc" => {
                *self = EmailFilter::Bcc(map.next_value()?);
            },
            b"subject" => {
                *self = EmailFilter::Subject(map.next_value()?);
            },
            b"body" => {
                *self = EmailFilter::Body(map.next_value()?);
            },
            b"header" => {
                *self = EmailFilter::Header(map.next_value()?);
            },
            b"text" => {
                *self = EmailFilter::Text(map.next_value()?);
            },
            b"sentBefore" => {
                *self = EmailFilter::SentBefore(map.next_value()?);
            },
            b"sentAfter" => {
                *self = EmailFilter::SentAfter(map.next_value()?);
            },
            b"inThread" => {
                *self = EmailFilter::InThread(map.next_value()?);
            },
            b"id" => {
                *self = EmailFilter::Id(map.next_value()?);
            },
            _ => {
                *self = EmailFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for EmailComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<Cow<str>>()?;
            hashify::fnc_map!(value.as_bytes(),
                b"receivedAt" => {
                    *self = EmailComparator::ReceivedAt;
                },
                b"size" => {
                    *self = EmailComparator::Size;
                },
                b"from" => {
                    *self = EmailComparator::From;
                },
                b"to" => {
                    *self = EmailComparator::To;
                },
                b"cc" => {
                    *self = EmailComparator::Cc;
                },
                b"subject" => {
                    *self = EmailComparator::Subject;
                },
                b"sentAt" => {
                    *self = EmailComparator::SentAt;
                },
                b"threadId" => {
                    *self = EmailComparator::ThreadId;
                },
                b"hasKeyword" => {
                    *self = EmailComparator::HasKeyword(self.take_keyword());
                },
                b"allInThreadHaveKeyword" => {
                    *self = EmailComparator::AllInThreadHaveKeyword(self.take_keyword());
                },
                b"someInThreadHaveKeyword" => {
                    *self = EmailComparator::SomeInThreadHaveKeyword(self.take_keyword());
                },
                _ => {
                    *self = EmailComparator::_T(key.to_string());
                }
            );
        } else if key == "keyword" {
            let keyword: Keyword = map.next_value()?;
            match self {
                EmailComparator::HasKeyword(_) => *self = EmailComparator::HasKeyword(keyword),
                EmailComparator::AllInThreadHaveKeyword(_) => {
                    *self = EmailComparator::AllInThreadHaveKeyword(keyword)
                }
                EmailComparator::SomeInThreadHaveKeyword(_) => {
                    *self = EmailComparator::SomeInThreadHaveKeyword(keyword)
                }
                _ => {
                    *self = EmailComparator::HasKeyword(keyword);
                }
            }
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
    }
}

impl Default for EmailFilter {
    fn default() -> Self {
        EmailFilter::_T("".to_string())
    }
}

impl Default for EmailComparator {
    fn default() -> Self {
        EmailComparator::_T("".to_string())
    }
}

impl EmailComparator {
    fn take_keyword(&mut self) -> Keyword {
        match self {
            EmailComparator::HasKeyword(k) => {
                std::mem::replace(k, Keyword::Other(Default::default()))
            }
            EmailComparator::AllInThreadHaveKeyword(k) => {
                std::mem::replace(k, Keyword::Other(Default::default()))
            }
            EmailComparator::SomeInThreadHaveKeyword(k) => {
                std::mem::replace(k, Keyword::Other(Default::default()))
            }
            _ => Keyword::Other(Default::default()),
        }
    }
}

impl Display for EmailFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            EmailFilter::InMailbox(_) => "inMailbox",
            EmailFilter::InMailboxOtherThan(_) => "inMailboxOtherThan",
            EmailFilter::Before(_) => "before",
            EmailFilter::After(_) => "after",
            EmailFilter::MinSize(_) => "minSize",
            EmailFilter::MaxSize(_) => "maxSize",
            EmailFilter::AllInThreadHaveKeyword(_) => "allInThreadHaveKeyword",
            EmailFilter::SomeInThreadHaveKeyword(_) => "someInThreadHaveKeyword",
            EmailFilter::NoneInThreadHaveKeyword(_) => "noneInThreadHaveKeyword",
            EmailFilter::HasKeyword(_) => "hasKeyword",
            EmailFilter::NotKeyword(_) => "notKeyword",
            EmailFilter::HasAttachment(_) => "hasAttachment",
            EmailFilter::From(_) => "from",
            EmailFilter::To(_) => "to",
            EmailFilter::Cc(_) => "cc",
            EmailFilter::Bcc(_) => "bcc",
            EmailFilter::Subject(_) => "subject",
            EmailFilter::Body(_) => "body",
            EmailFilter::Header(_) => "header",
            EmailFilter::Text(_) => "text",
            EmailFilter::SentBefore(_) => "sentBefore",
            EmailFilter::SentAfter(_) => "sentAfter",
            EmailFilter::InThread(_) => "inThread",
            EmailFilter::Id(_) => "id",
            EmailFilter::_T(v) => v.as_str(),
        })
    }
}

impl Display for EmailComparator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl EmailComparator {
    pub fn as_str(&self) -> &str {
        match self {
            EmailComparator::ReceivedAt => "receivedAt",
            EmailComparator::Size => "size",
            EmailComparator::From => "from",
            EmailComparator::To => "to",
            EmailComparator::Subject => "subject",
            EmailComparator::Cc => "cc",
            EmailComparator::SentAt => "sentAt",
            EmailComparator::ThreadId => "threadId",
            EmailComparator::HasKeyword(_) => "hasKeyword",
            EmailComparator::AllInThreadHaveKeyword(_) => "allInThreadHaveKeyword",
            EmailComparator::SomeInThreadHaveKeyword(_) => "someInThreadHaveKeyword",
            EmailComparator::_T(v) => v.as_str(),
        }
    }
}

impl Serialize for EmailComparator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl Filter<EmailFilter> {
    pub fn is_immutable(&self) -> bool {
        match self {
            Filter::Property(f) => f.is_immutable(),
            Filter::And | Filter::Or | Filter::Not | Filter::Close => true,
        }
    }
}

impl EmailFilter {
    pub fn is_immutable(&self) -> bool {
        matches!(
            self,
            EmailFilter::Before(_)
                | EmailFilter::After(_)
                | EmailFilter::MinSize(_)
                | EmailFilter::MaxSize(_)
                | EmailFilter::HasAttachment(_)
                | EmailFilter::From(_)
                | EmailFilter::To(_)
                | EmailFilter::Cc(_)
                | EmailFilter::Bcc(_)
                | EmailFilter::Subject(_)
                | EmailFilter::Body(_)
                | EmailFilter::Header(_)
                | EmailFilter::Text(_)
                | EmailFilter::Id(_)
                | EmailFilter::SentBefore(_)
                | EmailFilter::SentAfter(_)
        )
    }
}

impl Comparator<EmailComparator> {
    pub fn is_immutable(&self) -> bool {
        self.property.is_immutable()
    }
}

impl EmailComparator {
    pub fn is_immutable(&self) -> bool {
        matches!(
            self,
            EmailComparator::ReceivedAt
                | EmailComparator::Size
                | EmailComparator::From
                | EmailComparator::To
                | EmailComparator::Subject
                | EmailComparator::Cc
                | EmailComparator::SentAt
        )
    }
}

impl JmapObjectId for EmailValue {
    fn as_id(&self) -> Option<Id> {
        if let EmailValue::Id(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            EmailValue::Id(id) => Some(AnyId::Id(*id)),
            EmailValue::BlobId(id) => Some(AnyId::BlobId(id.clone())),
            _ => None,
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        if let EmailValue::IdReference(r) = self {
            Some(r)
        } else {
            None
        }
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        match new_id {
            AnyId::Id(id) => {
                *self = EmailValue::Id(id);
            }
            AnyId::BlobId(id) => {
                *self = EmailValue::BlobId(id);
            }
        }
        true
    }
}

impl From<Id> for EmailValue {
    fn from(id: Id) -> Self {
        EmailValue::Id(id)
    }
}

impl From<BlobId> for EmailValue {
    fn from(id: BlobId) -> Self {
        EmailValue::BlobId(id)
    }
}

impl From<UTCDate> for EmailValue {
    fn from(date: UTCDate) -> Self {
        EmailValue::Date(date)
    }
}

impl JmapObjectId for EmailProperty {
    fn as_id(&self) -> Option<Id> {
        if let EmailProperty::IdValue(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        if let EmailProperty::IdValue(id) = self {
            Some(AnyId::Id(*id))
        } else {
            None
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        match self {
            EmailProperty::IdReference(r) => Some(r),
            EmailProperty::Pointer(value) => {
                let value = value.as_slice();
                match (value.first(), value.get(1)) {
                    (
                        Some(JsonPointerItem::Key(Key::Property(EmailProperty::MailboxIds))),
                        Some(JsonPointerItem::Key(Key::Property(EmailProperty::IdReference(r)))),
                    ) => Some(r),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            if let EmailProperty::Pointer(value) = self {
                let value = value.as_mut_slice();
                if let Some(value) = value.get_mut(1) {
                    *value = JsonPointerItem::Key(Key::Property(EmailProperty::IdValue(id)));
                    return true;
                }
            } else {
                *self = EmailProperty::IdValue(id);
                return true;
            }
        }
        false
    }
}
