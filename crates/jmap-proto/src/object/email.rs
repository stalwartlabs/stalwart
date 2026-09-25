/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    method::query::{Comparator, Filter},
    object::{
        AnyId, JmapObject, JmapObjectId, MaybeReference,
        metadata::{MetadataFilter, MetadataProperty, MetadataRoot},
        parse_ref,
    },
    request::{MaybeInvalid, deserialize::DeserializeArguments},
    types::date::UTCDate,
};
use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, PointerDepth, Property};
use mail_parser::HeaderName;
use serde::{Serialize, Serializer};
use std::{borrow::Cow, fmt::Display, str::FromStr};
use types::{blob::BlobId, id::Id, keyword::Keyword, text::Text};

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

    // Object metadata
    Metadata,
    PrivateMetadata,

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
        Self::try_parse_nested(key, value, PointerDepth::default())
    }

    fn try_parse_nested(
        key: Option<&Key<'_, Self>>,
        value: &str,
        depth: PointerDepth,
    ) -> Option<Self> {
        let patch_depth = key.is_none().then_some(depth);
        match key {
            Some(Key::Property(key)) if key.metadata_root().is_some() => None,
            Some(Key::Property(key)) => match key.patch_or_prop() {
                EmailProperty::Keywords => EmailProperty::Keyword(Keyword::parse(value)).into(),
                EmailProperty::MailboxIds => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(EmailProperty::IdValue(v)),
                    MaybeReference::Reference(v) => Some(EmailProperty::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                _ => EmailProperty::parse(value, patch_depth),
            },
            _ => EmailProperty::parse(value, patch_depth),
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        self.text().to_cow()
    }

    fn key_eq(&self, other: &Self) -> bool {
        if self.has_dynamic_text() || other.has_dynamic_text() {
            self.text().eq_text(other.text())
        } else {
            self == other
        }
    }

    fn key_eq_str(&self, other: &str) -> bool {
        self.text().eq_str(other)
    }

    fn serialize_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.text().serialize(serializer)
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
        self.text().to_cow()
    }

    fn serialize_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            EmailValue::Date(date) => date.serialize(serializer),
            value => value.text().serialize(serializer),
        }
    }
}

impl EmailValue {
    pub fn text(&self) -> Text<'_> {
        match self {
            EmailValue::Id(id) => Text::Id(*id),
            EmailValue::Date(utcdate) => Text::Display(utcdate),
            EmailValue::BlobId(blob_id) => Text::Display(blob_id),
            EmailValue::IdReference(r) => Text::Reference(r),
        }
    }
}

impl EmailProperty {
    pub fn text(&self) -> Text<'_> {
        Text::Static(match self {
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
            EmailProperty::Metadata => "metadata",
            EmailProperty::PrivateMetadata => "privateMetadata",
            EmailProperty::Header(header) => return Text::Display(header),
            EmailProperty::Keyword(keyword) => return Text::Str(keyword.as_str()),
            EmailProperty::IdValue(id) => return Text::Id(*id),
            EmailProperty::Pointer(json_pointer) => return Text::Display(json_pointer),
            EmailProperty::IdReference(r) => return Text::Reference(r),
        })
    }

    fn has_dynamic_text(&self) -> bool {
        matches!(
            self,
            EmailProperty::Pointer(_)
                | EmailProperty::IdValue(_)
                | EmailProperty::Header(_)
                | EmailProperty::Keyword(_)
                | EmailProperty::IdReference(_)
        )
    }

    fn parse(value: &str, patch_depth: Option<PointerDepth>) -> Option<Self> {
        hashify::fnc_map!(value.as_bytes(),
                "id" => Some(EmailProperty::Id),
                "blobId" => Some(EmailProperty::BlobId),
                "threadId" => Some(EmailProperty::ThreadId),
                "mailboxIds" => Some(EmailProperty::MailboxIds),
                "keywords" => Some(EmailProperty::Keywords),
                "size" => Some(EmailProperty::Size),
                "receivedAt" => Some(EmailProperty::ReceivedAt),
                "name" => Some(EmailProperty::Name),
                "email" => Some(EmailProperty::Email),
                "addresses" => Some(EmailProperty::Addresses),
                "value" => Some(EmailProperty::Value),
                "messageId" => Some(EmailProperty::MessageId),
                "inReplyTo" => Some(EmailProperty::InReplyTo),
                "references" => Some(EmailProperty::References),
                "sender" => Some(EmailProperty::Sender),
                "from" => Some(EmailProperty::From),
                "to" => Some(EmailProperty::To),
                "cc" => Some(EmailProperty::Cc),
                "bcc" => Some(EmailProperty::Bcc),
                "replyTo" => Some(EmailProperty::ReplyTo),
                "subject" => Some(EmailProperty::Subject),
                "sentAt" => Some(EmailProperty::SentAt),
                "textBody" => Some(EmailProperty::TextBody),
                "htmlBody" => Some(EmailProperty::HtmlBody),
                "attachments" => Some(EmailProperty::Attachments),
                "partId" => Some(EmailProperty::PartId),
                "headers" => Some(EmailProperty::Headers),
                "type" => Some(EmailProperty::Type),
                "charset" => Some(EmailProperty::Charset),
                "disposition" => Some(EmailProperty::Disposition),
                "cid" => Some(EmailProperty::Cid),
                "language" => Some(EmailProperty::Language),
                "location" => Some(EmailProperty::Location),
                "subParts" => Some(EmailProperty::SubParts),
                "bodyStructure" => Some(EmailProperty::BodyStructure),
                "bodyValues" => Some(EmailProperty::BodyValues),
                "isEncodingProblem" => Some(EmailProperty::IsEncodingProblem),
                "isTruncated" => Some(EmailProperty::IsTruncated),
                "hasAttachment" => Some(EmailProperty::HasAttachment),
                "preview" => Some(EmailProperty::Preview),
                "metadata" => Some(EmailProperty::Metadata),
                "privateMetadata" => Some(EmailProperty::PrivateMetadata),
                _ => None
        )
        .or_else(|| {
            if let Some(header) = value.strip_prefix("header:") {
                HeaderProperty::parse(header).map(EmailProperty::Header)
            } else {
                patch_depth
                    .filter(|_| value.contains('/'))
                    .and_then(|depth| JsonPointer::parse_nested(value, depth))
                    .map(EmailProperty::Pointer)
            }
        })
    }

    fn patch_or_prop(&self) -> &EmailProperty {
        if let EmailProperty::Pointer(ptr) = self
            && self.metadata_pointer().is_none()
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

impl MetadataProperty for EmailProperty {
    fn as_metadata_root(&self) -> Option<MetadataRoot> {
        match self {
            EmailProperty::Metadata => Some(MetadataRoot::Shared),
            EmailProperty::PrivateMetadata => Some(MetadataRoot::Private),
            _ => None,
        }
    }

    fn as_pointer(&self) -> Option<&JsonPointer<Self>> {
        match self {
            EmailProperty::Pointer(pointer) => Some(pointer),
            _ => None,
        }
    }
}

impl FromStr for EmailProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        EmailProperty::parse(s, None)
            .or_else(|| {
                MetadataRoot::from_selector(s)
                    .map(|_| EmailProperty::Pointer(JsonPointer::parse(s)))
            })
            .ok_or(())
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

    type Filter = EmailQueryFilter;

    type Comparator = EmailComparator;

    type GetArguments = EmailGetArguments;

    type SetArguments<'de> = ();

    type QueryArguments = EmailQueryArguments;

    type CopyArguments = ();

    type ParseArguments = EmailParseArguments;

    const ID_PROPERTY: Self::Property = EmailProperty::Id;
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, PartialEq, Eq)]
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
pub enum EmailQueryFilter {
    Email(EmailFilter),
    Metadata(MetadataFilter),
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

impl<'de> DeserializeArguments<'de> for EmailQueryFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        *self = match MetadataFilter::try_deserialize(key, map)? {
            Some(filter) => EmailQueryFilter::Metadata(filter),
            None => {
                let mut filter = EmailFilter::default();
                filter.deserialize_argument(key, map)?;
                EmailQueryFilter::Email(filter)
            }
        };

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

impl Default for EmailQueryFilter {
    fn default() -> Self {
        EmailQueryFilter::Email(EmailFilter::default())
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

impl Display for EmailQueryFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmailQueryFilter::Email(filter) => filter.fmt(f),
            EmailQueryFilter::Metadata(filter) => f.write_str(filter.as_str()),
        }
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

impl Filter<EmailQueryFilter> {
    pub fn is_immutable(&self) -> bool {
        match self {
            Filter::Property(EmailQueryFilter::Email(f)) => f.is_immutable(),
            Filter::Property(EmailQueryFilter::Metadata(_)) => false,
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
