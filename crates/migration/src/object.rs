/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::slice::Iter;
use store::{Deserialize, U64_LEN};
use types::{acl::AclGrant, blob::BlobId, id::Id, keyword::*};
use utils::{
    codec::leb128::Leb128Iterator,
    map::{bitmap::Bitmap, vec_map::VecMap},
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Object<T> {
    pub properties: VecMap<Property, T>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Property {
    Acl,
    Aliases,
    Attachments,
    Bcc,
    BlobId,
    BodyStructure,
    BodyValues,
    Capabilities,
    Cc,
    Charset,
    Cid,
    DeliveryStatus,
    Description,
    DeviceClientId,
    Disposition,
    DsnBlobIds,
    Email,
    EmailId,
    EmailIds,
    Envelope,
    Expires,
    From,
    FromDate,
    HasAttachment,
    Headers,
    HtmlBody,
    HtmlSignature,
    Id,
    IdentityId,
    InReplyTo,
    IsActive,
    IsEnabled,
    IsSubscribed,
    Keys,
    Keywords,
    Language,
    Location,
    MailboxIds,
    MayDelete,
    MdnBlobIds,
    Members,
    MessageId,
    MyRights,
    Name,
    ParentId,
    PartId,
    Picture,
    Preview,
    Quota,
    ReceivedAt,
    References,
    ReplyTo,
    Role,
    Secret,
    SendAt,
    Sender,
    SentAt,
    Size,
    SortOrder,
    Subject,
    SubParts,
    TextBody,
    TextSignature,
    ThreadId,
    Timezone,
    To,
    ToDate,
    TotalEmails,
    TotalThreads,
    Type,
    Types,
    UndoStatus,
    UnreadEmails,
    UnreadThreads,
    Url,
    VerificationCode,
    Addresses,
    P256dh,
    Auth,
    Value,
    SmtpReply,
    Delivered,
    Displayed,
    MailFrom,
    RcptTo,
    Parameters,
    IsEncodingProblem,
    IsTruncated,
    MayReadItems,
    MayAddItems,
    MayRemoveItems,
    MaySetSeen,
    MaySetKeywords,
    MayCreateChild,
    MayRename,
    MaySubmit,
    ResourceType,
    Used,
    HardLimit,
    WarnLimit,
    SoftLimit,
    Scope,
    _T(String),
}

impl Object<Value> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            properties: VecMap::with_capacity(capacity),
        }
    }

    pub fn set(&mut self, property: Property, value: impl Into<Value>) -> bool {
        self.properties.set(property, value.into())
    }

    pub fn append(&mut self, property: Property, value: impl Into<Value>) {
        self.properties.append(property, value.into());
    }

    pub fn with_property(mut self, property: Property, value: impl Into<Value>) -> Self {
        self.properties.append(property, value.into());
        self
    }

    pub fn remove(&mut self, property: &Property) -> Value {
        self.properties.remove(property).unwrap_or(Value::Null)
    }

    pub fn get(&self, property: &Property) -> &Value {
        self.properties.get(property).unwrap_or(&Value::Null)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum Value {
    Text(String),
    UnsignedInt(u64),
    Bool(bool),
    Id(Id),
    Date(UTCDate),
    BlobId(BlobId),
    Keyword(Keyword),
    List(Vec<Value>),
    Object(Object<Value>),
    Acl(Vec<AclGrant>),
    Blob(Vec<u8>),
    #[default]
    Null,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct UTCDate {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub tz_before_gmt: bool,
    pub tz_hour: u8,
    pub tz_minute: u8,
}

const TEXT: u8 = 0;
const UNSIGNED_INT: u8 = 1;
const BOOL_TRUE: u8 = 2;
const BOOL_FALSE: u8 = 3;
const ID: u8 = 4;
const DATE: u8 = 5;
const BLOB_ID: u8 = 6;
const BLOB: u8 = 7;
const KEYWORD: u8 = 8;
const LIST: u8 = 9;
const OBJECT: u8 = 10;
const ACL: u8 = 11;
const NULL: u8 = 12;

pub trait DeserializeFrom: Sized {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self>;
}

impl Deserialize for Object<Value> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Object::deserialize_from(&mut bytes.iter()).ok_or_else(|| {
            trc::StoreEvent::DataCorruption
                .caused_by(trc::location!())
                .ctx(trc::Key::Value, bytes)
        })
    }
}

impl DeserializeFrom for AclGrant {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        let account_id = bytes.next_leb128()?;
        let mut grants = [0u8; U64_LEN];
        for byte in grants.iter_mut() {
            *byte = *bytes.next()?;
        }

        Some(Self {
            account_id,
            grants: Bitmap::from(u64::from_be_bytes(grants)),
        })
    }
}

impl DeserializeFrom for Object<Value> {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Object<Value>> {
        let len = bytes.next_leb128()?;
        let mut properties = VecMap::with_capacity(len);
        for _ in 0..len {
            let key = Property::deserialize_from(bytes)?;
            let value = Value::deserialize_from(bytes)?;
            properties.append(key, value);
        }
        Some(Object { properties })
    }
}

impl DeserializeFrom for Value {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        match *bytes.next()? {
            TEXT => Some(Value::Text(String::deserialize_from(bytes)?)),
            UNSIGNED_INT => Some(Value::UnsignedInt(bytes.next_leb128()?)),
            BOOL_TRUE => Some(Value::Bool(true)),
            BOOL_FALSE => Some(Value::Bool(false)),
            ID => Some(Value::Id(Id::new(bytes.next_leb128()?))),
            DATE => Some(Value::Date(UTCDate::from_timestamp(
                bytes.next_leb128::<u64>()? as i64,
            ))),
            BLOB_ID => Some(Value::BlobId(BlobId::deserialize_from(bytes)?)),
            KEYWORD => Some(Value::Keyword(Keyword::deserialize_from(bytes)?)),
            LIST => {
                let len = bytes.next_leb128()?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(Value::deserialize_from(bytes)?);
                }
                Some(Value::List(items))
            }
            OBJECT => Some(Value::Object(Object::deserialize_from(bytes)?)),
            BLOB => Some(Value::Blob(Vec::deserialize_from(bytes)?)),
            ACL => {
                let len = bytes.next_leb128()?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(AclGrant::deserialize_from(bytes)?);
                }
                Some(Value::Acl(items))
            }
            NULL => Some(Value::Null),
            _ => None,
        }
    }
}

impl DeserializeFrom for u32 {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        bytes.next_leb128()
    }
}

impl DeserializeFrom for u64 {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        bytes.next_leb128()
    }
}

impl DeserializeFrom for String {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        <Vec<u8>>::deserialize_from(bytes).and_then(|s| String::from_utf8(s).ok())
    }
}

impl DeserializeFrom for Vec<u8> {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        let len: usize = bytes.next_leb128()?;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(*bytes.next()?);
        }
        buf.into()
    }
}

impl DeserializeFrom for BlobId {
    fn deserialize_from(bytes: &mut std::slice::Iter<'_, u8>) -> Option<Self> {
        BlobId::from_iter(bytes)
    }
}

impl DeserializeFrom for Keyword {
    fn deserialize_from(bytes: &mut std::slice::Iter<'_, u8>) -> Option<Self> {
        match bytes.next_leb128::<usize>()? {
            SEEN => Some(Keyword::Seen),
            DRAFT => Some(Keyword::Draft),
            FLAGGED => Some(Keyword::Flagged),
            ANSWERED => Some(Keyword::Answered),
            RECENT => Some(Keyword::Recent),
            IMPORTANT => Some(Keyword::Important),
            PHISHING => Some(Keyword::Phishing),
            JUNK => Some(Keyword::Junk),
            NOTJUNK => Some(Keyword::NotJunk),
            DELETED => Some(Keyword::Deleted),
            FORWARDED => Some(Keyword::Forwarded),
            MDN_SENT => Some(Keyword::MdnSent),
            other => {
                let len = other - OTHER;
                let mut keyword = Vec::with_capacity(len);
                for _ in 0..len {
                    keyword.push(*bytes.next()?);
                }
                Some(Keyword::Other(
                    String::from_utf8(keyword).ok()?.into_boxed_str(),
                ))
            }
        }
    }
}

impl DeserializeFrom for Property {
    fn deserialize_from(bytes: &mut std::slice::Iter<'_, u8>) -> Option<Self> {
        match *bytes.next()? {
            0 => Some(Property::IsActive),
            1 => Some(Property::IsEnabled),
            2 => Some(Property::IsSubscribed),
            3 => Some(Property::Keys),
            4 => Some(Property::Keywords),
            5 => Some(Property::Language),
            6 => Some(Property::Location),
            7 => Some(Property::MailboxIds),
            8 => Some(Property::MayDelete),
            9 => Some(Property::MdnBlobIds),
            10 => Some(Property::Members),
            11 => Some(Property::MessageId),
            12 => Some(Property::MyRights),
            13 => Some(Property::Name),
            14 => Some(Property::ParentId),
            15 => Some(Property::PartId),
            16 => Some(Property::Picture),
            17 => Some(Property::Preview),
            18 => Some(Property::Quota),
            19 => Some(Property::ReceivedAt),
            20 => Some(Property::References),
            21 => Some(Property::ReplyTo),
            22 => Some(Property::Role),
            23 => Some(Property::Secret),
            24 => Some(Property::SendAt),
            25 => Some(Property::Sender),
            26 => Some(Property::SentAt),
            27 => Some(Property::Size),
            28 => Some(Property::SortOrder),
            29 => Some(Property::Subject),
            30 => Some(Property::SubParts),
            31 => Some(Property::TextBody),
            32 => Some(Property::TextSignature),
            33 => Some(Property::ThreadId),
            34 => Some(Property::Timezone),
            35 => Some(Property::To),
            36 => Some(Property::ToDate),
            37 => Some(Property::TotalEmails),
            38 => Some(Property::TotalThreads),
            39 => Some(Property::Type),
            40 => Some(Property::Types),
            41 => Some(Property::UndoStatus),
            42 => Some(Property::UnreadEmails),
            43 => Some(Property::UnreadThreads),
            44 => Some(Property::Url),
            45 => Some(Property::VerificationCode),
            46 => Some(Property::Parameters),
            47 => Some(Property::Addresses),
            48 => Some(Property::P256dh),
            49 => Some(Property::Auth),
            50 => Some(Property::Value),
            51 => Some(Property::SmtpReply),
            52 => Some(Property::Delivered),
            53 => Some(Property::Displayed),
            54 => Some(Property::MailFrom),
            55 => Some(Property::RcptTo),
            56 => Some(Property::IsEncodingProblem),
            57 => Some(Property::IsTruncated),
            58 => Some(Property::MayReadItems),
            59 => Some(Property::MayAddItems),
            60 => Some(Property::MayRemoveItems),
            61 => Some(Property::MaySetSeen),
            62 => Some(Property::MaySetKeywords),
            63 => Some(Property::MayCreateChild),
            64 => Some(Property::MayRename),
            65 => Some(Property::MaySubmit),
            66 => Some(Property::Acl),
            67 => Some(Property::Aliases),
            68 => Some(Property::Attachments),
            69 => Some(Property::Bcc),
            70 => Some(Property::BlobId),
            71 => Some(Property::BodyStructure),
            72 => Some(Property::BodyValues),
            73 => Some(Property::Capabilities),
            74 => Some(Property::Cc),
            75 => Some(Property::Charset),
            76 => Some(Property::Cid),
            77 => Some(Property::DeliveryStatus),
            78 => Some(Property::Description),
            79 => Some(Property::DeviceClientId),
            80 => Some(Property::Disposition),
            81 => Some(Property::DsnBlobIds),
            82 => Some(Property::Email),
            83 => Some(Property::EmailId),
            84 => Some(Property::EmailIds),
            85 => Some(Property::Envelope),
            86 => Some(Property::Expires),
            87 => Some(Property::From),
            88 => Some(Property::FromDate),
            89 => Some(Property::HasAttachment),
            91 => Some(Property::Headers),
            92 => Some(Property::HtmlBody),
            93 => Some(Property::HtmlSignature),
            94 => Some(Property::Id),
            95 => Some(Property::IdentityId),
            96 => Some(Property::InReplyTo),
            97 => String::deserialize_from(bytes).map(Property::_T),
            98 => Some(Property::ResourceType),
            99 => Some(Property::Used),
            100 => Some(Property::HardLimit),
            101 => Some(Property::WarnLimit),
            102 => Some(Property::SoftLimit),
            103 => Some(Property::Scope),
            _ => None,
        }
    }
}

pub trait FromLegacy {
    fn from_legacy(legacy: Object<Value>) -> Self;
}

pub trait TryFromLegacy: Sized {
    fn try_from_legacy(legacy: Object<Value>) -> Option<Self>;
}

impl Value {
    pub fn try_unwrap_id(self) -> Option<Id> {
        match self {
            Value::Id(id) => id.into(),
            _ => None,
        }
    }

    pub fn try_unwrap_bool(self) -> Option<bool> {
        match self {
            Value::Bool(b) => b.into(),
            _ => None,
        }
    }

    pub fn try_unwrap_keyword(self) -> Option<Keyword> {
        match self {
            Value::Keyword(k) => k.into(),
            _ => None,
        }
    }

    pub fn try_unwrap_string(self) -> Option<String> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn try_unwrap_object(self) -> Option<Object<Value>> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn try_unwrap_list(self) -> Option<Vec<Value>> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn try_unwrap_date(self) -> Option<UTCDate> {
        match self {
            Value::Date(d) => Some(d),
            _ => None,
        }
    }

    pub fn try_unwrap_blob_id(self) -> Option<BlobId> {
        match self {
            Value::BlobId(b) => Some(b),
            _ => None,
        }
    }

    pub fn try_unwrap_uint(self) -> Option<u64> {
        match self {
            Value::UnsignedInt(u) => Some(u),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_id(&self) -> Option<&Id> {
        match self {
            Value::Id(id) => Some(id),
            _ => None,
        }
    }

    pub fn as_blob_id(&self) -> Option<&BlobId> {
        match self {
            Value::BlobId(id) => Some(id),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&Vec<Value>> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn as_acl(&self) -> Option<&Vec<AclGrant>> {
        match self {
            Value::Acl(l) => Some(l),
            _ => None,
        }
    }

    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Value::UnsignedInt(u) => Some(*u),
            Value::Id(id) => Some(*id.as_ref()),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_date(&self) -> Option<&UTCDate> {
        match self {
            Value::Date(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_obj(&self) -> Option<&Object<Value>> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn as_obj_mut(&mut self) -> Option<&mut Object<Value>> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn try_cast_uint(&self) -> Option<u64> {
        match self {
            Value::UnsignedInt(u) => Some(*u),
            Value::Id(id) => Some(id.id()),
            Value::Bool(b) => Some(*b as u64),
            _ => None,
        }
    }
}

impl UTCDate {
    pub fn from_timestamp(timestamp: i64) -> Self {
        // Ported from http://howardhinnant.github.io/date_algorithms.html#civil_from_days
        let (z, seconds) = ((timestamp / 86400) + 719468, timestamp % 86400);
        let era: i64 = (if z >= 0 { z } else { z - 146096 }) / 146097;
        let doe: u64 = (z - era * 146097) as u64; // [0, 146096]
        let yoe: u64 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
        let y: i64 = (yoe as i64) + era * 400;
        let doy: u64 = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let d: u64 = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
        let m: u64 = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
        let (h, mn, s) = (seconds / 3600, (seconds / 60) % 60, seconds % 60);

        UTCDate {
            year: (y + i64::from(m <= 2)) as u16,
            month: m as u8,
            day: d as u8,
            hour: h as u8,
            minute: mn as u8,
            second: s as u8,
            tz_before_gmt: false,
            tz_hour: 0,
            tz_minute: 0,
        }
    }

    pub fn timestamp(&self) -> i64 {
        // Ported from https://github.com/protocolbuffers/upb/blob/22182e6e/upb/json_decode.c#L982-L992
        let month = self.month as u32;
        let year_base = 4800; /* Before min year, multiple of 400. */
        let m_adj = month.wrapping_sub(3); /* March-based month. */
        let carry = i64::from(m_adj > month);
        let adjust = if carry > 0 { 12 } else { 0 };
        let y_adj = self.year as i64 + year_base - carry;
        let month_days = ((m_adj.wrapping_add(adjust)) * 62719 + 769) / 2048;
        let leap_days = y_adj / 4 - y_adj / 100 + y_adj / 400;
        (y_adj * 365 + leap_days + month_days as i64 + (self.day as i64 - 1) - 2472632) * 86400
            + self.hour as i64 * 3600
            + self.minute as i64 * 60
            + self.second as i64
            + ((self.tz_hour as i64 * 3600 + self.tz_minute as i64 * 60)
                * if self.tz_before_gmt { 1 } else { -1 })
    }
}
